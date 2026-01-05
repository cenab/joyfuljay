"""Interactive REPL for exploring PCAP files.

Provides a command-line interface for loading, exploring, and
extracting features from PCAP files interactively.
"""

from __future__ import annotations

import cmd
import logging
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class JoyfulJayREPL(cmd.Cmd):
    """Interactive REPL for JoyfulJay.

    Commands:
        load <file>     - Load a PCAP file
        info            - Show info about loaded PCAP
        flows           - List flows in the PCAP
        features        - Extract features from loaded flows
        flow <id>       - Show details for a specific flow
        export <file>   - Export features to file
        config          - Show current configuration
        set <key> <val> - Set configuration value
        help            - Show help
        quit            - Exit the REPL
    """

    intro = """
╔══════════════════════════════════════════════════════════════╗
║                    JoyfulJay Interactive                      ║
║           Encrypted Traffic Feature Extraction               ║
╚══════════════════════════════════════════════════════════════╝

Type 'help' for commands, 'quit' to exit.
"""
    prompt = "joyfuljay> "

    def __init__(self) -> None:
        """Initialize the REPL."""
        super().__init__()
        self._pcap_path: Path | None = None
        self._flows: list[Any] = []
        self._features: list[dict[str, Any]] = []
        self._config: dict[str, Any] = {
            "flow_timeout": 60.0,
            "features": ["all"],
            "include_raw_sequences": False,
        }

    def do_load(self, arg: str) -> None:
        """Load a PCAP file.

        Usage: load <path/to/file.pcap>
        """
        if not arg:
            print("Usage: load <path/to/file.pcap>")
            return

        path = Path(arg.strip())
        if not path.exists():
            print(f"Error: File not found: {path}")
            return

        if path.suffix.lower() not in (".pcap", ".pcapng", ".cap"):
            print(f"Warning: File may not be a PCAP: {path.suffix}")

        try:
            from ..core.config import Config
            from ..core.flow import FlowTable
            from ..capture.scapy_backend import ScapyBackend

            print(f"Loading {path.name}...")

            backend = ScapyBackend(store_raw_payload=True)
            flow_table = FlowTable(timeout=self._config["flow_timeout"])

            packet_count = 0
            for packet in backend.iter_packets_offline(str(path)):
                flow_table.add_packet(packet)
                packet_count += 1

            # Get all flows including active ones
            self._flows = list(flow_table.get_all_flows())
            self._pcap_path = path
            self._features = []  # Clear previous features

            print(f"Loaded {packet_count} packets, {len(self._flows)} flows")

        except Exception as e:
            print(f"Error loading PCAP: {e}")

    def do_info(self, arg: str) -> None:
        """Show information about the loaded PCAP.

        Usage: info
        """
        if not self._pcap_path:
            print("No PCAP loaded. Use 'load <file>' first.")
            return

        print(f"\nFile: {self._pcap_path.name}")
        print(f"Path: {self._pcap_path}")
        print(f"Flows: {len(self._flows)}")

        if self._flows:
            # Calculate some basic stats
            total_packets = sum(f.total_packets for f in self._flows)
            total_bytes = sum(f.total_bytes for f in self._flows)

            protocols = {}
            for flow in self._flows:
                proto = flow.key.protocol
                protocols[proto] = protocols.get(proto, 0) + 1

            print(f"Total packets: {total_packets}")
            print(f"Total bytes: {total_bytes:,}")
            print("Protocols:")
            for proto, count in sorted(protocols.items()):
                proto_name = {6: "TCP", 17: "UDP"}.get(proto, f"Other({proto})")
                print(f"  {proto_name}: {count} flows")

    def do_flows(self, arg: str) -> None:
        """List flows in the loaded PCAP.

        Usage: flows [limit]
        """
        if not self._flows:
            print("No flows loaded. Use 'load <file>' first.")
            return

        limit = 20
        if arg.strip():
            try:
                limit = int(arg.strip())
            except ValueError:
                print("Invalid limit. Using default.")

        print(f"\n{'ID':<4} {'Protocol':<8} {'Source':<22} {'Dest':<22} {'Pkts':<6} {'Bytes':<10}")
        print("-" * 76)

        for i, flow in enumerate(self._flows[:limit]):
            proto = {6: "TCP", 17: "UDP"}.get(flow.key.protocol, str(flow.key.protocol))
            src = f"{flow.initiator_ip}:{flow.initiator_port}"
            dst = f"{flow.responder_ip}:{flow.responder_port}"
            print(f"{i:<4} {proto:<8} {src:<22} {dst:<22} {flow.total_packets:<6} {flow.total_bytes:<10}")

        if len(self._flows) > limit:
            print(f"\n... and {len(self._flows) - limit} more flows")

    def do_flow(self, arg: str) -> None:
        """Show details for a specific flow.

        Usage: flow <id>
        """
        if not arg.strip():
            print("Usage: flow <id>")
            return

        try:
            idx = int(arg.strip())
        except ValueError:
            print("Invalid flow ID")
            return

        if idx < 0 or idx >= len(self._flows):
            print(f"Flow ID out of range (0-{len(self._flows) - 1})")
            return

        flow = self._flows[idx]
        print(f"\nFlow {idx}:")
        print(f"  Protocol: {flow.key.protocol} ({['', '', '', '', '', '', 'TCP', '', '', '', '', '', '', '', '', '', '', 'UDP'][flow.key.protocol] if flow.key.protocol in (6, 17) else 'Other'})")
        print(f"  Source: {flow.initiator_ip}:{flow.initiator_port}")
        print(f"  Destination: {flow.responder_ip}:{flow.responder_port}")
        print(f"  Duration: {flow.duration:.3f}s")
        print(f"  Packets: {flow.total_packets} (fwd: {len(flow.initiator_packets)}, bwd: {len(flow.responder_packets)})")
        print(f"  Bytes: {flow.total_bytes} (fwd: {flow.initiator_bytes}, bwd: {flow.responder_bytes})")
        print(f"  Start: {flow.start_time}")
        print(f"  Terminated: {flow.terminated}")

    def do_features(self, arg: str) -> None:
        """Extract features from loaded flows.

        Usage: features [flow_id]
        """
        if not self._flows:
            print("No flows loaded. Use 'load <file>' first.")
            return

        try:
            from ..core.config import Config
            from ..extractors import (
                FlowMetaExtractor,
                TimingExtractor,
                SizeExtractor,
                TLSExtractor,
                QUICExtractor,
                EntropyExtractor,
                FingerprintExtractor,
            )

            # Build extractors
            extractors = [
                FlowMetaExtractor(),
                TimingExtractor(include_sequences=self._config.get("include_raw_sequences", False)),
                SizeExtractor(),
                TLSExtractor(),
                QUICExtractor(),
                EntropyExtractor(),
                FingerprintExtractor(),
            ]

            if arg.strip():
                # Extract for single flow
                try:
                    idx = int(arg.strip())
                    flows_to_process = [self._flows[idx]]
                except (ValueError, IndexError):
                    print("Invalid flow ID")
                    return
            else:
                flows_to_process = self._flows

            print(f"Extracting features from {len(flows_to_process)} flows...")

            self._features = []
            for flow in flows_to_process:
                features: dict[str, Any] = {}
                for extractor in extractors:
                    features.update(extractor.extract(flow))
                self._features.append(features)

            print(f"Extracted {len(self._features[0]) if self._features else 0} features per flow")

            # Show sample
            if self._features:
                print("\nSample features (first flow):")
                sample = list(self._features[0].items())[:10]
                for key, value in sample:
                    if isinstance(value, float):
                        print(f"  {key}: {value:.4f}")
                    else:
                        print(f"  {key}: {value}")
                if len(self._features[0]) > 10:
                    print(f"  ... and {len(self._features[0]) - 10} more")

        except Exception as e:
            print(f"Error extracting features: {e}")

    def do_export(self, arg: str) -> None:
        """Export features to a file.

        Usage: export <path> [format]
        Format: csv, json, parquet (default: csv)
        """
        if not self._features:
            print("No features extracted. Use 'features' first.")
            return

        parts = arg.strip().split()
        if not parts:
            print("Usage: export <path> [format]")
            return

        path = Path(parts[0])
        fmt = parts[1] if len(parts) > 1 else "csv"

        try:
            import pandas as pd

            df = pd.DataFrame(self._features)

            if fmt == "csv":
                df.to_csv(path, index=False)
            elif fmt == "json":
                df.to_json(path, orient="records", lines=True)
            elif fmt == "parquet":
                df.to_parquet(path, index=False)
            else:
                print(f"Unknown format: {fmt}")
                return

            print(f"Exported {len(self._features)} flows to {path}")

        except ImportError:
            print("pandas is required for export. Install with: pip install pandas")
        except Exception as e:
            print(f"Error exporting: {e}")

    def do_config(self, arg: str) -> None:
        """Show current configuration.

        Usage: config
        """
        print("\nCurrent configuration:")
        for key, value in self._config.items():
            print(f"  {key}: {value}")

    def do_set(self, arg: str) -> None:
        """Set a configuration value.

        Usage: set <key> <value>
        """
        parts = arg.strip().split(None, 1)
        if len(parts) != 2:
            print("Usage: set <key> <value>")
            return

        key, value = parts

        if key not in self._config:
            print(f"Unknown config key: {key}")
            print(f"Available keys: {', '.join(self._config.keys())}")
            return

        # Parse value
        try:
            if value.lower() in ("true", "false"):
                self._config[key] = value.lower() == "true"
            elif "." in value:
                self._config[key] = float(value)
            elif value.isdigit():
                self._config[key] = int(value)
            else:
                self._config[key] = value
            print(f"Set {key} = {self._config[key]}")
        except ValueError as e:
            print(f"Invalid value: {e}")

    def do_quit(self, arg: str) -> bool:
        """Exit the REPL.

        Usage: quit
        """
        print("Goodbye!")
        return True

    def do_exit(self, arg: str) -> bool:
        """Exit the REPL (alias for quit).

        Usage: exit
        """
        return self.do_quit(arg)

    def do_EOF(self, arg: str) -> bool:
        """Handle Ctrl+D."""
        print()
        return self.do_quit(arg)

    def emptyline(self) -> None:
        """Do nothing on empty line."""
        pass

    def default(self, line: str) -> None:
        """Handle unknown commands."""
        print(f"Unknown command: {line.split()[0]}")
        print("Type 'help' for available commands.")


def start_repl() -> None:
    """Start the interactive REPL."""
    repl = JoyfulJayREPL()
    try:
        repl.cmdloop()
    except KeyboardInterrupt:
        print("\nInterrupted. Goodbye!")
        sys.exit(0)


if __name__ == "__main__":
    start_repl()
