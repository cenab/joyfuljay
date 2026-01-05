#!/usr/bin/env python3
"""Live network capture and feature extraction.

This example demonstrates capturing packets from a live network
interface and extracting features in real-time.

Usage:
    sudo python live_capture.py eth0 --duration 30

Note: Live capture typically requires root/admin privileges.
"""

from __future__ import annotations

import argparse
import sys

import joyfuljay as jj


def main() -> None:
    """Capture and extract features from live traffic."""
    parser = argparse.ArgumentParser(description="Live capture example")
    parser.add_argument("interface", help="Network interface (e.g., eth0, en0)")
    parser.add_argument(
        "-d", "--duration", type=float, default=30.0, help="Capture duration in seconds"
    )
    parser.add_argument("-o", "--output", help="Output CSV file")
    parser.add_argument("-f", "--filter", help="BPF filter (e.g., 'tcp port 443')")
    parser.add_argument("--save-pcap", help="Save raw packets to PCAP file")

    args = parser.parse_args()

    print(f"Capturing on interface: {args.interface}")
    print(f"Duration: {args.duration} seconds")
    if args.filter:
        print(f"Filter: {args.filter}")
    print("-" * 40)

    # Configure pipeline
    config = jj.Config(
        features=["flow_meta", "timing", "size", "tls", "fingerprint"],
        flow_timeout=30.0,
        bpf_filter=args.filter,
    )

    pipeline = jj.Pipeline(config)

    try:
        # Stream features as flows complete
        print("Capturing... (Ctrl+C to stop early)")
        flow_count = 0

        for features in pipeline.process_live(
            args.interface,
            duration=args.duration,
            output_format="stream",
            save_pcap=args.save_pcap,
        ):
            flow_count += 1
            src = features.get("src_ip", "?")
            dst = features.get("dst_ip", "?")
            duration = features.get("duration", 0)
            packets = features.get("total_packets", 0)
            is_tor = features.get("is_tor", False)
            is_vpn = features.get("is_vpn", False)

            flags = []
            if is_tor:
                flags.append("TOR")
            if is_vpn:
                flags.append("VPN")
            flag_str = f" [{','.join(flags)}]" if flags else ""

            print(
                f"  Flow {flow_count}: {src} -> {dst} "
                f"({packets} pkts, {duration:.2f}s){flag_str}"
            )

        print("-" * 40)
        print(f"Captured {flow_count} flows")

        if args.output:
            # Re-run for batch output
            df = pipeline.process_live(
                args.interface,
                duration=args.duration,
                output_format="dataframe",
            )
            df.to_csv(args.output, index=False)
            print(f"Saved to: {args.output}")

    except PermissionError:
        print("Error: Live capture requires root/admin privileges.")
        print("Try: sudo python live_capture.py ...")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nCapture interrupted by user.")


if __name__ == "__main__":
    main()
