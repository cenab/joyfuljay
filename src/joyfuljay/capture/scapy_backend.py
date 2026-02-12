"""Scapy-based capture backend for PCAP reading and live capture."""

from __future__ import annotations

import logging
import platform
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Iterator

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Dot1Q, Ether
from scapy.utils import PcapNgReader, PcapReader, PcapWriter, RawPcapReader

from ..core.packet import Packet
from .base import CaptureBackend

if TYPE_CHECKING:
    from scapy.packet import Packet as ScapyPacket

logger = logging.getLogger(__name__)

# Platform detection
IS_WINDOWS = platform.system() == "Windows"
IS_MACOS = platform.system() == "Darwin"
IS_LINUX = platform.system() == "Linux"


class ScapyBackend(CaptureBackend):
    """Scapy-based packet capture backend.

    This backend uses Scapy for both offline PCAP reading and live
    packet capture. It uses streaming readers to avoid loading
    entire files into memory.

    Attributes:
        store_raw_payload: Whether to store raw payload bytes in packets.
        max_payload_bytes: Maximum payload bytes to store (0 for none).
    """

    def __init__(
        self,
        store_raw_payload: bool = False,
        max_payload_bytes: int = 256,
    ) -> None:
        """Initialize the Scapy backend.

        Args:
            store_raw_payload: Whether to store raw payload bytes.
            max_payload_bytes: Maximum payload bytes to store.
        """
        self.store_raw_payload = store_raw_payload
        self.max_payload_bytes = max_payload_bytes
        self._stop_event: threading.Event | None = None
        self._capture_thread: threading.Thread | None = None

    def __enter__(self) -> ScapyBackend:
        """Enter context manager.

        Returns:
            Self for use in with statements.
        """
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        """Exit context manager, stop any active capture.

        Args:
            exc_type: Exception type if an exception was raised.
            exc_val: Exception value if an exception was raised.
            exc_tb: Exception traceback if an exception was raised.
        """
        self.stop()

    def iter_packets_offline(self, path: str) -> Iterator[Packet]:
        """Stream packets from a PCAP file using Scapy.

        Uses PcapReader/PcapNgReader for streaming without loading
        the entire file into memory.

        Args:
            path: Path to the PCAP or PCAPNG file.

        Yields:
            Packet objects parsed from the file.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the file format is not supported.
        """
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {path}")

        # Detect file type and use appropriate reader
        reader: PcapReader | PcapNgReader
        try:
            # Try PcapNg first (more common now)
            reader = PcapNgReader(str(file_path))
        except Exception:
            try:
                reader = PcapReader(str(file_path))
            except Exception as e:
                raise ValueError(f"Unable to read PCAP file: {e}") from e

        try:
            for scapy_pkt in reader:
                packet = self._convert_packet(scapy_pkt)
                if packet is not None:
                    yield packet
        finally:
            reader.close()

    def iter_packets_live(
        self,
        interface: str,
        bpf_filter: str | None = None,
        packet_count: int | None = None,
        save_pcap: str | None = None,
        pid: int | None = None,
    ) -> Iterator[Packet]:
        """Capture packets from a live network interface.

        Uses Scapy's sniff function with store=False for memory efficiency.

        Args:
            interface: Network interface name (e.g., "eth0", "en0").
            bpf_filter: Optional BPF filter expression.
            packet_count: Optional maximum number of packets to capture.
            save_pcap: Optional path to save captured packets to a PCAP file.
            pid: Optional process ID to filter traffic by.

        Yields:
            Packet objects captured from the interface.

        Raises:
            PermissionError: If insufficient privileges for capture.
            ValueError: If the interface does not exist.
            RuntimeError: If required capture libraries are not installed.
        """
        # Check for Windows-specific requirements
        if IS_WINDOWS:
            try:
                # Test if Npcap/WinPcap is available
                from scapy.arch.windows import get_windows_if_list
                get_windows_if_list()
            except Exception as e:
                raise RuntimeError(
                    "Live capture on Windows requires Npcap. "
                    "Please install from https://npcap.com/ and restart your terminal. "
                    f"Error: {e}"
                ) from e

        from queue import Empty, Queue

        from scapy.sendrecv import sniff

        packet_queue: Queue[Packet | None] = Queue(maxsize=10000)
        self._stop_event = threading.Event()
        packets_captured = 0

        # Initialize PCAP writer if save path provided
        pcap_writer: PcapWriter | None = None
        if save_pcap:
            pcap_writer = PcapWriter(save_pcap, append=False, sync=True)
            logger.info(f"Saving captured packets to: {save_pcap}")

        # Initialize PID filter if PID filtering requested
        pid_filter = None
        if pid is not None:
            from ..utils.pid_filter import create_pid_filter

            pid_filter = create_pid_filter(pid)
            pid_filter.start()
            logger.info(f"Filtering traffic for PID: {pid} (method: {pid_filter.method.name})")

        def packet_callback(scapy_pkt: ScapyPacket) -> None:
            nonlocal packets_captured
            if self._stop_event and self._stop_event.is_set():
                return

            # Convert packet first (needed for PID filtering)
            packet = self._convert_packet(scapy_pkt)
            if packet is None:
                return

            # Filter by PID if filter is active
            if pid_filter is not None and not pid_filter.matches_packet(packet):
                return  # Skip packets not belonging to the target PID

            # Save raw packet to PCAP file if writer is configured
            if pcap_writer is not None:
                try:
                    pcap_writer.write(scapy_pkt)
                except Exception as e:
                    logger.warning(f"Failed to write packet to PCAP: {e}")

            try:
                packet_queue.put(packet, timeout=1.0)
                packets_captured += 1
            except Exception:
                pass  # Queue full, drop packet

        def capture_thread() -> None:
            try:
                sniff(
                    iface=interface,
                    prn=packet_callback,
                    filter=bpf_filter,
                    store=False,
                    count=packet_count or 0,
                    stop_filter=lambda _: (
                        self._stop_event is not None and self._stop_event.is_set()
                    ),
                )
            except PermissionError:
                logger.error(f"Permission denied for interface {interface}")
                raise
            except Exception as e:
                logger.error(f"Capture error: {e}")
            finally:
                packet_queue.put(None)  # Signal end of capture

        self._capture_thread = threading.Thread(target=capture_thread, daemon=True)
        self._capture_thread.start()

        # Yield packets from queue
        try:
            while True:
                try:
                    packet = packet_queue.get(timeout=0.1)
                    if packet is None:
                        break
                    yield packet

                    if packet_count and packets_captured >= packet_count:
                        break
                except Empty:
                    # Allow external stop() (e.g., duration timer) to end the generator
                    # even if no new packets arrive.
                    if self._stop_event is not None and self._stop_event.is_set():
                        break
                    thread = self._capture_thread
                    if thread is None or not thread.is_alive():
                        break
                    continue
        finally:
            # Ensure PCAP writer is closed properly
            if pcap_writer is not None:
                pcap_writer.close()
                logger.info(f"Closed PCAP file: {save_pcap}")

            # Stop PID filter
            if pid_filter is not None:
                pid_filter.stop()

    def stop(self) -> None:
        """Stop any active live capture."""
        if self._stop_event:
            self._stop_event.set()

        thread = self._capture_thread
        if thread and thread.is_alive():
            thread.join(timeout=2.0)

        # Only clear references once the capture thread has stopped; otherwise
        # scapy's stop_filter may never observe the stop event.
        if thread is None or not thread.is_alive():
            self._stop_event = None
            self._capture_thread = None

    def _convert_packet(self, scapy_pkt: ScapyPacket) -> Packet | None:
        """Convert a Scapy packet to our Packet dataclass.

        Args:
            scapy_pkt: The Scapy packet to convert.

        Returns:
            A Packet instance, or None if the packet is not IP-based.
        """
        # Check for IPv4 or IPv6
        has_ipv4 = scapy_pkt.haslayer(IP)
        has_ipv6 = scapy_pkt.haslayer(IPv6)

        if not has_ipv4 and not has_ipv6:
            return None

        # Get timestamp
        timestamp: float = float(scapy_pkt.time)

        # Layer 2 (MAC) fields
        src_mac: str | None = None
        dst_mac: str | None = None
        eth_type: int | None = None
        vlan_id: int | None = None

        if scapy_pkt.haslayer(Ether):
            ether = scapy_pkt[Ether]
            src_mac = ether.src
            dst_mac = ether.dst
            eth_type = ether.type

        if scapy_pkt.haslayer(Dot1Q):
            vlan_id = scapy_pkt[Dot1Q].vlan

        # Layer 3 (IP) fields - handle both IPv4 and IPv6
        ip_ttl: int | None = None
        ip_id: int | None = None
        ip_tos: int | None = None
        ip_flags: int | None = None
        ip_version: int | None = None
        ipv6_flow_label: int | None = None
        ipv6_traffic_class: int | None = None

        if has_ipv4:
            ip_layer = scapy_pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = ip_layer.proto
            total_len = ip_layer.len

            # Extended IP fields
            ip_ttl = ip_layer.ttl
            ip_id = ip_layer.id
            ip_tos = ip_layer.tos
            ip_flags = int(ip_layer.flags)
            ip_version = 4
        else:
            ip_layer = scapy_pkt[IPv6]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = ip_layer.nh  # Next Header
            total_len = ip_layer.plen + 40  # Payload length + IPv6 header

            # IPv6 specific fields
            ip_ttl = ip_layer.hlim  # Hop Limit
            ip_version = 6
            ipv6_flow_label = ip_layer.fl
            ipv6_traffic_class = ip_layer.tc

        # Transport layer fields
        src_port = 0
        dst_port = 0
        tcp_flags: int | None = None
        payload_len = 0
        raw_payload: bytes | None = None

        # TCP fields
        tcp_seq: int | None = None
        tcp_ack: int | None = None
        tcp_window: int | None = None
        tcp_options_raw: bytes | None = None
        tcp_mss: int | None = None
        tcp_window_scale: int | None = None
        tcp_timestamp: tuple[int, int] | None = None
        tcp_sack_permitted: bool = False
        tcp_sack_blocks: tuple[tuple[int, int], ...] | None = None

        # ICMP fields
        icmp_type: int | None = None
        icmp_code: int | None = None
        icmp_id: int | None = None
        icmp_seq: int | None = None

        if scapy_pkt.haslayer(TCP):
            tcp_layer = scapy_pkt[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            tcp_flags = int(tcp_layer.flags)

            # TCP Sequence/ACK/Window
            tcp_seq = tcp_layer.seq
            tcp_ack = tcp_layer.ack
            tcp_window = tcp_layer.window

            # TCP Options parsing
            tcp_options_raw, tcp_mss, tcp_window_scale, tcp_timestamp, \
                tcp_sack_permitted, tcp_sack_blocks = self._parse_tcp_options(
                    tcp_layer.options
                )

            if tcp_layer.payload:
                payload_len = len(tcp_layer.payload)
                if self.store_raw_payload and payload_len > 0:
                    payload_bytes = bytes(tcp_layer.payload)
                    raw_payload = payload_bytes[: self.max_payload_bytes]

        elif scapy_pkt.haslayer(UDP):
            udp_layer = scapy_pkt[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            if udp_layer.payload:
                payload_len = len(udp_layer.payload)
                if self.store_raw_payload and payload_len > 0:
                    payload_bytes = bytes(udp_layer.payload)
                    raw_payload = payload_bytes[: self.max_payload_bytes]

        elif scapy_pkt.haslayer(ICMP):
            icmp_layer = scapy_pkt[ICMP]
            icmp_type = icmp_layer.type
            icmp_code = icmp_layer.code
            # Echo request/reply have id and seq
            if hasattr(icmp_layer, "id"):
                icmp_id = icmp_layer.id
            if hasattr(icmp_layer, "seq"):
                icmp_seq = icmp_layer.seq
            payload_len = len(icmp_layer.payload) if icmp_layer.payload else 0

        else:
            # Non-TCP/UDP/ICMP IP packet - still track it
            payload_len = len(ip_layer.payload) if ip_layer.payload else 0

        return Packet(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            payload_len=payload_len,
            total_len=total_len,
            tcp_flags=tcp_flags,
            raw_payload=raw_payload,
            # Layer 2
            src_mac=src_mac,
            dst_mac=dst_mac,
            eth_type=eth_type,
            vlan_id=vlan_id,
            # Layer 3 Extended
            ip_ttl=ip_ttl,
            ip_id=ip_id,
            ip_tos=ip_tos,
            ip_flags=ip_flags,
            ip_version=ip_version,
            # IPv6
            ipv6_flow_label=ipv6_flow_label,
            ipv6_traffic_class=ipv6_traffic_class,
            # TCP Sequence/ACK/Window
            tcp_seq=tcp_seq,
            tcp_ack=tcp_ack,
            tcp_window=tcp_window,
            # TCP Options
            tcp_options_raw=tcp_options_raw,
            tcp_mss=tcp_mss,
            tcp_window_scale=tcp_window_scale,
            tcp_timestamp=tcp_timestamp,
            tcp_sack_permitted=tcp_sack_permitted,
            tcp_sack_blocks=tcp_sack_blocks,
            # ICMP
            icmp_type=icmp_type,
            icmp_code=icmp_code,
            icmp_id=icmp_id,
            icmp_seq=icmp_seq,
        )

    def _parse_tcp_options(
        self, options: list[tuple[str, int | bytes | tuple[int, int] | None]]
    ) -> tuple[
        bytes | None,  # raw options
        int | None,  # MSS
        int | None,  # Window Scale
        tuple[int, int] | None,  # Timestamp
        bool,  # SACK Permitted
        tuple[tuple[int, int], ...] | None,  # SACK Blocks
    ]:
        """Parse TCP options from Scapy's options list.

        Args:
            options: Scapy's TCP options list.

        Returns:
            Tuple of (raw_options, mss, window_scale, timestamp, sack_permitted, sack_blocks).
        """
        mss: int | None = None
        window_scale: int | None = None
        timestamp: tuple[int, int] | None = None
        sack_permitted: bool = False
        sack_blocks: list[tuple[int, int]] = []

        for opt_name, opt_value in options:
            if opt_name == "MSS" and isinstance(opt_value, int):
                mss = opt_value
            elif opt_name == "WScale" and isinstance(opt_value, int):
                window_scale = opt_value
            elif opt_name == "Timestamp" and isinstance(opt_value, tuple):
                timestamp = (int(opt_value[0]), int(opt_value[1]))
            elif opt_name == "SAckOK":
                sack_permitted = True
            elif opt_name == "SAck" and opt_value is not None:
                # SACK blocks come as tuples
                if isinstance(opt_value, tuple):
                    # Could be nested tuples for multiple blocks
                    if len(opt_value) >= 2 and isinstance(opt_value[0], int):
                        sack_blocks.append((int(opt_value[0]), int(opt_value[1])))
                    else:
                        # Multiple blocks
                        for block in opt_value:
                            if isinstance(block, tuple) and len(block) >= 2:
                                sack_blocks.append((int(block[0]), int(block[1])))

        # Build raw options bytes (simplified - just concatenate option names)
        raw_options: bytes | None = None
        if options:
            try:
                # This is a simplified representation
                raw_options = b"".join(
                    opt_name.encode() if isinstance(opt_name, str) else b""
                    for opt_name, _ in options
                )
            except Exception:
                pass

        return (
            raw_options,
            mss,
            window_scale,
            timestamp,
            sack_permitted,
            tuple(sack_blocks) if sack_blocks else None,
        )


def get_available_interfaces() -> list[dict[str, str]]:
    """Get list of available network interfaces.

    Returns:
        List of dicts with 'name' and 'description' keys.
    """
    interfaces: list[dict[str, str]] = []

    try:
        if IS_WINDOWS:
            from scapy.arch.windows import get_windows_if_list

            for iface in get_windows_if_list():
                interfaces.append({
                    "name": iface.get("name", ""),
                    "description": iface.get("description", ""),
                })
        else:
            from scapy.interfaces import get_if_list

            for name in get_if_list():
                interfaces.append({
                    "name": name,
                    "description": "",
                })
    except Exception as e:
        logger.warning(f"Could not enumerate interfaces: {e}")

    return interfaces


def check_live_capture_available() -> tuple[bool, str]:
    """Check if live capture is available on this system.

    Returns:
        Tuple of (available, message).
    """
    if IS_WINDOWS:
        try:
            from scapy.arch.windows import get_windows_if_list
            get_windows_if_list()
            return True, "Npcap detected"
        except Exception:
            return False, (
                "Npcap not found. Install from https://npcap.com/ for live capture. "
                "PCAP file processing will still work."
            )
    else:
        try:
            from scapy.interfaces import get_if_list
            ifaces = get_if_list()
            if ifaces:
                return True, f"libpcap available ({len(ifaces)} interfaces)"
            return True, "libpcap available"
        except Exception as e:
            return False, f"libpcap not available: {e}"
