"""dpkt-based capture backend for high-performance PCAP reading.

dpkt is approximately 10x faster than Scapy for PCAP parsing, making it
ideal for large file processing. This backend only supports offline
PCAP reading, not live capture.
"""

from __future__ import annotations

import logging
import struct
from pathlib import Path
from typing import TYPE_CHECKING, Iterator

from ..core.packet import Packet
from .base import CaptureBackend

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class DpktBackend(CaptureBackend):
    """High-performance dpkt-based PCAP reader.

    This backend uses dpkt for fast PCAP parsing, offering ~10x speed
    improvement over Scapy for large files. It only supports offline
    PCAP reading; for live capture, use ScapyBackend.

    Attributes:
        store_raw_payload: Whether to store raw payload bytes in packets.
        max_payload_bytes: Maximum payload bytes to store (0 for none).
    """

    def __init__(
        self,
        store_raw_payload: bool = False,
        max_payload_bytes: int = 256,
    ) -> None:
        """Initialize the dpkt backend.

        Args:
            store_raw_payload: Whether to store raw payload bytes.
            max_payload_bytes: Maximum payload bytes to store.
        """
        self.store_raw_payload = store_raw_payload
        self.max_payload_bytes = max_payload_bytes
        self._check_dpkt_available()

    def _check_dpkt_available(self) -> None:
        """Check if dpkt is installed."""
        try:
            import dpkt  # noqa: F401
        except ImportError as e:
            raise ImportError(
                "dpkt is required for DpktBackend. Install with: pip install dpkt"
            ) from e

    def __enter__(self) -> DpktBackend:
        """Enter context manager."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        """Exit context manager."""
        self.stop()

    def iter_packets_offline(self, path: str) -> Iterator[Packet]:
        """Stream packets from a PCAP file using dpkt.

        This method is significantly faster than Scapy for large files,
        offering approximately 10x speedup.

        Args:
            path: Path to the PCAP or PCAPNG file.

        Yields:
            Packet objects parsed from the file.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the file format is not supported.
        """
        import dpkt

        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {path}")

        with open(file_path, "rb") as f:
            # Try to detect file format
            try:
                # Check for pcapng magic bytes
                magic = f.read(4)
                f.seek(0)

                if magic == b"\x0a\x0d\x0d\x0a":
                    # PCAPNG format
                    reader = dpkt.pcapng.Reader(f)
                else:
                    # Regular PCAP format
                    reader = dpkt.pcap.Reader(f)

                for timestamp, buf in reader:
                    packet = self._parse_packet(timestamp, buf)
                    if packet is not None:
                        yield packet

            except (dpkt.dpkt.NeedData, struct.error) as e:
                raise ValueError(f"Unable to read PCAP file: {e}") from e

    def iter_packets_live(
        self,
        interface: str,
        bpf_filter: str | None = None,
        packet_count: int | None = None,
        save_pcap: str | None = None,
        pid: int | None = None,
    ) -> Iterator[Packet]:
        """dpkt does not support live capture.

        Args:
            interface: Network interface name.
            bpf_filter: Optional BPF filter expression.
            packet_count: Optional maximum number of packets.
            save_pcap: Optional path to save captured packets.
            pid: Optional process ID to filter traffic by.

        Raises:
            NotImplementedError: Always, as dpkt doesn't support live capture.
        """
        raise NotImplementedError(
            "DpktBackend does not support live capture. Use ScapyBackend instead."
        )

    def stop(self) -> None:
        """Stop any active capture (no-op for dpkt)."""
        pass

    def supports_live_capture(self) -> bool:
        """dpkt does not support live capture.

        Returns:
            False always.
        """
        return False

    def _parse_packet(self, timestamp: float, buf: bytes) -> Packet | None:
        """Parse a raw packet buffer into a Packet object.

        Args:
            timestamp: Packet timestamp from PCAP.
            buf: Raw packet bytes.

        Returns:
            Packet object, or None if not an IP packet.
        """
        import dpkt

        try:
            # Layer 2 (MAC) fields
            src_mac: str | None = None
            dst_mac: str | None = None
            eth_type: int | None = None
            vlan_id: int | None = None
            ip = None
            ip6 = None

            # Try Ethernet first (most common)
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                src_mac = self._mac_to_str(eth.src)
                dst_mac = self._mac_to_str(eth.dst)
                eth_type = eth.type

                # Check for VLAN (802.1Q)
                if eth_type == 0x8100:  # VLAN tagged
                    # Parse VLAN header (4 bytes: 2 TPID + 2 TCI)
                    if len(eth.data) >= 4:
                        vlan_tci = struct.unpack("!H", eth.data[:2])[0]
                        vlan_id = vlan_tci & 0x0FFF

                # Check if it's IP
                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                elif isinstance(eth.data, dpkt.ip6.IP6):
                    ip6 = eth.data
                else:
                    # Try raw IP (for some PCAP types)
                    try:
                        ip = dpkt.ip.IP(buf)
                    except (dpkt.dpkt.UnpackError, dpkt.dpkt.NeedData):
                        try:
                            ip6 = dpkt.ip6.IP6(buf)
                        except (dpkt.dpkt.UnpackError, dpkt.dpkt.NeedData):
                            return None
            except (dpkt.dpkt.UnpackError, dpkt.dpkt.NeedData):
                # Try raw IP
                try:
                    ip = dpkt.ip.IP(buf)
                except (dpkt.dpkt.UnpackError, dpkt.dpkt.NeedData):
                    try:
                        ip6 = dpkt.ip6.IP6(buf)
                    except (dpkt.dpkt.UnpackError, dpkt.dpkt.NeedData):
                        return None

            if ip is None and ip6 is None:
                return None

            # Layer 3 (IP) fields
            ip_ttl: int | None = None
            ip_id: int | None = None
            ip_tos: int | None = None
            ip_flags: int | None = None
            ip_version: int | None = None
            ipv6_flow_label: int | None = None
            ipv6_traffic_class: int | None = None

            if ip is not None:
                src_ip = self._ip_to_str(ip.src)
                dst_ip = self._ip_to_str(ip.dst)
                protocol = ip.p
                total_len = ip.len
                ip_ttl = ip.ttl
                ip_id = ip.id
                ip_tos = ip.tos
                ip_flags = (ip.off >> 13) & 0x7  # Top 3 bits of offset field
                ip_version = 4
                transport_data = ip.data
            else:
                # IPv6
                src_ip = self._ip_to_str(ip6.src)
                dst_ip = self._ip_to_str(ip6.dst)
                protocol = ip6.nxt  # Next header
                total_len = ip6.plen + 40
                ip_ttl = ip6.hlim  # Hop limit
                ip_version = 6
                ipv6_flow_label = ip6.flow
                ipv6_traffic_class = ip6.fc
                transport_data = ip6.data

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

            if isinstance(transport_data, dpkt.tcp.TCP):
                tcp = transport_data
                src_port = tcp.sport
                dst_port = tcp.dport
                tcp_flags = tcp.flags
                tcp_seq = tcp.seq
                tcp_ack = tcp.ack
                tcp_window = tcp.win

                # Parse TCP options
                tcp_options_raw, tcp_mss, tcp_window_scale, tcp_timestamp, \
                    tcp_sack_permitted, tcp_sack_blocks = self._parse_tcp_options(tcp.opts)

                payload_len = len(tcp.data) if tcp.data else 0
                if self.store_raw_payload and payload_len > 0:
                    raw_payload = bytes(tcp.data)[: self.max_payload_bytes]

            elif isinstance(transport_data, dpkt.udp.UDP):
                udp = transport_data
                src_port = udp.sport
                dst_port = udp.dport
                payload_len = len(udp.data) if udp.data else 0
                if self.store_raw_payload and payload_len > 0:
                    raw_payload = bytes(udp.data)[: self.max_payload_bytes]

            elif isinstance(transport_data, dpkt.icmp.ICMP):
                icmp = transport_data
                icmp_type = icmp.type
                icmp_code = icmp.code
                # Echo request/reply have id and seq in the data
                if hasattr(icmp, "data") and hasattr(icmp.data, "id"):
                    icmp_id = icmp.data.id
                    icmp_seq = icmp.data.seq
                payload_len = len(bytes(icmp)) if icmp else 0

            else:
                # Other IP protocols
                payload_len = len(transport_data) if transport_data else 0

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

        except (dpkt.dpkt.UnpackError, dpkt.dpkt.NeedData):
            return None

    def _parse_tcp_options(
        self, opts: bytes
    ) -> tuple[
        bytes | None,  # raw options
        int | None,  # MSS
        int | None,  # Window Scale
        tuple[int, int] | None,  # Timestamp
        bool,  # SACK Permitted
        tuple[tuple[int, int], ...] | None,  # SACK Blocks
    ]:
        """Parse TCP options from raw bytes.

        Args:
            opts: Raw TCP options bytes.

        Returns:
            Tuple of (raw_options, mss, window_scale, timestamp, sack_permitted, sack_blocks).
        """
        mss: int | None = None
        window_scale: int | None = None
        timestamp: tuple[int, int] | None = None
        sack_permitted: bool = False
        sack_blocks: list[tuple[int, int]] = []

        if not opts:
            return (None, None, None, None, False, None)

        i = 0
        while i < len(opts):
            kind = opts[i]

            if kind == 0:  # End of options
                break
            elif kind == 1:  # NOP
                i += 1
                continue
            elif i + 1 >= len(opts):
                break

            length = opts[i + 1]
            if length < 2 or i + length > len(opts):
                break

            if kind == 2 and length == 4:  # MSS
                mss = struct.unpack("!H", opts[i + 2 : i + 4])[0]
            elif kind == 3 and length == 3:  # Window Scale
                window_scale = opts[i + 2]
            elif kind == 4 and length == 2:  # SACK Permitted
                sack_permitted = True
            elif kind == 5:  # SACK Blocks
                num_blocks = (length - 2) // 8
                for j in range(num_blocks):
                    offset = i + 2 + j * 8
                    if offset + 8 <= len(opts):
                        left = struct.unpack("!I", opts[offset : offset + 4])[0]
                        right = struct.unpack("!I", opts[offset + 4 : offset + 8])[0]
                        sack_blocks.append((left, right))
            elif kind == 8 and length == 10:  # Timestamp
                tsval = struct.unpack("!I", opts[i + 2 : i + 6])[0]
                tsecr = struct.unpack("!I", opts[i + 6 : i + 10])[0]
                timestamp = (tsval, tsecr)

            i += length

        return (
            opts if opts else None,
            mss,
            window_scale,
            timestamp,
            sack_permitted,
            tuple(sack_blocks) if sack_blocks else None,
        )

    @staticmethod
    def _mac_to_str(mac_bytes: bytes) -> str:
        """Convert MAC address bytes to string.

        Args:
            mac_bytes: MAC address as bytes.

        Returns:
            MAC address as colon-separated hex string.
        """
        return ":".join(f"{b:02x}" for b in mac_bytes)

    @staticmethod
    def _ip_to_str(ip_bytes: bytes) -> str:
        """Convert IP address bytes to string.

        Args:
            ip_bytes: IP address as bytes.

        Returns:
            IP address as dotted decimal string.
        """
        import socket

        if len(ip_bytes) == 4:
            return socket.inet_ntoa(ip_bytes)
        elif len(ip_bytes) == 16:
            return socket.inet_ntop(socket.AF_INET6, ip_bytes)
        else:
            return ".".join(str(b) for b in ip_bytes)


def is_dpkt_available() -> bool:
    """Check if dpkt is installed.

    Returns:
        True if dpkt can be imported.
    """
    try:
        import dpkt  # noqa: F401
        return True
    except ImportError:
        return False
