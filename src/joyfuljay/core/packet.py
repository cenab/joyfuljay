"""Packet data structure for normalized packet representation."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class Packet:
    """Normalized packet representation from any capture backend.

    This dataclass provides a backend-agnostic representation of a network
    packet, containing all the metadata needed for feature extraction.

    Attributes:
        timestamp: Unix timestamp with high precision (from PCAP or system).
        src_ip: Source IP address as string.
        dst_ip: Destination IP address as string.
        src_port: Source port number (0 for non-TCP/UDP).
        dst_port: Destination port number (0 for non-TCP/UDP).
        protocol: IP protocol number (1=ICMP, 6=TCP, 17=UDP).
        payload_len: Length of transport layer payload in bytes.
        total_len: Total IP packet length in bytes.
        tcp_flags: TCP flags as integer bitmap (None for non-TCP).
        raw_payload: Raw payload bytes for deep inspection (optional).

        src_mac: Source MAC address as string (e.g., "aa:bb:cc:dd:ee:ff").
        dst_mac: Destination MAC address as string.
        eth_type: Ethernet type field (e.g., 0x0800 for IPv4).
        vlan_id: VLAN ID if present (802.1Q).

        ip_ttl: IP Time To Live value.
        ip_id: IP Identification field.
        ip_tos: IP Type of Service / DSCP field.
        ip_flags: IP flags as integer (DF, MF bits).
        ip_version: IP version (4 or 6).

        ipv6_flow_label: IPv6 flow label (20 bits).
        ipv6_traffic_class: IPv6 traffic class.

        tcp_seq: TCP sequence number.
        tcp_ack: TCP acknowledgment number.
        tcp_window: TCP window size.
        tcp_options_raw: Raw TCP options bytes.
        tcp_mss: TCP Maximum Segment Size option value.
        tcp_window_scale: TCP Window Scale option value.
        tcp_timestamp: TCP Timestamp option as (TSval, TSecr) tuple.
        tcp_sack_permitted: Whether SACK is permitted.
        tcp_sack_blocks: SACK blocks as tuple of (left, right) tuples.

        icmp_type: ICMP message type.
        icmp_code: ICMP message code.
        icmp_id: ICMP identifier (for echo request/reply).
        icmp_seq: ICMP sequence number (for echo request/reply).
    """

    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    payload_len: int
    total_len: int
    tcp_flags: int | None = None
    raw_payload: bytes | None = None

    # Layer 2 (MAC) fields - #45
    src_mac: str | None = None
    dst_mac: str | None = None
    eth_type: int | None = None
    vlan_id: int | None = None

    # Layer 3 (IP Extended) fields - #46
    ip_ttl: int | None = None
    ip_id: int | None = None
    ip_tos: int | None = None
    ip_flags: int | None = None
    ip_version: int | None = None

    # IPv6 fields - #47
    ipv6_flow_label: int | None = None
    ipv6_traffic_class: int | None = None

    # TCP Sequence/ACK fields - #51
    tcp_seq: int | None = None
    tcp_ack: int | None = None

    # TCP Window field - #52
    tcp_window: int | None = None

    # TCP Options fields - #54
    tcp_options_raw: bytes | None = None
    tcp_mss: int | None = None
    tcp_window_scale: int | None = None
    tcp_timestamp: tuple[int, int] | None = None
    tcp_sack_permitted: bool = False
    tcp_sack_blocks: tuple[tuple[int, int], ...] | None = None

    # ICMP fields - #58
    icmp_type: int | None = None
    icmp_code: int | None = None
    icmp_id: int | None = None
    icmp_seq: int | None = None

    # Protocol constants
    PROTO_ICMP: int = 1
    PROTO_TCP: int = 6
    PROTO_UDP: int = 17

    # TCP flag constants
    TCP_FIN: int = 0x01
    TCP_SYN: int = 0x02
    TCP_RST: int = 0x04
    TCP_PSH: int = 0x08
    TCP_ACK: int = 0x10
    TCP_URG: int = 0x20

    @property
    def is_tcp(self) -> bool:
        """Check if this packet uses TCP protocol."""
        return self.protocol == self.PROTO_TCP

    @property
    def is_udp(self) -> bool:
        """Check if this packet uses UDP protocol."""
        return self.protocol == self.PROTO_UDP

    @property
    def is_icmp(self) -> bool:
        """Check if this packet uses ICMP protocol."""
        return self.protocol == self.PROTO_ICMP

    @property
    def has_payload(self) -> bool:
        """Check if this packet has any payload data."""
        return self.payload_len > 0

    def has_tcp_flag(self, flag: int) -> bool:
        """Check if a specific TCP flag is set.

        Args:
            flag: TCP flag constant (e.g., Packet.TCP_SYN).

        Returns:
            True if the flag is set, False otherwise or if not TCP.
        """
        if self.tcp_flags is None:
            return False
        return bool(self.tcp_flags & flag)

    @property
    def is_syn(self) -> bool:
        """Check if this is a TCP SYN packet (without ACK)."""
        if self.tcp_flags is None:
            return False
        return bool(self.tcp_flags & self.TCP_SYN) and not bool(self.tcp_flags & self.TCP_ACK)

    @property
    def is_syn_ack(self) -> bool:
        """Check if this is a TCP SYN-ACK packet."""
        if self.tcp_flags is None:
            return False
        return bool(self.tcp_flags & self.TCP_SYN) and bool(self.tcp_flags & self.TCP_ACK)

    @property
    def is_fin(self) -> bool:
        """Check if this is a TCP FIN packet."""
        return self.has_tcp_flag(self.TCP_FIN)

    @property
    def is_rst(self) -> bool:
        """Check if this is a TCP RST packet."""
        return self.has_tcp_flag(self.TCP_RST)

    def five_tuple(self) -> tuple[str, int, str, int, int]:
        """Get the 5-tuple identifier for this packet.

        Returns:
            Tuple of (src_ip, src_port, dst_ip, dst_port, protocol).
        """
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol)
