"""Test fixtures for Tranalyzer-compatible feature extractors (#44-#58).

This module provides comprehensive helper functions to create packets with
all the new fields required for testing MAC, IP, TCP, and ICMP extractors.
"""

from __future__ import annotations

from joyfuljay.core.flow import Flow
from joyfuljay.core.packet import Packet


# =============================================================================
# Layer 2 (MAC) Fixtures - #45
# =============================================================================

def create_mac_packet(
    src_mac: str = "aa:bb:cc:dd:ee:01",
    dst_mac: str = "10:22:33:44:55:66",  # Unicast (first byte LSB=0)
    eth_type: int = 0x0800,  # IPv4
    vlan_id: int | None = None,
    **kwargs,
) -> Packet:
    """Create a packet with MAC layer information.

    Args:
        src_mac: Source MAC address.
        dst_mac: Destination MAC address.
        eth_type: Ethernet type (0x0800=IPv4, 0x86DD=IPv6).
        vlan_id: VLAN ID if tagged.
        **kwargs: Additional Packet fields.

    Returns:
        Packet with MAC fields populated.
    """
    defaults = {
        "timestamp": 1000.0,
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "src_port": 54321,
        "dst_port": 443,
        "protocol": 6,
        "payload_len": 100,
        "total_len": 140,
        "tcp_flags": 0x18,
        "ip_version": 4,  # IPv4 by default
    }
    defaults.update(kwargs)
    return Packet(
        src_mac=src_mac,
        dst_mac=dst_mac,
        eth_type=eth_type,
        vlan_id=vlan_id,
        **defaults,
    )


def create_broadcast_mac_packet(**kwargs) -> Packet:
    """Create a packet with broadcast destination MAC."""
    return create_mac_packet(dst_mac="ff:ff:ff:ff:ff:ff", **kwargs)


def create_multicast_mac_packet(**kwargs) -> Packet:
    """Create a packet with multicast destination MAC."""
    # Multicast MAC has LSB of first byte = 1
    return create_mac_packet(dst_mac="01:00:5e:00:00:01", **kwargs)


def create_vlan_tagged_packet(vlan_id: int = 100, **kwargs) -> Packet:
    """Create a VLAN-tagged packet."""
    return create_mac_packet(vlan_id=vlan_id, **kwargs)


def create_mac_flow(num_packets: int = 5, with_vlan: bool = False) -> Flow:
    """Create a flow with MAC information.

    Args:
        num_packets: Number of packets in the flow.
        with_vlan: Whether to include VLAN tags.

    Returns:
        Flow with MAC-enabled packets.
    """
    packets = []
    base_time = 1000.0

    for i in range(num_packets):
        is_forward = i % 2 == 0
        vlan = 100 if with_vlan else None

        pkt = create_mac_packet(
            timestamp=base_time + i * 0.01,
            src_ip="192.168.1.100" if is_forward else "10.0.0.1",
            dst_ip="10.0.0.1" if is_forward else "192.168.1.100",
            src_port=54321 if is_forward else 443,
            dst_port=443 if is_forward else 54321,
            src_mac="aa:bb:cc:dd:ee:01" if is_forward else "10:22:33:44:55:66",
            dst_mac="10:22:33:44:55:66" if is_forward else "aa:bb:cc:dd:ee:01",
            vlan_id=vlan,
        )
        packets.append(pkt)

    flow = Flow.from_first_packet(packets[0])
    for pkt in packets[1:]:
        flow.add_packet(pkt)

    return flow


# =============================================================================
# Layer 3 (IP Extended) Fixtures - #46
# =============================================================================

def create_ip_extended_packet(
    ip_ttl: int = 64,
    ip_id: int = 12345,
    ip_tos: int = 0,
    ip_flags: int = 0x02,  # DF flag
    ip_version: int = 4,
    **kwargs,
) -> Packet:
    """Create a packet with extended IP fields.

    Args:
        ip_ttl: Time to Live value.
        ip_id: IP identification field.
        ip_tos: Type of Service / DSCP field.
        ip_flags: IP flags (DF, MF bits).
        ip_version: IP version (4 or 6).
        **kwargs: Additional Packet fields.

    Returns:
        Packet with extended IP fields populated.
    """
    defaults = {
        "timestamp": 1000.0,
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "src_port": 54321,
        "dst_port": 443,
        "protocol": 6,
        "payload_len": 100,
        "total_len": 140,
        "tcp_flags": 0x18,
    }
    defaults.update(kwargs)
    return Packet(
        ip_ttl=ip_ttl,
        ip_id=ip_id,
        ip_tos=ip_tos,
        ip_flags=ip_flags,
        ip_version=ip_version,
        **defaults,
    )


def create_ip_flow_with_ttl_variations(ttl_values: list[int] | None = None) -> Flow:
    """Create a flow with varying TTL values.

    Args:
        ttl_values: List of TTL values for each packet.

    Returns:
        Flow with TTL variations.
    """
    if ttl_values is None:
        ttl_values = [64, 64, 63, 64, 62]

    packets = []
    base_time = 1000.0

    for i, ttl in enumerate(ttl_values):
        is_forward = i % 2 == 0
        pkt = create_ip_extended_packet(
            timestamp=base_time + i * 0.01,
            ip_ttl=ttl,
            ip_id=12345 + i,
            src_ip="192.168.1.100" if is_forward else "10.0.0.1",
            dst_ip="10.0.0.1" if is_forward else "192.168.1.100",
            src_port=54321 if is_forward else 443,
            dst_port=443 if is_forward else 54321,
        )
        packets.append(pkt)

    flow = Flow.from_first_packet(packets[0])
    for pkt in packets[1:]:
        flow.add_packet(pkt)

    return flow


def create_ip_flow_with_dscp(dscp: int = 46) -> Flow:
    """Create a flow with specific DSCP value.

    Args:
        dscp: DSCP value (0-63).

    Returns:
        Flow with DSCP-marked packets.
    """
    tos = dscp << 2  # DSCP is top 6 bits of ToS
    packets = []
    base_time = 1000.0

    for i in range(5):
        is_forward = i % 2 == 0
        pkt = create_ip_extended_packet(
            timestamp=base_time + i * 0.01,
            ip_tos=tos,
            src_ip="192.168.1.100" if is_forward else "10.0.0.1",
            dst_ip="10.0.0.1" if is_forward else "192.168.1.100",
            src_port=54321 if is_forward else 443,
            dst_port=443 if is_forward else 54321,
        )
        packets.append(pkt)

    flow = Flow.from_first_packet(packets[0])
    for pkt in packets[1:]:
        flow.add_packet(pkt)

    return flow


# =============================================================================
# IPv6 Fixtures - #47
# =============================================================================

def create_ipv6_packet(
    flow_label: int = 12345,
    traffic_class: int = 0,
    **kwargs,
) -> Packet:
    """Create an IPv6 packet.

    Args:
        flow_label: IPv6 flow label (20 bits).
        traffic_class: IPv6 traffic class.
        **kwargs: Additional Packet fields.

    Returns:
        IPv6 packet.
    """
    defaults = {
        "timestamp": 1000.0,
        "src_ip": "2001:db8::1",
        "dst_ip": "2001:db8::2",
        "src_port": 54321,
        "dst_port": 443,
        "protocol": 6,
        "payload_len": 100,
        "total_len": 140,
        "tcp_flags": 0x18,
        "ip_version": 6,
    }
    defaults.update(kwargs)
    return Packet(
        ipv6_flow_label=flow_label,
        ipv6_traffic_class=traffic_class,
        **defaults,
    )


def create_ipv6_flow(num_packets: int = 5) -> Flow:
    """Create an IPv6 flow.

    Args:
        num_packets: Number of packets.

    Returns:
        IPv6 flow.
    """
    packets = []
    base_time = 1000.0

    for i in range(num_packets):
        is_forward = i % 2 == 0
        pkt = create_ipv6_packet(
            timestamp=base_time + i * 0.01,
            src_ip="2001:db8::1" if is_forward else "2001:db8::2",
            dst_ip="2001:db8::2" if is_forward else "2001:db8::1",
            src_port=54321 if is_forward else 443,
            dst_port=443 if is_forward else 54321,
            flow_label=12345,
            traffic_class=0x28,  # DSCP 10
        )
        packets.append(pkt)

    flow = Flow.from_first_packet(packets[0])
    for pkt in packets[1:]:
        flow.add_packet(pkt)

    return flow


# =============================================================================
# TCP Sequence Fixtures - #51
# =============================================================================

def create_tcp_seq_packet(
    tcp_seq: int = 1000,
    tcp_ack: int = 2000,
    **kwargs,
) -> Packet:
    """Create a packet with TCP sequence/ack numbers.

    Args:
        tcp_seq: TCP sequence number.
        tcp_ack: TCP acknowledgment number.
        **kwargs: Additional Packet fields.

    Returns:
        Packet with TCP sequence information.
    """
    defaults = {
        "timestamp": 1000.0,
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "src_port": 54321,
        "dst_port": 443,
        "protocol": 6,
        "payload_len": 100,
        "total_len": 140,
        "tcp_flags": 0x18,
    }
    defaults.update(kwargs)
    return Packet(
        tcp_seq=tcp_seq,
        tcp_ack=tcp_ack,
        **defaults,
    )


def create_tcp_handshake_flow() -> Flow:
    """Create a complete TCP 3-way handshake flow.

    Returns:
        Flow with SYN, SYN-ACK, ACK sequence.
    """
    base_time = 1000.0
    client_isn = 1000000
    server_isn = 2000000

    packets = [
        # SYN
        create_tcp_seq_packet(
            timestamp=base_time,
            tcp_seq=client_isn,
            tcp_ack=0,
            tcp_flags=0x02,  # SYN
            payload_len=0,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            tcp_window=65535,
            tcp_mss=1460,
            tcp_window_scale=7,
            ip_ttl=64,
        ),
        # SYN-ACK
        create_tcp_seq_packet(
            timestamp=base_time + 0.01,
            tcp_seq=server_isn,
            tcp_ack=client_isn + 1,
            tcp_flags=0x12,  # SYN-ACK
            payload_len=0,
            src_ip="10.0.0.1",
            dst_ip="192.168.1.100",
            src_port=443,
            dst_port=54321,
            tcp_window=65535,
            tcp_mss=1460,
            tcp_window_scale=8,
            ip_ttl=64,
        ),
        # ACK
        create_tcp_seq_packet(
            timestamp=base_time + 0.02,
            tcp_seq=client_isn + 1,
            tcp_ack=server_isn + 1,
            tcp_flags=0x10,  # ACK
            payload_len=0,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            tcp_window=65535,
            ip_ttl=64,
        ),
        # Data from client
        create_tcp_seq_packet(
            timestamp=base_time + 0.03,
            tcp_seq=client_isn + 1,
            tcp_ack=server_isn + 1,
            tcp_flags=0x18,  # PSH-ACK
            payload_len=200,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            tcp_window=65535,
            ip_ttl=64,
        ),
        # Data from server
        create_tcp_seq_packet(
            timestamp=base_time + 0.05,
            tcp_seq=server_isn + 1,
            tcp_ack=client_isn + 201,
            tcp_flags=0x18,  # PSH-ACK
            payload_len=1400,
            src_ip="10.0.0.1",
            dst_ip="192.168.1.100",
            src_port=443,
            dst_port=54321,
            tcp_window=65535,
            ip_ttl=64,
        ),
    ]

    flow = Flow.from_first_packet(packets[0])
    for pkt in packets[1:]:
        flow.add_packet(pkt)

    return flow


def create_tcp_retransmission_flow() -> Flow:
    """Create a flow with retransmitted packets.

    Returns:
        Flow with retransmission patterns.
    """
    base_time = 1000.0
    isn = 1000000

    packets = [
        # Original data packet
        create_tcp_seq_packet(
            timestamp=base_time,
            tcp_seq=isn,
            tcp_ack=2000000,
            tcp_flags=0x18,
            payload_len=100,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
        ),
        # Retransmission (same seq number)
        create_tcp_seq_packet(
            timestamp=base_time + 0.5,  # Retry after timeout
            tcp_seq=isn,  # Same sequence number = retransmit
            tcp_ack=2000000,
            tcp_flags=0x18,
            payload_len=100,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
        ),
        # ACK from server
        create_tcp_seq_packet(
            timestamp=base_time + 0.55,
            tcp_seq=2000000,
            tcp_ack=isn + 100,
            tcp_flags=0x10,
            payload_len=0,
            src_ip="10.0.0.1",
            dst_ip="192.168.1.100",
            src_port=443,
            dst_port=54321,
        ),
    ]

    flow = Flow.from_first_packet(packets[0])
    for pkt in packets[1:]:
        flow.add_packet(pkt)

    return flow


def create_tcp_dup_ack_flow() -> Flow:
    """Create a flow with duplicate ACKs.

    Returns:
        Flow with duplicate ACK patterns.
    """
    base_time = 1000.0

    packets = [
        # Data packet
        create_tcp_seq_packet(
            timestamp=base_time,
            tcp_seq=1000,
            tcp_ack=2000,
            tcp_flags=0x18,
            payload_len=100,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
        ),
        # ACK
        create_tcp_seq_packet(
            timestamp=base_time + 0.01,
            tcp_seq=2000,
            tcp_ack=1100,
            tcp_flags=0x10,
            payload_len=0,
            src_ip="10.0.0.1",
            dst_ip="192.168.1.100",
            src_port=443,
            dst_port=54321,
        ),
        # Duplicate ACK 1
        create_tcp_seq_packet(
            timestamp=base_time + 0.02,
            tcp_seq=2000,
            tcp_ack=1100,  # Same ACK
            tcp_flags=0x10,
            payload_len=0,
            src_ip="10.0.0.1",
            dst_ip="192.168.1.100",
            src_port=443,
            dst_port=54321,
        ),
        # Duplicate ACK 2
        create_tcp_seq_packet(
            timestamp=base_time + 0.03,
            tcp_seq=2000,
            tcp_ack=1100,  # Same ACK again
            tcp_flags=0x10,
            payload_len=0,
            src_ip="10.0.0.1",
            dst_ip="192.168.1.100",
            src_port=443,
            dst_port=54321,
        ),
    ]

    flow = Flow.from_first_packet(packets[0])
    for pkt in packets[1:]:
        flow.add_packet(pkt)

    return flow


# =============================================================================
# TCP Window Fixtures - #52
# =============================================================================

def create_tcp_window_packet(
    tcp_window: int = 65535,
    tcp_window_scale: int | None = None,
    **kwargs,
) -> Packet:
    """Create a packet with TCP window information.

    Args:
        tcp_window: TCP window size.
        tcp_window_scale: Window scale factor (if any).
        **kwargs: Additional Packet fields.

    Returns:
        Packet with TCP window information.
    """
    defaults = {
        "timestamp": 1000.0,
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "src_port": 54321,
        "dst_port": 443,
        "protocol": 6,
        "payload_len": 100,
        "total_len": 140,
        "tcp_flags": 0x18,
    }
    defaults.update(kwargs)
    return Packet(
        tcp_window=tcp_window,
        tcp_window_scale=tcp_window_scale,
        **defaults,
    )


def create_tcp_window_flow(window_sizes: list[int] | None = None) -> Flow:
    """Create a flow with varying window sizes.

    Args:
        window_sizes: List of window sizes for each packet.

    Returns:
        Flow with window variations.
    """
    if window_sizes is None:
        window_sizes = [65535, 65535, 32768, 16384, 65535]

    packets = []
    base_time = 1000.0

    for i, win in enumerate(window_sizes):
        is_forward = i % 2 == 0
        pkt = create_tcp_window_packet(
            timestamp=base_time + i * 0.01,
            tcp_window=win,
            tcp_window_scale=7 if i == 0 else None,
            src_ip="192.168.1.100" if is_forward else "10.0.0.1",
            dst_ip="10.0.0.1" if is_forward else "192.168.1.100",
            src_port=54321 if is_forward else 443,
            dst_port=443 if is_forward else 54321,
        )
        packets.append(pkt)

    flow = Flow.from_first_packet(packets[0])
    for pkt in packets[1:]:
        flow.add_packet(pkt)

    return flow


def create_zero_window_flow() -> Flow:
    """Create a flow with zero window events.

    Returns:
        Flow with zero window conditions.
    """
    return create_tcp_window_flow([65535, 0, 0, 32768, 65535])


# =============================================================================
# TCP Options Fixtures - #54
# =============================================================================

def create_tcp_options_packet(
    tcp_mss: int | None = 1460,
    tcp_window_scale: int | None = 7,
    tcp_timestamp: tuple[int, int] | None = None,
    tcp_sack_permitted: bool = True,
    tcp_sack_blocks: tuple[tuple[int, int], ...] | None = None,
    tcp_options_raw: bytes | None = None,
    **kwargs,
) -> Packet:
    """Create a packet with TCP options.

    Args:
        tcp_mss: Maximum Segment Size.
        tcp_window_scale: Window Scale factor.
        tcp_timestamp: (TSval, TSecr) tuple.
        tcp_sack_permitted: Whether SACK is permitted.
        tcp_sack_blocks: SACK blocks.
        tcp_options_raw: Raw TCP options bytes.
        **kwargs: Additional Packet fields.

    Returns:
        Packet with TCP options.
    """
    defaults = {
        "timestamp": 1000.0,
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "src_port": 54321,
        "dst_port": 443,
        "protocol": 6,
        "payload_len": 0,
        "total_len": 60,
        "tcp_flags": 0x02,  # SYN
        "tcp_window": 65535,
    }
    defaults.update(kwargs)
    return Packet(
        tcp_mss=tcp_mss,
        tcp_window_scale=tcp_window_scale,
        tcp_timestamp=tcp_timestamp,
        tcp_sack_permitted=tcp_sack_permitted,
        tcp_sack_blocks=tcp_sack_blocks,
        tcp_options_raw=tcp_options_raw,
        **defaults,
    )


def create_tcp_options_flow() -> Flow:
    """Create a flow with various TCP options.

    Returns:
        Flow with TCP options in SYN packets.
    """
    base_time = 1000.0
    ts_base = 100000

    packets = [
        # SYN with options
        create_tcp_options_packet(
            timestamp=base_time,
            tcp_mss=1460,
            tcp_window_scale=7,
            tcp_sack_permitted=True,
            tcp_timestamp=(ts_base, 0),
            tcp_flags=0x02,
        ),
        # SYN-ACK with options
        create_tcp_options_packet(
            timestamp=base_time + 0.01,
            tcp_mss=1460,
            tcp_window_scale=8,
            tcp_sack_permitted=True,
            tcp_timestamp=(ts_base + 1000, ts_base),
            tcp_flags=0x12,
            src_ip="10.0.0.1",
            dst_ip="192.168.1.100",
            src_port=443,
            dst_port=54321,
        ),
        # Data with timestamp
        create_tcp_options_packet(
            timestamp=base_time + 0.02,
            tcp_mss=None,
            tcp_window_scale=None,
            tcp_sack_permitted=False,
            tcp_timestamp=(ts_base + 100, ts_base + 1000),
            tcp_flags=0x18,
            payload_len=100,
            total_len=140,
        ),
    ]

    flow = Flow.from_first_packet(packets[0])
    for pkt in packets[1:]:
        flow.add_packet(pkt)

    return flow


def create_tcp_sack_flow() -> Flow:
    """Create a flow with SACK blocks.

    Returns:
        Flow with SACK information.
    """
    base_time = 1000.0

    packets = [
        # Initial data
        create_tcp_options_packet(
            timestamp=base_time,
            tcp_sack_permitted=True,
            tcp_flags=0x18,
            payload_len=100,
            tcp_seq=1000,
            tcp_ack=2000,
        ),
        # ACK with SACK blocks (indicating missing data)
        create_tcp_options_packet(
            timestamp=base_time + 0.01,
            tcp_sack_permitted=False,
            tcp_sack_blocks=((2200, 2400), (2600, 2800)),
            tcp_flags=0x10,
            payload_len=0,
            src_ip="10.0.0.1",
            dst_ip="192.168.1.100",
            src_port=443,
            dst_port=54321,
            tcp_seq=2000,
            tcp_ack=1100,
        ),
    ]

    flow = Flow.from_first_packet(packets[0])
    for pkt in packets[1:]:
        flow.add_packet(pkt)

    return flow


# =============================================================================
# TCP MPTCP Fixtures - #55
# =============================================================================

def create_mptcp_capable_option() -> bytes:
    """Create raw TCP options containing MPTCP MP_CAPABLE.

    Returns:
        Raw TCP options bytes with MPTCP option (kind 30).
    """
    # MPTCP option: kind=30, length=12 (MP_CAPABLE)
    # Subtype 0 = MP_CAPABLE
    mptcp_option = bytes([
        30,  # Kind (MPTCP)
        12,  # Length
        0x00,  # Subtype 0 (MP_CAPABLE) << 4
        0x81,  # Flags
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Key
    ])
    # Add NOP padding
    return bytes([1, 1]) + mptcp_option


def create_mptcp_flow() -> Flow:
    """Create a flow with MPTCP capabilities.

    Returns:
        Flow with MPTCP-capable handshake.
    """
    base_time = 1000.0
    mptcp_opts = create_mptcp_capable_option()

    packets = [
        # SYN with MP_CAPABLE
        create_tcp_options_packet(
            timestamp=base_time,
            tcp_flags=0x02,
            tcp_options_raw=mptcp_opts,
        ),
        # SYN-ACK with MP_CAPABLE
        create_tcp_options_packet(
            timestamp=base_time + 0.01,
            tcp_flags=0x12,
            tcp_options_raw=mptcp_opts,
            src_ip="10.0.0.1",
            dst_ip="192.168.1.100",
            src_port=443,
            dst_port=54321,
        ),
        # ACK
        create_tcp_options_packet(
            timestamp=base_time + 0.02,
            tcp_flags=0x10,
            tcp_options_raw=None,
        ),
    ]

    flow = Flow.from_first_packet(packets[0])
    for pkt in packets[1:]:
        flow.add_packet(pkt)

    return flow


def create_non_mptcp_flow() -> Flow:
    """Create a regular TCP flow without MPTCP.

    Returns:
        Flow without MPTCP options.
    """
    return create_tcp_options_flow()


# =============================================================================
# TCP RTT Fixtures - #56
# =============================================================================

def create_tcp_rtt_flow(rtt_ms: float = 20.0) -> Flow:
    """Create a flow for RTT estimation.

    Args:
        rtt_ms: Simulated RTT in milliseconds.

    Returns:
        Flow with timing for RTT estimation.
    """
    base_time = 1000.0
    rtt_sec = rtt_ms / 1000.0
    ts_base = 100000
    ts_freq = 1000  # 1000 Hz timestamp

    packets = [
        # SYN
        create_tcp_seq_packet(
            timestamp=base_time,
            tcp_seq=1000000,
            tcp_ack=0,
            tcp_flags=0x02,
            payload_len=0,
            tcp_window=65535,
            tcp_timestamp=(ts_base, 0),
            ip_ttl=64,
        ),
        # SYN-ACK (RTT/2 later)
        create_tcp_seq_packet(
            timestamp=base_time + rtt_sec / 2,
            tcp_seq=2000000,
            tcp_ack=1000001,
            tcp_flags=0x12,
            payload_len=0,
            src_ip="10.0.0.1",
            dst_ip="192.168.1.100",
            src_port=443,
            dst_port=54321,
            tcp_window=65535,
            tcp_timestamp=(ts_base + int(rtt_sec / 2 * ts_freq), ts_base),
            ip_ttl=64,
        ),
        # ACK (full RTT from SYN)
        create_tcp_seq_packet(
            timestamp=base_time + rtt_sec,
            tcp_seq=1000001,
            tcp_ack=2000001,
            tcp_flags=0x10,
            payload_len=0,
            tcp_window=65535,
            tcp_timestamp=(ts_base + int(rtt_sec * ts_freq), ts_base + int(rtt_sec / 2 * ts_freq)),
            ip_ttl=64,
        ),
        # Data with response
        create_tcp_seq_packet(
            timestamp=base_time + rtt_sec + 0.001,
            tcp_seq=1000001,
            tcp_ack=2000001,
            tcp_flags=0x18,
            payload_len=100,
            tcp_window=65535,
            tcp_timestamp=(ts_base + int((rtt_sec + 0.001) * ts_freq), ts_base + int(rtt_sec / 2 * ts_freq)),
            ip_ttl=64,
        ),
        # ACK for data
        create_tcp_seq_packet(
            timestamp=base_time + 2 * rtt_sec,
            tcp_seq=2000001,
            tcp_ack=1000101,
            tcp_flags=0x10,
            payload_len=0,
            src_ip="10.0.0.1",
            dst_ip="192.168.1.100",
            src_port=443,
            dst_port=54321,
            tcp_window=65535,
            tcp_timestamp=(ts_base + int(2 * rtt_sec * ts_freq), ts_base + int((rtt_sec + 0.001) * ts_freq)),
            ip_ttl=64,
        ),
    ]

    flow = Flow.from_first_packet(packets[0])
    for pkt in packets[1:]:
        flow.add_packet(pkt)

    return flow


# =============================================================================
# TCP Fingerprint Fixtures - #57
# =============================================================================

def create_tcp_fingerprint_flow(
    client_ttl: int = 64,
    client_window: int = 65535,
    client_mss: int = 1460,
    client_ws: int = 7,
    server_ttl: int = 64,
    server_window: int = 65535,
    server_mss: int = 1460,
    server_ws: int = 8,
) -> Flow:
    """Create a flow for TCP fingerprinting.

    Args:
        client_ttl: Client initial TTL.
        client_window: Client initial window size.
        client_mss: Client MSS.
        client_ws: Client window scale.
        server_ttl: Server initial TTL.
        server_window: Server initial window size.
        server_mss: Server MSS.
        server_ws: Server window scale.

    Returns:
        Flow with fingerprinting parameters.
    """
    base_time = 1000.0
    ts_base = 1000000  # High timestamp = long uptime

    packets = [
        # SYN
        create_tcp_options_packet(
            timestamp=base_time,
            tcp_mss=client_mss,
            tcp_window_scale=client_ws,
            tcp_window=client_window,
            tcp_timestamp=(ts_base, 0),
            tcp_sack_permitted=True,
            tcp_flags=0x02,
            ip_ttl=client_ttl,
        ),
        # SYN-ACK
        create_tcp_options_packet(
            timestamp=base_time + 0.01,
            tcp_mss=server_mss,
            tcp_window_scale=server_ws,
            tcp_window=server_window,
            tcp_timestamp=(ts_base + 10000, ts_base),
            tcp_sack_permitted=True,
            tcp_flags=0x12,
            src_ip="10.0.0.1",
            dst_ip="192.168.1.100",
            src_port=443,
            dst_port=54321,
            ip_ttl=server_ttl,
        ),
    ]

    flow = Flow.from_first_packet(packets[0])
    for pkt in packets[1:]:
        flow.add_packet(pkt)

    return flow


def create_linux_fingerprint_flow() -> Flow:
    """Create a flow with Linux-like TCP fingerprint."""
    return create_tcp_fingerprint_flow(
        client_ttl=64,
        client_window=29200,
        client_mss=1460,
        client_ws=7,
    )


def create_windows_fingerprint_flow() -> Flow:
    """Create a flow with Windows-like TCP fingerprint."""
    return create_tcp_fingerprint_flow(
        client_ttl=128,
        client_window=65535,
        client_mss=1460,
        client_ws=8,
    )


# =============================================================================
# ICMP Fixtures - #58
# =============================================================================

def create_icmp_packet(
    icmp_type: int = 8,  # Echo request
    icmp_code: int = 0,
    icmp_id: int = 1234,
    icmp_seq: int = 1,
    **kwargs,
) -> Packet:
    """Create an ICMP packet.

    Args:
        icmp_type: ICMP message type.
        icmp_code: ICMP message code.
        icmp_id: ICMP identifier.
        icmp_seq: ICMP sequence number.
        **kwargs: Additional Packet fields.

    Returns:
        ICMP packet.
    """
    defaults = {
        "timestamp": 1000.0,
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "src_port": 0,
        "dst_port": 0,
        "protocol": 1,  # ICMP
        "payload_len": 64,
        "total_len": 84,
        "tcp_flags": None,
    }
    defaults.update(kwargs)
    return Packet(
        icmp_type=icmp_type,
        icmp_code=icmp_code,
        icmp_id=icmp_id,
        icmp_seq=icmp_seq,
        **defaults,
    )


def create_ping_flow(num_pings: int = 5, success_ratio: float = 1.0) -> Flow:
    """Create a ping (echo request/reply) flow.

    Args:
        num_pings: Number of ping requests.
        success_ratio: Ratio of successful replies (0.0-1.0).

    Returns:
        Flow with ping traffic.
    """
    packets = []
    base_time = 1000.0
    successful_pings = int(num_pings * success_ratio)

    for i in range(num_pings):
        # Echo request
        packets.append(create_icmp_packet(
            timestamp=base_time + i * 0.1,
            icmp_type=8,  # Echo request
            icmp_code=0,
            icmp_id=1234,
            icmp_seq=i + 1,
        ))

        # Echo reply (if successful)
        if i < successful_pings:
            packets.append(create_icmp_packet(
                timestamp=base_time + i * 0.1 + 0.01,
                icmp_type=0,  # Echo reply
                icmp_code=0,
                icmp_id=1234,
                icmp_seq=i + 1,
                src_ip="10.0.0.1",
                dst_ip="192.168.1.100",
            ))

    flow = Flow.from_first_packet(packets[0])
    for pkt in packets[1:]:
        flow.add_packet(pkt)

    return flow


def create_icmp_unreachable_flow() -> Flow:
    """Create a flow with ICMP destination unreachable messages.

    Returns:
        Flow with unreachable messages.
    """
    base_time = 1000.0

    packets = [
        # Destination unreachable - Host unreachable
        create_icmp_packet(
            timestamp=base_time,
            icmp_type=3,  # Destination unreachable
            icmp_code=1,  # Host unreachable
            icmp_id=None,
            icmp_seq=None,
            src_ip="10.0.0.254",  # Router
            dst_ip="192.168.1.100",
        ),
        # Destination unreachable - Port unreachable
        create_icmp_packet(
            timestamp=base_time + 0.1,
            icmp_type=3,
            icmp_code=3,  # Port unreachable
            icmp_id=None,
            icmp_seq=None,
            src_ip="10.0.0.1",
            dst_ip="192.168.1.100",
        ),
    ]

    flow = Flow.from_first_packet(packets[0])
    for pkt in packets[1:]:
        flow.add_packet(pkt)

    return flow


def create_icmp_ttl_exceeded_flow() -> Flow:
    """Create a flow with ICMP time exceeded (traceroute-like).

    Returns:
        Flow with TTL exceeded messages.
    """
    base_time = 1000.0

    packets = [
        # Time exceeded from first hop
        create_icmp_packet(
            timestamp=base_time,
            icmp_type=11,  # Time exceeded
            icmp_code=0,  # TTL exceeded in transit
            icmp_id=None,
            icmp_seq=None,
            src_ip="10.0.0.254",
            dst_ip="192.168.1.100",
        ),
        # Time exceeded from second hop
        create_icmp_packet(
            timestamp=base_time + 0.1,
            icmp_type=11,
            icmp_code=0,
            icmp_id=None,
            icmp_seq=None,
            src_ip="10.0.1.1",
            dst_ip="192.168.1.100",
        ),
    ]

    flow = Flow.from_first_packet(packets[0])
    for pkt in packets[1:]:
        flow.add_packet(pkt)

    return flow


# =============================================================================
# Combined/Complex Fixtures
# =============================================================================

def create_full_featured_tcp_flow() -> Flow:
    """Create a comprehensive TCP flow with all features populated.

    This flow includes:
    - MAC addresses and VLAN
    - IP TTL, ToS, flags
    - TCP handshake
    - TCP options (MSS, WS, timestamps, SACK)
    - Data transfer
    - FIN termination

    Returns:
        Fully-featured TCP flow.
    """
    base_time = 1000.0
    client_isn = 1000000
    server_isn = 2000000
    ts_base_client = 100000
    ts_base_server = 200000

    packets = [
        # SYN from client
        Packet(
            timestamp=base_time,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            protocol=6,
            payload_len=0,
            total_len=60,
            tcp_flags=0x02,
            # MAC
            src_mac="aa:bb:cc:dd:ee:01",
            dst_mac="10:22:33:44:55:66",
            eth_type=0x0800,
            vlan_id=100,
            # IP
            ip_ttl=64,
            ip_id=1000,
            ip_tos=0,
            ip_flags=0x02,
            ip_version=4,
            # TCP
            tcp_seq=client_isn,
            tcp_ack=0,
            tcp_window=65535,
            tcp_mss=1460,
            tcp_window_scale=7,
            tcp_sack_permitted=True,
            tcp_timestamp=(ts_base_client, 0),
        ),
        # SYN-ACK from server
        Packet(
            timestamp=base_time + 0.02,
            src_ip="10.0.0.1",
            dst_ip="192.168.1.100",
            src_port=443,
            dst_port=54321,
            protocol=6,
            payload_len=0,
            total_len=60,
            tcp_flags=0x12,
            src_mac="10:22:33:44:55:66",
            dst_mac="aa:bb:cc:dd:ee:01",
            eth_type=0x0800,
            vlan_id=100,
            ip_ttl=64,
            ip_id=5000,
            ip_tos=0,
            ip_flags=0x02,
            ip_version=4,
            tcp_seq=server_isn,
            tcp_ack=client_isn + 1,
            tcp_window=65535,
            tcp_mss=1460,
            tcp_window_scale=8,
            tcp_sack_permitted=True,
            tcp_timestamp=(ts_base_server, ts_base_client),
        ),
        # ACK from client
        Packet(
            timestamp=base_time + 0.04,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            protocol=6,
            payload_len=0,
            total_len=52,
            tcp_flags=0x10,
            src_mac="aa:bb:cc:dd:ee:01",
            dst_mac="10:22:33:44:55:66",
            eth_type=0x0800,
            vlan_id=100,
            ip_ttl=64,
            ip_id=1001,
            ip_tos=0,
            ip_flags=0x02,
            ip_version=4,
            tcp_seq=client_isn + 1,
            tcp_ack=server_isn + 1,
            tcp_window=65535,
            tcp_timestamp=(ts_base_client + 40, ts_base_server),
        ),
        # Data from client
        Packet(
            timestamp=base_time + 0.05,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            protocol=6,
            payload_len=500,
            total_len=552,
            tcp_flags=0x18,
            src_mac="aa:bb:cc:dd:ee:01",
            dst_mac="10:22:33:44:55:66",
            eth_type=0x0800,
            vlan_id=100,
            ip_ttl=64,
            ip_id=1002,
            ip_tos=0,
            ip_flags=0x02,
            ip_version=4,
            tcp_seq=client_isn + 1,
            tcp_ack=server_isn + 1,
            tcp_window=65535,
            tcp_timestamp=(ts_base_client + 50, ts_base_server),
        ),
        # Data from server
        Packet(
            timestamp=base_time + 0.07,
            src_ip="10.0.0.1",
            dst_ip="192.168.1.100",
            src_port=443,
            dst_port=54321,
            protocol=6,
            payload_len=1400,
            total_len=1452,
            tcp_flags=0x18,
            src_mac="10:22:33:44:55:66",
            dst_mac="aa:bb:cc:dd:ee:01",
            eth_type=0x0800,
            vlan_id=100,
            ip_ttl=64,
            ip_id=5001,
            ip_tos=0,
            ip_flags=0x02,
            ip_version=4,
            tcp_seq=server_isn + 1,
            tcp_ack=client_isn + 501,
            tcp_window=65535,
            tcp_timestamp=(ts_base_server + 70, ts_base_client + 50),
        ),
        # FIN from client
        Packet(
            timestamp=base_time + 1.0,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            protocol=6,
            payload_len=0,
            total_len=52,
            tcp_flags=0x11,  # FIN-ACK
            src_mac="aa:bb:cc:dd:ee:01",
            dst_mac="10:22:33:44:55:66",
            eth_type=0x0800,
            vlan_id=100,
            ip_ttl=64,
            ip_id=1003,
            ip_tos=0,
            ip_flags=0x02,
            ip_version=4,
            tcp_seq=client_isn + 501,
            tcp_ack=server_isn + 1401,
            tcp_window=65535,
            tcp_timestamp=(ts_base_client + 1000, ts_base_server + 70),
        ),
        # FIN-ACK from server
        Packet(
            timestamp=base_time + 1.02,
            src_ip="10.0.0.1",
            dst_ip="192.168.1.100",
            src_port=443,
            dst_port=54321,
            protocol=6,
            payload_len=0,
            total_len=52,
            tcp_flags=0x11,  # FIN-ACK
            src_mac="10:22:33:44:55:66",
            dst_mac="aa:bb:cc:dd:ee:01",
            eth_type=0x0800,
            vlan_id=100,
            ip_ttl=64,
            ip_id=5002,
            ip_tos=0,
            ip_flags=0x02,
            ip_version=4,
            tcp_seq=server_isn + 1401,
            tcp_ack=client_isn + 502,
            tcp_window=65535,
            tcp_timestamp=(ts_base_server + 1020, ts_base_client + 1000),
        ),
    ]

    flow = Flow.from_first_packet(packets[0])
    for pkt in packets[1:]:
        flow.add_packet(pkt)

    return flow


def create_empty_flow() -> Flow:
    """Create a minimal flow with a single packet (edge case testing).

    Returns:
        Single-packet flow.
    """
    pkt = Packet(
        timestamp=1000.0,
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        src_port=54321,
        dst_port=443,
        protocol=6,
        payload_len=0,
        total_len=40,
        tcp_flags=0x02,
    )
    return Flow.from_first_packet(pkt)


def create_non_tcp_flow() -> Flow:
    """Create a UDP flow (for testing TCP extractors with non-TCP traffic).

    Returns:
        UDP flow.
    """
    packets = []
    base_time = 1000.0

    for i in range(5):
        is_forward = i % 2 == 0
        pkt = Packet(
            timestamp=base_time + i * 0.01,
            src_ip="192.168.1.100" if is_forward else "10.0.0.1",
            dst_ip="10.0.0.1" if is_forward else "192.168.1.100",
            src_port=54321 if is_forward else 443,
            dst_port=443 if is_forward else 54321,
            protocol=17,  # UDP
            payload_len=100 + i * 10,
            total_len=128 + i * 10,
            tcp_flags=None,
        )
        packets.append(pkt)

    flow = Flow.from_first_packet(packets[0])
    for pkt in packets[1:]:
        flow.add_packet(pkt)

    return flow
