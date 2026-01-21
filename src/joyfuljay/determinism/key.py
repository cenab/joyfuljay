"""Deterministic flow key computation.

This module provides utilities for computing flow keys with canonical ordering
to ensure reproducible flow identification across different runs and systems.

The key guarantees are:
- Same PCAP + same config = same flow keys
- Bidirectional flows use canonical ordering (lower IP first)
- Same IP: use port ordering
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from joyfuljay.core.packet import Packet


class FlowKeyComponents(NamedTuple):
    """Components of a normalized flow key.

    Attributes:
        src_ip: Canonical source IP (lexicographically smaller).
        dst_ip: Canonical destination IP.
        src_port: Port associated with src_ip.
        dst_port: Port associated with dst_ip.
        protocol: IP protocol number (6=TCP, 17=UDP, etc.).
        reversed: True if endpoints were swapped during normalization.
    """
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    reversed: bool


def normalize_endpoint_pair(
    ip_a: str,
    port_a: int,
    ip_b: str,
    port_b: int,
) -> tuple[str, int, str, int, bool]:
    """Normalize an endpoint pair to canonical ordering.

    The canonical ordering ensures that the same bidirectional flow
    always produces the same key, regardless of which direction
    the first packet was observed.

    Ordering rules:
    1. Lower IP address is always first
    2. If IPs are equal, lower port is first

    Args:
        ip_a: First IP address.
        port_a: Port associated with ip_a.
        ip_b: Second IP address.
        port_b: Port associated with ip_b.

    Returns:
        Tuple of (canonical_ip_a, canonical_port_a, canonical_ip_b,
                  canonical_port_b, reversed) where reversed indicates
                  if the endpoints were swapped.
    """
    if ip_a < ip_b:
        return (ip_a, port_a, ip_b, port_b, False)
    elif ip_a > ip_b:
        return (ip_b, port_b, ip_a, port_a, True)
    else:
        # Same IP: use port ordering
        if port_a <= port_b:
            return (ip_a, port_a, ip_b, port_b, False)
        else:
            return (ip_b, port_b, ip_a, port_a, True)


def compute_flow_key(
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    protocol: int,
) -> FlowKeyComponents:
    """Compute a deterministic flow key from 5-tuple.

    This function applies canonical ordering to ensure that packets
    in either direction of a bidirectional flow produce the same key.

    Args:
        src_ip: Source IP address from the packet.
        src_port: Source port from the packet.
        dst_ip: Destination IP address from the packet.
        dst_port: Destination port from the packet.
        protocol: IP protocol number.

    Returns:
        FlowKeyComponents with normalized values and reversal flag.

    Example:
        >>> # These produce the same key
        >>> key1 = compute_flow_key("10.0.0.1", 12345, "10.0.0.2", 443, 6)
        >>> key2 = compute_flow_key("10.0.0.2", 443, "10.0.0.1", 12345, 6)
        >>> assert key1[:5] == key2[:5]  # Same canonical key
        >>> assert key1.reversed != key2.reversed  # Different reversal flag
    """
    norm_src_ip, norm_src_port, norm_dst_ip, norm_dst_port, reversed_flag = (
        normalize_endpoint_pair(src_ip, src_port, dst_ip, dst_port)
    )

    return FlowKeyComponents(
        src_ip=norm_src_ip,
        dst_ip=norm_dst_ip,
        src_port=norm_src_port,
        dst_port=norm_dst_port,
        protocol=protocol,
        reversed=reversed_flag,
    )


def compute_flow_key_from_packet(packet: Packet) -> FlowKeyComponents:
    """Compute a deterministic flow key from a Packet object.

    Convenience wrapper around compute_flow_key for Packet objects.

    Args:
        packet: The packet to compute a key from.

    Returns:
        FlowKeyComponents with normalized values.
    """
    return compute_flow_key(
        src_ip=packet.src_ip,
        src_port=packet.src_port,
        dst_ip=packet.dst_ip,
        dst_port=packet.dst_port,
        protocol=packet.protocol,
    )


def flow_key_tuple(components: FlowKeyComponents) -> tuple[str, int, str, int, int]:
    """Extract the 5-tuple from FlowKeyComponents for use as dict key.

    Args:
        components: The flow key components.

    Returns:
        A tuple of (src_ip, src_port, dst_ip, dst_port, protocol).
    """
    return (
        components.src_ip,
        components.src_port,
        components.dst_ip,
        components.dst_port,
        components.protocol,
    )
