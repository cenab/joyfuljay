"""Deterministic direction semantics for bidirectional flows.

This module defines the direction semantics used throughout JoyfulJay:
- Forward = direction of first packet (initiator -> responder)
- Backward = response direction (responder -> initiator)
- src_to_dst = initiator to responder
- dst_to_src = responder to initiator

The first packet's sender is always considered the initiator, ensuring
consistent direction labels across different runs.
"""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from joyfuljay.core.flow import Flow
    from joyfuljay.core.packet import Packet


class Direction(Enum):
    """Packet direction within a bidirectional flow.

    Attributes:
        FORWARD: From initiator to responder (first packet direction).
        BACKWARD: From responder to initiator (response direction).
    """
    FORWARD = "forward"
    BACKWARD = "backward"


class DirectionSemantics(Enum):
    """Semantics for directional feature naming.

    JoyfulJay uses two naming conventions for directional features:

    1. src_to_dst / dst_to_src:
       - src = initiator (sender of first packet)
       - dst = responder
       - Example: bytes_src_to_dst, packets_dst_to_src

    2. fwd / bwd (alias):
       - fwd = forward = src_to_dst = initiator -> responder
       - bwd = backward = dst_to_src = responder -> initiator
       - Example: fwd_packet_count, bwd_iat_mean
    """
    SRC_TO_DST = "src_to_dst"
    DST_TO_SRC = "dst_to_src"
    FORWARD = "fwd"
    BACKWARD = "bwd"
    BIDIRECTIONAL = "bidir"


def determine_direction(
    packet_src_ip: str,
    packet_src_port: int,
    initiator_ip: str,
    initiator_port: int,
) -> Direction:
    """Determine the direction of a packet within a flow.

    A packet is considered FORWARD if it's from the initiator,
    BACKWARD if it's from the responder.

    Args:
        packet_src_ip: Source IP of the packet.
        packet_src_port: Source port of the packet.
        initiator_ip: IP of the flow initiator (first packet sender).
        initiator_port: Port of the flow initiator.

    Returns:
        Direction.FORWARD if packet is from initiator, BACKWARD otherwise.
    """
    if packet_src_ip == initiator_ip and packet_src_port == initiator_port:
        return Direction.FORWARD
    return Direction.BACKWARD


def get_direction_label(
    direction: Direction,
    style: str = "src_dst",
) -> str:
    """Get the label string for a direction.

    Args:
        direction: The direction enum value.
        style: Label style, one of:
            - "src_dst": Returns "src_to_dst" or "dst_to_src"
            - "fwd_bwd": Returns "fwd" or "bwd"
            - "full": Returns "forward" or "backward"

    Returns:
        The direction label string.

    Raises:
        ValueError: If style is not recognized.
    """
    if style == "src_dst":
        return "src_to_dst" if direction == Direction.FORWARD else "dst_to_src"
    elif style == "fwd_bwd":
        return "fwd" if direction == Direction.FORWARD else "bwd"
    elif style == "full":
        return direction.value
    else:
        raise ValueError(f"Unknown style: {style}. Use 'src_dst', 'fwd_bwd', or 'full'.")


def packet_direction(packet: Packet, flow: Flow) -> Direction:
    """Determine the direction of a packet within its flow.

    Convenience function that uses the flow's initiator information.

    Args:
        packet: The packet to classify.
        flow: The flow the packet belongs to.

    Returns:
        Direction.FORWARD if packet is from initiator, BACKWARD otherwise.
    """
    return determine_direction(
        packet_src_ip=packet.src_ip,
        packet_src_port=packet.src_port,
        initiator_ip=flow.initiator_ip,
        initiator_port=flow.initiator_port,
    )


def is_initiator_packet(packet: Packet, flow: Flow) -> bool:
    """Check if a packet is from the flow initiator.

    Args:
        packet: The packet to check.
        flow: The flow the packet belongs to.

    Returns:
        True if packet is from the initiator, False otherwise.
    """
    return packet_direction(packet, flow) == Direction.FORWARD


def is_responder_packet(packet: Packet, flow: Flow) -> bool:
    """Check if a packet is from the flow responder.

    Args:
        packet: The packet to check.
        flow: The flow the packet belongs to.

    Returns:
        True if packet is from the responder, False otherwise.
    """
    return packet_direction(packet, flow) == Direction.BACKWARD
