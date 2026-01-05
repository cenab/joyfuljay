"""Tests for remote protocol compression handling."""

from __future__ import annotations

from joyfuljay.core.packet import Packet
from joyfuljay.remote.protocol import (
    deserialize_packet_compressed,
    serialize_packet_compressed,
)


def test_packet_compression_roundtrip() -> None:
    packet = Packet(
        timestamp=1.0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=1234,
        dst_port=443,
        protocol=6,
        payload_len=5,
        total_len=45,
        raw_payload=b"hello",
    )

    data = serialize_packet_compressed(packet, compress=True)
    restored = deserialize_packet_compressed(data)

    assert restored.src_ip == packet.src_ip
    assert restored.dst_ip == packet.dst_ip
    assert restored.raw_payload == packet.raw_payload


def test_packet_compression_disabled() -> None:
    packet = Packet(
        timestamp=1.0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=1234,
        dst_port=443,
        protocol=6,
        payload_len=5,
        total_len=45,
        raw_payload=b"hello",
    )

    data = serialize_packet_compressed(packet, compress=False)
    restored = deserialize_packet_compressed(data)

    assert restored.src_port == packet.src_port
