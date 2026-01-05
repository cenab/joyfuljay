"""Pytest fixtures and configuration for JoyfulJay tests."""

from __future__ import annotations

from typing import Generator

import pytest

from joyfuljay.core.config import Config
from joyfuljay.core.flow import Flow, FlowKey, FlowTable
from joyfuljay.core.packet import Packet


@pytest.fixture
def sample_packet() -> Packet:
    """Create a sample TCP packet for testing."""
    return Packet(
        timestamp=1000.0,
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        src_port=54321,
        dst_port=443,
        protocol=6,  # TCP
        payload_len=100,
        total_len=140,
        tcp_flags=0x18,  # PSH + ACK
        raw_payload=b"\x16\x03\x01" + b"\x00" * 97,  # TLS-like
    )


@pytest.fixture
def sample_packet_reverse() -> Packet:
    """Create a reverse direction packet."""
    return Packet(
        timestamp=1000.05,
        src_ip="10.0.0.1",
        dst_ip="192.168.1.100",
        src_port=443,
        dst_port=54321,
        protocol=6,
        payload_len=500,
        total_len=540,
        tcp_flags=0x18,
    )


@pytest.fixture
def sample_packets() -> list[Packet]:
    """Create a sequence of packets simulating a flow."""
    base_time = 1000.0
    return [
        # Client -> Server (initiator)
        Packet(
            timestamp=base_time,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            protocol=6,
            payload_len=0,
            total_len=40,
            tcp_flags=0x02,  # SYN
        ),
        # Server -> Client
        Packet(
            timestamp=base_time + 0.01,
            src_ip="10.0.0.1",
            dst_ip="192.168.1.100",
            src_port=443,
            dst_port=54321,
            protocol=6,
            payload_len=0,
            total_len=40,
            tcp_flags=0x12,  # SYN-ACK
        ),
        # Client -> Server
        Packet(
            timestamp=base_time + 0.02,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            protocol=6,
            payload_len=0,
            total_len=40,
            tcp_flags=0x10,  # ACK
        ),
        # Client -> Server (data)
        Packet(
            timestamp=base_time + 0.03,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            protocol=6,
            payload_len=200,
            total_len=240,
            tcp_flags=0x18,  # PSH-ACK
        ),
        # Server -> Client (data)
        Packet(
            timestamp=base_time + 0.05,
            src_ip="10.0.0.1",
            dst_ip="192.168.1.100",
            src_port=443,
            dst_port=54321,
            protocol=6,
            payload_len=1400,
            total_len=1440,
            tcp_flags=0x18,
        ),
        # Server -> Client (more data)
        Packet(
            timestamp=base_time + 0.06,
            src_ip="10.0.0.1",
            dst_ip="192.168.1.100",
            src_port=443,
            dst_port=54321,
            protocol=6,
            payload_len=1400,
            total_len=1440,
            tcp_flags=0x18,
        ),
        # Client -> Server (ACK)
        Packet(
            timestamp=base_time + 0.07,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            protocol=6,
            payload_len=0,
            total_len=40,
            tcp_flags=0x10,
        ),
        # Client -> Server (FIN)
        Packet(
            timestamp=base_time + 1.0,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            protocol=6,
            payload_len=0,
            total_len=40,
            tcp_flags=0x11,  # FIN-ACK
        ),
    ]


@pytest.fixture
def sample_flow(sample_packets: list[Packet]) -> Flow:
    """Create a sample flow from packet sequence."""
    flow = Flow.from_first_packet(sample_packets[0])
    for packet in sample_packets[1:]:
        flow.add_packet(packet)
    return flow


@pytest.fixture
def flow_table() -> FlowTable:
    """Create an empty flow table."""
    return FlowTable(timeout=60.0)


@pytest.fixture
def default_config() -> Config:
    """Create a default configuration."""
    return Config()


@pytest.fixture
def minimal_config() -> Config:
    """Create a minimal configuration for fast testing."""
    return Config(
        flow_timeout=10.0,
        features=["flow_meta", "timing"],
        include_ip_addresses=False,
        include_ports=False,
    )
