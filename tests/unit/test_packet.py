"""Tests for Packet data structure."""

from __future__ import annotations

import pytest

from joyfuljay.core.packet import Packet


class TestPacket:
    """Tests for the Packet dataclass."""

    def test_packet_creation(self, sample_packet: Packet) -> None:
        """Test basic packet creation."""
        assert sample_packet.src_ip == "192.168.1.100"
        assert sample_packet.dst_ip == "10.0.0.1"
        assert sample_packet.src_port == 54321
        assert sample_packet.dst_port == 443
        assert sample_packet.protocol == 6
        assert sample_packet.payload_len == 100
        assert sample_packet.total_len == 140

    def test_is_tcp(self, sample_packet: Packet) -> None:
        """Test TCP protocol detection."""
        assert sample_packet.is_tcp is True
        assert sample_packet.is_udp is False

    def test_is_udp(self) -> None:
        """Test UDP protocol detection."""
        udp_packet = Packet(
            timestamp=1000.0,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=53,
            protocol=17,  # UDP
            payload_len=50,
            total_len=78,
        )
        assert udp_packet.is_udp is True
        assert udp_packet.is_tcp is False

    def test_has_payload(self, sample_packet: Packet) -> None:
        """Test payload detection."""
        assert sample_packet.has_payload is True

        empty_packet = Packet(
            timestamp=1000.0,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            protocol=6,
            payload_len=0,
            total_len=40,
            tcp_flags=0x10,
        )
        assert empty_packet.has_payload is False

    def test_tcp_flags(self) -> None:
        """Test TCP flag detection."""
        syn_packet = Packet(
            timestamp=1000.0,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            protocol=6,
            payload_len=0,
            total_len=40,
            tcp_flags=0x02,  # SYN
        )
        assert syn_packet.is_syn is True
        assert syn_packet.is_syn_ack is False
        assert syn_packet.is_fin is False

        syn_ack_packet = Packet(
            timestamp=1000.0,
            src_ip="10.0.0.1",
            dst_ip="192.168.1.100",
            src_port=443,
            dst_port=54321,
            protocol=6,
            payload_len=0,
            total_len=40,
            tcp_flags=0x12,  # SYN-ACK
        )
        assert syn_ack_packet.is_syn_ack is True
        assert syn_ack_packet.is_syn is False

        fin_packet = Packet(
            timestamp=1000.0,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            protocol=6,
            payload_len=0,
            total_len=40,
            tcp_flags=0x11,  # FIN-ACK
        )
        assert fin_packet.is_fin is True

    def test_five_tuple(self, sample_packet: Packet) -> None:
        """Test 5-tuple extraction."""
        five_tuple = sample_packet.five_tuple()
        assert five_tuple == ("192.168.1.100", 54321, "10.0.0.1", 443, 6)

    def test_packet_immutability(self, sample_packet: Packet) -> None:
        """Test that packets are immutable (frozen dataclass)."""
        with pytest.raises(AttributeError):
            sample_packet.src_ip = "1.2.3.4"  # type: ignore
