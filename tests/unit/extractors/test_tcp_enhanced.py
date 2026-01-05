"""Tests for enhanced TCP extractor (#53).

Tests the Tranalyzer-compatible features added to TCPExtractor:
- tcp_fstat (flow status bitmap)
- tcp_flags_agg (aggregate flags)
- tcp_flags_fwd (forward direction flags)
- tcp_flags_bwd (backward direction flags)
"""

from __future__ import annotations

import pytest

from joyfuljay.core.flow import Flow
from joyfuljay.core.packet import Packet
from joyfuljay.extractors.tcp import TCPExtractor

from tests.fixtures.tranalyzer_packets import (
    create_full_featured_tcp_flow,
    create_mac_flow,
    create_non_tcp_flow,
    create_tcp_handshake_flow,
)


class TestTCPExtractorEnhanced:
    """Tests for enhanced TCPExtractor features (#53)."""

    @pytest.fixture
    def extractor(self) -> TCPExtractor:
        """Create a TCP extractor."""
        return TCPExtractor()

    def test_feature_names_include_tranalyzer(self, extractor: TCPExtractor) -> None:
        """Test that Tranalyzer-compatible feature names are present."""
        names = extractor.feature_names
        assert "tcp_fstat" in names
        assert "tcp_flags_agg" in names
        assert "tcp_flags_fwd" in names
        assert "tcp_flags_bwd" in names

    def test_extract_tcp_fstat_complete(self, extractor: TCPExtractor) -> None:
        """Test tcp_fstat for complete TCP connection."""
        flow = create_full_featured_tcp_flow()
        features = extractor.extract(flow)

        fstat = features["tcp_fstat"]
        # Bit 0: SYN from initiator
        assert fstat & 0x01
        # Bit 1: SYN-ACK from responder
        assert fstat & 0x02
        # Bit 2: ACK seen (handshake complete)
        assert fstat & 0x04
        # Bit 3: FIN from initiator
        assert fstat & 0x08
        # Bit 4: FIN from responder
        assert fstat & 0x10
        # Bit 6: Data transferred
        assert fstat & 0x40

    def test_extract_tcp_fstat_syn_only(self, extractor: TCPExtractor) -> None:
        """Test tcp_fstat for SYN-only flow."""
        pkt = Packet(
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
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        fstat = features["tcp_fstat"]
        # Only SYN bit should be set
        assert fstat & 0x01
        assert not (fstat & 0x02)  # No SYN-ACK

    def test_extract_tcp_fstat_rst(self, extractor: TCPExtractor) -> None:
        """Test tcp_fstat with RST."""
        packets = [
            Packet(
                timestamp=1000.0,
                src_ip="192.168.1.100",
                dst_ip="10.0.0.1",
                src_port=54321,
                dst_port=443,
                protocol=6,
                payload_len=0,
                total_len=40,
                tcp_flags=0x02,  # SYN
            ),
            Packet(
                timestamp=1000.01,
                src_ip="10.0.0.1",
                dst_ip="192.168.1.100",
                src_port=443,
                dst_port=54321,
                protocol=6,
                payload_len=0,
                total_len=40,
                tcp_flags=0x04,  # RST
            ),
        ]

        flow = Flow.from_first_packet(packets[0])
        flow.add_packet(packets[1])

        features = extractor.extract(flow)

        fstat = features["tcp_fstat"]
        # Bit 5: RST seen
        assert fstat & 0x20

    def test_extract_tcp_fstat_data(self, extractor: TCPExtractor) -> None:
        """Test tcp_fstat data transfer bit."""
        packets = [
            Packet(
                timestamp=1000.0,
                src_ip="192.168.1.100",
                dst_ip="10.0.0.1",
                src_port=54321,
                dst_port=443,
                protocol=6,
                payload_len=100,  # Has data
                total_len=140,
                tcp_flags=0x18,  # PSH-ACK
            ),
        ]

        flow = Flow.from_first_packet(packets[0])
        features = extractor.extract(flow)

        fstat = features["tcp_fstat"]
        # Bit 6: Data transferred
        assert fstat & 0x40

    def test_extract_tcp_fstat_anomaly(self, extractor: TCPExtractor) -> None:
        """Test tcp_fstat anomaly bit."""
        # Xmas tree scan: FIN+PSH+URG
        pkt = Packet(
            timestamp=1000.0,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            protocol=6,
            payload_len=0,
            total_len=40,
            tcp_flags=0x29,  # FIN+PSH+URG
        )
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        fstat = features["tcp_fstat"]
        # Bit 7: State anomaly detected
        assert fstat & 0x80

    def test_extract_tcp_flags_agg(self, extractor: TCPExtractor) -> None:
        """Test aggregate flags bitmap."""
        flow = create_tcp_handshake_flow()
        features = extractor.extract(flow)

        flags_agg = features["tcp_flags_agg"]
        # Should have SYN (0x02) and ACK (0x10) at minimum
        assert flags_agg & 0x02  # SYN
        assert flags_agg & 0x10  # ACK

    def test_extract_tcp_flags_agg_all_flags(self, extractor: TCPExtractor) -> None:
        """Test aggregate includes all seen flags."""
        packets = [
            Packet(
                timestamp=1000.0,
                src_ip="192.168.1.100",
                dst_ip="10.0.0.1",
                src_port=54321,
                dst_port=443,
                protocol=6,
                payload_len=0,
                total_len=40,
                tcp_flags=0x02,  # SYN
            ),
            Packet(
                timestamp=1000.01,
                src_ip="10.0.0.1",
                dst_ip="192.168.1.100",
                src_port=443,
                dst_port=54321,
                protocol=6,
                payload_len=0,
                total_len=40,
                tcp_flags=0x12,  # SYN-ACK
            ),
            Packet(
                timestamp=1000.02,
                src_ip="192.168.1.100",
                dst_ip="10.0.0.1",
                src_port=54321,
                dst_port=443,
                protocol=6,
                payload_len=100,
                total_len=140,
                tcp_flags=0x18,  # PSH-ACK
            ),
        ]

        flow = Flow.from_first_packet(packets[0])
        for pkt in packets[1:]:
            flow.add_packet(pkt)

        features = extractor.extract(flow)

        flags_agg = features["tcp_flags_agg"]
        # OR of all: 0x02 | 0x12 | 0x18 = 0x1A
        assert flags_agg & 0x02  # SYN
        assert flags_agg & 0x10  # ACK
        assert flags_agg & 0x08  # PSH

    def test_extract_tcp_flags_fwd(self, extractor: TCPExtractor) -> None:
        """Test forward direction flags."""
        flow = create_tcp_handshake_flow()
        features = extractor.extract(flow)

        flags_fwd = features["tcp_flags_fwd"]
        # Forward should have SYN and ACK
        assert flags_fwd & 0x02  # SYN (from client)
        assert flags_fwd & 0x10  # ACK

    def test_extract_tcp_flags_bwd(self, extractor: TCPExtractor) -> None:
        """Test backward direction flags."""
        flow = create_tcp_handshake_flow()
        features = extractor.extract(flow)

        flags_bwd = features["tcp_flags_bwd"]
        # Backward should have SYN-ACK (0x12)
        assert flags_bwd & 0x02  # SYN (from server)
        assert flags_bwd & 0x10  # ACK

    def test_extract_tcp_flags_direction_separation(self, extractor: TCPExtractor) -> None:
        """Test that forward and backward flags are separated."""
        packets = [
            # Client SYN
            Packet(
                timestamp=1000.0,
                src_ip="192.168.1.100",
                dst_ip="10.0.0.1",
                src_port=54321,
                dst_port=443,
                protocol=6,
                payload_len=0,
                total_len=40,
                tcp_flags=0x02,  # SYN only
            ),
            # Server RST
            Packet(
                timestamp=1000.01,
                src_ip="10.0.0.1",
                dst_ip="192.168.1.100",
                src_port=443,
                dst_port=54321,
                protocol=6,
                payload_len=0,
                total_len=40,
                tcp_flags=0x14,  # RST-ACK
            ),
        ]

        flow = Flow.from_first_packet(packets[0])
        flow.add_packet(packets[1])

        features = extractor.extract(flow)

        # Forward should only have SYN
        assert features["tcp_flags_fwd"] == 0x02
        # Backward should have RST-ACK
        assert features["tcp_flags_bwd"] == 0x14

    def test_extract_non_tcp_flow(self, extractor: TCPExtractor) -> None:
        """Test extraction from non-TCP flow."""
        flow = create_non_tcp_flow()
        features = extractor.extract(flow)

        assert features["tcp_is_tcp"] is False
        assert features["tcp_fstat"] == 0
        assert features["tcp_flags_agg"] == 0

    def test_extract_existing_features_preserved(self, extractor: TCPExtractor) -> None:
        """Test that existing TCP features still work."""
        flow = create_tcp_handshake_flow()
        features = extractor.extract(flow)

        # Original features should still be present
        assert "tcp_is_tcp" in features
        assert "tcp_syn_count" in features
        assert "tcp_synack_count" in features
        assert "tcp_complete_handshake" in features
        assert features["tcp_is_tcp"] is True

    def test_validate_all_features_present(self, extractor: TCPExtractor) -> None:
        """Test that all enhanced feature names are present."""
        flow = create_full_featured_tcp_flow()
        features = extractor.extract(flow)

        enhanced_features = ["tcp_fstat", "tcp_flags_agg", "tcp_flags_fwd", "tcp_flags_bwd"]
        for name in enhanced_features:
            assert name in features, f"Missing enhanced feature: {name}"

    def test_extract_handshake_and_data(self, extractor: TCPExtractor) -> None:
        """Test complete handshake with data transfer."""
        flow = create_full_featured_tcp_flow()
        features = extractor.extract(flow)

        # Should detect complete handshake
        assert features["tcp_complete_handshake"] is True
        # Should have data packets
        assert features["tcp_data_packets"] > 0
        # Should have proper close
        assert features["tcp_graceful_close"] is True
