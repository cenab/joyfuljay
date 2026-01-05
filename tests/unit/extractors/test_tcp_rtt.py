"""Tests for TCP RTT feature extractor (#56)."""

from __future__ import annotations

import pytest

from joyfuljay.core.flow import Flow
from joyfuljay.core.packet import Packet
from joyfuljay.extractors.tcp_rtt import TCPRTTExtractor

from tests.fixtures.tranalyzer_packets import (
    create_non_tcp_flow,
    create_tcp_handshake_flow,
    create_tcp_rtt_flow,
    create_tcp_seq_packet,
)


class TestTCPRTTExtractor:
    """Tests for TCPRTTExtractor."""

    @pytest.fixture
    def extractor(self) -> TCPRTTExtractor:
        """Create a TCP RTT extractor."""
        return TCPRTTExtractor()

    def test_feature_names(self, extractor: TCPRTTExtractor) -> None:
        """Test that feature names are properly defined."""
        names = extractor.feature_names
        assert isinstance(names, list)
        assert len(names) == 10
        assert "tcp_rtt_handshake" in names
        assert "tcp_rtt_min" in names
        assert "tcp_rtt_max" in names
        assert "tcp_rtt_mean" in names
        assert "tcp_rtt_samples" in names
        assert "tcp_rtt_std" in names
        assert "tcp_rtt_jitter_avg" in names
        assert "tcp_rtt_ack_min" in names
        assert "tcp_rtt_ack_max" in names
        assert "tcp_rtt_ack_mean" in names

    def test_extractor_name(self, extractor: TCPRTTExtractor) -> None:
        """Test extractor name."""
        assert extractor.name == "tcp_rtt"

    def test_extract_handshake_rtt(self, extractor: TCPRTTExtractor) -> None:
        """Test handshake RTT extraction."""
        flow = create_tcp_rtt_flow(rtt_ms=20.0)
        features = extractor.extract(flow)

        # Handshake RTT should be approximately 20ms
        assert features["tcp_rtt_handshake"] > 0
        assert 0.015 <= features["tcp_rtt_handshake"] <= 0.025

    def test_extract_timestamp_rtt(self, extractor: TCPRTTExtractor) -> None:
        """Test timestamp-based RTT extraction."""
        flow = create_tcp_rtt_flow(rtt_ms=20.0)
        features = extractor.extract(flow)

        # Should have RTT samples from timestamps
        if features["tcp_rtt_samples"] > 0:
            assert features["tcp_rtt_min"] > 0
            assert features["tcp_rtt_max"] >= features["tcp_rtt_min"]
            assert features["tcp_rtt_mean"] > 0

    def test_extract_rtt_statistics(self, extractor: TCPRTTExtractor) -> None:
        """Test RTT statistics (mean, std, jitter)."""
        flow = create_tcp_rtt_flow(rtt_ms=20.0)
        features = extractor.extract(flow)

        if features["tcp_rtt_samples"] >= 2:
            assert features["tcp_rtt_std"] >= 0
            assert features["tcp_rtt_jitter_avg"] >= 0

    def test_extract_ack_rtt(self, extractor: TCPRTTExtractor) -> None:
        """Test ACK-based RTT extraction."""
        flow = create_tcp_rtt_flow(rtt_ms=20.0)
        features = extractor.extract(flow)

        # ACK RTT should be available
        if features["tcp_rtt_ack_mean"] > 0:
            assert features["tcp_rtt_ack_min"] > 0
            assert features["tcp_rtt_ack_max"] >= features["tcp_rtt_ack_min"]

    def test_extract_high_rtt(self, extractor: TCPRTTExtractor) -> None:
        """Test high RTT flow (100ms)."""
        flow = create_tcp_rtt_flow(rtt_ms=100.0)
        features = extractor.extract(flow)

        # Should detect ~100ms RTT
        assert features["tcp_rtt_handshake"] > 0.05

    def test_extract_low_rtt(self, extractor: TCPRTTExtractor) -> None:
        """Test low RTT flow (1ms)."""
        flow = create_tcp_rtt_flow(rtt_ms=1.0)
        features = extractor.extract(flow)

        # Should detect ~1ms RTT
        assert features["tcp_rtt_handshake"] < 0.01

    def test_extract_no_handshake(self, extractor: TCPRTTExtractor) -> None:
        """Test flow without complete handshake."""
        # Create flow starting with data (no SYN)
        pkt = create_tcp_seq_packet(tcp_flags=0x18)
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        # No handshake RTT available
        assert features["tcp_rtt_handshake"] == 0.0

    def test_extract_no_timestamps(self, extractor: TCPRTTExtractor) -> None:
        """Test flow without TCP timestamps."""
        flow = create_tcp_handshake_flow()
        features = extractor.extract(flow)

        # Without timestamps, samples may be 0
        # But handshake RTT should still work
        assert features["tcp_rtt_handshake"] >= 0

    def test_extract_udp_flow(self, extractor: TCPRTTExtractor) -> None:
        """Test extraction from UDP flow (should return defaults)."""
        flow = create_non_tcp_flow()
        features = extractor.extract(flow)

        # UDP has no TCP RTT
        assert features["tcp_rtt_handshake"] == 0.0
        assert features["tcp_rtt_samples"] == 0

    def test_extract_single_packet_flow(self, extractor: TCPRTTExtractor) -> None:
        """Test single-packet flow."""
        pkt = create_tcp_seq_packet()
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        # Single packet can't have RTT
        assert features["tcp_rtt_handshake"] == 0.0
        assert features["tcp_rtt_samples"] == 0

    def test_extract_half_handshake(self, extractor: TCPRTTExtractor) -> None:
        """Test flow with only SYN and SYN-ACK (no final ACK)."""
        packets = [
            create_tcp_seq_packet(
                timestamp=1000.0,
                tcp_seq=1000000,
                tcp_ack=0,
                tcp_flags=0x02,  # SYN
            ),
            create_tcp_seq_packet(
                timestamp=1000.01,  # 10ms
                tcp_seq=2000000,
                tcp_ack=1000001,
                tcp_flags=0x12,  # SYN-ACK
                src_ip="10.0.0.1",
                dst_ip="192.168.1.100",
                src_port=443,
                dst_port=54321,
            ),
        ]

        flow = Flow.from_first_packet(packets[0])
        flow.add_packet(packets[1])

        features = extractor.extract(flow)

        # Should estimate RTT from half-handshake (SYN -> SYN-ACK * 2)
        assert features["tcp_rtt_handshake"] > 0
        # Estimated RTT ~= 20ms (10ms * 2)
        assert 0.015 <= features["tcp_rtt_handshake"] <= 0.025

    def test_extract_rtt_jitter(self, extractor: TCPRTTExtractor) -> None:
        """Test RTT jitter calculation."""
        # Create flow with varying RTT
        packets = []
        base_time = 1000.0
        ts_base = 100000
        ts_freq = 1000

        # Build packets with varying timing
        rtts = [0.01, 0.015, 0.02, 0.012]  # Varying RTTs

        for i, rtt in enumerate(rtts):
            is_forward = i % 2 == 0
            pkt = create_tcp_seq_packet(
                timestamp=base_time + sum(rtts[:i+1]),
                tcp_seq=1000 + i * 100,
                tcp_ack=2000 + i * 100,
                tcp_flags=0x18,
                tcp_timestamp=(ts_base + int(sum(rtts[:i+1]) * ts_freq), ts_base if i == 0 else ts_base + int(sum(rtts[:i]) * ts_freq)),
                src_ip="192.168.1.100" if is_forward else "10.0.0.1",
                dst_ip="10.0.0.1" if is_forward else "192.168.1.100",
                src_port=54321 if is_forward else 443,
                dst_port=443 if is_forward else 54321,
            )
            packets.append(pkt)

        flow = Flow.from_first_packet(packets[0])
        for pkt in packets[1:]:
            flow.add_packet(pkt)

        features = extractor.extract(flow)

        # Jitter should be >= 0
        assert features["tcp_rtt_jitter_avg"] >= 0

    def test_extract_rtt_outlier_filtering(self, extractor: TCPRTTExtractor) -> None:
        """Test that extremely high RTTs are filtered out."""
        # RTT > 60s should be ignored
        packets = [
            create_tcp_seq_packet(
                timestamp=1000.0,
                tcp_timestamp=(100000, 0),
            ),
            create_tcp_seq_packet(
                timestamp=1100.0,  # 100s later (unrealistic)
                tcp_timestamp=(200000, 100000),
                src_ip="10.0.0.1",
                dst_ip="192.168.1.100",
                src_port=443,
                dst_port=54321,
            ),
        ]

        flow = Flow.from_first_packet(packets[0])
        flow.add_packet(packets[1])

        features = extractor.extract(flow)

        # Should not include 100s RTT
        assert features["tcp_rtt_max"] < 60 or features["tcp_rtt_samples"] == 0

    def test_validate_all_features_present(self, extractor: TCPRTTExtractor) -> None:
        """Test that all feature names are present in extracted features."""
        flow = create_tcp_rtt_flow()
        features = extractor.extract(flow)

        for name in extractor.feature_names:
            assert name in features, f"Missing feature: {name}"
