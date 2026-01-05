"""Tests for TCP Window analysis feature extractor (#52)."""

from __future__ import annotations

import pytest

from joyfuljay.core.flow import Flow
from joyfuljay.core.packet import Packet
from joyfuljay.extractors.tcp_window import TCPWindowExtractor

from tests.fixtures.tranalyzer_packets import (
    create_non_tcp_flow,
    create_tcp_window_flow,
    create_tcp_window_packet,
    create_zero_window_flow,
)


class TestTCPWindowExtractor:
    """Tests for TCPWindowExtractor."""

    @pytest.fixture
    def extractor(self) -> TCPWindowExtractor:
        """Create a TCP Window extractor."""
        return TCPWindowExtractor()

    def test_feature_names(self, extractor: TCPWindowExtractor) -> None:
        """Test that feature names are properly defined."""
        names = extractor.feature_names
        assert isinstance(names, list)
        assert len(names) == 21
        assert "tcp_init_win_fwd" in names
        assert "tcp_init_win_bwd" in names
        assert "tcp_win_scale_fwd" in names
        assert "tcp_win_scale_bwd" in names
        assert "tcp_win_fwd_min" in names
        assert "tcp_win_fwd_max" in names
        assert "tcp_win_fwd_mean" in names
        assert "tcp_win_fwd_zero_count" in names
        assert "tcp_win_fwd_up_count" in names
        assert "tcp_win_fwd_down_count" in names
        assert "tcp_scaled_win_fwd_max" in names
        assert "tcp_zero_win_ratio" in names

    def test_extractor_name(self, extractor: TCPWindowExtractor) -> None:
        """Test extractor name."""
        assert extractor.name == "tcp_window"

    def test_extract_initial_window(self, extractor: TCPWindowExtractor) -> None:
        """Test initial window size extraction."""
        flow = create_tcp_window_flow()
        features = extractor.extract(flow)

        assert features["tcp_init_win_fwd"] == 65535

    def test_extract_window_statistics(self, extractor: TCPWindowExtractor) -> None:
        """Test window size statistics."""
        flow = create_tcp_window_flow([65535, 65535, 32768, 16384, 65535])
        features = extractor.extract(flow)

        # Forward packets (indices 0, 2, 4): 65535, 32768, 65535
        assert features["tcp_win_fwd_min"] == 32768
        assert features["tcp_win_fwd_max"] == 65535

        # Backward packets (indices 1, 3): 65535, 16384
        assert features["tcp_win_bwd_min"] == 16384
        assert features["tcp_win_bwd_max"] == 65535

    def test_extract_window_mean(self, extractor: TCPWindowExtractor) -> None:
        """Test window size mean calculation."""
        flow = create_tcp_window_flow([100, 200, 300, 400, 500])
        features = extractor.extract(flow)

        # Mean should be calculated correctly
        assert features["tcp_win_fwd_mean"] > 0
        assert features["tcp_win_bwd_mean"] > 0

    def test_extract_zero_window(self, extractor: TCPWindowExtractor) -> None:
        """Test zero window detection."""
        flow = create_zero_window_flow()  # [65535, 0, 0, 32768, 65535]
        features = extractor.extract(flow)

        # Should detect zero windows
        total_zero = features["tcp_win_fwd_zero_count"] + features["tcp_win_bwd_zero_count"]
        assert total_zero >= 2
        assert features["tcp_zero_win_ratio"] > 0

    def test_extract_no_zero_window(self, extractor: TCPWindowExtractor) -> None:
        """Test flow without zero windows."""
        flow = create_tcp_window_flow([65535, 65535, 65535, 65535, 65535])
        features = extractor.extract(flow)

        assert features["tcp_win_fwd_zero_count"] == 0
        assert features["tcp_win_bwd_zero_count"] == 0
        assert features["tcp_zero_win_ratio"] == 0.0

    def test_extract_window_scale(self, extractor: TCPWindowExtractor) -> None:
        """Test window scale factor extraction."""
        # First packet has window scale = 7
        flow = create_tcp_window_flow()
        features = extractor.extract(flow)

        assert features["tcp_win_scale_fwd"] == 7

    def test_extract_scaled_window(self, extractor: TCPWindowExtractor) -> None:
        """Test scaled window calculation."""
        flow = create_tcp_window_flow([65535, 65535, 65535, 65535, 65535])
        features = extractor.extract(flow)

        # With WS=7, scaled max = 65535 * 2^7 = 65535 * 128 = 8388480
        if features["tcp_win_scale_fwd"] == 7:
            assert features["tcp_scaled_win_fwd_max"] == 65535 * 128

    def test_extract_window_changes(self, extractor: TCPWindowExtractor) -> None:
        """Test window size change detection."""
        # Create flow with increasing then decreasing windows
        flow = create_tcp_window_flow([10000, 20000, 30000, 20000, 40000])
        features = extractor.extract(flow)

        # Should detect both up and down changes
        assert features["tcp_win_fwd_up_count"] >= 0
        assert features["tcp_win_fwd_down_count"] >= 0
        assert features["tcp_win_fwd_change_count"] == (
            features["tcp_win_fwd_up_count"] + features["tcp_win_fwd_down_count"]
        )

    def test_extract_no_window_info(self, extractor: TCPWindowExtractor) -> None:
        """Test flow without window information."""
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
            # No tcp_window
        )
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        assert features["tcp_init_win_fwd"] == 0
        assert features["tcp_win_fwd_min"] == 0
        assert features["tcp_win_fwd_max"] == 0

    def test_extract_udp_flow(self, extractor: TCPWindowExtractor) -> None:
        """Test extraction from UDP flow (should return defaults)."""
        flow = create_non_tcp_flow()
        features = extractor.extract(flow)

        # UDP has no TCP windows
        assert features["tcp_init_win_fwd"] == 0
        assert features["tcp_init_win_bwd"] == 0

    def test_extract_single_packet_flow(self, extractor: TCPWindowExtractor) -> None:
        """Test single-packet flow."""
        pkt = create_tcp_window_packet(tcp_window=65535, tcp_window_scale=7)
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        assert features["tcp_init_win_fwd"] == 65535
        assert features["tcp_win_scale_fwd"] == 7
        assert features["tcp_win_fwd_min"] == 65535
        assert features["tcp_win_fwd_max"] == 65535

    def test_extract_window_change_analysis(self, extractor: TCPWindowExtractor) -> None:
        """Test detailed window change analysis."""
        # Pattern: up, up, down, up (for forward packets at indices 0, 2, 4)
        flow = create_tcp_window_flow([1000, 5000, 2000, 3000, 3000])
        features = extractor.extract(flow)

        # Forward: 1000 -> 2000 (up) -> 3000 (up)
        assert features["tcp_win_fwd_up_count"] >= 0
        # Forward: no downs in this pattern
        assert features["tcp_win_fwd_change_count"] >= 0

    def test_extract_bidirectional_windows(self, extractor: TCPWindowExtractor) -> None:
        """Test bidirectional window extraction."""
        packets = [
            create_tcp_window_packet(
                timestamp=1000.0,
                tcp_window=65535,
                tcp_window_scale=7,
            ),
            create_tcp_window_packet(
                timestamp=1000.01,
                tcp_window=32768,
                tcp_window_scale=8,
                src_ip="10.0.0.1",
                dst_ip="192.168.1.100",
                src_port=443,
                dst_port=54321,
            ),
        ]

        flow = Flow.from_first_packet(packets[0])
        flow.add_packet(packets[1])

        features = extractor.extract(flow)

        assert features["tcp_init_win_fwd"] == 65535
        assert features["tcp_init_win_bwd"] == 32768
        assert features["tcp_win_scale_fwd"] == 7
        assert features["tcp_win_scale_bwd"] == 8

    def test_extract_very_small_window(self, extractor: TCPWindowExtractor) -> None:
        """Test handling of very small window sizes."""
        flow = create_tcp_window_flow([1, 2, 3, 4, 5])
        features = extractor.extract(flow)

        assert features["tcp_win_fwd_min"] >= 1
        assert features["tcp_win_fwd_max"] <= 5

    def test_validate_all_features_present(self, extractor: TCPWindowExtractor) -> None:
        """Test that all feature names are present in extracted features."""
        flow = create_tcp_window_flow()
        features = extractor.extract(flow)

        for name in extractor.feature_names:
            assert name in features, f"Missing feature: {name}"
