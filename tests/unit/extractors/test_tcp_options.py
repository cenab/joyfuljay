"""Tests for TCP Options feature extractor (#54)."""

from __future__ import annotations

import pytest

from joyfuljay.core.flow import Flow
from joyfuljay.core.packet import Packet
from joyfuljay.extractors.tcp_options import TCPOptionsExtractor

from tests.fixtures.tranalyzer_packets import (
    create_non_tcp_flow,
    create_tcp_options_flow,
    create_tcp_options_packet,
    create_tcp_sack_flow,
)


class TestTCPOptionsExtractor:
    """Tests for TCPOptionsExtractor."""

    @pytest.fixture
    def extractor(self) -> TCPOptionsExtractor:
        """Create a TCP Options extractor."""
        return TCPOptionsExtractor()

    def test_feature_names(self, extractor: TCPOptionsExtractor) -> None:
        """Test that feature names are properly defined."""
        names = extractor.feature_names
        assert isinstance(names, list)
        assert len(names) == 19
        assert "tcp_mss_fwd" in names
        assert "tcp_mss_bwd" in names
        assert "tcp_ws_fwd" in names
        assert "tcp_ws_bwd" in names
        assert "tcp_sack_permitted_fwd" in names
        assert "tcp_sack_blocks_total" in names
        assert "tcp_ts_fwd_present" in names
        assert "tcp_ts_fwd_first" in names
        assert "tcp_options_bitmap" in names

    def test_extractor_name(self, extractor: TCPOptionsExtractor) -> None:
        """Test extractor name."""
        assert extractor.name == "tcp_options"

    def test_extract_mss(self, extractor: TCPOptionsExtractor) -> None:
        """Test MSS (Maximum Segment Size) extraction."""
        flow = create_tcp_options_flow()
        features = extractor.extract(flow)

        assert features["tcp_mss_fwd"] == 1460
        assert features["tcp_mss_bwd"] == 1460

    def test_extract_window_scale(self, extractor: TCPOptionsExtractor) -> None:
        """Test Window Scale extraction."""
        flow = create_tcp_options_flow()
        features = extractor.extract(flow)

        assert features["tcp_ws_fwd"] == 7
        assert features["tcp_ws_bwd"] == 8

    def test_extract_sack_permitted(self, extractor: TCPOptionsExtractor) -> None:
        """Test SACK permitted extraction."""
        flow = create_tcp_options_flow()
        features = extractor.extract(flow)

        assert features["tcp_sack_permitted_fwd"] == 1
        assert features["tcp_sack_permitted_bwd"] == 1

    def test_extract_sack_blocks(self, extractor: TCPOptionsExtractor) -> None:
        """Test SACK blocks extraction."""
        flow = create_tcp_sack_flow()
        features = extractor.extract(flow)

        assert features["tcp_sack_blocks_total"] >= 2

    def test_extract_timestamps(self, extractor: TCPOptionsExtractor) -> None:
        """Test TCP timestamp extraction."""
        flow = create_tcp_options_flow()
        features = extractor.extract(flow)

        assert features["tcp_ts_fwd_present"] == 1
        assert features["tcp_ts_fwd_first"] == 100000
        assert features["tcp_ts_bwd_present"] == 1

    def test_extract_timestamp_diff(self, extractor: TCPOptionsExtractor) -> None:
        """Test timestamp difference calculation."""
        packets = [
            create_tcp_options_packet(
                timestamp=1000.0,
                tcp_timestamp=(100000, 0),
                tcp_flags=0x02,
            ),
            create_tcp_options_packet(
                timestamp=1000.01,
                tcp_timestamp=(100100, 100000),  # Diff = 100
                tcp_flags=0x18,
            ),
        ]

        flow = Flow.from_first_packet(packets[0])
        flow.add_packet(packets[1])

        features = extractor.extract(flow)

        assert features["tcp_ts_fwd_first"] == 100000
        assert features["tcp_ts_fwd_last"] == 100100
        assert features["tcp_ts_fwd_diff"] == 100

    def test_extract_options_bitmap(self, extractor: TCPOptionsExtractor) -> None:
        """Test options presence bitmap."""
        flow = create_tcp_options_flow()
        features = extractor.extract(flow)

        bitmap = features["tcp_options_bitmap"]
        # Bit 0: MSS present
        assert bitmap & 0x01
        # Bit 1: Window Scale present
        assert bitmap & 0x02
        # Bit 2: SACK permitted
        assert bitmap & 0x04
        # Bit 3: Timestamps present
        assert bitmap & 0x08

    def test_extract_packets_with_options(self, extractor: TCPOptionsExtractor) -> None:
        """Test counting packets with options."""
        flow = create_tcp_options_flow()
        features = extractor.extract(flow)

        assert features["tcp_options_pkt_count"] >= 2

    def test_extract_no_options(self, extractor: TCPOptionsExtractor) -> None:
        """Test flow without TCP options."""
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
            # No TCP options
        )
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        assert features["tcp_mss_fwd"] == 0
        assert features["tcp_ws_fwd"] == 0
        assert features["tcp_sack_permitted_fwd"] == 0
        assert features["tcp_ts_fwd_present"] == 0
        assert features["tcp_options_bitmap"] == 0

    def test_extract_udp_flow(self, extractor: TCPOptionsExtractor) -> None:
        """Test extraction from UDP flow (should return defaults)."""
        flow = create_non_tcp_flow()
        features = extractor.extract(flow)

        # UDP has no TCP options
        assert features["tcp_mss_fwd"] == 0
        assert features["tcp_options_bitmap"] == 0

    def test_extract_partial_options(self, extractor: TCPOptionsExtractor) -> None:
        """Test flow with only some options present."""
        pkt = create_tcp_options_packet(
            tcp_mss=1460,
            tcp_window_scale=None,
            tcp_timestamp=None,
            tcp_sack_permitted=False,
        )
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        assert features["tcp_mss_fwd"] == 1460
        assert features["tcp_ws_fwd"] == 0
        assert features["tcp_ts_fwd_present"] == 0
        assert features["tcp_sack_permitted_fwd"] == 0

        # Only MSS bit should be set
        assert features["tcp_options_bitmap"] == 0x01

    def test_extract_timestamp_echo_reply(self, extractor: TCPOptionsExtractor) -> None:
        """Test timestamp echo reply extraction."""
        pkt = create_tcp_options_packet(
            tcp_timestamp=(100000, 50000),  # TSecr = 50000
        )
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        assert features["tcp_ts_ecr_fwd_first"] == 50000

    def test_extract_timestamp_wraparound(self, extractor: TCPOptionsExtractor) -> None:
        """Test timestamp wraparound handling."""
        packets = [
            create_tcp_options_packet(
                timestamp=1000.0,
                tcp_timestamp=(4294967290, 0),  # Near max
            ),
            create_tcp_options_packet(
                timestamp=1000.01,
                tcp_timestamp=(10, 4294967290),  # After wraparound
            ),
        ]

        flow = Flow.from_first_packet(packets[0])
        flow.add_packet(packets[1])

        features = extractor.extract(flow)

        # Should handle wraparound
        assert features["tcp_ts_fwd_first"] == 4294967290
        assert features["tcp_ts_fwd_last"] == 10
        # Diff should be positive (with wraparound adjustment)
        assert features["tcp_ts_fwd_diff"] >= 0

    def test_extract_bidirectional_options(self, extractor: TCPOptionsExtractor) -> None:
        """Test bidirectional option extraction."""
        packets = [
            create_tcp_options_packet(
                timestamp=1000.0,
                tcp_mss=1460,
                tcp_window_scale=7,
                tcp_flags=0x02,
            ),
            create_tcp_options_packet(
                timestamp=1000.01,
                tcp_mss=1380,  # Different MSS
                tcp_window_scale=5,
                tcp_flags=0x12,
                src_ip="10.0.0.1",
                dst_ip="192.168.1.100",
                src_port=443,
                dst_port=54321,
            ),
        ]

        flow = Flow.from_first_packet(packets[0])
        flow.add_packet(packets[1])

        features = extractor.extract(flow)

        assert features["tcp_mss_fwd"] == 1460
        assert features["tcp_mss_bwd"] == 1380
        assert features["tcp_ws_fwd"] == 7
        assert features["tcp_ws_bwd"] == 5

    def test_validate_all_features_present(self, extractor: TCPOptionsExtractor) -> None:
        """Test that all feature names are present in extracted features."""
        flow = create_tcp_options_flow()
        features = extractor.extract(flow)

        for name in extractor.feature_names:
            assert name in features, f"Missing feature: {name}"
