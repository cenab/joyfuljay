"""Tests for TCP Multipath (MPTCP) feature extractor (#55)."""

from __future__ import annotations

import pytest

from joyfuljay.core.flow import Flow
from joyfuljay.core.packet import Packet
from joyfuljay.extractors.tcp_mptcp import MPTCPExtractor

from tests.fixtures.tranalyzer_packets import (
    create_mptcp_capable_option,
    create_mptcp_flow,
    create_non_mptcp_flow,
    create_non_tcp_flow,
    create_tcp_options_packet,
)


class TestMPTCPExtractor:
    """Tests for MPTCPExtractor."""

    @pytest.fixture
    def extractor(self) -> MPTCPExtractor:
        """Create an MPTCP extractor."""
        return MPTCPExtractor()

    def test_feature_names(self, extractor: MPTCPExtractor) -> None:
        """Test that feature names are properly defined."""
        names = extractor.feature_names
        assert isinstance(names, list)
        assert len(names) == 6
        assert "mptcp_detected" in names
        assert "mptcp_capable_fwd" in names
        assert "mptcp_capable_bwd" in names
        assert "mptcp_option_count" in names
        assert "mptcp_stat" in names
        assert "is_mptcp" in names

    def test_extractor_name(self, extractor: MPTCPExtractor) -> None:
        """Test extractor name."""
        assert extractor.name == "tcp_mptcp"

    def test_extract_mptcp_flow(self, extractor: MPTCPExtractor) -> None:
        """Test MPTCP-capable flow detection."""
        flow = create_mptcp_flow()
        features = extractor.extract(flow)

        assert features["mptcp_detected"] == 1
        assert features["mptcp_capable_fwd"] == 1
        assert features["mptcp_capable_bwd"] == 1
        assert features["is_mptcp"] == 1

    def test_extract_mptcp_option_count(self, extractor: MPTCPExtractor) -> None:
        """Test MPTCP option counting."""
        flow = create_mptcp_flow()
        features = extractor.extract(flow)

        # At least 2 packets have MPTCP options (SYN and SYN-ACK)
        assert features["mptcp_option_count"] >= 2

    def test_extract_mptcp_stat_bitmap(self, extractor: MPTCPExtractor) -> None:
        """Test MPTCP status bitmap."""
        flow = create_mptcp_flow()
        features = extractor.extract(flow)

        stat = features["mptcp_stat"]
        # Bit 0: MPTCP detected
        assert stat & 0x01
        # Bit 1: Forward MP_CAPABLE
        assert stat & 0x02
        # Bit 2: Backward MP_CAPABLE
        assert stat & 0x04
        # Bit 3: Both directions (full MPTCP)
        assert stat & 0x08

    def test_extract_non_mptcp_flow(self, extractor: MPTCPExtractor) -> None:
        """Test regular TCP flow (no MPTCP)."""
        flow = create_non_mptcp_flow()
        features = extractor.extract(flow)

        assert features["mptcp_detected"] == 0
        assert features["mptcp_capable_fwd"] == 0
        assert features["mptcp_capable_bwd"] == 0
        assert features["is_mptcp"] == 0
        assert features["mptcp_stat"] == 0

    def test_extract_udp_flow(self, extractor: MPTCPExtractor) -> None:
        """Test extraction from UDP flow (should return defaults)."""
        flow = create_non_tcp_flow()
        features = extractor.extract(flow)

        # UDP cannot have MPTCP
        assert features["mptcp_detected"] == 0
        assert features["is_mptcp"] == 0

    def test_extract_one_sided_mptcp(self, extractor: MPTCPExtractor) -> None:
        """Test MPTCP with only one side capable."""
        mptcp_opts = create_mptcp_capable_option()

        packets = [
            # SYN with MP_CAPABLE
            create_tcp_options_packet(
                timestamp=1000.0,
                tcp_flags=0x02,
                tcp_options_raw=mptcp_opts,
            ),
            # SYN-ACK without MP_CAPABLE (server doesn't support)
            create_tcp_options_packet(
                timestamp=1000.01,
                tcp_flags=0x12,
                tcp_options_raw=None,
                src_ip="10.0.0.1",
                dst_ip="192.168.1.100",
                src_port=443,
                dst_port=54321,
            ),
        ]

        flow = Flow.from_first_packet(packets[0])
        flow.add_packet(packets[1])

        features = extractor.extract(flow)

        assert features["mptcp_detected"] == 1
        assert features["mptcp_capable_fwd"] == 1
        assert features["mptcp_capable_bwd"] == 0
        assert features["is_mptcp"] == 0  # Not full MPTCP

    def test_extract_no_options(self, extractor: MPTCPExtractor) -> None:
        """Test flow without any TCP options."""
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
            # No tcp_options_raw
        )
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        assert features["mptcp_detected"] == 0
        assert features["mptcp_option_count"] == 0

    def test_extract_other_options(self, extractor: MPTCPExtractor) -> None:
        """Test flow with TCP options but no MPTCP."""
        # Create options with MSS, WS, etc. but no MPTCP (kind 30)
        # MSS option: kind=2, length=4, value=1460
        options = bytes([2, 4, 0x05, 0xb4, 0, 0, 0, 0])  # MSS + padding

        pkt = create_tcp_options_packet(
            tcp_options_raw=options,
            tcp_flags=0x02,
        )
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        assert features["mptcp_detected"] == 0

    def test_mptcp_option_parsing(self, extractor: MPTCPExtractor) -> None:
        """Test MPTCP option parsing edge cases."""
        # Test with NOP padding before MPTCP
        options = bytes([
            1, 1, 1, 1,  # 4 NOPs
            30, 12,  # MPTCP, length 12
            0x00, 0x81,  # Subtype + flags
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Key
        ])

        pkt = create_tcp_options_packet(
            tcp_options_raw=options,
            tcp_flags=0x02,
        )
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        assert features["mptcp_detected"] == 1

    def test_mptcp_option_end_of_options(self, extractor: MPTCPExtractor) -> None:
        """Test MPTCP option with end-of-options marker."""
        # End of options (kind 0) before MPTCP
        options = bytes([0])

        pkt = create_tcp_options_packet(
            tcp_options_raw=options,
            tcp_flags=0x02,
        )
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        assert features["mptcp_detected"] == 0

    def test_mptcp_malformed_options(self, extractor: MPTCPExtractor) -> None:
        """Test handling of malformed TCP options."""
        # Malformed: kind 30 but length too short
        options = bytes([30, 1])  # Invalid length

        pkt = create_tcp_options_packet(
            tcp_options_raw=options,
            tcp_flags=0x02,
        )
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        # Should not crash, return no MPTCP detected
        assert features["mptcp_detected"] == 0

    def test_validate_all_features_present(self, extractor: MPTCPExtractor) -> None:
        """Test that all feature names are present in extracted features."""
        flow = create_mptcp_flow()
        features = extractor.extract(flow)

        for name in extractor.feature_names:
            assert name in features, f"Missing feature: {name}"
