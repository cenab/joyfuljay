"""Tests for IPv6 Options feature extractor (#47)."""

from __future__ import annotations

import pytest

from joyfuljay.core.flow import Flow
from joyfuljay.core.packet import Packet
from joyfuljay.extractors.ipv6_options import IPv6OptionsExtractor

from tests.fixtures.tranalyzer_packets import (
    create_ipv6_flow,
    create_ipv6_packet,
    create_mac_flow,
)


class TestIPv6OptionsExtractor:
    """Tests for IPv6OptionsExtractor."""

    @pytest.fixture
    def extractor(self) -> IPv6OptionsExtractor:
        """Create an IPv6 Options extractor."""
        return IPv6OptionsExtractor()

    def test_feature_names(self, extractor: IPv6OptionsExtractor) -> None:
        """Test that feature names are properly defined."""
        names = extractor.feature_names
        assert isinstance(names, list)
        assert len(names) == 11
        assert "ipv6_packet_count" in names
        assert "ipv4_packet_count" in names
        assert "ipv6_flow_label" in names
        assert "ipv6_flow_label_unique_count" in names
        assert "ipv6_flow_label_changes" in names
        assert "ipv6_traffic_class" in names
        assert "ipv6_dscp" in names
        assert "ipv6_ecn" in names
        assert "ipv6_ratio" in names
        assert "is_ipv6_only" in names

    def test_extractor_name(self, extractor: IPv6OptionsExtractor) -> None:
        """Test extractor name."""
        assert extractor.name == "ipv6_options"

    def test_extract_ipv6_flow(self, extractor: IPv6OptionsExtractor) -> None:
        """Test IPv6 flow extraction."""
        flow = create_ipv6_flow()
        features = extractor.extract(flow)

        assert features["ipv6_packet_count"] == 5
        assert features["ipv4_packet_count"] == 0
        assert features["ipv6_ratio"] == 1.0
        assert features["is_ipv6_only"] == 1

    def test_extract_flow_label(self, extractor: IPv6OptionsExtractor) -> None:
        """Test IPv6 flow label extraction."""
        flow = create_ipv6_flow()
        features = extractor.extract(flow)

        assert features["ipv6_flow_label"] == 12345
        assert features["ipv6_flow_label_unique_count"] == 1
        assert features["ipv6_flow_label_changes"] == 0

    def test_extract_traffic_class(self, extractor: IPv6OptionsExtractor) -> None:
        """Test IPv6 traffic class extraction."""
        flow = create_ipv6_flow()  # Uses traffic_class=0x28 (DSCP 10)
        features = extractor.extract(flow)

        assert features["ipv6_traffic_class"] == 0x28
        assert features["ipv6_dscp"] == 0x28 >> 2  # DSCP = top 6 bits
        assert features["ipv6_ecn"] == 0x28 & 0x03  # ECN = bottom 2 bits

    def test_extract_ipv4_flow(self, extractor: IPv6OptionsExtractor) -> None:
        """Test IPv4-only flow."""
        flow = create_mac_flow()  # IPv4 flow
        features = extractor.extract(flow)

        assert features["ipv6_packet_count"] == 0
        assert features["ipv4_packet_count"] == 5
        assert features["ipv6_ratio"] == 0.0
        assert features["is_ipv6_only"] == 0

    def test_extract_mixed_flow(self, extractor: IPv6OptionsExtractor) -> None:
        """Test mixed IPv4/IPv6 flow (unusual)."""
        packets = [
            create_ipv6_packet(timestamp=1000.0),
            Packet(
                timestamp=1000.01,
                src_ip="10.0.0.1",
                dst_ip="192.168.1.100",
                src_port=443,
                dst_port=54321,
                protocol=6,
                payload_len=100,
                total_len=140,
                tcp_flags=0x18,
                ip_version=4,
            ),
        ]

        flow = Flow.from_first_packet(packets[0])
        flow.add_packet(packets[1])

        features = extractor.extract(flow)

        assert features["ipv6_packet_count"] == 1
        assert features["ipv4_packet_count"] == 1
        assert features["ipv6_ratio"] == 0.5
        assert features["is_ipv6_only"] == 0

    def test_extract_multiple_flow_labels(self, extractor: IPv6OptionsExtractor) -> None:
        """Test flow with changing flow labels (anomalous)."""
        packets = [
            create_ipv6_packet(timestamp=1000.0, flow_label=11111),
            create_ipv6_packet(
                timestamp=1000.01,
                flow_label=22222,  # Different flow label
                src_ip="2001:db8::2",
                dst_ip="2001:db8::1",
                src_port=443,
                dst_port=54321,
            ),
            create_ipv6_packet(timestamp=1000.02, flow_label=33333),
        ]

        flow = Flow.from_first_packet(packets[0])
        for pkt in packets[1:]:
            flow.add_packet(pkt)

        features = extractor.extract(flow)

        assert features["ipv6_flow_label_unique_count"] == 3
        assert features["ipv6_flow_label_changes"] == 2

    def test_extract_no_flow_label(self, extractor: IPv6OptionsExtractor) -> None:
        """Test IPv6 packet without flow label (= 0)."""
        pkt = create_ipv6_packet(flow_label=0)
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        assert features["ipv6_flow_label"] == 0

    def test_extract_no_traffic_class(self, extractor: IPv6OptionsExtractor) -> None:
        """Test IPv6 packet with default traffic class."""
        pkt = create_ipv6_packet(traffic_class=0)
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        assert features["ipv6_traffic_class"] == 0
        assert features["ipv6_dscp"] == 0
        assert features["ipv6_ecn"] == 0

    def test_extract_high_dscp(self, extractor: IPv6OptionsExtractor) -> None:
        """Test high DSCP value (EF = 46)."""
        pkt = create_ipv6_packet(traffic_class=46 << 2)  # DSCP 46
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        assert features["ipv6_dscp"] == 46

    def test_extract_ecn_values(self, extractor: IPv6OptionsExtractor) -> None:
        """Test ECN bit extraction."""
        # ECN = 3 (CE - Congestion Experienced)
        pkt = create_ipv6_packet(traffic_class=0x03)
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        assert features["ipv6_ecn"] == 3

    def test_extract_no_version_info(self, extractor: IPv6OptionsExtractor) -> None:
        """Test packet without version information."""
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
            # No ip_version field
        )
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        # Without explicit version, counts should be 0
        assert features["ipv6_packet_count"] == 0
        assert features["ipv4_packet_count"] == 0

    def test_validate_all_features_present(self, extractor: IPv6OptionsExtractor) -> None:
        """Test that all feature names are present in extracted features."""
        flow = create_ipv6_flow()
        features = extractor.extract(flow)

        for name in extractor.feature_names:
            assert name in features, f"Missing feature: {name}"
