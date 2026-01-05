"""Tests for ICMP feature extractor (#58)."""

from __future__ import annotations

import pytest

from joyfuljay.core.flow import Flow
from joyfuljay.core.packet import Packet
from joyfuljay.extractors.icmp import ICMPExtractor

from tests.fixtures.tranalyzer_packets import (
    create_icmp_packet,
    create_icmp_ttl_exceeded_flow,
    create_icmp_unreachable_flow,
    create_mac_flow,
    create_ping_flow,
)


class TestICMPExtractor:
    """Tests for ICMPExtractor."""

    @pytest.fixture
    def extractor(self) -> ICMPExtractor:
        """Create an ICMP extractor."""
        return ICMPExtractor()

    def test_feature_names(self, extractor: ICMPExtractor) -> None:
        """Test that feature names are properly defined."""
        names = extractor.feature_names
        assert isinstance(names, list)
        assert len(names) == 16
        assert "icmp_packet_count" in names
        assert "icmp_echo_request_count" in names
        assert "icmp_echo_reply_count" in names
        assert "icmp_dest_unreachable_count" in names
        assert "icmp_time_exceeded_count" in names
        assert "icmp_unique_type_codes" in names
        assert "icmp_dominant_type" in names
        assert "icmp_echo_success_ratio" in names
        assert "icmp_unique_ids" in names
        assert "icmp_seq_min" in names
        assert "icmp_seq_max" in names
        assert "icmp_stat" in names
        assert "icmp_ratio" in names
        assert "is_icmp_only" in names

    def test_extractor_name(self, extractor: ICMPExtractor) -> None:
        """Test extractor name."""
        assert extractor.name == "icmp"

    def test_extract_ping_flow(self, extractor: ICMPExtractor) -> None:
        """Test ping (echo request/reply) flow extraction."""
        flow = create_ping_flow(num_pings=5, success_ratio=1.0)
        features = extractor.extract(flow)

        assert features["icmp_packet_count"] == 10  # 5 requests + 5 replies
        assert features["icmp_echo_request_count"] == 5
        assert features["icmp_echo_reply_count"] == 5
        assert features["icmp_echo_success_ratio"] == 1.0

    def test_extract_partial_ping(self, extractor: ICMPExtractor) -> None:
        """Test ping with packet loss."""
        flow = create_ping_flow(num_pings=5, success_ratio=0.6)
        features = extractor.extract(flow)

        assert features["icmp_echo_request_count"] == 5
        assert features["icmp_echo_reply_count"] == 3  # 60% success
        assert features["icmp_echo_success_ratio"] == 0.6

    def test_extract_no_replies(self, extractor: ICMPExtractor) -> None:
        """Test ping with no replies (100% loss)."""
        flow = create_ping_flow(num_pings=5, success_ratio=0.0)
        features = extractor.extract(flow)

        assert features["icmp_echo_request_count"] == 5
        assert features["icmp_echo_reply_count"] == 0
        assert features["icmp_echo_success_ratio"] == 0.0

    def test_extract_dest_unreachable(self, extractor: ICMPExtractor) -> None:
        """Test destination unreachable message extraction."""
        flow = create_icmp_unreachable_flow()
        features = extractor.extract(flow)

        assert features["icmp_dest_unreachable_count"] == 2
        assert features["icmp_stat"] & 0x04  # Bit 2: dest unreachable

    def test_extract_time_exceeded(self, extractor: ICMPExtractor) -> None:
        """Test time exceeded (traceroute) message extraction."""
        flow = create_icmp_ttl_exceeded_flow()
        features = extractor.extract(flow)

        assert features["icmp_time_exceeded_count"] == 2
        assert features["icmp_stat"] & 0x08  # Bit 3: time exceeded

    def test_extract_icmp_stat_bitmap(self, extractor: ICMPExtractor) -> None:
        """Test ICMP status bitmap."""
        flow = create_ping_flow()
        features = extractor.extract(flow)

        stat = features["icmp_stat"]
        # Bit 0: Has echo requests
        assert stat & 0x01
        # Bit 1: Has echo replies
        assert stat & 0x02

    def test_extract_dominant_type(self, extractor: ICMPExtractor) -> None:
        """Test dominant ICMP type detection."""
        flow = create_ping_flow()
        features = extractor.extract(flow)

        # Echo request (8) or reply (0) should be dominant
        assert features["icmp_dominant_type"] in [0, 8]
        assert features["icmp_dominant_type_count"] > 0

    def test_extract_unique_type_codes(self, extractor: ICMPExtractor) -> None:
        """Test unique type/code pair counting."""
        flow = create_icmp_unreachable_flow()  # Has codes 1 and 3
        features = extractor.extract(flow)

        # Should have 2 unique type/code pairs
        assert features["icmp_unique_type_codes"] == 2

    def test_extract_sequence_numbers(self, extractor: ICMPExtractor) -> None:
        """Test ICMP sequence number extraction."""
        flow = create_ping_flow(num_pings=5)
        features = extractor.extract(flow)

        assert features["icmp_seq_min"] == 1
        assert features["icmp_seq_max"] == 5

    def test_extract_sequence_gaps(self, extractor: ICMPExtractor) -> None:
        """Test sequence number gap detection."""
        # Create flow with gaps in sequence
        packets = [
            create_icmp_packet(icmp_seq=1),
            create_icmp_packet(timestamp=1000.1, icmp_seq=2),
            create_icmp_packet(timestamp=1000.2, icmp_seq=5),  # Gap: 3, 4 missing
        ]

        flow = Flow.from_first_packet(packets[0])
        for pkt in packets[1:]:
            flow.add_packet(pkt)

        features = extractor.extract(flow)

        assert features["icmp_seq_gaps"] >= 1

    def test_extract_unique_ids(self, extractor: ICMPExtractor) -> None:
        """Test unique ICMP ID counting."""
        flow = create_ping_flow()
        features = extractor.extract(flow)

        # All pings use same ID (1234)
        assert features["icmp_unique_ids"] == 1

    def test_extract_multiple_ids(self, extractor: ICMPExtractor) -> None:
        """Test multiple ICMP IDs (multiple ping sessions)."""
        packets = [
            create_icmp_packet(icmp_id=1234, icmp_seq=1),
            create_icmp_packet(timestamp=1000.1, icmp_id=5678, icmp_seq=1),
        ]

        flow = Flow.from_first_packet(packets[0])
        flow.add_packet(packets[1])

        features = extractor.extract(flow)

        assert features["icmp_unique_ids"] == 2

    def test_extract_icmp_ratio(self, extractor: ICMPExtractor) -> None:
        """Test ICMP packet ratio."""
        flow = create_ping_flow()
        features = extractor.extract(flow)

        assert features["icmp_ratio"] == 1.0
        assert features["is_icmp_only"] == 1

    def test_extract_non_icmp_flow(self, extractor: ICMPExtractor) -> None:
        """Test non-ICMP (TCP) flow."""
        flow = create_mac_flow()  # TCP flow
        features = extractor.extract(flow)

        assert features["icmp_packet_count"] == 0
        assert features["icmp_echo_request_count"] == 0
        assert features["icmp_ratio"] == 0.0
        assert features["is_icmp_only"] == 0

    def test_extract_mixed_flow(self, extractor: ICMPExtractor) -> None:
        """Test mixed flow (ICMP + other)."""
        icmp_pkt = create_icmp_packet()
        tcp_pkt = Packet(
            timestamp=1000.1,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            protocol=6,  # TCP
            payload_len=100,
            total_len=140,
            tcp_flags=0x18,
        )

        flow = Flow.from_first_packet(icmp_pkt)
        flow.add_packet(tcp_pkt)

        features = extractor.extract(flow)

        assert features["icmp_packet_count"] == 1
        assert features["icmp_ratio"] == 0.5
        assert features["is_icmp_only"] == 0

    def test_extract_no_icmp_type(self, extractor: ICMPExtractor) -> None:
        """Test packet without ICMP type info."""
        pkt = Packet(
            timestamp=1000.0,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=0,
            dst_port=0,
            protocol=1,  # ICMP protocol
            payload_len=64,
            total_len=84,
            # No icmp_type field
        )
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        # No ICMP type = not counted as ICMP
        assert features["icmp_packet_count"] == 0

    def test_extract_redirect(self, extractor: ICMPExtractor) -> None:
        """Test ICMP redirect message detection."""
        pkt = create_icmp_packet(
            icmp_type=5,  # Redirect
            icmp_code=0,
            icmp_id=None,
            icmp_seq=None,
        )
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        # Bit 4: Has redirect
        assert features["icmp_stat"] & 0x10

    def test_extract_other_types(self, extractor: ICMPExtractor) -> None:
        """Test other ICMP type detection."""
        # Timestamp request (type 13)
        pkt = create_icmp_packet(
            icmp_type=13,
            icmp_code=0,
        )
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        # Bit 5: Has other types
        assert features["icmp_stat"] & 0x20

    def test_validate_all_features_present(self, extractor: ICMPExtractor) -> None:
        """Test that all feature names are present in extracted features."""
        flow = create_ping_flow()
        features = extractor.extract(flow)

        for name in extractor.feature_names:
            assert name in features, f"Missing feature: {name}"
