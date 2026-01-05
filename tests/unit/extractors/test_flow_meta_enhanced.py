"""Tests for enhanced Flow Metadata extractor (#44).

Tests the Tranalyzer-compatible features added to FlowMetaExtractor:
- time_first, time_last (timestamp aliases)
- flow_stat (termination status bitmap)
- num_hdrs, hdr_desc (protocol stack description)
"""

from __future__ import annotations

import pytest

from joyfuljay.core.flow import Flow
from joyfuljay.core.packet import Packet
from joyfuljay.extractors.flow_meta import FlowMetaExtractor

from tests.fixtures.tranalyzer_packets import (
    create_full_featured_tcp_flow,
    create_ipv6_flow,
    create_mac_flow,
    create_non_tcp_flow,
    create_ping_flow,
    create_tcp_handshake_flow,
)


class TestFlowMetaExtractorEnhanced:
    """Tests for enhanced FlowMetaExtractor features (#44)."""

    @pytest.fixture
    def extractor(self) -> FlowMetaExtractor:
        """Create a Flow Meta extractor."""
        return FlowMetaExtractor()

    def test_feature_names_include_tranalyzer(self, extractor: FlowMetaExtractor) -> None:
        """Test that Tranalyzer-compatible feature names are present."""
        names = extractor.feature_names
        assert "time_first" in names
        assert "time_last" in names
        assert "flow_stat" in names
        assert "num_hdrs" in names
        assert "hdr_desc" in names

    def test_extract_time_aliases(self, extractor: FlowMetaExtractor) -> None:
        """Test time_first and time_last extraction."""
        flow = create_mac_flow()
        features = extractor.extract(flow)

        # time_first and time_last should match start_time and end_time
        assert features["time_first"] == features["start_time"]
        assert features["time_last"] == features["end_time"]
        assert features["time_first"] < features["time_last"]

    def test_extract_flow_stat_complete_tcp(self, extractor: FlowMetaExtractor) -> None:
        """Test flow_stat for complete TCP connection."""
        flow = create_full_featured_tcp_flow()
        features = extractor.extract(flow)

        flow_stat = features["flow_stat"]
        # Bit 0: Has SYN
        assert flow_stat & 0x01
        # Bit 1: Has SYN-ACK
        assert flow_stat & 0x02
        # Bit 2: Has FIN from initiator
        assert flow_stat & 0x04
        # Bit 3: Has FIN from responder
        assert flow_stat & 0x08
        # Bit 6: Proper termination
        assert flow_stat & 0x40

    def test_extract_flow_stat_syn_only(self, extractor: FlowMetaExtractor) -> None:
        """Test flow_stat for SYN-only flow (port scan)."""
        pkt = Packet(
            timestamp=1000.0,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            protocol=6,
            payload_len=0,
            total_len=40,
            tcp_flags=0x02,  # SYN only
        )
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        flow_stat = features["flow_stat"]
        # Bit 0: Has SYN
        assert flow_stat & 0x01
        # Bit 1: No SYN-ACK
        assert not (flow_stat & 0x02)

    def test_extract_flow_stat_rst(self, extractor: FlowMetaExtractor) -> None:
        """Test flow_stat for RST-terminated connection."""
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
                tcp_flags=0x14,  # RST-ACK
            ),
        ]

        flow = Flow.from_first_packet(packets[0])
        flow.add_packet(packets[1])

        features = extractor.extract(flow)

        flow_stat = features["flow_stat"]
        # Bit 4: Has RST
        assert flow_stat & 0x10

    def test_extract_flow_stat_udp(self, extractor: FlowMetaExtractor) -> None:
        """Test flow_stat for UDP flow (no TCP flags)."""
        flow = create_non_tcp_flow()
        features = extractor.extract(flow)

        # UDP has no TCP flags, so flow_stat should be 0
        assert features["flow_stat"] == 0

    def test_extract_hdr_desc_tcp(self, extractor: FlowMetaExtractor) -> None:
        """Test protocol stack description for TCP."""
        flow = create_mac_flow()  # TCP flow with MAC
        features = extractor.extract(flow)

        # Should describe protocol layers
        hdr_desc = features["hdr_desc"]
        assert "TCP" in hdr_desc
        # May include ETH if MAC present
        if flow.packets[0].src_mac:
            assert "ETH" in hdr_desc

    def test_extract_hdr_desc_udp(self, extractor: FlowMetaExtractor) -> None:
        """Test protocol stack description for UDP."""
        flow = create_non_tcp_flow()
        features = extractor.extract(flow)

        hdr_desc = features["hdr_desc"]
        assert "UDP" in hdr_desc

    def test_extract_hdr_desc_ipv6(self, extractor: FlowMetaExtractor) -> None:
        """Test protocol stack description for IPv6."""
        flow = create_ipv6_flow()
        features = extractor.extract(flow)

        hdr_desc = features["hdr_desc"]
        assert "IP6" in hdr_desc or "IPv6" in hdr_desc.upper()

    def test_extract_hdr_desc_icmp(self, extractor: FlowMetaExtractor) -> None:
        """Test protocol stack description for ICMP."""
        flow = create_ping_flow()
        features = extractor.extract(flow)

        hdr_desc = features["hdr_desc"]
        assert "ICMP" in hdr_desc

    def test_extract_num_hdrs(self, extractor: FlowMetaExtractor) -> None:
        """Test header count extraction."""
        flow = create_mac_flow()
        features = extractor.extract(flow)

        # Should have at least 2 headers (IP + TCP/UDP)
        assert features["num_hdrs"] >= 2
        # With MAC, should have 3 (ETH + IP + TCP)
        if flow.packets[0].src_mac:
            assert features["num_hdrs"] == 3

    def test_extract_num_hdrs_without_mac(self, extractor: FlowMetaExtractor) -> None:
        """Test header count without MAC layer."""
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
            # No MAC fields
        )
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        # Should have 2 headers (IP + TCP)
        assert features["num_hdrs"] == 2

    def test_extract_protocol_stack_format(self, extractor: FlowMetaExtractor) -> None:
        """Test protocol stack format (dash-separated)."""
        flow = create_mac_flow()
        features = extractor.extract(flow)

        hdr_desc = features["hdr_desc"]
        # Format should be "ETH-IP-TCP" or similar
        if "-" in hdr_desc:
            parts = hdr_desc.split("-")
            assert len(parts) == features["num_hdrs"]

    def test_extract_graceful_close(self, extractor: FlowMetaExtractor) -> None:
        """Test flow_stat for graceful FIN close."""
        flow = create_full_featured_tcp_flow()
        features = extractor.extract(flow)

        flow_stat = features["flow_stat"]
        # Both FIN bits and proper termination bit
        has_fin_fwd = bool(flow_stat & 0x04)
        has_fin_bwd = bool(flow_stat & 0x08)
        proper_term = bool(flow_stat & 0x40)

        if has_fin_fwd and has_fin_bwd:
            assert proper_term

    def test_validate_all_features_present(self, extractor: FlowMetaExtractor) -> None:
        """Test that all enhanced feature names are present."""
        flow = create_full_featured_tcp_flow()
        features = extractor.extract(flow)

        enhanced_features = ["time_first", "time_last", "flow_stat", "num_hdrs", "hdr_desc"]
        for name in enhanced_features:
            assert name in features, f"Missing enhanced feature: {name}"

    def test_extract_existing_features_preserved(self, extractor: FlowMetaExtractor) -> None:
        """Test that existing features still work."""
        flow = create_mac_flow()
        features = extractor.extract(flow)

        # Original features should still be present
        assert "duration" in features
        assert "total_packets" in features
        assert "total_bytes" in features
        assert "packets_fwd" in features
        assert "packets_bwd" in features
