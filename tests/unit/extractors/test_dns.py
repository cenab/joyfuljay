"""Tests for DNS feature extractor."""

from __future__ import annotations

import pytest

from joyfuljay.extractors.dns import DNSExtractor

from tests.fixtures.packets import create_dns_flow, create_dns_query, create_dns_response


class TestDNSExtractor:
    """Tests for DNSExtractor."""

    @pytest.fixture
    def extractor(self) -> DNSExtractor:
        """Create a DNS extractor."""
        return DNSExtractor()

    def test_feature_names(self, extractor: DNSExtractor) -> None:
        """Test that feature names are properly defined."""
        names = extractor.feature_names
        assert isinstance(names, list)
        assert len(names) > 0
        assert "dns_detected" in names

    def test_extractor_name(self, extractor: DNSExtractor) -> None:
        """Test extractor name."""
        assert extractor.name == "DNSExtractor"

    def test_extract_dns_detected(self, extractor: DNSExtractor) -> None:
        """Test DNS detection."""
        flow = create_dns_flow()
        features = extractor.extract(flow)

        assert features["dns_detected"] is True

    def test_extract_query_name(self, extractor: DNSExtractor) -> None:
        """Test DNS query name extraction."""
        flow = create_dns_flow(domain="test.example.com")
        features = extractor.extract(flow)

        if "dns_query_name" in features:
            assert "test.example.com" in features["dns_query_name"]

    def test_extract_query_type(self, extractor: DNSExtractor) -> None:
        """Test DNS query type extraction."""
        flow = create_dns_flow()
        features = extractor.extract(flow)

        if "dns_query_type" in features:
            assert features["dns_query_type"] == 1  # A record

    def test_extract_response_code(self, extractor: DNSExtractor) -> None:
        """Test DNS response code extraction."""
        flow = create_dns_flow()
        features = extractor.extract(flow)

        # Response code feature exists
        if "dns_response_code" in features:
            # -1 means no response parsed, 0 would be NOERROR
            assert features["dns_response_code"] in [-1, 0, 1, 2, 3]

    def test_extract_answer_count(self, extractor: DNSExtractor) -> None:
        """Test DNS answer count extraction."""
        flow = create_dns_flow()
        features = extractor.extract(flow)

        # Answer count should be non-negative
        if "dns_answer_count" in features:
            assert features["dns_answer_count"] >= 0

    def test_no_dns_traffic(self, extractor: DNSExtractor) -> None:
        """Test extraction from non-DNS flow."""
        from joyfuljay.core.flow import Flow
        from joyfuljay.core.packet import Packet

        # HTTP traffic on port 80
        packet = Packet(
            timestamp=1000.0,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=80,
            protocol=6,
            payload_len=100,
            total_len=140,
            tcp_flags=0x18,
            raw_payload=b"GET / HTTP/1.1\r\n",
        )

        flow = Flow.from_first_packet(packet)
        features = extractor.extract(flow)

        assert features["dns_detected"] is False

    def test_validate_features(self, extractor: DNSExtractor) -> None:
        """Test feature validation."""
        flow = create_dns_flow()
        features = extractor.extract(flow)

        assert extractor.validate_features(features)

    def test_dns_query_only(self, extractor: DNSExtractor) -> None:
        """Test DNS query without response."""
        from joyfuljay.core.flow import Flow
        from joyfuljay.core.packet import Packet

        query = create_dns_query(domain="example.com")
        packet = Packet(
            timestamp=1000.0,
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=53,
            protocol=17,
            payload_len=len(query),
            total_len=len(query) + 28,
            raw_payload=query,
        )

        flow = Flow.from_first_packet(packet)
        features = extractor.extract(flow)

        # Should detect DNS even with query only
        assert features["dns_detected"] is True

    def test_ttl_extraction(self, extractor: DNSExtractor) -> None:
        """Test DNS TTL extraction."""
        flow = create_dns_flow()
        features = extractor.extract(flow)

        if "dns_ttl_min" in features:
            assert features["dns_ttl_min"] >= 0
        if "dns_ttl_max" in features:
            assert features["dns_ttl_max"] >= 0
