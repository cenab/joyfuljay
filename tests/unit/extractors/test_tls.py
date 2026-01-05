"""Tests for TLS feature extractor."""

from __future__ import annotations

import pytest

from joyfuljay.extractors.tls import TLSExtractor

from tests.fixtures.packets import (
    create_tls_flow,
    create_tls_client_hello,
    create_tls_server_hello,
    create_tls_certificate,
)


class TestTLSExtractor:
    """Tests for TLSExtractor."""

    @pytest.fixture
    def extractor(self) -> TLSExtractor:
        """Create a TLS extractor."""
        return TLSExtractor()

    def test_feature_names(self, extractor: TLSExtractor) -> None:
        """Test that feature names are properly defined."""
        names = extractor.feature_names
        assert isinstance(names, list)
        assert len(names) > 0
        assert "tls_detected" in names
        assert "tls_version" in names
        assert "ja3_hash" in names
        assert "ja3s_hash" in names
        assert "tls_sni" in names

    def test_extractor_name(self, extractor: TLSExtractor) -> None:
        """Test extractor name."""
        assert extractor.name == "TLSExtractor"

    def test_extract_tls_detected(self, extractor: TLSExtractor) -> None:
        """Test TLS detection from ClientHello."""
        flow = create_tls_flow()
        features = extractor.extract(flow)

        assert features["tls_detected"] is True

    def test_extract_tls_version(self, extractor: TLSExtractor) -> None:
        """Test TLS version extraction."""
        flow = create_tls_flow(version=0x0303)  # TLS 1.2
        features = extractor.extract(flow)

        assert features["tls_version"] == 0x0303
        assert features["tls_version_str"] == "TLS 1.2"

    def test_extract_sni(self, extractor: TLSExtractor) -> None:
        """Test SNI extraction."""
        flow = create_tls_flow(sni="test.example.com")
        features = extractor.extract(flow)

        assert features["tls_sni"] == "test.example.com"

    def test_extract_ja3_hash(self, extractor: TLSExtractor) -> None:
        """Test JA3 fingerprint computation."""
        flow = create_tls_flow()
        features = extractor.extract(flow)

        assert features["ja3_hash"] != ""
        assert len(features["ja3_hash"]) == 32  # MD5 hex length

    def test_extract_ja3s_hash(self, extractor: TLSExtractor) -> None:
        """Test JA3S fingerprint computation."""
        flow = create_tls_flow()
        features = extractor.extract(flow)

        assert features["ja3s_hash"] != ""
        assert len(features["ja3s_hash"]) == 32

    def test_extract_cipher_suite(self, extractor: TLSExtractor) -> None:
        """Test cipher suite extraction from ServerHello."""
        flow = create_tls_flow()
        features = extractor.extract(flow)

        assert features["tls_cipher_suite"] == 0x1301  # TLS_AES_128_GCM_SHA256
        assert features["tls_cipher_count"] > 0

    def test_extract_certificate_metadata(self, extractor: TLSExtractor) -> None:
        """Test certificate chain extraction."""
        flow = create_tls_flow(include_certificate=True)
        features = extractor.extract(flow)

        assert features["tls_cert_count"] == 2  # Mock has 2 certs
        assert features["tls_cert_total_length"] == 1024 + 512
        assert features["tls_cert_first_length"] == 1024
        assert features["tls_cert_chain_length"] == 2

    def test_extract_no_certificate(self, extractor: TLSExtractor) -> None:
        """Test flow without certificate (session resumption)."""
        flow = create_tls_flow(include_certificate=False)
        features = extractor.extract(flow)

        assert features["tls_cert_count"] == 0
        # Session resumed if no certificate seen
        # (depends on session ID/ticket)

    def test_extract_handshake_packets(self, extractor: TLSExtractor) -> None:
        """Test handshake packet counting."""
        flow = create_tls_flow()
        features = extractor.extract(flow)

        assert features["tls_handshake_packets"] >= 2

    def test_extract_alpn(self, extractor: TLSExtractor) -> None:
        """Test ALPN protocol extraction."""
        flow = create_tls_flow()
        features = extractor.extract(flow)

        assert features["tls_alpn"] == "h2"

    def test_extract_extension_count(self, extractor: TLSExtractor) -> None:
        """Test extension count."""
        flow = create_tls_flow()
        features = extractor.extract(flow)

        assert features["tls_extension_count"] > 0

    def test_no_tls_traffic(self, extractor: TLSExtractor) -> None:
        """Test extraction from non-TLS flow."""
        from joyfuljay.core.flow import Flow
        from joyfuljay.core.packet import Packet

        # Plain HTTP-like traffic
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
            raw_payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )

        flow = Flow.from_first_packet(packet)
        features = extractor.extract(flow)

        assert features["tls_detected"] is False
        assert features["tls_version"] == 0
        assert features["ja3_hash"] == ""

    def test_malformed_tls_record(self, extractor: TLSExtractor) -> None:
        """Test handling of malformed TLS data."""
        from joyfuljay.core.flow import Flow
        from joyfuljay.core.packet import Packet

        # Truncated TLS record
        packet = Packet(
            timestamp=1000.0,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            protocol=6,
            payload_len=5,
            total_len=45,
            tcp_flags=0x18,
            raw_payload=b"\x16\x03\x01\x00",  # Incomplete record
        )

        flow = Flow.from_first_packet(packet)
        features = extractor.extract(flow)

        # Should not crash, just return defaults
        assert features["tls_detected"] is False

    def test_validate_features(self, extractor: TLSExtractor) -> None:
        """Test feature validation."""
        flow = create_tls_flow()
        features = extractor.extract(flow)

        assert extractor.validate_features(features)

    def test_session_resumption_detection(self, extractor: TLSExtractor) -> None:
        """Test session resumption detection."""
        flow = create_tls_flow(include_certificate=False)
        features = extractor.extract(flow)

        # Without certificate, session might be resumed
        assert "tls_session_resumed" in features
        assert "tls_session_id_len" in features
        assert "tls_session_ticket_ext" in features

    def test_key_exchange_extraction(self, extractor: TLSExtractor) -> None:
        """Test DH/ECDHE key exchange parameter extraction."""
        flow = create_tls_flow()
        features = extractor.extract(flow)

        # Key exchange features should exist
        assert "tls_key_exchange_group" in features
        assert "tls_key_exchange_group_name" in features
        assert "tls_key_exchange_length" in features
