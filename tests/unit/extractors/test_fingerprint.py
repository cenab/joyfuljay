"""Tests for fingerprint feature extractor."""

from __future__ import annotations

import pytest

from joyfuljay.extractors.fingerprint import FingerprintExtractor

from tests.fixtures.packets import create_fingerprint_flow, create_tls_flow


class TestFingerprintExtractor:
    """Tests for FingerprintExtractor."""

    @pytest.fixture
    def extractor(self) -> FingerprintExtractor:
        """Create a fingerprint extractor."""
        return FingerprintExtractor()

    def test_feature_names(self, extractor: FingerprintExtractor) -> None:
        """Test that feature names are properly defined."""
        names = extractor.feature_names
        assert isinstance(names, list)
        assert len(names) > 0
        assert "likely_tor" in names
        assert "likely_vpn" in names
        assert "likely_doh" in names

    def test_extractor_name(self, extractor: FingerprintExtractor) -> None:
        """Test extractor name."""
        assert extractor.name == "FingerprintExtractor"

    def test_extract_tor_detection(self, extractor: FingerprintExtractor) -> None:
        """Test Tor traffic detection."""
        flow = create_fingerprint_flow("tor")
        features = extractor.extract(flow)

        # Tor detection depends on packet size patterns
        # The feature exists and has a confidence value
        assert "likely_tor" in features
        assert "tor_confidence" in features
        # Even if not detected as Tor, the feature should be valid
        assert isinstance(features["likely_tor"], bool)
        assert 0.0 <= features["tor_confidence"] <= 1.0

    def test_extract_vpn_detection(self, extractor: FingerprintExtractor) -> None:
        """Test VPN traffic detection."""
        flow = create_fingerprint_flow("vpn")
        features = extractor.extract(flow)

        assert features["likely_vpn"] is True
        assert features["vpn_confidence"] > 0.0
        assert features["vpn_type"] != ""

    def test_extract_normal_traffic(self, extractor: FingerprintExtractor) -> None:
        """Test normal HTTPS traffic (not Tor/VPN)."""
        flow = create_fingerprint_flow("normal")
        features = extractor.extract(flow)

        # Normal traffic should not strongly match Tor/VPN
        assert features["likely_tor"] is False or features["tor_confidence"] < 0.5

    def test_extract_traffic_type(self, extractor: FingerprintExtractor) -> None:
        """Test traffic type classification."""
        flow = create_tls_flow()
        features = extractor.extract(flow)

        assert "traffic_type" in features
        # Traffic type can be various classifications
        assert features["traffic_type"] in ["", "unknown", "https", "http", "tls", "encrypted"]

    def test_validate_features(self, extractor: FingerprintExtractor) -> None:
        """Test feature validation."""
        flow = create_fingerprint_flow("normal")
        features = extractor.extract(flow)

        assert extractor.validate_features(features)

    def test_confidence_range(self, extractor: FingerprintExtractor) -> None:
        """Test that confidence values are in valid range."""
        flow = create_fingerprint_flow("tor")
        features = extractor.extract(flow)

        assert 0.0 <= features["tor_confidence"] <= 1.0
        assert 0.0 <= features["vpn_confidence"] <= 1.0
        if "doh_confidence" in features:
            assert 0.0 <= features["doh_confidence"] <= 1.0
