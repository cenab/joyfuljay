"""Tests for padding feature extractor."""

from __future__ import annotations

import pytest

from joyfuljay.extractors.padding import PaddingExtractor

from tests.fixtures.packets import create_padding_flow


class TestPaddingExtractor:
    """Tests for PaddingExtractor."""

    @pytest.fixture
    def extractor(self) -> PaddingExtractor:
        """Create a padding extractor."""
        return PaddingExtractor()

    def test_feature_names(self, extractor: PaddingExtractor) -> None:
        """Test that feature names are properly defined."""
        names = extractor.feature_names
        assert isinstance(names, list)
        assert len(names) > 0
        assert "is_constant_size" in names
        assert "padding_score" in names

    def test_extractor_name(self, extractor: PaddingExtractor) -> None:
        """Test extractor name."""
        assert extractor.name == "PaddingExtractor"

    def test_extract_constant_size(self, extractor: PaddingExtractor) -> None:
        """Test constant packet size detection."""
        # All packets same size (Tor-like)
        flow = create_padding_flow([586, 586, 586, 586, 586])
        features = extractor.extract(flow)

        assert features["is_constant_size"] is True
        assert features["pkt_size_variance"] == 0

    def test_extract_variable_size(self, extractor: PaddingExtractor) -> None:
        """Test variable packet size detection."""
        flow = create_padding_flow([100, 500, 200, 1000, 300])
        features = extractor.extract(flow)

        assert features["is_constant_size"] is False
        assert features["pkt_size_variance"] > 0

    def test_extract_tor_cell_detection(self, extractor: PaddingExtractor) -> None:
        """Test Tor cell pattern detection (~586 bytes total_len)."""
        # Note: padding extractor uses total_len, so we need 586-40=546 payload
        # to get 586 total_len (with 40 byte header overhead)
        flow = create_padding_flow([546, 546, 546, 546, 546])
        features = extractor.extract(flow)

        # With 40-byte header overhead added in create_padding_flow,
        # total_len = 546 + 40 = 586, which matches Tor cell size
        assert features["tor_cell_count"] == 5
        assert features["tor_cell_ratio"] == 1.0
        assert features["is_tor_like"] is True

    def test_extract_dominant_size(self, extractor: PaddingExtractor) -> None:
        """Test dominant packet size detection."""
        # Most packets are 1000 bytes (total_len = payload + 40)
        flow = create_padding_flow([960, 960, 960, 460, 960])
        features = extractor.extract(flow)

        # dominant_size_mode is the feature name
        assert features["dominant_size_mode"] == 1000  # 960 + 40
        assert features["dominant_size_ratio"] == 0.8

    def test_extract_padding_score(self, extractor: PaddingExtractor) -> None:
        """Test padding score calculation."""
        flow = create_padding_flow([586, 586, 586, 586, 586])
        features = extractor.extract(flow)

        # High padding score for constant-size traffic
        assert features["padding_score"] >= 0.5

    def test_extract_size_entropy(self, extractor: PaddingExtractor) -> None:
        """Test size entropy calculation."""
        # Low entropy (uniform sizes)
        flow = create_padding_flow([100, 100, 100, 100, 100])
        features_uniform = extractor.extract(flow)

        # Higher entropy (varied sizes)
        flow = create_padding_flow([100, 200, 300, 400, 500])
        features_varied = extractor.extract(flow)

        assert features_uniform["size_entropy"] < features_varied["size_entropy"]

    def test_extract_unique_size_count(self, extractor: PaddingExtractor) -> None:
        """Test unique size counting."""
        flow = create_padding_flow([100, 200, 100, 300, 200])
        features = extractor.extract(flow)

        assert features["unique_size_count"] == 3

    def test_validate_features(self, extractor: PaddingExtractor) -> None:
        """Test feature validation."""
        flow = create_padding_flow()
        features = extractor.extract(flow)

        assert extractor.validate_features(features)

    def test_single_packet_flow(self, extractor: PaddingExtractor) -> None:
        """Test handling of single-packet flow."""
        flow = create_padding_flow([500])
        features = extractor.extract(flow)

        # Should not crash
        assert features["is_constant_size"] is True
        assert features["unique_size_count"] == 1
