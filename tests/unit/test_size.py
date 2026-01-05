"""Tests for size feature extractor."""

from __future__ import annotations

import pytest

from joyfuljay.core.flow import Flow
from joyfuljay.extractors.size import SizeExtractor


class TestSizeExtractor:
    """Tests for SizeExtractor."""

    @pytest.fixture
    def extractor(self) -> SizeExtractor:
        """Create a default size extractor."""
        return SizeExtractor()

    @pytest.fixture
    def extractor_with_sequences(self) -> SizeExtractor:
        """Create a size extractor that includes sequences."""
        return SizeExtractor(include_sequences=True, max_sequence_length=10)

    def test_feature_names(self, extractor: SizeExtractor) -> None:
        """Test that feature names are properly defined."""
        names = extractor.feature_names
        assert isinstance(names, list)
        assert len(names) > 0
        assert "pkt_len_mean" in names
        assert "pkt_len_std" in names
        assert "dominant_pkt_size" in names

    def test_extract_features(
        self,
        extractor: SizeExtractor,
        sample_flow: Flow,
    ) -> None:
        """Test feature extraction from a sample flow."""
        features = extractor.extract(sample_flow)

        assert isinstance(features, dict)
        assert "pkt_len_mean" in features
        assert "pkt_len_std" in features
        assert "pkt_len_min" in features
        assert "pkt_len_max" in features

        # Check values are reasonable
        assert features["pkt_len_mean"] > 0
        assert features["pkt_len_min"] > 0
        assert features["pkt_len_max"] >= features["pkt_len_min"]

    def test_extract_directional_features(
        self,
        extractor: SizeExtractor,
        sample_flow: Flow,
    ) -> None:
        """Test per-direction size features."""
        features = extractor.extract(sample_flow)

        assert "pkt_len_fwd_mean" in features
        assert "pkt_len_bwd_mean" in features
        assert "payload_len_fwd_mean" in features
        assert "payload_len_bwd_mean" in features

    def test_extract_dominant_size(
        self,
        extractor: SizeExtractor,
        sample_flow: Flow,
    ) -> None:
        """Test dominant packet size detection."""
        features = extractor.extract(sample_flow)

        assert "dominant_pkt_size" in features
        assert "dominant_pkt_ratio" in features
        assert 0 <= features["dominant_pkt_ratio"] <= 1

    def test_extract_with_sequences(
        self,
        extractor_with_sequences: SizeExtractor,
        sample_flow: Flow,
    ) -> None:
        """Test that sequences are included when enabled."""
        features = extractor_with_sequences.extract(sample_flow)

        assert "pkt_len_sequence" in features
        assert isinstance(features["pkt_len_sequence"], list)
        assert len(features["pkt_len_sequence"]) == 10

    def test_header_only_ratio(
        self,
        extractor: SizeExtractor,
        sample_flow: Flow,
    ) -> None:
        """Test header-only packet ratio."""
        features = extractor.extract(sample_flow)

        assert "header_only_ratio" in features
        assert 0 <= features["header_only_ratio"] <= 1
        assert "packets_with_payload" in features
