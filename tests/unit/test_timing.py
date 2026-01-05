"""Tests for timing feature extractor."""

from __future__ import annotations

import pytest

from joyfuljay.core.flow import Flow
from joyfuljay.extractors.timing import TimingExtractor


class TestTimingExtractor:
    """Tests for TimingExtractor."""

    @pytest.fixture
    def extractor(self) -> TimingExtractor:
        """Create a default timing extractor."""
        return TimingExtractor()

    @pytest.fixture
    def extractor_with_sequences(self) -> TimingExtractor:
        """Create a timing extractor that includes sequences."""
        return TimingExtractor(include_sequences=True, max_sequence_length=10)

    def test_feature_names(self, extractor: TimingExtractor) -> None:
        """Test that feature names are properly defined."""
        names = extractor.feature_names
        assert isinstance(names, list)
        assert len(names) > 0
        assert "iat_mean" in names
        assert "iat_std" in names
        assert "burstiness_index" in names

    def test_feature_names_with_sequences(
        self,
        extractor_with_sequences: TimingExtractor,
    ) -> None:
        """Test feature names include sequence when enabled."""
        names = extractor_with_sequences.feature_names
        assert "iat_sequence" in names

    def test_extract_features(
        self,
        extractor: TimingExtractor,
        sample_flow: Flow,
    ) -> None:
        """Test feature extraction from a sample flow."""
        features = extractor.extract(sample_flow)

        assert isinstance(features, dict)
        assert "iat_mean" in features
        assert "iat_std" in features
        assert "iat_min" in features
        assert "iat_max" in features
        assert "burst_count" in features

        # Check values are reasonable
        assert features["iat_mean"] >= 0
        assert features["iat_min"] >= 0
        assert features["iat_max"] >= features["iat_min"]

    def test_extract_burstiness(
        self,
        extractor: TimingExtractor,
        sample_flow: Flow,
    ) -> None:
        """Test burstiness metrics extraction."""
        features = extractor.extract(sample_flow)

        assert "burstiness_index" in features
        assert "burstiness_index_fwd" in features
        assert "burstiness_index_bwd" in features
        assert features["burstiness_index"] >= 0

    def test_extract_burst_metrics(
        self,
        extractor: TimingExtractor,
        sample_flow: Flow,
    ) -> None:
        """Test burst and idle metrics."""
        features = extractor.extract(sample_flow)

        assert "burst_count" in features
        assert "avg_burst_packets" in features
        assert "idle_count" in features
        assert "max_idle_duration" in features

    def test_extract_with_sequences(
        self,
        extractor_with_sequences: TimingExtractor,
        sample_flow: Flow,
    ) -> None:
        """Test that sequences are included when enabled."""
        features = extractor_with_sequences.extract(sample_flow)

        assert "iat_sequence" in features
        assert isinstance(features["iat_sequence"], list)
        assert len(features["iat_sequence"]) == 10  # max_sequence_length

    def test_first_response_time(
        self,
        extractor: TimingExtractor,
        sample_flow: Flow,
    ) -> None:
        """Test first response time calculation."""
        features = extractor.extract(sample_flow)

        assert "first_response_time" in features
        assert features["first_response_time"] >= 0
