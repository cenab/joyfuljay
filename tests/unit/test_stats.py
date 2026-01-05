"""Tests for statistical utility functions."""

from __future__ import annotations

import pytest

from joyfuljay.utils.stats import (
    coefficient_of_variation,
    compute_interarrival_times,
    compute_percentiles,
    compute_statistics,
)


class TestComputeStatistics:
    """Tests for compute_statistics function."""

    def test_basic_statistics(self) -> None:
        """Test basic statistical calculations."""
        values = [1.0, 2.0, 3.0, 4.0, 5.0]
        stats = compute_statistics(values)

        assert stats.count == 5
        assert stats.min == 1.0
        assert stats.max == 5.0
        assert stats.mean == 3.0
        assert stats.sum == 15.0
        assert stats.median == 3.0

    def test_empty_input(self) -> None:
        """Test with empty input."""
        stats = compute_statistics([])

        assert stats.count == 0
        assert stats.min == 0.0
        assert stats.max == 0.0
        assert stats.mean == 0.0

    def test_single_value(self) -> None:
        """Test with single value."""
        stats = compute_statistics([42.0])

        assert stats.count == 1
        assert stats.min == 42.0
        assert stats.max == 42.0
        assert stats.mean == 42.0
        assert stats.std == 0.0

    def test_percentiles(self) -> None:
        """Test percentile calculations."""
        values = list(range(1, 101))  # 1 to 100
        stats = compute_statistics(values)

        assert stats.p25 == pytest.approx(25.75, rel=0.1)
        assert stats.p75 == pytest.approx(75.25, rel=0.1)
        assert stats.p90 == pytest.approx(90.1, rel=0.1)
        assert stats.p99 == pytest.approx(99.01, rel=0.1)


class TestComputePercentiles:
    """Tests for compute_percentiles function."""

    def test_default_percentiles(self) -> None:
        """Test default percentile calculation."""
        values = list(range(1, 101))
        result = compute_percentiles(values)

        assert "p25" in result
        assert "p50" in result
        assert "p75" in result
        assert "p90" in result
        assert "p95" in result
        assert "p99" in result

    def test_custom_percentiles(self) -> None:
        """Test custom percentile calculation."""
        values = list(range(1, 101))
        result = compute_percentiles(values, percentiles=[10, 50, 90])

        assert "p10" in result
        assert "p50" in result
        assert "p90" in result
        assert "p25" not in result

    def test_empty_input(self) -> None:
        """Test with empty input."""
        result = compute_percentiles([])

        assert result["p25"] == 0.0
        assert result["p75"] == 0.0


class TestCoefficientOfVariation:
    """Tests for coefficient_of_variation function."""

    def test_uniform_values(self) -> None:
        """Test with uniform values (CV should be 0)."""
        values = [5.0, 5.0, 5.0, 5.0]
        cv = coefficient_of_variation(values)
        assert cv == 0.0

    def test_varying_values(self) -> None:
        """Test with varying values."""
        values = [1.0, 2.0, 3.0, 4.0, 5.0]
        cv = coefficient_of_variation(values)
        assert cv > 0

    def test_empty_input(self) -> None:
        """Test with empty input."""
        cv = coefficient_of_variation([])
        assert cv == 0.0

    def test_zero_mean(self) -> None:
        """Test with zero mean (should return 0 to avoid division by zero)."""
        values = [-1.0, 0.0, 1.0]
        cv = coefficient_of_variation(values)
        # Mean is 0, so CV should handle this gracefully
        assert cv == 0.0


class TestComputeInterarrivalTimes:
    """Tests for compute_interarrival_times function."""

    def test_basic_iat(self) -> None:
        """Test basic IAT calculation."""
        timestamps = [0.0, 1.0, 3.0, 6.0]
        iats = compute_interarrival_times(timestamps)

        assert len(iats) == 3
        assert iats[0] == 1.0
        assert iats[1] == 2.0
        assert iats[2] == 3.0

    def test_single_timestamp(self) -> None:
        """Test with single timestamp."""
        iats = compute_interarrival_times([1.0])
        assert len(iats) == 0

    def test_empty_input(self) -> None:
        """Test with empty input."""
        iats = compute_interarrival_times([])
        assert len(iats) == 0

    def test_two_timestamps(self) -> None:
        """Test with two timestamps."""
        iats = compute_interarrival_times([0.0, 0.5])
        assert len(iats) == 1
        assert iats[0] == 0.5
