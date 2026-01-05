"""Property-based tests for statistical utilities."""

from __future__ import annotations

import math

import pytest
from hypothesis import given, settings, strategies as st

from joyfuljay.utils.stats import (
    coefficient_of_variation,
    compute_interarrival_times,
    compute_statistics,
    compute_statistics_dict,
)


@given(
    st.lists(
        st.floats(min_value=-1e6, max_value=1e6, allow_nan=False, allow_infinity=False),
        min_size=1,
        max_size=100,
    )
)
@settings(max_examples=50)
def test_compute_statistics_invariants(values: list[float]) -> None:
    stats = compute_statistics(values)
    stats_dict = compute_statistics_dict(values)

    assert stats.count == len(values)
    assert stats.min <= stats.max
    # Use tolerance for floating-point comparison
    eps = 1e-10
    assert stats.min - eps <= stats.mean <= stats.max + eps
    assert stats.std >= 0.0
    assert math.isclose(stats.sum, sum(values), rel_tol=1e-6, abs_tol=1e-6)

    assert stats_dict["count"] == len(values)
    assert stats_dict["min"] <= stats_dict["max"]
    # Use tolerance for floating-point comparison
    assert stats_dict["min"] - eps <= stats_dict["mean"] <= stats_dict["max"] + eps
    assert stats_dict["std"] >= 0.0


@given(
    st.lists(
        st.floats(min_value=0.0, max_value=1e6, allow_nan=False, allow_infinity=False),
        min_size=1,
        max_size=100,
    )
)
@settings(max_examples=50)
def test_coefficient_of_variation_non_negative(values: list[float]) -> None:
    cov = coefficient_of_variation(values)
    assert cov >= 0.0


@given(
    st.lists(
        st.floats(min_value=0.0, max_value=1e6, allow_nan=False, allow_infinity=False),
        min_size=0,
        max_size=50,
    )
)
@settings(max_examples=50)
def test_interarrival_times_properties(timestamps: list[float]) -> None:
    timestamps_sorted = sorted(timestamps)
    gaps = compute_interarrival_times(timestamps_sorted)

    if len(timestamps_sorted) < 2:
        assert gaps == []
    else:
        assert len(gaps) == len(timestamps_sorted) - 1
        assert all(gap >= 0.0 for gap in gaps)
