"""Property-based tests for entropy utilities."""

from __future__ import annotations

from hypothesis import given, settings, strategies as st

from joyfuljay.utils.entropy import (
    byte_entropy,
    byte_histogram,
    byte_distribution_uniformity,
    normalized_entropy,
)


@given(st.binary(min_size=0, max_size=1024))
@settings(max_examples=50)
def test_entropy_bounds(data: bytes) -> None:
    entropy = byte_entropy(data)
    normalized = normalized_entropy(data)

    assert 0.0 <= entropy <= 8.0
    assert 0.0 <= normalized <= 1.0


@given(st.binary(min_size=0, max_size=1024))
@settings(max_examples=50)
def test_histogram_counts(data: bytes) -> None:
    histogram = byte_histogram(data)
    assert len(histogram) == 256
    assert sum(histogram) == len(data)


@given(st.binary(min_size=0, max_size=2048))
@settings(max_examples=50)
def test_uniformity_bounds(data: bytes) -> None:
    uniformity = byte_distribution_uniformity(data)
    assert uniformity >= 0.0
