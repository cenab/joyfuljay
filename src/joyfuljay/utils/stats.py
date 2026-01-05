"""Statistical computation utilities."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

import numpy as np


@dataclass(slots=True)
class Statistics:
    """Container for computed statistics."""

    count: int
    min: float
    max: float
    mean: float
    std: float
    median: float
    sum: float
    p25: float
    p75: float
    p90: float
    p99: float


def compute_statistics(values: Sequence[float]) -> Statistics:
    """Compute comprehensive statistics for a sequence of values.

    Args:
        values: Sequence of numeric values.

    Returns:
        Statistics object with all computed metrics.
    """
    if len(values) == 0:
        return Statistics(
            count=0,
            min=0.0,
            max=0.0,
            mean=0.0,
            std=0.0,
            median=0.0,
            sum=0.0,
            p25=0.0,
            p75=0.0,
            p90=0.0,
            p99=0.0,
        )

    arr = np.array(values, dtype=np.float64)

    return Statistics(
        count=len(arr),
        min=float(np.min(arr)),
        max=float(np.max(arr)),
        mean=float(np.mean(arr)),
        std=float(np.std(arr)),
        median=float(np.median(arr)),
        sum=float(np.sum(arr)),
        p25=float(np.percentile(arr, 25)),
        p75=float(np.percentile(arr, 75)),
        p90=float(np.percentile(arr, 90)),
        p99=float(np.percentile(arr, 99)),
    )


def compute_percentiles(
    values: Sequence[float],
    percentiles: Sequence[int] = (25, 50, 75, 90, 95, 99),
) -> dict[str, float]:
    """Compute specified percentiles for a sequence of values.

    Args:
        values: Sequence of numeric values.
        percentiles: Percentile values to compute.

    Returns:
        Dictionary mapping percentile names (e.g., "p25") to values.
    """
    if len(values) == 0:
        return {f"p{p}": 0.0 for p in percentiles}

    arr = np.array(values, dtype=np.float64)
    result: dict[str, float] = {}

    for p in percentiles:
        result[f"p{p}"] = float(np.percentile(arr, p))

    return result


def coefficient_of_variation(values: Sequence[float]) -> float:
    """Compute coefficient of variation (std / mean).

    Useful for measuring relative variability, often used
    as a burstiness index.

    Args:
        values: Sequence of numeric values.

    Returns:
        Coefficient of variation, or 0.0 if mean is zero.
    """
    if len(values) == 0:
        return 0.0

    arr = np.array(values, dtype=np.float64)
    mean = np.mean(arr)

    if mean == 0:
        return 0.0

    return float(np.std(arr) / mean)


def compute_interarrival_times(timestamps: Sequence[float]) -> list[float]:
    """Compute inter-arrival times from a sequence of timestamps.

    Args:
        timestamps: Sequence of timestamps in chronological order.

    Returns:
        List of inter-arrival times (gaps between consecutive timestamps).
    """
    if len(timestamps) < 2:
        return []

    arr = np.array(timestamps, dtype=np.float64)
    return list(np.diff(arr))


# --- Dict-returning versions for Cython fallback compatibility ---


def compute_statistics_dict(values: Sequence[float]) -> dict[str, float | int]:
    """Compute comprehensive statistics, returning a dict.

    This is the pure Python fallback for the Cython compute_statistics_fast.

    Args:
        values: Sequence of numeric values.

    Returns:
        Dictionary with count, min, max, mean, std, median, sum,
        p25, p75, p90, p99.
    """
    n = len(values)

    if n == 0:
        return {
            "count": 0,
            "min": 0.0,
            "max": 0.0,
            "mean": 0.0,
            "std": 0.0,
            "median": 0.0,
            "sum": 0.0,
            "p25": 0.0,
            "p75": 0.0,
            "p90": 0.0,
            "p99": 0.0,
        }

    arr = np.array(values, dtype=np.float64)

    # Single sort for all percentiles
    sorted_arr = np.sort(arr)
    total = float(np.sum(arr))
    mean = total / n
    variance = float(np.sum((arr - mean) ** 2)) / n
    std = float(np.sqrt(variance))

    def percentile_from_sorted(p: float) -> float:
        idx = (n - 1) * p / 100.0
        lower = int(idx)
        upper = min(lower + 1, n - 1)
        frac = idx - lower
        return float(sorted_arr[lower] * (1 - frac) + sorted_arr[upper] * frac)

    return {
        "count": n,
        "min": float(sorted_arr[0]),
        "max": float(sorted_arr[-1]),
        "mean": mean,
        "std": std,
        "median": percentile_from_sorted(50.0),
        "sum": total,
        "p25": percentile_from_sorted(25.0),
        "p75": percentile_from_sorted(75.0),
        "p90": percentile_from_sorted(90.0),
        "p99": percentile_from_sorted(99.0),
    }


def compute_interarrival_times_list(timestamps: Sequence[float]) -> list[float]:
    """Compute inter-arrival times from timestamps.

    Pure Python fallback for compute_interarrival_times_fast.
    Same as compute_interarrival_times but with a different name for clarity.

    Args:
        timestamps: Sequence of timestamps in chronological order.

    Returns:
        List of inter-arrival times.
    """
    if len(timestamps) < 2:
        return []

    arr = np.array(timestamps, dtype=np.float64)
    return list(np.diff(arr))


def compute_percentiles_dict(
    values: Sequence[float],
    percentiles: Sequence[int] = (25, 50, 75, 90, 95, 99),
) -> dict[str, float]:
    """Compute specified percentiles efficiently with single sort.

    Pure Python fallback for compute_percentiles_fast.

    Args:
        values: Sequence of numeric values.
        percentiles: Percentile values to compute.

    Returns:
        Dictionary mapping "pXX" to percentile value.
    """
    n = len(values)

    if n == 0:
        return {f"p{p}": 0.0 for p in percentiles}

    sorted_arr = np.sort(np.array(values, dtype=np.float64))

    def percentile_from_sorted(p: float) -> float:
        idx = (n - 1) * p / 100.0
        lower = int(idx)
        upper = min(lower + 1, n - 1)
        frac = idx - lower
        return float(sorted_arr[lower] * (1 - frac) + sorted_arr[upper] * frac)

    return {f"p{int(p)}": percentile_from_sorted(float(p)) for p in percentiles}
