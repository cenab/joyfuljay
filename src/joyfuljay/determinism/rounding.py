"""Rounding and precision rules for deterministic output.

This module defines the precision and rounding policies for different
feature types to ensure reproducible output across platforms.

Key principles:
- Use IEEE 754 double precision (64-bit) for all floats
- No rounding for most values (full precision)
- Integers are exact (no rounding needed)
- Timestamps use full nanosecond precision when available
"""

from __future__ import annotations

import math
from enum import Enum
from typing import Any


class RoundingPolicy(Enum):
    """Rounding policy for feature values.

    Attributes:
        NONE: No rounding, full IEEE 754 double precision.
        DECIMALS_3: Round to 3 decimal places.
        DECIMALS_6: Round to 6 decimal places (microsecond precision).
        DECIMALS_9: Round to 9 decimal places (nanosecond precision).
        INTEGER: Truncate to integer.
    """
    NONE = "none"
    DECIMALS_3 = "decimals_3"
    DECIMALS_6 = "decimals_6"
    DECIMALS_9 = "decimals_9"
    INTEGER = "integer"


# Default policies by feature category
DEFAULT_POLICIES: dict[str, RoundingPolicy] = {
    "timestamp": RoundingPolicy.NONE,      # Full precision for timestamps
    "duration": RoundingPolicy.NONE,       # Full precision for durations
    "count": RoundingPolicy.INTEGER,       # Counts are always integers
    "ratio": RoundingPolicy.NONE,          # Full precision for ratios
    "bytes": RoundingPolicy.INTEGER,       # Byte counts are integers
    "hash": RoundingPolicy.NONE,           # Hashes are strings, no rounding
    "statistical": RoundingPolicy.NONE,    # Full precision for stats
}


def get_precision(policy: RoundingPolicy) -> int | None:
    """Get the number of decimal places for a rounding policy.

    Args:
        policy: The rounding policy.

    Returns:
        Number of decimal places, or None for no rounding/integer.
    """
    precision_map = {
        RoundingPolicy.NONE: None,
        RoundingPolicy.DECIMALS_3: 3,
        RoundingPolicy.DECIMALS_6: 6,
        RoundingPolicy.DECIMALS_9: 9,
        RoundingPolicy.INTEGER: 0,
    }
    return precision_map.get(policy)


def apply_rounding(
    value: float | int,
    policy: RoundingPolicy = RoundingPolicy.NONE,
) -> float | int:
    """Apply rounding policy to a value.

    Args:
        value: The value to round.
        policy: The rounding policy to apply.

    Returns:
        The rounded value.

    Example:
        >>> apply_rounding(3.14159, RoundingPolicy.DECIMALS_3)
        3.142
        >>> apply_rounding(3.14159, RoundingPolicy.INTEGER)
        3
        >>> apply_rounding(3.14159, RoundingPolicy.NONE)
        3.14159
    """
    if policy == RoundingPolicy.NONE:
        return value
    elif policy == RoundingPolicy.INTEGER:
        return int(value)
    else:
        decimals = get_precision(policy)
        if decimals is not None:
            return round(value, decimals)
        return value


def validate_precision(
    value: float,
    expected_decimals: int | None = None,
    tolerance: float = 1e-12,
) -> bool:
    """Validate that a value has the expected precision.

    This is useful for golden test validation to ensure values
    match expected precision.

    Args:
        value: The value to validate.
        expected_decimals: Expected number of decimal places, or None for any.
        tolerance: Tolerance for floating-point comparison.

    Returns:
        True if value matches expected precision.
    """
    if expected_decimals is None:
        return True

    if expected_decimals == 0:
        return abs(value - round(value)) < tolerance

    # Check if value matches rounded version
    rounded = round(value, expected_decimals)
    return abs(value - rounded) < tolerance


def is_nan_safe(value: Any) -> bool:
    """Check if a value is NaN (safely handles non-float types).

    Args:
        value: The value to check.

    Returns:
        True if value is NaN, False otherwise.
    """
    try:
        return math.isnan(value)
    except (TypeError, ValueError):
        return False


def is_inf_safe(value: Any) -> bool:
    """Check if a value is infinite (safely handles non-float types).

    Args:
        value: The value to check.

    Returns:
        True if value is positive or negative infinity, False otherwise.
    """
    try:
        return math.isinf(value)
    except (TypeError, ValueError):
        return False


def normalize_float(
    value: float,
    nan_replacement: float | None = None,
    inf_replacement: float | None = None,
) -> float | None:
    """Normalize a float value, handling NaN and infinity.

    Args:
        value: The value to normalize.
        nan_replacement: Replacement for NaN values (None to keep NaN).
        inf_replacement: Replacement for infinite values (None to keep inf).

    Returns:
        The normalized value, or the appropriate replacement.
    """
    if is_nan_safe(value):
        return nan_replacement if nan_replacement is not None else value
    if is_inf_safe(value):
        return inf_replacement if inf_replacement is not None else value
    return value


def stable_mean(values: list[float]) -> float:
    """Compute mean using a numerically stable algorithm.

    Uses Welford's online algorithm to avoid floating-point
    accumulation errors for large datasets.

    Args:
        values: List of values to average.

    Returns:
        The mean value, or NaN if empty.
    """
    if not values:
        return float("nan")

    mean = 0.0
    for i, x in enumerate(values, 1):
        mean += (x - mean) / i
    return mean


def stable_variance(values: list[float], ddof: int = 0) -> float:
    """Compute variance using a numerically stable algorithm.

    Uses Welford's online algorithm for numerical stability.

    Args:
        values: List of values.
        ddof: Delta degrees of freedom (0 for population, 1 for sample).

    Returns:
        The variance, or NaN if insufficient values.
    """
    n = len(values)
    if n < ddof + 1:
        return float("nan")

    mean = 0.0
    m2 = 0.0

    for i, x in enumerate(values, 1):
        delta = x - mean
        mean += delta / i
        delta2 = x - mean
        m2 += delta * delta2

    return m2 / (n - ddof)


def stable_std(values: list[float], ddof: int = 0) -> float:
    """Compute standard deviation using a numerically stable algorithm.

    Args:
        values: List of values.
        ddof: Delta degrees of freedom (0 for population, 1 for sample).

    Returns:
        The standard deviation, or NaN if insufficient values.
    """
    var = stable_variance(values, ddof)
    if is_nan_safe(var):
        return float("nan")
    return math.sqrt(var)
