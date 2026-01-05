"""Native extensions for performance-critical operations.

This package provides Cython-optimized implementations of hot paths:

- `fast_stats`: Optimized statistics computation (single-pass algorithms)
- `fast_entropy`: Optimized entropy and byte distribution analysis

The extensions are optional. If not compiled, pure Python fallbacks are used.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Track which extensions are available
_CYTHON_AVAILABLE = False
_FAST_STATS_AVAILABLE = False
_FAST_ENTROPY_AVAILABLE = False

try:
    from ._fast_stats import (
        compute_statistics_fast,
        compute_interarrival_times_fast,
        compute_percentiles_fast,
    )
    _FAST_STATS_AVAILABLE = True
    _CYTHON_AVAILABLE = True
except ImportError:
    # Fall back to pure Python implementations
    from ..utils.stats import (
        compute_statistics_dict as compute_statistics_fast,
        compute_interarrival_times_list as compute_interarrival_times_fast,
        compute_percentiles_dict as compute_percentiles_fast,
    )
    logger.debug("Cython fast_stats not available, using pure Python")

try:
    from ._fast_entropy import (
        shannon_entropy_fast,
        byte_distribution_fast,
        character_class_counts_fast,
    )
    _FAST_ENTROPY_AVAILABLE = True
    _CYTHON_AVAILABLE = True
except ImportError:
    # Fall back to pure Python implementations
    from ..utils.entropy import (
        shannon_entropy_fallback as shannon_entropy_fast,
        byte_distribution_fallback as byte_distribution_fast,
        character_class_counts_fallback as character_class_counts_fast,
    )
    logger.debug("Cython fast_entropy not available, using pure Python")


def is_cython_available() -> bool:
    """Check if any Cython extensions are available."""
    return _CYTHON_AVAILABLE


def get_available_extensions() -> dict[str, bool]:
    """Get status of all extensions."""
    return {
        "fast_stats": _FAST_STATS_AVAILABLE,
        "fast_entropy": _FAST_ENTROPY_AVAILABLE,
    }


__all__ = [
    "compute_statistics_fast",
    "compute_interarrival_times_fast",
    "compute_percentiles_fast",
    "shannon_entropy_fast",
    "byte_distribution_fast",
    "character_class_counts_fast",
    "is_cython_available",
    "get_available_extensions",
]
