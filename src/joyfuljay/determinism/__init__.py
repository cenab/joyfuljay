"""Determinism module for reproducible feature extraction.

This module provides utilities and guarantees for deterministic behavior:
- Flow key computation with canonical ordering
- Direction semantics (forward/backward, initiator/responder)
- Precision and rounding rules for floating-point values

See docs/engineering/determinism.md for full documentation.
"""

from __future__ import annotations

from .key import (
    compute_flow_key,
    normalize_endpoint_pair,
    FlowKeyComponents,
)
from .direction import (
    Direction,
    DirectionSemantics,
    determine_direction,
    get_direction_label,
)
from .rounding import (
    RoundingPolicy,
    apply_rounding,
    get_precision,
    validate_precision,
)

__all__ = [
    # Key computation
    "compute_flow_key",
    "normalize_endpoint_pair",
    "FlowKeyComponents",
    # Direction
    "Direction",
    "DirectionSemantics",
    "determine_direction",
    "get_direction_label",
    # Rounding
    "RoundingPolicy",
    "apply_rounding",
    "get_precision",
    "validate_precision",
]
