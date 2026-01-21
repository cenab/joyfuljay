"""Schema module for feature registry and profile management."""

from __future__ import annotations

from .registry import (
    DType,
    FeatureMeta,
    Privacy,
    Scope,
    all_feature_ids,
    all_feature_meta,
    get_extractors,
    get_feature_ids_ordered,
)
from .profiles import (
    list_profiles,
    load_profile,
    validate_profile,
    get_profile_features,
)
from .tiering import (
    validate_tiering_complete,
    get_feature_tier,
    get_all_feature_tiers,
)
from .generate import (
    generate_feature_schema,
    generate_minimal_schema,
    write_schema,
)

__all__ = [
    # Registry
    "DType",
    "FeatureMeta",
    "Privacy",
    "Scope",
    "all_feature_ids",
    "all_feature_meta",
    "get_extractors",
    "get_feature_ids_ordered",
    # Profiles
    "list_profiles",
    "load_profile",
    "validate_profile",
    "get_profile_features",
    # Tiering
    "validate_tiering_complete",
    "get_feature_tier",
    "get_all_feature_tiers",
    # Schema generation
    "generate_feature_schema",
    "generate_minimal_schema",
    "write_schema",
]
