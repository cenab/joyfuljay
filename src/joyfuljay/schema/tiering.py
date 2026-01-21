"""Tiering validation to ensure all features are assigned to exactly one profile."""

from __future__ import annotations

from .profiles import list_profiles, load_profile
from .registry import all_feature_ids


def validate_tiering_complete() -> None:
    """Validate that every feature is assigned to exactly one profile.

    Raises:
        ValueError: If features are in multiple profiles or not assigned.
    """
    all_ids = all_feature_ids()
    tiered: set[str] = set()
    overlap: set[str] = set()

    for profile in list_profiles():
        ids = set(load_profile(profile))
        overlap |= tiered & ids
        tiered |= ids

    missing = all_ids - tiered

    if overlap:
        raise ValueError(
            f"Features present in multiple profiles: {sorted(overlap)[:20]}"
        )
    if missing:
        raise ValueError(
            f"Features not assigned to any profile: {sorted(missing)[:20]}"
        )


def get_feature_tier(feature_id: str) -> str:
    """Get the tier (profile) for a feature ID.

    Args:
        feature_id: The feature ID to look up.

    Returns:
        Profile name containing this feature.

    Raises:
        ValueError: If feature is not in any profile.
    """
    for profile in list_profiles():
        if feature_id in set(load_profile(profile)):
            return profile

    raise ValueError(f"Feature {feature_id} not found in any profile")


def get_all_feature_tiers() -> dict[str, str]:
    """Get a mapping of all feature IDs to their tiers.

    Returns:
        Dictionary mapping feature ID to profile name.
    """
    tiers: dict[str, str] = {}
    for profile in list_profiles():
        for feature_id in load_profile(profile):
            tiers[feature_id] = profile
    return tiers
