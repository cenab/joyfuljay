"""Profile loader and validation for feature sets."""

from __future__ import annotations

from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING

VALID_PROFILES = ["JJ-CORE", "JJ-EXTENDED", "JJ-EXPERIMENTAL"]


def _load_profile_content(profile: str) -> str:
    """Load profile file content using importlib.resources.

    Args:
        profile: Profile name (e.g., "JJ-CORE").

    Returns:
        Content of the profile file.

    Raises:
        FileNotFoundError: If profile file doesn't exist.
    """
    try:
        # Python 3.9+ approach
        files = resources.files("joyfuljay.resources.profiles")
        profile_file = files.joinpath(f"{profile}.txt")
        return profile_file.read_text(encoding="utf-8")
    except (TypeError, AttributeError, FileNotFoundError):
        # Fallback to filesystem path (for development)
        profiles_dir = Path(__file__).resolve().parents[1] / "resources" / "profiles"
        path = profiles_dir / f"{profile}.txt"
        if not path.exists():
            # Try the root profiles directory (legacy)
            legacy_dir = Path(__file__).resolve().parents[3] / "profiles"
            path = legacy_dir / f"{profile}.txt"
        if not path.exists():
            raise FileNotFoundError(f"Profile file not found: {profile}")
        return path.read_text(encoding="utf-8")


def list_profiles() -> list[str]:
    """List all available profile names.

    Returns:
        List of profile names.
    """
    return VALID_PROFILES.copy()


def load_profile(profile: str) -> list[str]:
    """Load feature IDs from a profile file.

    Args:
        profile: Profile name (e.g., "JJ-CORE").

    Returns:
        List of feature IDs in the profile (ordered as in file).

    Raises:
        FileNotFoundError: If profile file doesn't exist.
        ValueError: If profile contains duplicate feature IDs.
    """
    content = _load_profile_content(profile)

    ids: list[str] = []
    seen: set[str] = set()

    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line in seen:
            raise ValueError(f"Duplicate feature id in {profile}: {line}")
        seen.add(line)
        ids.append(line)

    return ids


def validate_profile(profile: str) -> None:
    """Validate that a profile contains only known feature IDs.

    Args:
        profile: Profile name to validate.

    Raises:
        ValueError: If profile contains unknown feature IDs.
    """
    from .registry import all_feature_ids

    defined = set(load_profile(profile))
    available = all_feature_ids()
    missing = defined - available

    if missing:
        raise ValueError(
            f"{profile} contains unknown feature ids: {sorted(missing)[:20]}"
        )


def get_profile_features(profile: str) -> set[str]:
    """Get the set of feature IDs in a profile.

    Args:
        profile: Profile name.

    Returns:
        Set of feature IDs.
    """
    return set(load_profile(profile))
