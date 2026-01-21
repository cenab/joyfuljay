"""Runtime resources for JoyfulJay.

This module provides access to packaged resources like profiles and schemas
using importlib.resources for reliable access regardless of installation method.
"""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import Any


def get_profile_path(profile_name: str) -> Path:
    """Get the path to a profile file.

    Args:
        profile_name: Name of the profile (e.g., "JJ-CORE").

    Returns:
        Path to the profile file.

    Raises:
        FileNotFoundError: If profile doesn't exist.
    """
    try:
        files = resources.files("joyfuljay.resources.profiles")
        profile_file = files.joinpath(f"{profile_name}.txt")
        # Use as_file for compatibility
        with resources.as_file(profile_file) as path:
            if not path.exists():
                raise FileNotFoundError(f"Profile not found: {profile_name}")
            return path
    except (TypeError, AttributeError):
        # Fallback for older Python versions
        import importlib.resources as legacy_resources
        with legacy_resources.path("joyfuljay.resources.profiles", f"{profile_name}.txt") as path:
            return path


def load_profile_features(profile_name: str) -> list[str]:
    """Load feature IDs from a profile file.

    Args:
        profile_name: Name of the profile (e.g., "JJ-CORE").

    Returns:
        List of feature IDs in the profile.

    Raises:
        FileNotFoundError: If profile doesn't exist.
    """
    try:
        files = resources.files("joyfuljay.resources.profiles")
        profile_file = files.joinpath(f"{profile_name}.txt")
        content = profile_file.read_text(encoding="utf-8")
    except (TypeError, AttributeError):
        # Fallback for older Python versions
        import importlib.resources as legacy_resources
        content = legacy_resources.read_text("joyfuljay.resources.profiles", f"{profile_name}.txt")

    features = []
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            features.append(line)
    return features


def list_available_profiles() -> list[str]:
    """List all available profile names.

    Returns:
        List of profile names (without .txt extension).
    """
    try:
        files = resources.files("joyfuljay.resources.profiles")
        return [
            f.name.removesuffix(".txt")
            for f in files.iterdir()
            if f.name.endswith(".txt")
        ]
    except (TypeError, AttributeError):
        # Fallback: return known profiles
        return ["JJ-CORE", "JJ-EXTENDED", "JJ-EXPERIMENTAL"]


def get_schema_path(version: str = "v1.0") -> Path:
    """Get the path to the feature schema file.

    Args:
        version: Schema version (default: "v1.0").

    Returns:
        Path to the schema JSON file.

    Raises:
        FileNotFoundError: If schema doesn't exist.
    """
    try:
        files = resources.files(f"joyfuljay.resources.schema.{version}")
        schema_file = files.joinpath("feature_schema.json")
        with resources.as_file(schema_file) as path:
            if not path.exists():
                raise FileNotFoundError(f"Schema not found: {version}")
            return path
    except (TypeError, AttributeError, ModuleNotFoundError):
        # Fallback for older Python versions or missing schema
        raise FileNotFoundError(f"Schema not found: {version}")


def load_schema(version: str = "v1.0") -> dict[str, Any]:
    """Load the feature schema.

    Args:
        version: Schema version (default: "v1.0").

    Returns:
        Schema dictionary.

    Raises:
        FileNotFoundError: If schema doesn't exist.
    """
    try:
        files = resources.files(f"joyfuljay.resources.schema.{version}")
        schema_file = files.joinpath("feature_schema.json")
        content = schema_file.read_text(encoding="utf-8")
        return json.loads(content)
    except (TypeError, AttributeError, ModuleNotFoundError):
        raise FileNotFoundError(f"Schema not found: {version}")


__all__ = [
    "get_profile_path",
    "load_profile_features",
    "list_available_profiles",
    "get_schema_path",
    "load_schema",
]
