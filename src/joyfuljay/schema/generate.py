"""Schema generator for feature metadata."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .registry import all_feature_ids, get_extractors, FeatureMeta
from .profiles import list_profiles, load_profile


def collect_feature_meta() -> dict[str, FeatureMeta]:
    """Collect feature metadata from all extractors (lenient mode).

    Returns:
        Dictionary mapping feature IDs to metadata.
    """
    all_meta: dict[str, FeatureMeta] = {}

    for extractor in get_extractors():
        try:
            meta = extractor.feature_meta()
            all_meta.update(meta)
        except Exception:
            # Skip extractors that fail to provide meta
            pass

    return all_meta


def generate_feature_schema() -> dict[str, Any]:
    """Generate complete feature schema with metadata.

    Returns:
        Schema dictionary with all features and their metadata.
    """
    from .. import __version__

    all_meta = collect_feature_meta()

    # Build profile membership mapping
    profile_membership: dict[str, str] = {}
    for profile in list_profiles():
        for feature_id in load_profile(profile):
            profile_membership[feature_id] = profile

    # Convert FeatureMeta to dict and add profile info
    features: dict[str, dict[str, Any]] = {}
    for feature_id, meta in sorted(all_meta.items()):
        feature_dict = asdict(meta)
        feature_dict["profile"] = profile_membership.get(feature_id, "unassigned")
        features[feature_id] = feature_dict

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "JoyfulJay Feature Schema",
        "description": "Schema for encrypted traffic feature extraction outputs",
        "version": "v1.0",
        "jj_version": __version__,
        "total_features": len(features),
        "profiles": {
            profile: len(load_profile(profile))
            for profile in list_profiles()
        },
        "features": features,
    }


def generate_minimal_schema() -> dict[str, Any]:
    """Generate minimal schema with just feature names, types, and profiles.

    Returns:
        Minimal schema dictionary.
    """
    all_meta = collect_feature_meta()

    # Build profile membership mapping
    profile_membership: dict[str, str] = {}
    for profile in list_profiles():
        for feature_id in load_profile(profile):
            profile_membership[feature_id] = profile

    features = {}
    for feature_id, meta in sorted(all_meta.items()):
        features[feature_id] = {
            "dtype": meta.dtype,
            "profile": profile_membership.get(feature_id, "unassigned"),
        }

    return {
        "version": "v1.0",
        "total_features": len(features),
        "features": features,
    }


def write_schema(
    output_path: str | Path,
    minimal: bool = False,
) -> None:
    """Write feature schema to JSON file.

    Args:
        output_path: Path to output JSON file.
        minimal: If True, generate minimal schema.
    """
    schema = generate_minimal_schema() if minimal else generate_feature_schema()
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(schema, f, indent=2, default=str)


def main() -> None:
    """CLI entry point for schema generation."""
    import argparse

    parser = argparse.ArgumentParser(description="Generate JoyfulJay feature schema")
    parser.add_argument(
        "-o", "--output",
        default="schema/v1.0/feature_schema.json",
        help="Output path for schema JSON",
    )
    parser.add_argument(
        "--minimal",
        action="store_true",
        help="Generate minimal schema",
    )
    args = parser.parse_args()

    write_schema(args.output, minimal=args.minimal)
    print(f"Schema written to: {args.output}")


if __name__ == "__main__":
    main()
