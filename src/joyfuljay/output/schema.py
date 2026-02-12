"""Feature schema definitions and documentation.

This module backs the `jj schema` and `jj features` CLI commands.

Historically this file contained a small hand-written subset of feature
definitions. That drifted from the actual extractors/profiles over time.
We now generate documentation/schema from the feature registry metadata
(`joyfuljay.schema.registry`) so the CLI reflects the real output columns.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any


class FeatureType(str, Enum):
    """Feature data types."""

    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    SEQUENCE = "sequence"


@dataclass(frozen=True)
class FeatureDefinition:
    """Definition of a single feature.

    Attributes:
        name: Feature name (column name in output).
        type: Data type of the feature.
        description: Human-readable description.
        unit: Unit of measurement (if applicable).
        group: Feature group this belongs to.
    """

    name: str
    type: FeatureType
    description: str
    unit: str | None = None
    group: str = "general"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON export."""
        return {
            "name": self.name,
            "type": self.type.value,
            "description": self.description,
            "unit": self.unit,
            "group": self.group,
        }


def _dtype_to_feature_type(dtype: str) -> FeatureType:
    dt = dtype.lower()
    if dt in {"string", "categorical"}:
        return FeatureType.STRING
    if dt in {"int", "int32", "int64", "uint32", "uint64"}:
        return FeatureType.INTEGER
    if dt in {"float", "float32", "float64"}:
        return FeatureType.FLOAT
    if dt in {"bool", "boolean"}:
        return FeatureType.BOOLEAN
    return FeatureType.STRING


@lru_cache
def _feature_definitions_by_name() -> dict[str, FeatureDefinition]:
    """Build a map of output column name -> FeatureDefinition."""
    from ..schema.registry import all_feature_meta

    defs: dict[str, FeatureDefinition] = {}
    for feature_id, meta in all_feature_meta().items():
        if "." in feature_id:
            group, name = feature_id.split(".", 1)
        else:
            group, name = "general", feature_id

        if name in defs:
            raise ValueError(
                f"Duplicate feature name across extractors: {name} "
                f"(example id: {feature_id})"
            )

        defs[name] = FeatureDefinition(
            name=name,
            type=_dtype_to_feature_type(meta.dtype),
            description=meta.description,
            unit=meta.units or None,
            group=group,
        )

    return defs


def get_feature_definition(name: str) -> FeatureDefinition | None:
    """Get the definition for a feature by name.

    Args:
        name: Feature name.

    Returns:
        FeatureDefinition if found, None otherwise.
    """
    return _feature_definitions_by_name().get(name)


def get_feature_documentation(group: str | None = None) -> str:
    """Generate markdown documentation for features.

    Returns:
        Markdown-formatted feature documentation.
    """
    lines = ["# Feature Documentation\n"]

    # Group features by their group
    groups: dict[str, list[FeatureDefinition]] = {}
    for defn in _feature_definitions_by_name().values():
        if group is not None and defn.group != group:
            continue
        if defn.group not in groups:
            groups[defn.group] = []
        groups[defn.group].append(defn)

    for group_name, features in sorted(groups.items()):
        lines.append(f"\n## {group_name.replace('_', ' ').title()}\n")
        lines.append("| Feature | Type | Description | Unit |")
        lines.append("|---------|------|-------------|------|")

        for feat in sorted(features, key=lambda f: f.name):
            unit = feat.unit or "-"
            lines.append(f"| `{feat.name}` | {feat.type.value} | {feat.description} | {unit} |")

    return "\n".join(lines)


def export_schema_json(path: str | Path | None = None, group: str | None = None) -> str:
    """Export feature schema as JSON.

    Args:
        path: Optional file path to write to. If None, returns JSON string.
        group: Optional feature group name to filter by.

    Returns:
        JSON string representation of the schema.
    """
    defs = list(
        _feature_definitions_by_name().values()
        if group is None
        else get_features_by_group(group)
    )
    schema = {
        "version": "1.0",
        "features": [defn.to_dict() for defn in sorted(defs, key=lambda d: (d.group, d.name))],
        "groups": sorted(set(d.group for d in defs)),
    }

    json_str = json.dumps(schema, indent=2)

    if path:
        Path(path).write_text(json_str)

    return json_str


def export_schema_csv(path: str | Path | None = None, group: str | None = None) -> str:
    """Export feature schema as CSV.

    Args:
        path: Optional file path to write to. If None, returns CSV string.
        group: Optional feature group name to filter by.

    Returns:
        CSV string representation of the schema.
    """
    import csv
    import io

    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow(["name", "type", "description", "unit", "group"])

    # Data
    defs = (
        _feature_definitions_by_name().values()
        if group is None
        else get_features_by_group(group)
    )
    for defn in sorted(defs, key=lambda d: (d.group, d.name)):
        writer.writerow([defn.name, defn.type.value, defn.description, defn.unit or "", defn.group])

    csv_str = output.getvalue()

    if path:
        Path(path).write_text(csv_str)

    return csv_str


def get_all_feature_names() -> list[str]:
    """Get list of all documented feature names.

    Returns:
        Sorted list of feature names.
    """
    return sorted(_feature_definitions_by_name().keys())


def get_features_by_group(group: str) -> list[FeatureDefinition]:
    """Get all features in a specific group.

    Args:
        group: Feature group name.

    Returns:
        List of FeatureDefinition objects in the group.
    """
    return [defn for defn in _feature_definitions_by_name().values() if defn.group == group]


def get_available_groups() -> list[str]:
    """Get list of available feature groups.

    Returns:
        Sorted list of unique group names.
    """
    return sorted(set(d.group for d in _feature_definitions_by_name().values()))


# Backwards-compatible public mapping used by older callers/tests.
# Keyed by output column name (basename).
FEATURE_DEFINITIONS: dict[str, FeatureDefinition] = _feature_definitions_by_name()
