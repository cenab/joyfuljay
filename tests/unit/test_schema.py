"""Tests for feature schema utilities."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from joyfuljay.output.schema import (
    FEATURE_DEFINITIONS,
    FeatureDefinition,
    FeatureType,
    export_schema_csv,
    export_schema_json,
    get_all_feature_names,
    get_available_groups,
    get_feature_definition,
    get_feature_documentation,
    get_features_by_group,
)


class TestFeatureType:
    """Tests for FeatureType enum."""

    def test_string_type(self) -> None:
        """Test STRING type."""
        assert FeatureType.STRING.value == "string"

    def test_integer_type(self) -> None:
        """Test INTEGER type."""
        assert FeatureType.INTEGER.value == "integer"

    def test_float_type(self) -> None:
        """Test FLOAT type."""
        assert FeatureType.FLOAT.value == "float"

    def test_boolean_type(self) -> None:
        """Test BOOLEAN type."""
        assert FeatureType.BOOLEAN.value == "boolean"

    def test_sequence_type(self) -> None:
        """Test SEQUENCE type."""
        assert FeatureType.SEQUENCE.value == "sequence"

    def test_all_types_are_strings(self) -> None:
        """Test that all types are string enums."""
        for ft in FeatureType:
            assert isinstance(ft.value, str)


class TestFeatureDefinition:
    """Tests for FeatureDefinition dataclass."""

    def test_basic_creation(self) -> None:
        """Test basic creation."""
        defn = FeatureDefinition(
            name="test_feature",
            type=FeatureType.INTEGER,
            description="A test feature",
        )

        assert defn.name == "test_feature"
        assert defn.type == FeatureType.INTEGER
        assert defn.description == "A test feature"
        assert defn.unit is None
        assert defn.group == "general"

    def test_with_all_fields(self) -> None:
        """Test with all fields specified."""
        defn = FeatureDefinition(
            name="duration",
            type=FeatureType.FLOAT,
            description="Flow duration",
            unit="seconds",
            group="timing",
        )

        assert defn.name == "duration"
        assert defn.unit == "seconds"
        assert defn.group == "timing"

    def test_to_dict(self) -> None:
        """Test to_dict method."""
        defn = FeatureDefinition(
            name="test",
            type=FeatureType.BOOLEAN,
            description="Test desc",
            unit="ms",
            group="test_group",
        )

        result = defn.to_dict()

        assert result["name"] == "test"
        assert result["type"] == "boolean"
        assert result["description"] == "Test desc"
        assert result["unit"] == "ms"
        assert result["group"] == "test_group"

    def test_frozen(self) -> None:
        """Test that FeatureDefinition is frozen."""
        defn = FeatureDefinition(
            name="test",
            type=FeatureType.STRING,
            description="Test",
        )

        with pytest.raises(AttributeError):
            defn.name = "new_name"  # type: ignore


class TestFeatureDefinitions:
    """Tests for FEATURE_DEFINITIONS dictionary."""

    def test_not_empty(self) -> None:
        """Test that definitions are populated."""
        assert len(FEATURE_DEFINITIONS) > 0

    def test_contains_common_features(self) -> None:
        """Test that common features are defined."""
        expected = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "duration"]
        for feat in expected:
            assert feat in FEATURE_DEFINITIONS, f"Missing feature: {feat}"

    def test_all_definitions_have_required_fields(self) -> None:
        """Test that all definitions have required fields."""
        for name, defn in FEATURE_DEFINITIONS.items():
            assert defn.name == name
            assert isinstance(defn.type, FeatureType)
            assert defn.description != ""
            assert defn.group != ""


class TestGetFeatureDefinition:
    """Tests for get_feature_definition function."""

    def test_existing_feature(self) -> None:
        """Test getting an existing feature."""
        defn = get_feature_definition("src_ip")

        assert defn is not None
        assert defn.name == "src_ip"
        assert defn.type == FeatureType.STRING

    def test_nonexistent_feature(self) -> None:
        """Test getting a nonexistent feature."""
        defn = get_feature_definition("nonexistent_feature")
        assert defn is None

    def test_returns_correct_type(self) -> None:
        """Test that function returns FeatureDefinition or None."""
        result = get_feature_definition("duration")
        assert isinstance(result, FeatureDefinition)


class TestGetFeatureDocumentation:
    """Tests for get_feature_documentation function."""

    def test_returns_string(self) -> None:
        """Test that function returns a string."""
        result = get_feature_documentation()
        assert isinstance(result, str)

    def test_contains_markdown_headers(self) -> None:
        """Test that output contains markdown headers."""
        result = get_feature_documentation()
        assert "# Feature Documentation" in result

    def test_contains_table_format(self) -> None:
        """Test that output contains markdown tables."""
        result = get_feature_documentation()
        assert "| Feature |" in result
        assert "|---" in result

    def test_contains_feature_names(self) -> None:
        """Test that output contains feature names."""
        result = get_feature_documentation()
        assert "`src_ip`" in result
        assert "`dst_ip`" in result


class TestExportSchemaJSON:
    """Tests for export_schema_json function."""

    def test_returns_valid_json(self) -> None:
        """Test that function returns valid JSON."""
        result = export_schema_json()
        parsed = json.loads(result)

        assert isinstance(parsed, dict)

    def test_contains_version(self) -> None:
        """Test that output contains version."""
        result = export_schema_json()
        parsed = json.loads(result)

        assert "version" in parsed

    def test_contains_features_list(self) -> None:
        """Test that output contains features list."""
        result = export_schema_json()
        parsed = json.loads(result)

        assert "features" in parsed
        assert isinstance(parsed["features"], list)
        assert len(parsed["features"]) > 0

    def test_contains_groups_list(self) -> None:
        """Test that output contains groups list."""
        result = export_schema_json()
        parsed = json.loads(result)

        assert "groups" in parsed
        assert isinstance(parsed["groups"], list)

    def test_writes_to_file(self, tmp_path: Path) -> None:
        """Test writing to file."""
        output_file = tmp_path / "schema.json"
        export_schema_json(output_file)

        assert output_file.exists()
        content = json.loads(output_file.read_text())
        assert "features" in content

    def test_returns_same_with_and_without_file(self, tmp_path: Path) -> None:
        """Test that return value is the same with and without file."""
        output_file = tmp_path / "schema.json"

        result1 = export_schema_json()
        result2 = export_schema_json(output_file)

        assert result1 == result2


class TestExportSchemaCSV:
    """Tests for export_schema_csv function."""

    def test_returns_string(self) -> None:
        """Test that function returns a string."""
        result = export_schema_csv()
        assert isinstance(result, str)

    def test_has_header_row(self) -> None:
        """Test that output has header row."""
        result = export_schema_csv()
        lines = result.strip().split("\n")

        assert "name" in lines[0]
        assert "type" in lines[0]
        assert "description" in lines[0]

    def test_has_data_rows(self) -> None:
        """Test that output has data rows."""
        result = export_schema_csv()
        lines = result.strip().split("\n")

        # Should have more than just header
        assert len(lines) > 1

    def test_writes_to_file(self, tmp_path: Path) -> None:
        """Test writing to file."""
        output_file = tmp_path / "schema.csv"
        export_schema_csv(output_file)

        assert output_file.exists()
        content = output_file.read_text()
        assert "name,type,description" in content


class TestGetAllFeatureNames:
    """Tests for get_all_feature_names function."""

    def test_returns_list(self) -> None:
        """Test that function returns a list."""
        result = get_all_feature_names()
        assert isinstance(result, list)

    def test_returns_sorted(self) -> None:
        """Test that list is sorted."""
        result = get_all_feature_names()
        assert result == sorted(result)

    def test_contains_expected_features(self) -> None:
        """Test that list contains expected features."""
        result = get_all_feature_names()
        assert "src_ip" in result
        assert "dst_ip" in result


class TestGetFeaturesByGroup:
    """Tests for get_features_by_group function."""

    def test_returns_list(self) -> None:
        """Test that function returns a list."""
        result = get_features_by_group("flow_meta")
        assert isinstance(result, list)

    def test_returns_correct_group(self) -> None:
        """Test that all returned features are in correct group."""
        result = get_features_by_group("flow_meta")

        for defn in result:
            assert defn.group == "flow_meta"

    def test_empty_for_unknown_group(self) -> None:
        """Test that unknown group returns empty list."""
        result = get_features_by_group("nonexistent_group")
        assert result == []


class TestGetAvailableGroups:
    """Tests for get_available_groups function."""

    def test_returns_list(self) -> None:
        """Test that function returns a list."""
        result = get_available_groups()
        assert isinstance(result, list)

    def test_returns_sorted(self) -> None:
        """Test that list is sorted."""
        result = get_available_groups()
        assert result == sorted(result)

    def test_contains_common_groups(self) -> None:
        """Test that list contains common groups."""
        result = get_available_groups()
        expected = ["flow_meta", "timing", "tls"]
        for group in expected:
            assert group in result, f"Missing group: {group}"

    def test_no_duplicates(self) -> None:
        """Test that there are no duplicate groups."""
        result = get_available_groups()
        assert len(result) == len(set(result))
