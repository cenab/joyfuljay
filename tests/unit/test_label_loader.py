"""Tests for label loading utilities."""

from __future__ import annotations

import csv
import json
import tempfile
from pathlib import Path

import pytest

from joyfuljay.utils.label_loader import (
    LabelLoader,
    LabelMapping,
    load_labels_from_file,
)


class TestLabelMapping:
    """Tests for LabelMapping dataclass."""

    def test_default_values(self) -> None:
        """Test default values."""
        mapping = LabelMapping()
        assert mapping.flow_id_column is None
        assert mapping.label_column == "label"
        assert mapping.src_ip_column == "src_ip"
        assert mapping.dst_ip_column == "dst_ip"
        assert mapping.src_port_column == "src_port"
        assert mapping.dst_port_column == "dst_port"
        assert mapping.protocol_column == "protocol"
        assert mapping.timestamp_column is None
        assert mapping.timestamp_tolerance == 1.0

    def test_custom_values(self) -> None:
        """Test custom values."""
        mapping = LabelMapping(
            label_column="class",
            src_ip_column="source",
            timestamp_tolerance=5.0,
        )
        assert mapping.label_column == "class"
        assert mapping.src_ip_column == "source"
        assert mapping.timestamp_tolerance == 5.0


class TestLabelLoaderCSV:
    """Tests for LabelLoader with CSV files."""

    def test_load_csv_basic(self, tmp_path: Path) -> None:
        """Test loading basic CSV labels."""
        csv_file = tmp_path / "labels.csv"
        csv_file.write_text(
            "src_ip,dst_ip,src_port,dst_port,protocol,label\n"
            "1.1.1.1,2.2.2.2,12345,80,6,benign\n"
            "3.3.3.3,4.4.4.4,54321,443,6,malware\n"
        )

        loader = LabelLoader()
        count = loader.load_csv(csv_file)

        assert count == 2

    def test_load_csv_with_flow_id(self, tmp_path: Path) -> None:
        """Test loading CSV with flow ID column."""
        csv_file = tmp_path / "labels.csv"
        csv_file.write_text(
            "flow_id,label\n"
            "flow-001,benign\n"
            "flow-002,malware\n"
        )

        mapping = LabelMapping(flow_id_column="flow_id")
        loader = LabelLoader(mapping=mapping)
        count = loader.load_csv(csv_file)

        assert count == 2
        assert loader.get_label(flow_id="flow-001") == "benign"
        assert loader.get_label(flow_id="flow-002") == "malware"

    def test_load_csv_file_not_found(self) -> None:
        """Test error when CSV file doesn't exist."""
        loader = LabelLoader()
        with pytest.raises(FileNotFoundError):
            loader.load_csv("/nonexistent/file.csv")

    def test_load_csv_missing_label_column(self, tmp_path: Path) -> None:
        """Test error when label column is missing."""
        csv_file = tmp_path / "labels.csv"
        csv_file.write_text("src_ip,dst_ip\n1.1.1.1,2.2.2.2\n")

        loader = LabelLoader()
        with pytest.raises(ValueError, match="Label column"):
            loader.load_csv(csv_file)


class TestLabelLoaderJSON:
    """Tests for LabelLoader with JSON files."""

    def test_load_json_array(self, tmp_path: Path) -> None:
        """Test loading JSON array format."""
        json_file = tmp_path / "labels.json"
        data = [
            {"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "label": "benign"},
            {"src_ip": "3.3.3.3", "dst_ip": "4.4.4.4", "label": "malware"},
        ]
        json_file.write_text(json.dumps(data))

        loader = LabelLoader()
        count = loader.load_json(json_file)

        assert count == 2

    def test_load_json_lines(self, tmp_path: Path) -> None:
        """Test loading JSON Lines format."""
        jsonl_file = tmp_path / "labels.jsonl"
        lines = [
            json.dumps({"src_ip": "1.1.1.1", "label": "benign"}),
            json.dumps({"src_ip": "2.2.2.2", "label": "malware"}),
        ]
        jsonl_file.write_text("\n".join(lines))

        loader = LabelLoader()
        count = loader.load_json(jsonl_file)

        assert count == 2

    def test_load_json_file_not_found(self) -> None:
        """Test error when JSON file doesn't exist."""
        loader = LabelLoader()
        with pytest.raises(FileNotFoundError):
            loader.load_json("/nonexistent/file.json")


class TestLabelLoaderAuto:
    """Tests for auto-detection loading."""

    def test_auto_detect_csv(self, tmp_path: Path) -> None:
        """Test auto-detecting CSV files."""
        csv_file = tmp_path / "labels.csv"
        csv_file.write_text("src_ip,label\n1.1.1.1,benign\n")

        loader = LabelLoader()
        count = loader.load_auto(csv_file)
        assert count == 1

    def test_auto_detect_json(self, tmp_path: Path) -> None:
        """Test auto-detecting JSON files."""
        json_file = tmp_path / "labels.json"
        json_file.write_text('[{"src_ip": "1.1.1.1", "label": "benign"}]')

        loader = LabelLoader()
        count = loader.load_auto(json_file)
        assert count == 1

    def test_auto_detect_jsonl(self, tmp_path: Path) -> None:
        """Test auto-detecting JSONL files."""
        jsonl_file = tmp_path / "labels.jsonl"
        jsonl_file.write_text('{"src_ip": "1.1.1.1", "label": "benign"}')

        loader = LabelLoader()
        count = loader.load_auto(jsonl_file)
        assert count == 1


class TestLabelLoaderGetLabel:
    """Tests for get_label method."""

    @pytest.fixture
    def loaded_loader(self, tmp_path: Path) -> LabelLoader:
        """Create a loader with labels loaded."""
        csv_file = tmp_path / "labels.csv"
        csv_file.write_text(
            "src_ip,dst_ip,src_port,dst_port,protocol,label\n"
            "1.1.1.1,2.2.2.2,12345,80,6,benign\n"
            "3.3.3.3,4.4.4.4,54321,443,6,malware\n"
        )

        loader = LabelLoader()
        loader.load_csv(csv_file)
        return loader

    def test_get_label_by_5tuple(self, loaded_loader: LabelLoader) -> None:
        """Test getting label by 5-tuple."""
        label = loaded_loader.get_label(
            src_ip="1.1.1.1",
            src_port=12345,
            dst_ip="2.2.2.2",
            dst_port=80,
            protocol=6,
        )
        assert label == "benign"

    def test_get_label_reverse_direction(self, loaded_loader: LabelLoader) -> None:
        """Test getting label with reversed direction."""
        label = loaded_loader.get_label(
            src_ip="2.2.2.2",
            src_port=80,
            dst_ip="1.1.1.1",
            dst_port=12345,
            protocol=6,
        )
        assert label == "benign"

    def test_get_label_not_found(self, loaded_loader: LabelLoader) -> None:
        """Test default label when not found."""
        label = loaded_loader.get_label(
            src_ip="9.9.9.9",
            dst_ip="8.8.8.8",
        )
        assert label == "unknown"

    def test_get_label_custom_default(self, tmp_path: Path) -> None:
        """Test custom default label."""
        csv_file = tmp_path / "labels.csv"
        csv_file.write_text("src_ip,label\n1.1.1.1,benign\n")

        loader = LabelLoader(default_label="unlabeled")
        loader.load_csv(csv_file)

        label = loader.get_label(src_ip="9.9.9.9")
        assert label == "unlabeled"


class TestLabelLoaderMerge:
    """Tests for merge_with_features method."""

    def test_merge_with_features(self, tmp_path: Path) -> None:
        """Test merging labels with features."""
        csv_file = tmp_path / "labels.csv"
        csv_file.write_text(
            "flow_id,label\n"
            "flow-001,benign\n"
            "flow-002,malware\n"
        )

        mapping = LabelMapping(flow_id_column="flow_id")
        loader = LabelLoader(mapping=mapping)
        loader.load_csv(csv_file)

        features = [
            {"flow_id": "flow-001", "packets": 100},
            {"flow_id": "flow-002", "packets": 50},
            {"flow_id": "flow-003", "packets": 75},
        ]

        result = loader.merge_with_features(features)

        assert result[0]["label"] == "benign"
        assert result[1]["label"] == "malware"
        assert result[2]["label"] == "unknown"

    def test_merge_custom_column_name(self, tmp_path: Path) -> None:
        """Test merging with custom label column name."""
        csv_file = tmp_path / "labels.csv"
        csv_file.write_text("flow_id,label\nflow-001,benign\n")

        mapping = LabelMapping(flow_id_column="flow_id")
        loader = LabelLoader(mapping=mapping)
        loader.load_csv(csv_file)

        features = [{"flow_id": "flow-001"}]
        result = loader.merge_with_features(features, label_column_name="class")

        assert "class" in result[0]
        assert result[0]["class"] == "benign"


class TestLabelLoaderProperties:
    """Tests for LabelLoader properties."""

    def test_label_counts(self, tmp_path: Path) -> None:
        """Test label_counts property."""
        csv_file = tmp_path / "labels.csv"
        csv_file.write_text(
            "flow_id,label\n"
            "flow-001,benign\n"
            "flow-002,benign\n"
            "flow-003,malware\n"
        )

        mapping = LabelMapping(flow_id_column="flow_id")
        loader = LabelLoader(mapping=mapping)
        loader.load_csv(csv_file)

        counts = loader.label_counts
        assert counts["benign"] == 2
        assert counts["malware"] == 1

    def test_unique_labels(self, tmp_path: Path) -> None:
        """Test unique_labels property."""
        csv_file = tmp_path / "labels.csv"
        csv_file.write_text(
            "flow_id,label\n"
            "flow-001,benign\n"
            "flow-002,malware\n"
            "flow-003,benign\n"
        )

        mapping = LabelMapping(flow_id_column="flow_id")
        loader = LabelLoader(mapping=mapping)
        loader.load_csv(csv_file)

        labels = loader.unique_labels
        assert sorted(labels) == ["benign", "malware"]


class TestLoadLabelsFromFile:
    """Tests for load_labels_from_file convenience function."""

    def test_basic_usage(self, tmp_path: Path) -> None:
        """Test basic usage of convenience function."""
        csv_file = tmp_path / "labels.csv"
        csv_file.write_text("src_ip,label\n1.1.1.1,benign\n")

        loader = load_labels_from_file(csv_file)

        assert isinstance(loader, LabelLoader)
        assert len(loader.unique_labels) == 1

    def test_custom_label_column(self, tmp_path: Path) -> None:
        """Test with custom label column."""
        csv_file = tmp_path / "labels.csv"
        csv_file.write_text("src_ip,class\n1.1.1.1,benign\n")

        loader = load_labels_from_file(csv_file, label_column="class")

        assert "benign" in loader.unique_labels
