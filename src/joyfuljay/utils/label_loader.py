"""Label loading and merging utilities for ML training.

Provides functions to load labels from various formats and merge them
with extracted flow features for supervised learning.
"""

from __future__ import annotations

import csv
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

logger = logging.getLogger(__name__)


@dataclass
class LabelMapping:
    """Mapping configuration for flow labels.

    Attributes:
        flow_id_column: Column name for flow ID in label file.
        label_column: Column name for the label.
        src_ip_column: Source IP column for flow matching.
        dst_ip_column: Destination IP column for flow matching.
        src_port_column: Source port column.
        dst_port_column: Destination port column.
        protocol_column: Protocol column.
        timestamp_column: Timestamp column for temporal matching.
        timestamp_tolerance: Tolerance in seconds for timestamp matching.
    """

    flow_id_column: str | None = None
    label_column: str = "label"
    src_ip_column: str = "src_ip"
    dst_ip_column: str = "dst_ip"
    src_port_column: str = "src_port"
    dst_port_column: str = "dst_port"
    protocol_column: str = "protocol"
    timestamp_column: str | None = None
    timestamp_tolerance: float = 1.0


class LabelLoader:
    """Load and merge labels with flow features.

    Supports CSV, JSON, and JSON Lines label files with flexible
    column mapping for various dataset formats.
    """

    def __init__(
        self,
        mapping: LabelMapping | None = None,
        default_label: str = "unknown",
    ) -> None:
        """Initialize the label loader.

        Args:
            mapping: Column mapping configuration.
            default_label: Default label for unmatched flows.
        """
        self.mapping = mapping or LabelMapping()
        self.default_label = default_label
        self._labels: dict[str, str] = {}
        self._label_records: list[dict[str, Any]] = []

    def load_csv(self, path: str | Path) -> int:
        """Load labels from a CSV file.

        Args:
            path: Path to the CSV file.

        Returns:
            Number of labels loaded.

        Raises:
            FileNotFoundError: If file doesn't exist.
            ValueError: If required columns are missing.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Label file not found: {path}")

        self._label_records = []
        with path.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)

            # Verify required columns
            if reader.fieldnames:
                self._verify_columns(reader.fieldnames)

            for row in reader:
                self._label_records.append(dict(row))

        self._build_index()
        logger.info(f"Loaded {len(self._label_records)} labels from {path}")
        return len(self._label_records)

    def load_json(self, path: str | Path) -> int:
        """Load labels from a JSON file.

        Supports both JSON array and JSON Lines format.

        Args:
            path: Path to the JSON file.

        Returns:
            Number of labels loaded.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Label file not found: {path}")

        self._label_records = []
        with path.open("r", encoding="utf-8") as f:
            content = f.read().strip()

            if content.startswith("["):
                # JSON array
                self._label_records = json.loads(content)
            else:
                # JSON Lines
                for line in content.split("\n"):
                    if line.strip():
                        self._label_records.append(json.loads(line))

        self._build_index()
        logger.info(f"Loaded {len(self._label_records)} labels from {path}")
        return len(self._label_records)

    def load_auto(self, path: str | Path) -> int:
        """Auto-detect format and load labels.

        Args:
            path: Path to the label file.

        Returns:
            Number of labels loaded.
        """
        path = Path(path)
        suffix = path.suffix.lower()

        if suffix == ".csv":
            return self.load_csv(path)
        elif suffix in (".json", ".jsonl"):
            return self.load_json(path)
        else:
            # Try to detect from content
            with path.open("r", encoding="utf-8") as f:
                first_char = f.read(1)
                if first_char in ("{", "["):
                    return self.load_json(path)
                else:
                    return self.load_csv(path)

    def _verify_columns(self, columns: Sequence[str]) -> None:
        """Verify required columns exist.

        Args:
            columns: List of column names from file.

        Raises:
            ValueError: If label column is missing.
        """
        if self.mapping.label_column not in columns:
            raise ValueError(
                f"Label column '{self.mapping.label_column}' not found. "
                f"Available columns: {columns}"
            )

    def _build_index(self) -> None:
        """Build lookup index for fast matching."""
        self._labels = {}

        for record in self._label_records:
            label = record.get(self.mapping.label_column, self.default_label)

            # Build flow key
            if self.mapping.flow_id_column and self.mapping.flow_id_column in record:
                key = str(record[self.mapping.flow_id_column])
            else:
                # Build key from 5-tuple
                key = self._make_flow_key(record)

            if key:
                self._labels[key] = str(label)

    def _make_flow_key(self, record: dict[str, Any]) -> str:
        """Create a flow key from record fields.

        Args:
            record: Label record.

        Returns:
            Flow key string.
        """
        parts = []
        if self.mapping.src_ip_column in record:
            parts.append(str(record[self.mapping.src_ip_column]))
        if self.mapping.src_port_column in record:
            parts.append(str(record[self.mapping.src_port_column]))
        if self.mapping.dst_ip_column in record:
            parts.append(str(record[self.mapping.dst_ip_column]))
        if self.mapping.dst_port_column in record:
            parts.append(str(record[self.mapping.dst_port_column]))
        if self.mapping.protocol_column in record:
            parts.append(str(record[self.mapping.protocol_column]))

        return ":".join(parts) if parts else ""

    def get_label(
        self,
        flow_id: str | None = None,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        src_port: int | None = None,
        dst_port: int | None = None,
        protocol: int | None = None,
    ) -> str:
        """Get label for a flow.

        Args:
            flow_id: Direct flow ID to look up.
            src_ip: Source IP address.
            dst_ip: Destination IP address.
            src_port: Source port.
            dst_port: Destination port.
            protocol: IP protocol number.

        Returns:
            Label string, or default_label if not found.
        """
        if flow_id and flow_id in self._labels:
            return self._labels[flow_id]

        # Try 5-tuple key
        key = ":".join(
            str(x) for x in [src_ip, src_port, dst_ip, dst_port, protocol] if x is not None
        )
        if key in self._labels:
            return self._labels[key]

        # Try reverse direction
        key_reverse = ":".join(
            str(x) for x in [dst_ip, dst_port, src_ip, src_port, protocol] if x is not None
        )
        if key_reverse in self._labels:
            return self._labels[key_reverse]

        return self.default_label

    def merge_with_features(
        self,
        features: list[dict[str, Any]],
        label_column_name: str = "label",
    ) -> list[dict[str, Any]]:
        """Merge labels with extracted features.

        Args:
            features: List of feature dictionaries.
            label_column_name: Name for the label column in output.

        Returns:
            Features with labels added.
        """
        for feature_dict in features:
            label = self.get_label(
                flow_id=feature_dict.get("flow_id"),
                src_ip=feature_dict.get("src_ip"),
                dst_ip=feature_dict.get("dst_ip"),
                src_port=feature_dict.get("src_port"),
                dst_port=feature_dict.get("dst_port"),
                protocol=feature_dict.get("protocol"),
            )
            feature_dict[label_column_name] = label

        return features

    @property
    def label_counts(self) -> dict[str, int]:
        """Get count of each label.

        Returns:
            Dictionary mapping labels to counts.
        """
        counts: dict[str, int] = {}
        for label in self._labels.values():
            counts[label] = counts.get(label, 0) + 1
        return counts

    @property
    def unique_labels(self) -> list[str]:
        """Get list of unique labels.

        Returns:
            Sorted list of unique label values.
        """
        return sorted(set(self._labels.values()))


def load_labels_from_file(
    path: str | Path,
    label_column: str = "label",
    **mapping_kwargs: Any,
) -> LabelLoader:
    """Convenience function to load labels from file.

    Args:
        path: Path to label file.
        label_column: Name of the label column.
        **mapping_kwargs: Additional mapping configuration.

    Returns:
        Configured LabelLoader with labels loaded.
    """
    mapping = LabelMapping(label_column=label_column, **mapping_kwargs)
    loader = LabelLoader(mapping=mapping)
    loader.load_auto(path)
    return loader
