"""Output format handlers for feature export."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from types import TracebackType
from typing import Any, Iterator, TextIO

import numpy as np
import pandas as pd


class StreamingWriter:
    """Incrementally writes features to disk to avoid memory issues with large captures.

    Supports CSV, JSON Lines, and Parquet (in row groups) formats.
    Use as a context manager to ensure proper cleanup.

    Example:
        >>> with StreamingWriter("output.csv", format="csv") as writer:
        ...     for flow in pipeline.process_live_stream("en0"):
        ...         features = pipeline._extract_features(flow)
        ...         writer.write(features)
    """

    def __init__(
        self,
        path: str | Path,
        format: str = "csv",
        parquet_row_group_size: int = 10000,
        compression: str | None = None,
    ) -> None:
        """Initialize the streaming writer.

        Args:
            path: Output file path.
            format: Output format ("csv", "jsonl", "parquet").
            parquet_row_group_size: Number of rows per Parquet row group.
            compression: Compression for Parquet files.
        """
        self.path = Path(path)
        self.format = format.lower()
        self.parquet_row_group_size = parquet_row_group_size
        self.compression = compression or ("snappy" if format == "parquet" else None)

        self._file: TextIO | None = None
        self._csv_writer: csv.DictWriter[Any] | None = None
        self._header_written = False
        self._fieldnames: list[str] | None = None
        self._row_count = 0

        # For Parquet buffering
        self._parquet_buffer: list[dict[str, Any]] = []
        self._parquet_writer: Any | None = None

    def __enter__(self) -> "StreamingWriter":
        """Open the output file."""
        if self.format == "parquet":
            # Parquet uses buffered writing
            pass
        else:
            self._file = self.path.open("w", newline="" if self.format == "csv" else None)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Close the output file and flush any remaining data."""
        self.close()

    def write(self, features: dict[str, Any]) -> None:
        """Write a single feature dictionary to the output.

        Args:
            features: Feature dictionary for one flow.
        """
        self._row_count += 1

        if self.format == "csv":
            self._write_csv(features)
        elif self.format == "jsonl":
            self._write_jsonl(features)
        elif self.format == "parquet":
            self._write_parquet(features)
        else:
            raise ValueError(f"Unknown format: {self.format}")

    def write_many(self, features_iter: Iterator[dict[str, Any]]) -> int:
        """Write multiple feature dictionaries from an iterator.

        Args:
            features_iter: Iterator of feature dictionaries.

        Returns:
            Number of rows written.
        """
        for features in features_iter:
            self.write(features)
        return self._row_count

    def _write_csv(self, features: dict[str, Any]) -> None:
        """Write a row to CSV."""
        if self._file is None:
            raise RuntimeError("CSV writer is not opened")
        if self._csv_writer is None:
            self._fieldnames = list(features.keys())
            self._csv_writer = csv.DictWriter(self._file, fieldnames=self._fieldnames)
            self._csv_writer.writeheader()
            self._header_written = True

        # Convert lists to JSON strings
        processed: dict[str, Any] = {}
        for key, value in features.items():
            if isinstance(value, list):
                processed[key] = json.dumps(value)
            elif isinstance(value, (np.integer, np.floating)):
                processed[key] = float(value)
            else:
                processed[key] = value
        self._csv_writer.writerow(processed)

    def _write_jsonl(self, features: dict[str, Any]) -> None:
        """Write a row to JSON Lines."""
        if self._file is None:
            raise RuntimeError("JSONL writer is not opened")
        self._file.write(json.dumps(_serialize_row(features)) + "\n")

    def _write_parquet(self, features: dict[str, Any]) -> None:
        """Buffer and write to Parquet in row groups."""
        self._parquet_buffer.append(features)

        if len(self._parquet_buffer) >= self.parquet_row_group_size:
            self._flush_parquet_buffer()

    def _flush_parquet_buffer(self) -> None:
        """Flush the Parquet buffer to disk."""
        if not self._parquet_buffer:
            return

        try:
            import pyarrow as pa
            import pyarrow.parquet as pq
        except ImportError as e:
            raise ImportError(
                "pyarrow is required for Parquet output. "
                "Install with: pip install pyarrow"
            ) from e

        df = to_dataframe(self._parquet_buffer)

        # Convert list columns to string representation
        for col in df.columns:
            if df[col].dtype == object:
                try:
                    if len(df) > 0 and isinstance(df[col].iloc[0], list):
                        df[col] = df[col].apply(
                            lambda x: json.dumps(x) if isinstance(x, list) else x
                        )
                except (IndexError, TypeError):
                    pass

        table = pa.Table.from_pandas(df)

        if self._parquet_writer is None:
            self._parquet_writer = pq.ParquetWriter(
                self.path, table.schema, compression=self.compression
            )

        writer = self._parquet_writer
        if writer is None:
            raise RuntimeError("Parquet writer initialization failed")
        writer.write_table(table)
        self._parquet_buffer = []

    def close(self) -> None:
        """Close the writer and flush any remaining data."""
        if self.format == "parquet":
            self._flush_parquet_buffer()
            if self._parquet_writer is not None:
                self._parquet_writer.close()
        elif self._file is not None:
            self._file.close()
            self._file = None

    @property
    def rows_written(self) -> int:
        """Return the number of rows written so far."""
        return self._row_count


def to_dataframe(features: list[dict[str, Any]]) -> pd.DataFrame:
    """Convert feature dictionaries to a pandas DataFrame.

    Args:
        features: List of feature dictionaries (one per flow).

    Returns:
        DataFrame with features as columns and flows as rows.
    """
    if not features:
        return pd.DataFrame()

    df = pd.DataFrame(features)

    # Convert appropriate columns to optimal dtypes
    for col in df.columns:
        if df[col].dtype == object:
            # Try to infer better dtype
            try:
                # Check if it's a list column (sequences)
                if isinstance(df[col].iloc[0], list):
                    continue  # Keep as object
                df[col] = pd.to_numeric(df[col])
            except (ValueError, TypeError, IndexError):
                pass

    return df


def to_numpy(
    features: list[dict[str, Any]],
) -> tuple[np.ndarray, list[str]]:
    """Convert feature dictionaries to a NumPy array.

    Non-numeric columns (IPs, sequences) are excluded from the array.

    Args:
        features: List of feature dictionaries.

    Returns:
        Tuple of (array, feature_names) where array has shape
        (n_flows, n_numeric_features).
    """
    if not features:
        return np.array([]), []

    df = to_dataframe(features)

    # Select only numeric columns
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()

    # Remove sequence columns (lists stored as object)
    numeric_cols = [c for c in numeric_cols if not c.endswith("_sequence")]

    if not numeric_cols:
        return np.array([]), []

    array = df[numeric_cols].to_numpy(dtype=np.float64)
    return array, numeric_cols


def to_csv(
    features: list[dict[str, Any]],
    path: str | Path,
    include_header: bool = True,
) -> None:
    """Write features to a CSV file.

    Args:
        features: List of feature dictionaries.
        path: Output file path.
        include_header: Whether to include column headers.
    """
    if not features:
        # Write empty file with header if available
        Path(path).touch()
        return

    df = to_dataframe(features)

    # Convert list columns to strings for CSV compatibility
    for col in df.columns:
        if df[col].dtype == object:
            try:
                if isinstance(df[col].iloc[0], list):
                    df[col] = df[col].apply(lambda x: json.dumps(x) if isinstance(x, list) else x)
            except (IndexError, TypeError):
                pass

    df.to_csv(path, index=False, header=include_header)


def to_csv_stream(
    features: list[dict[str, Any]],
    file: TextIO,
    include_header: bool = True,
) -> None:
    """Stream features to a CSV file object.

    Useful for writing to stdout or open file handles.

    Args:
        features: List of feature dictionaries.
        file: File object to write to.
        include_header: Whether to include column headers.
    """
    if not features:
        return

    fieldnames = list(features[0].keys())
    writer = csv.DictWriter(file, fieldnames=fieldnames)

    if include_header:
        writer.writeheader()

    for row in features:
        # Convert lists to JSON strings
        processed_row = {}
        for key, value in row.items():
            if isinstance(value, list):
                processed_row[key] = json.dumps(value)
            else:
                processed_row[key] = value
        writer.writerow(processed_row)


def to_json(
    features: list[dict[str, Any]],
    path: str | Path,
    lines: bool = True,
) -> None:
    """Write features to a JSON file.

    Args:
        features: List of feature dictionaries.
        path: Output file path.
        lines: If True, write one JSON object per line (JSON Lines format).
               If False, write as a JSON array.
    """
    path = Path(path)

    if lines:
        # JSON Lines format (one object per line)
        with path.open("w") as f:
            for row in features:
                f.write(json.dumps(_serialize_row(row)) + "\n")
    else:
        # Standard JSON array
        with path.open("w") as f:
            json.dump([_serialize_row(row) for row in features], f, indent=2)


def to_json_stream(
    features: list[dict[str, Any]],
    file: TextIO,
) -> None:
    """Stream features as JSON Lines to a file object.

    Args:
        features: List of feature dictionaries.
        file: File object to write to.
    """
    for row in features:
        file.write(json.dumps(_serialize_row(row)) + "\n")


def _serialize_row(row: dict[str, Any]) -> dict[str, Any]:
    """Serialize a feature row to JSON-compatible types.

    Args:
        row: Feature dictionary.

    Returns:
        Dictionary with JSON-compatible values.
    """
    result: dict[str, Any] = {}
    for key, value in row.items():
        if isinstance(value, (np.integer, np.floating)):
            result[key] = float(value)
        elif isinstance(value, np.ndarray):
            result[key] = value.tolist()
        elif value is None or isinstance(value, (str, int, float, bool, list)):
            result[key] = value
        else:
            result[key] = str(value)
    return result


def to_parquet(
    features: list[dict[str, Any]],
    path: str | Path,
    compression: str = "snappy",
) -> None:
    """Write features to a Parquet file.

    Parquet is a columnar format ideal for big data analytics.
    Offers excellent compression and fast column-wise queries.

    Args:
        features: List of feature dictionaries.
        path: Output file path.
        compression: Compression codec ('snappy', 'gzip', 'brotli', 'lz4', 'zstd', None).

    Raises:
        ImportError: If pyarrow is not installed.
    """
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ImportError as e:
        raise ImportError(
            "pyarrow is required for Parquet output. "
            "Install with: pip install pyarrow"
        ) from e

    if not features:
        # Create empty parquet file
        table = pa.table({})
        pq.write_table(table, path, compression=compression)
        return

    df = to_dataframe(features)

    # Convert list columns to string representation for Parquet compatibility
    for col in df.columns:
        if df[col].dtype == object:
            try:
                if len(df) > 0 and isinstance(df[col].iloc[0], list):
                    df[col] = df[col].apply(
                        lambda x: json.dumps(x) if isinstance(x, list) else x
                    )
            except (IndexError, TypeError):
                pass

    # Convert to Arrow table and write
    table = pa.Table.from_pandas(df)
    pq.write_table(table, path, compression=compression)


def is_parquet_available() -> bool:
    """Check if Parquet output is available (pyarrow installed)."""
    try:
        import pyarrow  # noqa: F401

        return True
    except ImportError:
        return False
