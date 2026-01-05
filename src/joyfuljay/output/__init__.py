"""Output format handlers for feature export."""

from __future__ import annotations

from .database import DatabaseWriter, detect_database_backend, to_database
from .formats import (
    StreamingWriter,
    is_parquet_available,
    to_csv,
    to_csv_stream,
    to_dataframe,
    to_json,
    to_json_stream,
    to_numpy,
    to_parquet,
)
from .kafka import KafkaWriter, is_kafka_available, to_kafka

__all__ = [
    "DatabaseWriter",
    "KafkaWriter",
    "StreamingWriter",
    "detect_database_backend",
    "is_kafka_available",
    "is_parquet_available",
    "to_csv",
    "to_csv_stream",
    "to_database",
    "to_dataframe",
    "to_json",
    "to_json_stream",
    "to_kafka",
    "to_numpy",
    "to_parquet",
]
