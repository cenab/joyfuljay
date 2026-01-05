"""Kafka output sink for streaming feature rows."""

from __future__ import annotations

import json
from typing import Any, Iterable

import numpy as np


def is_kafka_available() -> bool:
    """Check if kafka-python is available."""
    try:
        import kafka  # noqa: F401
    except ImportError:
        return False
    return True


def _serialize_value(value: Any) -> Any:
    if isinstance(value, (np.integer, np.floating)):
        return value.item()
    if isinstance(value, np.ndarray):
        return value.tolist()
    if isinstance(value, (list, dict)):
        return value
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _serialize_row(row: dict[str, Any]) -> dict[str, Any]:
    return {key: _serialize_value(value) for key, value in row.items()}


class KafkaWriter:
    """Stream feature dictionaries to Kafka."""

    def __init__(
        self,
        brokers: str | list[str],
        topic: str,
        key_field: str | None = None,
        batch_size: int = 1000,
        acks: str | int = "all",
        compression_type: str | None = None,
        linger_ms: int | None = None,
        client_id: str | None = None,
        producer: Any | None = None,
    ) -> None:
        """Initialize a Kafka writer.

        Args:
            brokers: Kafka bootstrap servers (comma-separated or list).
            topic: Kafka topic to publish to.
            key_field: Optional feature field to use as Kafka message key.
            batch_size: Flush every N messages.
            acks: Kafka acknowledgements mode.
            compression_type: Optional Kafka compression type.
            linger_ms: Optional linger time in milliseconds.
            client_id: Optional Kafka client ID.
            producer: Optional injected producer (for testing).
        """
        if isinstance(brokers, str):
            brokers_list = [b.strip() for b in brokers.split(",") if b.strip()]
        else:
            brokers_list = brokers

        if not brokers_list:
            raise ValueError("Kafka brokers list cannot be empty")

        self.topic = topic
        self.key_field = key_field
        self.batch_size = max(1, batch_size)
        self._rows_written = 0

        if producer is None:
            try:
                from kafka import KafkaProducer
            except ImportError as exc:
                raise ImportError(
                    "Kafka output requires kafka-python. Install with: pip install kafka-python"
                ) from exc

            self._producer = KafkaProducer(
                bootstrap_servers=brokers_list,
                acks=acks,
                compression_type=compression_type,
                linger_ms=linger_ms,
                client_id=client_id,
            )
        else:
            self._producer = producer

    def __enter__(self) -> "KafkaWriter":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def write(self, features: dict[str, Any]) -> None:
        """Write a single feature dictionary to Kafka."""
        payload = json.dumps(_serialize_row(features)).encode("utf-8")
        key = None
        if self.key_field:
            key_value = features.get(self.key_field)
            if key_value is not None:
                key = str(key_value).encode("utf-8")

        self._producer.send(self.topic, value=payload, key=key)
        self._rows_written += 1

        if self._rows_written % self.batch_size == 0:
            self._producer.flush()

    def write_many(self, rows: Iterable[dict[str, Any]]) -> int:
        """Write multiple feature dictionaries."""
        for row in rows:
            self.write(row)
        return self._rows_written

    def close(self) -> None:
        """Flush and close the Kafka producer."""
        try:
            self._producer.flush()
        except Exception:
            pass
        try:
            self._producer.close()
        except Exception:
            pass

    @property
    def rows_written(self) -> int:
        """Number of rows written so far."""
        return self._rows_written


def to_kafka(
    features: list[dict[str, Any]],
    brokers: str | list[str],
    topic: str,
    key_field: str | None = None,
    batch_size: int = 1000,
) -> int:
    """Write features to Kafka.

    Args:
        features: Feature dictionaries to publish.
        brokers: Kafka bootstrap servers.
        topic: Kafka topic to publish to.
        key_field: Optional feature field to use as Kafka message key.
        batch_size: Flush every N messages.

    Returns:
        Number of messages published.
    """
    if not features:
        return 0

    with KafkaWriter(
        brokers=brokers,
        topic=topic,
        key_field=key_field,
        batch_size=batch_size,
    ) as writer:
        writer.write_many(features)
        return writer.rows_written
