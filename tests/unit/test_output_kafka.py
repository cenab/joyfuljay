"""Tests for Kafka output sink."""

from __future__ import annotations

import json

from joyfuljay.output.kafka import KafkaWriter


class FakeProducer:
    def __init__(self) -> None:
        self.sent: list[tuple[str, bytes, bytes | None]] = []
        self.flush_count = 0
        self.closed = False

    def send(self, topic: str, value: bytes | None = None, key: bytes | None = None) -> None:
        self.sent.append((topic, value or b"", key))

    def flush(self) -> None:
        self.flush_count += 1

    def close(self) -> None:
        self.closed = True


def test_kafka_writer_serializes_and_flushes() -> None:
    producer = FakeProducer()
    writer = KafkaWriter(
        brokers=["localhost:9092"],
        topic="features",
        key_field="src_ip",
        batch_size=2,
        producer=producer,
    )

    writer.write({"src_ip": "1.1.1.1", "duration": 1.0})
    writer.write({"src_ip": "2.2.2.2", "duration": 2.5})
    writer.close()

    assert producer.flush_count >= 1
    assert producer.closed is True
    assert len(producer.sent) == 2

    topic, payload, key = producer.sent[0]
    assert topic == "features"
    assert key == b"1.1.1.1"
    data = json.loads(payload.decode("utf-8"))
    assert data["duration"] == 1.0
