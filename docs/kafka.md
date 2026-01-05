# Kafka Streaming

Stream extracted features directly to Apache Kafka for real-time data pipelines, SIEM integration, or distributed processing.

## Installation

```bash
pip install joyfuljay[kafka]
```

This installs `kafka-python>=2.0` as a dependency.

## Quick Start

### Basic Usage

```python
from joyfuljay.output.kafka import KafkaWriter, to_kafka

# Option 1: Context manager (recommended)
with KafkaWriter("localhost:9092", topic="network-features") as writer:
    writer.write({"flow_id": "abc123", "duration": 1.5, "packets": 42})
    writer.write({"flow_id": "def456", "duration": 2.3, "packets": 17})

# Option 2: Convenience function for batch writes
features = [
    {"flow_id": "abc123", "duration": 1.5},
    {"flow_id": "def456", "duration": 2.3},
]
count = to_kafka(features, "localhost:9092", topic="network-features")
print(f"Published {count} messages")
```

### With PCAP Processing

```python
from joyfuljay import Pipeline, Config
from joyfuljay.output.kafka import KafkaWriter

config = Config(features=["timing", "size", "tls"])
pipeline = Pipeline(config)

with KafkaWriter("kafka-cluster:9092", topic="pcap-features") as writer:
    for flow in pipeline.iter_flows("capture.pcap"):
        features = pipeline._extract_features(flow)
        writer.write(features)
```

## API Reference

### KafkaWriter

```python
class KafkaWriter:
    def __init__(
        self,
        brokers: str | list[str],      # Kafka bootstrap servers
        topic: str,                     # Target topic
        key_field: str | None = None,  # Feature field to use as message key
        batch_size: int = 1000,        # Flush after N messages
        acks: str | int = "all",       # Acknowledgment mode
        compression_type: str | None = None,  # gzip, snappy, lz4, zstd
        linger_ms: int | None = None,  # Batch wait time
        client_id: str | None = None,  # Kafka client identifier
        producer: Any | None = None,   # Inject custom producer (testing)
    ) -> None: ...
```

#### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `brokers` | `str \| list[str]` | Required | Kafka bootstrap servers. Can be comma-separated string or list. |
| `topic` | `str` | Required | Kafka topic to publish messages to. |
| `key_field` | `str \| None` | `None` | Feature field to extract as message key. Enables partitioning by flow. |
| `batch_size` | `int` | `1000` | Number of messages before automatic flush. |
| `acks` | `str \| int` | `"all"` | Producer acknowledgment mode. `"all"` for durability, `1` for speed. |
| `compression_type` | `str \| None` | `None` | Compression algorithm: `"gzip"`, `"snappy"`, `"lz4"`, `"zstd"`. |
| `linger_ms` | `int \| None` | `None` | Milliseconds to wait for batch accumulation. |
| `client_id` | `str \| None` | `None` | Client identifier for Kafka logs. |

#### Methods

| Method | Description |
|--------|-------------|
| `write(features: dict)` | Write a single feature dictionary as a JSON message. |
| `write_many(rows: Iterable[dict]) -> int` | Write multiple feature dictionaries. Returns count. |
| `close()` | Flush pending messages and close the producer. |
| `rows_written -> int` | Property returning total messages written. |

### to_kafka

Convenience function for one-shot batch writes:

```python
def to_kafka(
    features: list[dict],
    brokers: str | list[str],
    topic: str,
    key_field: str | None = None,
    batch_size: int = 1000,
) -> int:
    """Write features to Kafka. Returns message count."""
```

### is_kafka_available

Check if kafka-python is installed:

```python
from joyfuljay.output.kafka import is_kafka_available

if is_kafka_available():
    # Kafka features available
    from joyfuljay.output.kafka import KafkaWriter
```

## Configuration Examples

### High-Throughput Configuration

```python
writer = KafkaWriter(
    brokers="kafka1:9092,kafka2:9092,kafka3:9092",
    topic="high-volume-features",
    batch_size=10000,
    linger_ms=100,           # Wait up to 100ms for batching
    compression_type="lz4",  # Fast compression
    acks=1,                  # Leader-only acks for speed
)
```

### High-Durability Configuration

```python
writer = KafkaWriter(
    brokers="kafka:9092",
    topic="critical-features",
    batch_size=100,
    acks="all",              # Wait for all replicas
    compression_type="gzip", # Best compression ratio
)
```

### Partitioning by Flow

```python
# Use flow_id as the message key for consistent partitioning
writer = KafkaWriter(
    brokers="kafka:9092",
    topic="partitioned-features",
    key_field="flow_id",  # Messages with same flow_id go to same partition
)
```

## Message Format

Messages are published as JSON with the following characteristics:

- **Value**: JSON-encoded feature dictionary
- **Key**: Optional, extracted from `key_field` parameter
- **Encoding**: UTF-8

### Type Handling

The writer automatically handles Python and NumPy types:

| Python Type | JSON Type |
|-------------|-----------|
| `int`, `float`, `str`, `bool` | Preserved |
| `None` | `null` |
| `np.integer`, `np.floating` | Converted to Python int/float |
| `np.ndarray` | Converted to list |
| `list`, `dict` | Preserved |
| Other | Converted to string |

## Error Handling

```python
from joyfuljay.output.kafka import KafkaWriter

try:
    with KafkaWriter("kafka:9092", topic="features") as writer:
        writer.write(features)
except ImportError:
    print("Install with: pip install joyfuljay[kafka]")
except Exception as e:
    print(f"Kafka error: {e}")
```

## Integration Patterns

### With Prometheus Metrics

```python
from joyfuljay.output.kafka import KafkaWriter
from joyfuljay.monitoring import PrometheusMetrics

metrics = PrometheusMetrics()

with KafkaWriter("kafka:9092", topic="features") as writer:
    for flow in pipeline.iter_flows("capture.pcap"):
        features = pipeline._extract_features(flow)
        writer.write(features)
        metrics.observe_flow(flow, "kafka")
```

### Consumer Example

Reading features from Kafka (using kafka-python):

```python
from kafka import KafkaConsumer
import json

consumer = KafkaConsumer(
    "network-features",
    bootstrap_servers="localhost:9092",
    value_deserializer=lambda m: json.loads(m.decode("utf-8")),
)

for message in consumer:
    features = message.value
    print(f"Flow: {features.get('flow_id')}, Duration: {features.get('duration')}")
```

## Testing

For unit testing without a Kafka cluster:

```python
from unittest.mock import MagicMock
from joyfuljay.output.kafka import KafkaWriter

# Inject mock producer
mock_producer = MagicMock()
writer = KafkaWriter(
    brokers="fake:9092",
    topic="test",
    producer=mock_producer,  # Bypass real Kafka connection
)

writer.write({"test": "data"})
mock_producer.send.assert_called_once()
```
