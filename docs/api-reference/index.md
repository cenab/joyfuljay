# API Reference

Complete Python API documentation for JoyfulJay.

---

## Quick Reference

```python
import joyfuljay as jj

# One-liner extraction
df = jj.extract("capture.pcap")

# With configuration
config = jj.Config(features=["timing", "tls"], flow_timeout=30.0)
pipeline = jj.Pipeline(config)
df = pipeline.process_pcap("capture.pcap")

# Live capture
df = jj.extract_live("eth0", duration=60)
```

---

## Module Overview

### Top-Level Module: `joyfuljay`

The main entry point for JoyfulJay functionality.

| Function/Class | Description |
|----------------|-------------|
| [`extract()`](joyfuljay/extract.md) | Extract features from a PCAP file |
| [`extract_live()`](joyfuljay/extract-live.md) | Extract features from live capture |
| [`Config`](core/config.md) | Configuration options |
| [`Pipeline`](core/pipeline.md) | Main processing pipeline |

### Core Module: `joyfuljay.core`

Core data structures and processing logic.

| Class | Description |
|-------|-------------|
| [`Config`](core/config.md) | Configuration options for extraction |
| [`Pipeline`](core/pipeline.md) | Main processing pipeline |
| [`Flow`](core/flow.md) | Bidirectional network flow |
| [`FlowKey`](core/flow.md#flowkey) | Flow identifier (5-tuple) |
| [`FlowTable`](core/flow.md#flowtable) | Active flow management |
| [`Packet`](core/packet.md) | Normalized packet representation |

### Capture Module: `joyfuljay.capture`

Packet capture backends.

| Class | Description |
|-------|-------------|
| [`CaptureBackend`](capture/backends.md#capturebackend) | Abstract backend protocol |
| [`ScapyBackend`](capture/backends.md#scapybackend) | Default Scapy-based backend |
| [`DpktBackend`](capture/backends.md#dpktbackend) | Fast DPKT-based backend |
| [`RemoteCaptureBackend`](capture/backends.md#remotecapturebackend) | WebSocket remote capture |

### Extractors Module: `joyfuljay.extractors`

Feature extraction modules.

| Class | Description |
|-------|-------------|
| [`FeatureExtractor`](../extractors/architecture.md) | Base class for extractors |
| [`FlowMetaExtractor`](../extractors/flow-meta.md) | Flow metadata features |
| [`TimingExtractor`](../extractors/timing.md) | Timing and IAT features |
| [`SizeExtractor`](../extractors/size.md) | Packet size features |
| [`TLSExtractor`](../extractors/tls.md) | TLS/JA3 features |
| [`QUICExtractor`](../extractors/quic.md) | QUIC protocol features |
| [`SSHExtractor`](../extractors/ssh.md) | SSH/HASSH features |
| [`FingerprintExtractor`](../extractors/fingerprint.md) | Traffic fingerprinting |
| *...and more* | See [Extractors](../extractors/index.md) |

### Output Module: `joyfuljay.output`

Output formatting and writers.

| Class/Function | Description |
|----------------|-------------|
| [`to_dataframe()`](output/index.md#to_dataframe) | Convert to pandas DataFrame |
| [`to_numpy()`](output/index.md#to_numpy) | Convert to NumPy array |
| [`StreamingWriter`](output/writers.md#streamingwriter) | Memory-efficient file writer |
| [`KafkaWriter`](output/writers.md#kafkawriter) | Kafka topic streaming |
| [`DatabaseWriter`](output/writers.md#databasewriter) | SQL database output |

### Remote Module: `joyfuljay.remote`

Remote packet capture over WebSocket.

| Class/Function | Description |
|----------------|-------------|
| [`Server`](../remote-capture/server-setup.md) | Remote capture server |
| [`discover_servers()`](../remote-capture/discovery.md) | mDNS server discovery |

### Monitoring Module: `joyfuljay.monitoring`

Prometheus metrics and Grafana dashboards.

| Class/Function | Description |
|----------------|-------------|
| [`PrometheusMetrics`](monitoring/index.md) | Prometheus metrics collector |
| [`start_prometheus_server()`](monitoring/index.md) | Start metrics HTTP server |
| [`DashboardBuilder`](monitoring/index.md#dashboardbuilder) | Grafana dashboard generator |

### Utils Module: `joyfuljay.utils`

Utility functions.

| Function | Description |
|----------|-------------|
| [`compute_ja3_hash()`](utils/index.md#ja3) | Compute JA3 fingerprint |
| [`compute_hassh()`](utils/index.md#hassh) | Compute HASSH fingerprint |
| [`byte_entropy()`](utils/index.md#entropy) | Calculate byte entropy |
| [`compute_statistics()`](utils/index.md#statistics) | Compute statistical measures |

---

## Common Patterns

### Basic Extraction

```python
import joyfuljay as jj

# Simple extraction with defaults
df = jj.extract("traffic.pcap")
```

### Configured Extraction

```python
import joyfuljay as jj

config = jj.Config(
    features=["timing", "tls", "fingerprint"],
    flow_timeout=30.0,
    anonymize_ips=True,
)

pipeline = jj.Pipeline(config)
df = pipeline.process_pcap("traffic.pcap")
```

### Streaming Large Files

```python
import joyfuljay as jj
from joyfuljay.output import StreamingWriter

config = jj.Config(features=["timing", "size"])
pipeline = jj.Pipeline(config)

with StreamingWriter("output.csv", format="csv") as writer:
    for features in pipeline.iter_features("huge_file.pcap"):
        writer.write(features)
```

### Kafka Integration

```python
from joyfuljay.output import KafkaWriter

with KafkaWriter("localhost:9092", topic="features") as writer:
    for features in pipeline.iter_features("traffic.pcap"):
        writer.write(features)
```

### Prometheus Monitoring

```python
from joyfuljay.monitoring import PrometheusMetrics, start_prometheus_server

metrics = PrometheusMetrics()
start_prometheus_server(9090)

pipeline = jj.Pipeline(config, metrics=metrics)
df = pipeline.process_pcap("traffic.pcap")
```

---

## Type Annotations

JoyfulJay uses comprehensive type annotations throughout. Key types:

```python
from joyfuljay.core import Config, Pipeline, Flow, FlowKey, Packet

# Function signatures
def extract(
    pcap_path: str,
    features: list[str] | str = "all",
    output_format: str = "dataframe",
    **config_kwargs: Any,
) -> pd.DataFrame | np.ndarray | list[dict]:
    ...
```

---

## Exceptions

| Exception | When Raised |
|-----------|-------------|
| `FileNotFoundError` | PCAP file doesn't exist |
| `ValueError` | Invalid configuration values |
| `ImportError` | Missing optional dependency |
| `PermissionError` | Insufficient privileges for live capture |

---

## See Also

- [Configuration Reference](../user-guide/configuration/index.md) - All configuration options
- [Features Reference](../features/complete-reference.md) - All 387 features
- [CLI Reference](../user-guide/cli/all-commands.md) - Command-line interface
