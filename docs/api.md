# API Reference

Complete Python API documentation for JoyfulJay.

---

## Quick Reference

```python
import joyfuljay as jj

# Top-level functions
df = jj.extract("capture.pcap")           # Extract from PCAP
df = jj.extract_live("eth0", duration=30) # Live capture

# Core classes
config = jj.Config(features=["tls"])      # Configuration
pipeline = jj.Pipeline(config)            # Processing pipeline
```

---

## Module: `joyfuljay`

### `extract()`

Extract features from a PCAP file.

```python
jj.extract(
    pcap_path: str,
    features: list[str] | str = "all",
    output_format: str = "dataframe",
    **config_kwargs
) -> pd.DataFrame | np.ndarray | list[dict]
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `pcap_path` | str | required | Path to PCAP or PCAPNG file |
| `features` | list/str | `"all"` | Feature groups: `"all"` or list like `["timing", "tls"]` |
| `output_format` | str | `"dataframe"` | `"dataframe"`, `"numpy"`, or `"dict"` |
| `**config_kwargs` | | | Additional Config options |

**Returns:** DataFrame, NumPy array, or list of dicts

**Example:**
```python
import joyfuljay as jj

# Basic usage
df = jj.extract("traffic.pcap")

# Select features
df = jj.extract("traffic.pcap", features=["timing", "size"])

# With config options
df = jj.extract("traffic.pcap", flow_timeout=30.0, anonymize_ips=True)
```

---

### `extract_live()`

Extract features from live network capture.

```python
jj.extract_live(
    interface: str,
    duration: float = None,
    packet_count: int = None,
    bpf_filter: str = None,
    features: list[str] | str = "all",
    output_format: str = "dataframe",
    **config_kwargs
) -> pd.DataFrame | np.ndarray | list[dict]
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `interface` | str | required | Network interface (e.g., `"eth0"`) |
| `duration` | float | None | Capture duration in seconds |
| `packet_count` | int | None | Stop after N packets |
| `bpf_filter` | str | None | BPF filter (e.g., `"tcp port 443"`) |
| `features` | list/str | `"all"` | Feature groups to extract |
| `output_format` | str | `"dataframe"` | Output format |

**Example:**
```python
import joyfuljay as jj

# Capture for 60 seconds
df = jj.extract_live("eth0", duration=60)

# With BPF filter
df = jj.extract_live("eth0", duration=30, bpf_filter="port 443")
```

**Note:** Requires root/admin privileges.

---

## Class: `Config`

Configuration for feature extraction.

```python
config = jj.Config(
    features: list[str] = ["all"],
    flow_timeout: float = 60.0,
    include_ip_addresses: bool = True,
    anonymize_ips: bool = False,
    ...
)
```

### All Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `features` | list | `["all"]` | Feature groups to extract |
| `flow_timeout` | float | `60.0` | Flow inactivity timeout (seconds) |
| `include_ip_addresses` | bool | `True` | Include src_ip/dst_ip |
| `anonymize_ips` | bool | `False` | Hash IP addresses |
| `include_flow_id` | bool | `True` | Include flow_id column |
| `include_ports` | bool | `True` | Include port numbers |
| `max_sequence_length` | int | `100` | Max sequence feature length |
| `burst_threshold_ms` | float | `50.0` | Burst detection threshold |
| `sampling_rate` | float | `1.0` | Packet sampling (0.0-1.0) |
| `bidirectional_split` | bool | `False` | Split by direction |
| `bpf_filter` | str | None | BPF filter string |
| `entropy_sample_bytes` | int | `256` | Bytes for entropy calc |

**Example:**
```python
import joyfuljay as jj

config = jj.Config(
    features=["timing", "tls", "fingerprint"],
    flow_timeout=30.0,
    anonymize_ips=True,
)
```

See [Configuration](configuration.md) for complete reference.

---

## Class: `Pipeline`

Main processing pipeline.

```python
pipeline = jj.Pipeline(config: Config)
```

### Methods

#### `process_pcap()`

```python
pipeline.process_pcap(
    pcap_path: str,
    output_format: str = "dataframe"
) -> pd.DataFrame | np.ndarray | list[dict]
```

Process a PCAP file and return features.

#### `process_pcaps_batch()`

```python
pipeline.process_pcaps_batch(
    pcap_paths: list[str],
    output_format: str = "dataframe",
    num_workers: int = 1
) -> pd.DataFrame | list[dict]
```

Process multiple PCAP files (optionally in parallel).

#### `iter_features()`

```python
pipeline.iter_features(
    source: str,
    live: bool = False
) -> Iterator[dict]
```

Iterate over flows (memory efficient for large files).

#### `get_feature_names()`

```python
pipeline.get_feature_names() -> list[str]
```

Get list of all feature names.

**Example:**
```python
import joyfuljay as jj

config = jj.Config(features=["timing", "size"])
pipeline = jj.Pipeline(config)

# Process single file
df = pipeline.process_pcap("capture.pcap")

# Process multiple files in parallel
df = pipeline.process_pcaps_batch(
    ["a.pcap", "b.pcap", "c.pcap"],
    num_workers=4
)

# Memory-efficient iteration
for features in pipeline.iter_features("large.pcap"):
    process(features)

# Get feature names
print(pipeline.get_feature_names())
```

---

## Class: `Flow`

Represents a bidirectional network flow.

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `key` | FlowKey | 5-tuple identifier |
| `packets` | list[Packet] | All packets |
| `start_time` | float | First packet timestamp |
| `end_time` | float | Last packet timestamp |
| `duration` | float | Duration in seconds |
| `packet_count` | int | Total packets |
| `byte_count` | int | Total bytes |
| `terminated` | bool | FIN/RST seen |

### Methods

```python
flow = jj.Flow.from_first_packet(packet)
flow.add_packet(packet)
flow.is_expired(timeout, now)
flow.get_direction(packet)  # 0=forward, 1=backward
```

---

## Class: `Packet`

Represents a network packet.

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `timestamp` | float | Unix timestamp |
| `src_ip` | str | Source IP |
| `dst_ip` | str | Destination IP |
| `src_port` | int | Source port |
| `dst_port` | int | Destination port |
| `protocol` | int | IP protocol (6=TCP, 17=UDP) |
| `payload_len` | int | Payload bytes |
| `total_len` | int | Total packet length |
| `tcp_flags` | int | TCP flags bitmap |
| `raw_payload` | bytes | Raw payload |

---

## Module: `joyfuljay.output`

### Output Functions

```python
from joyfuljay.output import (
    to_csv,
    to_json,
    to_dataframe,
    to_numpy,
    to_parquet,
    StreamingWriter,
    KafkaWriter,
    DatabaseWriter,
)
```

### `StreamingWriter`

Memory-efficient streaming output:

```python
from joyfuljay.output import StreamingWriter

with StreamingWriter("output.csv", format="csv") as writer:
    for features in pipeline.iter_features("large.pcap"):
        writer.write(features)
```

### `KafkaWriter`

Stream to Kafka:

```python
from joyfuljay.output import KafkaWriter

with KafkaWriter("localhost:9092", topic="features") as writer:
    for features in pipeline.iter_features("capture.pcap"):
        writer.write(features)
```

### `DatabaseWriter`

Write to SQL database:

```python
from joyfuljay.output import DatabaseWriter

with DatabaseWriter("sqlite:///features.db", table="flows") as writer:
    for features in pipeline.iter_features("capture.pcap"):
        writer.write(features)
```

---

## Module: `joyfuljay.capture`

### Capture Backends

```python
from joyfuljay.capture import (
    ScapyBackend,      # Default, full-featured
    DpktBackend,       # 10x faster
    RemoteCaptureBackend,  # Network streaming
)
```

**Example:**
```python
from joyfuljay.capture import DpktBackend

# Use fast backend
backend = DpktBackend()
for packet in backend.iter_packets_offline("capture.pcap"):
    print(packet)
```

---

## Module: `joyfuljay.remote`

### `Server`

Remote capture server:

```python
from joyfuljay.remote import Server

server = Server(
    interface="eth0",
    port=8765,
    tls_cert="server.crt",
    tls_key="server.key",
)
server.start()
```

### `discover_servers()`

Find servers via mDNS:

```python
from joyfuljay.remote import discover_servers

servers = discover_servers(timeout=5.0)
for s in servers:
    print(f"{s.name}: {s.address}:{s.port}")
```

---

## Module: `joyfuljay.monitoring`

### `PrometheusMetrics`

```python
from joyfuljay.monitoring import PrometheusMetrics, start_prometheus_server

metrics = PrometheusMetrics()
start_prometheus_server(9090)
# Metrics at http://localhost:9090/metrics
```

### `DashboardBuilder`

```python
from joyfuljay.monitoring import DashboardBuilder, export_dashboard

builder = DashboardBuilder("My Dashboard")
builder.add_stat_panel("Flows", "joyfuljay_flows_total")
builder.add_graph_panel("Rate", "rate(joyfuljay_flows_total[1m])")

export_dashboard("dashboard.json", builder.build())
```

---

## Module: `joyfuljay.extractors`

### Creating Custom Extractors

```python
from joyfuljay.extractors import FeatureExtractor
from joyfuljay.core import Flow

class MyExtractor(FeatureExtractor):
    def extract(self, flow: Flow) -> dict:
        return {
            "my_feature": len(flow.packets),
        }

    @property
    def feature_names(self) -> list[str]:
        return ["my_feature"]
```

### Built-in Extractors

| Extractor | Description |
|-----------|-------------|
| `FlowMetaExtractor` | Basic metadata |
| `TimingExtractor` | IAT statistics |
| `SizeExtractor` | Packet sizes |
| `TLSExtractor` | TLS/JA3 |
| `QUICExtractor` | QUIC protocol |
| `SSHExtractor` | SSH/HASSH |
| `DNSExtractor` | DNS queries |
| `TCPExtractor` | TCP analysis |
| `FingerprintExtractor` | Tor/VPN/DoH |
| `EntropyExtractor` | Payload entropy |
| `HTTP2Extractor` | HTTP/2 & HTTP/3 |

See [Extractors](extractors/index.md) for full list.

---

## Module: `joyfuljay.utils`

### Statistics

```python
from joyfuljay.utils import compute_statistics

stats = compute_statistics([1.0, 2.0, 3.0])
print(stats.mean, stats.std, stats.min, stats.max)
```

### Entropy

```python
from joyfuljay.utils import byte_entropy

entropy = byte_entropy(b"encrypted data")  # 0.0-8.0
```

### JA3 Hashing

```python
from joyfuljay.utils import compute_ja3_hash

hash = compute_ja3_hash(
    tls_version=0x0303,
    cipher_suites=[0x1301],
    extensions=[0x0000],
    elliptic_curves=[0x001d],
    ec_point_formats=[0x00],
)
```

### Labels

```python
from joyfuljay.utils import LabelLoader

loader = LabelLoader()
loader.load_csv("labels.csv")
labeled_features = loader.merge_with_features(features)
```

---

## Feature Groups

Available groups for `Config(features=[...])`:

| Group | Description |
|-------|-------------|
| `"all"` | All features |
| `"flow_meta"` | Basic metadata |
| `"timing"` | IAT statistics |
| `"size"` | Size statistics |
| `"tls"` | TLS features |
| `"quic"` | QUIC features |
| `"ssh"` | SSH features |
| `"dns"` | DNS features |
| `"tcp"` | TCP features |
| `"fingerprint"` | Traffic classification |
| `"entropy"` | Entropy features |
| `"padding"` | Padding detection |
| `"connection"` | Graph features |
| `"mac"` | Layer 2 features |
| `"icmp"` | ICMP features |
| `"http2"` | HTTP/2 & HTTP/3 |

See [Features](features.md) for complete feature list.
