# Architecture

This document describes the internal architecture of JoyfulJay for developers who want to understand how the library works, contribute to it, or extend it with custom functionality.

## High-Level Overview

JoyfulJay follows a streaming pipeline architecture designed for memory efficiency and extensibility:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              JoyfulJay Pipeline                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │   Capture   │    │    Flow     │    │  Feature    │    │   Output    │  │
│  │   Backend   │───▶│   Table     │───▶│ Extractors  │───▶│  Formatter  │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
│        │                  │                  │                   │          │
│        ▼                  ▼                  ▼                   ▼          │
│   PCAP/Live        Bidirectional      387 Features       DataFrame/CSV/    │
│   Interface         Flow Assembly      across 24          JSON/Parquet     │
│                                        Extractors                           │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Data Flow

```
PCAP File / Live Interface
         │
         ▼
┌────────────────────┐
│  Capture Backend   │  Scapy (default), DPKT (fast), or Remote (WebSocket)
│  iter_packets()    │
└────────────────────┘
         │
         ▼ Packet
┌────────────────────┐
│    Flow Table      │  Groups packets into bidirectional flows
│  add_packet()      │  Handles timeout expiration & LRU eviction
└────────────────────┘
         │
         ▼ Flow (when complete)
┌────────────────────┐
│ Feature Extractors │  24 extractors run in sequence
│  extractor.extract │  Each produces a dict of features
└────────────────────┘
         │
         ▼ dict[str, Any]
┌────────────────────┐
│  Output Formatter  │  Converts to DataFrame, NumPy, CSV, JSON, etc.
│                    │  Streaming writers for large captures
└────────────────────┘
```

---

## Module Organization

```
src/joyfuljay/
├── __init__.py              # Public API exports
├── core/                    # Core data structures
│   ├── packet.py            # Packet dataclass (60+ fields)
│   ├── flow.py              # Flow, FlowKey, FlowTable
│   ├── pipeline.py          # Main Pipeline orchestrator
│   └── config.py            # Config dataclass (40+ options)
│
├── capture/                 # Packet capture backends
│   ├── base.py              # CaptureBackend protocol
│   ├── scapy_backend.py     # Default Scapy-based backend
│   ├── dpkt_backend.py      # Fast DPKT-based backend
│   └── libpcap_backend.py   # High-speed libpcap backend
│
├── extractors/              # Feature extraction modules
│   ├── base.py              # FeatureExtractor abstract base
│   ├── flow_meta.py         # Flow metadata (5-tuple, duration)
│   ├── timing.py            # Inter-arrival time statistics
│   ├── size.py              # Packet size statistics
│   ├── tcp.py               # TCP flag analysis
│   ├── tls.py               # TLS/JA3 fingerprinting
│   ├── quic.py              # QUIC protocol features
│   ├── ssh.py               # SSH/HASSH fingerprinting
│   ├── dns.py               # DNS query features
│   ├── entropy.py           # Payload entropy
│   ├── padding.py           # Padding detection
│   ├── fingerprint.py       # Tor/VPN/DoH detection
│   ├── connection.py        # Connection graph features
│   ├── mac.py               # Layer 2 MAC features
│   ├── ip_extended.py       # Extended IP features
│   ├── ipv6_options.py      # IPv6 extension headers
│   ├── icmp.py              # ICMP features
│   ├── tcp_sequence.py      # TCP sequence analysis
│   ├── tcp_window.py        # TCP window analysis
│   ├── tcp_options.py       # TCP options parsing
│   ├── tcp_mptcp.py         # Multipath TCP
│   ├── tcp_rtt.py           # RTT estimation
│   ├── tcp_fingerprint.py   # TCP fingerprinting
│   └── http2.py             # HTTP/2 features
│
├── output/                  # Output formatters
│   ├── formats.py           # DataFrame, NumPy, streaming writers
│   ├── kafka.py             # Kafka streaming output
│   └── database.py          # PostgreSQL output
│
├── remote/                  # Remote capture
│   ├── server.py            # WebSocket server
│   ├── client.py            # WebSocket client
│   ├── protocol.py          # Wire protocol (msgpack)
│   └── discovery.py         # mDNS announcement/discovery
│
├── monitoring/              # Observability
│   ├── base.py              # MetricsSink protocol
│   ├── prometheus.py        # Prometheus metrics
│   └── grafana.py           # Dashboard utilities
│
├── cli/                     # Command-line interface
│   └── main.py              # Click CLI with 11 commands
│
├── analysis/                # Analysis utilities
│   └── connection_graph.py  # NetworkX graph analysis
│
└── utils/                   # Shared utilities
    ├── stats.py             # Statistical functions
    ├── entropy.py           # Entropy calculation
    ├── hashing.py           # JA3/HASSH hashing
    ├── bidir_split.py       # Bidirectional feature splitting
    └── tls_parser.py        # TLS handshake parsing
```

---

## Core Components

### Packet (`core/packet.py`)

The `Packet` dataclass is an immutable, backend-agnostic representation of a network packet:

```python
@dataclass(slots=True, frozen=True)
class Packet:
    # Required fields
    timestamp: float          # Unix timestamp (high precision)
    src_ip: str               # Source IP address
    dst_ip: str               # Destination IP address
    src_port: int             # Source port (0 for non-TCP/UDP)
    dst_port: int             # Destination port
    protocol: int             # IP protocol (6=TCP, 17=UDP, 1=ICMP)
    payload_len: int          # Transport payload bytes
    total_len: int            # Total IP packet length

    # Optional fields (60+ total)
    tcp_flags: int | None     # TCP flag bitmap
    raw_payload: bytes | None # Raw payload for deep inspection
    src_mac: str | None       # Source MAC address
    dst_mac: str | None       # Destination MAC address
    ip_ttl: int | None        # IP Time To Live
    tcp_seq: int | None       # TCP sequence number
    tcp_window: int | None    # TCP window size
    # ... 40+ more fields
```

**Design decisions:**
- `frozen=True`: Packets are immutable once created
- `slots=True`: Memory-efficient representation
- Optional fields default to `None`: Backends only populate what they can parse

### Flow (`core/flow.py`)

The `Flow` class aggregates packets into bidirectional conversations:

```python
@dataclass
class Flow:
    key: FlowKey                    # Bidirectional 5-tuple key
    start_time: float               # First packet timestamp
    last_seen: float                # Most recent packet timestamp
    initiator_ip: str               # Connection initiator
    initiator_port: int
    packets: list[Packet]           # All packets (both directions)
    initiator_packets: list[Packet] # Initiator → Responder
    responder_packets: list[Packet] # Responder → Initiator
    tls_client_hello: bytes | None  # TLS ClientHello if captured
    tls_server_hello: bytes | None  # TLS ServerHello if captured
    terminated: bool                # Flow ended (FIN/RST)
```

**FlowKey** normalizes the 5-tuple so packets in either direction share the same key:

```python
@dataclass(slots=True, frozen=True)
class FlowKey:
    ip_a: str      # Lexicographically smaller IP
    port_a: int
    ip_b: str
    port_b: int
    protocol: int

    @classmethod
    def from_packet(cls, packet: Packet) -> FlowKey:
        # Normalizes direction by sorting endpoints
```

### FlowTable (`core/flow.py`)

The `FlowTable` manages active flows with timeout-based expiration:

```python
class FlowTable:
    def __init__(
        self,
        timeout: float = 60.0,        # Inactivity timeout (seconds)
        max_flows: int = 0,           # Max concurrent flows (0=unlimited)
        eviction_strategy: str = "lru" # "lru" or "oldest"
    ): ...

    def add_packet(self, packet: Packet) -> Flow | list[Flow] | None:
        # Returns completed/evicted flows

    def expire_flows(self, current_time: float) -> list[Flow]:
        # Returns flows that have timed out

    def flush_all(self) -> list[Flow]:
        # Returns all remaining flows (end of capture)
```

### Pipeline (`core/pipeline.py`)

The `Pipeline` class orchestrates the entire extraction process:

```python
class Pipeline:
    def __init__(
        self,
        config: Config | None = None,
        backend: CaptureBackend | None = None,
        metrics: MetricsSink | None = None,
    ): ...

    # Main processing methods
    def process_pcap(self, path: str) -> pd.DataFrame
    def process_live(self, interface: str, duration: float) -> pd.DataFrame
    def iter_features(self, path: str) -> Iterator[dict]  # Streaming

    # Internal methods
    def _extract_features(self, flow: Flow) -> dict[str, Any]
    def _init_extractors(self) -> list[FeatureExtractor]
```

### Config (`core/config.py`)

The `Config` dataclass holds all configuration options:

```python
@dataclass
class Config:
    # Flow management
    flow_timeout: float = 60.0
    max_concurrent_flows: int = 0
    flow_eviction_strategy: str = "lru"
    sampling_rate: float | None = None

    # Feature selection
    features: list[str] = ["all"]
    specific_features: list[str] | None = None
    bidirectional_split: bool = False

    # Privacy
    anonymize_ips: bool = False
    anonymization_salt: str = ""

    # Performance
    num_workers: int = 1
    entropy_sample_bytes: int = 256

    # ... 20+ more options
```

---

## Extractor Framework

### FeatureExtractor Base Class

All extractors inherit from `FeatureExtractor`:

```python
class FeatureExtractor(ABC):
    @abstractmethod
    def extract(self, flow: Flow) -> dict[str, Any]:
        """Extract features from a completed flow."""

    @property
    @abstractmethod
    def feature_names(self) -> list[str]:
        """List of feature names this extractor produces."""

    @property
    def name(self) -> str:
        """Extractor name (defaults to class name)."""
        return self.__class__.__name__
```

### Extractor Lifecycle

1. **Initialization**: Extractors are created once when the Pipeline is initialized
2. **Configuration**: Some extractors accept constructor parameters (e.g., `max_sequence_length`)
3. **Extraction**: Called for each completed flow, returns dict of features
4. **Error Handling**: Failed extractors log warnings, return `None` for all features

### Feature Groups

Features are organized into groups (`FeatureGroup` enum in `config.py`):

| Group | Extractor | Features | Description |
|-------|-----------|----------|-------------|
| `flow_meta` | FlowMetaExtractor | 10 | 5-tuple, duration, counts |
| `timing` | TimingExtractor | 20+ | IAT statistics, bursts |
| `size` | SizeExtractor | 15+ | Packet/payload size stats |
| `tcp` | TCPExtractor | 26 | TCP flags, handshake |
| `tls` | TLSExtractor | 30+ | JA3/JA3S, cipher suites |
| `quic` | QUICExtractor | 10+ | QUIC version, CIDs |
| `ssh` | SSHExtractor | 10+ | HASSH fingerprints |
| `dns` | DNSExtractor | 15+ | Query analysis |
| `entropy` | EntropyExtractor | 6 | Payload entropy |
| `padding` | PaddingExtractor | 8 | Padding detection |
| `fingerprint` | FingerprintExtractor | 6 | Tor/VPN/DoH detection |
| `connection` | ConnectionExtractor | 20+ | Graph metrics |
| ... | ... | ... | ... |

**Total: 387 features across 24 extractors**

---

## Capture Backends

### CaptureBackend Protocol

All capture backends implement this protocol:

```python
class CaptureBackend(Protocol):
    def iter_packets_offline(self, path: str) -> Iterator[Packet]:
        """Read packets from a PCAP file."""

    def iter_packets_live(
        self,
        interface: str,
        bpf_filter: str | None = None,
        save_pcap: str | None = None,
        pid: int | None = None,
    ) -> Iterator[Packet]:
        """Capture packets from a live interface."""

    def stop(self) -> None:
        """Stop any active capture."""
```

### Available Backends

| Backend | Module | Speed | Features | Install |
|---------|--------|-------|----------|---------|
| Scapy | `scapy_backend.py` | Medium | Full protocol parsing | Default |
| DPKT | `dpkt_backend.py` | Fast | Basic parsing | `[fast]` |
| Remote | `remote/client.py` | Network-bound | Stream from remote | Default |

### Backend Selection

```python
from joyfuljay.capture.dpkt_backend import DPKTBackend

# Use DPKT for faster parsing
pipeline = Pipeline(backend=DPKTBackend())
```

---

## Output System

### Output Formats

| Format | Function | Use Case |
|--------|----------|----------|
| DataFrame | `to_dataframe()` | pandas analysis, ML |
| NumPy | `to_numpy()` | ML frameworks |
| CSV | `StreamingWriter` | Disk storage |
| JSON Lines | `StreamingWriter` | Streaming systems |
| Parquet | `StreamingWriter` | Big data, columnar |
| Kafka | `KafkaWriter` | Real-time pipelines |
| PostgreSQL | `DatabaseWriter` | Structured storage |

### Streaming Writers

For large captures, use streaming writers to avoid memory issues:

```python
from joyfuljay.output.formats import StreamingWriter

with StreamingWriter("output.csv", format="csv") as writer:
    for features in pipeline.iter_features("large.pcap"):
        writer.write(features)
```

---

## Remote Capture Architecture

```
┌─────────────────┐                 ┌─────────────────┐
│  Remote Device  │                 │ Analysis Machine│
│  (Android/RPi)  │                 │                 │
│                 │   WebSocket     │                 │
│  ┌───────────┐  │   (msgpack)     │  ┌───────────┐  │
│  │  Server   │◀─┼────TLS/WSS────▶│  │  Client   │  │
│  │ (capture) │  │                 │  │ (process) │  │
│  └───────────┘  │                 │  └───────────┘  │
│       │         │                 │       │         │
│       ▼         │                 │       ▼         │
│  wlan0/eth0     │                 │  Features.csv   │
└─────────────────┘                 └─────────────────┘
```

### Wire Protocol

Messages are serialized using msgpack:

```python
# Packet message
{
    "type": "packet",
    "data": {
        "timestamp": 1234567890.123,
        "src_ip": "192.168.1.1",
        "dst_ip": "10.0.0.1",
        # ... all Packet fields
    }
}

# Control messages
{"type": "start", "interface": "wlan0", "filter": "tcp port 443"}
{"type": "stop"}
{"type": "stats", "packets": 1000, "bytes": 150000}
```

### Security

- **TLS/WSS**: Optional TLS encryption for secure transport
- **Token Auth**: Shared secret token for client authentication
- **mDNS**: Zero-config discovery on local network

---

## Monitoring & Observability

### MetricsSink Protocol

```python
class MetricsSink(Protocol):
    def observe_packet(self, packet: Packet) -> None: ...
    def observe_flow(self, flow: Flow, reason: str) -> None: ...
    def observe_processing_time(self, mode: str, seconds: float) -> None: ...
    def observe_error(self, stage: str, error: Exception | None) -> None: ...
    def set_active_flows(self, count: int) -> None: ...
```

### Prometheus Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `joyfuljay_packets_total` | Counter | Total packets processed |
| `joyfuljay_bytes_total` | Counter | Total bytes processed |
| `joyfuljay_flows_total` | Counter | Flows completed (by reason) |
| `joyfuljay_errors_total` | Counter | Errors (by stage) |
| `joyfuljay_processing_duration_seconds` | Histogram | Processing time |
| `joyfuljay_active_flows` | Gauge | Current active flows |

---

## Performance Optimizations

### Memory Efficiency

1. **Streaming Processing**: Packets are processed one-at-a-time, flows are flushed when complete
2. **Slots Dataclasses**: `Packet` uses `__slots__` for reduced memory footprint
3. **LRU Eviction**: `FlowTable` caps concurrent flows with LRU eviction
4. **Streaming Writers**: Write features to disk incrementally

### Processing Speed

1. **DPKT Backend**: 2-3x faster than Scapy for basic parsing
2. **Parallel Processing**: `process_pcaps_batch()` with `num_workers > 1`
3. **Sampling**: `sampling_rate` to process a subset of packets
4. **BPF Filters**: Hardware-level packet filtering

### Scaling Patterns

| Scenario | Solution |
|----------|----------|
| Large PCAP (10GB+) | `process_pcap_streaming()` or `iter_features()` |
| Many PCAPs | `process_pcaps_batch()` with `num_workers=4` |
| High-rate live capture | `[fast]` backend + `max_concurrent_flows` limit |
| Memory-constrained | `sampling_rate=0.1` + LRU eviction |

---

## Extension Points

### Adding a New Extractor

1. Create `src/joyfuljay/extractors/my_protocol.py`
2. Inherit from `FeatureExtractor`
3. Implement `extract()` and `feature_names`
4. Add to `FeatureGroup` enum in `config.py`
5. Register in `Pipeline._init_extractors()`

See [Developer Guide](developer-guide.md) for detailed tutorial.

### Adding a Capture Backend

1. Create `src/joyfuljay/capture/my_backend.py`
2. Implement `CaptureBackend` protocol
3. Pass to `Pipeline(backend=MyBackend())`

### Adding an Output Format

1. Create writer class in `src/joyfuljay/output/`
2. Implement context manager (`__enter__`, `__exit__`)
3. Implement `write(features: dict)` method

---

## Testing Architecture

```
tests/
├── conftest.py          # Shared fixtures (sample_packet, sample_flow)
├── fixtures/            # Packet/flow generators
├── unit/                # Unit tests (per module)
│   └── extractors/      # Extractor-specific tests
├── integration/         # End-to-end tests
├── fuzz/                # Hypothesis fuzzing
└── property/            # Property-based tests
```

### Test Categories

| Category | Marker | Purpose |
|----------|--------|---------|
| Unit | (default) | Individual function/class behavior |
| Integration | `@pytest.mark.integration` | Full pipeline tests |
| Slow | `@pytest.mark.slow` | Long-running tests |
| Fuzz | `tests/fuzz/` | Random input testing |
| Property | `tests/property/` | Statistical invariants |

---

## Thread Safety

- **Packet**: Immutable (`frozen=True`), thread-safe
- **Flow**: Mutable during construction, should not be shared across threads
- **FlowTable**: Not thread-safe, use one per processing thread
- **Pipeline**: Not thread-safe, create separate instances for parallel processing
- **Extractors**: Stateless, thread-safe

For parallel processing, use `process_pcaps_batch()` which creates separate Pipeline instances per worker process.
