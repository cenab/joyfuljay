# Feature Extractors

JoyfulJay uses a modular extractor architecture to extract features from network traffic. Each extractor focuses on a specific aspect of network behavior, producing ML-ready features without requiring decryption.

---

## How Extractors Work

Extractors process network flows (bidirectional connections) and produce feature vectors:

```mermaid
graph LR
    A[PCAP/Live] --> B[Flow Assembly]
    B --> C[Packet Processing]
    C --> D[Feature Extractors]
    D --> E[ML-Ready Output]
```

Each extractor implements a simple interface:

1. **`extract(flow)`**: Process a flow and return features
2. **`get_feature_names()`**: Return list of feature names
3. **`reset()`**: Clear state for next flow

---

## Available Extractors

### Core Extractors

These extractors handle fundamental network traffic analysis:

| Extractor | Group | Features | Description |
|-----------|-------|----------|-------------|
| [FlowMetaExtractor](flow-meta.md) | `flow_meta` | 22 | Flow identification, duration, packet/byte counts |
| [TimingExtractor](timing.md) | `timing` | 35 | Inter-arrival times, bursts, idle periods |
| [SizeExtractor](size.md) | `size` | 15 | Packet length statistics |

### Protocol Extractors

Specialized extractors for encrypted protocol analysis:

| Extractor | Group | Features | Description |
|-----------|-------|----------|-------------|
| [TLSExtractor](tls.md) | `tls` | 30+ | TLS metadata, JA3/JA3S fingerprints, certificates |
| [QUICExtractor](quic.md) | `quic` | 10 | QUIC version, connection IDs, SNI |
| [SSHExtractor](ssh.md) | `ssh` | 10 | SSH version, HASSH fingerprints |
| [DNSExtractor](dns.md) | `dns` | 15 | DNS queries, response codes, TTLs |

### TCP Analysis Extractors

Detailed TCP behavior analysis:

| Extractor | Group | Features | Description |
|-----------|-------|----------|-------------|
| [TCPExtractor](tcp.md) | `tcp` | 26 | TCP flags, handshake, retransmissions |

### Traffic Classification Extractors

Pattern detection for traffic fingerprinting:

| Extractor | Group | Features | Description |
|-----------|-------|----------|-------------|
| [FingerprintExtractor](fingerprint.md) | `fingerprint` | 8 | Tor, VPN, DoH detection |
| [EntropyExtractor](entropy.md) | `entropy` | 6 | Payload entropy analysis |
| [PaddingExtractor](padding.md) | `padding` | 14 | Constant-size and rate detection |

---

## Selecting Feature Groups

### Extract All Features (Default)

```python
import joyfuljay as jj

# All extractors enabled by default
df = jj.extract("capture.pcap")
```

### Select Specific Groups

Choose only the feature groups you need:

```python
import joyfuljay as jj

# Only timing, TLS, and fingerprint features
df = jj.extract("capture.pcap", features=["timing", "tls", "fingerprint"])
```

### Using Configuration

For fine-grained control:

```python
import joyfuljay as jj

config = jj.Config(
    features=["flow_meta", "timing", "size", "tls"],
    bidirectional_split=True,  # Separate forward/backward features
    include_raw_sequences=True,  # Include SPLT sequences
    max_sequence_length=100,
)

pipeline = jj.Pipeline(config)
df = pipeline.process_pcap("capture.pcap")
```

### Command Line

```bash
# Select specific feature groups
jj extract capture.pcap --features timing tls fingerprint -o features.csv

# List all available features
jj features
```

---

## Feature Naming Convention

All features follow a consistent naming pattern:

```
{category}_{metric}[_{direction}]
```

**Examples:**

| Feature | Meaning |
|---------|---------|
| `iat_mean` | Mean inter-arrival time |
| `pkt_len_std` | Packet length standard deviation |
| `tcp_syn_count` | Count of TCP SYN flags |
| `tls_version` | TLS protocol version |
| `ja3_hash` | JA3 client fingerprint |

### Directional Features

When `bidirectional_split=True`, features are computed separately for each direction:

| Base Feature | Forward | Backward |
|--------------|---------|----------|
| `iat_mean` | `iat_mean_fwd` | `iat_mean_bwd` |
| `pkt_len_std` | `pkt_len_std_fwd` | `pkt_len_std_bwd` |
| `total_bytes` | `bytes_fwd` | `bytes_bwd` |

**Forward** = Client to Server (flow initiator)
**Backward** = Server to Client (flow responder)

---

## Feature Types

| Type | Python Type | Example |
|------|-------------|---------|
| Integer | `int` | Packet counts, flag counts |
| Float | `float` | Statistics, ratios, durations |
| String | `str` | Hashes, IP addresses, SNI |
| Boolean | `bool` | Detection flags (`likely_tor`) |
| List | `list[int]` | Sequences (SPLT) |

---

## Performance Characteristics

### Fast Extractors

These extractors work on packet headers only:

- `flow_meta` - Basic flow statistics
- `timing` - Inter-arrival times
- `size` - Packet lengths
- `tcp` - TCP header analysis

### Deep Inspection Extractors

These extractors require payload access:

- `tls` - TLS handshake parsing
- `quic` - QUIC header parsing
- `ssh` - SSH banner parsing
- `dns` - DNS message parsing
- `entropy` - Payload entropy calculation

The pipeline automatically enables payload capture when these groups are selected.

---

## Recommended Feature Sets

### For Traffic Classification

```python
config = jj.Config(
    features=["timing", "size", "tls", "fingerprint"],
    bidirectional_split=True,
)
```

### For Anomaly Detection

```python
config = jj.Config(
    features=["timing", "size", "entropy", "tcp"],
    include_raw_sequences=True,
    max_sequence_length=50,
)
```

### For Application Identification

```python
config = jj.Config(
    features=["tls", "quic", "dns", "flow_meta"],
)
```

### Minimal Feature Set (Fast)

```python
config = jj.Config(
    features=["flow_meta", "timing", "size"],
)
```

---

## Creating Custom Extractors

See the [Custom Extractors Tutorial](../tutorials/custom-extractors.md) for a complete guide to creating your own extractors.

Basic structure:

```python
from joyfuljay.extractors.base import FeatureExtractor

class MyExtractor(FeatureExtractor):
    """Custom feature extractor."""

    name = "my_features"

    def get_feature_names(self) -> list[str]:
        return ["my_feature_1", "my_feature_2"]

    def extract(self, flow) -> dict:
        return {
            "my_feature_1": self._compute_feature_1(flow),
            "my_feature_2": self._compute_feature_2(flow),
        }
```

---

## See Also

- [Features Reference](../features.md) - Complete feature documentation
- [Configuration](../configuration.md) - All configuration options
- [Architecture](../architecture.md) - System design details
- [Developer Guide](../developer-guide.md) - Contributing extractors
