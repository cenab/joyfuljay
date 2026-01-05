# JoyfulJay Documentation

<div align="center">

**Encrypted Traffic Feature Extraction for Machine Learning**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[Quick Start](#quick-start) | [Installation](installation.md) | [API Reference](api.md) | [Benchmarks](benchmarks.md)

</div>

---

## What is JoyfulJay?

JoyfulJay extracts **ML-ready features** from encrypted network traffic without decrypting it. It analyzes timing patterns, packet sizes, and protocol metadata to produce feature vectors suitable for traffic classification, anomaly detection, and network forensics.

```python
import joyfuljay as jj

# Extract features from a PCAP file
df = jj.extract("capture.pcap")
print(f"Extracted {len(df)} flows with {len(df.columns)} features")
```

---

## Key Features

| Feature | Description |
|---------|-------------|
| **12x Faster** | Process 10+ GB/s with DPKT backend |
| **387 Features** | 4.6x more features than CICFlowMeter |
| **ML-Ready Output** | DataFrame, NumPy, CSV, JSON, Parquet |
| **Protocol Analysis** | TLS, QUIC, SSH, DNS, HTTP/2, ICMP |
| **Traffic Fingerprinting** | Detect Tor, VPN, DoH patterns |
| **Enterprise Ready** | Kafka streaming, Prometheus metrics |

See [Why JoyfulJay?](why-joyfuljay.md) for detailed comparisons and [Benchmarks](benchmarks.md) for performance data.

---

## Quick Start

### Installation

```bash
pip install joyfuljay
```

### Extract Features from PCAP

```python
import joyfuljay as jj

# Simple extraction
df = jj.extract("traffic.pcap")

# With specific feature groups
df = jj.extract("traffic.pcap", features=["timing", "tls", "fingerprint"])

# Save to CSV
df.to_csv("features.csv", index=False)
```

### Command Line

```bash
# Extract to CSV
jj extract capture.pcap -o features.csv

# Live capture for 60 seconds
jj live eth0 --duration 60 -o live.csv

# View system status
jj status
```

### Live Capture

```python
import joyfuljay as jj

# Capture from network interface
df = jj.extract_live("eth0", duration=30)
print(f"Captured {len(df)} flows")
```

---

## Documentation Guide

### Getting Started
| Document | Description |
|----------|-------------|
| [Installation](installation.md) | Install JoyfulJay and optional dependencies |
| [Quick Start](quickstart.md) | Your first feature extraction in 5 minutes |
| [CLI Reference](cli-reference.md) | Complete command-line interface guide |

### Core Concepts
| Document | Description |
|----------|-------------|
| [Configuration](configuration.md) | All 40+ configuration options explained |
| [Features](features.md) | Complete list of 387 features |
| [Architecture](architecture.md) | System design and data flow |

### Feature Extractors
| Document | Description |
|----------|-------------|
| [Extractors Overview](extractors/index.md) | All 24 extractors at a glance |
| [TLS Extractor](extractors/tls.md) | TLS/SSL analysis and JA3 fingerprints |
| [Timing Extractor](extractors/timing.md) | Inter-arrival times and burst metrics |
| [Fingerprint Extractor](extractors/fingerprint.md) | Tor/VPN/DoH detection |

### Advanced Features
| Document | Description |
|----------|-------------|
| [Remote Capture](remote-capture.md) | Stream packets from remote devices |
| [Kafka Streaming](kafka.md) | Real-time feature pipelines |
| [Monitoring](monitoring.md) | Prometheus metrics and Grafana dashboards |

### Tutorials
| Document | Description |
|----------|-------------|
| [Traffic Classification](tutorials/traffic-classification.md) | Train ML models on network traffic |
| [Encrypted Traffic Analysis](tutorials/encrypted-traffic.md) | Detect Tor, VPN, DoH |
| [Real-time Monitoring](tutorials/realtime-monitoring.md) | Kafka + Prometheus + Grafana |
| [Batch Processing](tutorials/batch-processing.md) | Process large datasets efficiently |

### Benchmarks & Comparisons
| Document | Description |
|----------|-------------|
| [Why JoyfulJay?](why-joyfuljay.md) | Comparison with CICFlowMeter, NFStream, Zeek |
| [Benchmarks](benchmarks.md) | Detailed performance benchmarks |

### For Contributors
| Document | Description |
|----------|-------------|
| [Developer Guide](developer-guide.md) | Create extractors, extend JoyfulJay |
| [Testing Guide](testing.md) | Run tests, add coverage |
| [API Reference](api.md) | Python API documentation |

---

## Feature Groups

JoyfulJay organizes features into logical groups:

| Group | Features | Description |
|-------|----------|-------------|
| `flow_meta` | 10 | Basic flow metadata (IPs, ports, duration, counts) |
| `timing` | 25+ | Inter-arrival times, burst/idle metrics |
| `size` | 20+ | Packet lengths, payload statistics |
| `tls` | 30+ | TLS version, ciphers, SNI, JA3/JA3S |
| `quic` | 15+ | QUIC version, ALPN, connection IDs |
| `ssh` | 10+ | SSH version, HASSH fingerprints |
| `dns` | 10+ | Query names, types, response codes |
| `tcp` | 25+ | Flags, handshake, window analysis |
| `fingerprint` | 10+ | Tor/VPN/DoH classification |
| `entropy` | 5+ | Payload entropy, byte distribution |
| `padding` | 5+ | Fixed-size and constant-rate detection |
| `connection` | 10+ | Fan-out, graph metrics |

Select groups when extracting:

```python
import joyfuljay as jj

# Only TLS and timing features
df = jj.extract("capture.pcap", features=["tls", "timing"])

# All features (default)
df = jj.extract("capture.pcap", features="all")
```

---

## Common Use Cases

### Traffic Classification

```python
import joyfuljay as jj
from sklearn.ensemble import RandomForestClassifier

# Extract features
df = jj.extract("labeled_traffic.pcap", features=["timing", "size", "tls"])

# Prepare for ML
X = df.select_dtypes(include=['number']).fillna(0)
y = df['label']  # Assuming labels are present

# Train classifier
clf = RandomForestClassifier()
clf.fit(X, y)
```

### Tor Detection

```python
import joyfuljay as jj

df = jj.extract("capture.pcap", features=["fingerprint", "tls"])

# Check Tor indicators
tor_flows = df[df['likely_tor'] == True]
print(f"Found {len(tor_flows)} potential Tor flows")
```

### Real-time Monitoring

```python
import joyfuljay as jj
from joyfuljay.output import KafkaWriter

# Stream features to Kafka
config = jj.Config(features=["flow_meta", "tls"])
pipeline = jj.Pipeline(config)

with KafkaWriter("localhost:9092", topic="features") as writer:
    for flow_features in pipeline.iter_features("eth0", live=True):
        writer.write(flow_features)
```

### Remote Capture

```bash
# On capture device (e.g., Raspberry Pi)
jj serve wlan0 --port 8765 --announce

# On analysis machine
jj discover  # Find servers
jj connect jj://192.168.1.100:8765 -o features.csv
```

---

## Output Formats

| Format | Function | Use Case |
|--------|----------|----------|
| DataFrame | `jj.extract(..., output_format="dataframe")` | Interactive analysis, Jupyter |
| NumPy | `jj.extract(..., output_format="numpy")` | ML pipelines |
| CSV | `jj extract ... -o file.csv` | File storage, sharing |
| JSON | `jj extract ... -o file.json -f json` | Web APIs, streaming |
| Parquet | `jj extract ... -o file.parquet -f parquet` | Big data, columnar storage |

---

## System Requirements

- **Python**: 3.10, 3.11, or 3.12
- **OS**: Linux, macOS, Windows
- **Dependencies**: scapy, pandas, numpy (auto-installed)

### Optional Dependencies

```bash
# Fast PCAP parsing (10x faster)
pip install joyfuljay[fast]

# Kafka streaming
pip install joyfuljay[kafka]

# Prometheus metrics
pip install joyfuljay[monitoring]

# mDNS server discovery
pip install joyfuljay[discovery]

# Connection graph analysis
pip install joyfuljay[graphs]

# Everything
pip install joyfuljay[all]
```

---

## Getting Help

- **Issues**: [GitHub Issues](https://github.com/cenab/joyfuljay/issues)
- **Discussions**: [GitHub Discussions](https://github.com/cenab/joyfuljay/discussions)

## License

MIT License - see [LICENSE](https://github.com/cenab/joyfuljay/blob/main/LICENSE)
