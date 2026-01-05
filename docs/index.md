# JoyfulJay Documentation

<div align="center">

<img src="assets/images/logo.png" alt="JoyfulJay Logo" width="200">

**Extract ML-Ready Features from Encrypted Network Traffic**

*Analyze TLS, QUIC, SSH, and more - without decryption*

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

![JoyfulJay](https://img.shields.io/badge/JoyfulJay-387%20Features-blue?style=flat-square)
![ML Ready](https://img.shields.io/badge/ML-Research%20Ready-22D3EE?style=flat-square)
![Encrypted Traffic](https://img.shields.io/badge/Encrypted-TLS%20%2F%20QUIC-success?style=flat-square)
![Research Tool](https://img.shields.io/badge/Use-Academic%20Research-informational?style=flat-square)

[Quick Start](#quick-start) | [Installation](installation.md) | [Features](features.md) | [Tutorials](tutorials/index.md)

</div>

---

## The Problem: Encrypted Traffic is Hard to Analyze

Over 95% of web traffic is now encrypted with TLS. Traditional deep packet inspection can't see inside encrypted connections, yet you still need to:

- **Classify traffic** (streaming vs. browsing vs. malicious)
- **Detect threats** (malware C2, data exfiltration, policy violations)
- **Identify applications** (what's running on your network?)
- **Detect anonymization** (Tor, VPNs, DNS-over-HTTPS)

**The solution?** Analyze the *behavior* of encrypted traffic - timing patterns, packet sizes, protocol handshakes - without ever needing to decrypt it.

---

## How JoyfulJay Works

JoyfulJay extracts **200+ behavioral features** from network flows that reveal traffic characteristics without exposing content:

```python
import joyfuljay as jj

# Extract features from encrypted traffic
df = jj.extract("https_traffic.pcap")

# You now have ML-ready features like:
# - Timing: iat_mean, iat_std, burstiness_index
# - Size: pkt_len_mean, pkt_len_std, byte_asymmetry
# - TLS: ja3_hash, tls_sni, tls_cipher_count
# - Detection: likely_tor, vpn_type, likely_doh
```

These features can distinguish a Tor connection from a VPN connection from regular HTTPS - all without seeing the encrypted payload.

---

## What Can You Do With JoyfulJay?

### Traffic Classification
Train ML models to identify application types (Netflix vs. YouTube vs. Zoom) based on behavioral patterns.

### Threat Detection
Detect malware command-and-control traffic, data exfiltration attempts, and suspicious communication patterns.

### Network Forensics
Analyze captured traffic to understand what happened during a security incident.

### Privacy Research
Study anonymization tools and encrypted DNS to understand their fingerprints.

### QoS Monitoring
Classify traffic for quality-of-service policies without inspecting content.

---

## Quick Start

### Installation

```bash
pip install joyfuljay
```

### Extract Features from PCAP

```python
import joyfuljay as jj

# Extract all features (200+)
df = jj.extract("traffic.pcap")
print(f"Extracted {len(df)} flows with {len(df.columns)} features")

# Select specific feature groups
df = jj.extract("traffic.pcap", features=["timing", "tls", "fingerprint"])

# Save for ML training
df.to_csv("features.csv", index=False)
```

### Command Line Interface

```bash
# Extract to CSV
jj extract capture.pcap -o features.csv

# Select features
jj extract capture.pcap --features timing tls -o features.csv

# Live capture from network interface
jj live eth0 --duration 60 -o live.csv

# View available features
jj features
```

### Detect Tor Traffic

```python
import joyfuljay as jj

df = jj.extract("capture.pcap", features=["fingerprint", "padding"])

# Find Tor flows
tor_flows = df[df['likely_tor'] == True]
print(f"Detected {len(tor_flows)} potential Tor connections")

# Check confidence scores
print(tor_flows[['src_ip', 'dst_ip', 'tor_confidence', 'padding_score']])
```

### Train a Traffic Classifier

```python
import joyfuljay as jj
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# Extract features
df = jj.extract("labeled_traffic.pcap", features=["timing", "size", "tls"])

# Prepare for ML (numeric features only)
X = df.select_dtypes(include=['number']).fillna(0)
y = df['label']  # Assuming you have labels

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

# Train classifier
clf = RandomForestClassifier(n_estimators=100)
clf.fit(X_train, y_train)

# Evaluate
print(f"Accuracy: {clf.score(X_test, y_test):.2%}")
```

---

## Key Capabilities

| Capability | Description |
|------------|-------------|
| **200+ Features** | Timing, size, TLS, QUIC, SSH, DNS, TCP, entropy, padding, graph metrics |
| **12x Faster** | Process 10+ GB/s with optimized DPKT backend |
| **Protocol Analysis** | Parse TLS handshakes, extract JA3/JA3S fingerprints, SNI, certificates |
| **Traffic Fingerprinting** | Detect Tor, VPN (WireGuard, OpenVPN, IPSec), DNS-over-HTTPS |
| **Enterprise Ready** | Kafka streaming, Prometheus metrics, parallel processing |
| **Privacy Preserving** | Anonymize IPs, exclude identifiers for research datasets |

---

## Feature Groups

JoyfulJay organizes 200+ features into logical groups:

| Group | Description | Key Features |
|-------|-------------|--------------|
| `flow_meta` | Flow identification | src_ip, dst_ip, duration, packet counts |
| `timing` | Temporal patterns | iat_mean, iat_std, burstiness, burst_count |
| `size` | Packet sizes | pkt_len_mean, pkt_len_std, byte_asymmetry |
| `tls` | TLS analysis | ja3_hash, tls_sni, tls_version, cipher_count |
| `quic` | QUIC protocol | quic_version, quic_alpn, quic_sni |
| `ssh` | SSH fingerprinting | ssh_hassh, ssh_version, ssh_software |
| `tcp` | TCP behavior | syn_count, rst_count, handshake_complete |
| `fingerprint` | Traffic detection | likely_tor, likely_vpn, vpn_type, likely_doh |
| `entropy` | Payload analysis | entropy_payload, printable_ratio |
| `padding` | Obfuscation detection | is_constant_size, padding_score |
| `connection` | Graph analysis | unique_dsts, betweenness, community_id |

Select groups when extracting:

```python
# Only what you need (faster)
df = jj.extract("capture.pcap", features=["timing", "tls"])

# Everything (comprehensive)
df = jj.extract("capture.pcap", features=["all"])
```

See [Complete Feature Reference](features.md) for detailed documentation of every feature.

---

## Documentation Guide

### Getting Started
| Document | Description |
|----------|-------------|
| [Installation](installation.md) | Install JoyfulJay and optional dependencies |
| [Quick Start](quickstart.md) | Your first feature extraction in 5 minutes |
| [Why JoyfulJay?](why-joyfuljay.md) | Comparison with alternatives |

### Core Concepts
| Document | Description |
|----------|-------------|
| [Features Reference](features.md) | **Complete guide to all 200+ features** |
| [Configuration](configuration.md) | All configuration options explained |
| [CLI Reference](cli-reference.md) | Command-line interface |
| [Architecture](architecture.md) | System design and data flow |

### Feature Extractors
| Document | Description |
|----------|-------------|
| [Extractors Overview](extractors/index.md) | All extractors at a glance |
| [Flow Metadata](extractors/flow-meta.md) | Basic flow identification |
| [Timing](extractors/timing.md) | Inter-arrival times and bursts |
| [Size](extractors/size.md) | Packet size analysis |
| [TLS](extractors/tls.md) | TLS/SSL analysis and JA3 |
| [Fingerprint](extractors/fingerprint.md) | Tor/VPN/DoH detection |

### Tutorials
| Tutorial | Level | Description |
|----------|-------|-------------|
| [Traffic Classification](tutorials/traffic-classification.md) | Beginner | Train ML models on network traffic |
| [Encrypted Traffic Analysis](tutorials/encrypted-traffic.md) | Beginner | Detect Tor, VPN, DoH |
| [Batch Processing](tutorials/batch-processing.md) | Intermediate | Process large datasets |
| [Real-time Monitoring](tutorials/realtime-monitoring.md) | Advanced | Kafka + Prometheus + Grafana |
| [Custom Extractors](tutorials/custom-extractors.md) | Advanced | Create your own extractors |

### Advanced
| Document | Description |
|----------|-------------|
| [Kafka Streaming](kafka.md) | Real-time feature pipelines |
| [Prometheus Monitoring](monitoring.md) | Metrics and dashboards |
| [Remote Capture](remote-capture.md) | Distributed packet capture |
| [Benchmarks](benchmarks.md) | Performance data |

### Development
| Document | Description |
|----------|-------------|
| [Developer Guide](developer-guide.md) | Contribute to JoyfulJay |
| [Testing](testing.md) | Run tests, add coverage |
| [API Reference](api.md) | Python API documentation |

---

## System Requirements

- **Python**: 3.10, 3.11, or 3.12
- **OS**: Linux, macOS, Windows
- **Dependencies**: Auto-installed (scapy, pandas, numpy)

### Optional Extras

```bash
# Fast PCAP parsing (recommended for large files)
pip install joyfuljay[fast]

# Kafka streaming output
pip install joyfuljay[kafka]

# Prometheus metrics
pip install joyfuljay[monitoring]

# Connection graph analysis
pip install joyfuljay[graphs]

# Everything
pip install joyfuljay[all]
```

---

## Example: Complete Traffic Analysis

```python
import joyfuljay as jj

# Configure for comprehensive analysis
config = jj.Config(
    features=["flow_meta", "timing", "size", "tls", "fingerprint"],
    include_raw_sequences=True,
    max_sequence_length=100,
)

# Create pipeline
pipeline = jj.Pipeline(config)

# Process PCAP
df = pipeline.process_pcap("enterprise_traffic.pcap")

# Analyze results
print(f"Total flows: {len(df)}")
print(f"TLS flows: {df['tls_detected'].sum()}")
print(f"Tor flows: {df['likely_tor'].sum()}")
print(f"VPN flows: {df['likely_vpn'].sum()}")

# Top destinations by volume
top_dsts = df.groupby('dst_ip')['total_bytes'].sum().nlargest(10)
print("Top destinations:")
print(top_dsts)

# Export for ML
df.to_parquet("features.parquet")
```

---

## Getting Help

- **Documentation**: You're here!
- **Issues**: [GitHub Issues](https://github.com/cenab/joyfuljay/issues)
- **Discussions**: [GitHub Discussions](https://github.com/cenab/joyfuljay/discussions)

## License

MIT License - see [LICENSE](https://github.com/cenab/joyfuljay/blob/main/LICENSE)
