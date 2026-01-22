<div align="center">

<img src="docs/assets/images/logo.png" alt="JoyfulJay Logo" width="200">

# JoyfulJay - Encrypted Traffic Feature Extraction

[![CI](https://github.com/cenab/joyfuljay/actions/workflows/ci.yml/badge.svg)](https://github.com/cenab/joyfuljay/actions/workflows/ci.yml)
[![PyPI version](https://badge.fury.io/py/joyfuljay.svg)](https://badge.fury.io/py/joyfuljay)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

![JoyfulJay](https://img.shields.io/badge/JoyfulJay-387%20Features-blue?style=flat-square)
![ML Ready](https://img.shields.io/badge/ML-Research%20Ready-22D3EE?style=flat-square)
![Encrypted Traffic](https://img.shields.io/badge/Encrypted-TLS%20%2F%20QUIC-success?style=flat-square)
![Research Tool](https://img.shields.io/badge/Use-Academic%20Research-informational?style=flat-square)

</div>

**JoyfulJay** is a Python library for extracting standardized, ML-ready features from encrypted network traffic. It operates on PCAP files and live network interfaces, producing feature vectors that capture timing, size, and protocol metadata patterns - all without decrypting any traffic.

## Features

- **Encrypted Traffic Focus**: Extract features proven effective for classifying TLS, QUIC, VPN, and Tor traffic
- **ML-Ready Output**: Pandas DataFrames, NumPy arrays, CSV, JSON, or Parquet - ready for scikit-learn, PyTorch, etc.
- **Streaming Architecture**: Process multi-GB PCAPs without loading them into memory
- **Live Capture**: Real-time feature extraction from network interfaces
- **Remote Capture**: Stream packets from remote devices over secure WebSocket (TLS/WSS)
- **Protocol Metadata**: TLS handshake parsing, JA3/JA3S fingerprints, QUIC metadata
- **Traffic Fingerprinting**: Detect Tor, VPN, and DoH traffic patterns
- **Tranalyzer Compatible**: 387 features across 21 extractors, matching research-grade tools
- **Enterprise Ready**: Kafka streaming, Prometheus metrics, mDNS discovery

## Installation

```bash
pip install joyfuljay
# or
uv pip install joyfuljay
```

For optional features (same syntax works with `uv pip`):

```bash
# Fast parsing with dpkt
pip install joyfuljay[fast]

# High-speed capture with libpcap
pip install joyfuljay[libpcap]

# Kafka streaming output
pip install joyfuljay[kafka]

# Prometheus metrics
pip install joyfuljay[monitoring]

# mDNS server discovery
pip install joyfuljay[discovery]

# Connection graph analysis
pip install joyfuljay[graphs]

# All optional features
pip install joyfuljay[fast,kafka,monitoring,discovery,graphs]
```

## Quick Start

### Python API

```python
from joyfuljay import extract_features_from_pcap

# Extract features from a PCAP file
features_df = extract_features_from_pcap("capture.pcap")

print(features_df.shape)
print(features_df.columns.tolist())
print(features_df.head())
```

### Command Line

```bash
# Extract features to CSV
jj extract capture.pcap -o features.csv

# Live capture for 60 seconds
jj live eth0 --duration 60 -o live_features.csv

# Output as JSON
jj extract capture.pcap -o features.json --format json
```

## Feature Groups

| Group | Features |
|-------|----------|
| **Flow Metadata** | 5-tuple, duration, packet/byte counts |
| **Timing** | Inter-arrival time statistics, burst metrics |
| **Size** | Packet length statistics, payload bytes |
| **TLS** | Version, cipher suite, SNI, JA3/JA3S fingerprints |
| **QUIC** | Version, ALPN, connection IDs |
| **Padding** | Fixed-size detection, constant-rate detection |
| **Fingerprint** | Tor/VPN/DoH classification |
| **TCP Analysis** | Flags, handshake, sequence/window analysis |
| **MAC/Layer 2** | Source/dest MAC, VLAN, Ethernet type |
| **ICMP** | Type/code, echo success ratio |
| **Connection Graphs** | Fan-out, communities, centrality (requires `[graphs]`) |

## Remote Capture

Stream packets from a remote device (e.g., Android phone, Raspberry Pi) to your analysis machine:

```bash
# On the capture device - start server with TLS
jj serve wlan0 --tls-cert server.crt --tls-key server.key --announce

# On your machine - discover and connect
jj discover                    # Find servers on LAN
jj connect jj://192.168.1.50:8765?token=xxx&tls=1 -o features.csv
```

## Kafka Streaming

Stream features directly to Kafka for real-time pipelines:

```python
from joyfuljay.output.kafka import KafkaWriter

with KafkaWriter("localhost:9092", topic="network-features") as writer:
    for features in extract_features_streaming("capture.pcap"):
        writer.write(features)
```

## Prometheus Metrics

Export processing metrics for monitoring:

```python
from joyfuljay.monitoring import PrometheusMetrics, start_prometheus_server

metrics = PrometheusMetrics()
start_prometheus_server(9090)  # Scrape at http://localhost:9090/metrics
```

## Requirements

- Python 3.10+
- scapy >= 2.5.0
- pandas >= 2.0.0
- numpy >= 1.24.0

## Cross-Platform Support

| Feature | Linux | macOS | Windows |
|---------|-------|-------|---------|
| PCAP file processing | ✅ | ✅ | ✅ |
| Live capture | ✅ | ✅ | ✅ (requires [Npcap](https://npcap.com/)) |

Check your system status with:
```bash
jj status
```

## Documentation

Full documentation: [[https://joyfuljay.readthedocs.io](https://joyfuljay.readthedocs.io)](https://docs.joyfuljay.com/en/stable/)

## Citation

If you use JoyfulJay in academic research, please cite:

```bibtex
@software{joyfuljay2025,
  title = {{JoyfulJay}: Encrypted Traffic Feature Extraction Library},
  year = {2025},
  publisher = {GitHub},
  url = {https://github.com/cenab/joyfuljay}
}
```

## License

MIT License - see [LICENSE](LICENSE) for details.
