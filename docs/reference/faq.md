# Frequently Asked Questions

Common questions and answers about JoyfulJay.

---

## General Questions

### What is JoyfulJay?

JoyfulJay is a Python library for extracting ML-ready features from encrypted network traffic. It analyzes timing patterns, packet sizes, and protocol metadata without decrypting any traffic content.

### Why should I use JoyfulJay instead of other tools?

JoyfulJay offers several advantages:

| Advantage | Details |
|-----------|---------|
| **More features** | 387 features vs 84 (CICFlowMeter) or 40 (NFStream) |
| **Modern Python** | Type hints, dataclasses, Python 3.10+ |
| **ML focus** | Output formats designed for ML pipelines |
| **Streaming** | Process multi-GB files without memory issues |
| **Extensible** | Easy to add custom extractors |
| **Enterprise ready** | Kafka, Prometheus, PostgreSQL integrations |

See [Why JoyfulJay?](../comparison/index.md) for detailed comparisons.

### Does JoyfulJay decrypt traffic?

No. JoyfulJay never decrypts traffic. It extracts features from:
- Packet timing and sizes
- Protocol headers (TLS handshakes, TCP options)
- Metadata (SNI, JA3 fingerprints)

All analysis is performed on metadata visible without decryption.

### What Python versions are supported?

JoyfulJay supports Python 3.10, 3.11, and 3.12.

### What operating systems are supported?

- **Linux**: Full support
- **macOS**: Full support
- **Windows**: Full support (requires [Npcap](https://npcap.com/) for live capture)

---

## Installation

### How do I install JoyfulJay?

```bash
pip install joyfuljay
```

For optional features:
```bash
pip install joyfuljay[fast]      # 10x faster with DPKT
pip install joyfuljay[all]       # All optional dependencies
```

See [Installation Guide](../getting-started/installation.md) for details.

### Why is live capture not working?

Live capture requires root/administrator privileges:

**Linux/macOS:**
```bash
sudo jj live eth0 --duration 30
```

**Windows:**
1. Install [Npcap](https://npcap.com/)
2. Run command prompt as Administrator

### I get ImportError for optional dependencies

Install the required extras:

```bash
# For connection graph features
pip install joyfuljay[graphs]

# For Kafka streaming
pip install joyfuljay[kafka]

# For Prometheus metrics
pip install joyfuljay[monitoring]
```

---

## Usage

### How do I extract features from a PCAP file?

**Python:**
```python
import joyfuljay as jj

df = jj.extract("capture.pcap")
print(df.head())
```

**CLI:**
```bash
jj extract capture.pcap -o features.csv
```

### How do I select specific features?

```python
import joyfuljay as jj

# Select feature groups
df = jj.extract("capture.pcap", features=["timing", "tls"])

# Select specific features
config = jj.Config(
    features=["all"],
    specific_features=["ja3_hash", "iat_mean", "total_bytes"]
)
df = jj.Pipeline(config).process_pcap("capture.pcap")
```

### How do I process multiple PCAP files?

```python
import joyfuljay as jj
from pathlib import Path

config = jj.Config(features=["timing", "tls"])
pipeline = jj.Pipeline(config)

# Sequential processing
all_features = []
for pcap in Path("./pcaps").glob("*.pcap"):
    df = pipeline.process_pcap(str(pcap))
    df["source"] = pcap.name
    all_features.append(df)

combined = pd.concat(all_features)

# Parallel processing
df = pipeline.process_pcaps_batch(
    list(Path("./pcaps").glob("*.pcap")),
    num_workers=4
)
```

### How do I handle large PCAP files?

Use streaming mode to process without loading the entire file:

```python
import joyfuljay as jj

config = jj.Config(features=["timing", "size"])
pipeline = jj.Pipeline(config)

# Process one flow at a time
for features in pipeline.iter_features("large_file.pcap"):
    # Process or save each flow
    save_to_database(features)
```

### How do I detect Tor/VPN/DoH traffic?

```python
import joyfuljay as jj

df = jj.extract("capture.pcap", features=["fingerprint"])

tor_flows = df[df["likely_tor"] == True]
vpn_flows = df[df["likely_vpn"] == True]
doh_flows = df[df["likely_doh"] == True]

print(f"Tor: {len(tor_flows)}, VPN: {len(vpn_flows)}, DoH: {len(doh_flows)}")
```

### How do I anonymize IP addresses?

```python
import joyfuljay as jj

config = jj.Config(
    anonymize_ips=True,
    anonymization_salt="my-secret-salt"  # For reproducibility
)

df = jj.Pipeline(config).process_pcap("capture.pcap")
# IPs are now hashed: src_ip = "a1b2c3d4..."
```

### How do I filter traffic?

Use BPF filters:

```python
import joyfuljay as jj

# Only TLS traffic
config = jj.Config(bpf_filter="tcp port 443")

# Only traffic to/from specific IP
config = jj.Config(bpf_filter="host 192.168.1.1")

# Exclude DNS
config = jj.Config(bpf_filter="not port 53")
```

---

## Features

### How many features does JoyfulJay extract?

JoyfulJay extracts 387 features across 24 extractors. See [Features Reference](../features/complete-reference.md) for the complete list.

### What is JA3/JA3S?

JA3 is a method for fingerprinting TLS clients based on the ClientHello message. JA3S fingerprints servers based on ServerHello. These fingerprints help identify specific applications or malware.

```python
df = jj.extract("tls_traffic.pcap", features=["tls"])
print(df[["ja3_hash", "ja3s_hash", "sni"]].head())
```

### What is HASSH?

HASSH is similar to JA3 but for SSH traffic. It fingerprints SSH clients and servers based on key exchange parameters.

```python
df = jj.extract("ssh_traffic.pcap", features=["ssh"])
print(df[["hassh_hash", "hassh_server_hash"]].head())
```

### How do I get raw packet sequences?

Enable sequence features for deep learning models:

```python
config = jj.Config(
    include_raw_sequences=True,
    include_splt=True,
    max_sequence_length=100
)

df = jj.Pipeline(config).process_pcap("capture.pcap")
# df["iat_sequence"] contains list of IATs
# df["size_sequence"] contains list of packet sizes
```

---

## Performance

### How fast is JoyfulJay?

Performance depends on the backend and features selected:

| Backend | Speed | Features |
|---------|-------|----------|
| Scapy (default) | ~3.5 MB/s | All features |
| DPKT | ~35 MB/s | Most features |

For faster processing:
```bash
pip install joyfuljay[fast]
```

### How do I improve performance?

1. **Use DPKT backend**: 10x faster than Scapy
2. **Select fewer features**: Only extract what you need
3. **Use sampling**: Process a fraction of packets
4. **Parallel processing**: Use multiple workers for batch processing

```python
config = jj.Config(
    features=["timing", "size"],  # Minimal features
    sampling_rate=0.1,            # 10% of packets
    num_workers=4                 # Parallel processing
)
```

### How do I handle memory issues?

Use streaming mode for large files:

```python
# Instead of:
df = pipeline.process_pcap("huge.pcap")  # May run out of memory

# Use:
for features in pipeline.iter_features("huge.pcap"):
    save_or_process(features)  # Memory-efficient
```

---

## Machine Learning

### How do I train a classifier?

```python
import joyfuljay as jj
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# Extract features
df = jj.extract("labeled_traffic.pcap", features=["timing", "size", "tls"])

# Prepare data
X = df.select_dtypes(include=['number']).fillna(0)
y = df['label']

# Train
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
clf = RandomForestClassifier()
clf.fit(X_train, y_train)

print(f"Accuracy: {clf.score(X_test, y_test):.2%}")
```

See [Traffic Classification Tutorial](../tutorials/traffic-classification.md) for a complete guide.

### Which features are best for classification?

Start with these feature groups:

| Group | Use Case |
|-------|----------|
| `timing` | Distinguish real-time (VoIP) from bursty (web) |
| `size` | Protocol identification |
| `tls` | Application fingerprinting |
| `fingerprint` | Tor/VPN/DoH detection |
| `entropy` | Encrypted vs plaintext |

### How do I use JoyfulJay with PyTorch/TensorFlow?

Output to NumPy arrays for direct use:

```python
import joyfuljay as jj
import torch

config = jj.Config(
    features=["timing", "size"],
    include_raw_sequences=True
)
pipeline = jj.Pipeline(config)

# Get NumPy array
array = pipeline.process_pcap("capture.pcap", output_format="numpy")

# Convert to PyTorch tensor
tensor = torch.from_numpy(array)
```

---

## Integration

### How do I stream to Kafka?

```python
from joyfuljay.output import KafkaWriter

with KafkaWriter("localhost:9092", topic="features") as writer:
    for features in pipeline.iter_features("capture.pcap"):
        writer.write(features)
```

See [Kafka Integration](../integrations/kafka/index.md) for details.

### How do I monitor with Prometheus?

```python
from joyfuljay.monitoring import PrometheusMetrics, start_prometheus_server

metrics = PrometheusMetrics()
start_prometheus_server(9090)  # http://localhost:9090/metrics

pipeline = jj.Pipeline(config, metrics=metrics)
```

See [Prometheus Integration](../integrations/prometheus/index.md) for details.

### How do I save to a database?

```python
from joyfuljay.output import DatabaseWriter

with DatabaseWriter("postgresql://user:pass@localhost/db", table="flows") as writer:
    for features in pipeline.iter_features("capture.pcap"):
        writer.write(features)
```

---

## Troubleshooting

### "No flows extracted" - empty results

Common causes:
1. **Wrong file format**: Ensure the file is PCAP or PCAPNG
2. **BPF filter too restrictive**: Try without a filter first
3. **Flow timeout too short**: Increase with `flow_timeout=120`
4. **Encrypted only**: If expecting cleartext, check the file

### "Permission denied" for live capture

Live capture requires elevated privileges:
- Linux/macOS: Use `sudo`
- Windows: Run as Administrator and install Npcap

### Features contain NaN values

This is expected for flows without certain traffic:
- TLS features are NaN for non-TLS flows
- SSH features are NaN for non-SSH flows

Handle in your ML pipeline:
```python
X = df.select_dtypes(include=['number']).fillna(0)
```

### Memory error with large files

Use streaming mode:
```python
for features in pipeline.iter_features("large.pcap"):
    process(features)
```

---

## Contributing

### How do I contribute?

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `pytest`
5. Submit a pull request

See [Contributing Guide](../development/contributing.md) for details.

### How do I create a custom extractor?

```python
from joyfuljay.extractors import FeatureExtractor
from joyfuljay.core import Flow

class MyExtractor(FeatureExtractor):
    def extract(self, flow: Flow) -> dict:
        return {
            "my_custom_feature": calculate_something(flow),
        }

    @property
    def feature_names(self) -> list[str]:
        return ["my_custom_feature"]
```

See [Custom Extractors Tutorial](../tutorials/custom-extractors.md) for a complete guide.

---

## Still have questions?

- **GitHub Issues**: [Report a bug or request a feature](https://github.com/cenab/joyfuljay/issues)
- **GitHub Discussions**: [Ask questions and share ideas](https://github.com/cenab/joyfuljay/discussions)
