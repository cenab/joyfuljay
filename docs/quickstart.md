# Quick Start Guide

Get started with JoyfulJay in 5 minutes.

---

## Installation

```bash
pip install joyfuljay
```

Verify installation:

```bash
jj status
```

---

## Your First Extraction

### Python

```python
import joyfuljay as jj

# Extract features from a PCAP file
df = jj.extract("capture.pcap")

# View results
print(f"Flows: {len(df)}")
print(f"Features: {len(df.columns)}")
print(df.head())
```

### Command Line

```bash
# Extract to CSV
jj extract capture.pcap -o features.csv

# View PCAP info
jj info capture.pcap
```

---

## Select Feature Groups

Don't need all 387 features? Select specific groups:

```python
import joyfuljay as jj

# Only timing and TLS features
df = jj.extract("capture.pcap", features=["timing", "tls"])

# Only flow metadata
df = jj.extract("capture.pcap", features=["flow_meta"])
```

**Available groups:**

| Group | Description |
|-------|-------------|
| `flow_meta` | IPs, ports, duration, packet counts |
| `timing` | Inter-arrival times, burst metrics |
| `size` | Packet length statistics |
| `tls` | TLS version, ciphers, JA3 fingerprints |
| `quic` | QUIC protocol metadata |
| `ssh` | SSH version, HASSH fingerprints |
| `dns` | DNS queries and responses |
| `tcp` | TCP flags, handshake analysis |
| `fingerprint` | Tor/VPN/DoH detection |
| `entropy` | Payload entropy |
| `padding` | Padding detection |

---

## Live Capture

Capture traffic from a network interface:

### Python

```python
import joyfuljay as jj

# Capture for 30 seconds
df = jj.extract_live("eth0", duration=30)
print(f"Captured {len(df)} flows")
```

### Command Line

```bash
# Capture with BPF filter
jj live eth0 --duration 60 --filter "port 443" -o tls_traffic.csv
```

**Note:** Live capture requires root/admin privileges.

---

## Configure Extraction

Use `Config` for fine-grained control:

```python
import joyfuljay as jj

# Create custom configuration
config = jj.Config(
    features=["timing", "tls", "fingerprint"],
    flow_timeout=30.0,          # 30 second flow timeout
    include_ip_addresses=True,  # Include IPs in output
    anonymize_ips=False,        # Don't hash IPs
)

# Create pipeline
pipeline = jj.Pipeline(config)

# Process PCAP
df = pipeline.process_pcap("capture.pcap")

# Or iterate over flows (memory efficient)
for features in pipeline.iter_features("large_capture.pcap"):
    print(features)
```

---

## Output Formats

### DataFrame (Default)

```python
df = jj.extract("capture.pcap")
# Returns pandas DataFrame
```

### NumPy Array

```python
config = jj.Config(features=["timing", "size"])
pipeline = jj.Pipeline(config)
array = pipeline.process_pcap("capture.pcap", output_format="numpy")
# Returns numpy array with numeric features only
```

### CSV File

```bash
jj extract capture.pcap -o features.csv
```

### JSON File

```bash
jj extract capture.pcap -o features.json --format json
```

---

## Use with Machine Learning

JoyfulJay output is designed for ML:

```python
import joyfuljay as jj
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# Extract features
df = jj.extract("labeled_traffic.pcap", features=["timing", "size"])

# Prepare data
X = df.select_dtypes(include=['number']).fillna(0)
y = df['label']  # Your labels

# Train
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
clf = RandomForestClassifier()
clf.fit(X_train, y_train)

# Evaluate
print(f"Accuracy: {clf.score(X_test, y_test):.2%}")
```

---

## Detect Encrypted Traffic Types

Use the fingerprint extractor:

```python
import joyfuljay as jj

df = jj.extract("capture.pcap", features=["fingerprint"])

# Check for Tor
tor_flows = df[df['likely_tor'] == True]
print(f"Tor flows: {len(tor_flows)}")

# Check for VPN
vpn_flows = df[df['likely_vpn'] == True]
print(f"VPN flows: {len(vpn_flows)}")

# Check for DoH
doh_flows = df[df['likely_doh'] == True]
print(f"DoH flows: {len(doh_flows)}")
```

---

## Process Multiple Files

```python
import joyfuljay as jj
from pathlib import Path

# Create pipeline once
config = jj.Config(features=["timing", "tls"])
pipeline = jj.Pipeline(config)

# Process multiple files
pcap_dir = Path("./captures")
all_features = []

for pcap_file in pcap_dir.glob("*.pcap"):
    df = pipeline.process_pcap(str(pcap_file))
    df['source_file'] = pcap_file.name
    all_features.append(df)

# Combine
import pandas as pd
combined = pd.concat(all_features, ignore_index=True)
combined.to_csv("all_features.csv", index=False)
```

---

## Command Line Cheat Sheet

```bash
# Basic extraction
jj extract capture.pcap -o features.csv

# Select features
jj extract capture.pcap -o features.csv --features timing tls

# Live capture
jj live eth0 --duration 60 -o live.csv

# With BPF filter
jj live eth0 --filter "tcp port 443" -o tls.csv

# View PCAP info
jj info capture.pcap

# Check system status
jj status

# List available features
jj features

# Export feature schema
jj schema -o schema.json

# Start remote capture server
jj serve eth0 --port 8765

# Discover remote servers
jj discover

# Connect to remote server
jj connect jj://192.168.1.100:8765 -o features.csv
```

---

## Next Steps

- **[Configuration](configuration.md)** - All configuration options
- **[Features](features.md)** - Complete feature reference
- **[CLI Reference](cli-reference.md)** - All CLI commands
- **[Extractors](extractors/index.md)** - Extractor documentation
- **[Remote Capture](remote-capture.md)** - Distributed capture setup
