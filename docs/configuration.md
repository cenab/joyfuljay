# Configuration Reference

JoyfulJay provides extensive configuration options to customize feature extraction for different use cases. This document covers all available options.

## Configuration Methods

### Python API

```python
from joyfuljay import Pipeline, Config

# Default configuration
config = Config()

# Custom configuration
config = Config(
    flow_timeout=30.0,
    features=["flow_meta", "timing", "tls"],
    anonymize_ips=True,
)

pipeline = Pipeline(config)
```

### JSON Configuration File

```json
{
  "flow_timeout": 30.0,
  "features": ["flow_meta", "timing", "tls"],
  "anonymize_ips": true,
  "include_ip_addresses": true,
  "max_sequence_length": 100
}
```

```python
config = Config.from_json("config.json")
```

### YAML Configuration File

```yaml
flow_timeout: 30.0
features:
  - flow_meta
  - timing
  - tls
anonymize_ips: true
include_ip_addresses: true
max_sequence_length: 100
```

```python
config = Config.from_yaml("config.yaml")
# or auto-detect format:
config = Config.from_file("config.yaml")
```

### CLI Options

Most config options map to CLI flags:

```bash
jj extract capture.pcap \
    --flow-timeout 30 \
    --features flow_meta,timing,tls \
    --anonymize-ips \
    -o output.csv
```

---

## All Configuration Options

### Flow Management

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `flow_timeout` | float | `60.0` | Inactivity timeout (seconds) before flow expires |
| `max_concurrent_flows` | int | `0` | Maximum active flows (0 = unlimited) |
| `flow_eviction_strategy` | str | `"lru"` | Eviction strategy: `"lru"` or `"oldest"` |
| `sampling_rate` | float\|None | `None` | Packet sampling rate (0.0-1.0, None = all) |

#### `flow_timeout`

Time in seconds before an inactive flow is considered complete. Lower values capture more flows but may split long-lived connections.

```python
# Short timeout for detecting quick scans
config = Config(flow_timeout=5.0)

# Long timeout for persistent connections
config = Config(flow_timeout=300.0)
```

#### `max_concurrent_flows`

Limits memory usage by evicting flows when the limit is reached.

```python
# Limit to 10,000 concurrent flows
config = Config(max_concurrent_flows=10000)
```

#### `flow_eviction_strategy`

- `"lru"`: Least Recently Used - evicts flows that haven't seen traffic recently
- `"oldest"`: Evicts flows with the earliest start time

```python
config = Config(
    max_concurrent_flows=5000,
    flow_eviction_strategy="oldest"
)
```

#### `sampling_rate`

Process only a fraction of packets to reduce processing time.

```python
# Process 10% of packets
config = Config(sampling_rate=0.1)

# Process all packets (default)
config = Config(sampling_rate=None)
```

---

### Feature Selection

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `features` | list[str] | `["all"]` | Feature groups to extract |
| `specific_features` | list[str]\|None | `None` | Filter to specific feature names |
| `bidirectional_split` | bool | `False` | Split features by direction (fwd/bwd) |

#### `features`

Select which feature groups to extract. Use `["all"]` for all features.

**Available feature groups:**

| Group | Description | Features |
|-------|-------------|----------|
| `all` | All features | 387 |
| `flow_meta` | Flow metadata (5-tuple, duration) | 10 |
| `timing` | Inter-arrival time statistics | 20+ |
| `size` | Packet/payload size statistics | 15+ |
| `tcp` | TCP flags and handshake | 26 |
| `tls` | TLS/JA3 fingerprinting | 30+ |
| `quic` | QUIC protocol features | 10+ |
| `ssh` | SSH/HASSH fingerprinting | 10+ |
| `dns` | DNS query analysis | 15+ |
| `padding` | Padding detection | 8 |
| `fingerprint` | Tor/VPN/DoH detection | 6 |
| `entropy` | Payload entropy | 6 |
| `connection` | Connection graph metrics | 20+ |
| `mac` | Layer 2 MAC features | 8 |
| `ip_extended` | Extended IP header fields | 12 |
| `ipv6_options` | IPv6 extension headers | 8 |
| `tcp_sequence` | TCP sequence analysis | 10 |
| `tcp_window` | TCP window analysis | 8 |
| `tcp_options` | TCP options parsing | 12 |
| `tcp_mptcp` | Multipath TCP | 6 |
| `tcp_rtt` | RTT estimation | 8 |
| `tcp_fingerprint` | TCP fingerprinting | 4 |
| `icmp` | ICMP features | 10 |

```python
# Minimal features for fast processing
config = Config(features=["flow_meta", "timing", "size"])

# All TLS-related features
config = Config(features=["flow_meta", "tls"])

# Research configuration with everything
config = Config(features=["all"])
```

#### `specific_features`

Filter output to only include specific feature names (post-extraction filter).

```python
# Only output these specific features
config = Config(
    features=["all"],
    specific_features=[
        "src_ip", "dst_ip", "duration",
        "total_packets", "total_bytes",
        "ja3_hash", "ja3s_hash"
    ]
)
```

#### `bidirectional_split`

When enabled, directional features are split into forward (`_fwd`) and backward (`_bwd`) variants.

```python
config = Config(bidirectional_split=True)

# Output includes:
# - iat_mean_fwd, iat_mean_bwd (instead of just iat_mean)
# - packet_count_fwd, packet_count_bwd
# - etc.
```

---

### Sequence Features

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `include_raw_sequences` | bool | `False` | Include raw packet sequences |
| `include_splt` | bool | `False` | Include SPLT (Sequence of Packet Lengths and Times) |
| `max_sequence_length` | int | `50` | Maximum sequence length to include |

#### `include_raw_sequences`

Include raw sequences of inter-arrival times and packet sizes.

```python
config = Config(
    include_raw_sequences=True,
    max_sequence_length=100
)

# Output includes:
# - iat_sequence: [0.001, 0.002, 0.015, ...]
# - size_sequence: [64, 1500, 1500, ...]
```

#### `include_splt`

Include SPLT (Sequence of Packet Lengths and Times) for deep learning models.

```python
config = Config(include_splt=True)

# Output includes:
# - splt: [(size, iat), (size, iat), ...]
```

---

### Privacy & Security

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `include_ip_addresses` | bool | `True` | Include IP addresses in output |
| `include_ports` | bool | `True` | Include port numbers in output |
| `anonymize_ips` | bool | `False` | Hash IP addresses |
| `anonymization_salt` | str | `""` | Salt for IP hashing (reproducibility) |
| `include_flow_id` | bool | `False` | Include hashed flow identifier |

#### IP Anonymization

```python
# Exclude IPs entirely
config = Config(include_ip_addresses=False)

# Hash IPs for privacy (but still linkable)
config = Config(
    anonymize_ips=True,
    anonymization_salt="my-secret-salt"  # For reproducibility
)

# Include flow ID for linking flows without IPs
config = Config(
    include_ip_addresses=False,
    include_flow_id=True
)
```

---

### Performance Tuning

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `burst_threshold_ms` | float | `50.0` | Minimum gap (ms) between bursts |
| `entropy_sample_bytes` | int | `256` | Bytes to sample for entropy |
| `num_workers` | int | `1` | Parallel workers for batch processing |
| `bpf_filter` | str\|None | `None` | BPF filter for capture |

#### `burst_threshold_ms`

Defines the minimum inter-packet gap to separate bursts.

```python
# Sensitive burst detection (10ms gap)
config = Config(burst_threshold_ms=10.0)

# Coarse burst detection (100ms gap)
config = Config(burst_threshold_ms=100.0)
```

#### `entropy_sample_bytes`

Number of payload bytes to sample for entropy calculation. Higher values are more accurate but slower.

```python
# Fast, less accurate
config = Config(entropy_sample_bytes=64)

# Slower, more accurate
config = Config(entropy_sample_bytes=1024)
```

#### `num_workers`

Number of worker processes for parallel batch processing.

```python
# Process multiple PCAPs in parallel
config = Config(num_workers=4)

pipeline = Pipeline(config)
features = pipeline.process_pcaps_batch([
    "file1.pcap",
    "file2.pcap",
    "file3.pcap",
])
```

#### `bpf_filter`

Berkeley Packet Filter expression for live capture.

```python
# Only TCP traffic
config = Config(bpf_filter="tcp")

# Only HTTPS traffic
config = Config(bpf_filter="tcp port 443")

# Exclude SSH
config = Config(bpf_filter="not tcp port 22")
```

---

### Connection Graph Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `connection_use_ports` | bool | `False` | Include ports in graph nodes |
| `connection_include_graph_metrics` | bool | `True` | Compute NetworkX metrics |
| `connection_include_temporal` | bool | `False` | Compute temporal patterns |
| `connection_community_algorithm` | str | `"louvain"` | Community detection algorithm |

```python
config = Config(
    features=["flow_meta", "connection"],
    connection_use_ports=True,
    connection_include_graph_metrics=True,
    connection_community_algorithm="label_propagation"
)
```

---

## Example Configurations

### Minimal (Fast Processing)

```python
config = Config(
    features=["flow_meta"],
    flow_timeout=30.0,
)
```

### Research (All Features)

```python
config = Config(
    features=["all"],
    include_raw_sequences=True,
    include_splt=True,
    max_sequence_length=200,
    entropy_sample_bytes=512,
)
```

### Production (Optimized)

```python
config = Config(
    features=["flow_meta", "timing", "size", "tcp", "tls"],
    flow_timeout=60.0,
    max_concurrent_flows=50000,
    sampling_rate=0.5,  # Sample 50% of packets
    num_workers=4,
)
```

### Privacy-Preserving

```python
config = Config(
    features=["timing", "size", "entropy"],  # No protocol-specific
    include_ip_addresses=False,
    include_ports=False,
    anonymize_ips=True,
    anonymization_salt="research-project-2025",
    include_flow_id=True,
)
```

### ML Training

```python
config = Config(
    features=["all"],
    bidirectional_split=True,
    include_raw_sequences=True,
    max_sequence_length=100,
    specific_features=[
        "duration", "total_packets", "total_bytes",
        "iat_mean_fwd", "iat_mean_bwd",
        "pkt_len_mean_fwd", "pkt_len_mean_bwd",
        "ja3_hash", "is_tor", "is_vpn",
    ],
)
```

### Live Capture

```python
config = Config(
    features=["flow_meta", "timing", "tls", "fingerprint"],
    flow_timeout=30.0,
    max_concurrent_flows=10000,
    bpf_filter="tcp port 443 or udp port 443",  # HTTPS + QUIC
)
```

---

## Saving and Loading Configuration

### Save to File

```python
config = Config(features=["flow_meta", "tls"], anonymize_ips=True)

# Save as JSON
config.to_json("config.json")

# Save as YAML (requires PyYAML)
config.to_yaml("config.yaml")
```

### Load from File

```python
# Load JSON
config = Config.from_json("config.json")

# Load YAML
config = Config.from_yaml("config.yaml")

# Auto-detect format
config = Config.from_file("config.json")
config = Config.from_file("config.yaml")
```

### Convert to Dictionary

```python
config = Config(features=["all"])
config_dict = config.to_dict()

# Recreate from dict
config2 = Config.from_dict(config_dict)
```

---

## Validation

The `Config` class validates options on creation:

```python
# Raises ValueError: flow_timeout must be positive
Config(flow_timeout=-1)

# Raises ValueError: sampling_rate must be between 0.0 and 1.0
Config(sampling_rate=1.5)

# Raises ValueError: max_concurrent_flows must be non-negative
Config(max_concurrent_flows=-100)
```

---

## Environment Variables

Some options can be set via environment variables:

| Variable | Config Option |
|----------|---------------|
| `JOYFULJAY_FLOW_TIMEOUT` | `flow_timeout` |
| `JOYFULJAY_MAX_FLOWS` | `max_concurrent_flows` |
| `JOYFULJAY_NUM_WORKERS` | `num_workers` |

```bash
export JOYFULJAY_FLOW_TIMEOUT=30
export JOYFULJAY_NUM_WORKERS=4
jj extract capture.pcap -o output.csv
```

---

## Feature Group Dependencies

Some feature groups require optional dependencies:

| Feature Group | Required Extra | Install Command |
|---------------|----------------|-----------------|
| `connection` | `graphs` | `pip install joyfuljay[graphs]` |
| (monitoring) | `monitoring` | `pip install joyfuljay[monitoring]` |
| (discovery) | `discovery` | `pip install joyfuljay[discovery]` |
| (kafka output) | `kafka` | `pip install joyfuljay[kafka]` |

```python
# Will raise ImportError if networkx not installed
config = Config(features=["connection"])
```
