# Feature Extractors

JoyfulJay includes 24 feature extractors that produce 387 total features for ML-ready network traffic analysis. This page provides an overview of all extractors and links to detailed documentation.

## Quick Reference

| Group | Extractor | Features | Description |
|-------|-----------|----------|-------------|
| `flow_meta` | [FlowMetaExtractor](flow-meta.md) | 10 | Flow metadata (5-tuple, duration) |
| `timing` | [TimingExtractor](timing.md) | 20+ | Inter-arrival time statistics |
| `size` | [SizeExtractor](size.md) | 15+ | Packet/payload size statistics |
| `tcp` | [TCPExtractor](tcp.md) | 26 | TCP flags and handshake analysis |
| `tls` | [TLSExtractor](tls.md) | 30+ | TLS/JA3 fingerprinting |
| `quic` | [QUICExtractor](quic.md) | 10+ | QUIC protocol features |
| `ssh` | [SSHExtractor](ssh.md) | 10+ | SSH/HASSH fingerprinting |
| `dns` | [DNSExtractor](dns.md) | 15+ | DNS query analysis |
| `entropy` | [EntropyExtractor](entropy.md) | 6 | Payload entropy |
| `padding` | [PaddingExtractor](padding.md) | 8 | Padding detection |
| `fingerprint` | [FingerprintExtractor](fingerprint.md) | 6 | Tor/VPN/DoH detection |
| `connection` | [ConnectionExtractor](connection.md) | 20+ | Connection graph metrics |
| `mac` | [MACExtractor](mac.md) | 8 | Layer 2 MAC features |
| `ip_extended` | [IPExtendedExtractor](ip-extended.md) | 12 | Extended IP header fields |
| `ipv6_options` | [IPv6OptionsExtractor](ipv6-options.md) | 8 | IPv6 extension headers |
| `icmp` | [ICMPExtractor](icmp.md) | 10 | ICMP features |
| `tcp_sequence` | [TCPSequenceExtractor](tcp-sequence.md) | 10 | TCP sequence analysis |
| `tcp_window` | [TCPWindowExtractor](tcp-window.md) | 8 | TCP window analysis |
| `tcp_options` | [TCPOptionsExtractor](tcp-options.md) | 12 | TCP options parsing |
| `tcp_mptcp` | [MPTCPExtractor](tcp-mptcp.md) | 6 | Multipath TCP |
| `tcp_rtt` | [TCPRTTExtractor](tcp-rtt.md) | 8 | RTT estimation |
| `tcp_fingerprint` | [TCPFingerprintExtractor](tcp-fingerprint.md) | 4 | TCP fingerprinting |
| `http2` | [HTTP2Extractor](http2.md) | 10+ | HTTP/2 features |

---

## Selecting Features

### All Features (Default)

```python
from joyfuljay import Config, Pipeline

config = Config(features=["all"])  # Default
pipeline = Pipeline(config)
```

### Specific Groups

```python
# Select specific feature groups
config = Config(features=["flow_meta", "timing", "tls", "fingerprint"])
```

### Specific Features

```python
# Select individual features (post-extraction filter)
config = Config(
    features=["all"],
    specific_features=[
        "src_ip", "dst_ip", "duration",
        "ja3_hash", "is_tor", "is_vpn"
    ]
)
```

---

## Feature Categories

### Core Network Features

These extractors analyze basic network properties:

- **Flow Metadata** (`flow_meta`): 5-tuple, duration, packet/byte counts
- **Timing** (`timing`): Inter-arrival times, bursts, SPLT sequences
- **Size** (`size`): Packet lengths, payload sizes, statistics

### Protocol Analysis

Deep protocol inspection for encrypted traffic:

- **TLS** (`tls`): JA3/JA3S fingerprints, cipher suites, SNI, certificate info
- **QUIC** (`quic`): Version, ALPN, connection IDs
- **SSH** (`ssh`): HASSH fingerprints, algorithms
- **DNS** (`dns`): Query types, counts, patterns
- **HTTP/2** (`http2`): Frame types, stream counts, settings

### TCP Analysis

Detailed TCP behavior analysis:

- **TCP Basic** (`tcp`): Flags, handshake, retransmissions
- **TCP Sequence** (`tcp_sequence`): Sequence number patterns
- **TCP Window** (`tcp_window`): Window sizes, scaling
- **TCP Options** (`tcp_options`): MSS, SACK, timestamps
- **TCP RTT** (`tcp_rtt`): Round-trip time estimation
- **TCP MPTCP** (`tcp_mptcp`): Multipath TCP detection
- **TCP Fingerprint** (`tcp_fingerprint`): OS fingerprinting

### Traffic Classification

Pattern detection for traffic classification:

- **Fingerprint** (`fingerprint`): Tor, VPN, DoH detection
- **Entropy** (`entropy`): Payload randomness
- **Padding** (`padding`): Constant-size detection

### Network Topology

Graph-based analysis:

- **Connection** (`connection`): Fan-out, communities, centrality (requires `[graphs]`)

### Layer 2/3 Extended

Additional header fields:

- **MAC** (`mac`): Source/dest MAC, VLAN, Ethernet type
- **IP Extended** (`ip_extended`): TTL, ToS, flags
- **IPv6 Options** (`ipv6_options`): Extension headers
- **ICMP** (`icmp`): Type, code, echo analysis

---

## Feature Naming Convention

Features follow a consistent naming scheme:

```
{prefix}_{metric}[_{direction}]
```

**Examples:**
- `iat_mean` - Mean inter-arrival time
- `pkt_len_std` - Packet length standard deviation
- `tcp_syn_count` - TCP SYN packet count
- `iat_mean_fwd` - Forward direction IAT mean (with `bidirectional_split`)

### Directional Features

When `bidirectional_split=True`, directional features are split:

| Original | Forward | Backward |
|----------|---------|----------|
| `iat_mean` | `iat_mean_fwd` | `iat_mean_bwd` |
| `pkt_len_std` | `pkt_len_std_fwd` | `pkt_len_std_bwd` |
| `total_packets` | `total_packets_fwd` | `total_packets_bwd` |

---

## Feature Types

| Type | Python Type | Description |
|------|-------------|-------------|
| `int` | `int` | Counts, flags |
| `float` | `float` | Statistics, ratios |
| `str` | `str` | Hashes, addresses |
| `list[int]` | `list[int]` | Sequences (e.g., SPLT) |
| `list[float]` | `list[float]` | Raw IAT sequences |
| `bool` | `bool` | Detection flags |

---

## Performance Considerations

### Fast Extractors (No Deep Inspection)

These extractors work without raw payload:
- `flow_meta`, `timing`, `size`, `tcp`, `mac`, `ip_extended`
- `tcp_sequence`, `tcp_window`, `tcp_options`, `tcp_rtt`, `icmp`

### Deep Inspection Required

These extractors need `raw_payload`:
- `tls`, `quic`, `ssh`, `dns`, `entropy`, `http2`

The pipeline automatically enables raw payload capture when these groups are selected.

### Two-Phase Processing

The `connection` extractor requires all flows to be collected before graph analysis. This means:
- Not available in streaming mode
- Uses more memory for large captures

---

## Example: Custom Feature Selection for ML

```python
from joyfuljay import Config, Pipeline

# Features proven effective for traffic classification
config = Config(
    features=["timing", "size", "tls", "fingerprint", "entropy"],
    bidirectional_split=True,  # Separate forward/backward
    include_raw_sequences=True,  # For deep learning
    max_sequence_length=100,
)

pipeline = Pipeline(config)
df = pipeline.process_pcap("capture.pcap")

# Output has ~100 features optimized for ML
print(f"Feature columns: {len(df.columns)}")
print(df.head())
```

---

## See Also

- [Configuration Reference](../configuration.md) - All configuration options
- [Developer Guide](../developer-guide.md) - Creating custom extractors
- [Architecture](../architecture.md) - Extractor framework design
