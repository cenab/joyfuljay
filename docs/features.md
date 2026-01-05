# Feature Documentation

This document describes all features extracted by JoyfulJay.

## Table of Contents

1. [Feature Groups](#feature-groups)
2. [Flow Metadata](#flow-metadata-flow_meta)
3. [Timing Features](#timing-timing)
4. [Size Features](#size-size)
5. [TLS Features](#tls-tls)
6. [QUIC Features](#quic-quic)
7. [SSH Features](#ssh-ssh)
8. [Padding Features](#padding-padding)
9. [Fingerprint Features](#fingerprint-fingerprint)
10. [Optional Sequence Features](#optional-sequence-features)
11. [Configuration Options](#configuration-options)

---

## Feature Groups

| Group | Description |
|-------|-------------|
| `all` | All feature groups (default) |
| `flow_meta` | Flow identification and statistics |
| `timing` | Inter-arrival time and burst metrics |
| `size` | Packet size statistics |
| `tls` | TLS handshake metadata |
| `quic` | QUIC protocol metadata |
| `ssh` | SSH protocol metadata |
| `padding` | Padding and obfuscation detection |
| `fingerprint` | Traffic type classification |
| `entropy` | Payload entropy analysis |

**Usage:**

```python
from joyfuljay import Config

# Select specific groups
config = Config(features=["tls", "timing", "fingerprint"])
```

```bash
jj extract capture.pcap --features tls --features timing
```

---

## Flow Metadata (`flow_meta`)

Basic flow identification and statistics.

| Feature | Type | Description | Unit |
|---------|------|-------------|------|
| `flow_id` | string | Hashed flow identifier (when `include_flow_id=True`) | - |
| `src_ip` | string | Source IP (flow initiator) | - |
| `dst_ip` | string | Destination IP (responder) | - |
| `src_port` | int | Source port number | - |
| `dst_port` | int | Destination port number | - |
| `protocol` | int | IP protocol (6=TCP, 17=UDP) | - |
| `start_time` | float | Flow start timestamp | Unix epoch |
| `end_time` | float | Flow end timestamp | Unix epoch |
| `duration` | float | Flow duration | seconds |
| `total_packets` | int | Total packets both directions | count |
| `packets_fwd` | int | Packets from initiator | count |
| `packets_bwd` | int | Packets from responder | count |
| `total_bytes` | int | Total bytes both directions | bytes |
| `bytes_fwd` | int | Bytes from initiator | bytes |
| `bytes_bwd` | int | Bytes from responder | bytes |
| `payload_bytes_fwd` | int | Payload bytes from initiator | bytes |
| `payload_bytes_bwd` | int | Payload bytes from responder | bytes |
| `payload_bytes_total` | int | Total payload bytes | bytes |
| `packets_ratio` | float | Forward/backward packet ratio | - |
| `bytes_ratio` | float | Forward/backward byte ratio | - |
| `packets_per_second` | float | Average packet rate | pps |
| `bytes_per_second` | float | Average byte rate | Bps |
| `avg_packet_size` | float | Mean packet size | bytes |

### Privacy Options

| Option | Effect |
|--------|--------|
| `include_ip_addresses=False` | Exclude `src_ip` and `dst_ip` |
| `include_ports=False` | Exclude `src_port` and `dst_port` |
| `anonymize_ips=True` | Hash IP addresses (SHA-256, truncated) |
| `anonymization_salt="..."` | Salt for reproducible hashing |
| `include_flow_id=True` | Add hashed 5-tuple identifier |

---

## Timing (`timing`)

Inter-arrival time and burst metrics.

### Overall IAT Statistics

| Feature | Type | Description | Unit |
|---------|------|-------------|------|
| `iat_min` | float | Minimum inter-arrival time | seconds |
| `iat_max` | float | Maximum inter-arrival time | seconds |
| `iat_mean` | float | Mean inter-arrival time | seconds |
| `iat_std` | float | IAT standard deviation | seconds |
| `iat_median` | float | Median inter-arrival time | seconds |
| `iat_sum` | float | Sum of all IATs | seconds |
| `iat_p25` | float | 25th percentile IAT | seconds |
| `iat_p75` | float | 75th percentile IAT | seconds |
| `iat_p90` | float | 90th percentile IAT | seconds |
| `iat_p99` | float | 99th percentile IAT | seconds |

### Directional IAT Statistics

| Feature | Type | Description | Unit |
|---------|------|-------------|------|
| `iat_fwd_min` | float | Min IAT (forward direction) | seconds |
| `iat_fwd_max` | float | Max IAT (forward) | seconds |
| `iat_fwd_mean` | float | Mean IAT (forward) | seconds |
| `iat_fwd_std` | float | Std dev IAT (forward) | seconds |
| `iat_fwd_median` | float | Median IAT (forward) | seconds |
| `iat_bwd_min` | float | Min IAT (backward direction) | seconds |
| `iat_bwd_max` | float | Max IAT (backward) | seconds |
| `iat_bwd_mean` | float | Mean IAT (backward) | seconds |
| `iat_bwd_std` | float | Std dev IAT (backward) | seconds |
| `iat_bwd_median` | float | Median IAT (backward) | seconds |

### Burstiness Metrics

| Feature | Type | Description | Unit |
|---------|------|-------------|------|
| `burstiness_index` | float | Coefficient of variation of IAT | - |
| `burstiness_index_fwd` | float | Burstiness (forward direction) | - |
| `burstiness_index_bwd` | float | Burstiness (backward direction) | - |
| `burst_count` | int | Number of packet bursts | count |
| `avg_burst_packets` | float | Average packets per burst | count |
| `avg_burst_duration` | float | Average burst duration | seconds |
| `max_burst_packets` | int | Maximum packets in a burst | count |
| `idle_count` | int | Number of idle periods | count |
| `avg_idle_duration` | float | Average idle period | seconds |
| `max_idle_duration` | float | Maximum idle duration | seconds |
| `first_response_time` | float | Time to first response | seconds |

**Burst threshold:** Configurable via `burst_threshold_ms` (default: 50ms)

---

## Size (`size`)

Packet size and payload statistics.

### Overall Size Statistics

| Feature | Type | Description | Unit |
|---------|------|-------------|------|
| `pkt_len_min` | int | Minimum packet length | bytes |
| `pkt_len_max` | int | Maximum packet length | bytes |
| `pkt_len_mean` | float | Mean packet length | bytes |
| `pkt_len_std` | float | Packet length std dev | bytes |
| `pkt_len_median` | float | Median packet length | bytes |

### Directional Size Statistics

| Feature | Type | Description | Unit |
|---------|------|-------------|------|
| `pkt_len_fwd_min` | int | Min length (forward) | bytes |
| `pkt_len_fwd_max` | int | Max length (forward) | bytes |
| `pkt_len_fwd_mean` | float | Mean length (forward) | bytes |
| `pkt_len_fwd_std` | float | Std dev (forward) | bytes |
| `pkt_len_fwd_median` | float | Median (forward) | bytes |
| `pkt_len_bwd_min` | int | Min length (backward) | bytes |
| `pkt_len_bwd_max` | int | Max length (backward) | bytes |
| `pkt_len_bwd_mean` | float | Mean length (backward) | bytes |
| `pkt_len_bwd_std` | float | Std dev (backward) | bytes |
| `pkt_len_bwd_median` | float | Median (backward) | bytes |

---

## TLS (`tls`)

TLS handshake metadata and fingerprinting.

### Basic TLS Information

| Feature | Type | Description | Unit |
|---------|------|-------------|------|
| `tls_detected` | bool | Whether TLS was detected | - |
| `tls_version` | int | TLS version number | - |
| `tls_version_str` | string | TLS version string (e.g., "TLS 1.3") | - |
| `tls_cipher_suite` | int | Selected cipher suite | - |
| `tls_cipher_count` | int | Number of offered ciphers | count |
| `tls_extension_count` | int | Number of TLS extensions | count |
| `tls_sni` | string | Server Name Indication | - |
| `tls_alpn` | string | Application Layer Protocol | - |
| `tls_handshake_packets` | int | Handshake packet count | count |

### TLS Fingerprinting

| Feature | Type | Description | Unit |
|---------|------|-------------|------|
| `ja3_hash` | string | JA3 client fingerprint (MD5) | - |
| `ja3s_hash` | string | JA3S server fingerprint (MD5) | - |

### Certificate Metadata

| Feature | Type | Description | Unit |
|---------|------|-------------|------|
| `tls_cert_count` | int | Certificates in chain | count |
| `tls_cert_total_length` | int | Total certificate bytes | bytes |
| `tls_cert_first_length` | int | First certificate size | bytes |
| `tls_cert_chain_length` | int | Certificate chain depth | count |

### Session Resumption Detection

| Feature | Type | Description | Unit |
|---------|------|-------------|------|
| `tls_session_id_len` | int | Session ID length | bytes |
| `tls_session_ticket_ext` | bool | Session ticket extension present | - |
| `tls_session_resumed` | bool | Session resumption detected | - |
| `tls_psk_ext` | bool | Pre-shared key extension (TLS 1.3) | - |
| `tls_early_data_ext` | bool | Early data extension (0-RTT) | - |

---

## QUIC (`quic`)

QUIC protocol metadata.

| Feature | Type | Description | Unit |
|---------|------|-------------|------|
| `quic_detected` | bool | Whether QUIC was detected | - |
| `quic_version` | int | QUIC version number | - |
| `quic_version_str` | string | QUIC version string | - |
| `quic_dcid_len` | int | Destination Connection ID length | bytes |
| `quic_scid_len` | int | Source Connection ID length | bytes |
| `quic_initial_packets` | int | Number of Initial packets | count |
| `quic_0rtt_detected` | bool | 0-RTT usage detected | - |
| `quic_retry_detected` | bool | Retry packet detected | - |
| `quic_alpn` | string | Application Layer Protocol (e.g., "h3") | - |
| `quic_sni` | string | Server Name Indication | - |

---

## SSH (`ssh`)

SSH protocol metadata and fingerprinting.

### Basic SSH Information

| Feature | Type | Description | Unit |
|---------|------|-------------|------|
| `ssh_detected` | bool | Whether SSH was detected | - |
| `ssh_version` | string | SSH protocol version (e.g., "2.0") | - |
| `ssh_client_software` | string | Client software name | - |
| `ssh_server_software` | string | Server software name | - |
| `ssh_client_version` | string | Client SSH version | - |
| `ssh_server_version` | string | Server SSH version | - |

### SSH Fingerprinting (HASSH)

| Feature | Type | Description | Unit |
|---------|------|-------------|------|
| `ssh_hassh` | string | HASSH client fingerprint (MD5) | - |
| `ssh_hassh_server` | string | HASSH server fingerprint (MD5) | - |

### SSH Traffic Metrics

| Feature | Type | Description | Unit |
|---------|------|-------------|------|
| `ssh_kex_packets` | int | Key exchange packet count | count |
| `ssh_encrypted_packets` | int | Encrypted packet count | count |

---

## Padding (`padding`)

Padding and obfuscation detection.

### Size Distribution

| Feature | Type | Description | Unit |
|---------|------|-------------|------|
| `pkt_size_variance` | float | Packet size variance | bytes² |
| `pkt_size_cv` | float | Size coefficient of variation | - |
| `is_constant_size` | bool | Constant packet size detected | - |
| `dominant_size_mode` | int | Most common packet size | bytes |
| `dominant_pkt_size` | int | Dominant size value | bytes |
| `dominant_size_ratio` | float | Ratio of dominant size | - |
| `dominant_pkt_ratio` | float | Ratio of dominant packets | - |
| `size_entropy` | float | Entropy of size distribution | bits |
| `unique_size_count` | int | Number of unique sizes | count |

### Rate Detection

| Feature | Type | Description | Unit |
|---------|------|-------------|------|
| `is_constant_rate` | bool | Constant packet rate detected | - |

### Tor Detection

| Feature | Type | Description | Unit |
|---------|------|-------------|------|
| `tor_cell_count` | int | Packets matching Tor cell size (~586 bytes) | count |
| `tor_cell_ratio` | float | Ratio of Tor-like packets | - |
| `is_tor_like` | bool | Traffic resembles Tor | - |

### Padding Score

| Feature | Type | Description | Unit |
|---------|------|-------------|------|
| `padding_score` | float | Overall padding likelihood | 0-1 |

---

## Fingerprint (`fingerprint`)

Traffic type classification.

### Tor Detection

| Feature | Type | Description | Unit |
|---------|------|-------------|------|
| `likely_tor` | bool | Probably Tor traffic | - |
| `tor_confidence` | float | Tor detection confidence | 0-1 |

### VPN Detection

| Feature | Type | Description | Unit |
|---------|------|-------------|------|
| `likely_vpn` | bool | Probably VPN traffic | - |
| `vpn_confidence` | float | VPN detection confidence | 0-1 |
| `vpn_type` | string | Detected VPN type (openvpn, wireguard, ipsec, l2tp) | - |

### DoH Detection

| Feature | Type | Description | Unit |
|---------|------|-------------|------|
| `likely_doh` | bool | Probably DNS over HTTPS | - |
| `doh_confidence` | float | DoH detection confidence | 0-1 |

### Overall Classification

| Feature | Type | Description | Unit |
|---------|------|-------------|------|
| `traffic_type` | string | Overall traffic classification | - |

---

## Optional Sequence Features

### IAT Sequence

When `include_raw_sequences=True`:

| Feature | Type | Description |
|---------|------|-------------|
| `iat_sequence` | list[float] | First N inter-arrival times (padded to `max_sequence_length`) |
| `pkt_len_sequence` | list[int] | First N packet sizes (signed by direction: + for fwd, - for bwd) |

### SPLT Encoding

When `include_splt=True`:

SPLT (Sequence of Packet Lengths and Times) is a standard ML-ready encoding that combines packet lengths, inter-arrival times, and direction information.

| Feature | Type | Description |
|---------|------|-------------|
| `splt` | list[tuple] | List of (length, time, direction) tuples |
| `splt_lengths` | list[int] | Packet lengths from SPLT |
| `splt_times` | list[float] | Inter-arrival times from SPLT |
| `splt_directions` | list[int] | Directions from SPLT (1=forward, -1=backward) |

**SPLT Format:**

Each packet is encoded as a tuple: `(packet_length, inter_arrival_time, direction)`

- `packet_length`: Total packet size in bytes
- `inter_arrival_time`: Time since previous packet (0 for first packet)
- `direction`: 1 for forward (client→server), -1 for backward (server→client)

**Example:**

```python
config = Config(include_splt=True, max_sequence_length=100)
df = extract_features_from_pcap("capture.pcap", config=config)

for _, row in df.iterrows():
    splt = row["splt"]
    # [(1500, 0.0, 1), (60, 0.001, -1), (1500, 0.002, 1), ...]
```

---

## Configuration Options

### Config Reference

```python
from joyfuljay import Config

config = Config(
    # Flow Management
    flow_timeout=60.0,              # Inactivity timeout (seconds)

    # Feature Selection
    features=["all"],               # Feature groups to extract

    # Sequence Features
    include_raw_sequences=False,    # Include IAT and size sequences
    include_splt=False,             # Include SPLT encoding
    max_sequence_length=50,         # Maximum sequence length

    # Capture Options
    bpf_filter=None,                # BPF filter expression

    # Privacy Options
    include_ip_addresses=True,      # Include IPs in output
    include_ports=True,             # Include ports in output
    anonymize_ips=False,            # Hash IP addresses
    anonymization_salt="",          # Salt for IP hashing
    include_flow_id=False,          # Include hashed flow ID

    # Processing Options
    burst_threshold_ms=50.0,        # Burst detection threshold
    entropy_sample_bytes=256,       # Bytes for entropy calculation
    num_workers=1,                  # Parallel workers for batch processing
)
```

### Configuration File Support

JoyfulJay supports YAML and JSON configuration files:

**config.yaml:**
```yaml
flow_timeout: 30.0
features:
  - tls
  - timing
  - fingerprint
include_splt: true
max_sequence_length: 100
anonymize_ips: true
num_workers: 4
```

**Loading:**
```python
config = Config.from_file("config.yaml")
```

```bash
jj extract capture.pcap -c config.yaml
```

---

## Feature Count Summary

| Category | Features |
|----------|----------|
| Flow Metadata | 22 |
| Timing | 35 |
| Size | 15 |
| TLS | 20 |
| QUIC | 10 |
| SSH | 10 |
| Padding | 14 |
| Fingerprint | 8 |
| **Total** | **134+** |

*Note: Some features are optional and depend on configuration settings.*

---

*Documentation for JoyfulJay v0.2.0*
