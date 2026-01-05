# Flow Metadata Extractor

The Flow Metadata extractor (`FlowMetaExtractor`) provides **fundamental flow identification and statistics**. These features form the foundation for understanding any network connection and are essential for flow tracking, traffic analysis, and ML feature engineering.

---

## Quick Start

```python
import joyfuljay as jj

# Extract flow metadata
df = jj.extract("capture.pcap", features=["flow_meta"])

# With privacy settings
config = jj.Config(
    features=["flow_meta"],
    anonymize_ips=True,
    include_flow_id=True,
)
df = jj.Pipeline(config).process_pcap("capture.pcap")
```

```bash
# CLI usage
jj extract capture.pcap --features flow_meta -o flows.csv
```

---

## Understanding Flows

A **flow** represents a bidirectional network conversation identified by the **5-tuple**:

1. Source IP address
2. Destination IP address
3. Source port
4. Destination port
5. Protocol (TCP/UDP/ICMP)

### Initiator vs Responder

- **Initiator** (src): The endpoint that sent the first packet - typically the client
- **Responder** (dst): The endpoint that received the first packet - typically the server

This assignment is based on who sends the first observed packet, which may not always be the TCP SYN (e.g., if capture started mid-connection).

---

## Features

### Identification Features

| Feature | Type | Description |
|---------|------|-------------|
| `flow_id` | str | **Unique 32-character hash** of the 5-tuple. Useful for cross-referencing flows without exposing raw addresses. Requires `include_flow_id=True`. |
| `src_ip` | str | **Source IP address** (flow initiator). IPv4 or IPv6 format. |
| `dst_ip` | str | **Destination IP address** (flow responder). |
| `src_port` | int | **Source port** (ephemeral port, typically high-numbered). |
| `dst_port` | int | **Destination port** (service port: 443=HTTPS, 80=HTTP, 22=SSH). |
| `dst_port_class` | str | **Service classification**: `"well_known"` (0-1023), `"registered"` (1024-49151), `"dynamic"` (49152-65535). |
| `dst_port_class_num` | int | **Numeric classification**: 0=well_known, 1=registered, 2=dynamic. |
| `protocol` | int | **IP protocol number**: 6=TCP, 17=UDP, 1=ICMP, 50=ESP, 51=AH. |

### Timing Features

| Feature | Type | Description |
|---------|------|-------------|
| `start_time` | float | **Unix timestamp** of the first packet. |
| `end_time` | float | **Unix timestamp** of the last packet. |
| `duration` | float | **Flow duration** in seconds. |
| `time_first` | float | Alias for `start_time` (Tranalyzer compatibility). |
| `time_last` | float | Alias for `end_time` (Tranalyzer compatibility). |

### Packet Count Features

| Feature | Type | Description |
|---------|------|-------------|
| `total_packets` | int | **Total packets** in both directions. |
| `packets_fwd` | int | **Forward packets** (initiator to responder). |
| `packets_bwd` | int | **Backward packets** (responder to initiator). |
| `packets_ratio` | float | **Ratio** `packets_fwd / packets_bwd`. Values >1 = client-heavy, <1 = server-heavy. |

### Byte Count Features

| Feature | Type | Description |
|---------|------|-------------|
| `total_bytes` | int | **Total bytes** including all headers. |
| `bytes_fwd` | int | **Forward bytes** (includes headers). |
| `bytes_bwd` | int | **Backward bytes** (includes headers). |
| `payload_bytes_fwd` | int | **Forward payload** (application data only). |
| `payload_bytes_bwd` | int | **Backward payload** (application data only). |
| `payload_bytes_total` | int | **Total payload** (application data only). |
| `bytes_ratio` | float | **Ratio** `bytes_fwd / bytes_bwd`. |

### Rate Features

| Feature | Type | Description |
|---------|------|-------------|
| `packets_per_second` | float | **Average packet rate** (pps). |
| `bytes_per_second` | float | **Average throughput** (Bps). |
| `avg_packet_size` | float | **Mean packet size** in bytes. |

### Protocol Stack Features (Tranalyzer-compatible)

| Feature | Type | Description |
|---------|------|-------------|
| `flow_stat` | int | **TCP state bitmap**: bit 0=SYN, 1=SYN-ACK, 2=FIN fwd, 3=FIN bwd, 4=RST, 6=proper termination. |
| `num_hdrs` | int | **Protocol layer count** (typically 2-3). |
| `hdr_desc` | str | **Protocol stack** string: "ETH-IP-TCP", "ETH-IP6-UDP", etc. |

---

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `include_ip_addresses` | bool | `True` | Include `src_ip` and `dst_ip` in output. |
| `include_ports` | bool | `True` | Include `src_port` and `dst_port` in output. |
| `anonymize_ips` | bool | `False` | Hash IP addresses with SHA-256 (truncated to 16 chars). |
| `anonymization_salt` | str | `""` | Salt for reproducible IP hashing. |
| `include_flow_id` | bool | `False` | Include 32-char hashed `flow_id`. |

---

## Usage Examples

### Basic Flow Statistics

```python
import joyfuljay as jj

df = jj.extract("capture.pcap", features=["flow_meta"])

# Top talkers by bytes
top_senders = df.groupby("src_ip")["bytes_fwd"].sum().nlargest(10)
print("Top 10 senders:")
print(top_senders)

# Protocol distribution
protocol_counts = df["protocol"].value_counts()
protocol_names = {6: "TCP", 17: "UDP", 1: "ICMP"}
print("Protocol distribution:")
print(protocol_counts.rename(protocol_names))
```

### Privacy-Preserving Analysis

```python
import joyfuljay as jj

# Anonymize IPs for research sharing
config = jj.Config(
    features=["flow_meta", "timing", "size"],
    anonymize_ips=True,
    anonymization_salt="research-project-2025",
)
df = jj.Pipeline(config).process_pcap("capture.pcap")

# IPs are now SHA-256 hashes
print(df["src_ip"].head())
# 5f4dcc3b5aa765d6
# 8d969eef6ecad3c2
# ...
```

### Exclude Identifiers for ML

```python
import joyfuljay as jj

# Remove IPs and ports for ML training
config = jj.Config(
    features=["flow_meta"],
    include_ip_addresses=False,
    include_ports=False,
)
df = jj.Pipeline(config).process_pcap("capture.pcap")

# Only numeric features remain
print(df.columns.tolist())
# ['protocol', 'start_time', 'duration', 'total_packets', ...]
```

### Flow Linking with flow_id

```python
import joyfuljay as jj

# Use flow_id to link flows across captures
config = jj.Config(
    features=["flow_meta"],
    include_flow_id=True,
    anonymization_salt="consistent-salt",
)

df1 = jj.Pipeline(config).process_pcap("capture1.pcap")
df2 = jj.Pipeline(config).process_pcap("capture2.pcap")

# Find flows that appear in both captures
common_flows = df1[df1["flow_id"].isin(df2["flow_id"])]
print(f"Found {len(common_flows)} common flows")
```

---

## Example Output

```python
{
    "flow_id": "a3f2b1c4d5e6f7890123456789abcdef",
    "src_ip": "192.168.1.100",
    "dst_ip": "142.250.189.46",
    "src_port": 52341,
    "dst_port": 443,
    "dst_port_class": "well_known",
    "dst_port_class_num": 0,
    "protocol": 6,
    "start_time": 1704067200.123456,
    "end_time": 1704067202.789012,
    "duration": 2.665556,
    "total_packets": 45,
    "packets_fwd": 22,
    "packets_bwd": 23,
    "total_bytes": 12500,
    "bytes_fwd": 3200,
    "bytes_bwd": 9300,
    "payload_bytes_fwd": 2800,
    "payload_bytes_bwd": 8900,
    "payload_bytes_total": 11700,
    "packets_ratio": 0.957,
    "bytes_ratio": 0.344,
    "packets_per_second": 16.89,
    "bytes_per_second": 4690.38,
    "avg_packet_size": 277.78,
    "time_first": 1704067200.123456,
    "time_last": 1704067202.789012,
    "flow_stat": 67,  # 0x43 = complete TCP connection
    "num_hdrs": 3,
    "hdr_desc": "ETH-IP-TCP",
}
```

---

## Understanding flow_stat

The `flow_stat` bitmap encodes TCP connection state:

| Bit | Value | Meaning |
|-----|-------|---------|
| 0 | 0x01 | SYN seen from initiator |
| 1 | 0x02 | SYN-ACK seen from responder |
| 2 | 0x04 | FIN seen from initiator |
| 3 | 0x08 | FIN seen from responder |
| 4 | 0x10 | RST seen |
| 6 | 0x40 | Proper termination (FIN-FIN or RST after handshake) |

**Common values:**
- `0x43` (67): Complete TCP connection (SYN + SYN-ACK + proper close)
- `0x11` (17): Connection refused (SYN + RST)
- `0x03` (3): Incomplete handshake (SYN + SYN-ACK only)

---

## Use Cases

### Traffic Volume Analysis
Identify top talkers, bandwidth hogs, and traffic patterns.

### Flow Fingerprinting
Combine `flow_id` with other features for persistent flow tracking.

### Protocol Distribution
Analyze TCP vs UDP vs ICMP traffic mix.

### Privacy-Preserving Research
Share datasets with anonymized IPs while maintaining flow integrity.

### ML Feature Engineering
Use packet/byte counts and ratios as baseline ML features.

---

## Related Extractors

- [Timing](timing.md) - Inter-arrival times and burst metrics
- [Size](size.md) - Packet size distributions
- [TCP](tcp.md) - TCP flag analysis and connection state
- [Connection](connection.md) - Graph-based flow relationships
