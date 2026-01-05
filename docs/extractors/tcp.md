# TCP Extractor

The TCP extractor analyzes TCP header fields, flags, and connection behavior for detailed protocol analysis.

## Feature Group

```python
config = Config(features=["tcp"])
```

## Features

### Flag Counts

| Feature | Type | Description |
|---------|------|-------------|
| `tcp_syn_count` | int | SYN packets |
| `tcp_ack_count` | int | ACK packets |
| `tcp_fin_count` | int | FIN packets |
| `tcp_rst_count` | int | RST packets |
| `tcp_psh_count` | int | PSH packets |
| `tcp_urg_count` | int | URG packets |
| `tcp_ece_count` | int | ECE packets (ECN) |
| `tcp_cwr_count` | int | CWR packets (ECN) |

### Flag Ratios

| Feature | Type | Description |
|---------|------|-------------|
| `tcp_syn_ratio` | float | SYN packets / total |
| `tcp_ack_ratio` | float | ACK packets / total |
| `tcp_fin_ratio` | float | FIN packets / total |
| `tcp_rst_ratio` | float | RST packets / total |
| `tcp_psh_ratio` | float | PSH packets / total |

### Connection State

| Feature | Type | Description |
|---------|------|-------------|
| `tcp_handshake_complete` | bool | 3-way handshake completed |
| `tcp_connection_terminated` | bool | Graceful close (FIN) |
| `tcp_connection_reset` | bool | Connection reset (RST) |
| `tcp_initial_window` | int | Initial window size |

### Retransmission Analysis

| Feature | Type | Description |
|---------|------|-------------|
| `tcp_retrans_count` | int | Detected retransmissions |
| `tcp_retrans_ratio` | float | Retransmissions / total |
| `tcp_out_of_order` | int | Out-of-order packets |
| `tcp_dup_ack_count` | int | Duplicate ACKs |

### Directional

| Feature | Type | Description |
|---------|------|-------------|
| `tcp_syn_count_fwd` | int | Forward SYN count |
| `tcp_syn_count_bwd` | int | Backward SYN count |
| `tcp_psh_count_fwd` | int | Forward PSH count |
| `tcp_psh_count_bwd` | int | Backward PSH count |

## TCP Flags Reference

| Flag | Hex | Purpose |
|------|-----|---------|
| FIN | 0x01 | Finish (close connection) |
| SYN | 0x02 | Synchronize (open connection) |
| RST | 0x04 | Reset (abort connection) |
| PSH | 0x08 | Push (deliver immediately) |
| ACK | 0x10 | Acknowledgment |
| URG | 0x20 | Urgent |
| ECE | 0x40 | ECN Echo |
| CWR | 0x80 | Congestion Window Reduced |

## Example Output

```python
{
    "tcp_syn_count": 1,
    "tcp_ack_count": 45,
    "tcp_fin_count": 2,
    "tcp_rst_count": 0,
    "tcp_psh_count": 12,
    "tcp_syn_ratio": 0.02,
    "tcp_psh_ratio": 0.26,
    "tcp_handshake_complete": True,
    "tcp_connection_terminated": True,
    "tcp_connection_reset": False,
    "tcp_initial_window": 65535,
    "tcp_retrans_count": 0,
}
```

## Understanding TCP Behavior

### Normal Connection

```
Client                Server
  |-------- SYN -------->|
  |<----- SYN+ACK -------|
  |-------- ACK -------->|
  |                      |
  |<===== Data =========>|
  |                      |
  |-------- FIN -------->|
  |<----- FIN+ACK -------|
  |-------- ACK -------->|
```

### Reset Connection

```
Client                Server
  |-------- SYN -------->|
  |<------- RST ---------|
```

### Retransmission Indicators

High retransmission ratio indicates:
- Network congestion
- Packet loss
- Potential attack (SYN flood)

## Use Cases

- **Connection health**: Track handshakes, resets, retransmissions
- **Attack detection**: SYN floods, RST attacks
- **Application behavior**: PSH patterns indicate interactivity
- **Network quality**: Retransmission rates

## Related Extractors

- [TCP Sequence](tcp-sequence.md) - Sequence number analysis
- [TCP Window](tcp-window.md) - Window size analysis
- [TCP Options](tcp-options.md) - Options parsing
- [TCP RTT](tcp-rtt.md) - Round-trip time estimation
- [TCP Fingerprint](tcp-fingerprint.md) - OS fingerprinting
