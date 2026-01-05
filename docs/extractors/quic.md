# QUIC Extractor

The QUIC extractor parses QUIC protocol headers for HTTP/3 and modern transport analysis.

## Feature Group

```python
config = Config(features=["quic"])
```

## Features

### Protocol Detection

| Feature | Type | Description |
|---------|------|-------------|
| `is_quic` | bool | QUIC protocol detected |
| `quic_version` | int\|None | QUIC version number |
| `quic_version_str` | str\|None | Version string (e.g., "v1", "v2") |

### Connection IDs

| Feature | Type | Description |
|---------|------|-------------|
| `quic_dcid_len` | int | Destination Connection ID length |
| `quic_scid_len` | int | Source Connection ID length |
| `quic_dcid` | str\|None | Destination Connection ID (hex) |
| `quic_scid` | str\|None | Source Connection ID (hex) |

### Handshake

| Feature | Type | Description |
|---------|------|-------------|
| `quic_initial_packets` | int | Initial packets count |
| `quic_handshake_packets` | int | Handshake packets count |
| `quic_retry_count` | int | Retry packets |
| `quic_0rtt_packets` | int | 0-RTT packets |

### ALPN (Application Protocol)

| Feature | Type | Description |
|---------|------|-------------|
| `quic_alpn` | list[str]\|None | Application protocols |
| `quic_is_http3` | bool | HTTP/3 detected |

### Packet Analysis

| Feature | Type | Description |
|---------|------|-------------|
| `quic_packet_count` | int | Total QUIC packets |
| `quic_long_header_count` | int | Long header packets |
| `quic_short_header_count` | int | Short header packets |

## QUIC Versions

| Value | Version |
|-------|---------|
| 0x00000001 | QUIC v1 (RFC 9000) |
| 0x6b3343cf | QUIC v2 (RFC 9369) |
| 0xff000000-0xffffffff | Draft versions |

## Example Output

```python
{
    "is_quic": True,
    "quic_version": 1,
    "quic_version_str": "v1",
    "quic_dcid_len": 8,
    "quic_scid_len": 8,
    "quic_initial_packets": 2,
    "quic_handshake_packets": 4,
    "quic_0rtt_packets": 0,
    "quic_alpn": ["h3"],
    "quic_is_http3": True,
    "quic_packet_count": 156,
}
```

## Understanding QUIC

### QUIC vs TCP+TLS

| Aspect | TCP+TLS | QUIC |
|--------|---------|------|
| Transport | TCP (port 443) | UDP (port 443) |
| Encryption | TLS 1.2/1.3 | TLS 1.3 built-in |
| Handshake | 2-3 RTT | 1 RTT (0-RTT possible) |
| Multiplexing | No | Yes (streams) |
| Connection migration | No | Yes |

### QUIC Packet Types

```
Long Header Packets (connection establishment):
- Initial (handshake start)
- 0-RTT (early data)
- Handshake (TLS)
- Retry (server rejection)

Short Header Packets (data transfer):
- 1-RTT (encrypted data)
```

## Use Cases

- **HTTP/3 detection**: Identify QUIC-based web traffic
- **Protocol migration tracking**: TCP to QUIC transitions
- **Performance analysis**: 0-RTT usage, handshake efficiency
- **Connection migration**: Mobile network changes

## Detection Example

```python
import joyfuljay as jj

df = jj.extract("capture.pcap", features=["quic"])

# Find HTTP/3 traffic
http3 = df[df["quic_is_http3"] == True]
print(f"HTTP/3 flows: {len(http3)}")

# Check for 0-RTT usage
zero_rtt = df[df["quic_0rtt_packets"] > 0]
print(f"Flows with 0-RTT: {len(zero_rtt)}")
```

## Related Extractors

- [TLS](tls.md) - TLS features (QUIC uses TLS 1.3 internally)
- [HTTP2](http2.md) - HTTP/2 features
- [Fingerprint](fingerprint.md) - Traffic classification
