# Padding Extractor

The Padding extractor detects traffic shaping and padding patterns that indicate privacy tools or constant-rate protocols.

## Feature Group

```python
config = Config(features=["padding"])
```

## Features

### Fixed Size Detection

| Feature | Type | Description |
|---------|------|-------------|
| `fixed_size_ratio` | float | Ratio of packets with fixed sizes |
| `fixed_size_count` | int | Count of most common size |
| `fixed_size_value` | int | Most common packet size |
| `size_variance_ratio` | float | Packet size variance ratio |

### Constant Rate Detection

| Feature | Type | Description |
|---------|------|-------------|
| `constant_rate_score` | float | How constant the packet rate is |
| `iat_regularity` | float | Inter-arrival time regularity |
| `burst_uniformity` | float | Uniformity of burst patterns |

### Padding Indicators

| Feature | Type | Description |
|---------|------|-------------|
| `likely_padded` | bool | Traffic appears padded |
| `padding_pattern` | str\|None | Detected padding type |
| `chaff_score` | float | Likelihood of chaff traffic |

## Example Output

```python
{
    "fixed_size_ratio": 0.95,
    "fixed_size_count": 142,
    "fixed_size_value": 512,
    "size_variance_ratio": 0.02,
    "constant_rate_score": 0.88,
    "iat_regularity": 0.92,
    "likely_padded": True,
    "padding_pattern": "tor_cell",
}
```

## Understanding Padding

### Why Padding Matters

Traffic padding obscures:
- Actual message sizes
- Activity patterns
- Content type inference

### Common Padding Patterns

| Pattern | Size | Protocol |
|---------|------|----------|
| Tor cells | 512 bytes | Tor |
| DTLS records | Variable, aligned | WebRTC |
| QUIC frames | Coalesced | HTTP/3 |
| TLS records | Up to 16KB | HTTPS |

## Detection Patterns

### Tor Traffic

```python
# Tor uses fixed 512-byte cells
if fixed_size_value in range(510, 520) and fixed_size_ratio > 0.8:
    likely_tor = True
```

### VPN Traffic

```python
# VPNs often have MTU-based fixed sizes
if fixed_size_value in [1400, 1420, 1480] and fixed_size_ratio > 0.5:
    likely_vpn_tunnel = True
```

### Constant-Rate Streams

```python
# Voice/video with CBR codec
if constant_rate_score > 0.9 and iat_regularity > 0.85:
    likely_cbr_stream = True
```

## Use Cases

- **Tor detection**: 512-byte cell pattern
- **VPN detection**: MTU-related fixed sizes
- **Privacy tool detection**: Traffic shaping
- **Protocol identification**: CBR vs VBR codecs

## Detection Example

```python
import joyfuljay as jj

df = jj.extract("capture.pcap", features=["padding", "fingerprint"])

# Find padded traffic
padded = df[df["likely_padded"] == True]
print(f"Padded traffic flows: {len(padded)}")

# Check padding patterns
patterns = padded["padding_pattern"].value_counts()
print("Padding patterns:")
print(patterns)

# Correlate with fingerprint detection
tor_confirmed = df[
    (df["likely_padded"] == True) &
    (df["fixed_size_value"].between(510, 520)) &
    (df["likely_tor"] == True)
]
print(f"Confirmed Tor flows: {len(tor_confirmed)}")
```

## Padding Bypass Considerations

Padding detection has limitations:

| Factor | Impact |
|--------|--------|
| Coalescing | Multiple messages in one packet |
| Fragmentation | Messages split across packets |
| Variable padding | Random pad lengths |
| Timing noise | Jitter obscures patterns |

## Related Extractors

- [Fingerprint](fingerprint.md) - Tor/VPN detection
- [Size](size.md) - Packet size statistics
- [Timing](timing.md) - IAT analysis
- [Entropy](entropy.md) - Payload randomness
