# Entropy Extractor

The Entropy extractor measures payload randomness to distinguish encrypted, compressed, and plaintext traffic.

## Feature Group

```python
config = Config(features=["entropy"])
```

## Features

| Feature | Type | Description |
|---------|------|-------------|
| `payload_entropy_mean` | float | Mean Shannon entropy (0.0-8.0) |
| `payload_entropy_std` | float | Entropy standard deviation |
| `payload_entropy_min` | float | Minimum packet entropy |
| `payload_entropy_max` | float | Maximum packet entropy |
| `entropy_consistency` | float | How consistent entropy is across packets |
| `high_entropy_ratio` | float | Ratio of packets with entropy > 7.0 |

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `entropy_sample_bytes` | 256 | Bytes to sample per packet |

## Example Output

```python
{
    "payload_entropy_mean": 7.82,
    "payload_entropy_std": 0.15,
    "payload_entropy_min": 7.45,
    "payload_entropy_max": 7.95,
    "entropy_consistency": 0.98,
    "high_entropy_ratio": 1.0,
}
```

## Understanding Entropy

Shannon entropy measures randomness on a scale of 0-8 bits:

| Entropy Range | Traffic Type |
|--------------|--------------|
| 0.0 - 1.0 | Highly repetitive (null bytes, patterns) |
| 1.0 - 4.0 | Text, HTML, plaintext protocols |
| 4.0 - 6.0 | Binary, compressed images |
| 6.0 - 7.0 | Compressed data |
| 7.0 - 8.0 | Encrypted or random data |

### Visual Scale

```
0 -------- 4 -------- 6 ----- 7 ----- 8
    Text     Compressed   Encrypted/Random
```

## Entropy Calculation

```python
from joyfuljay.utils import byte_entropy

# Calculate entropy of payload
entropy = byte_entropy(payload_bytes)  # Returns 0.0-8.0
```

## Use Cases

### Encryption Detection

```python
df = jj.extract("capture.pcap", features=["entropy"])

# Likely encrypted traffic
encrypted = df[df["payload_entropy_mean"] > 7.5]
```

### Plaintext Detection

```python
# Likely plaintext/unencrypted
plaintext = df[df["payload_entropy_mean"] < 5.0]
```

### Malware Analysis

Malware often uses:
- High entropy for encrypted C2
- Low entropy consistency for beacon patterns

```python
# Suspicious: high entropy but inconsistent
suspicious = df[
    (df["payload_entropy_mean"] > 7.0) &
    (df["entropy_consistency"] < 0.8)
]
```

## Entropy Patterns

| Traffic Type | Mean Entropy | Consistency |
|-------------|--------------|-------------|
| HTTPS/TLS | 7.8+ | High |
| Tor | 7.9+ | Very High |
| VPN | 7.5+ | High |
| HTTP | 4.0-6.0 | Medium |
| DNS (plaintext) | 4.0-5.5 | Medium |
| SSH | 7.5+ | High |
| SMTP | 3.0-5.0 | Low |

## Related Extractors

- [TLS](tls.md) - TLS detection
- [Fingerprint](fingerprint.md) - Traffic classification
- [Padding](padding.md) - Padding detection
