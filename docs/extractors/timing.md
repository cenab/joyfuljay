# Timing Extractor

The Timing extractor analyzes inter-arrival time (IAT) patterns in network flows, which are crucial features for encrypted traffic classification.

## Feature Group

```python
config = Config(features=["timing"])
```

## Features

### Basic Statistics

| Feature | Type | Description |
|---------|------|-------------|
| `iat_mean` | float | Mean inter-arrival time (seconds) |
| `iat_std` | float | IAT standard deviation |
| `iat_min` | float | Minimum IAT |
| `iat_max` | float | Maximum IAT |
| `iat_median` | float | Median IAT |

### Percentiles

| Feature | Type | Description |
|---------|------|-------------|
| `iat_p25` | float | 25th percentile IAT |
| `iat_p75` | float | 75th percentile IAT |
| `iat_p90` | float | 90th percentile IAT |
| `iat_p95` | float | 95th percentile IAT |

### Derived Metrics

| Feature | Type | Description |
|---------|------|-------------|
| `iat_skew` | float | IAT distribution skewness |
| `iat_kurtosis` | float | IAT distribution kurtosis |
| `iat_cv` | float | Coefficient of variation (std/mean) |

### Burst Analysis

| Feature | Type | Description |
|---------|------|-------------|
| `burst_count` | int | Number of packet bursts |
| `burst_mean_size` | float | Mean packets per burst |
| `burst_mean_duration` | float | Mean burst duration (seconds) |
| `inter_burst_gap_mean` | float | Mean time between bursts |

### Directional (with `bidirectional_split`)

| Feature | Type | Description |
|---------|------|-------------|
| `iat_mean_fwd` | float | Forward direction IAT mean |
| `iat_mean_bwd` | float | Backward direction IAT mean |
| `iat_std_fwd` | float | Forward IAT standard deviation |
| `iat_std_bwd` | float | Backward IAT standard deviation |

### Raw Sequences (with `include_raw_sequences`)

| Feature | Type | Description |
|---------|------|-------------|
| `iat_sequence` | list[float] | Raw IAT sequence |
| `iat_sequence_fwd` | list[float] | Forward IAT sequence |
| `iat_sequence_bwd` | list[float] | Backward IAT sequence |

### SPLT (with `include_splt`)

| Feature | Type | Description |
|---------|------|-------------|
| `splt` | list[tuple] | Sequence of (size, iat) pairs |

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `burst_threshold_ms` | 50.0 | Minimum gap to define burst boundary |
| `max_sequence_length` | 50 | Maximum sequence length |
| `include_raw_sequences` | False | Include raw IAT sequences |
| `include_splt` | False | Include SPLT data |
| `bidirectional_split` | False | Split by direction |

## Example Output

```python
{
    "iat_mean": 0.0234,
    "iat_std": 0.0156,
    "iat_min": 0.0001,
    "iat_max": 0.2341,
    "iat_median": 0.0189,
    "iat_p95": 0.0567,
    "iat_skew": 2.341,
    "iat_kurtosis": 8.567,
    "burst_count": 5,
    "burst_mean_size": 8.4,
}
```

## Understanding Burst Analysis

Bursts are detected by identifying gaps larger than `burst_threshold_ms`:

```
Packets:  ●●●●●   ●●●   ●●●●●●●●
Time:     |-----|---|---|--------|
          burst1 gap burst2 gap burst3
```

**Burst threshold tuning:**
- 10ms: Sensitive, detects micro-bursts
- 50ms: Balanced (default)
- 100ms: Coarse, only major activity gaps

## Use Cases

- **VPN Detection**: VPN traffic often shows regular IAT patterns
- **Tor Detection**: Tor has distinctive timing due to circuit delays
- **Application Fingerprinting**: Different apps have unique timing signatures
- **QoS Analysis**: Jitter and delay measurement

## SPLT for Deep Learning

Sequence of Packet Lengths and Times (SPLT) captures temporal patterns:

```python
config = Config(
    features=["timing", "size"],
    include_splt=True,
    max_sequence_length=100,
)

# Output:
# "splt": [(1500, 0.001), (52, 0.002), (1500, 0.015), ...]
```

This format is ideal for RNN/LSTM/Transformer models.

## Related Extractors

- [Size](size.md) - Packet size statistics
- [Fingerprint](fingerprint.md) - Traffic classification
- [Entropy](entropy.md) - Payload analysis
