# Size Extractor

The Size extractor analyzes packet and payload length distributions, which are key features for traffic classification.

## Feature Group

```python
config = Config(features=["size"])
```

## Features

### Packet Length Statistics

| Feature | Type | Description |
|---------|------|-------------|
| `pkt_len_mean` | float | Mean packet length (bytes) |
| `pkt_len_std` | float | Packet length standard deviation |
| `pkt_len_min` | int | Minimum packet length |
| `pkt_len_max` | int | Maximum packet length |
| `pkt_len_median` | float | Median packet length |
| `pkt_len_mode` | int | Most common packet length |

### Percentiles

| Feature | Type | Description |
|---------|------|-------------|
| `pkt_len_p25` | float | 25th percentile |
| `pkt_len_p75` | float | 75th percentile |
| `pkt_len_p90` | float | 90th percentile |
| `pkt_len_p95` | float | 95th percentile |

### Payload Statistics

| Feature | Type | Description |
|---------|------|-------------|
| `payload_len_mean` | float | Mean payload length |
| `payload_len_std` | float | Payload length standard deviation |
| `payload_len_total` | int | Total payload bytes |
| `payload_ratio` | float | Payload bytes / total bytes |

### Distribution Metrics

| Feature | Type | Description |
|---------|------|-------------|
| `pkt_len_skew` | float | Length distribution skewness |
| `pkt_len_kurtosis` | float | Length distribution kurtosis |
| `pkt_len_cv` | float | Coefficient of variation |

### Directional (with `bidirectional_split`)

| Feature | Type | Description |
|---------|------|-------------|
| `pkt_len_mean_fwd` | float | Forward direction mean |
| `pkt_len_mean_bwd` | float | Backward direction mean |
| `pkt_len_std_fwd` | float | Forward standard deviation |
| `pkt_len_std_bwd` | float | Backward standard deviation |

### Raw Sequences (with `include_raw_sequences`)

| Feature | Type | Description |
|---------|------|-------------|
| `pkt_len_sequence` | list[int] | Raw packet length sequence |
| `pkt_len_sequence_fwd` | list[int] | Forward direction sequence |
| `pkt_len_sequence_bwd` | list[int] | Backward direction sequence |

## Example Output

```python
{
    "pkt_len_mean": 847.3,
    "pkt_len_std": 523.4,
    "pkt_len_min": 52,
    "pkt_len_max": 1500,
    "pkt_len_median": 1024.0,
    "pkt_len_mode": 1500,
    "pkt_len_p95": 1500.0,
    "payload_len_mean": 794.2,
    "payload_len_total": 158840,
    "payload_ratio": 0.89,
}
```

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `max_sequence_length` | 50 | Maximum sequence length |
| `include_raw_sequences` | False | Include raw length sequences |
| `bidirectional_split` | False | Split by direction |

## Understanding Packet Sizes

### MTU and Fragmentation

- **MTU (Maximum Transmission Unit)**: Typically 1500 bytes for Ethernet
- **Max segment size**: 1460 bytes (1500 - 40 byte TCP/IP headers)
- Many full-size packets (1500 bytes) indicate bulk transfer

### Common Patterns

| Pattern | Typical Traffic |
|---------|----------------|
| Bimodal (small + large) | Web browsing, HTTP |
| Mostly large (1400-1500) | File transfer, streaming |
| Mostly small (< 200) | Interactive, VoIP, gaming |
| Fixed size | Padding, Tor cells |

## Use Cases

- **Application identification**: Apps have characteristic size distributions
- **Tor detection**: 512-byte cell sizes
- **VPN detection**: MTU changes from encapsulation
- **QoS classification**: Voice vs video vs data
- **Anomaly detection**: Unusual size patterns

## Related Extractors

- [Timing](timing.md) - IAT statistics
- [Padding](padding.md) - Fixed-size detection
- [Entropy](entropy.md) - Payload analysis
