# Flow Metadata Extractor

The Flow Metadata extractor provides basic flow identification and aggregate statistics.

## Feature Group

```python
config = Config(features=["flow_meta"])
```

## Features

| Feature | Type | Description |
|---------|------|-------------|
| `src_ip` | str | Source IP address |
| `dst_ip` | str | Destination IP address |
| `src_port` | int | Source port number |
| `dst_port` | int | Destination port number |
| `protocol` | int | IP protocol (6=TCP, 17=UDP, 1=ICMP) |
| `duration` | float | Flow duration in seconds |
| `total_packets` | int | Total packet count (both directions) |
| `total_bytes` | int | Total bytes transferred |
| `initiator_packets` | int | Packets from initiator |
| `responder_packets` | int | Packets from responder |

### Optional Features

| Feature | Type | Condition | Description |
|---------|------|-----------|-------------|
| `flow_id` | str | `include_flow_id=True` | Hashed flow identifier |

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `include_ip_addresses` | True | Include src_ip, dst_ip |
| `include_ports` | True | Include src_port, dst_port |
| `anonymize_ips` | False | Hash IP addresses |
| `anonymization_salt` | "" | Salt for IP hashing |
| `include_flow_id` | False | Include flow_id |

## Example Output

```python
{
    "src_ip": "192.168.1.100",
    "dst_ip": "93.184.216.34",
    "src_port": 54321,
    "dst_port": 443,
    "protocol": 6,
    "duration": 2.456,
    "total_packets": 45,
    "total_bytes": 12500,
    "initiator_packets": 22,
    "responder_packets": 23,
}
```

## Privacy Mode

```python
# Anonymize IPs
config = Config(
    features=["flow_meta"],
    anonymize_ips=True,
    anonymization_salt="research-2025",
)

# Output:
# "src_ip": "5f4dcc3b5aa765d61d8327deb882cf99"
```

## Use Cases

- Flow identification and linking
- Traffic volume analysis
- Protocol distribution
- Privacy-preserving research datasets

## Related Extractors

- [Timing](timing.md) - Temporal patterns
- [Size](size.md) - Size statistics
