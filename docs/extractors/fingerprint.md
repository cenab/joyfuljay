# Fingerprint Extractor

The Fingerprint extractor detects specific traffic types including Tor, VPN, and DNS-over-HTTPS (DoH) using pattern-based heuristics.

## Feature Group

```python
config = Config(features=["fingerprint"])
```

## Features

| Feature | Type | Description |
|---------|------|-------------|
| `is_tor` | bool | Detected as Tor traffic |
| `is_vpn` | bool | Detected as VPN traffic |
| `is_doh` | bool | Detected as DNS-over-HTTPS |
| `tor_confidence` | float | Tor detection confidence (0.0-1.0) |
| `vpn_confidence` | float | VPN detection confidence (0.0-1.0) |
| `doh_confidence` | float | DoH detection confidence (0.0-1.0) |

## Example Output

```python
{
    "is_tor": True,
    "is_vpn": False,
    "is_doh": False,
    "tor_confidence": 0.85,
    "vpn_confidence": 0.0,
    "doh_confidence": 0.0,
}
```

## Detection Methods

### Tor Detection

Tor traffic is identified by:

1. **Port patterns**: Default Tor ports (9001, 9030, 9050, 9051, 9150)
2. **TLS fingerprints**: Known Tor Browser JA3 hashes
3. **Cell size patterns**: Tor uses 512-byte cells
4. **Timing patterns**: Circuit-based delays

**Confidence factors:**
- Known Tor port: +0.3
- Matching JA3: +0.5
- 512-byte cell pattern: +0.2
- High-latency timing: +0.1

### VPN Detection

VPN traffic is identified by:

1. **Protocol signatures**: OpenVPN, WireGuard, IPsec headers
2. **Port patterns**: Common VPN ports (1194, 51820, 500, 4500)
3. **Packet size patterns**: MTU-based constant sizes
4. **Entropy**: High-entropy payloads

**Confidence factors:**
- Protocol signature: +0.8
- Known VPN port: +0.2
- Constant packet sizes: +0.3
- High entropy: +0.2

### DoH Detection

DNS-over-HTTPS is identified by:

1. **Known DoH endpoints**: IP addresses of major DoH providers
2. **TLS patterns**: Specific JA3 patterns for DoH clients
3. **Payload sizes**: DNS query/response size patterns
4. **Port 443**: HTTPS port with small payloads

**Confidence factors:**
- Known DoH IP: +0.7
- DoH client JA3: +0.2
- Small payload pattern: +0.1

## Known Endpoints

### Tor Nodes
- Tor directory authorities
- Known Tor relay IPs (updated periodically)

### DoH Providers
- Cloudflare: 1.1.1.1, 1.0.0.1
- Google: 8.8.8.8, 8.8.4.4
- Quad9: 9.9.9.9
- NextDNS, AdGuard, etc.

## Use Cases

- **Security Monitoring**: Detect anonymization attempts
- **Policy Enforcement**: Identify unauthorized VPN usage
- **Traffic Classification**: Categorize encrypted traffic
- **Research**: Study anonymous traffic patterns

## Limitations

- **False Positives**: Some legitimate traffic may match patterns
- **Evasion**: Sophisticated users can modify fingerprints
- **New Endpoints**: May not detect new/unknown services
- **Encrypted DoH**: Hard to distinguish from regular HTTPS

## Combining with Other Features

For better accuracy, combine with other extractors:

```python
config = Config(
    features=["fingerprint", "tls", "timing", "entropy"],
)

# Use multiple signals:
# - is_tor + tor JA3 patterns
# - is_vpn + high entropy + constant sizes
# - is_doh + known DoH IP + small payloads
```

## Related Extractors

- [TLS](tls.md) - JA3 fingerprints for detection
- [Entropy](entropy.md) - Payload randomness
- [Timing](timing.md) - Timing patterns
- [Size](size.md) - Packet size patterns
