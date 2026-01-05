# DNS Extractor

The DNS extractor parses DNS queries and responses for domain analysis and DNS tunneling detection.

## Feature Group

```python
config = Config(features=["dns"])
```

## Features

### Query Information

| Feature | Type | Description |
|---------|------|-------------|
| `dns_query_count` | int | Number of DNS queries |
| `dns_response_count` | int | Number of DNS responses |
| `dns_query_names` | list[str]\|None | Queried domain names |
| `dns_query_types` | list[int]\|None | Query types (A, AAAA, etc.) |

### Query Types

| Feature | Type | Description |
|---------|------|-------------|
| `dns_type_a_count` | int | A record queries |
| `dns_type_aaaa_count` | int | AAAA record queries |
| `dns_type_mx_count` | int | MX record queries |
| `dns_type_txt_count` | int | TXT record queries |
| `dns_type_cname_count` | int | CNAME record queries |
| `dns_type_ptr_count` | int | PTR record queries |

### Response Analysis

| Feature | Type | Description |
|---------|------|-------------|
| `dns_rcode_success` | int | Successful responses |
| `dns_rcode_nxdomain` | int | Non-existent domain |
| `dns_rcode_refused` | int | Refused queries |
| `dns_answer_count` | int | Total answers |
| `dns_response_time_mean` | float | Mean response time (ms) |

### Tunneling Indicators

| Feature | Type | Description |
|---------|------|-------------|
| `dns_query_len_mean` | float | Mean query name length |
| `dns_query_len_max` | int | Max query name length |
| `dns_subdomain_depth` | float | Mean subdomain levels |
| `dns_query_entropy` | float | Query name entropy |

## DNS Record Types

| Type | Value | Description |
|------|-------|-------------|
| A | 1 | IPv4 address |
| AAAA | 28 | IPv6 address |
| CNAME | 5 | Canonical name |
| MX | 15 | Mail exchange |
| TXT | 16 | Text record |
| PTR | 12 | Reverse DNS |
| NS | 2 | Name server |
| SOA | 6 | Start of authority |

## Example Output

```python
{
    "dns_query_count": 5,
    "dns_response_count": 5,
    "dns_query_names": ["example.com", "www.example.com"],
    "dns_type_a_count": 4,
    "dns_type_aaaa_count": 1,
    "dns_rcode_success": 5,
    "dns_rcode_nxdomain": 0,
    "dns_query_len_mean": 15.2,
    "dns_query_entropy": 3.8,
}
```

## DNS Tunneling Detection

DNS tunneling encodes data in DNS queries/responses:

### Indicators

| Indicator | Normal | Tunneling |
|-----------|--------|-----------|
| Query length | 10-30 chars | 50+ chars |
| Subdomain depth | 1-3 levels | 4+ levels |
| Query entropy | 2.0-4.0 | 4.5+ |
| TXT query ratio | < 5% | > 30% |

### Detection Example

```python
import joyfuljay as jj

df = jj.extract("capture.pcap", features=["dns"])

# Potential DNS tunneling
suspicious = df[
    (df["dns_query_len_mean"] > 40) |
    (df["dns_query_entropy"] > 4.5) |
    (df["dns_type_txt_count"] > df["dns_type_a_count"])
]

print(f"Suspicious DNS flows: {len(suspicious)}")
```

## DoH/DoT Detection

DNS over HTTPS (DoH) and DNS over TLS (DoT) require different detection:

```python
# DoH: Standard HTTPS, use fingerprint extractor
df = jj.extract("capture.pcap", features=["fingerprint"])
doh = df[df["likely_doh"] == True]

# DoT: Port 853
# Filter at capture time or check dst_port
```

## Use Cases

- **DNS tunneling detection**: Exfiltration via DNS
- **C2 communication**: Malware DNS beacons
- **Domain analysis**: Query patterns
- **DoH detection**: Encrypted DNS traffic

## Related Extractors

- [Fingerprint](fingerprint.md) - DoH detection
- [Entropy](entropy.md) - Query entropy analysis
- [TLS](tls.md) - DoT analysis
