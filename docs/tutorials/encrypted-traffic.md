# Encrypted Traffic Analysis

Detect Tor, VPN, and DNS-over-HTTPS (DoH) traffic without decryption.

---

## Overview

JoyfulJay's `fingerprint` extractor identifies encrypted tunnel traffic using:
- Timing patterns
- Packet size distributions
- TLS fingerprints
- Protocol-specific behaviors

---

## Quick Detection

```python
import joyfuljay as jj

df = jj.extract("capture.pcap", features=["fingerprint"])

# Check detection flags
tor_flows = df[df["likely_tor"] == True]
vpn_flows = df[df["likely_vpn"] == True]
doh_flows = df[df["likely_doh"] == True]

print(f"Tor flows: {len(tor_flows)}")
print(f"VPN flows: {len(vpn_flows)}")
print(f"DoH flows: {len(doh_flows)}")
```

---

## Tor Detection

### How It Works

Tor traffic exhibits distinctive patterns:

| Feature | Tor Pattern |
|---------|-------------|
| Cell size | Fixed 512-byte cells |
| TLS cipher | Specific cipher suites |
| IAT | Characteristic timing |
| Certificate | Self-signed, specific fields |

### Detection Example

```python
import joyfuljay as jj

config = jj.Config(
    features=["fingerprint", "tls", "timing", "size"],
)
pipeline = jj.Pipeline(config)
df = pipeline.process_pcap("capture.pcap")

# Primary detection
tor_flows = df[df["likely_tor"] == True]

# Additional indicators
for _, flow in tor_flows.iterrows():
    print(f"Flow: {flow['src_ip']} -> {flow['dst_ip']}")
    print(f"  Tor score: {flow.get('tor_score', 'N/A')}")
    print(f"  Cell-like packets: {flow.get('fixed_size_ratio', 'N/A')}")
    print(f"  TLS cipher: {flow.get('tls_cipher_suite', 'N/A')}")
```

### Tor Indicators

```python
# Manual analysis using multiple features
def analyze_tor_indicators(df):
    indicators = []

    for idx, flow in df.iterrows():
        score = 0
        reasons = []

        # Check packet size distribution (Tor uses 512-byte cells)
        if flow.get("pkt_len_mode") in range(510, 520):
            score += 2
            reasons.append("cell-sized packets")

        # Check for fixed-size padding
        if flow.get("fixed_size_ratio", 0) > 0.8:
            score += 2
            reasons.append("fixed padding")

        # Check TLS patterns
        ja3 = flow.get("ja3_hash", "")
        if ja3 in KNOWN_TOR_JA3_HASHES:
            score += 3
            reasons.append("known Tor JA3")

        # Check timing patterns
        if flow.get("iat_std", float("inf")) < 0.1:
            score += 1
            reasons.append("regular timing")

        if score >= 3:
            indicators.append({
                "flow_id": flow.get("flow_id"),
                "score": score,
                "reasons": reasons
            })

    return indicators

# Known Tor JA3 hashes (example - actual list varies)
KNOWN_TOR_JA3_HASHES = {
    "e7d705a3286e19ea42f587b344ee6865",
    "6734f37431670b3ab4292b8f60f29984",
}
```

---

## VPN Detection

### How It Works

VPN protocols have identifiable patterns:

| Protocol | Indicators |
|----------|------------|
| OpenVPN | Port 1194, specific handshake |
| WireGuard | Port 51820, small keepalives |
| IPsec | ESP headers, IKE ports |
| SSTP | Port 443, specific TLS |

### Detection Example

```python
import joyfuljay as jj

df = jj.extract("capture.pcap", features=["fingerprint", "timing", "size"])

vpn_flows = df[df["likely_vpn"] == True]

for _, flow in vpn_flows.iterrows():
    print(f"VPN detected: {flow['src_ip']} -> {flow['dst_ip']}")
    print(f"  Protocol hint: {flow.get('vpn_protocol', 'unknown')}")
    print(f"  Confidence: {flow.get('vpn_score', 'N/A')}")
```

### VPN Protocol Identification

```python
def identify_vpn_protocol(flow):
    dst_port = flow.get("dst_port", 0)
    protocol = flow.get("protocol", 0)

    # OpenVPN
    if dst_port == 1194:
        return "OpenVPN (UDP/TCP)"

    # WireGuard
    if dst_port == 51820 and protocol == 17:  # UDP
        return "WireGuard"

    # IPsec IKE
    if dst_port in (500, 4500) and protocol == 17:
        return "IPsec"

    # Check for tunnel characteristics
    entropy = flow.get("payload_entropy_mean", 0)
    if entropy > 7.5:  # High entropy suggests encryption
        pkt_size_std = flow.get("pkt_len_std", float("inf"))
        if pkt_size_std < 50:  # Low variance suggests tunnel
            return "Unknown VPN (encrypted tunnel)"

    return "Not VPN"
```

---

## DNS-over-HTTPS (DoH) Detection

### How It Works

DoH traffic has distinctive patterns:

| Feature | DoH Pattern |
|---------|-------------|
| Port | 443 (HTTPS) |
| Packet size | Small requests, small responses |
| IAT | Bursty (DNS queries in batches) |
| Server | Known DoH providers |

### Detection Example

```python
import joyfuljay as jj

df = jj.extract("capture.pcap", features=["fingerprint", "dns", "tls"])

doh_flows = df[df["likely_doh"] == True]

for _, flow in doh_flows.iterrows():
    print(f"DoH detected: {flow['src_ip']} -> {flow['dst_ip']}")
    print(f"  SNI: {flow.get('tls_sni', 'N/A')}")
```

### Known DoH Providers

```python
DOH_PROVIDERS = {
    # Cloudflare
    "1.1.1.1", "1.0.0.1",
    "cloudflare-dns.com",

    # Google
    "8.8.8.8", "8.8.4.4",
    "dns.google",

    # Quad9
    "9.9.9.9",
    "dns.quad9.net",

    # NextDNS
    "dns.nextdns.io",

    # Mozilla
    "mozilla.cloudflare-dns.com",
}

def check_doh_provider(flow):
    dst_ip = flow.get("dst_ip", "")
    sni = flow.get("tls_sni", "")

    if dst_ip in DOH_PROVIDERS or sni in DOH_PROVIDERS:
        return True
    return False
```

---

## Combined Analysis

```python
import joyfuljay as jj
import pandas as pd

def analyze_encrypted_traffic(pcap_path):
    """Comprehensive encrypted traffic analysis."""

    config = jj.Config(
        features=["fingerprint", "tls", "timing", "size", "entropy"],
    )
    pipeline = jj.Pipeline(config)
    df = pipeline.process_pcap(pcap_path)

    results = {
        "total_flows": len(df),
        "tor_flows": len(df[df["likely_tor"] == True]),
        "vpn_flows": len(df[df["likely_vpn"] == True]),
        "doh_flows": len(df[df["likely_doh"] == True]),
        "high_entropy_flows": len(df[df["payload_entropy_mean"] > 7.5]),
    }

    # Detailed breakdown
    print(f"Total flows analyzed: {results['total_flows']}")
    print(f"Tor traffic: {results['tor_flows']} flows")
    print(f"VPN traffic: {results['vpn_flows']} flows")
    print(f"DoH traffic: {results['doh_flows']} flows")
    print(f"High entropy (encrypted): {results['high_entropy_flows']} flows")

    # Export suspicious flows
    suspicious = df[
        (df["likely_tor"] == True) |
        (df["likely_vpn"] == True) |
        (df["likely_doh"] == True)
    ]

    if len(suspicious) > 0:
        suspicious.to_csv("suspicious_flows.csv", index=False)
        print(f"\nExported {len(suspicious)} suspicious flows to suspicious_flows.csv")

    return df, results

# Run analysis
df, results = analyze_encrypted_traffic("network_capture.pcap")
```

---

## Real-time Detection

```python
import joyfuljay as jj

config = jj.Config(features=["fingerprint", "tls"])
pipeline = jj.Pipeline(config)

def alert_callback(flow_features):
    if flow_features.get("likely_tor"):
        print(f"[ALERT] Tor detected: {flow_features['src_ip']}")
    if flow_features.get("likely_vpn"):
        print(f"[ALERT] VPN detected: {flow_features['src_ip']}")
    if flow_features.get("likely_doh"):
        print(f"[ALERT] DoH detected: {flow_features['dst_ip']}")

# Live capture with alerts
for features in pipeline.iter_features("eth0", live=True):
    alert_callback(features)
```

---

## Accuracy Considerations

### False Positives

Some legitimate traffic may trigger detection:

| Detection | Common False Positives |
|-----------|------------------------|
| Tor | WebSocket, some CDNs |
| VPN | Gaming, streaming |
| DoH | Regular HTTPS to DoH IPs |

### Improving Accuracy

```python
# Combine multiple indicators
def confident_tor_detection(flow):
    indicators = 0

    if flow.get("likely_tor"):
        indicators += 1
    if flow.get("fixed_size_ratio", 0) > 0.7:
        indicators += 1
    if flow.get("payload_entropy_mean", 0) > 7.0:
        indicators += 1
    if flow.get("tls_sni", "") == "":  # No SNI
        indicators += 1

    return indicators >= 3  # Require multiple indicators
```

---

## See Also

- [Traffic Classification](traffic-classification.md) - ML-based classification
- [Feature Reference](../features.md) - All fingerprint features
- [TLS Extractor](../extractors/tls.md) - TLS/JA3 details
