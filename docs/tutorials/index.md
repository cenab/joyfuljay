# Tutorials

Learn JoyfulJay through practical, hands-on tutorials that cover real-world use cases.

---

## Learning Path

Whether you're new to network traffic analysis or an experienced ML practitioner, these tutorials will help you get the most out of JoyfulJay.

### Beginner Path

If you're just getting started, follow these tutorials in order:

1. **[Traffic Classification](traffic-classification.md)** - Learn the fundamentals of extracting features and training a classifier to identify different types of network traffic. This tutorial covers the complete workflow from PCAP to trained model.

2. **[Encrypted Traffic Analysis](encrypted-traffic.md)** - Understand how to detect Tor, VPN, and DNS-over-HTTPS traffic without decrypting it. Learn about the fingerprinting techniques that make this possible.

### Advanced Path

Once you're comfortable with the basics:

3. **[Batch Processing](batch-processing.md)** - Process large PCAP datasets efficiently using parallel workers, memory-efficient iteration, and output streaming. Essential for production workloads.

4. **[Real-time Monitoring](realtime-monitoring.md)** - Build a complete monitoring pipeline with live capture, Kafka streaming, and Prometheus metrics. Includes Grafana dashboard setup.

5. **[Custom Extractors](custom-extractors.md)** - Create your own feature extractors to capture domain-specific information. Learn the extractor architecture and best practices.

---

## Tutorial Overview

| Tutorial | Level | Time | What You'll Learn |
|----------|-------|------|-------------------|
| [Traffic Classification](traffic-classification.md) | Beginner | 30 min | Feature extraction, ML pipeline, model training |
| [Encrypted Traffic Analysis](encrypted-traffic.md) | Beginner | 25 min | Tor/VPN/DoH detection, fingerprinting techniques |
| [Batch Processing](batch-processing.md) | Intermediate | 20 min | Parallel processing, memory efficiency, large datasets |
| [Real-time Monitoring](realtime-monitoring.md) | Advanced | 45 min | Live capture, Kafka, Prometheus, Grafana |
| [Custom Extractors](custom-extractors.md) | Advanced | 40 min | Extractor architecture, custom features |

---

## Prerequisites

Before starting these tutorials, make sure you have:

- **JoyfulJay installed**: See the [Installation Guide](../installation.md)
- **Python 3.10+**: With pandas, numpy, and scikit-learn for ML tutorials
- **Sample PCAP files**: Use your own captures or download public datasets

### Recommended PCAP Datasets

For learning and testing:

- **[CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html)** - Intrusion detection dataset with labeled traffic
- **[CTU-13](https://www.stratosphereips.org/datasets-ctu13)** - Botnet traffic captures
- **[ISCX VPN-nonVPN](https://www.unb.ca/cic/datasets/vpn.html)** - VPN traffic classification dataset

---

## Quick Reference

### Feature Extraction Basics

```python
import joyfuljay as jj

# Extract all features from a PCAP file
df = jj.extract("capture.pcap")

# Select specific feature groups
df = jj.extract("capture.pcap", features=["timing", "tls", "fingerprint"])

# Use configuration for fine-grained control
config = jj.Config(
    features=["timing", "size", "tls"],
    flow_timeout=30.0,
    include_ip_addresses=True
)
pipeline = jj.Pipeline(config)
df = pipeline.process_pcap("capture.pcap")
```

### Command Line Usage

```bash
# Basic extraction
jj extract capture.pcap -o features.csv

# Select features
jj extract capture.pcap --features timing tls -o features.csv

# Live capture
jj live eth0 --duration 60 -o live.csv

# View PCAP info
jj info capture.pcap
```

---

## Need Help?

- **[Quick Start Guide](../quickstart.md)** - Get your first extraction running
- **[Features Reference](../features.md)** - Detailed feature documentation
- **[Configuration](../configuration.md)** - All configuration options
- **[FAQ](https://github.com/cenab/joyfuljay/discussions)** - Common questions and answers
