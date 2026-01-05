# Installation

## Requirements

- Python 3.10 or higher
- pip package manager

## Basic Installation

Install JoyfulJay from PyPI:

```bash
pip install joyfuljay
```

## Optional Dependencies

JoyfulJay has several optional dependency groups for different use cases.

### Fast Parsing

For improved parsing performance with dpkt (10x faster for large PCAPs):

```bash
pip install joyfuljay[fast]
```

### High-Speed Capture

For high-speed live capture with libpcap:

```bash
pip install joyfuljay[libpcap]
```

Note: This requires libpcap development headers on your system.

### Kafka Streaming

For streaming features to Apache Kafka:

```bash
pip install joyfuljay[kafka]
```

See [Kafka Streaming Documentation](kafka.md) for usage details.

### Prometheus Metrics

For exporting processing metrics to Prometheus:

```bash
pip install joyfuljay[monitoring]
```

See [Monitoring Documentation](monitoring.md) for usage details.

### mDNS Discovery

For automatic server discovery on local networks:

```bash
pip install joyfuljay[discovery]
```

See [Remote Capture Documentation](remote-capture.md) for usage details.

### Connection Graphs

For network graph analysis with NetworkX:

```bash
pip install joyfuljay[graphs]
```

### PostgreSQL Database

For direct database insertion:

```bash
pip install joyfuljay[db]
```

### Multiple Extras

Install multiple extras at once:

```bash
pip install joyfuljay[fast,kafka,monitoring,discovery,graphs]
```

### Development

For development and testing (includes hypothesis, pytest, mypy, ruff):

```bash
pip install joyfuljay[dev]
```

## Installation from Source

Clone the repository and install in development mode:

```bash
git clone https://github.com/joyfuljay/joyfuljay.git
cd joyfuljay
pip install -e ".[dev]"
```

## Verifying Installation

After installation, verify JoyfulJay is working:

```bash
jj --version
```

Or in Python:

```python
import joyfuljay
print(joyfuljay.__version__)
```

## Platform-Specific Setup

### Windows

**Live capture requires Npcap:**

1. Download Npcap from [https://npcap.com/](https://npcap.com/)
2. Run the installer (check "Install in WinPcap API-compatible mode")
3. Restart your terminal/IDE

Check your setup:
```bash
jj status
```

Note: PCAP file processing works without Npcap.

### macOS

Live capture works out of the box with the built-in libpcap.

For permissions, either:
- Run with `sudo`: `sudo jj live en0 -d 10`
- Or grant Terminal network access in System Preferences → Security & Privacy → Privacy → Network

### Linux

Live capture requires libpcap (usually pre-installed).

For permissions, either:
- Run as root: `sudo jj live eth0 -d 10`
- Or add capture capability: `sudo setcap cap_net_raw+ep $(which python)`

## Checking Your Setup

Run the status command to verify everything works:

```bash
jj status
```

Example output:
```
JoyfulJay v0.1.0
Platform: Darwin 23.0.0
Python: 3.11.5

Live capture: [OK] libpcap available (5 interfaces)

Available interfaces:
  - en0
  - lo0
  - utun0

PCAP file processing: [OK] Always available
```

## Troubleshooting

### Scapy Import Errors

If you see Scapy-related errors, ensure Scapy is properly installed:

```bash
pip install scapy>=2.5.0
```

### Permission Denied on Live Capture

Ensure you have appropriate privileges for network capture. On Linux:

```bash
sudo jj live eth0 --duration 10
```

### Missing libpcap

If using the `[libpcap]` extra and encountering build errors, install libpcap:

- **Ubuntu/Debian**: `sudo apt-get install libpcap-dev`
- **macOS**: `brew install libpcap`
- **RHEL/CentOS**: `sudo yum install libpcap-devel`
