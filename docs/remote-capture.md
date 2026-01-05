# Remote Capture

JoyfulJay supports streaming packets from remote devices over WebSocket connections. This enables scenarios like:

- Capture traffic on a mobile phone and analyze on a laptop
- Distributed capture across multiple network segments
- Capture on a Raspberry Pi or embedded device with limited storage

## Architecture

```
┌─────────────────┐        WebSocket (WSS)       ┌──────────────────┐
│  Capture Device │ ─────────────────────────────▶ │  Analysis Host   │
│  (Server)       │    Compressed Packets         │  (Client)        │
│  - Android      │    Token Auth                 │  - Feature       │
│  - Raspberry Pi │    TLS Encrypted              │    Extraction    │
│  - Linux box    │                               │  - ML Pipeline   │
└─────────────────┘                               └──────────────────┘
```

## Installation

For TLS support and mDNS discovery:

```bash
pip install joyfuljay[discovery]  # Includes zeroconf for mDNS
```

## Server Setup

### Basic Server (No TLS)

```bash
# Start server on interface wlan0
jj serve wlan0

# Output shows connection URL
# Connect with: jj://192.168.1.50:8765?token=abc123...
```

### Secure Server (TLS)

```bash
# With existing certificates
jj serve wlan0 --tls-cert server.crt --tls-key server.key

# Connection URL includes tls=1 flag
# jj://192.168.1.50:8765?token=xxx&tls=1
```

### With mDNS Discovery

```bash
# Advertise server on local network
jj serve wlan0 --announce --announce-name "Living Room Pi"

# Clients can discover without knowing the IP
```

### Python API

```python
import asyncio
from joyfuljay.remote import Server

# Create server
server = Server(
    interface="wlan0",
    port=8765,
    tls_cert="server.crt",      # Enable TLS
    tls_key="server.key",
    announce=True,               # Enable mDNS
    announce_name="My Server",
    max_clients=5,
    max_bandwidth=1_000_000,     # 1 MB/s per client
    compress=True,               # Enable LZ4 compression
)

# Print connection URL
print(f"Connect with: {server.get_connection_url()}")

# Run server
asyncio.run(server.run())
```

## Client Connection

### Using Connection URL

```bash
# Connect using URL from server output
jj connect "jj://192.168.1.50:8765?token=abc123&tls=1" -o features.csv
```

### Using mDNS Discovery

```bash
# List available servers on the network
jj discover

# Output:
# Found 2 JoyfulJay servers:
#   1. Living Room Pi (192.168.1.50:8765) [TLS]
#   2. Office Capture (192.168.1.100:8765)

# Connect by name or index
jj connect --discover "Living Room Pi" -o features.csv
```

### Python API

```python
from joyfuljay.remote.discovery import discover_servers

# Find servers on the network
servers = discover_servers(timeout=5.0)

for server in servers:
    print(f"{server.name}: {server.address}:{server.port}")
    print(f"  TLS: {server.properties.get('tls', '0') == '1'}")
```

## Server Configuration

### Constructor Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `interface` | `str` | Required | Network interface to capture from |
| `host` | `str` | `"0.0.0.0"` | Address to bind to |
| `port` | `int` | `8765` | WebSocket port |
| `bpf_filter` | `str \| None` | `None` | BPF filter expression |
| `token` | `str \| None` | Auto-generated | Authentication token |
| `pid` | `int \| None` | `None` | Process ID to filter |
| `max_clients` | `int` | `5` | Maximum concurrent clients (0 = unlimited) |
| `max_bandwidth` | `float \| None` | `None` | Bytes/second limit per client |
| `compress` | `bool` | `True` | Enable LZ4 compression |
| `tls_cert` | `str \| None` | `None` | Path to TLS certificate |
| `tls_key` | `str \| None` | `None` | Path to TLS private key |
| `announce` | `bool` | `False` | Advertise via mDNS |
| `announce_name` | `str \| None` | Auto-generated | mDNS service name |
| `announce_properties` | `dict \| None` | `{}` | Additional TXT records |
| `client_queue_size` | `int` | `1000` | Per-client packet buffer |

### BPF Filters

Limit captured traffic with Berkeley Packet Filter expressions:

```bash
# Only HTTPS traffic
jj serve wlan0 --filter "tcp port 443"

# Only traffic to/from specific host
jj serve wlan0 --filter "host 10.0.0.1"

# Exclude SSH
jj serve wlan0 --filter "not port 22"
```

### Process Filtering

Capture traffic only from a specific process:

```bash
# By process ID
jj serve wlan0 --pid 12345

# By process name
jj serve wlan0 --process chrome
```

## TLS Configuration

### Generate Self-Signed Certificate

```bash
# Generate private key
openssl genrsa -out server.key 2048

# Generate self-signed certificate
openssl req -new -x509 -key server.key -out server.crt -days 365 \
  -subj "/CN=joyfuljay-server"
```

### Using Let's Encrypt

For public servers, use proper certificates:

```bash
# Use certbot or similar to obtain certificates
jj serve eth0 \
  --tls-cert /etc/letsencrypt/live/example.com/fullchain.pem \
  --tls-key /etc/letsencrypt/live/example.com/privkey.pem
```

## mDNS Discovery

### Service Type

JoyfulJay servers advertise as: `_joyfuljay._tcp.local.`

### TXT Records

The following TXT records are included:

| Key | Description |
|-----|-------------|
| `protocol` | Always `"jj"` |
| `version` | JoyfulJay version |
| `tls` | `"1"` if TLS enabled, `"0"` otherwise |
| Custom | Any from `announce_properties` |

### Discovery API

```python
from joyfuljay.remote.discovery import discover_servers, MDNSAnnouncer

# Discover servers (blocking for timeout seconds)
servers = discover_servers(timeout=3.0)

# Announcer for custom services
announcer = MDNSAnnouncer(
    name="Custom Service",
    port=8765,
    address="192.168.1.50",
    properties={"custom": "value"},
)
announcer.start()
# ... later
announcer.stop()
```

## Multi-Client Support

The server supports multiple simultaneous clients:

```python
server = Server(
    interface="wlan0",
    max_clients=10,  # Allow up to 10 clients
)
```

Each client:
- Has an independent packet queue
- Can have individual bandwidth limits
- Receives the same packet stream
- Is authenticated independently

When `max_clients` is reached, new connections are rejected with an error.

## Bandwidth Throttling

Limit bandwidth per client to prevent network saturation:

```python
server = Server(
    interface="wlan0",
    max_bandwidth=500_000,  # 500 KB/s per client
)
```

The server uses a token bucket algorithm:
- Allows bursts up to 2x the rate
- Smoothly limits sustained throughput
- Prevents slow clients from causing backpressure

## Connection URL Format

```
jj://[host]:[port]?token=[auth_token]&tls=[0|1]
```

| Component | Description |
|-----------|-------------|
| `host` | Server IP address or hostname |
| `port` | WebSocket port (default: 8765) |
| `token` | Authentication token (required) |
| `tls` | `1` for WSS, `0` or omitted for WS |

Examples:
- `jj://192.168.1.50:8765?token=abc123` - Plaintext
- `jj://192.168.1.50:8765?token=abc123&tls=1` - TLS encrypted

## Security Considerations

### Token Authentication

- Tokens are generated using `secrets.token_urlsafe(32)`
- Use constant-time comparison to prevent timing attacks
- Tokens are visible in URLs - use TLS to protect in transit

### TLS Recommendations

- Always use TLS when transmitting over untrusted networks
- Use proper certificates in production (not self-signed)
- Keep private keys secure with appropriate file permissions

### Network Security

- Consider firewall rules to limit access
- Use VPN for capture across the internet
- mDNS only works on local network segments

## Troubleshooting

### Connection Refused

```bash
# Check if server is running
netstat -tlnp | grep 8765

# Check firewall
sudo ufw allow 8765/tcp
```

### Authentication Failed

- Verify token matches exactly
- Check for URL encoding issues
- Ensure token hasn't been regenerated

### No Packets Received

- Verify interface is correct: `ip link show`
- Check capture permissions: run with sudo or set capabilities
- Verify BPF filter syntax

### High Latency

- Enable compression: `--compress`
- Reduce bandwidth limit if network is saturated
- Check client queue size
