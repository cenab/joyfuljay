# CLI Reference

JoyfulJay provides a comprehensive command-line interface accessible via `joyfuljay` or the shorter alias `jj`.

## Global Options

```bash
jj [OPTIONS] COMMAND [ARGS]...

Options:
  -v, --verbose        Enable verbose output (debug logging)
  --version            Show version and exit
  --help               Show help and exit
```

---

## Commands Overview

| Command | Description |
|---------|-------------|
| [`extract`](#extract) | Extract features from PCAP files |
| [`live`](#live) | Capture and extract from live traffic |
| [`serve`](#serve) | Start remote capture server |
| [`connect`](#connect) | Connect to remote server |
| [`discover`](#discover) | Discover servers via mDNS |
| [`watch`](#watch) | Watch directory for new PCAPs |
| [`repl`](#repl) | Interactive REPL mode |
| [`schema`](#schema) | Export feature schema |
| [`features`](#features) | List available features |
| [`status`](#status) | Check system status |
| [`info`](#info) | Show PCAP file information |

---

## extract

Extract features from PCAP file(s).

```bash
jj extract INPUT_PATH [OPTIONS]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `INPUT_PATH` | PCAP file or directory containing PCAPs |

### Options

**Output Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `-o, --output FILE` | stdout | Output file path |
| `-f, --format FORMAT` | csv | Output format: `csv`, `json`, `parquet`, `sqlite`, `postgres`, `kafka` |
| `--streaming` | - | Write output incrementally (for large captures) |
| `--progress/--no-progress` | yes | Show progress bar |

**Configuration:**

| Option | Default | Description |
|--------|---------|-------------|
| `-c, --config FILE` | - | Configuration file (JSON/YAML) |
| `--features GROUP` | all | Feature groups to extract (repeatable) |
| `--feature NAME` | - | Specific feature names to include (repeatable) |
| `--timeout SECONDS` | 60.0 | Flow inactivity timeout |
| `--bidir-split` | - | Split features into fwd/bwd directions |
| `--include-sequences` | - | Include raw packet sequences |
| `--no-ips` | - | Exclude IP addresses |
| `--no-ports` | - | Exclude port numbers |
| `-w, --workers N` | 1 | Parallel workers for batch processing |

**Database Output:**

| Option | Default | Description |
|--------|---------|-------------|
| `--db-table NAME` | joyfuljay_features | Table name |
| `--db-if-exists ACTION` | append | Table handling: `append`, `replace`, `fail` |
| `--db-batch-size N` | 1000 | Rows per batch |

**Kafka Output:**

| Option | Default | Description |
|--------|---------|-------------|
| `--kafka-brokers HOSTS` | - | Bootstrap servers (comma-separated) |
| `--kafka-topic TOPIC` | - | Target topic |
| `--kafka-key FIELD` | - | Feature field for message key |
| `--kafka-batch-size N` | 1000 | Flush every N messages |

**Monitoring:**

| Option | Default | Description |
|--------|---------|-------------|
| `--prometheus-port PORT` | - | Expose metrics on this port |
| `--prometheus-addr ADDR` | 0.0.0.0 | Metrics bind address |

### Examples

```bash
# Basic extraction to CSV
jj extract capture.pcap -o features.csv

# Process directory of PCAPs
jj extract traces/ -o all_features.csv

# JSON output with specific features
jj extract capture.pcap -f json --features timing --features tls -o features.json

# Use configuration file
jj extract capture.pcap -c config.yaml -o output.csv

# Streaming mode for large files (memory efficient)
jj extract large.pcap -o features.csv --streaming

# Parallel processing of multiple files
jj extract traces/ -w 4 -o features.csv

# Output to PostgreSQL
jj extract capture.pcap -f postgres -o "postgresql://user:pass@host/db" --db-table flows

# Stream to Kafka
jj extract capture.pcap -f kafka --kafka-brokers localhost:9092 --kafka-topic features

# Select specific features
jj extract capture.pcap --feature src_ip --feature dst_ip --feature duration --feature ja3_hash

# Export as Parquet
jj extract capture.pcap -f parquet -o features.parquet
```

---

## live

Capture and extract features from live network traffic.

```bash
jj live INTERFACE [OPTIONS]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `INTERFACE` | Network interface (e.g., `eth0`, `en0`, `wlan0`) |

### Options

**Capture Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `-d, --duration SECONDS` | unlimited | Capture duration |
| `--filter EXPR` | - | BPF filter expression |
| `--save-pcap FILE` | - | Save packets to PCAP file |
| `--pid PID` | - | Filter by process ID |
| `--process NAME` | - | Filter by process name |

**Output Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `-o, --output FILE` | stdout | Output file path |
| `-f, --format FORMAT` | csv | Output format |
| `--timeout SECONDS` | 60.0 | Flow inactivity timeout |

**Database, Kafka, and Monitoring options same as `extract`.**

### Examples

```bash
# Capture for 60 seconds
jj live eth0 -d 60 -o features.csv

# Filter HTTPS traffic only
jj live en0 --filter "tcp port 443" -o https_features.csv

# Capture Chrome traffic
jj live en0 --process chrome -o chrome_traffic.csv

# Capture specific process by PID
jj live en0 --pid 12345 -o app_traffic.csv

# Save raw packets and extract features
jj live wlan0 -d 120 --save-pcap raw.pcap -o features.csv

# Stream to Kafka in real-time
jj live eth0 -f kafka --kafka-brokers localhost:9092 --kafka-topic live-features

# JSON output to stdout
jj live eth0 -d 30 -f json
```

**Note:** Live capture requires root/administrator privileges on most systems.

---

## serve

Start a remote capture server for streaming packets to clients.

```bash
jj serve INTERFACE [OPTIONS]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `INTERFACE` | Network interface to capture from |

### Options

**Server Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `-p, --port PORT` | 8765 | Port to listen on |
| `--host ADDR` | 0.0.0.0 | Bind address |
| `--token TOKEN` | auto-generated | Authentication token |
| `--max-clients N` | 5 | Maximum concurrent clients (0=unlimited) |
| `--max-bandwidth SIZE` | unlimited | Max bandwidth per client (e.g., `1M`, `500K`) |

**Capture Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--filter EXPR` | - | BPF filter expression |
| `--pid PID` | - | Filter by process ID |
| `--process NAME` | - | Filter by process name |

**TLS Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--tls-cert FILE` | - | TLS certificate file |
| `--tls-key FILE` | - | TLS private key file |

**Discovery Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--announce/--no-announce` | no | Advertise via mDNS |
| `--announce-name NAME` | - | Override mDNS service name |

**Other:**

| Option | Default | Description |
|--------|---------|-------------|
| `--compress/--no-compress` | yes | Enable stream compression |

### Examples

```bash
# Basic server
jj serve wlan0

# Custom port with TLS
jj serve eth0 -p 9000 --tls-cert server.crt --tls-key server.key

# Advertise via mDNS for discovery
jj serve wlan0 --announce --announce-name "my-capture-server"

# Limit bandwidth and clients
jj serve eth0 --max-clients 3 --max-bandwidth 10M

# Filter specific traffic
jj serve wlan0 --filter "tcp port 443"

# Capture specific application
jj serve wlan0 --process firefox
```

**Output shows connection URL and token:**
```
============================================================
Connection URL: jj://192.168.1.100:8765?token=abc123def456
Token: abc123def456
============================================================
```

---

## connect

Connect to a remote JoyfulJay capture server.

```bash
jj connect URL [OPTIONS]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `URL` | Server URL: `jj://host:port?token=xxx` |

### Options

**Connection Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `-d, --duration SECONDS` | unlimited | Capture duration |
| `--save-pcap FILE` | - | Save packets locally |
| `--tls-ca FILE` | - | CA bundle for verification |
| `--tls-insecure` | - | Disable certificate verification |

**Output Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `-o, --output FILE` | stdout | Output file path |
| `-f, --format FORMAT` | csv | Output format |
| `--timeout SECONDS` | 60.0 | Flow inactivity timeout |

**Database, Kafka, and Monitoring options same as `extract`.**

### Examples

```bash
# Connect and extract features
jj connect "jj://192.168.1.100:8765?token=abc123" -o features.csv

# Capture for 60 seconds
jj connect "jj://192.168.1.100:8765?token=abc123" -d 60 -o features.csv

# Save raw packets locally
jj connect "jj://192.168.1.100:8765?token=abc123" --save-pcap capture.pcap -o features.csv

# TLS connection (WSS)
jj connect "jj://192.168.1.100:8765?token=abc123&tls=1" --tls-ca ca.crt -o features.csv

# Skip TLS verification (development only)
jj connect "jj://localhost:8765?token=abc123&tls=1" --tls-insecure -o features.csv
```

---

## discover

Discover JoyfulJay servers on the local network via mDNS/Bonjour.

```bash
jj discover [OPTIONS]
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--timeout SECONDS` | 2.0 | Discovery time window |
| `--json` | - | Output as JSON |

### Examples

```bash
# Discover servers
jj discover

# Output example:
# Discovered JoyfulJay servers:
# - my-capture-server: jj://192.168.1.100:8765
# - office-sensor: jj://192.168.1.101:8765?tls=1

# JSON output
jj discover --json

# Longer discovery window
jj discover --timeout 5
```

**Note:** Requires the `[discovery]` extra: `pip install joyfuljay[discovery]`

---

## watch

Watch a directory and automatically process new PCAP files.

```bash
jj watch DIRECTORY [OPTIONS]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `DIRECTORY` | Directory to watch for new PCAPs |

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `-o, --output-dir DIR` | `DIRECTORY/features/` | Output directory |
| `-f, --format FORMAT` | csv | Output format: `csv`, `json`, `parquet` |
| `--recursive/--no-recursive` | yes | Watch subdirectories |
| `-c, --config FILE` | - | Configuration file |

### Examples

```bash
# Watch directory
jj watch /var/pcap -o /var/features

# Watch with JSON output
jj watch ./captures --format json -o ./features

# Watch non-recursively
jj watch /data --no-recursive

# Use configuration
jj watch /var/pcap -c config.yaml
```

**Output:**
```
Watching directory: /var/pcap
Output directory: /var/features
Recursive: True
Press Ctrl+C to stop...

Processing: capture_001.pcap
  -> /var/features/capture_001.csv (150 flows)
Processing: capture_002.pcap
  -> /var/features/capture_002.csv (89 flows)
```

---

## repl

Start an interactive REPL for exploring PCAP files.

```bash
jj repl
```

### REPL Commands

| Command | Description |
|---------|-------------|
| `load <file>` | Load a PCAP file |
| `info` | Show info about loaded PCAP |
| `flows` | List flows in the PCAP |
| `features` | Extract and display features |
| `export <file>` | Export features to file |
| `config <key> <value>` | Set configuration option |
| `help` | Show all commands |
| `quit` | Exit REPL |

### Example Session

```
$ jj repl
JoyfulJay Interactive REPL
Type 'help' for commands, 'quit' to exit.

jj> load capture.pcap
Loaded: capture.pcap (1523 packets)

jj> info
File: capture.pcap
Packets: 1523
Duration: 45.23 seconds
Protocols: TCP (89%), UDP (11%)

jj> flows
Flow 1: 192.168.1.100:54321 -> 93.184.216.34:443 (TCP, 45 packets)
Flow 2: 192.168.1.100:54322 -> 8.8.8.8:53 (UDP, 2 packets)
...

jj> features
Extracting features...
150 flows extracted.

jj> export features.csv
Exported to: features.csv

jj> quit
Goodbye!
```

---

## schema

Export the feature schema in various formats.

```bash
jj schema [OPTIONS]
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `-o, --output FILE` | stdout | Output file path |
| `-f, --format FORMAT` | json | Format: `json`, `csv`, `markdown` |
| `--group GROUP` | - | Filter by feature group |

### Examples

```bash
# Export full schema as JSON
jj schema -f json -o schema.json

# Export as CSV
jj schema -f csv -o schema.csv

# Export as Markdown documentation
jj schema -f markdown -o FEATURES.md

# Filter to TLS features only
jj schema --group tls -f json
```

### JSON Schema Example

```json
{
  "features": [
    {
      "name": "src_ip",
      "type": "string",
      "group": "flow_meta",
      "description": "Source IP address",
      "unit": null
    },
    {
      "name": "duration",
      "type": "float",
      "group": "flow_meta",
      "description": "Flow duration in seconds",
      "unit": "seconds"
    }
  ]
}
```

---

## features

List all available features with descriptions.

```bash
jj features
```

### Example Output

```
JoyfulJay Features
==================

Flow Metadata (flow_meta)
-------------------------
  src_ip          Source IP address
  dst_ip          Destination IP address
  src_port        Source port number
  dst_port        Destination port number
  protocol        IP protocol number
  duration        Flow duration (seconds)
  total_packets   Total packet count
  total_bytes     Total bytes transferred

Timing Analysis (timing)
------------------------
  iat_mean        Mean inter-arrival time (seconds)
  iat_std         IAT standard deviation
  iat_min         Minimum IAT
  iat_max         Maximum IAT
  ...

TLS Features (tls)
------------------
  tls_version     TLS version
  ja3_hash        JA3 fingerprint hash
  ja3s_hash       JA3S fingerprint hash
  sni             Server Name Indication
  ...
```

---

## status

Check system status, available interfaces, and live capture capability.

```bash
jj status
```

### Example Output

```
JoyfulJay v0.1.0
Platform: Darwin 23.0.0
Python: 3.11.6

Live capture: [OK] libpcap available

Available interfaces:
  - en0 (Wi-Fi)
  - lo0 (Loopback)
  - bridge0 (Bridge)
  - utun0 (UTUN)

PCAP file processing: [OK] Always available
```

**On Windows without Npcap:**
```
Live capture: [WARNING] Npcap not installed. Install from https://npcap.com/
```

---

## info

Show information about a PCAP file without full processing.

```bash
jj info INPUT_PATH
```

### Arguments

| Argument | Description |
|----------|-------------|
| `INPUT_PATH` | PCAP file path |

### Example

```bash
$ jj info capture.pcap
Analyzing: capture.pcap

Packets: 15234
Duration: 125.43 seconds
Packets/sec: 121.45

Protocols:
  TCP: 12543 (82.3%)
  UDP: 2691 (17.7%)
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
| 130 | Interrupted (Ctrl+C) |

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `JOYFULJAY_FLOW_TIMEOUT` | Default flow timeout |
| `JOYFULJAY_MAX_FLOWS` | Default max concurrent flows |
| `JOYFULJAY_NUM_WORKERS` | Default parallel workers |

---

## Shell Completion

### Bash

```bash
# Add to ~/.bashrc
eval "$(_JJ_COMPLETE=bash_source jj)"
```

### Zsh

```bash
# Add to ~/.zshrc
eval "$(_JJ_COMPLETE=zsh_source jj)"
```

### Fish

```bash
# Add to ~/.config/fish/completions/jj.fish
_JJ_COMPLETE=fish_source jj | source
```

---

## See Also

- [Configuration Reference](configuration.md) - All configuration options
- [Feature Groups](extractors/index.md) - Available feature extractors
- [Remote Capture](remote-capture.md) - Detailed remote capture guide
- [Kafka Integration](kafka.md) - Kafka streaming documentation
