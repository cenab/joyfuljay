# Real-time Monitoring

Stream features to Kafka and monitor with Prometheus/Grafana.

---

## Overview

JoyfulJay supports real-time pipelines:

```
Network Interface
      |
      v
  JoyfulJay (live capture)
      |
      +---> Kafka (streaming)
      |
      +---> Prometheus (metrics)
      |
      v
   Grafana (dashboards)
```

---

## Prerequisites

```bash
# Install monitoring dependencies
pip install joyfuljay[kafka,monitoring]

# Or install all extras
pip install joyfuljay[all]
```

---

## Kafka Streaming

### Basic Setup

```python
import joyfuljay as jj
from joyfuljay.output import KafkaWriter

config = jj.Config(features=["flow_meta", "timing", "tls"])
pipeline = jj.Pipeline(config)

# Stream to Kafka
with KafkaWriter("localhost:9092", topic="network-features") as writer:
    for features in pipeline.iter_features("eth0", live=True):
        writer.write(features)
```

### With BPF Filter

```python
import joyfuljay as jj
from joyfuljay.output import KafkaWriter

# Only TLS traffic
config = jj.Config(
    features=["flow_meta", "tls", "fingerprint"],
    bpf_filter="tcp port 443",
)
pipeline = jj.Pipeline(config)

with KafkaWriter("localhost:9092", topic="tls-features") as writer:
    for features in pipeline.iter_features("eth0", live=True):
        writer.write(features)
```

### Kafka Consumer Example

```python
from kafka import KafkaConsumer
import json

consumer = KafkaConsumer(
    "network-features",
    bootstrap_servers=["localhost:9092"],
    value_deserializer=lambda m: json.loads(m.decode("utf-8")),
)

for message in consumer:
    features = message.value
    print(f"Flow: {features['src_ip']} -> {features['dst_ip']}")

    # Process features (anomaly detection, alerting, etc.)
    if features.get("likely_tor"):
        print(f"  [ALERT] Tor traffic detected!")
```

---

## Prometheus Metrics

### Enable Metrics

```python
import joyfuljay as jj
from joyfuljay.monitoring import PrometheusMetrics, start_prometheus_server

# Start metrics server
start_prometheus_server(9090)
print("Metrics available at http://localhost:9090/metrics")

# Create pipeline with metrics
config = jj.Config(features=["flow_meta", "timing"])
pipeline = jj.Pipeline(config)

# Process (metrics are collected automatically)
for features in pipeline.iter_features("eth0", live=True):
    pass  # Metrics updated automatically
```

### Available Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `joyfuljay_packets_total` | Counter | Total packets processed |
| `joyfuljay_flows_total` | Counter | Total flows completed |
| `joyfuljay_flows_active` | Gauge | Currently active flows |
| `joyfuljay_bytes_total` | Counter | Total bytes processed |
| `joyfuljay_processing_seconds` | Histogram | Processing time per flow |
| `joyfuljay_errors_total` | Counter | Processing errors |

### Custom Metrics

```python
from joyfuljay.monitoring import PrometheusMetrics

metrics = PrometheusMetrics()

# Add custom counters
metrics.register_counter("tor_flows_detected", "Tor flows detected")
metrics.register_counter("vpn_flows_detected", "VPN flows detected")

# Increment in processing loop
for features in pipeline.iter_features("eth0", live=True):
    if features.get("likely_tor"):
        metrics.increment("tor_flows_detected")
    if features.get("likely_vpn"):
        metrics.increment("vpn_flows_detected")
```

---

## Grafana Dashboards

### Pre-built Dashboard

JoyfulJay includes a pre-built Grafana dashboard:

```bash
# Export dashboard JSON
jj schema --grafana -o joyfuljay-dashboard.json

# Or find it in the installation
ls dashboards/joyfuljay-overview.json
```

Import into Grafana:
1. Open Grafana (http://localhost:3000)
2. Go to Dashboards > Import
3. Upload `joyfuljay-overview.json`

### Custom Dashboard

```python
from joyfuljay.monitoring import DashboardBuilder, export_dashboard

builder = DashboardBuilder("Network Traffic Analysis")

# Add panels
builder.add_stat_panel(
    title="Active Flows",
    query="joyfuljay_flows_active",
)

builder.add_graph_panel(
    title="Flow Rate",
    query="rate(joyfuljay_flows_total[1m])",
)

builder.add_graph_panel(
    title="Bytes/sec",
    query="rate(joyfuljay_bytes_total[1m])",
)

builder.add_table_panel(
    title="Top Talkers",
    query='topk(10, sum by (src_ip) (joyfuljay_bytes_total))',
)

# Export
export_dashboard("my-dashboard.json", builder.build())
```

---

## Complete Real-time Pipeline

```python
#!/usr/bin/env python3
"""Real-time network monitoring with Kafka and Prometheus."""

import joyfuljay as jj
from joyfuljay.output import KafkaWriter
from joyfuljay.monitoring import PrometheusMetrics, start_prometheus_server
import signal
import sys

# Configuration
INTERFACE = "eth0"
KAFKA_BROKER = "localhost:9092"
KAFKA_TOPIC = "network-features"
PROMETHEUS_PORT = 9090

def main():
    # Start Prometheus metrics server
    start_prometheus_server(PROMETHEUS_PORT)
    print(f"Metrics: http://localhost:{PROMETHEUS_PORT}/metrics")

    # Create custom metrics
    metrics = PrometheusMetrics()
    metrics.register_counter("suspicious_flows", "Suspicious flows detected")

    # Configure extraction
    config = jj.Config(
        features=["flow_meta", "timing", "tls", "fingerprint"],
        flow_timeout=30.0,
    )
    pipeline = jj.Pipeline(config)

    # Graceful shutdown
    running = True
    def signal_handler(sig, frame):
        nonlocal running
        print("\nShutting down...")
        running = False

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print(f"Starting capture on {INTERFACE}...")
    print(f"Streaming to Kafka topic: {KAFKA_TOPIC}")

    with KafkaWriter(KAFKA_BROKER, topic=KAFKA_TOPIC) as writer:
        for features in pipeline.iter_features(INTERFACE, live=True):
            if not running:
                break

            # Write to Kafka
            writer.write(features)

            # Check for suspicious activity
            if features.get("likely_tor") or features.get("likely_vpn"):
                metrics.increment("suspicious_flows")
                print(f"[ALERT] Suspicious: {features['src_ip']} -> {features['dst_ip']}")

    print("Shutdown complete")

if __name__ == "__main__":
    main()
```

---

## Docker Compose Setup

```yaml
# docker-compose.yml
version: "3.8"

services:
  zookeeper:
    image: confluentinc/cp-zookeeper:latest
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181

  kafka:
    image: confluentinc/cp-kafka:latest
    depends_on:
      - zookeeper
    ports:
      - "9092:9092"
    environment:
      KAFKA_BROKER_ID: 1
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://localhost:9092
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    volumes:
      - ./dashboards:/var/lib/grafana/dashboards
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
```

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: "joyfuljay"
    static_configs:
      - targets: ["host.docker.internal:9090"]
```

---

## CLI Commands

```bash
# Start remote capture server with metrics
jj serve eth0 --port 8765 --metrics-port 9090

# Live capture to CSV with filter
jj live eth0 --duration 3600 --filter "port 443" -o tls_traffic.csv

# Watch directory for new PCAPs
jj watch ./incoming --output ./processed --format json
```

---

## Performance Tips

### High-throughput Capture

```python
config = jj.Config(
    features=["flow_meta", "timing"],  # Minimal features
    sampling_rate=0.1,  # Sample 10% of packets
    flow_timeout=15.0,  # Faster flow expiration
)
```

### Batch Writes to Kafka

```python
from joyfuljay.output import KafkaWriter

with KafkaWriter(
    "localhost:9092",
    topic="features",
    batch_size=100,  # Write every 100 flows
    linger_ms=100,   # Or every 100ms
) as writer:
    for features in pipeline.iter_features("eth0", live=True):
        writer.write(features)
```

---

## See Also

- [Remote Capture](../remote-capture.md) - Distributed capture
- [Monitoring Reference](../monitoring.md) - Full monitoring docs
- [Kafka Integration](../kafka.md) - Kafka configuration
