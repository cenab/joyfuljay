# Monitoring & Observability

JoyfulJay provides built-in Prometheus metrics for monitoring processing performance, tracking errors, and integrating with observability platforms.

## Installation

```bash
pip install joyfuljay[monitoring]
```

This installs `prometheus-client>=0.17.0` as a dependency.

## Quick Start

### Start Metrics Server

```python
from joyfuljay.monitoring import PrometheusMetrics, start_prometheus_server

# Initialize metrics collector
metrics = PrometheusMetrics()

# Start HTTP server for Prometheus scraping
start_prometheus_server(9090)
# Metrics available at http://localhost:9090/metrics

# Use metrics in your processing pipeline
metrics.observe_packet(packet)
metrics.observe_flow(flow, reason="completed")
metrics.set_active_flows(42)
```

### With Pipeline Processing

```python
from joyfuljay import Pipeline, Config
from joyfuljay.monitoring import PrometheusMetrics, start_prometheus_server
import time

# Setup
metrics = PrometheusMetrics()
start_prometheus_server(9090)

config = Config(features=["all"])
pipeline = Pipeline(config)

# Process with metrics
start = time.perf_counter()
for flow in pipeline.iter_flows("capture.pcap"):
    for packet in flow.packets:
        metrics.observe_packet(packet)
    features = pipeline._extract_features(flow)
    metrics.observe_flow(flow, "completed")

elapsed = time.perf_counter() - start
metrics.observe_processing_time("pcap", elapsed)
```

## Metrics Reference

### Available Metrics

| Metric Name | Type | Labels | Description |
|------------|------|--------|-------------|
| `joyfuljay_packets_total` | Counter | - | Total number of packets processed |
| `joyfuljay_bytes_total` | Counter | - | Total bytes processed (from packet.total_len) |
| `joyfuljay_flows_total` | Counter | `reason` | Flows completed, labeled by reason |
| `joyfuljay_errors_total` | Counter | `stage` | Errors encountered, labeled by pipeline stage |
| `joyfuljay_processing_duration_seconds` | Histogram | `mode` | Processing duration in seconds |
| `joyfuljay_active_flows` | Gauge | - | Current number of active flows |

### Labels

#### `reason` (flows_total)
- `completed` - Flow finished normally
- `timeout` - Flow expired due to inactivity
- `rst` - Flow terminated by TCP RST
- `fin` - Flow closed gracefully with FIN
- `kafka` - Flow sent to Kafka
- Custom values supported

#### `stage` (errors_total)
- `parsing` - Packet parsing error
- `extraction` - Feature extraction error
- `output` - Output writing error
- Custom values supported

#### `mode` (processing_duration_seconds)
- `pcap` - PCAP file processing
- `live` - Live capture
- `remote` - Remote capture
- Custom values supported

## API Reference

### PrometheusMetrics

```python
class PrometheusMetrics:
    def __init__(
        self,
        namespace: str = "joyfuljay",  # Metric prefix
        registry: CollectorRegistry | None = None,  # Custom registry
    ) -> None: ...
```

#### Methods

| Method | Description |
|--------|-------------|
| `observe_packet(packet: Packet)` | Record a processed packet. Increments packets_total and bytes_total. |
| `observe_flow(flow: Flow, reason: str)` | Record a completed flow with the given reason label. |
| `observe_processing_time(mode: str, seconds: float)` | Record processing duration for the given mode. |
| `observe_error(stage: str, error: Exception \| None = None)` | Record an error at the given pipeline stage. |
| `set_active_flows(count: int)` | Set the current number of active flows. |

### start_prometheus_server

```python
def start_prometheus_server(
    port: int,                    # HTTP port to listen on
    addr: str = "0.0.0.0",       # Bind address
    registry: CollectorRegistry | None = None,  # Custom registry
) -> None:
    """Start a Prometheus HTTP metrics server."""
```

### MetricsSink Protocol

For custom metrics backends, implement the `MetricsSink` protocol:

```python
from joyfuljay.monitoring.base import MetricsSink

class CustomMetrics(MetricsSink):
    def observe_packet(self, packet) -> None:
        # Your implementation
        pass

    def observe_flow(self, flow, reason: str) -> None:
        pass

    def observe_processing_time(self, mode: str, seconds: float) -> None:
        pass

    def observe_error(self, stage: str, error: Exception | None = None) -> None:
        pass

    def set_active_flows(self, count: int) -> None:
        pass
```

## Prometheus Configuration

### prometheus.yml

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'joyfuljay'
    static_configs:
      - targets: ['localhost:9090']
    metrics_path: /metrics
```

### Example Queries (PromQL)

```promql
# Packets per second
rate(joyfuljay_packets_total[1m])

# Flows per minute by reason
sum by (reason) (rate(joyfuljay_flows_total[1m])) * 60

# Average bytes per packet
rate(joyfuljay_bytes_total[5m]) / rate(joyfuljay_packets_total[5m])

# Error rate by stage
sum by (stage) (rate(joyfuljay_errors_total[5m]))

# Processing time percentiles
histogram_quantile(0.95, rate(joyfuljay_processing_duration_seconds_bucket[5m]))

# Current active flows
joyfuljay_active_flows
```

## Grafana Dashboard

JoyfulJay includes a pre-built Grafana dashboard for visualizing processing metrics.

### Installing the Dashboard

#### Option 1: Import from File

1. Export the dashboard:
```python
from joyfuljay.monitoring import export_dashboard

export_dashboard("joyfuljay-dashboard.json")
```

2. In Grafana: **Dashboards > Import > Upload JSON file**

#### Option 2: Copy from Dashboards Directory

The dashboard is located at: `dashboards/joyfuljay-overview.json`

#### Option 3: Using the CLI

```bash
# Export dashboard to current directory
jj export-dashboard -o dashboard.json

# Export with custom datasource UID
jj export-dashboard -o dashboard.json --datasource-uid my-prometheus
```

### Dashboard Panels

The overview dashboard includes:

| Section | Panels |
|---------|--------|
| **Overview** | Total Packets, Total Bytes, Total Flows, Active Flows, Total Errors, Packets/sec |
| **Throughput** | Packet Rate, Byte Rate, Flows per Minute, Active Flows over time |
| **Latency** | Processing Duration (p50, p95, p99), Processing Jobs by Mode |
| **Errors** | Errors by Stage, Flow Completion Reasons, Error Distribution |
| **Efficiency** | Average Packet Size, Processing Success Rate |

### Dashboard Variables

The dashboard includes configurable variables:

| Variable | Description |
|----------|-------------|
| `datasource` | Prometheus datasource to use |
| `job` | Filter by Prometheus job name |

### Building Custom Dashboards

Use the `DashboardBuilder` for programmatic dashboard creation:

```python
from joyfuljay.monitoring import DashboardBuilder

builder = DashboardBuilder("My Custom Dashboard")

# Add overview stats
builder.add_row("Overview")
builder.add_stat_panel("Total Packets", "joyfuljay_packets_total")
builder.add_stat_panel("Total Errors", "sum(joyfuljay_errors_total)", width=4)

# Add graphs
builder.add_row("Throughput")
builder.add_graph_panel(
    "Packet Rate",
    "rate(joyfuljay_packets_total[1m])",
    unit="pps",
)
builder.add_graph_panel(
    "Latency Percentiles",
    [
        "histogram_quantile(0.50, rate(joyfuljay_processing_duration_seconds_bucket[5m]))",
        "histogram_quantile(0.95, rate(joyfuljay_processing_duration_seconds_bucket[5m]))",
        "histogram_quantile(0.99, rate(joyfuljay_processing_duration_seconds_bucket[5m]))",
    ],
    legend_format=["p50", "p95", "p99"],
    unit="s",
)

# Export
dashboard = builder.build()
export_dashboard("custom-dashboard.json", dashboard)
```

### Alerting Rules

Generate Prometheus alerting rules:

```python
from joyfuljay.monitoring import generate_alerting_rules

rules = generate_alerting_rules(
    error_threshold=10,      # Alert if >10 errors/sec
    packet_rate_threshold=0, # Alert if no packets
)
print(rules)

# Save to file
with open("joyfuljay-alerts.yml", "w") as f:
    f.write(rules)
```

Generated alerts:
- **JoyfulJayHighErrorRate**: Fires when error rate exceeds threshold
- **JoyfulJayNoPackets**: Fires when no packets are being processed
- **JoyfulJayHighActiveFlows**: Fires when active flows exceed 1000

## Isolated Registries

For testing or running multiple instances, use isolated registries:

```python
from prometheus_client import CollectorRegistry
from joyfuljay.monitoring import PrometheusMetrics

# Create isolated registry
registry = CollectorRegistry()
metrics = PrometheusMetrics(registry=registry)

# Metrics won't conflict with default registry
# Useful for unit tests
```

## Testing

```python
import pytest
from prometheus_client import CollectorRegistry, generate_latest
from joyfuljay.monitoring import PrometheusMetrics
from joyfuljay.core.packet import Packet

def test_metrics():
    registry = CollectorRegistry()
    metrics = PrometheusMetrics(registry=registry)

    # Create test packet
    packet = Packet(
        timestamp=1.0,
        src_ip="192.168.1.1",
        dst_ip="10.0.0.1",
        src_port=12345,
        dst_port=443,
        protocol=6,
        payload_len=100,
        total_len=140,
    )

    # Record metrics
    metrics.observe_packet(packet)
    metrics.observe_flow(object(), "completed")

    # Verify output
    output = generate_latest(registry).decode("utf-8")
    assert "joyfuljay_packets_total 1.0" in output
    assert "joyfuljay_bytes_total 140.0" in output
    assert 'joyfuljay_flows_total{reason="completed"} 1.0' in output
```

## Integration Examples

### With Remote Capture Server

```python
from joyfuljay.remote import Server
from joyfuljay.monitoring import PrometheusMetrics, start_prometheus_server

# Start metrics server
metrics = PrometheusMetrics()
start_prometheus_server(9090)

# Server with metrics
server = Server("wlan0", port=8765)
# Note: Server integration with metrics is manual currently
```

### With Kafka Output

```python
from joyfuljay.output.kafka import KafkaWriter
from joyfuljay.monitoring import PrometheusMetrics

metrics = PrometheusMetrics()

with KafkaWriter("kafka:9092", topic="features") as writer:
    for flow in pipeline.iter_flows("capture.pcap"):
        try:
            features = pipeline._extract_features(flow)
            writer.write(features)
            metrics.observe_flow(flow, "kafka")
        except Exception as e:
            metrics.observe_error("kafka", e)
```
