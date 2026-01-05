# Integrations

JoyfulJay integrates with popular tools and frameworks for enterprise deployments, machine learning pipelines, and security operations.

---

## Enterprise Integrations

<div class="feature-grid" markdown>

<div class="feature-card" markdown>
### Apache Kafka
Stream features in real-time to Kafka topics for distributed processing.

**Use case:** Real-time monitoring, event-driven architectures

[Learn more →](kafka/index.md)
</div>

<div class="feature-card" markdown>
### Prometheus
Export processing metrics for monitoring and alerting.

**Use case:** Operational monitoring, performance tracking

[Learn more →](prometheus/index.md)
</div>

<div class="feature-card" markdown>
### Grafana
Visualize metrics with pre-built and custom dashboards.

**Use case:** Real-time visualization, dashboards

[Learn more →](grafana/index.md)
</div>

<div class="feature-card" markdown>
### Databases
Write features to PostgreSQL or SQLite for persistence.

**Use case:** Data warehousing, historical analysis

[Learn more →](databases/index.md)
</div>

</div>

---

## ML Framework Integrations

JoyfulJay outputs are designed for seamless integration with popular ML frameworks.

| Framework | Output Format | Guide |
|-----------|---------------|-------|
| **scikit-learn** | DataFrame, NumPy | [Integration Guide](ml-frameworks/scikit-learn.md) |
| **PyTorch** | NumPy, sequences | [Integration Guide](ml-frameworks/pytorch.md) |
| **TensorFlow** | NumPy, sequences | [Integration Guide](ml-frameworks/tensorflow.md) |
| **XGBoost** | DataFrame, NumPy | [Integration Guide](ml-frameworks/xgboost.md) |

---

## Security Tool Integrations

Integrate JoyfulJay into your security operations workflow.

| Tool | Integration Type | Guide |
|------|-----------------|-------|
| **Zeek** | Complementary analysis | [Integration Guide](security-tools/zeek.md) |
| **Elasticsearch** | Data export | [Integration Guide](security-tools/elastic.md) |
| **Splunk** | Data export | [Integration Guide](security-tools/splunk.md) |

---

## Quick Start Examples

### Kafka Streaming

```python
from joyfuljay.output import KafkaWriter
import joyfuljay as jj

config = jj.Config(features=["flow_meta", "timing", "tls"])
pipeline = jj.Pipeline(config)

with KafkaWriter("localhost:9092", topic="network-features") as writer:
    for features in pipeline.iter_features("capture.pcap"):
        writer.write(features)
```

### Prometheus Metrics

```python
from joyfuljay.monitoring import PrometheusMetrics, start_prometheus_server
import joyfuljay as jj

metrics = PrometheusMetrics()
start_prometheus_server(9090)

pipeline = jj.Pipeline(jj.Config(), metrics=metrics)
df = pipeline.process_pcap("capture.pcap")
# Metrics at http://localhost:9090/metrics
```

### scikit-learn Pipeline

```python
import joyfuljay as jj
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline as SKPipeline
from sklearn.preprocessing import StandardScaler

# Extract features
df = jj.extract("labeled_traffic.pcap", features=["timing", "size"])

# Create ML pipeline
X = df.select_dtypes(include=['number']).fillna(0)
y = df['label']

ml_pipeline = SKPipeline([
    ('scaler', StandardScaler()),
    ('classifier', RandomForestClassifier())
])
ml_pipeline.fit(X, y)
```

---

## Installation

Enterprise integrations require optional dependencies:

```bash
# Kafka
pip install joyfuljay[kafka]

# Prometheus monitoring
pip install joyfuljay[monitoring]

# PostgreSQL
pip install joyfuljay[db]

# All integrations
pip install joyfuljay[kafka,monitoring,db]
```

---

## Architecture Overview

```
                    ┌─────────────────┐
                    │   JoyfulJay     │
                    │   Pipeline      │
                    └────────┬────────┘
                             │
         ┌───────────────────┼───────────────────┐
         ▼                   ▼                   ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  Kafka Writer   │  │ Prometheus      │  │  Database       │
│  (streaming)    │  │ Metrics         │  │  Writer         │
└────────┬────────┘  └────────┬────────┘  └────────┬────────┘
         │                    │                    │
         ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  Apache Kafka   │  │  Prometheus     │  │  PostgreSQL/    │
│  Topics         │  │  + Grafana      │  │  SQLite         │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

---

## See Also

- [Real-time Monitoring Tutorial](../tutorials/realtime-monitoring.md) - Complete Kafka + Prometheus setup
- [Production Deployment](../tutorials/advanced/production-deployment.md) - Scaling guide
- [Architecture](../architecture/index.md) - System design details
