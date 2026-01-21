# Concepts

Core concepts and design principles behind JoyfulJay.

## Feature Extraction

JoyfulJay extracts ML-ready features from encrypted network traffic using a modular extractor architecture.

- [Feature Schema](schema.md) - Understanding feature definitions and metadata
- [Determinism](determinism.md) - Reproducibility guarantees

## Profiles

Features are organized into stability tiers:

| Profile | Features | Stability | Use Case |
|---------|----------|-----------|----------|
| **JJ-CORE** | 151 | Frozen | Production, published research |
| **JJ-EXTENDED** | 148 | Stable | Advanced analysis |
| **JJ-EXPERIMENTAL** | 102 | Unstable | Prototyping |

See [Reproducibility](../release/reproducibility.md) for profile details.

## Architecture

JoyfulJay uses a pipeline architecture:

```
PCAP → Parser → Flow Aggregator → Extractors → Features
```

- **Parser**: Reads packets using dpkt or scapy backend
- **Flow Aggregator**: Groups packets into bidirectional flows
- **Extractors**: Compute features from flow data
- **Features**: Output as DataFrame, CSV, JSON, or Parquet

See [Architecture](../architecture.md) for detailed design.
