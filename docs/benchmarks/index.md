# Benchmarks

Performance benchmarks comparing JoyfulJay with other network traffic feature extraction tools.

## Overview

JoyfulJay prioritizes feature richness over raw speed, extracting **387 features** compared to 38-112 for other tools.

| Tool | Features | Throughput | Python Native |
|------|----------|------------|---------------|
| **JoyfulJay** | **387** | 3.6 MB/s | Yes |
| Tranalyzer2 | 112 | 1-10 Gbps | No |
| CICFlowMeter | 84 | ~50 MB/s | No |
| NFStream | 38 | 38 MB/s | Yes |

## Documentation

- [Benchmark Protocol](benchmark-protocol.md) - Exact methodology for reproducing benchmarks
- [Performance Comparison](../benchmarks.md) - Detailed comparison with other tools

## Quick Results

### Feature Extraction Trade-off

```
Speed vs Features
═══════════════════════════════════════════════════════

Tranalyzer2     Speed: ████████████████████  1-10 Gbps
                Features: ████  112

JoyfulJay       Speed: █  3.6 MB/s
                Features: ████████████████████  387

═══════════════════════════════════════════════════════
Choose Tranalyzer2 for SPEED, JoyfulJay for FEATURES
```

## Running Benchmarks

```bash
# Install benchmark dependencies
pip install -e ".[benchmark]"

# Run comprehensive benchmarks
python benchmarks/comprehensive_benchmark.py

# Results are written to benchmarks/results/
```

See [Benchmark Protocol](benchmark-protocol.md) for detailed methodology.
