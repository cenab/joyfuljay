# Benchmark Protocol

This document describes the exact methodology for reproducing JoyfulJay benchmark results. It is written in the style of a methods section to enable precise replication.

## Test Environment

### Hardware Configuration

| Component | Specification |
|-----------|---------------|
| CPU | Apple M4 (ARM64) |
| RAM | 24 GB |
| Storage | NVMe SSD |
| OS | macOS 15.1 (Darwin 25.1.0) |
| Python | 3.14.0a3 |

### Software Versions

| Package | Version |
|---------|---------|
| JoyfulJay | 0.1.0 |
| dpkt | 1.9.8 |
| scapy | 2.5.0 |
| nfstream | 6.5.3 |
| pandas | 2.2.0 |
| numpy | 1.26.3 |

## Datasets

### Primary Test Files

| Dataset | Size | Packets | Flows | Description |
|---------|------|---------|-------|-------------|
| `smallFlows.pcap` | 9 MB | 14,261 | 641 | Mixed web traffic (ISCX) |
| `bigFlows.pcap` | 351 MB | 791,615 | 28,471 | Enterprise network (CIC) |

### Data Sources

Datasets are from the Canadian Institute for Cybersecurity (CIC) public datasets:
- ISCX-IDS-2012
- CICIDS-2017

## Feature Profile

All benchmarks use the **JJ-CORE v1.0** feature profile unless otherwise specified:

- **Profile**: JJ-CORE
- **Schema Version**: v1.0
- **Feature Count**: 151 features
- **Stability**: Frozen (no breaking changes)

## Extraction Configuration

### Default Configuration

```python
import joyfuljay as jj

config = jj.Config(
    flow_timeout=120.0,           # Flow timeout in seconds
    terminate_on_fin_rst=False,   # Do not terminate flows on FIN/RST
    profile="JJ-CORE",            # Feature profile
    backend="dpkt",               # Packet parsing backend
)
```

### CLI Equivalent

```bash
jj extract bigFlows.pcap \
    --profile JJ-CORE \
    --backend dpkt \
    --flow-timeout 120 \
    --no-terminate-on-fin-rst \
    -o features.csv
```

## Measurement Protocol

### Metrics Collected

| Metric | Description | Method |
|--------|-------------|--------|
| Wall-clock time | Total extraction time | `time.perf_counter()` |
| Peak memory | Maximum memory usage | `tracemalloc.get_traced_memory()` |
| Throughput (MB/s) | File size / time | `file_size_mb / elapsed_seconds` |
| Throughput (PPS) | Packets per second | `packet_count / elapsed_seconds` |
| Flow count | Extracted flows | `len(df)` |
| Feature count | Output columns | `len(df.columns)` |

### Measurement Procedure

1. **Warmup**: Run garbage collection before each measurement
2. **Single run**: Each configuration is run once (not averaged)
3. **Isolation**: No other intensive processes during measurement
4. **Memory tracking**: `tracemalloc` enabled before extraction

```python
import gc
import time
import tracemalloc

gc.collect()
tracemalloc.start()

start = time.perf_counter()
df = jj.extract(pcap_path, config=config)
elapsed = time.perf_counter() - start

current, peak = tracemalloc.get_traced_memory()
tracemalloc.stop()
```

## Reproducibility

### Random Seeds

JoyfulJay feature extraction is deterministic and does not use random seeds. Given the same:
- PCAP file
- JoyfulJay version
- Configuration

The output is **byte-for-byte identical**.

### Configuration Hash

Each benchmark includes a configuration hash for verification:

```python
from joyfuljay.provenance import compute_config_hash

config_hash = compute_config_hash(config.to_dict())
# Returns: "sha256:abc123..."
```

### Provenance Sidecar

Full provenance metadata is written alongside benchmark results:

```bash
ls benchmarks/results/
# comprehensive_benchmark_results.json
# comprehensive_benchmark_results.json.provenance.json
```

## Running Benchmarks

### Full Benchmark Suite

```bash
# Clone repository
git clone https://github.com/cenab/joyfuljay.git
cd joyfuljay

# Create virtual environment
python -m venv benchmarks/.venv
source benchmarks/.venv/bin/activate

# Install dependencies
pip install -e .
pip install nfstream pandas dpkt scapy

# Run comprehensive benchmarks
python benchmarks/comprehensive_benchmark.py
```

### Individual Configuration

```bash
# Run with specific backend
python -m benchmarks.run \
    --pcap data/bigFlows.pcap \
    --backend dpkt \
    --profile JJ-CORE \
    --output results/benchmark.json
```

## Comparison Methodology

### Fair Comparison

When comparing with other tools:

1. **Same flow definition**: Bidirectional 5-tuple
2. **Same timeout**: 120 seconds idle timeout
3. **Same dataset**: Identical PCAP file
4. **Same hardware**: All measurements on same machine

### NFStream Comparison Settings

```python
from nfstream import NFStreamer

streamer = NFStreamer(
    source="bigFlows.pcap",
    idle_timeout=120,
    active_timeout=1800,
)
df = streamer.to_pandas()
```

## Results Reporting

### Required Information

When citing benchmark results, include:

1. JoyfulJay version (e.g., `0.1.0`)
2. Feature profile (e.g., `JJ-CORE v1.0`)
3. Schema version (e.g., `v1.0`)
4. Backend (e.g., `dpkt`)
5. Hardware specification
6. Dataset description
7. Configuration hash

### Example Citation

> Benchmarks were performed using JoyfulJay v0.1.0 with the JJ-CORE v1.0
> feature profile (151 features) on an Apple M4 system with 24 GB RAM.
> The bigFlows.pcap dataset (351 MB, 791,615 packets) was processed
> with a 120-second flow timeout using the dpkt backend, achieving
> 3.6 MB/s throughput and extracting 28,471 flows with 387 features each.

## Known Limitations

### Platform-Specific Notes

- **ARM macOS**: Tranalyzer2 v0.9.4 has an IP header parsing bug on Apple Silicon
- **Memory reporting**: `tracemalloc` may underreport total Python process memory
- **Flow counting**: Different tools may count flows differently at timeouts

### Comparison Caveats

- Published performance numbers for other tools may use different hardware
- Feature counts are for default configurations
- Some tools have configurable feature sets
