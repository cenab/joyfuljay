# JoyfulJay Benchmarks

Reproducible benchmarks comparing JoyfulJay with other network traffic analysis tools.

## Quick Start

```bash
# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -e ..  # Install JoyfulJay from parent directory
pip install nfstream pandas dpkt scapy

# Run comprehensive benchmark
python comprehensive_benchmark.py
```

## Latest Results

Tested on Apple M4 (ARM64), 24GB RAM, macOS 15.1:

```
================================================================================
COMPREHENSIVE BENCHMARK RESULTS
================================================================================
Tool                           PCAP                 Time       Throughput    Flows       Features
--------------------------------------------------------------------------------
JoyfulJay (Scapy, all)         bigFlows.pcap        339.3s     1.0 MB/s      28,471      387
JoyfulJay (DPKT, all)          bigFlows.pcap        96.6s      3.6 MB/s      28,471      387
JoyfulJay (DPKT, minimal)      bigFlows.pcap        63.6s      5.5 MB/s      28,471      60
NFStream                       bigFlows.pcap        9.2s       38.1 MB/s     28,576      38
================================================================================
```

**Key Findings**:
- JoyfulJay extracts **10x more features** (387 vs 38) than NFStream
- Flow counts match between tools when using `terminate_on_fin_rst=False`

## Directory Structure

```
benchmarks/
├── README.md                     # This file
├── comprehensive_benchmark.py    # Main benchmark (JoyfulJay vs NFStream)
├── data/                         # Test PCAP files
│   ├── smallFlows.pcap          # 9 MB test file
│   └── bigFlows.pcap            # 351 MB test file
├── results/                      # JSON benchmark results
│   └── comprehensive_benchmark_results.json
├── speed_benchmark.py            # Speed-focused benchmarks
├── memory_benchmark.py           # Memory profiling
├── feature_benchmark.py          # Feature count analysis
└── run_all.py                    # Run all benchmarks
```

## Benchmark Scripts

### comprehensive_benchmark.py (Recommended)

The main benchmark script that compares:

| Configuration | Description | Features |
|--------------|-------------|----------|
| JoyfulJay (Scapy, all) | All features, Scapy backend | 387 |
| JoyfulJay (DPKT, all) | All features, DPKT backend | 387 |
| JoyfulJay (DPKT, minimal) | Minimal features (flow_meta + timing) | 60 |
| NFStream | Default configuration | 38 |
| Raw DPKT | Packet parsing only (baseline) | 0 |
| Raw Scapy | Packet parsing only (baseline) | 0 |

```bash
python comprehensive_benchmark.py
```

### Other Benchmarks

```bash
python speed_benchmark.py --pcap data/smallFlows.pcap
python memory_benchmark.py --pcap data/smallFlows.pcap
python feature_benchmark.py
python run_all.py
```

## Test Data

### Included Datasets

| Dataset | Size | Packets | Source |
|---------|------|---------|--------|
| `smallFlows.pcap` | 9 MB | 14,261 | ISCX/CIC |
| `bigFlows.pcap` | 351 MB | 791,615 | ISCX/CIC |

### Download Additional Data

```bash
cd data

# CTU Normal dataset
curl -LO https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-20/capture.pcap

# ISCX datasets (requires registration)
# Visit: https://www.unb.ca/cic/datasets/
```

### Recommended Sources

| Source | URL | Description |
|--------|-----|-------------|
| ISCX/CIC | https://www.unb.ca/cic/datasets/ | Labeled network traffic |
| CTU | https://mcfp.felk.cvut.cz/ | Malware captures |
| Wireshark | https://wiki.wireshark.org/SampleCaptures | Various protocols |
| MAWI | http://mawi.wide.ad.jp/ | Backbone traffic |

## Metrics Captured

| Metric | Description |
|--------|-------------|
| `time_s` | Total processing time in seconds |
| `throughput_mbs` | Megabytes processed per second |
| `pps` | Packets per second |
| `flows` | Number of flows extracted |
| `features` | Number of features per flow |
| `peak_memory_mb` | Peak memory usage (via tracemalloc) |

## Results Format

Results are saved as JSON:

```json
{
  "tool": "JoyfulJay",
  "pcap": "bigFlows.pcap",
  "config": "JoyfulJay-dpkt-all",
  "size_mb": 351.0,
  "packets": 791615,
  "time_s": 116.7,
  "throughput_mbs": 3.0,
  "pps": 6783,
  "flows": 52670,
  "features": 387,
  "peak_memory_mb": 2084,
  "success": true
}
```

## Adding New Tools

```python
def benchmark_new_tool(pcap_path: str) -> BenchmarkResult:
    size_mb, packets = get_pcap_info(pcap_path)

    gc.collect()
    tracemalloc.start()

    try:
        start = time.perf_counter()
        # Your tool code here
        df = new_tool.process(pcap_path)
        elapsed = time.perf_counter() - start

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        return BenchmarkResult(
            tool="NewTool",
            pcap=Path(pcap_path).name,
            config="default",
            size_mb=size_mb,
            packets=packets,
            time_s=elapsed,
            throughput_mbs=size_mb / elapsed,
            pps=packets / elapsed,
            flows=len(df),
            features=len(df.columns),
            peak_memory_mb=peak / (1024 * 1024),
            success=True
        )
    except Exception as e:
        tracemalloc.stop()
        return BenchmarkResult(..., success=False, error=str(e))
```

## Known Issues

### Tranalyzer2 on ARM macOS (Apple Silicon)

Tranalyzer2 v0.9.4 has a parsing bug on ARM macOS - the IP header length extraction (`IP_HL` macro) returns 0, triggering "IPv4 header length < 20 bytes" errors. This appears to be a byte-order or memory alignment issue in the ARM build. The packets are read but not parsed as IP traffic.

Workarounds:
- Use on x86_64 Linux (works correctly)
- Use NFStream or JoyfulJay on ARM macOS
- See `docs/benchmarks.md` for Tranalyzer2's published performance numbers

### PyShark asyncio

PyShark has asyncio issues in the benchmark context. Use NFStream for Python-based comparisons.

## Hardware Requirements

For reproducible results:

- CPU: 4+ cores
- RAM: 16 GB+
- Storage: SSD (for PCAP reading)

## See Also

- [docs/benchmarks.md](../docs/benchmarks.md) - Detailed benchmark analysis and charts
- [docs/why-joyfuljay.md](../docs/why-joyfuljay.md) - Feature comparison overview
