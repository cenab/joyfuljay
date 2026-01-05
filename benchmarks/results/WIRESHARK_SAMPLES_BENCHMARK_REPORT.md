# Wireshark Sample Captures Benchmark Report

Comprehensive benchmark of JoyfulJay vs NFStream on 498 Wireshark sample captures.

## Summary

| Metric | JoyfulJay | NFStream | Winner |
|--------|-----------|----------|--------|
| **Success Rate** | **470/498 (94.4%)** | 379/498 (76.1%) | **JoyfulJay** |
| **Total Flows** | **30,662** | 18,930 | **JoyfulJay** (+62%) |
| **Avg Features** | **368** | 38 | **JoyfulJay** (10x more) |
| **Processing Time** | 31.45s | **18.24s** | **NFStream** (1.7x faster) |
| **Throughput** | 9.14 MB/s | **15.77 MB/s** | **NFStream** |

## Key Findings

### 1. JoyfulJay Has Higher Protocol Coverage

JoyfulJay successfully processed **91 more files** than NFStream (470 vs 379). Files that JoyfulJay handles but NFStream doesn't include:
- Various Layer 2 protocols (CDP, LLDP, STP)
- Wireless protocols (Wi-SUN, 802.15.4)
- Industrial protocols (DNP3, Modbus)
- Specialized encapsulations (ERSPAN, GRE variants)

### 2. JoyfulJay Extracts More Flows

JoyfulJay extracted **62% more flows** (30,662 vs 18,930) from the same capture files. This is due to:
- Better handling of encapsulated traffic
- Detection of flows in non-standard encapsulations
- Support for more protocol combinations

### 3. Feature Extraction Comparison

```
Features per Flow - Higher is Better for ML
================================================================================

JoyfulJay             ████████████████████████████████████████████████████  368
NFStream              █████                                                  38

================================================================================
```

JoyfulJay extracts **10x more features** per flow, including:
- TLS fingerprinting (JA3/JA3S, JA4)
- SSH fingerprinting (HASSH)
- TCP analysis (26 features)
- Timing patterns (20+ features)
- Size distributions (15+ features)
- Entropy analysis
- Connection graphs

### 4. Processing Speed

NFStream is approximately **1.7x faster** (15.77 MB/s vs 9.14 MB/s).

This trade-off makes sense:
- **NFStream**: Uses C-based nDPI library with 38 features
- **JoyfulJay**: Pure Python with 368 features (10x more computation)

## Test Dataset

- **Files**: 498 Wireshark sample captures
- **Total Size**: 287.6 MB
- **Protocols**: DNS, HTTP, TLS, SSH, QUIC, BGP, SIP, RTP, industrial protocols, etc.
- **Source**: https://wiki.wireshark.org/SampleCaptures

## Failure Analysis

### JoyfulJay Failures (28 files, 5.6%)

| Reason | Count | Examples |
|--------|-------|----------|
| Invalid tcpdump header | 15 | Bluetooth, FCoE, special encaps |
| Slice error (parsing) | 3 | GRE variants |
| Unsupported format | 10 | NTAR, specialized formats |

### NFStream Failures (119 files, 23.9%)

| Reason | Count | Examples |
|--------|-------|----------|
| No IP traffic | 91 | Layer 2 only, ARP, CDP, LLDP |
| Format issues | 28 | Bluetooth, specialized |

## Conclusion

**For ML/Research Applications**: JoyfulJay is the clear choice:
- 10x more features per flow
- Better protocol coverage (94% vs 76% success rate)
- 62% more flows extracted

**For High-Speed Processing**: NFStream is faster but extracts fewer features:
- 1.7x faster throughput
- Lower feature count limits ML applications
- More files fail to process

## Running This Benchmark

```bash
cd benchmarks
source ../.venv/bin/activate

# Download all Wireshark samples
python download_all_samples.py

# Run benchmark
python benchmark_all_wireshark.py
```

---
*Generated: 2026-01-04*
*Platform: Apple M4 (ARM64), macOS 15.1*
