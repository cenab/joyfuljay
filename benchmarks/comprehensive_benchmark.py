#!/usr/bin/env python3
"""
Comprehensive Benchmark Suite for JoyfulJay vs Other Flow Extraction Tools

This script performs real benchmarks comparing:
- JoyfulJay (with different backends and feature sets)
- NFStream
- DPKT raw parsing
- Scapy raw parsing

Run with: python benchmarks/comprehensive_benchmark.py
"""

import sys
from pathlib import Path
# Add src to path for development
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import json
import time
import tracemalloc
import gc
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional

# Benchmark settings
BENCHMARK_DIR = Path(__file__).parent
DATA_DIR = BENCHMARK_DIR / "data"
RESULTS_DIR = BENCHMARK_DIR / "results"
RESULTS_DIR.mkdir(exist_ok=True)

@dataclass
class BenchmarkResult:
    tool: str
    pcap: str
    config: str
    size_mb: float
    packets: int
    time_s: float
    throughput_mbs: float
    pps: float
    flows: int
    features: int
    peak_memory_mb: float
    success: bool
    error: Optional[str] = None


def get_pcap_info(pcap_path: str) -> tuple:
    """Get PCAP size in MB and packet count."""
    import dpkt
    size_mb = Path(pcap_path).stat().st_size / (1024 * 1024)
    packets = 0
    with open(pcap_path, 'rb') as f:
        try:
            pcap = dpkt.pcap.Reader(f)
            for _ in pcap:
                packets += 1
        except:
            pcap = dpkt.pcapng.Reader(f)
            for _ in pcap:
                packets += 1
    return size_mb, packets


def benchmark_joyfuljay(pcap_path: str, features: list, backend_type: str = "scapy") -> BenchmarkResult:
    """Benchmark JoyfulJay with specified features and backend."""
    import joyfuljay as jj

    size_mb, packets = get_pcap_info(pcap_path)
    config_name = f"JoyfulJay-{backend_type}-{'-'.join(features) if len(features) <= 3 else 'all'}"

    gc.collect()
    tracemalloc.start()

    try:
        # Use terminate_on_fin_rst=False for NFStream-compatible flow counts
        # Use flow_timeout=120.0 to match NFStream's default idle timeout
        config = jj.Config(features=features, terminate_on_fin_rst=False, flow_timeout=120.0)

        if backend_type == "dpkt":
            from joyfuljay.capture.dpkt_backend import DpktBackend
            backend = DpktBackend()
        else:
            backend = None  # Uses default Scapy

        pipeline = jj.Pipeline(config, backend=backend)

        start = time.perf_counter()
        df = pipeline.process_pcap(pcap_path)
        elapsed = time.perf_counter() - start

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        return BenchmarkResult(
            tool="JoyfulJay",
            pcap=Path(pcap_path).name,
            config=config_name,
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
        return BenchmarkResult(
            tool="JoyfulJay",
            pcap=Path(pcap_path).name,
            config=config_name,
            size_mb=size_mb,
            packets=packets,
            time_s=0,
            throughput_mbs=0,
            pps=0,
            flows=0,
            features=0,
            peak_memory_mb=0,
            success=False,
            error=str(e)
        )


def benchmark_nfstream(pcap_path: str) -> BenchmarkResult:
    """Benchmark NFStream."""
    from nfstream import NFStreamer

    size_mb, packets = get_pcap_info(pcap_path)

    gc.collect()
    tracemalloc.start()

    try:
        start = time.perf_counter()
        streamer = NFStreamer(source=pcap_path)
        df = streamer.to_pandas()
        elapsed = time.perf_counter() - start

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        return BenchmarkResult(
            tool="NFStream",
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
        return BenchmarkResult(
            tool="NFStream",
            pcap=Path(pcap_path).name,
            config="default",
            size_mb=size_mb,
            packets=packets,
            time_s=0,
            throughput_mbs=0,
            pps=0,
            flows=0,
            features=0,
            peak_memory_mb=0,
            success=False,
            error=str(e)
        )


def benchmark_raw_dpkt(pcap_path: str) -> BenchmarkResult:
    """Benchmark raw DPKT packet parsing speed."""
    import dpkt

    size_mb, packets = get_pcap_info(pcap_path)

    gc.collect()
    tracemalloc.start()

    try:
        start = time.perf_counter()
        count = 0
        with open(pcap_path, 'rb') as f:
            try:
                pcap = dpkt.pcap.Reader(f)
            except:
                f.seek(0)
                pcap = dpkt.pcapng.Reader(f)

            for ts, buf in pcap:
                # Parse Ethernet frame
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if hasattr(eth, 'ip'):
                        count += 1
                except:
                    pass

        elapsed = time.perf_counter() - start
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        return BenchmarkResult(
            tool="Raw-DPKT",
            pcap=Path(pcap_path).name,
            config="parse-only",
            size_mb=size_mb,
            packets=packets,
            time_s=elapsed,
            throughput_mbs=size_mb / elapsed,
            pps=packets / elapsed,
            flows=0,  # No flow aggregation
            features=0,
            peak_memory_mb=peak / (1024 * 1024),
            success=True
        )
    except Exception as e:
        tracemalloc.stop()
        return BenchmarkResult(
            tool="Raw-DPKT",
            pcap=Path(pcap_path).name,
            config="parse-only",
            size_mb=size_mb,
            packets=packets,
            time_s=0,
            throughput_mbs=0,
            pps=0,
            flows=0,
            features=0,
            peak_memory_mb=0,
            success=False,
            error=str(e)
        )


def benchmark_raw_scapy(pcap_path: str) -> BenchmarkResult:
    """Benchmark raw Scapy packet parsing speed."""
    from scapy.all import PcapReader

    size_mb, packets = get_pcap_info(pcap_path)

    gc.collect()
    tracemalloc.start()

    try:
        start = time.perf_counter()
        count = 0
        with PcapReader(pcap_path) as reader:
            for pkt in reader:
                count += 1

        elapsed = time.perf_counter() - start
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        return BenchmarkResult(
            tool="Raw-Scapy",
            pcap=Path(pcap_path).name,
            config="parse-only",
            size_mb=size_mb,
            packets=packets,
            time_s=elapsed,
            throughput_mbs=size_mb / elapsed,
            pps=packets / elapsed,
            flows=0,
            features=0,
            peak_memory_mb=peak / (1024 * 1024),
            success=True
        )
    except Exception as e:
        tracemalloc.stop()
        return BenchmarkResult(
            tool="Raw-Scapy",
            pcap=Path(pcap_path).name,
            config="parse-only",
            size_mb=size_mb,
            packets=packets,
            time_s=0,
            throughput_mbs=0,
            pps=0,
            flows=0,
            features=0,
            peak_memory_mb=0,
            success=False,
            error=str(e)
        )


def run_benchmarks():
    """Run all benchmarks and save results."""
    results = []

    # Find all PCAP files
    pcap_files = list(DATA_DIR.glob("*.pcap"))
    if not pcap_files:
        print(f"No PCAP files found in {DATA_DIR}")
        return

    print("=" * 80)
    print("COMPREHENSIVE BENCHMARK SUITE")
    print("=" * 80)

    for pcap_path in sorted(pcap_files):
        pcap_path = str(pcap_path)
        print(f"\n📁 Processing: {Path(pcap_path).name}")

        # 1. JoyfulJay with all features (Scapy backend)
        print("  → JoyfulJay (all features, Scapy)...", end=" ", flush=True)
        result = benchmark_joyfuljay(pcap_path, ["all"], "scapy")
        if result.success:
            print(f"✓ {result.time_s:.2f}s, {result.flows} flows, {result.features} features")
        else:
            print(f"✗ {result.error}")
        results.append(result)
        gc.collect()

        # 2. JoyfulJay with all features (DPKT backend)
        print("  → JoyfulJay (all features, DPKT)...", end=" ", flush=True)
        result = benchmark_joyfuljay(pcap_path, ["all"], "dpkt")
        if result.success:
            print(f"✓ {result.time_s:.2f}s, {result.flows} flows, {result.features} features")
        else:
            print(f"✗ {result.error}")
        results.append(result)
        gc.collect()

        # 3. JoyfulJay minimal features
        print("  → JoyfulJay (minimal features)...", end=" ", flush=True)
        result = benchmark_joyfuljay(pcap_path, ["flow_meta", "timing"], "dpkt")
        if result.success:
            print(f"✓ {result.time_s:.2f}s, {result.flows} flows, {result.features} features")
        else:
            print(f"✗ {result.error}")
        results.append(result)
        gc.collect()

        # 4. NFStream
        print("  → NFStream...", end=" ", flush=True)
        result = benchmark_nfstream(pcap_path)
        if result.success:
            print(f"✓ {result.time_s:.2f}s, {result.flows} flows, {result.features} features")
        else:
            print(f"✗ {result.error}")
        results.append(result)
        gc.collect()

        # 5. Raw DPKT (packet parsing baseline)
        print("  → Raw DPKT (parse only)...", end=" ", flush=True)
        result = benchmark_raw_dpkt(pcap_path)
        if result.success:
            print(f"✓ {result.time_s:.3f}s, {result.pps:.0f} pps")
        else:
            print(f"✗ {result.error}")
        results.append(result)
        gc.collect()

        # 6. Raw Scapy (packet parsing baseline) - only for small files
        if Path(pcap_path).stat().st_size < 50 * 1024 * 1024:  # < 50MB
            print("  → Raw Scapy (parse only)...", end=" ", flush=True)
            result = benchmark_raw_scapy(pcap_path)
            if result.success:
                print(f"✓ {result.time_s:.3f}s, {result.pps:.0f} pps")
            else:
                print(f"✗ {result.error}")
            results.append(result)
            gc.collect()

    # Save results
    results_file = RESULTS_DIR / "comprehensive_benchmark_results.json"
    with open(results_file, 'w') as f:
        json.dump([asdict(r) for r in results], f, indent=2)
    print(f"\n📊 Results saved to: {results_file}")

    # Print summary table
    print("\n" + "=" * 120)
    print("SUMMARY TABLE")
    print("=" * 120)
    print(f"{'Tool':<30} {'PCAP':<20} {'Time(s)':<10} {'MB/s':<10} {'PPS':<15} {'Flows':<10} {'Features':<10} {'Memory(MB)':<12}")
    print("-" * 120)

    for r in results:
        if r.success:
            print(f"{r.config:<30} {r.pcap:<20} {r.time_s:<10.3f} {r.throughput_mbs:<10.1f} {r.pps:<15,.0f} {r.flows:<10} {r.features:<10} {r.peak_memory_mb:<12.1f}")
        else:
            print(f"{r.config:<30} {r.pcap:<20} {'FAILED':<10} {'-':<10} {'-':<15} {'-':<10} {'-':<10} {'-':<12}")

    print("=" * 120)

    return results


if __name__ == "__main__":
    run_benchmarks()
