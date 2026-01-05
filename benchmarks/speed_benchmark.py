#!/usr/bin/env python3
"""Speed benchmark comparing JoyfulJay with other tools."""

from __future__ import annotations

import argparse
import gc
import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


@dataclass
class BenchmarkResult:
    """Result from a single benchmark run."""

    tool: str
    pcap_size_mb: float
    duration_seconds: float
    throughput_mbps: float
    packets_per_second: float
    flows_extracted: int


def get_pcap_info(pcap_path: str) -> tuple[float, int]:
    """Get PCAP size in MB and packet count."""
    size_mb = os.path.getsize(pcap_path) / (1024 * 1024)

    # Try to get packet count with capinfos or tshark
    try:
        result = subprocess.run(
            ["capinfos", "-c", pcap_path],
            capture_output=True,
            text=True,
            timeout=60,
        )
        for line in result.stdout.split("\n"):
            if "Number of packets" in line:
                return size_mb, int(line.split()[-1])
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Fallback: estimate from file size
    return size_mb, int(size_mb * 1400)  # ~1400 packets per MB average


def benchmark_joyfuljay_dpkt(pcap_path: str) -> BenchmarkResult:
    """Benchmark JoyfulJay with DPKT backend."""
    import joyfuljay as jj

    size_mb, packet_count = get_pcap_info(pcap_path)

    gc.collect()
    start = time.perf_counter()

    config = jj.Config(features=["timing", "size", "tls"], capture_backend="dpkt")
    pipeline = jj.Pipeline(config)
    df = pipeline.process_pcap(pcap_path)

    duration = time.perf_counter() - start

    return BenchmarkResult(
        tool="JoyfulJay (DPKT)",
        pcap_size_mb=size_mb,
        duration_seconds=duration,
        throughput_mbps=size_mb / duration,
        packets_per_second=packet_count / duration,
        flows_extracted=len(df),
    )


def benchmark_joyfuljay_scapy(pcap_path: str) -> BenchmarkResult:
    """Benchmark JoyfulJay with Scapy backend."""
    import joyfuljay as jj

    size_mb, packet_count = get_pcap_info(pcap_path)

    gc.collect()
    start = time.perf_counter()

    config = jj.Config(features=["timing", "size", "tls"], capture_backend="scapy")
    pipeline = jj.Pipeline(config)
    df = pipeline.process_pcap(pcap_path)

    duration = time.perf_counter() - start

    return BenchmarkResult(
        tool="JoyfulJay (Scapy)",
        pcap_size_mb=size_mb,
        duration_seconds=duration,
        throughput_mbps=size_mb / duration,
        packets_per_second=packet_count / duration,
        flows_extracted=len(df),
    )


def benchmark_nfstream(pcap_path: str) -> BenchmarkResult | None:
    """Benchmark NFStream."""
    try:
        from nfstream import NFStreamer
    except ImportError:
        print("NFStream not installed, skipping...")
        return None

    size_mb, packet_count = get_pcap_info(pcap_path)

    gc.collect()
    start = time.perf_counter()

    streamer = NFStreamer(source=pcap_path)
    df = streamer.to_pandas()

    duration = time.perf_counter() - start

    return BenchmarkResult(
        tool="NFStream",
        pcap_size_mb=size_mb,
        duration_seconds=duration,
        throughput_mbps=size_mb / duration,
        packets_per_second=packet_count / duration,
        flows_extracted=len(df),
    )


def benchmark_pyshark(pcap_path: str) -> BenchmarkResult | None:
    """Benchmark PyShark (for reference - known to be slow)."""
    try:
        import pyshark
    except ImportError:
        print("PyShark not installed, skipping...")
        return None

    size_mb, packet_count = get_pcap_info(pcap_path)

    # PyShark is very slow, limit to small files
    if size_mb > 100:
        print(f"Skipping PyShark for {size_mb:.0f}MB file (too slow)")
        return None

    gc.collect()
    start = time.perf_counter()

    cap = pyshark.FileCapture(pcap_path)
    flows = {}
    for pkt in cap:
        try:
            key = (pkt.ip.src, pkt.ip.dst, pkt[pkt.transport_layer].srcport)
            flows[key] = flows.get(key, 0) + 1
        except AttributeError:
            pass
    cap.close()

    duration = time.perf_counter() - start

    return BenchmarkResult(
        tool="PyShark",
        pcap_size_mb=size_mb,
        duration_seconds=duration,
        throughput_mbps=size_mb / duration,
        packets_per_second=packet_count / duration,
        flows_extracted=len(flows),
    )


def benchmark_cicflowmeter(pcap_path: str, jar_path: str | None = None) -> BenchmarkResult | None:
    """Benchmark CICFlowMeter."""
    if jar_path is None:
        jar_path = os.environ.get("CICFLOWMETER_JAR")

    if not jar_path or not os.path.exists(jar_path):
        print("CICFlowMeter JAR not found, skipping...")
        return None

    size_mb, packet_count = get_pcap_info(pcap_path)

    with tempfile.TemporaryDirectory() as tmpdir:
        gc.collect()
        start = time.perf_counter()

        result = subprocess.run(
            ["java", "-jar", jar_path, pcap_path, tmpdir],
            capture_output=True,
            timeout=1800,  # 30 min timeout
        )

        duration = time.perf_counter() - start

        # Count output rows
        flows = 0
        for csv_file in Path(tmpdir).glob("*.csv"):
            with open(csv_file) as f:
                flows += sum(1 for _ in f) - 1  # -1 for header

    return BenchmarkResult(
        tool="CICFlowMeter",
        pcap_size_mb=size_mb,
        duration_seconds=duration,
        throughput_mbps=size_mb / duration,
        packets_per_second=packet_count / duration,
        flows_extracted=flows,
    )


def benchmark_zeek(pcap_path: str) -> BenchmarkResult | None:
    """Benchmark Zeek."""
    try:
        subprocess.run(["zeek", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Zeek not installed, skipping...")
        return None

    size_mb, packet_count = get_pcap_info(pcap_path)

    with tempfile.TemporaryDirectory() as tmpdir:
        gc.collect()
        start = time.perf_counter()

        subprocess.run(
            ["zeek", "-r", pcap_path, "local"],
            cwd=tmpdir,
            capture_output=True,
            timeout=1800,
        )

        duration = time.perf_counter() - start

        # Count conn.log rows
        flows = 0
        conn_log = Path(tmpdir) / "conn.log"
        if conn_log.exists():
            with open(conn_log) as f:
                flows = sum(1 for line in f if not line.startswith("#"))

    return BenchmarkResult(
        tool="Zeek",
        pcap_size_mb=size_mb,
        duration_seconds=duration,
        throughput_mbps=size_mb / duration,
        packets_per_second=packet_count / duration,
        flows_extracted=flows,
    )


def run_benchmarks(
    pcap_path: str,
    runs: int = 5,
    warmup: int = 1,
    tools: list[str] | None = None,
) -> list[BenchmarkResult]:
    """Run all benchmarks."""
    all_benchmarks: dict[str, Callable] = {
        "joyfuljay-dpkt": benchmark_joyfuljay_dpkt,
        "joyfuljay-scapy": benchmark_joyfuljay_scapy,
        "nfstream": benchmark_nfstream,
        "pyshark": benchmark_pyshark,
        "zeek": benchmark_zeek,
    }

    if tools:
        all_benchmarks = {k: v for k, v in all_benchmarks.items() if k in tools}

    results = []

    for name, benchmark_fn in all_benchmarks.items():
        print(f"\nBenchmarking {name}...")

        # Warmup runs
        for i in range(warmup):
            print(f"  Warmup {i + 1}/{warmup}...")
            try:
                benchmark_fn(pcap_path)
            except Exception as e:
                print(f"  Warmup failed: {e}")
                break

        # Actual runs
        run_results = []
        for i in range(runs):
            print(f"  Run {i + 1}/{runs}...")
            try:
                result = benchmark_fn(pcap_path)
                if result:
                    run_results.append(result)
            except Exception as e:
                print(f"  Run failed: {e}")

        if run_results:
            # Use median result
            run_results.sort(key=lambda r: r.duration_seconds)
            median_result = run_results[len(run_results) // 2]
            results.append(median_result)
            print(f"  Median: {median_result.duration_seconds:.2f}s")

    return results


def print_results(results: list[BenchmarkResult], output_format: str = "table") -> None:
    """Print benchmark results."""
    if output_format == "json":
        print(json.dumps([r.__dict__ for r in results], indent=2))
        return

    if output_format == "csv":
        print("tool,pcap_size_mb,duration_seconds,throughput_mbps,packets_per_second,flows")
        for r in results:
            print(f"{r.tool},{r.pcap_size_mb:.1f},{r.duration_seconds:.2f},"
                  f"{r.throughput_mbps:.1f},{r.packets_per_second:.0f},{r.flows_extracted}")
        return

    # Table format
    results.sort(key=lambda r: r.duration_seconds)

    print("\n" + "=" * 70)
    print(f"Speed Benchmark Results ({results[0].pcap_size_mb:.0f} MB PCAP)")
    print("=" * 70)
    print(f"{'Tool':<25} {'Time (s)':<12} {'Throughput':<15} {'Speedup':<10}")
    print("-" * 70)

    baseline = results[-1].duration_seconds  # Slowest is baseline

    for r in results:
        speedup = baseline / r.duration_seconds
        print(f"{r.tool:<25} {r.duration_seconds:<12.2f} {r.throughput_mbps:<12.1f} MB/s {speedup:<10.1f}x")

    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(description="Speed benchmark for traffic analysis tools")
    parser.add_argument("--pcap", required=True, help="Path to PCAP file")
    parser.add_argument("--runs", type=int, default=5, help="Number of benchmark runs")
    parser.add_argument("--warmup", type=int, default=1, help="Number of warmup runs")
    parser.add_argument("--output", choices=["table", "json", "csv"], default="table")
    parser.add_argument("--tools", nargs="+", help="Specific tools to benchmark")
    args = parser.parse_args()

    if not os.path.exists(args.pcap):
        print(f"Error: PCAP file not found: {args.pcap}")
        sys.exit(1)

    results = run_benchmarks(
        args.pcap,
        runs=args.runs,
        warmup=args.warmup,
        tools=args.tools,
    )

    print_results(results, args.output)


if __name__ == "__main__":
    main()
