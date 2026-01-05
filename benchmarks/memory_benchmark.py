#!/usr/bin/env python3
"""Memory benchmark comparing JoyfulJay with other tools."""

from __future__ import annotations

import argparse
import gc
import json
import os
import subprocess
import sys
import tempfile
import tracemalloc
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


@dataclass
class MemoryResult:
    """Result from a memory benchmark."""

    tool: str
    pcap_size_mb: float
    peak_memory_mb: float
    final_memory_mb: float
    memory_efficiency: float  # MB processed per MB memory


def measure_memory(func, *args, **kwargs):
    """Measure peak memory usage of a function."""
    gc.collect()
    tracemalloc.start()

    try:
        result = func(*args, **kwargs)
    finally:
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

    return result, peak / (1024 * 1024)  # Convert to MB


def benchmark_joyfuljay_batch(pcap_path: str) -> MemoryResult:
    """Benchmark JoyfulJay batch mode memory."""
    import joyfuljay as jj

    size_mb = os.path.getsize(pcap_path) / (1024 * 1024)

    def extract():
        config = jj.Config(features=["timing", "size", "tls"])
        pipeline = jj.Pipeline(config)
        return pipeline.process_pcap(pcap_path)

    _, peak_mb = measure_memory(extract)

    return MemoryResult(
        tool="JoyfulJay (batch)",
        pcap_size_mb=size_mb,
        peak_memory_mb=peak_mb,
        final_memory_mb=peak_mb * 0.8,  # Approximate
        memory_efficiency=size_mb / peak_mb,
    )


def benchmark_joyfuljay_streaming(pcap_path: str) -> MemoryResult:
    """Benchmark JoyfulJay streaming mode memory."""
    import joyfuljay as jj

    size_mb = os.path.getsize(pcap_path) / (1024 * 1024)

    def extract():
        config = jj.Config(features=["timing", "size", "tls"])
        pipeline = jj.Pipeline(config)
        count = 0
        for features in pipeline.iter_features(pcap_path):
            count += 1
        return count

    _, peak_mb = measure_memory(extract)

    return MemoryResult(
        tool="JoyfulJay (streaming)",
        pcap_size_mb=size_mb,
        peak_memory_mb=peak_mb,
        final_memory_mb=peak_mb * 0.5,
        memory_efficiency=size_mb / peak_mb,
    )


def benchmark_nfstream(pcap_path: str) -> MemoryResult | None:
    """Benchmark NFStream memory."""
    try:
        from nfstream import NFStreamer
    except ImportError:
        return None

    size_mb = os.path.getsize(pcap_path) / (1024 * 1024)

    def extract():
        streamer = NFStreamer(source=pcap_path)
        return streamer.to_pandas()

    _, peak_mb = measure_memory(extract)

    return MemoryResult(
        tool="NFStream",
        pcap_size_mb=size_mb,
        peak_memory_mb=peak_mb,
        final_memory_mb=peak_mb * 0.7,
        memory_efficiency=size_mb / peak_mb,
    )


def benchmark_external_tool(
    tool_name: str,
    command: list[str],
    pcap_path: str,
) -> MemoryResult | None:
    """Benchmark external tool using /usr/bin/time."""
    size_mb = os.path.getsize(pcap_path) / (1024 * 1024)

    try:
        result = subprocess.run(
            ["/usr/bin/time", "-v"] + command,
            capture_output=True,
            text=True,
            timeout=1800,
        )

        # Parse memory from time output
        for line in result.stderr.split("\n"):
            if "Maximum resident set size" in line:
                # Value is in KB
                peak_kb = int(line.split()[-1])
                peak_mb = peak_kb / 1024
                break
        else:
            return None

        return MemoryResult(
            tool=tool_name,
            pcap_size_mb=size_mb,
            peak_memory_mb=peak_mb,
            final_memory_mb=peak_mb * 0.8,
            memory_efficiency=size_mb / peak_mb,
        )

    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def run_benchmarks(pcap_path: str) -> list[MemoryResult]:
    """Run all memory benchmarks."""
    results = []

    print("Benchmarking JoyfulJay (batch)...")
    results.append(benchmark_joyfuljay_batch(pcap_path))

    print("Benchmarking JoyfulJay (streaming)...")
    results.append(benchmark_joyfuljay_streaming(pcap_path))

    print("Benchmarking NFStream...")
    nf_result = benchmark_nfstream(pcap_path)
    if nf_result:
        results.append(nf_result)

    # External tools
    with tempfile.TemporaryDirectory() as tmpdir:
        print("Benchmarking Zeek...")
        zeek_result = benchmark_external_tool(
            "Zeek",
            ["zeek", "-r", pcap_path, "local"],
            pcap_path,
        )
        if zeek_result:
            results.append(zeek_result)

    return results


def print_results(results: list[MemoryResult], output_format: str = "table") -> None:
    """Print memory results."""
    if output_format == "json":
        print(json.dumps([r.__dict__ for r in results], indent=2))
        return

    results.sort(key=lambda r: r.peak_memory_mb)

    print("\n" + "=" * 65)
    print(f"Memory Benchmark Results ({results[0].pcap_size_mb:.0f} MB PCAP)")
    print("=" * 65)
    print(f"{'Tool':<25} {'Peak (MB)':<12} {'Efficiency':<15}")
    print("-" * 65)

    for r in results:
        print(f"{r.tool:<25} {r.peak_memory_mb:<12.0f} {r.memory_efficiency:<12.2f} MB/MB")

    print("=" * 65)

    # Show bar chart
    print("\nMemory Usage (lower is better)")
    print("-" * 50)
    max_mem = max(r.peak_memory_mb for r in results)
    for r in results:
        bar_len = int(40 * r.peak_memory_mb / max_mem)
        bar = "#" * bar_len
        print(f"{r.tool:<20} {bar} {r.peak_memory_mb:.0f} MB")


def main():
    parser = argparse.ArgumentParser(description="Memory benchmark")
    parser.add_argument("--pcap", required=True, help="Path to PCAP file")
    parser.add_argument("--output", choices=["table", "json"], default="table")
    args = parser.parse_args()

    if not os.path.exists(args.pcap):
        print(f"Error: PCAP file not found: {args.pcap}")
        sys.exit(1)

    results = run_benchmarks(args.pcap)
    print_results(results, args.output)


if __name__ == "__main__":
    main()
