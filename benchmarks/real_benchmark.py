#!/usr/bin/env python3
"""Real benchmark runner for JoyfulJay vs competitors."""

from __future__ import annotations

import gc
import json
import os
import subprocess
import sys
import tempfile
import time
import traceback
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

# Configuration
T2_BINARY = "/Users/batu/Documents/DEVELOPMENT/tranalyzer2-0.9.4/tranalyzer2/build/tranalyzer"
BENCHMARK_DIR = Path(__file__).parent
DATA_DIR = BENCHMARK_DIR / "data"
RESULTS_DIR = BENCHMARK_DIR / "results"

# Add project src to path
sys.path.insert(0, str(BENCHMARK_DIR.parent / "src"))


@dataclass
class BenchmarkResult:
    """Result from a benchmark run."""
    tool: str
    pcap_file: str
    pcap_size_mb: float
    packet_count: int
    duration_seconds: float
    throughput_mbps: float
    packets_per_second: float
    flows_extracted: int
    feature_count: int
    peak_memory_mb: float
    error: str | None = None


def get_pcap_info(pcap_path: str) -> tuple[float, int]:
    """Get PCAP size in MB and packet count."""
    size_mb = os.path.getsize(pcap_path) / (1024 * 1024)

    try:
        result = subprocess.run(
            ["tshark", "-r", pcap_path, "-q", "-z", "io,stat,0"],
            capture_output=True, text=True, timeout=60
        )
        for line in result.stdout.split("\n"):
            if "|" in line and "Frames" not in line and "Interval" in line:
                continue
            parts = line.split("|")
            if len(parts) >= 3:
                try:
                    frames = int(parts[1].strip().split()[0])
                    return size_mb, frames
                except (ValueError, IndexError):
                    continue
    except Exception:
        pass

    # Fallback estimate
    return size_mb, int(size_mb * 1500)


def measure_memory_subprocess(cmd: list[str], timeout: int = 300) -> tuple[float, str, str]:
    """Run command and measure peak memory using /usr/bin/time."""
    try:
        # On macOS, use gtime if available, otherwise /usr/bin/time
        time_cmd = "gtime" if subprocess.run(["which", "gtime"], capture_output=True).returncode == 0 else "/usr/bin/time"

        if time_cmd == "/usr/bin/time":
            # macOS /usr/bin/time uses -l for memory
            result = subprocess.run(
                [time_cmd, "-l"] + cmd,
                capture_output=True, text=True, timeout=timeout
            )
            # Parse macOS time output - look for "maximum resident set size"
            for line in result.stderr.split("\n"):
                if "maximum resident set size" in line.lower():
                    # Value is in bytes on macOS
                    mem_bytes = int(line.strip().split()[0])
                    return mem_bytes / (1024 * 1024), result.stdout, result.stderr
        else:
            # GNU time
            result = subprocess.run(
                [time_cmd, "-v"] + cmd,
                capture_output=True, text=True, timeout=timeout
            )
            for line in result.stderr.split("\n"):
                if "Maximum resident set size" in line:
                    mem_kb = int(line.split()[-1])
                    return mem_kb / 1024, result.stdout, result.stderr
    except Exception as e:
        print(f"Memory measurement failed: {e}")

    return 0.0, "", ""


def benchmark_joyfuljay(pcap_path: str, backend: str = "scapy") -> BenchmarkResult:
    """Benchmark JoyfulJay."""
    import joyfuljay as jj

    size_mb, packet_count = get_pcap_info(pcap_path)
    pcap_name = os.path.basename(pcap_path)

    try:
        gc.collect()

        # Time the extraction
        start = time.perf_counter()
        config = jj.Config(features=["all"])
        pipeline = jj.Pipeline(config)
        df = pipeline.process_pcap(pcap_path)
        duration = time.perf_counter() - start

        flows = len(df)
        features = len(df.columns)

        # Get memory (approximate - run again with memory tracking)
        # For now, use tracemalloc
        import tracemalloc
        tracemalloc.start()
        gc.collect()

        config2 = jj.Config(features=["all"])
        pipeline2 = jj.Pipeline(config2)
        _ = pipeline2.process_pcap(pcap_path)

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peak_mb = peak / (1024 * 1024)

        return BenchmarkResult(
            tool=f"JoyfulJay",
            pcap_file=pcap_name,
            pcap_size_mb=size_mb,
            packet_count=packet_count,
            duration_seconds=duration,
            throughput_mbps=size_mb / duration if duration > 0 else 0,
            packets_per_second=packet_count / duration if duration > 0 else 0,
            flows_extracted=flows,
            feature_count=features,
            peak_memory_mb=peak_mb,
        )
    except Exception as e:
        return BenchmarkResult(
            tool="JoyfulJay",
            pcap_file=pcap_name,
            pcap_size_mb=size_mb,
            packet_count=packet_count,
            duration_seconds=0,
            throughput_mbps=0,
            packets_per_second=0,
            flows_extracted=0,
            feature_count=0,
            peak_memory_mb=0,
            error=str(e),
        )


def benchmark_nfstream(pcap_path: str) -> BenchmarkResult:
    """Benchmark NFStream."""
    from nfstream import NFStreamer

    size_mb, packet_count = get_pcap_info(pcap_path)
    pcap_name = os.path.basename(pcap_path)

    try:
        gc.collect()

        import tracemalloc
        tracemalloc.start()

        start = time.perf_counter()
        streamer = NFStreamer(source=pcap_path)
        df = streamer.to_pandas()
        duration = time.perf_counter() - start

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        return BenchmarkResult(
            tool="NFStream",
            pcap_file=pcap_name,
            pcap_size_mb=size_mb,
            packet_count=packet_count,
            duration_seconds=duration,
            throughput_mbps=size_mb / duration if duration > 0 else 0,
            packets_per_second=packet_count / duration if duration > 0 else 0,
            flows_extracted=len(df),
            feature_count=len(df.columns),
            peak_memory_mb=peak / (1024 * 1024),
        )
    except Exception as e:
        return BenchmarkResult(
            tool="NFStream",
            pcap_file=pcap_name,
            pcap_size_mb=size_mb,
            packet_count=packet_count,
            duration_seconds=0,
            throughput_mbps=0,
            packets_per_second=0,
            flows_extracted=0,
            feature_count=0,
            peak_memory_mb=0,
            error=str(e),
        )


def benchmark_tranalyzer2(pcap_path: str) -> BenchmarkResult:
    """Benchmark Tranalyzer2."""
    size_mb, packet_count = get_pcap_info(pcap_path)
    pcap_name = os.path.basename(pcap_path)

    if not os.path.exists(T2_BINARY):
        return BenchmarkResult(
            tool="Tranalyzer2",
            pcap_file=pcap_name,
            pcap_size_mb=size_mb,
            packet_count=packet_count,
            duration_seconds=0,
            throughput_mbps=0,
            packets_per_second=0,
            flows_extracted=0,
            feature_count=0,
            peak_memory_mb=0,
            error=f"T2 binary not found at {T2_BINARY}",
        )

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            gc.collect()

            start = time.perf_counter()

            # Run T2
            result = subprocess.run(
                [T2_BINARY, "-r", pcap_path, "-w", tmpdir],
                capture_output=True, text=True, timeout=600
            )

            duration = time.perf_counter() - start

            # Count flows from output
            flows = 0
            features = 0
            for f in Path(tmpdir).glob("*_flows.txt"):
                with open(f) as fp:
                    lines = fp.readlines()
                    # First line is header
                    if lines:
                        features = len(lines[0].split("\t"))
                        flows = len(lines) - 1  # Subtract header

            # Get memory by running again with time
            peak_mb, _, _ = measure_memory_subprocess(
                [T2_BINARY, "-r", pcap_path, "-w", tmpdir]
            )

            return BenchmarkResult(
                tool="Tranalyzer2",
                pcap_file=pcap_name,
                pcap_size_mb=size_mb,
                packet_count=packet_count,
                duration_seconds=duration,
                throughput_mbps=size_mb / duration if duration > 0 else 0,
                packets_per_second=packet_count / duration if duration > 0 else 0,
                flows_extracted=flows,
                feature_count=features,
                peak_memory_mb=peak_mb,
            )
    except Exception as e:
        traceback.print_exc()
        return BenchmarkResult(
            tool="Tranalyzer2",
            pcap_file=pcap_name,
            pcap_size_mb=size_mb,
            packet_count=packet_count,
            duration_seconds=0,
            throughput_mbps=0,
            packets_per_second=0,
            flows_extracted=0,
            feature_count=0,
            peak_memory_mb=0,
            error=str(e),
        )


def benchmark_scapy_manual(pcap_path: str) -> BenchmarkResult:
    """Benchmark manual Scapy extraction (baseline)."""
    from scapy.all import rdpcap, IP, TCP, UDP

    size_mb, packet_count = get_pcap_info(pcap_path)
    pcap_name = os.path.basename(pcap_path)

    # Only run on small files
    if size_mb > 50:
        return BenchmarkResult(
            tool="Scapy (manual)",
            pcap_file=pcap_name,
            pcap_size_mb=size_mb,
            packet_count=packet_count,
            duration_seconds=0,
            throughput_mbps=0,
            packets_per_second=0,
            flows_extracted=0,
            feature_count=0,
            peak_memory_mb=0,
            error="Skipped (file too large for Scapy)",
        )

    try:
        gc.collect()

        import tracemalloc
        tracemalloc.start()

        start = time.perf_counter()

        packets = rdpcap(pcap_path)
        flows = {}
        for pkt in packets:
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                proto = pkt[IP].proto
                sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
                dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
                key = (src, dst, sport, dport, proto)
                if key not in flows:
                    flows[key] = {"packets": 0, "bytes": 0}
                flows[key]["packets"] += 1
                flows[key]["bytes"] += len(pkt)

        duration = time.perf_counter() - start

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        return BenchmarkResult(
            tool="Scapy (manual)",
            pcap_file=pcap_name,
            pcap_size_mb=size_mb,
            packet_count=packet_count,
            duration_seconds=duration,
            throughput_mbps=size_mb / duration if duration > 0 else 0,
            packets_per_second=packet_count / duration if duration > 0 else 0,
            flows_extracted=len(flows),
            feature_count=2,  # Just packets and bytes
            peak_memory_mb=peak / (1024 * 1024),
        )
    except Exception as e:
        return BenchmarkResult(
            tool="Scapy (manual)",
            pcap_file=pcap_name,
            pcap_size_mb=size_mb,
            packet_count=packet_count,
            duration_seconds=0,
            throughput_mbps=0,
            packets_per_second=0,
            flows_extracted=0,
            feature_count=0,
            peak_memory_mb=0,
            error=str(e),
        )


def benchmark_pyshark(pcap_path: str) -> BenchmarkResult:
    """Benchmark PyShark."""
    import pyshark

    size_mb, packet_count = get_pcap_info(pcap_path)
    pcap_name = os.path.basename(pcap_path)

    # Only run on small files - PyShark is very slow
    if size_mb > 20:
        return BenchmarkResult(
            tool="PyShark",
            pcap_file=pcap_name,
            pcap_size_mb=size_mb,
            packet_count=packet_count,
            duration_seconds=0,
            throughput_mbps=0,
            packets_per_second=0,
            flows_extracted=0,
            feature_count=0,
            peak_memory_mb=0,
            error="Skipped (file too large for PyShark)",
        )

    try:
        gc.collect()

        start = time.perf_counter()

        cap = pyshark.FileCapture(pcap_path)
        flows = {}
        pkt_count = 0
        for pkt in cap:
            pkt_count += 1
            try:
                if hasattr(pkt, 'ip'):
                    src = pkt.ip.src
                    dst = pkt.ip.dst
                    proto = pkt.transport_layer if hasattr(pkt, 'transport_layer') else 'unknown'
                    sport = pkt[proto].srcport if proto and hasattr(pkt, proto) else 0
                    dport = pkt[proto].dstport if proto and hasattr(pkt, proto) else 0
                    key = (src, dst, sport, dport, proto)
                    flows[key] = flows.get(key, 0) + 1
            except Exception:
                pass
        cap.close()

        duration = time.perf_counter() - start

        return BenchmarkResult(
            tool="PyShark",
            pcap_file=pcap_name,
            pcap_size_mb=size_mb,
            packet_count=packet_count,
            duration_seconds=duration,
            throughput_mbps=size_mb / duration if duration > 0 else 0,
            packets_per_second=pkt_count / duration if duration > 0 else 0,
            flows_extracted=len(flows),
            feature_count=1,  # Just count
            peak_memory_mb=0,  # Hard to measure with pyshark
        )
    except Exception as e:
        return BenchmarkResult(
            tool="PyShark",
            pcap_file=pcap_name,
            pcap_size_mb=size_mb,
            packet_count=packet_count,
            duration_seconds=0,
            throughput_mbps=0,
            packets_per_second=0,
            flows_extracted=0,
            feature_count=0,
            peak_memory_mb=0,
            error=str(e),
        )


def run_all_benchmarks(pcap_files: list[str], runs: int = 3) -> list[BenchmarkResult]:
    """Run all benchmarks."""
    all_results = []

    for pcap_path in pcap_files:
        print(f"\n{'='*60}")
        print(f"Benchmarking: {os.path.basename(pcap_path)}")
        print(f"{'='*60}")

        size_mb, packets = get_pcap_info(pcap_path)
        print(f"Size: {size_mb:.1f} MB, Packets: {packets:,}")

        benchmarks = [
            ("JoyfulJay", benchmark_joyfuljay),
            ("NFStream", benchmark_nfstream),
            ("Tranalyzer2", benchmark_tranalyzer2),
            ("Scapy (manual)", benchmark_scapy_manual),
            ("PyShark", benchmark_pyshark),
        ]

        for name, func in benchmarks:
            print(f"\n  Running {name}...")

            results_for_tool = []
            for i in range(runs):
                print(f"    Run {i+1}/{runs}...", end=" ", flush=True)
                result = func(pcap_path)
                if result.error:
                    print(f"Error: {result.error}")
                    break
                else:
                    print(f"{result.duration_seconds:.2f}s")
                    results_for_tool.append(result)

            if results_for_tool:
                # Take median
                results_for_tool.sort(key=lambda r: r.duration_seconds)
                median = results_for_tool[len(results_for_tool) // 2]
                all_results.append(median)
                print(f"    Median: {median.duration_seconds:.2f}s, "
                      f"{median.throughput_mbps:.1f} MB/s, "
                      f"{median.flows_extracted} flows, "
                      f"{median.feature_count} features")

    return all_results


def print_results_table(results: list[BenchmarkResult]):
    """Print results as a table."""
    print("\n" + "=" * 100)
    print("BENCHMARK RESULTS")
    print("=" * 100)

    # Group by PCAP file
    by_pcap: dict[str, list[BenchmarkResult]] = {}
    for r in results:
        if r.pcap_file not in by_pcap:
            by_pcap[r.pcap_file] = []
        by_pcap[r.pcap_file].append(r)

    for pcap, pcap_results in by_pcap.items():
        print(f"\n{pcap} ({pcap_results[0].pcap_size_mb:.1f} MB, {pcap_results[0].packet_count:,} packets)")
        print("-" * 100)
        print(f"{'Tool':<20} {'Time (s)':<12} {'MB/s':<12} {'pps':<15} {'Flows':<10} {'Features':<10} {'Mem (MB)':<10}")
        print("-" * 100)

        for r in sorted(pcap_results, key=lambda x: x.duration_seconds if x.duration_seconds > 0 else float('inf')):
            if r.error:
                print(f"{r.tool:<20} {'ERROR':<12} {r.error}")
            else:
                print(f"{r.tool:<20} {r.duration_seconds:<12.2f} {r.throughput_mbps:<12.1f} "
                      f"{r.packets_per_second:<15,.0f} {r.flows_extracted:<10} {r.feature_count:<10} "
                      f"{r.peak_memory_mb:<10.1f}")

    print("=" * 100)


def save_results(results: list[BenchmarkResult], output_file: str):
    """Save results to JSON."""
    RESULTS_DIR.mkdir(exist_ok=True)
    with open(output_file, "w") as f:
        json.dump([asdict(r) for r in results], f, indent=2)
    print(f"\nResults saved to {output_file}")


def main():
    """Run benchmarks."""
    import argparse

    parser = argparse.ArgumentParser(description="Run real benchmarks")
    parser.add_argument("--pcap", nargs="+", help="Specific PCAP files to test")
    parser.add_argument("--runs", type=int, default=3, help="Number of runs per tool")
    parser.add_argument("--output", default=str(RESULTS_DIR / "benchmark_results.json"))
    args = parser.parse_args()

    # Find PCAP files
    if args.pcap:
        pcap_files = args.pcap
    else:
        pcap_files = list(DATA_DIR.glob("*.pcap"))
        if not pcap_files:
            print(f"No PCAP files found in {DATA_DIR}")
            print("Download some test files first:")
            print("  curl -L -o benchmarks/data/smallFlows.pcap https://s3.amazonaws.com/tcpreplay-pcap-files/smallFlows.pcap")
            sys.exit(1)
        pcap_files = [str(p) for p in sorted(pcap_files, key=lambda p: p.stat().st_size)]

    print(f"PCAP files to benchmark: {pcap_files}")
    print(f"Runs per tool: {args.runs}")

    results = run_all_benchmarks(pcap_files, runs=args.runs)
    print_results_table(results)
    save_results(results, args.output)


if __name__ == "__main__":
    main()
