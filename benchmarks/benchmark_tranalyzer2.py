#!/usr/bin/env python3
"""
Comprehensive benchmark of JoyfulJay vs Tranalyzer2 on all Wireshark sample captures.

NOTE: Tranalyzer2 v0.9.4 has a known bug on ARM macOS (Apple Silicon) where it
fails to parse IP headers correctly. Run this benchmark on x86_64 Linux for
accurate Tranalyzer2 results.

Tests both tools on all downloaded capture files and produces aggregate statistics.
"""

import gc
import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

# Add parent to path for joyfuljay
sys.path.insert(0, str(Path(__file__).parent.parent))

# Configuration
WIRESHARK_SAMPLES_DIR = Path(__file__).parent / "data" / "wireshark_samples"
RESULTS_DIR = Path(__file__).parent / "results"
CAPTURE_EXTENSIONS = {'.pcap', '.pcapng', '.cap', '.trace', '.ntar', '.erf'}

# Tranalyzer2 binary path - update if different on your system
T2_BINARY = Path.home() / "Documents/DEVELOPMENT/tranalyzer2-0.9.4/tranalyzer2/build/tranalyzer"


@dataclass
class BenchmarkResult:
    """Single benchmark result."""
    tool: str
    pcap: str
    size_bytes: int
    time_s: float
    flows: int
    features: int
    success: bool
    error: Optional[str] = None


def get_pcap_size(pcap_path: Path) -> int:
    """Get file size in bytes."""
    return pcap_path.stat().st_size


def benchmark_joyfuljay(pcap_path: Path) -> BenchmarkResult:
    """Benchmark JoyfulJay on a single file."""
    import joyfuljay as jj
    from joyfuljay.capture.dpkt_backend import DpktBackend

    gc.collect()

    try:
        config = jj.Config(
            features=["all"],
            terminate_on_fin_rst=False,
            flow_timeout=120.0,
        )
        backend = DpktBackend()
        pipeline = jj.Pipeline(config, backend=backend)

        start = time.perf_counter()
        df = pipeline.process_pcap(str(pcap_path))
        elapsed = time.perf_counter() - start

        return BenchmarkResult(
            tool="JoyfulJay",
            pcap=pcap_path.name,
            size_bytes=get_pcap_size(pcap_path),
            time_s=elapsed,
            flows=len(df),
            features=len(df.columns),
            success=True,
        )
    except Exception as e:
        return BenchmarkResult(
            tool="JoyfulJay",
            pcap=pcap_path.name,
            size_bytes=get_pcap_size(pcap_path),
            time_s=0,
            flows=0,
            features=0,
            success=False,
            error=str(e)[:200],
        )


def benchmark_tranalyzer2(pcap_path: Path) -> BenchmarkResult:
    """Benchmark Tranalyzer2 on a single file."""
    if not T2_BINARY.exists():
        return BenchmarkResult(
            tool="Tranalyzer2",
            pcap=pcap_path.name,
            size_bytes=get_pcap_size(pcap_path),
            time_s=0,
            flows=0,
            features=0,
            success=False,
            error=f"Tranalyzer2 not found at {T2_BINARY}",
        )

    gc.collect()

    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_prefix = Path(temp_dir) / "output"

            start = time.perf_counter()
            result = subprocess.run(
                [str(T2_BINARY), "-r", str(pcap_path), "-w", str(output_prefix)],
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
            )
            elapsed = time.perf_counter() - start

            # Parse flow file
            flow_file = Path(temp_dir) / "output_flows.txt"
            if flow_file.exists():
                with open(flow_file, 'r') as f:
                    lines = f.readlines()

                # First line is header, count remaining lines as flows
                if lines:
                    header = lines[0].strip().split('\t')
                    features = len(header)
                    flows = len(lines) - 1  # Subtract header
                else:
                    features = 0
                    flows = 0

                # Check for ARM macOS bug
                if "IPv4 header length < 20 bytes" in result.stderr and flows == 0:
                    return BenchmarkResult(
                        tool="Tranalyzer2",
                        pcap=pcap_path.name,
                        size_bytes=get_pcap_size(pcap_path),
                        time_s=elapsed,
                        flows=0,
                        features=features,
                        success=False,
                        error="ARM macOS bug: IPv4 header parsing fails",
                    )

                return BenchmarkResult(
                    tool="Tranalyzer2",
                    pcap=pcap_path.name,
                    size_bytes=get_pcap_size(pcap_path),
                    time_s=elapsed,
                    flows=flows,
                    features=features,
                    success=True,
                )
            else:
                return BenchmarkResult(
                    tool="Tranalyzer2",
                    pcap=pcap_path.name,
                    size_bytes=get_pcap_size(pcap_path),
                    time_s=elapsed,
                    flows=0,
                    features=0,
                    success=False,
                    error="No flow file produced",
                )

    except subprocess.TimeoutExpired:
        return BenchmarkResult(
            tool="Tranalyzer2",
            pcap=pcap_path.name,
            size_bytes=get_pcap_size(pcap_path),
            time_s=300,
            flows=0,
            features=0,
            success=False,
            error="Timeout after 5 minutes",
        )
    except Exception as e:
        return BenchmarkResult(
            tool="Tranalyzer2",
            pcap=pcap_path.name,
            size_bytes=get_pcap_size(pcap_path),
            time_s=0,
            flows=0,
            features=0,
            success=False,
            error=str(e)[:200],
        )


def get_capture_files(directory: Path) -> list[Path]:
    """Get all capture files sorted by size."""
    files = []
    for ext in CAPTURE_EXTENSIONS:
        files.extend(directory.glob(f"*{ext}"))
    # Sort by size (smallest first for faster initial results)
    return sorted(files, key=lambda f: f.stat().st_size)


def main():
    """Run benchmarks on all Wireshark sample captures."""
    print("=" * 80)
    print("JOYFULJAY VS TRANALYZER2 BENCHMARK")
    print("=" * 80)

    # Check Tranalyzer2
    if not T2_BINARY.exists():
        print(f"\nWARNING: Tranalyzer2 not found at {T2_BINARY}")
        print("Please update T2_BINARY path in this script.\n")
    else:
        # Check version
        result = subprocess.run([str(T2_BINARY), "--version"], capture_output=True, text=True)
        print(f"Tranalyzer2: {result.stdout.strip()}")

    # Get all capture files
    capture_files = get_capture_files(WIRESHARK_SAMPLES_DIR)
    print(f"\nFound {len(capture_files)} capture files")

    total_size = sum(f.stat().st_size for f in capture_files)
    print(f"Total size: {total_size / 1024 / 1024:.1f} MB")

    # Results storage
    results: list[BenchmarkResult] = []

    # Track aggregate stats
    jj_success = 0
    jj_fail = 0
    t2_success = 0
    t2_fail = 0

    jj_total_time = 0.0
    t2_total_time = 0.0
    jj_total_flows = 0
    t2_total_flows = 0

    print("\n" + "-" * 90)
    print(f"{'File':<40} {'Size':>10} {'JJ Time':>10} {'T2 Time':>10} {'JJ Flows':>10} {'T2 Flows':>10}")
    print("-" * 90)

    for i, pcap_path in enumerate(capture_files, 1):
        size_kb = pcap_path.stat().st_size / 1024

        # Benchmark JoyfulJay
        jj_result = benchmark_joyfuljay(pcap_path)
        results.append(jj_result)

        if jj_result.success:
            jj_success += 1
            jj_total_time += jj_result.time_s
            jj_total_flows += jj_result.flows
            jj_time_str = f"{jj_result.time_s:.3f}s"
            jj_flows_str = str(jj_result.flows)
        else:
            jj_fail += 1
            jj_time_str = "FAIL"
            jj_flows_str = "-"

        # Benchmark Tranalyzer2
        t2_result = benchmark_tranalyzer2(pcap_path)
        results.append(t2_result)

        if t2_result.success:
            t2_success += 1
            t2_total_time += t2_result.time_s
            t2_total_flows += t2_result.flows
            t2_time_str = f"{t2_result.time_s:.3f}s"
            t2_flows_str = str(t2_result.flows)
        else:
            t2_fail += 1
            t2_time_str = "FAIL"
            t2_flows_str = "-"

        # Print progress
        name = pcap_path.name[:38] + ".." if len(pcap_path.name) > 40 else pcap_path.name
        print(f"{name:<40} {size_kb:>8.1f}KB {jj_time_str:>10} {t2_time_str:>10} {jj_flows_str:>10} {t2_flows_str:>10}")

        # Save intermediate results every 50 files
        if i % 50 == 0:
            save_results(results)
            print(f"\n[Checkpoint: {i}/{len(capture_files)} files processed]\n")

    # Final summary
    print("\n" + "=" * 80)
    print("AGGREGATE RESULTS")
    print("=" * 80)

    print(f"\nJoyfulJay:")
    print(f"  Success: {jj_success}/{len(capture_files)} files ({100*jj_success/len(capture_files):.1f}%)")
    print(f"  Failed:  {jj_fail} files")
    print(f"  Total time: {jj_total_time:.2f}s")
    print(f"  Total flows: {jj_total_flows:,}")
    print(f"  Throughput: {total_size/1024/1024/jj_total_time:.2f} MB/s" if jj_total_time > 0 else "  Throughput: N/A")

    print(f"\nTranalyzer2:")
    print(f"  Success: {t2_success}/{len(capture_files)} files ({100*t2_success/len(capture_files):.1f}%)")
    print(f"  Failed:  {t2_fail} files")
    print(f"  Total time: {t2_total_time:.2f}s")
    print(f"  Total flows: {t2_total_flows:,}")
    print(f"  Throughput: {total_size/1024/1024/t2_total_time:.2f} MB/s" if t2_total_time > 0 else "  Throughput: N/A")

    print(f"\nComparison:")
    if jj_total_time > 0 and t2_total_time > 0:
        print(f"  Speed ratio (Tranalyzer2/JoyfulJay): {jj_total_time/t2_total_time:.1f}x")
    if t2_total_flows > 0:
        print(f"  Flow difference: {jj_total_flows - t2_total_flows:+,} ({100*(jj_total_flows-t2_total_flows)/t2_total_flows:+.1f}%)")

    # Save final results
    save_results(results)

    # Create summary report
    create_summary_report(results, capture_files, total_size)

    print(f"\nResults saved to: {RESULTS_DIR}")


def save_results(results: list[BenchmarkResult]):
    """Save results to JSON file."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    output_path = RESULTS_DIR / "tranalyzer2_benchmark_results.json"

    with open(output_path, 'w') as f:
        json.dump([asdict(r) for r in results], f, indent=2)


def create_summary_report(results: list[BenchmarkResult], capture_files: list[Path], total_size: int):
    """Create a summary report."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # Separate by tool
    jj_results = [r for r in results if r.tool == "JoyfulJay"]
    t2_results = [r for r in results if r.tool == "Tranalyzer2"]

    jj_success = [r for r in jj_results if r.success]
    t2_success = [r for r in t2_results if r.success]

    report = {
        "summary": {
            "total_files": len(capture_files),
            "total_size_mb": total_size / 1024 / 1024,
        },
        "joyfuljay": {
            "success_count": len(jj_success),
            "fail_count": len(jj_results) - len(jj_success),
            "total_time_s": sum(r.time_s for r in jj_success),
            "total_flows": sum(r.flows for r in jj_success),
            "avg_features": sum(r.features for r in jj_success) / len(jj_success) if jj_success else 0,
            "throughput_mbs": (total_size / 1024 / 1024) / sum(r.time_s for r in jj_success) if sum(r.time_s for r in jj_success) > 0 else 0,
        },
        "tranalyzer2": {
            "success_count": len(t2_success),
            "fail_count": len(t2_results) - len(t2_success),
            "total_time_s": sum(r.time_s for r in t2_success),
            "total_flows": sum(r.flows for r in t2_success),
            "avg_features": sum(r.features for r in t2_success) / len(t2_success) if t2_success else 0,
            "throughput_mbs": (total_size / 1024 / 1024) / sum(r.time_s for r in t2_success) if sum(r.time_s for r in t2_success) > 0 else 0,
        },
        "failures": {
            "joyfuljay": [{"file": r.pcap, "error": r.error} for r in jj_results if not r.success],
            "tranalyzer2": [{"file": r.pcap, "error": r.error} for r in t2_results if not r.success],
        }
    }

    output_path = RESULTS_DIR / "tranalyzer2_benchmark_summary.json"
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)


if __name__ == "__main__":
    main()
