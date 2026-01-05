#!/usr/bin/env python3
"""
Comprehensive benchmark of JoyfulJay vs NFStream on all Wireshark sample captures.

Tests both tools on all downloaded capture files and produces aggregate statistics.
"""

import gc
import json
import sys
import time
import traceback
import tracemalloc
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

import pandas as pd

# Add parent to path for joyfuljay
sys.path.insert(0, str(Path(__file__).parent.parent))

# Configuration
WIRESHARK_SAMPLES_DIR = Path(__file__).parent / "data" / "wireshark_samples"
RESULTS_DIR = Path(__file__).parent / "results"
CAPTURE_EXTENSIONS = {'.pcap', '.pcapng', '.cap', '.trace', '.ntar', '.erf'}


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


def benchmark_nfstream(pcap_path: Path) -> BenchmarkResult:
    """Benchmark NFStream on a single file."""
    from nfstream import NFStreamer

    gc.collect()

    try:
        start = time.perf_counter()
        streamer = NFStreamer(source=str(pcap_path))
        df = streamer.to_pandas()
        elapsed = time.perf_counter() - start

        return BenchmarkResult(
            tool="NFStream",
            pcap=pcap_path.name,
            size_bytes=get_pcap_size(pcap_path),
            time_s=elapsed,
            flows=len(df),
            features=len(df.columns),
            success=True,
        )
    except Exception as e:
        return BenchmarkResult(
            tool="NFStream",
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
    print("COMPREHENSIVE WIRESHARK SAMPLES BENCHMARK")
    print("=" * 80)

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
    nfs_success = 0
    nfs_fail = 0

    jj_total_time = 0.0
    nfs_total_time = 0.0
    jj_total_flows = 0
    nfs_total_flows = 0

    print("\n" + "-" * 80)
    print(f"{'File':<40} {'Size':>10} {'JJ Time':>10} {'NFS Time':>10} {'JJ Flows':>10} {'NFS Flows':>10}")
    print("-" * 80)

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

        # Benchmark NFStream
        nfs_result = benchmark_nfstream(pcap_path)
        results.append(nfs_result)

        if nfs_result.success:
            nfs_success += 1
            nfs_total_time += nfs_result.time_s
            nfs_total_flows += nfs_result.flows
            nfs_time_str = f"{nfs_result.time_s:.3f}s"
            nfs_flows_str = str(nfs_result.flows)
        else:
            nfs_fail += 1
            nfs_time_str = "FAIL"
            nfs_flows_str = "-"

        # Print progress
        name = pcap_path.name[:38] + ".." if len(pcap_path.name) > 40 else pcap_path.name
        print(f"{name:<40} {size_kb:>8.1f}KB {jj_time_str:>10} {nfs_time_str:>10} {jj_flows_str:>10} {nfs_flows_str:>10}")

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

    print(f"\nNFStream:")
    print(f"  Success: {nfs_success}/{len(capture_files)} files ({100*nfs_success/len(capture_files):.1f}%)")
    print(f"  Failed:  {nfs_fail} files")
    print(f"  Total time: {nfs_total_time:.2f}s")
    print(f"  Total flows: {nfs_total_flows:,}")
    print(f"  Throughput: {total_size/1024/1024/nfs_total_time:.2f} MB/s" if nfs_total_time > 0 else "  Throughput: N/A")

    print(f"\nComparison:")
    if jj_total_time > 0 and nfs_total_time > 0:
        print(f"  Speed ratio (NFStream/JoyfulJay): {jj_total_time/nfs_total_time:.1f}x")
    print(f"  Flow difference: {jj_total_flows - nfs_total_flows:+,} ({100*(jj_total_flows-nfs_total_flows)/max(nfs_total_flows,1):+.1f}%)")

    # Save final results
    save_results(results)

    # Create summary report
    create_summary_report(results, capture_files, total_size)

    print(f"\nResults saved to: {RESULTS_DIR}")


def save_results(results: list[BenchmarkResult]):
    """Save results to JSON file."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    output_path = RESULTS_DIR / "wireshark_benchmark_results.json"

    with open(output_path, 'w') as f:
        json.dump([asdict(r) for r in results], f, indent=2)


def create_summary_report(results: list[BenchmarkResult], capture_files: list[Path], total_size: int):
    """Create a summary report."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # Separate by tool
    jj_results = [r for r in results if r.tool == "JoyfulJay"]
    nfs_results = [r for r in results if r.tool == "NFStream"]

    jj_success = [r for r in jj_results if r.success]
    nfs_success = [r for r in nfs_results if r.success]

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
        "nfstream": {
            "success_count": len(nfs_success),
            "fail_count": len(nfs_results) - len(nfs_success),
            "total_time_s": sum(r.time_s for r in nfs_success),
            "total_flows": sum(r.flows for r in nfs_success),
            "avg_features": sum(r.features for r in nfs_success) / len(nfs_success) if nfs_success else 0,
            "throughput_mbs": (total_size / 1024 / 1024) / sum(r.time_s for r in nfs_success) if sum(r.time_s for r in nfs_success) > 0 else 0,
        },
        "failures": {
            "joyfuljay": [{"file": r.pcap, "error": r.error} for r in jj_results if not r.success],
            "nfstream": [{"file": r.pcap, "error": r.error} for r in nfs_results if not r.success],
        }
    }

    output_path = RESULTS_DIR / "wireshark_benchmark_summary.json"
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)


if __name__ == "__main__":
    main()
