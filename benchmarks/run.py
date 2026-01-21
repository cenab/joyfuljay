#!/usr/bin/env python3
"""Unified benchmark runner for JoyfulJay.

This is the canonical entrypoint for running benchmarks. It provides a
consistent interface for quick testing and comprehensive benchmarking.

Usage:
    python -m benchmarks.run --suite quick
    python -m benchmarks.run --suite full --data-dir benchmarks/_data_cache
    python -m benchmarks.run --list
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

# Benchmark directory
BENCHMARK_DIR = Path(__file__).parent
REPORTS_DIR = BENCHMARK_DIR / "reports"
DEFAULT_DATA_DIR = BENCHMARK_DIR / "_data_cache"
SMALL_DATA_DIR = BENCHMARK_DIR / "datasets.small"


@dataclass
class BenchmarkResult:
    """Result of a single benchmark run."""

    name: str
    suite: str
    duration_seconds: float
    flows_extracted: int
    packets_processed: int
    throughput_pps: float  # packets per second
    throughput_fps: float  # flows per second
    memory_mb: float
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class BenchmarkSuite:
    """Definition of a benchmark suite."""

    name: str
    description: str
    pcap_patterns: list[str]
    timeout_seconds: int = 300
    warmup_runs: int = 1
    measured_runs: int = 3


# Suite definitions
SUITES = {
    "quick": BenchmarkSuite(
        name="quick",
        description="Quick sanity check with small files",
        pcap_patterns=["datasets.small/*.pcap", "datasets.small/*.pcapng"],
        timeout_seconds=60,
        warmup_runs=0,
        measured_runs=1,
    ),
    "full": BenchmarkSuite(
        name="full",
        description="Comprehensive benchmark with large corpora",
        pcap_patterns=[
            "_data_cache/quick/*.pcap",
            "_data_cache/full/*.pcap",
            "_data_cache/**/*.pcap.gz",
        ],
        timeout_seconds=600,
        warmup_runs=1,
        measured_runs=3,
    ),
}


def find_pcap_files(base_dir: Path, patterns: list[str]) -> list[Path]:
    """Find PCAP files matching patterns.

    Args:
        base_dir: Base directory for pattern matching.
        patterns: Glob patterns to match.

    Returns:
        List of matching PCAP file paths.
    """
    files = []
    for pattern in patterns:
        files.extend(base_dir.glob(pattern))
    return sorted(set(files))


def run_joyfuljay_benchmark(pcap_path: Path, profile: str = "JJ-CORE") -> BenchmarkResult:
    """Run JoyfulJay extraction benchmark.

    Args:
        pcap_path: Path to PCAP file.
        profile: Feature profile to use.

    Returns:
        Benchmark result.
    """
    import traceback

    try:
        # Import here to avoid loading if just listing
        from joyfuljay.core.config import Config
        from joyfuljay.core.pipeline import Pipeline

        # Get memory before
        try:
            import resource
            mem_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        except ImportError:
            mem_before = 0

        # Run extraction
        config = Config(profile=profile)
        pipeline = Pipeline(config)

        start_time = time.perf_counter()
        result = pipeline.process_pcap(str(pcap_path), output_format="dict")
        end_time = time.perf_counter()

        duration = end_time - start_time

        # Get flow count
        if hasattr(result, "__len__"):
            flow_count = len(result)
        else:
            flow_count = sum(1 for _ in result)

        # Get memory after
        try:
            import resource
            mem_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            # macOS returns bytes, Linux returns kilobytes
            if sys.platform == "darwin":
                memory_mb = (mem_after - mem_before) / 1024 / 1024
            else:
                memory_mb = (mem_after - mem_before) / 1024
        except ImportError:
            memory_mb = 0.0

        # Estimate packet count (rough)
        packet_count = flow_count * 10  # Rough estimate

        return BenchmarkResult(
            name=pcap_path.name,
            suite="joyfuljay",
            duration_seconds=duration,
            flows_extracted=flow_count,
            packets_processed=packet_count,
            throughput_pps=packet_count / duration if duration > 0 else 0,
            throughput_fps=flow_count / duration if duration > 0 else 0,
            memory_mb=memory_mb,
            metadata={"profile": profile, "file_size_mb": pcap_path.stat().st_size / 1024 / 1024},
        )

    except Exception as e:
        return BenchmarkResult(
            name=pcap_path.name,
            suite="joyfuljay",
            duration_seconds=0,
            flows_extracted=0,
            packets_processed=0,
            throughput_pps=0,
            throughput_fps=0,
            memory_mb=0,
            errors=[f"{type(e).__name__}: {e}\n{traceback.format_exc()}"],
        )


def run_suite(suite: BenchmarkSuite, data_dir: Path) -> list[BenchmarkResult]:
    """Run all benchmarks in a suite.

    Args:
        suite: Suite definition.
        data_dir: Directory containing benchmark data.

    Returns:
        List of benchmark results.
    """
    print(f"\n{'=' * 60}")
    print(f"Running suite: {suite.name}")
    print(f"Description: {suite.description}")
    print(f"{'=' * 60}\n")

    # Find PCAP files
    pcap_files = find_pcap_files(data_dir, suite.pcap_patterns)

    if not pcap_files:
        print(f"No PCAP files found for suite '{suite.name}'")
        print(f"Searched patterns: {suite.pcap_patterns}")
        print(f"In directory: {data_dir}")
        print("\nRun 'python scripts/download_benchmark_data.py' to download test data.")
        return []

    print(f"Found {len(pcap_files)} PCAP files\n")

    results = []

    for i, pcap_path in enumerate(pcap_files, 1):
        print(f"[{i}/{len(pcap_files)}] {pcap_path.name}")

        # Warmup runs
        for w in range(suite.warmup_runs):
            print(f"  Warmup {w + 1}/{suite.warmup_runs}...", end=" ", flush=True)
            run_joyfuljay_benchmark(pcap_path)
            print("done")

        # Measured runs
        run_results = []
        for r in range(suite.measured_runs):
            print(f"  Run {r + 1}/{suite.measured_runs}...", end=" ", flush=True)
            result = run_joyfuljay_benchmark(pcap_path)
            run_results.append(result)

            if result.errors:
                print(f"ERROR: {result.errors[0][:50]}")
            else:
                print(f"{result.duration_seconds:.2f}s, {result.flows_extracted} flows")

        # Average results
        if run_results and not any(r.errors for r in run_results):
            avg_duration = sum(r.duration_seconds for r in run_results) / len(run_results)
            avg_result = BenchmarkResult(
                name=pcap_path.name,
                suite=suite.name,
                duration_seconds=avg_duration,
                flows_extracted=run_results[0].flows_extracted,
                packets_processed=run_results[0].packets_processed,
                throughput_pps=run_results[0].packets_processed / avg_duration if avg_duration > 0 else 0,
                throughput_fps=run_results[0].flows_extracted / avg_duration if avg_duration > 0 else 0,
                memory_mb=max(r.memory_mb for r in run_results),
                metadata=run_results[0].metadata,
            )
            results.append(avg_result)
        elif run_results:
            results.append(run_results[0])  # Include error result

    return results


def save_report(results: list[BenchmarkResult], suite_name: str) -> Path:
    """Save benchmark results to a report file.

    Args:
        results: List of benchmark results.
        suite_name: Name of the suite.

    Returns:
        Path to the report file.
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = REPORTS_DIR / f"benchmark_{suite_name}_{timestamp}.json"

    report = {
        "suite": suite_name,
        "timestamp": datetime.now().isoformat(),
        "results": [
            {
                "name": r.name,
                "duration_seconds": r.duration_seconds,
                "flows_extracted": r.flows_extracted,
                "throughput_fps": r.throughput_fps,
                "memory_mb": r.memory_mb,
                "errors": r.errors,
                "metadata": r.metadata,
            }
            for r in results
        ],
        "summary": {
            "total_files": len(results),
            "successful": sum(1 for r in results if not r.errors),
            "total_flows": sum(r.flows_extracted for r in results),
            "total_duration": sum(r.duration_seconds for r in results),
        },
    }

    report_path.write_text(json.dumps(report, indent=2))
    return report_path


def print_summary(results: list[BenchmarkResult]) -> None:
    """Print benchmark summary."""
    if not results:
        return

    print(f"\n{'=' * 60}")
    print("SUMMARY")
    print(f"{'=' * 60}\n")

    successful = [r for r in results if not r.errors]
    failed = [r for r in results if r.errors]

    print(f"Files processed: {len(results)}")
    print(f"Successful: {len(successful)}")
    print(f"Failed: {len(failed)}")

    if successful:
        total_flows = sum(r.flows_extracted for r in successful)
        total_duration = sum(r.duration_seconds for r in successful)
        avg_fps = total_flows / total_duration if total_duration > 0 else 0

        print(f"\nTotal flows extracted: {total_flows:,}")
        print(f"Total duration: {total_duration:.2f}s")
        print(f"Average throughput: {avg_fps:.0f} flows/sec")

    if failed:
        print(f"\nFailed files:")
        for r in failed:
            print(f"  - {r.name}: {r.errors[0][:60] if r.errors else 'unknown error'}")


def list_suites() -> None:
    """List available benchmark suites."""
    print("Available benchmark suites:\n")
    for name, suite in SUITES.items():
        print(f"  {name}:")
        print(f"    Description: {suite.description}")
        print(f"    Warmup runs: {suite.warmup_runs}")
        print(f"    Measured runs: {suite.measured_runs}")
        print(f"    Timeout: {suite.timeout_seconds}s")
        print()


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Run JoyfulJay benchmarks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python -m benchmarks.run --suite quick
    python -m benchmarks.run --suite full --data-dir /path/to/data
    python -m benchmarks.run --list
        """,
    )
    parser.add_argument(
        "--suite",
        choices=list(SUITES.keys()),
        default="quick",
        help="Benchmark suite to run (default: quick).",
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=BENCHMARK_DIR,
        help="Directory containing benchmark data.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available suites and exit.",
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="Don't save report file.",
    )

    args = parser.parse_args()

    if args.list:
        list_suites()
        return 0

    suite = SUITES[args.suite]
    results = run_suite(suite, args.data_dir)

    print_summary(results)

    if results and not args.no_report:
        report_path = save_report(results, args.suite)
        print(f"\nReport saved to: {report_path}")

    # Return error code if any benchmarks failed
    return 1 if any(r.errors for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
