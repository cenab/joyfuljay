#!/usr/bin/env python3
"""Run all benchmarks and generate report."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from speed_benchmark import run_benchmarks as run_speed
from memory_benchmark import run_benchmarks as run_memory
from feature_benchmark import compare_features


def find_test_pcap() -> str | None:
    """Find a test PCAP file."""
    search_paths = [
        Path(__file__).parent / "data",
        Path(__file__).parent.parent / "tests" / "fixtures",
        Path("/tmp"),
        Path.home() / "pcaps",
    ]

    for path in search_paths:
        if path.exists():
            for pcap in path.glob("*.pcap"):
                if pcap.stat().st_size > 1024 * 1024:  # > 1MB
                    return str(pcap)
            for pcap in path.glob("*.pcapng"):
                if pcap.stat().st_size > 1024 * 1024:
                    return str(pcap)

    return None


def generate_report(
    speed_results,
    memory_results,
    feature_results,
    output_format: str = "markdown",
) -> str:
    """Generate benchmark report."""

    if output_format == "json":
        return json.dumps({
            "timestamp": datetime.now().isoformat(),
            "speed": [r.__dict__ for r in speed_results] if speed_results else [],
            "memory": [r.__dict__ for r in memory_results] if memory_results else [],
            "features": [
                {"name": t.name, "total": t.total_features}
                for t in feature_results
            ],
        }, indent=2)

    # Markdown format
    lines = [
        "# JoyfulJay Benchmark Report",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "",
        "## Speed Comparison",
        "",
    ]

    if speed_results:
        lines.append("| Tool | Time (s) | Throughput (MB/s) | Speedup |")
        lines.append("|------|----------|-------------------|---------|")

        speed_results.sort(key=lambda r: r.duration_seconds)
        baseline = speed_results[-1].duration_seconds

        for r in speed_results:
            speedup = baseline / r.duration_seconds
            lines.append(
                f"| {r.tool} | {r.duration_seconds:.2f} | "
                f"{r.throughput_mbps:.1f} | {speedup:.1f}x |"
            )
    else:
        lines.append("*Speed benchmarks not run*")

    lines.extend(["", "## Memory Usage", ""])

    if memory_results:
        lines.append("| Tool | Peak Memory (MB) | Efficiency |")
        lines.append("|------|------------------|------------|")

        for r in sorted(memory_results, key=lambda r: r.peak_memory_mb):
            lines.append(
                f"| {r.tool} | {r.peak_memory_mb:.0f} | "
                f"{r.memory_efficiency:.2f} MB/MB |"
            )
    else:
        lines.append("*Memory benchmarks not run*")

    lines.extend(["", "## Feature Count", ""])

    if feature_results:
        lines.append("| Tool | Total Features |")
        lines.append("|------|----------------|")

        for t in sorted(feature_results, key=lambda t: -t.total_features):
            lines.append(f"| {t.name} | {t.total_features} |")

    lines.extend([
        "",
        "## Summary",
        "",
        "JoyfulJay provides:",
        "",
    ])

    if speed_results and len(speed_results) > 1:
        jj_speed = next((r for r in speed_results if "JoyfulJay" in r.tool), None)
        slowest = max(speed_results, key=lambda r: r.duration_seconds)
        if jj_speed and jj_speed != slowest:
            speedup = slowest.duration_seconds / jj_speed.duration_seconds
            lines.append(f"- **{speedup:.1f}x faster** than {slowest.tool}")

    if feature_results:
        jj_features = next((t for t in feature_results if t.name == "JoyfulJay"), None)
        others = [t for t in feature_results if t.name != "JoyfulJay"]
        if jj_features and others:
            avg_others = sum(t.total_features for t in others) / len(others)
            ratio = jj_features.total_features / avg_others
            lines.append(f"- **{ratio:.1f}x more features** than average competitor")

    if memory_results and len(memory_results) > 1:
        jj_mem = next((r for r in memory_results if "streaming" in r.tool.lower()), None)
        highest = max(memory_results, key=lambda r: r.peak_memory_mb)
        if jj_mem and jj_mem != highest:
            ratio = highest.peak_memory_mb / jj_mem.peak_memory_mb
            lines.append(f"- **{ratio:.1f}x less memory** than {highest.tool}")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Run all benchmarks")
    parser.add_argument("--pcap", help="Path to PCAP file for speed/memory tests")
    parser.add_argument(
        "--output",
        choices=["markdown", "json", "csv"],
        default="markdown",
    )
    parser.add_argument("--speed", action="store_true", help="Run speed benchmark")
    parser.add_argument("--memory", action="store_true", help="Run memory benchmark")
    parser.add_argument("--features", action="store_true", help="Run feature comparison")
    parser.add_argument("--all", action="store_true", help="Run all benchmarks")
    parser.add_argument("--save", help="Save results to file")
    args = parser.parse_args()

    # Default to all if nothing specified
    if not any([args.speed, args.memory, args.features, args.all]):
        args.all = True

    speed_results = None
    memory_results = None
    feature_results = None

    # Find or use provided PCAP
    pcap_path = args.pcap or find_test_pcap()

    if args.all or args.features:
        print("Running feature comparison...")
        feature_results = compare_features()

    if pcap_path:
        if args.all or args.speed:
            print(f"Running speed benchmarks on {pcap_path}...")
            speed_results = run_speed(pcap_path, runs=3, warmup=1)

        if args.all or args.memory:
            print(f"Running memory benchmarks on {pcap_path}...")
            memory_results = run_memory(pcap_path)
    else:
        if args.speed or args.memory:
            print("Warning: No PCAP file found. Skipping speed/memory benchmarks.")
            print("Use --pcap to specify a PCAP file.")

    # Generate report
    report = generate_report(
        speed_results or [],
        memory_results or [],
        feature_results or [],
        args.output,
    )

    print("\n" + report)

    if args.save:
        with open(args.save, "w") as f:
            f.write(report)
        print(f"\nSaved to {args.save}")


if __name__ == "__main__":
    main()
