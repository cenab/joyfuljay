#!/usr/bin/env python3
"""Benchmark JoyfulJay pipeline on sample PCAP."""

from __future__ import annotations

import time
from pathlib import Path

from joyfuljay.core.config import Config
from joyfuljay.core.pipeline import Pipeline


def run_benchmark() -> None:
    """Run a simple pipeline benchmark on the bundled sample PCAP."""
    pcap_path = Path(__file__).resolve().parents[1] / "tests" / "data" / "sample.pcap"
    if not pcap_path.exists():
        raise FileNotFoundError(f"Sample PCAP not found at {pcap_path}")

    config = Config()
    pipeline = Pipeline(config)

    start = time.perf_counter()
    features = pipeline.process_pcap(str(pcap_path), output_format="dict")
    elapsed = time.perf_counter() - start

    flow_count = len(features) if isinstance(features, list) else 0

    print("=" * 70)
    print("JoyfulJay Pipeline Benchmark")
    print("=" * 70)
    print(f"PCAP: {pcap_path}")
    print(f"Flows: {flow_count}")
    print(f"Elapsed: {elapsed:.2f}s")
    if elapsed > 0:
        print(f"Flows/sec: {flow_count / elapsed:.2f}")
    print("=" * 70)


if __name__ == "__main__":
    run_benchmark()
