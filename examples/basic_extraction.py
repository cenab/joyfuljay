#!/usr/bin/env python3
"""Basic feature extraction from PCAP files.

This example demonstrates the simplest way to extract features
from a PCAP file using JoyfulJay.

Usage:
    python basic_extraction.py capture.pcap
"""

from __future__ import annotations

import sys
from pathlib import Path

import joyfuljay as jj


def main() -> None:
    """Extract features from a PCAP file."""
    if len(sys.argv) < 2:
        print("Usage: python basic_extraction.py <pcap_file>")
        sys.exit(1)

    pcap_path = sys.argv[1]

    # Method 1: Simple one-liner
    print("Method 1: Simple extraction")
    print("-" * 40)
    df = jj.extract(pcap_path)
    print(f"Extracted {len(df)} flows with {len(df.columns)} features")
    print(f"Columns: {df.columns.tolist()[:10]}...")
    print()

    # Method 2: Using Pipeline with Config
    print("Method 2: With configuration")
    print("-" * 40)
    config = jj.Config(
        features=["flow_meta", "timing", "size", "tls"],
        flow_timeout=30.0,
    )
    pipeline = jj.Pipeline(config)
    df = pipeline.process_pcap(pcap_path)
    print(f"Extracted {len(df)} flows")
    print(f"Selected features: {df.columns.tolist()[:10]}...")
    print()

    # Method 3: Streaming for large files
    print("Method 3: Streaming extraction")
    print("-" * 40)
    pipeline = jj.Pipeline()
    flow_count = 0
    for features in pipeline.iter_features(pcap_path):
        flow_count += 1
        if flow_count <= 3:
            print(f"  Flow {flow_count}: {features['src_ip']} -> {features['dst_ip']}")
    print(f"  ... (total: {flow_count} flows)")
    print()

    # Display sample output
    print("Sample Features (first flow):")
    print("-" * 40)
    df = jj.extract(pcap_path)
    if not df.empty:
        first_flow = df.iloc[0]
        for col in ["src_ip", "dst_ip", "duration", "total_packets", "total_bytes"]:
            if col in first_flow:
                print(f"  {col}: {first_flow[col]}")


if __name__ == "__main__":
    main()
