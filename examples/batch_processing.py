#!/usr/bin/env python3
"""Batch processing of multiple PCAP files.

This example demonstrates processing multiple PCAP files
with parallel workers and streaming output.

Usage:
    python batch_processing.py traces/ -o features.csv -w 4
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import joyfuljay as jj


def find_pcap_files(directory: str, recursive: bool = True) -> list[Path]:
    """Find all PCAP files in a directory.

    Args:
        directory: Directory to search.
        recursive: Search subdirectories.

    Returns:
        List of PCAP file paths.
    """
    path = Path(directory)
    if not path.is_dir():
        return [path] if path.suffix in (".pcap", ".pcapng") else []

    if recursive:
        pcaps = list(path.rglob("*.pcap")) + list(path.rglob("*.pcapng"))
    else:
        pcaps = list(path.glob("*.pcap")) + list(path.glob("*.pcapng"))

    return sorted(pcaps)


def process_sequential(
    pcap_files: list[Path],
    config: jj.Config,
    output_path: str,
) -> tuple[int, float]:
    """Process files sequentially with streaming output.

    Args:
        pcap_files: List of PCAP files.
        config: Pipeline configuration.
        output_path: Output file path.

    Returns:
        Tuple of (flow_count, elapsed_time).
    """
    from joyfuljay.output.formats import StreamingWriter

    pipeline = jj.Pipeline(config)
    flow_count = 0
    start_time = time.time()

    with StreamingWriter(output_path, format="csv") as writer:
        for pcap_file in pcap_files:
            print(f"  Processing: {pcap_file.name}")
            file_flows = 0

            for features in pipeline.iter_features(str(pcap_file)):
                writer.write(features)
                flow_count += 1
                file_flows += 1

            print(f"    -> {file_flows} flows")

    elapsed = time.time() - start_time
    return flow_count, elapsed


def process_parallel(
    pcap_files: list[Path],
    config: jj.Config,
    output_path: str,
    workers: int,
) -> tuple[int, float]:
    """Process files in parallel.

    Args:
        pcap_files: List of PCAP files.
        config: Pipeline configuration.
        output_path: Output file path.
        workers: Number of parallel workers.

    Returns:
        Tuple of (flow_count, elapsed_time).
    """
    config.num_workers = workers
    pipeline = jj.Pipeline(config)

    start_time = time.time()
    print(f"  Processing {len(pcap_files)} files with {workers} workers...")

    df = pipeline.process_pcaps_batch(
        [str(f) for f in pcap_files],
        output_format="dataframe",
    )

    # Save to CSV
    df.to_csv(output_path, index=False)

    elapsed = time.time() - start_time
    return len(df), elapsed


def main() -> None:
    """Process multiple PCAP files."""
    parser = argparse.ArgumentParser(description="Batch PCAP processing")
    parser.add_argument("input", help="PCAP file or directory")
    parser.add_argument("-o", "--output", required=True, help="Output CSV file")
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=1,
        help="Parallel workers (default: 1 = sequential)",
    )
    parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="Don't search subdirectories",
    )
    parser.add_argument(
        "--streaming",
        action="store_true",
        help="Use streaming mode (memory efficient)",
    )

    args = parser.parse_args()

    print("JoyfulJay Batch Processing Example")
    print("=" * 50)

    # Find PCAP files
    pcap_files = find_pcap_files(args.input, not args.no_recursive)

    if not pcap_files:
        print(f"No PCAP files found in: {args.input}")
        sys.exit(1)

    print(f"Found {len(pcap_files)} PCAP files")
    print(f"Output: {args.output}")
    print(f"Workers: {args.workers}")
    print("-" * 50)

    # Configure
    config = jj.Config(
        features=["flow_meta", "timing", "size", "tls"],
        flow_timeout=60.0,
    )

    # Process
    if args.streaming or args.workers == 1:
        print("Mode: Sequential with streaming output")
        flow_count, elapsed = process_sequential(pcap_files, config, args.output)
    else:
        print(f"Mode: Parallel ({args.workers} workers)")
        flow_count, elapsed = process_parallel(
            pcap_files, config, args.output, args.workers
        )

    print("-" * 50)
    print(f"Processed {len(pcap_files)} files")
    print(f"Total flows: {flow_count}")
    print(f"Time: {elapsed:.2f}s ({flow_count/elapsed:.1f} flows/sec)")
    print(f"Output: {args.output}")


if __name__ == "__main__":
    main()
