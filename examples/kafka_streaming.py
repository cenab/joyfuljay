#!/usr/bin/env python3
"""Real-time Kafka streaming with JoyfulJay.

This example demonstrates streaming extracted features to Kafka
for real-time processing pipelines.

Usage:
    python kafka_streaming.py capture.pcap --topic network-features

Requirements:
    pip install joyfuljay[kafka]
"""

from __future__ import annotations

import argparse
import sys
import time

import joyfuljay as jj

try:
    from joyfuljay.output.kafka import KafkaWriter
except ImportError:
    print("Kafka support not installed. Install with:")
    print("  pip install joyfuljay[kafka]")
    sys.exit(1)


def stream_to_kafka(
    pcap_path: str,
    brokers: str,
    topic: str,
    key_field: str | None = None,
    batch_size: int = 100,
) -> int:
    """Stream features from PCAP to Kafka.

    Args:
        pcap_path: Path to PCAP file.
        brokers: Kafka bootstrap servers.
        topic: Kafka topic name.
        key_field: Feature field to use as message key.
        batch_size: Flush every N messages.

    Returns:
        Number of flows processed.
    """
    config = jj.Config(
        features=["flow_meta", "timing", "size", "tls", "fingerprint"],
        flow_timeout=30.0,
    )
    pipeline = jj.Pipeline(config)

    flow_count = 0
    start_time = time.time()

    with KafkaWriter(
        brokers=brokers,
        topic=topic,
        key_field=key_field,
        batch_size=batch_size,
    ) as writer:
        for features in pipeline.iter_features(pcap_path):
            writer.write(features)
            flow_count += 1

            if flow_count % 100 == 0:
                elapsed = time.time() - start_time
                rate = flow_count / elapsed if elapsed > 0 else 0
                print(f"  Processed {flow_count} flows ({rate:.1f}/sec)")

    return flow_count


def main() -> None:
    """Stream PCAP features to Kafka."""
    parser = argparse.ArgumentParser(description="Kafka streaming example")
    parser.add_argument("pcap", help="PCAP file to process")
    parser.add_argument(
        "--brokers",
        default="localhost:9092",
        help="Kafka bootstrap servers (default: localhost:9092)",
    )
    parser.add_argument(
        "--topic",
        default="network-features",
        help="Kafka topic (default: network-features)",
    )
    parser.add_argument("--key", help="Feature field for message key (e.g., 'src_ip')")
    parser.add_argument(
        "--batch-size", type=int, default=100, help="Batch size for flushing"
    )

    args = parser.parse_args()

    print("JoyfulJay Kafka Streaming Example")
    print("=" * 50)
    print(f"PCAP: {args.pcap}")
    print(f"Brokers: {args.brokers}")
    print(f"Topic: {args.topic}")
    if args.key:
        print(f"Key field: {args.key}")
    print("-" * 50)

    start = time.time()
    try:
        count = stream_to_kafka(
            args.pcap,
            args.brokers,
            args.topic,
            args.key,
            args.batch_size,
        )
        elapsed = time.time() - start
        print("-" * 50)
        print(f"Streamed {count} flows in {elapsed:.2f}s ({count/elapsed:.1f}/sec)")
        print(f"Topic: {args.topic}")

    except Exception as e:
        print(f"Error: {e}")
        print("\nMake sure Kafka is running:")
        print("  docker run -d -p 9092:9092 apache/kafka:latest")
        sys.exit(1)


if __name__ == "__main__":
    main()
