#!/usr/bin/env python3
"""Remote capture client example.

This example demonstrates connecting to a remote JoyfulJay server
to receive packets and extract features.

Usage:
    # On the capture device:
    jj serve wlan0 --port 8765

    # On your analysis machine:
    python remote_capture.py jj://192.168.1.100:8765?token=xxx

See also: docs/remote-capture.md
"""

from __future__ import annotations

import argparse
import sys
import time

import joyfuljay as jj
from joyfuljay.capture.remote_backend import RemoteCaptureBackend


def main() -> None:
    """Connect to remote server and extract features."""
    parser = argparse.ArgumentParser(description="Remote capture client")
    parser.add_argument(
        "url",
        help="Server URL (jj://host:port?token=xxx)",
    )
    parser.add_argument(
        "-d", "--duration",
        type=float,
        default=30.0,
        help="Capture duration in seconds",
    )
    parser.add_argument(
        "-o", "--output",
        help="Output CSV file",
    )
    parser.add_argument(
        "--save-pcap",
        help="Save received packets to PCAP file",
    )
    parser.add_argument(
        "--tls-insecure",
        action="store_true",
        help="Disable TLS certificate verification",
    )

    args = parser.parse_args()

    print("JoyfulJay Remote Capture Client")
    print("=" * 50)
    print(f"Server URL: {args.url}")
    print(f"Duration: {args.duration}s")
    if args.save_pcap:
        print(f"Save PCAP: {args.save_pcap}")
    print("-" * 50)

    try:
        # Create remote backend from URL
        backend = RemoteCaptureBackend.from_jj_url(
            args.url,
            tls_verify=not args.tls_insecure,
        )

        # Configure pipeline
        config = jj.Config(
            features=["flow_meta", "timing", "size", "tls", "fingerprint"],
            flow_timeout=30.0,
        )
        pipeline = jj.Pipeline(config, backend=backend)

        # Stream features
        print("Connecting...")
        flow_count = 0
        start_time = time.time()

        for features in pipeline.process_live(
            interface="",  # Not used for remote
            duration=args.duration,
            output_format="stream",
            save_pcap=args.save_pcap,
        ):
            flow_count += 1
            src = features.get("src_ip", "?")
            dst = features.get("dst_ip", "?")
            packets = features.get("total_packets", 0)
            duration = features.get("duration", 0)

            print(f"  Flow {flow_count}: {src} -> {dst} ({packets} pkts, {duration:.2f}s)")

        elapsed = time.time() - start_time
        print("-" * 50)
        print(f"Received {flow_count} flows in {elapsed:.1f}s")

        # Save to CSV if requested
        if args.output:
            print(f"\nRe-running for CSV export...")
            df = pipeline.process_live(
                interface="",
                duration=args.duration,
                output_format="dataframe",
            )
            df.to_csv(args.output, index=False)
            print(f"Saved to: {args.output}")

    except ValueError as e:
        print(f"Invalid URL: {e}")
        print("\nURL format: jj://host:port?token=xxx")
        print("Example: jj://192.168.1.100:8765?token=abc123")
        sys.exit(1)

    except ConnectionError as e:
        print(f"Connection failed: {e}")
        print("\nMake sure the server is running:")
        print("  jj serve wlan0 --port 8765")
        sys.exit(1)

    except KeyboardInterrupt:
        print("\nCapture interrupted by user.")


if __name__ == "__main__":
    main()
