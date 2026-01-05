#!/usr/bin/env python3
"""Creating and using a custom feature extractor.

This example demonstrates how to create a custom extractor
that integrates with the JoyfulJay pipeline.

Usage:
    python custom_extractor.py capture.pcap
"""

from __future__ import annotations

import sys
from typing import Any

from joyfuljay.core.config import Config
from joyfuljay.core.flow import Flow
from joyfuljay.core.pipeline import Pipeline
from joyfuljay.extractors.base import FeatureExtractor


class HTTPHeaderExtractor(FeatureExtractor):
    """Extract features from HTTP headers in unencrypted traffic.

    This is a simple example extractor that looks for HTTP patterns
    in packet payloads. For production use, you would want more
    robust parsing.
    """

    def __init__(self) -> None:
        """Initialize the extractor."""
        self._feature_names = [
            "http_request_count",
            "http_response_count",
            "http_content_length_total",
            "http_has_user_agent",
            "http_has_cookies",
            "http_methods",
        ]

    @property
    def feature_names(self) -> list[str]:
        """List of features this extractor produces."""
        return self._feature_names

    @property
    def name(self) -> str:
        """Extractor name."""
        return "http_header"

    def extract(self, flow: Flow) -> dict[str, Any]:
        """Extract HTTP header features from a flow.

        Args:
            flow: Completed network flow.

        Returns:
            Dictionary of feature names to values.
        """
        request_count = 0
        response_count = 0
        content_length_total = 0
        has_user_agent = False
        has_cookies = False
        methods: set[str] = set()

        for packet in flow.packets:
            if packet.raw_payload is None:
                continue

            try:
                payload = packet.raw_payload.decode("utf-8", errors="ignore")
            except Exception:
                continue

            # Check for HTTP request
            if payload.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ")):
                request_count += 1
                method = payload.split(" ", 1)[0]
                methods.add(method)

            # Check for HTTP response
            if payload.startswith("HTTP/"):
                response_count += 1

            # Check headers
            if "User-Agent:" in payload:
                has_user_agent = True
            if "Cookie:" in payload:
                has_cookies = True

            # Parse Content-Length
            if "Content-Length:" in payload:
                try:
                    for line in payload.split("\r\n"):
                        if line.lower().startswith("content-length:"):
                            length = int(line.split(":", 1)[1].strip())
                            content_length_total += length
                            break
                except (ValueError, IndexError):
                    pass

        return {
            "http_request_count": request_count,
            "http_response_count": response_count,
            "http_content_length_total": content_length_total,
            "http_has_user_agent": has_user_agent,
            "http_has_cookies": has_cookies,
            "http_methods": ",".join(sorted(methods)) if methods else "",
        }


class CustomPipeline(Pipeline):
    """Pipeline with custom extractor added."""

    def __init__(self, config: Config | None = None) -> None:
        """Initialize pipeline with custom extractor."""
        super().__init__(config)
        # Add our custom extractor
        self.extractors.append(HTTPHeaderExtractor())


def main() -> None:
    """Demonstrate custom extractor usage."""
    print("JoyfulJay Custom Extractor Example")
    print("=" * 50)

    if len(sys.argv) < 2:
        print("\nUsage: python custom_extractor.py <pcap_file>")
        print("\nNote: This example works best with unencrypted HTTP traffic.")

        # Demo without PCAP
        print("\n" + "-" * 50)
        print("Demonstrating extractor structure:")

        extractor = HTTPHeaderExtractor()
        print(f"\nExtractor name: {extractor.name}")
        print(f"Features: {extractor.feature_names}")
        return

    pcap_path = sys.argv[1]
    print(f"Processing: {pcap_path}")
    print("-" * 50)

    # Use custom pipeline
    config = Config(
        features=["flow_meta", "timing"],  # Base features
        flow_timeout=30.0,
    )
    pipeline = CustomPipeline(config)

    # Process PCAP
    df = pipeline.process_pcap(pcap_path)

    print(f"\nExtracted {len(df)} flows")
    print(f"Total features: {len(df.columns)}")

    # Show HTTP-specific features
    http_cols = [col for col in df.columns if col.startswith("http_")]
    if http_cols:
        print(f"\nHTTP features found: {http_cols}")
        print("\nSample values:")
        for col in http_cols:
            sample = df[col].iloc[0] if len(df) > 0 else "N/A"
            print(f"  {col}: {sample}")

    # Show flows with HTTP activity
    if "http_request_count" in df.columns:
        http_flows = df[df["http_request_count"] > 0]
        print(f"\nFlows with HTTP requests: {len(http_flows)}")


if __name__ == "__main__":
    main()
