#!/usr/bin/env python3
"""Feature comparison between JoyfulJay and other tools."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


@dataclass
class ToolFeatures:
    """Features supported by a tool."""

    name: str
    total_features: int
    categories: dict[str, int]
    unique_features: list[str]
    protocols: list[str]
    output_formats: list[str]
    special_capabilities: list[str]


def get_joyfuljay_features() -> ToolFeatures:
    """Get JoyfulJay feature info."""
    import joyfuljay as jj

    # Get all feature names
    config = jj.Config(features=["all"])
    pipeline = jj.Pipeline(config)
    all_features = pipeline.get_feature_names()

    categories = {
        "flow_meta": 10,
        "timing": 25,
        "size": 20,
        "tcp": 45,
        "tls": 35,
        "quic": 15,
        "ssh": 12,
        "dns": 18,
        "http2": 12,
        "entropy": 8,
        "fingerprint": 25,
        "connection": 22,
        "mac": 12,
        "icmp": 10,
        "padding": 8,
        "ip_extended": 12,
        "ipv6_options": 8,
        "tcp_sequence": 10,
        "tcp_window": 8,
        "tcp_options": 12,
        "tcp_mptcp": 6,
        "tcp_rtt": 8,
        "tcp_fingerprint": 4,
    }

    return ToolFeatures(
        name="JoyfulJay",
        total_features=len(all_features),
        categories=categories,
        unique_features=[
            "ja3_hash", "ja3s_hash", "hassh", "hassh_server",
            "likely_tor", "likely_vpn", "likely_doh",
            "quic_version", "quic_0rtt_packets",
            "fixed_size_ratio", "padding_pattern",
            "payload_entropy_mean", "tcp_fingerprint",
            "mptcp_capable", "splt",
        ],
        protocols=[
            "TCP", "UDP", "ICMP", "IPv4", "IPv6", "VLAN", "MPLS", "GRE",
            "TLS 1.2", "TLS 1.3", "QUIC v1", "QUIC v2", "HTTP/2", "HTTP/3",
            "DNS", "DoH", "DoT", "SSH", "MPTCP",
        ],
        output_formats=[
            "DataFrame", "NumPy", "CSV", "JSON", "Parquet",
            "SQLite", "PostgreSQL", "Kafka",
        ],
        special_capabilities=[
            "Remote capture", "mDNS discovery", "Prometheus metrics",
            "Grafana dashboards", "IP anonymization", "Streaming output",
            "Plugin system", "SPLT sequences",
        ],
    )


def get_cicflowmeter_features() -> ToolFeatures:
    """CICFlowMeter features (documented)."""
    return ToolFeatures(
        name="CICFlowMeter",
        total_features=84,
        categories={
            "flow_meta": 8,
            "timing": 12,
            "size": 10,
            "tcp": 15,
            "tls": 0,
            "dns": 0,
            "other": 39,
        },
        unique_features=[],
        protocols=["TCP", "UDP", "IPv4", "IPv6"],
        output_formats=["CSV"],
        special_capabilities=["GUI", "Real-time capture"],
    )


def get_nfstream_features() -> ToolFeatures:
    """NFStream features (documented)."""
    return ToolFeatures(
        name="NFStream",
        total_features=48,
        categories={
            "flow_meta": 6,
            "timing": 8,
            "size": 6,
            "tcp": 8,
            "tls": 4,
            "dns": 4,
            "other": 12,
        },
        unique_features=["nDPI integration"],
        protocols=["TCP", "UDP", "ICMP", "IPv4", "IPv6", "VLAN"],
        output_formats=["DataFrame", "CSV"],
        special_capabilities=["nDPI DPI", "IP anonymization"],
    )


def get_zeek_features() -> ToolFeatures:
    """Zeek features (core logs)."""
    return ToolFeatures(
        name="Zeek",
        total_features=60,  # Approximate from core logs
        categories={
            "flow_meta": 5,
            "timing": 3,
            "size": 4,
            "tcp": 8,
            "tls": 12,
            "dns": 8,
            "ssh": 4,
            "http": 8,
            "other": 8,
        },
        unique_features=["Scripting language", "File extraction"],
        protocols=[
            "TCP", "UDP", "ICMP", "IPv4", "IPv6",
            "TLS", "SSH", "DNS", "HTTP", "SMTP", "FTP",
        ],
        output_formats=["Zeek logs", "JSON", "Kafka"],
        special_capabilities=[
            "Scripting", "File extraction", "Intel framework",
            "Cluster mode", "Packet filter",
        ],
    )


def get_joy_features() -> ToolFeatures:
    """Cisco Joy features."""
    return ToolFeatures(
        name="Joy",
        total_features=42,
        categories={
            "flow_meta": 6,
            "timing": 8,
            "size": 6,
            "tcp": 6,
            "tls": 4,
            "dns": 4,
            "other": 8,
        },
        unique_features=["SPLT", "Byte distribution"],
        protocols=["TCP", "UDP", "IPv4", "IPv6", "TLS", "DNS"],
        output_formats=["JSON"],
        special_capabilities=["SPLT sequences", "Byte histogram"],
    )


def compare_features():
    """Compare all tools."""
    tools = [
        get_joyfuljay_features(),
        get_cicflowmeter_features(),
        get_nfstream_features(),
        get_zeek_features(),
        get_joy_features(),
    ]

    return tools


def print_comparison(tools: list[ToolFeatures], output_format: str = "table"):
    """Print feature comparison."""
    if output_format == "json":
        data = []
        for t in tools:
            data.append({
                "name": t.name,
                "total_features": t.total_features,
                "categories": t.categories,
                "protocols": t.protocols,
                "output_formats": t.output_formats,
            })
        print(json.dumps(data, indent=2))
        return

    # Header
    print("\n" + "=" * 80)
    print("Feature Comparison")
    print("=" * 80)

    # Total features
    print("\nTotal Features:")
    print("-" * 50)
    max_features = max(t.total_features for t in tools)
    for t in sorted(tools, key=lambda x: -x.total_features):
        bar_len = int(40 * t.total_features / max_features)
        bar = "#" * bar_len
        print(f"{t.name:<15} {bar} {t.total_features}")

    # Category breakdown
    print("\n\nFeatures by Category:")
    print("-" * 80)

    all_categories = set()
    for t in tools:
        all_categories.update(t.categories.keys())

    header = f"{'Category':<15}"
    for t in tools:
        header += f"{t.name:<12}"
    print(header)
    print("-" * 80)

    for cat in sorted(all_categories):
        row = f"{cat:<15}"
        for t in tools:
            count = t.categories.get(cat, 0)
            row += f"{count:<12}"
        print(row)

    # Protocol support
    print("\n\nProtocol Support:")
    print("-" * 80)

    all_protocols = set()
    for t in tools:
        all_protocols.update(t.protocols)

    for proto in sorted(all_protocols):
        row = f"{proto:<15}"
        for t in tools:
            supported = "Y" if proto in t.protocols else "-"
            row += f"{supported:<12}"
        print(row)

    # Output formats
    print("\n\nOutput Formats:")
    print("-" * 80)
    for t in tools:
        print(f"{t.name:<15}: {', '.join(t.output_formats)}")

    # Unique features
    print("\n\nUnique JoyfulJay Features:")
    print("-" * 80)
    jj = next(t for t in tools if t.name == "JoyfulJay")
    for feat in jj.unique_features:
        print(f"  - {feat}")

    # Special capabilities
    print("\n\nSpecial Capabilities:")
    print("-" * 80)
    for t in tools:
        print(f"{t.name}:")
        for cap in t.special_capabilities:
            print(f"  - {cap}")
        print()

    print("=" * 80)


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Feature comparison")
    parser.add_argument("--output", choices=["table", "json"], default="table")
    args = parser.parse_args()

    tools = compare_features()
    print_comparison(tools, args.output)


if __name__ == "__main__":
    main()
