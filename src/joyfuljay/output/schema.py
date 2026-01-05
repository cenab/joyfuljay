"""Feature schema definitions and documentation."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any


class FeatureType(str, Enum):
    """Feature data types."""

    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    SEQUENCE = "sequence"


@dataclass(frozen=True)
class FeatureDefinition:
    """Definition of a single feature.

    Attributes:
        name: Feature name (column name in output).
        type: Data type of the feature.
        description: Human-readable description.
        unit: Unit of measurement (if applicable).
        group: Feature group this belongs to.
    """

    name: str
    type: FeatureType
    description: str
    unit: str | None = None
    group: str = "general"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON export."""
        return {
            "name": self.name,
            "type": self.type.value,
            "description": self.description,
            "unit": self.unit,
            "group": self.group,
        }


# Feature definitions for documentation and validation
FEATURE_DEFINITIONS: dict[str, FeatureDefinition] = {
    # Flow metadata
    "src_ip": FeatureDefinition(
        "src_ip",
        FeatureType.STRING,
        "Source IP address (flow initiator)",
        group="flow_meta",
    ),
    "dst_ip": FeatureDefinition(
        "dst_ip",
        FeatureType.STRING,
        "Destination IP address (flow responder)",
        group="flow_meta",
    ),
    "src_port": FeatureDefinition(
        "src_port",
        FeatureType.INTEGER,
        "Source port number",
        group="flow_meta",
    ),
    "dst_port": FeatureDefinition(
        "dst_port",
        FeatureType.INTEGER,
        "Destination port number",
        group="flow_meta",
    ),
    "protocol": FeatureDefinition(
        "protocol",
        FeatureType.INTEGER,
        "IP protocol number (6=TCP, 17=UDP)",
        group="flow_meta",
    ),
    "duration": FeatureDefinition(
        "duration",
        FeatureType.FLOAT,
        "Flow duration from first to last packet",
        unit="seconds",
        group="flow_meta",
    ),
    "total_packets": FeatureDefinition(
        "total_packets",
        FeatureType.INTEGER,
        "Total number of packets in both directions",
        group="flow_meta",
    ),
    "total_bytes": FeatureDefinition(
        "total_bytes",
        FeatureType.INTEGER,
        "Total bytes transmitted in both directions",
        unit="bytes",
        group="flow_meta",
    ),
    # Timing features
    "iat_mean": FeatureDefinition(
        "iat_mean",
        FeatureType.FLOAT,
        "Mean inter-arrival time between packets",
        unit="seconds",
        group="timing",
    ),
    "iat_std": FeatureDefinition(
        "iat_std",
        FeatureType.FLOAT,
        "Standard deviation of inter-arrival times",
        unit="seconds",
        group="timing",
    ),
    "burstiness_index": FeatureDefinition(
        "burstiness_index",
        FeatureType.FLOAT,
        "Coefficient of variation of IAT (std/mean)",
        group="timing",
    ),
    # Size features
    "pkt_len_mean": FeatureDefinition(
        "pkt_len_mean",
        FeatureType.FLOAT,
        "Mean packet length",
        unit="bytes",
        group="size",
    ),
    "pkt_len_std": FeatureDefinition(
        "pkt_len_std",
        FeatureType.FLOAT,
        "Standard deviation of packet lengths",
        unit="bytes",
        group="size",
    ),
    "dominant_pkt_size": FeatureDefinition(
        "dominant_pkt_size",
        FeatureType.INTEGER,
        "Most common packet size in the flow",
        unit="bytes",
        group="size",
    ),
    "dominant_pkt_ratio": FeatureDefinition(
        "dominant_pkt_ratio",
        FeatureType.FLOAT,
        "Proportion of packets with the dominant size",
        group="size",
    ),
    # TLS features
    "tls_detected": FeatureDefinition(
        "tls_detected",
        FeatureType.BOOLEAN,
        "Whether TLS handshake was detected",
        group="tls",
    ),
    "tls_version_str": FeatureDefinition(
        "tls_version_str",
        FeatureType.STRING,
        "TLS version string (e.g., 'TLS 1.3')",
        group="tls",
    ),
    "tls_sni": FeatureDefinition(
        "tls_sni",
        FeatureType.STRING,
        "Server Name Indication from ClientHello",
        group="tls",
    ),
    "ja3_hash": FeatureDefinition(
        "ja3_hash",
        FeatureType.STRING,
        "JA3 client fingerprint hash",
        group="tls",
    ),
    "ja3s_hash": FeatureDefinition(
        "ja3s_hash",
        FeatureType.STRING,
        "JA3S server fingerprint hash",
        group="tls",
    ),
    "tls_key_exchange_group_name": FeatureDefinition(
        "tls_key_exchange_group_name",
        FeatureType.STRING,
        "Key exchange group name (e.g., 'x25519', 'secp256r1')",
        group="tls",
    ),
    # SSH features
    "ssh_detected": FeatureDefinition(
        "ssh_detected",
        FeatureType.BOOLEAN,
        "Whether SSH protocol was detected",
        group="ssh",
    ),
    "ssh_hassh": FeatureDefinition(
        "ssh_hassh",
        FeatureType.STRING,
        "HASSH client fingerprint hash",
        group="ssh",
    ),
    "ssh_hassh_server": FeatureDefinition(
        "ssh_hassh_server",
        FeatureType.STRING,
        "HASSHServer fingerprint hash",
        group="ssh",
    ),
    # QUIC features
    "quic_detected": FeatureDefinition(
        "quic_detected",
        FeatureType.BOOLEAN,
        "Whether QUIC protocol was detected",
        group="quic",
    ),
    "quic_version_str": FeatureDefinition(
        "quic_version_str",
        FeatureType.STRING,
        "QUIC version string",
        group="quic",
    ),
    "quic_sni": FeatureDefinition(
        "quic_sni",
        FeatureType.STRING,
        "Server Name Indication from QUIC Initial",
        group="quic",
    ),
    # Fingerprint features
    "likely_tor": FeatureDefinition(
        "likely_tor",
        FeatureType.BOOLEAN,
        "Whether traffic appears to be Tor",
        group="fingerprint",
    ),
    "likely_vpn": FeatureDefinition(
        "likely_vpn",
        FeatureType.BOOLEAN,
        "Whether traffic appears to be VPN",
        group="fingerprint",
    ),
    "likely_doh": FeatureDefinition(
        "likely_doh",
        FeatureType.BOOLEAN,
        "Whether traffic appears to be DNS-over-HTTPS",
        group="fingerprint",
    ),
    "traffic_type": FeatureDefinition(
        "traffic_type",
        FeatureType.STRING,
        "Classified traffic type (tor/vpn/doh/encrypted)",
        group="fingerprint",
    ),
    # Entropy features
    "entropy_payload": FeatureDefinition(
        "entropy_payload",
        FeatureType.FLOAT,
        "Shannon entropy of payload bytes (0-8 scale)",
        unit="bits/byte",
        group="entropy",
    ),
    "printable_ratio": FeatureDefinition(
        "printable_ratio",
        FeatureType.FLOAT,
        "Ratio of printable ASCII characters in payload",
        group="entropy",
    ),
}


def get_feature_definition(name: str) -> FeatureDefinition | None:
    """Get the definition for a feature by name.

    Args:
        name: Feature name.

    Returns:
        FeatureDefinition if found, None otherwise.
    """
    return FEATURE_DEFINITIONS.get(name)


def get_feature_documentation() -> str:
    """Generate markdown documentation for all features.

    Returns:
        Markdown-formatted feature documentation.
    """
    lines = ["# Feature Documentation\n"]

    # Group features by their group
    groups: dict[str, list[FeatureDefinition]] = {}
    for defn in FEATURE_DEFINITIONS.values():
        if defn.group not in groups:
            groups[defn.group] = []
        groups[defn.group].append(defn)

    for group_name, features in sorted(groups.items()):
        lines.append(f"\n## {group_name.replace('_', ' ').title()}\n")
        lines.append("| Feature | Type | Description | Unit |")
        lines.append("|---------|------|-------------|------|")

        for feat in sorted(features, key=lambda f: f.name):
            unit = feat.unit or "-"
            lines.append(f"| `{feat.name}` | {feat.type.value} | {feat.description} | {unit} |")

    return "\n".join(lines)


def export_schema_json(path: str | Path | None = None) -> str:
    """Export feature schema as JSON.

    Args:
        path: Optional file path to write to. If None, returns JSON string.

    Returns:
        JSON string representation of the schema.
    """
    schema = {
        "version": "1.0",
        "features": [defn.to_dict() for defn in FEATURE_DEFINITIONS.values()],
        "groups": sorted(set(d.group for d in FEATURE_DEFINITIONS.values())),
    }

    json_str = json.dumps(schema, indent=2)

    if path:
        Path(path).write_text(json_str)

    return json_str


def export_schema_csv(path: str | Path | None = None) -> str:
    """Export feature schema as CSV.

    Args:
        path: Optional file path to write to. If None, returns CSV string.

    Returns:
        CSV string representation of the schema.
    """
    import csv
    import io

    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow(["name", "type", "description", "unit", "group"])

    # Data
    for defn in sorted(FEATURE_DEFINITIONS.values(), key=lambda d: (d.group, d.name)):
        writer.writerow([defn.name, defn.type.value, defn.description, defn.unit or "", defn.group])

    csv_str = output.getvalue()

    if path:
        Path(path).write_text(csv_str)

    return csv_str


def get_all_feature_names() -> list[str]:
    """Get list of all documented feature names.

    Returns:
        Sorted list of feature names.
    """
    return sorted(FEATURE_DEFINITIONS.keys())


def get_features_by_group(group: str) -> list[FeatureDefinition]:
    """Get all features in a specific group.

    Args:
        group: Feature group name.

    Returns:
        List of FeatureDefinition objects in the group.
    """
    return [defn for defn in FEATURE_DEFINITIONS.values() if defn.group == group]


def get_available_groups() -> list[str]:
    """Get list of available feature groups.

    Returns:
        Sorted list of unique group names.
    """
    return sorted(set(d.group for d in FEATURE_DEFINITIONS.values()))
