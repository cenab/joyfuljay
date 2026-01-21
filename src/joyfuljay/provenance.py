"""Provenance metadata for feature extraction outputs."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any


def compute_config_hash(config: dict[str, Any]) -> str:
    """Compute a stable hash of configuration dictionary.

    Args:
        config: Configuration dictionary.

    Returns:
        SHA-256 hash prefixed with "sha256:".
    """
    # Sort keys for stable ordering
    sorted_json = json.dumps(config, sort_keys=True, default=str)
    hash_value = hashlib.sha256(sorted_json.encode("utf-8")).hexdigest()
    return f"sha256:{hash_value}"


def build_provenance(
    profile: str = "JJ-CORE",
    schema_version: str = "v1.0",
    backend: str = "scapy",
    capture_mode: str = "offline",
    config: dict[str, Any] | None = None,
    ip_anonymization: bool = False,
    port_redaction: bool = False,
) -> dict[str, Any]:
    """Build provenance metadata dictionary.

    Args:
        profile: Feature profile name (e.g., "JJ-CORE").
        schema_version: Schema version string (e.g., "v1.0").
        backend: Capture backend name (e.g., "scapy", "dpkt", "remote").
        capture_mode: Capture mode ("offline" or "live").
        config: Configuration dictionary for hashing.
        ip_anonymization: Whether IP anonymization is enabled.
        port_redaction: Whether port redaction is enabled.

    Returns:
        Provenance metadata dictionary.
    """
    from . import __version__

    config_dict = config or {}
    timestamp = datetime.now(timezone.utc).isoformat()

    return {
        "jj_version": __version__,
        "schema_version": schema_version,
        "profile": profile,
        "backend": backend,
        "capture_mode": capture_mode,
        "config_hash": compute_config_hash(config_dict),
        "timestamp_generated": timestamp,
        "privacy": {
            "ip_anonymization": ip_anonymization,
            "port_redaction": port_redaction,
        },
    }


def write_provenance_sidecar(
    output_path: str,
    provenance: dict[str, Any],
) -> str:
    """Write provenance metadata to a sidecar JSON file.

    Args:
        output_path: Path to the main output file.
        provenance: Provenance metadata dictionary.

    Returns:
        Path to the written sidecar file.
    """
    from pathlib import Path

    output = Path(output_path)
    sidecar_path = output.with_suffix(output.suffix + ".provenance.json")

    with open(sidecar_path, "w", encoding="utf-8") as f:
        json.dump(provenance, f, indent=2)

    return str(sidecar_path)


def provenance_to_jsonl_header(provenance: dict[str, Any]) -> str:
    """Convert provenance to JSONL metadata header line.

    Args:
        provenance: Provenance metadata dictionary.

    Returns:
        JSON string for the metadata line.
    """
    return json.dumps({"type": "metadata", "provenance": provenance})
