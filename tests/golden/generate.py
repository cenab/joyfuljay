"""Generate golden test outputs.

This script generates expected output JSON files for golden tests.
These files are used to validate determinism across JoyfulJay versions.

Usage:
    python -m tests.golden.generate

This will process all PCAP files in tests/data/ and generate corresponding
JSON files in tests/golden/.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# Directories
GOLDEN_DIR = Path(__file__).parent
DATA_DIR = Path(__file__).parent.parent / "data"


def generate_golden_output(pcap_path: Path, profile: str = "JJ-CORE") -> dict[str, Any]:
    """Generate golden output for a PCAP file.

    Args:
        pcap_path: Path to the PCAP file.
        profile: Feature profile to use.

    Returns:
        Dictionary with version info and flow features.
    """
    from joyfuljay import __version__
    from joyfuljay.core.config import Config
    from joyfuljay.core.pipeline import Pipeline
    from joyfuljay.provenance import compute_config_hash

    # Create configuration
    config = Config(profile=profile)

    # Extract features
    pipeline = Pipeline(config)
    flows = pipeline.process_pcap(str(pcap_path))

    # Convert flows to dicts (handle DataFrame if returned)
    flow_dicts: list[dict[str, Any]] = []
    if hasattr(flows, "to_dict"):
        # It's a DataFrame
        flow_dicts = flows.to_dict(orient="records")
    else:
        # It's a list of dicts
        flow_dicts = list(flows)

    # Build output
    return {
        "jj_version": __version__,
        "schema_version": "v1.0",
        "profile": profile,
        "config_hash": compute_config_hash(config.to_dict()),
        "pcap_file": pcap_path.name,
        "flow_count": len(flow_dicts),
        "flows": flow_dicts,
    }


def generate_all_golden_outputs() -> None:
    """Generate golden outputs for all PCAP files in tests/data/."""
    print(f"Looking for PCAP files in {DATA_DIR}")

    pcap_files = list(DATA_DIR.glob("*.pcap")) + list(DATA_DIR.glob("*.pcapng"))

    if not pcap_files:
        print("No PCAP files found!")
        return

    for pcap_path in pcap_files:
        output_name = pcap_path.stem
        output_path = GOLDEN_DIR / f"{output_name}.json"

        print(f"Processing {pcap_path.name}...")

        try:
            golden_output = generate_golden_output(pcap_path)

            with open(output_path, "w") as f:
                json.dump(golden_output, f, indent=2, default=str)

            print(f"  -> Generated {output_path.name}")
            print(f"     {golden_output['flow_count']} flows extracted")
        except Exception as e:
            print(f"  -> ERROR: {e}")


if __name__ == "__main__":
    generate_all_golden_outputs()
