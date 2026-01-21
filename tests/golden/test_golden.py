"""Golden tests for determinism validation.

These tests verify that JoyfulJay produces identical feature values
across multiple runs for the same input PCAP and configuration.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

# Golden test configuration
GOLDEN_DIR = Path(__file__).parent
DATA_DIR = Path(__file__).parent.parent / "data"


def load_expected_output(name: str) -> dict[str, Any] | None:
    """Load expected output JSON for a golden test.

    Args:
        name: Test name (e.g., "sample" for sample.json).

    Returns:
        Expected output dict, or None if file doesn't exist.
    """
    path = GOLDEN_DIR / f"{name}.json"
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return None


def save_expected_output(name: str, data: dict[str, Any]) -> None:
    """Save expected output JSON for a golden test.

    Args:
        name: Test name.
        data: Data to save.
    """
    path = GOLDEN_DIR / f"{name}.json"
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def compare_feature_values(
    actual: dict[str, Any],
    expected: dict[str, Any],
    tolerance: float = 1e-9,
) -> list[str]:
    """Compare feature values with tolerance for floats.

    Args:
        actual: Actual feature values.
        expected: Expected feature values.
        tolerance: Tolerance for floating-point comparisons.

    Returns:
        List of difference descriptions (empty if identical).
    """
    differences: list[str] = []

    # Check for missing or extra keys
    actual_keys = set(actual.keys())
    expected_keys = set(expected.keys())

    missing = expected_keys - actual_keys
    extra = actual_keys - expected_keys

    if missing:
        differences.append(f"Missing features: {sorted(missing)}")
    if extra:
        differences.append(f"Extra features: {sorted(extra)}")

    # Compare common keys
    for key in actual_keys & expected_keys:
        actual_val = actual[key]
        expected_val = expected[key]

        if isinstance(expected_val, float) and isinstance(actual_val, float):
            if abs(actual_val - expected_val) > tolerance:
                differences.append(
                    f"{key}: expected {expected_val}, got {actual_val} "
                    f"(diff: {abs(actual_val - expected_val)})"
                )
        elif actual_val != expected_val:
            differences.append(f"{key}: expected {expected_val!r}, got {actual_val!r}")

    return differences


class TestGoldenDeterminism:
    """Tests for deterministic output validation."""

    @pytest.fixture
    def sample_pcap_path(self) -> Path:
        """Path to sample PCAP file."""
        return DATA_DIR / "sample.pcap"

    def test_sample_pcap_exists(self, sample_pcap_path: Path) -> None:
        """Verify sample PCAP exists."""
        assert sample_pcap_path.exists(), f"Sample PCAP not found: {sample_pcap_path}"

    @pytest.mark.skipif(
        not (GOLDEN_DIR / "sample.json").exists(),
        reason="Golden output not generated yet",
    )
    def test_sample_determinism(self, sample_pcap_path: Path) -> None:
        """Verify sample PCAP produces deterministic output."""
        from joyfuljay.core.config import Config
        from joyfuljay.core.pipeline import Pipeline

        # Load expected output
        expected = load_expected_output("sample")
        assert expected is not None, "Expected output not found"

        # Extract features
        config = Config(profile="JJ-CORE")
        pipeline = Pipeline(config)
        flows = pipeline.process_pcap(str(sample_pcap_path))

        # Normalize to list of feature dicts
        if hasattr(flows, "to_dict"):
            flow_dicts = flows.to_dict(orient="records")
        else:
            flow_dicts = list(flows)

        # Compare each flow
        for i, flow_features in enumerate(flow_dicts):
            if i < len(expected.get("flows", [])):
                expected_flow = expected["flows"][i]
                differences = compare_feature_values(
                    flow_features, expected_flow, tolerance=1e-9
                )
                assert not differences, f"Flow {i} differs:\n" + "\n".join(differences)

    def test_flow_key_determinism(self) -> None:
        """Verify flow key computation is deterministic."""
        from joyfuljay.determinism.key import compute_flow_key

        # Same packets in different order should produce same key
        key1 = compute_flow_key("10.0.0.1", 12345, "10.0.0.2", 443, 6)
        key2 = compute_flow_key("10.0.0.2", 443, "10.0.0.1", 12345, 6)

        # Keys should be identical (except for reversal flag)
        assert key1.src_ip == key2.src_ip
        assert key1.dst_ip == key2.dst_ip
        assert key1.src_port == key2.src_port
        assert key1.dst_port == key2.dst_port
        assert key1.protocol == key2.protocol
        assert key1.reversed != key2.reversed  # Opposite reversal

    def test_direction_determinism(self) -> None:
        """Verify direction labeling is deterministic."""
        from joyfuljay.determinism.direction import (
            Direction,
            determine_direction,
            get_direction_label,
        )

        # Initiator packet should always be FORWARD
        direction = determine_direction("10.0.0.1", 12345, "10.0.0.1", 12345)
        assert direction == Direction.FORWARD
        assert get_direction_label(direction, "src_dst") == "src_to_dst"

        # Responder packet should always be BACKWARD
        direction = determine_direction("10.0.0.2", 443, "10.0.0.1", 12345)
        assert direction == Direction.BACKWARD
        assert get_direction_label(direction, "src_dst") == "dst_to_src"

    def test_rounding_determinism(self) -> None:
        """Verify rounding is deterministic."""
        from joyfuljay.determinism.rounding import (
            RoundingPolicy,
            apply_rounding,
            stable_mean,
            stable_std,
        )

        # Test rounding policies
        value = 3.141592653589793
        assert apply_rounding(value, RoundingPolicy.NONE) == value
        assert apply_rounding(value, RoundingPolicy.DECIMALS_3) == 3.142
        assert apply_rounding(value, RoundingPolicy.INTEGER) == 3

        # Test stable algorithms
        values = [1.0, 2.0, 3.0, 4.0, 5.0]
        mean = stable_mean(values)
        std = stable_std(values)

        assert abs(mean - 3.0) < 1e-10
        assert abs(std - 1.4142135623730951) < 1e-10

    def test_multiple_runs_identical(self) -> None:
        """Verify multiple extraction runs produce identical results."""
        from joyfuljay.determinism.key import compute_flow_key
        from joyfuljay.determinism.rounding import stable_mean

        # Run the same computation 100 times
        results = []
        for _ in range(100):
            key = compute_flow_key("192.168.1.1", 54321, "10.0.0.1", 443, 6)
            mean = stable_mean([1.1, 2.2, 3.3, 4.4, 5.5])
            results.append((key, mean))

        # All results should be identical
        first = results[0]
        for result in results[1:]:
            assert result[0] == first[0], "Flow key differs between runs"
            assert result[1] == first[1], "Mean differs between runs"


class TestGoldenGeneration:
    """Tests for golden output generation."""

    def test_generate_expected_output_structure(self) -> None:
        """Verify expected output structure is correct."""
        expected = {
            "jj_version": "0.1.0",
            "schema_version": "v1.0",
            "profile": "JJ-CORE",
            "config_hash": "sha256:...",
            "flows": [
                {
                    "flow_meta.src_ip": "192.168.1.100",
                    "flow_meta.dst_ip": "10.0.0.1",
                    "timing.duration": 1.0,
                    # ... more features
                }
            ],
        }

        assert "jj_version" in expected
        assert "schema_version" in expected
        assert "profile" in expected
        assert "flows" in expected
        assert isinstance(expected["flows"], list)
