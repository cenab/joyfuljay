"""Payload entropy feature extractor."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..extensions import (
    byte_distribution_fast,
    character_class_counts_fast,
    shannon_entropy_fast,
)
from .base import FeatureExtractor

if TYPE_CHECKING:
    from ..core.flow import Flow


class EntropyExtractor(FeatureExtractor):
    """Extracts payload entropy features.

    Computes Shannon entropy and related metrics to distinguish
    encrypted, compressed, and plaintext traffic patterns.

    Features:
    - Shannon entropy (bits per byte, 0-8 range)
    - Entropy for initiator and responder separately
    - Byte frequency distribution statistics
    """

    def __init__(self, sample_size: int = 4096) -> None:
        """Initialize the entropy extractor.

        Args:
            sample_size: Maximum bytes to sample from each direction.
                Larger values are more accurate but slower.
        """
        self.sample_size = sample_size

    def extract(self, flow: Flow) -> dict[str, Any]:
        """Extract entropy features from a flow.

        Args:
            flow: The completed flow.

        Returns:
            Dictionary of entropy features.
        """
        features: dict[str, Any] = {
            "entropy_payload": 0.0,
            "entropy_initiator": 0.0,
            "entropy_responder": 0.0,
            "entropy_ratio": 0.0,
            "byte_distribution_uniformity": 0.0,
            "printable_ratio": 0.0,
            "null_ratio": 0.0,
            "high_byte_ratio": 0.0,
            "payload_bytes_sampled": 0,
        }

        # Collect payload bytes from each direction
        initiator_bytes = self._collect_payload_bytes(flow.initiator_packets)
        responder_bytes = self._collect_payload_bytes(flow.responder_packets)
        all_bytes = initiator_bytes + responder_bytes

        features["payload_bytes_sampled"] = len(all_bytes)

        if not all_bytes:
            return features

        # Use fast byte distribution analysis (computes entropy, uniformity, etc. in one pass)
        byte_dist = byte_distribution_fast(all_bytes)
        features["entropy_payload"] = byte_dist["entropy"]
        features["byte_distribution_uniformity"] = byte_dist["uniformity"]

        # Compute directional entropy
        if initiator_bytes:
            features["entropy_initiator"] = shannon_entropy_fast(initiator_bytes)
        if responder_bytes:
            features["entropy_responder"] = shannon_entropy_fast(responder_bytes)

        # Entropy ratio (initiator vs responder asymmetry)
        if features["entropy_responder"] > 0:
            features["entropy_ratio"] = (
                features["entropy_initiator"] / features["entropy_responder"]
            )
        elif features["entropy_initiator"] > 0:
            features["entropy_ratio"] = float("inf")

        # Character class analysis using fast implementation
        char_classes = character_class_counts_fast(all_bytes)
        total = char_classes["total"]

        features["printable_ratio"] = char_classes["printable_count"] / total
        features["null_ratio"] = char_classes["null_count"] / total
        features["high_byte_ratio"] = char_classes["high_byte_count"] / total

        return features

    def _collect_payload_bytes(self, packets: list) -> bytes:
        """Collect payload bytes from packets up to sample_size."""
        collected = bytearray()
        remaining = self.sample_size

        for packet in packets:
            if packet.raw_payload and remaining > 0:
                chunk = packet.raw_payload[:remaining]
                collected.extend(chunk)
                remaining -= len(chunk)

        return bytes(collected)

    @property
    def feature_names(self) -> list[str]:
        """Get feature names produced by this extractor."""
        return [
            "entropy_payload",
            "entropy_initiator",
            "entropy_responder",
            "entropy_ratio",
            "byte_distribution_uniformity",
            "printable_ratio",
            "null_ratio",
            "high_byte_ratio",
            "payload_bytes_sampled",
        ]
