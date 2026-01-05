"""Padding and obfuscation detection feature extractor."""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING, Any

import numpy as np

from .base import FeatureExtractor

if TYPE_CHECKING:
    from ..core.flow import Flow
    from ..core.packet import Packet

# Known fixed packet sizes for common protocols
TOR_CELL_SIZE = 586  # Tor cell (512 bytes) + TLS overhead
TOR_CELL_SIZE_NEW = 588  # Newer Tor versions
IPSEC_MTU_SIZE = 1420  # Common IPsec ESP packet size


class PaddingExtractor(FeatureExtractor):
    """Extracts padding and obfuscation detection features.

    Detects patterns indicative of:
    - Fixed-size padding (like Tor cells)
    - Constant-rate traffic shaping
    - Protocol obfuscation
    """

    def __init__(
        self,
        constant_size_threshold: float = 0.95,
        constant_rate_cv_threshold: float = 0.1,
        burst_threshold_ms: float = 50.0,
    ) -> None:
        """Initialize the padding extractor.

        Args:
            constant_size_threshold: Ratio threshold for constant size detection.
            constant_rate_cv_threshold: CV threshold for constant rate detection.
            burst_threshold_ms: Gap threshold (ms) defining burst boundaries.
        """
        self.constant_size_threshold = constant_size_threshold
        self.constant_rate_cv_threshold = constant_rate_cv_threshold
        self.burst_threshold_seconds = burst_threshold_ms / 1000.0

    def extract(self, flow: Flow) -> dict[str, Any]:
        """Extract padding detection features from a flow.

        Args:
            flow: The completed flow.

        Returns:
            Dictionary of padding-related features.
        """
        features: dict[str, Any] = {}

        # Get packet sizes and IATs
        sizes = [p.total_len for p in flow.packets]
        timestamps = [p.timestamp for p in flow.packets]

        # Size variance analysis
        features.update(self._analyze_size_distribution(sizes))

        # Timing variance analysis
        features.update(self._analyze_timing_distribution(timestamps))

        # Tor cell detection
        features.update(self._detect_tor_cells(sizes))

        # Burst padding analysis
        features.update(self._analyze_burst_padding(flow.packets))

        # Combined padding score
        features["padding_score"] = self._compute_padding_score(features)

        return features

    def _analyze_size_distribution(
        self,
        sizes: list[int],
    ) -> dict[str, Any]:
        """Analyze packet size distribution for padding indicators."""
        if len(sizes) == 0:
            return {
                "pkt_size_variance": 0.0,
                "pkt_size_cv": 0.0,
                "is_constant_size": False,
                "dominant_size_mode": 0,
                "dominant_size_ratio": 0.0,
                "unique_size_count": 0,
                "size_entropy": 0.0,
            }

        arr = np.array(sizes, dtype=np.float64)

        variance = float(np.var(arr))
        mean = float(np.mean(arr))
        cv = float(np.std(arr) / mean) if mean > 0 else 0.0

        # Dominant size (mode)
        counter = Counter(sizes)
        mode_size, mode_count = counter.most_common(1)[0]
        mode_ratio = mode_count / len(sizes)

        # Unique size count
        unique_count = len(counter)

        # Size entropy (normalized)
        size_entropy = self._compute_entropy(sizes)

        # Is constant size?
        is_constant = mode_ratio >= self.constant_size_threshold

        return {
            "pkt_size_variance": variance,
            "pkt_size_cv": cv,
            "is_constant_size": is_constant,
            "dominant_size_mode": mode_size,
            "dominant_size_ratio": mode_ratio,
            "unique_size_count": unique_count,
            "size_entropy": size_entropy,
        }

    def _analyze_timing_distribution(
        self,
        timestamps: list[float],
    ) -> dict[str, Any]:
        """Analyze timing distribution for constant-rate detection."""
        if len(timestamps) < 2:
            return {
                "iat_variance": 0.0,
                "iat_cv": 0.0,
                "is_constant_rate": False,
            }

        # Compute IATs
        arr = np.array(timestamps)
        iats = np.diff(arr)

        if len(iats) == 0:
            return {
                "iat_variance": 0.0,
                "iat_cv": 0.0,
                "is_constant_rate": False,
            }

        variance = float(np.var(iats))
        mean = float(np.mean(iats))
        cv = float(np.std(iats) / mean) if mean > 0 else 0.0

        # Is constant rate?
        is_constant = cv <= self.constant_rate_cv_threshold

        return {
            "iat_variance": variance,
            "iat_cv": cv,
            "is_constant_rate": is_constant,
        }

    def _detect_tor_cells(self, sizes: list[int]) -> dict[str, Any]:
        """Detect Tor cell characteristics in packet sizes."""
        if len(sizes) == 0:
            return {
                "tor_cell_count": 0,
                "tor_cell_ratio": 0.0,
                "is_tor_like": False,
            }

        # Count packets near Tor cell sizes (with some tolerance)
        tor_sizes = {TOR_CELL_SIZE, TOR_CELL_SIZE_NEW, 586, 587, 588, 589}
        tor_count = sum(1 for s in sizes if s in tor_sizes or (580 <= s <= 600))
        tor_ratio = tor_count / len(sizes)

        # Also check for common Tor packet patterns
        # Tor typically has very uniform packet sizes
        is_tor_like = tor_ratio >= 0.7 and self._is_uniform_sizes(sizes)

        return {
            "tor_cell_count": tor_count,
            "tor_cell_ratio": tor_ratio,
            "is_tor_like": is_tor_like,
        }

    def _is_uniform_sizes(self, sizes: list[int]) -> bool:
        """Check if sizes are uniform (low variance)."""
        if len(sizes) < 2:
            return True

        arr = np.array(sizes, dtype=np.float64)
        cv = float(np.std(arr) / np.mean(arr)) if np.mean(arr) > 0 else 0
        return cv < 0.1

    def _compute_entropy(self, values: list[int]) -> float:
        """Compute normalized entropy of a value distribution."""
        if len(values) == 0:
            return 0.0

        counter = Counter(values)
        total = len(values)
        probabilities = [count / total for count in counter.values()]

        entropy = 0.0
        for p in probabilities:
            if p > 0:
                entropy -= p * np.log2(p)

        # Normalize by max entropy
        max_entropy = np.log2(len(counter)) if len(counter) > 1 else 1.0
        return float(entropy / max_entropy) if max_entropy > 0 else 0.0

    def _analyze_burst_padding(self, packets: list[Packet]) -> dict[str, Any]:
        """Analyze padding characteristics within bursts.

        Calculates the ratio of payload to overhead per burst, which can
        indicate padding or obfuscation.

        Args:
            packets: List of packets in the flow.

        Returns:
            Dictionary of burst padding features.
        """
        if len(packets) < 2:
            return {
                "burst_padding_ratio": 0.0,
                "burst_overhead_bytes": 0,
                "avg_burst_payload_efficiency": 1.0,
            }

        # Identify bursts based on IAT threshold
        bursts: list[list[Packet]] = []
        current_burst: list[Packet] = [packets[0]]

        for i in range(1, len(packets)):
            iat = packets[i].timestamp - packets[i - 1].timestamp
            if iat < self.burst_threshold_seconds:
                current_burst.append(packets[i])
            else:
                if current_burst:
                    bursts.append(current_burst)
                current_burst = [packets[i]]

        if current_burst:
            bursts.append(current_burst)

        if not bursts:
            return {
                "burst_padding_ratio": 0.0,
                "burst_overhead_bytes": 0,
                "avg_burst_payload_efficiency": 1.0,
            }

        # Calculate padding metrics per burst
        total_payload = 0
        total_overhead = 0
        efficiencies: list[float] = []

        for burst in bursts:
            burst_payload = sum(p.payload_len for p in burst)
            burst_total = sum(p.total_len for p in burst)
            burst_overhead = burst_total - burst_payload

            total_payload += burst_payload
            total_overhead += burst_overhead

            if burst_total > 0:
                efficiencies.append(burst_payload / burst_total)

        # Overall padding ratio (overhead / total)
        total_bytes = total_payload + total_overhead
        if total_bytes > 0:
            padding_ratio = total_overhead / total_bytes
        else:
            padding_ratio = 0.0

        # Average payload efficiency across bursts
        avg_efficiency = sum(efficiencies) / len(efficiencies) if efficiencies else 1.0

        return {
            "burst_padding_ratio": padding_ratio,
            "burst_overhead_bytes": total_overhead,
            "avg_burst_payload_efficiency": avg_efficiency,
        }

    def _compute_padding_score(self, features: dict[str, Any]) -> float:
        """Compute overall padding/obfuscation score.

        Higher score indicates more likely padding/obfuscation.

        Returns:
            Score between 0.0 and 1.0.
        """
        score = 0.0

        # Constant size increases score
        if features.get("is_constant_size"):
            score += 0.3

        # High dominant ratio increases score
        if features.get("dominant_size_ratio", 0) > 0.8:
            score += 0.2

        # Constant rate increases score
        if features.get("is_constant_rate"):
            score += 0.2

        # Tor-like patterns
        if features.get("is_tor_like"):
            score += 0.3

        return min(score, 1.0)

    @property
    def feature_names(self) -> list[str]:
        """Get feature names produced by this extractor."""
        return [
            "pkt_size_variance",
            "pkt_size_cv",
            "is_constant_size",
            "dominant_size_mode",
            "dominant_size_ratio",
            "unique_size_count",
            "size_entropy",
            "iat_variance",
            "iat_cv",
            "is_constant_rate",
            "tor_cell_count",
            "tor_cell_ratio",
            "is_tor_like",
            "burst_padding_ratio",
            "burst_overhead_bytes",
            "avg_burst_payload_efficiency",
            "padding_score",
        ]
