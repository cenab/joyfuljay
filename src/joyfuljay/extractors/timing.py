"""Timing and burst metrics feature extractor."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..extensions import compute_interarrival_times_fast, compute_statistics_fast
from ..utils.stats import coefficient_of_variation
from .base import FeatureExtractor

if TYPE_CHECKING:
    from ..core.flow import Flow
    from ..core.packet import Packet


class TimingExtractor(FeatureExtractor):
    """Extracts timing-related features from flows.

    Features include:
    - Inter-arrival time (IAT) statistics
    - Per-direction IAT statistics
    - Burst and idle metrics
    - Optional raw IAT sequences
    - Optional SPLT (Sequence of Packet Lengths and Times) encoding
    """

    def __init__(
        self,
        include_sequences: bool = False,
        max_sequence_length: int = 50,
        burst_threshold_ms: float = 50.0,
        include_splt: bool = False,
    ) -> None:
        """Initialize the timing extractor.

        Args:
            include_sequences: Whether to include raw IAT sequences.
            max_sequence_length: Maximum sequence length to include.
            burst_threshold_ms: Gap threshold (ms) defining burst boundaries.
            include_splt: Whether to include SPLT (Sequence of Packet Lengths and Times).
        """
        self.include_sequences = include_sequences
        self.max_sequence_length = max_sequence_length
        self.burst_threshold_seconds = burst_threshold_ms / 1000.0
        self.include_splt = include_splt

    def extract(self, flow: Flow) -> dict[str, Any]:
        """Extract timing features from a flow.

        Args:
            flow: The completed flow.

        Returns:
            Dictionary of timing features.
        """
        features: dict[str, Any] = {}

        # Get timestamps
        all_timestamps = [p.timestamp for p in flow.packets]
        fwd_timestamps = [p.timestamp for p in flow.initiator_packets]
        bwd_timestamps = [p.timestamp for p in flow.responder_packets]

        # Compute IATs using fast implementation
        all_iats = compute_interarrival_times_fast(all_timestamps)
        fwd_iats = compute_interarrival_times_fast(fwd_timestamps)
        bwd_iats = compute_interarrival_times_fast(bwd_timestamps)

        # Overall IAT statistics
        all_stats = compute_statistics_fast(all_iats)
        features["iat_min"] = all_stats["min"]
        features["iat_max"] = all_stats["max"]
        features["iat_mean"] = all_stats["mean"]
        features["iat_std"] = all_stats["std"]
        features["iat_median"] = all_stats["median"]
        features["iat_sum"] = all_stats["sum"]
        features["iat_p25"] = all_stats["p25"]
        features["iat_p75"] = all_stats["p75"]
        features["iat_p90"] = all_stats["p90"]
        features["iat_p99"] = all_stats["p99"]

        # Forward direction IAT statistics
        fwd_stats = compute_statistics_fast(fwd_iats)
        features["iat_fwd_min"] = fwd_stats["min"]
        features["iat_fwd_max"] = fwd_stats["max"]
        features["iat_fwd_mean"] = fwd_stats["mean"]
        features["iat_fwd_std"] = fwd_stats["std"]
        features["iat_fwd_median"] = fwd_stats["median"]

        # Backward direction IAT statistics
        bwd_stats = compute_statistics_fast(bwd_iats)
        features["iat_bwd_min"] = bwd_stats["min"]
        features["iat_bwd_max"] = bwd_stats["max"]
        features["iat_bwd_mean"] = bwd_stats["mean"]
        features["iat_bwd_std"] = bwd_stats["std"]
        features["iat_bwd_median"] = bwd_stats["median"]

        # Burstiness index (coefficient of variation)
        features["burstiness_index"] = coefficient_of_variation(all_iats)
        features["burstiness_index_fwd"] = coefficient_of_variation(fwd_iats)
        features["burstiness_index_bwd"] = coefficient_of_variation(bwd_iats)

        # Burst and idle metrics
        burst_metrics = self._compute_burst_metrics(all_iats, flow.packets)
        features.update(burst_metrics)

        # First packet timing
        if len(flow.responder_packets) > 0:
            first_response_time = flow.responder_packets[0].timestamp - flow.start_time
            features["first_response_time"] = first_response_time
        else:
            features["first_response_time"] = 0.0

        # Optional raw sequences
        if self.include_sequences:
            # Pad or truncate to fixed length
            seq = all_iats[: self.max_sequence_length]
            padded = seq + [0.0] * (self.max_sequence_length - len(seq))
            features["iat_sequence"] = padded

            # Raw timestamp sequence (relative to flow start)
            ts_seq = [(t - flow.start_time) for t in all_timestamps[: self.max_sequence_length]]
            ts_padded = ts_seq + [0.0] * (self.max_sequence_length - len(ts_seq))
            features["timestamp_sequence"] = ts_padded

        # SPLT (Sequence of Packet Lengths and Times) encoding
        if self.include_splt:
            splt = self._compute_splt(flow)
            features["splt"] = splt
            # Also provide flattened version for ML compatibility
            features["splt_lengths"] = [p[0] for p in splt]
            features["splt_times"] = [p[1] for p in splt]
            features["splt_directions"] = [p[2] for p in splt]

        return features

    def _compute_splt(self, flow: Flow) -> list[tuple[int, float, int]]:
        """Compute SPLT (Sequence of Packet Lengths and Times).

        SPLT encodes each packet as a tuple of (length, time, direction):
        - length: Packet size in bytes
        - time: Inter-arrival time from previous packet (0 for first)
        - direction: 1 for forward (initiator->responder), -1 for backward

        Args:
            flow: The flow to encode.

        Returns:
            List of (length, time, direction) tuples, truncated to max_sequence_length.
        """
        if not flow.packets:
            return []

        splt: list[tuple[int, float, int]] = []
        prev_time = flow.packets[0].timestamp

        for i, packet in enumerate(flow.packets[: self.max_sequence_length]):
            # Determine direction
            if (packet.src_ip == flow.initiator_ip and
                packet.src_port == flow.initiator_port):
                direction = 1
            else:
                direction = -1

            # Calculate IAT (0 for first packet)
            if i == 0:
                iat = 0.0
            else:
                iat = packet.timestamp - prev_time
                prev_time = packet.timestamp

            splt.append((packet.total_len, iat, direction))

        return splt

    def _compute_burst_metrics(
        self,
        iats: list[float],
        packets: list[Packet],
    ) -> dict[str, Any]:
        """Compute burst and idle period metrics.

        A burst is defined as a sequence of packets with IATs below
        the threshold. Idle periods are gaps above the threshold.

        Args:
            iats: List of inter-arrival times.
            packets: List of packets (for size info during bursts).

        Returns:
            Dictionary of burst/idle metrics.
        """
        if len(iats) == 0:
            return {
                "burst_count": 0,
                "avg_burst_packets": 0.0,
                "avg_burst_duration": 0.0,
                "max_burst_packets": 0,
                "idle_count": 0,
                "avg_idle_duration": 0.0,
                "max_idle_duration": 0.0,
            }

        bursts: list[dict[str, float]] = []
        idles: list[float] = []

        current_burst_packets = 1  # First packet starts a burst
        current_burst_start_idx = 0

        for i, iat in enumerate(iats):
            if iat < self.burst_threshold_seconds:
                # Continue current burst
                current_burst_packets += 1
            else:
                # End current burst, start idle
                if current_burst_packets > 0:
                    burst_duration = sum(iats[current_burst_start_idx:i]) if i > current_burst_start_idx else 0.0
                    bursts.append({
                        "packets": current_burst_packets,
                        "duration": burst_duration,
                    })

                idles.append(iat)
                current_burst_packets = 1
                current_burst_start_idx = i + 1

        # Don't forget the last burst
        if current_burst_packets > 0:
            burst_duration = sum(iats[current_burst_start_idx:]) if current_burst_start_idx < len(iats) else 0.0
            bursts.append({
                "packets": current_burst_packets,
                "duration": burst_duration,
            })

        # Compute metrics
        burst_count = len(bursts)
        avg_burst_packets = sum(b["packets"] for b in bursts) / burst_count if burst_count > 0 else 0.0
        avg_burst_duration = sum(b["duration"] for b in bursts) / burst_count if burst_count > 0 else 0.0
        max_burst_packets = max((b["packets"] for b in bursts), default=0)

        idle_count = len(idles)
        avg_idle_duration = sum(idles) / idle_count if idle_count > 0 else 0.0
        max_idle_duration = max(idles, default=0.0)

        return {
            "burst_count": burst_count,
            "avg_burst_packets": avg_burst_packets,
            "avg_burst_duration": avg_burst_duration,
            "max_burst_packets": int(max_burst_packets),
            "idle_count": idle_count,
            "avg_idle_duration": avg_idle_duration,
            "max_idle_duration": max_idle_duration,
        }

    @property
    def feature_names(self) -> list[str]:
        """Get feature names produced by this extractor."""
        names = [
            # Overall IAT stats
            "iat_min",
            "iat_max",
            "iat_mean",
            "iat_std",
            "iat_median",
            "iat_sum",
            "iat_p25",
            "iat_p75",
            "iat_p90",
            "iat_p99",
            # Forward IAT stats
            "iat_fwd_min",
            "iat_fwd_max",
            "iat_fwd_mean",
            "iat_fwd_std",
            "iat_fwd_median",
            # Backward IAT stats
            "iat_bwd_min",
            "iat_bwd_max",
            "iat_bwd_mean",
            "iat_bwd_std",
            "iat_bwd_median",
            # Burstiness
            "burstiness_index",
            "burstiness_index_fwd",
            "burstiness_index_bwd",
            # Burst metrics
            "burst_count",
            "avg_burst_packets",
            "avg_burst_duration",
            "max_burst_packets",
            "idle_count",
            "avg_idle_duration",
            "max_idle_duration",
            # Response timing
            "first_response_time",
        ]

        if self.include_sequences:
            names.extend(["iat_sequence", "timestamp_sequence"])

        if self.include_splt:
            names.extend(["splt", "splt_lengths", "splt_times", "splt_directions"])

        return names
