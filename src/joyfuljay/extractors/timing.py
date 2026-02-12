"""Timing and burst metrics feature extractor."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..extensions import compute_interarrival_times_fast, compute_statistics_fast
from ..utils.stats import coefficient_of_variation
from .base import FeatureExtractor

if TYPE_CHECKING:
    from ..core.flow import Flow
    from ..core.packet import Packet
    from ..schema.registry import FeatureMeta


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
        packets = flow.packets
        if not packets:
            return []

        splt: list[tuple[int, float, int]] = []
        initiator_ip = flow.initiator_ip
        initiator_port = flow.initiator_port
        prev_time = packets[0].timestamp

        for i, packet in enumerate(packets[: self.max_sequence_length]):
            # Determine direction
            if (packet.src_ip == initiator_ip and
                packet.src_port == initiator_port):
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

        threshold = self.burst_threshold_seconds
        prefix_sums = [0.0]
        for iat in iats:
            prefix_sums.append(prefix_sums[-1] + iat)

        burst_count = 0
        sum_burst_packets = 0
        sum_burst_duration = 0.0
        max_burst_packets = 0

        idle_count = 0
        idle_sum = 0.0
        idle_max = 0.0

        current_burst_packets = 1  # First packet starts a burst
        current_burst_start_idx = 0

        for i, iat in enumerate(iats):
            if iat < threshold:
                # Continue current burst
                current_burst_packets += 1
            else:
                # End current burst, start idle
                if current_burst_packets > 0:
                    burst_duration = prefix_sums[i] - prefix_sums[current_burst_start_idx]
                    burst_count += 1
                    sum_burst_packets += current_burst_packets
                    sum_burst_duration += burst_duration
                    if current_burst_packets > max_burst_packets:
                        max_burst_packets = current_burst_packets

                idle_count += 1
                idle_sum += iat
                if iat > idle_max:
                    idle_max = iat
                current_burst_packets = 1
                current_burst_start_idx = i + 1

        # Don't forget the last burst
        if current_burst_packets > 0:
            burst_duration = prefix_sums[-1] - prefix_sums[current_burst_start_idx]
            burst_count += 1
            sum_burst_packets += current_burst_packets
            sum_burst_duration += burst_duration
            if current_burst_packets > max_burst_packets:
                max_burst_packets = current_burst_packets

        # Compute metrics
        avg_burst_packets = sum_burst_packets / burst_count if burst_count > 0 else 0.0
        avg_burst_duration = sum_burst_duration / burst_count if burst_count > 0 else 0.0

        avg_idle_duration = idle_sum / idle_count if idle_count > 0 else 0.0
        max_idle_duration = idle_max

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

    @property
    def extractor_id(self) -> str:
        """Get the stable identifier for this extractor."""
        return "timing"

    def feature_meta(self) -> dict[str, FeatureMeta]:
        """Get metadata for all features produced by this extractor."""
        from ..schema.registry import FeatureMeta

        meta: dict[str, FeatureMeta] = {}
        prefix = self.extractor_id

        # Define metadata for each feature
        feature_definitions = {
            # Overall IAT statistics
            "iat_min": FeatureMeta(
                id=f"{prefix}.iat_min",
                dtype="float64",
                shape=[1],
                units="s",
                scope="flow",
                direction="bidir",
                direction_semantics="Minimum IAT across all packets in flow",
                missing_policy="nan",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Minimum inter-arrival time between consecutive packets",
            ),
            "iat_max": FeatureMeta(
                id=f"{prefix}.iat_max",
                dtype="float64",
                shape=[1],
                units="s",
                scope="flow",
                direction="bidir",
                direction_semantics="Maximum IAT across all packets in flow",
                missing_policy="nan",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Maximum inter-arrival time between consecutive packets",
            ),
            "iat_mean": FeatureMeta(
                id=f"{prefix}.iat_mean",
                dtype="float64",
                shape=[1],
                units="s",
                scope="flow",
                direction="bidir",
                direction_semantics="Mean IAT across all packets in flow",
                missing_policy="nan",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Mean inter-arrival time between consecutive packets",
            ),
            "iat_std": FeatureMeta(
                id=f"{prefix}.iat_std",
                dtype="float64",
                shape=[1],
                units="s",
                scope="flow",
                direction="bidir",
                direction_semantics="Standard deviation of IAT across all packets",
                missing_policy="nan",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Standard deviation of inter-arrival times",
            ),
            "iat_median": FeatureMeta(
                id=f"{prefix}.iat_median",
                dtype="float64",
                shape=[1],
                units="s",
                scope="flow",
                direction="bidir",
                direction_semantics="Median IAT across all packets in flow",
                missing_policy="nan",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Median inter-arrival time between consecutive packets",
            ),
            "iat_sum": FeatureMeta(
                id=f"{prefix}.iat_sum",
                dtype="float64",
                shape=[1],
                units="s",
                scope="flow",
                direction="bidir",
                direction_semantics="Sum of all IATs (approximately flow duration)",
                missing_policy="nan",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Sum of all inter-arrival times",
            ),
            "iat_p25": FeatureMeta(
                id=f"{prefix}.iat_p25",
                dtype="float64",
                shape=[1],
                units="s",
                scope="flow",
                direction="bidir",
                direction_semantics="25th percentile of IAT distribution",
                missing_policy="nan",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="25th percentile of inter-arrival times",
            ),
            "iat_p75": FeatureMeta(
                id=f"{prefix}.iat_p75",
                dtype="float64",
                shape=[1],
                units="s",
                scope="flow",
                direction="bidir",
                direction_semantics="75th percentile of IAT distribution",
                missing_policy="nan",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="75th percentile of inter-arrival times",
            ),
            "iat_p90": FeatureMeta(
                id=f"{prefix}.iat_p90",
                dtype="float64",
                shape=[1],
                units="s",
                scope="flow",
                direction="bidir",
                direction_semantics="90th percentile of IAT distribution",
                missing_policy="nan",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="90th percentile of inter-arrival times",
            ),
            "iat_p99": FeatureMeta(
                id=f"{prefix}.iat_p99",
                dtype="float64",
                shape=[1],
                units="s",
                scope="flow",
                direction="bidir",
                direction_semantics="99th percentile of IAT distribution",
                missing_policy="nan",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="99th percentile of inter-arrival times",
            ),
            # Forward direction IAT statistics
            "iat_fwd_min": FeatureMeta(
                id=f"{prefix}.iat_fwd_min",
                dtype="float64",
                shape=[1],
                units="s",
                scope="direction",
                direction="src_to_dst",
                direction_semantics="Minimum IAT in forward direction only",
                missing_policy="nan",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Minimum forward direction inter-arrival time",
            ),
            "iat_fwd_max": FeatureMeta(
                id=f"{prefix}.iat_fwd_max",
                dtype="float64",
                shape=[1],
                units="s",
                scope="direction",
                direction="src_to_dst",
                direction_semantics="Maximum IAT in forward direction only",
                missing_policy="nan",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Maximum forward direction inter-arrival time",
            ),
            "iat_fwd_mean": FeatureMeta(
                id=f"{prefix}.iat_fwd_mean",
                dtype="float64",
                shape=[1],
                units="s",
                scope="direction",
                direction="src_to_dst",
                direction_semantics="Mean IAT in forward direction only",
                missing_policy="nan",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Mean forward direction inter-arrival time",
            ),
            "iat_fwd_std": FeatureMeta(
                id=f"{prefix}.iat_fwd_std",
                dtype="float64",
                shape=[1],
                units="s",
                scope="direction",
                direction="src_to_dst",
                direction_semantics="Standard deviation of IAT in forward direction",
                missing_policy="nan",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Standard deviation of forward direction inter-arrival times",
            ),
            "iat_fwd_median": FeatureMeta(
                id=f"{prefix}.iat_fwd_median",
                dtype="float64",
                shape=[1],
                units="s",
                scope="direction",
                direction="src_to_dst",
                direction_semantics="Median IAT in forward direction only",
                missing_policy="nan",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Median forward direction inter-arrival time",
            ),
            # Backward direction IAT statistics
            "iat_bwd_min": FeatureMeta(
                id=f"{prefix}.iat_bwd_min",
                dtype="float64",
                shape=[1],
                units="s",
                scope="direction",
                direction="dst_to_src",
                direction_semantics="Minimum IAT in backward direction only",
                missing_policy="nan",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Minimum backward direction inter-arrival time",
            ),
            "iat_bwd_max": FeatureMeta(
                id=f"{prefix}.iat_bwd_max",
                dtype="float64",
                shape=[1],
                units="s",
                scope="direction",
                direction="dst_to_src",
                direction_semantics="Maximum IAT in backward direction only",
                missing_policy="nan",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Maximum backward direction inter-arrival time",
            ),
            "iat_bwd_mean": FeatureMeta(
                id=f"{prefix}.iat_bwd_mean",
                dtype="float64",
                shape=[1],
                units="s",
                scope="direction",
                direction="dst_to_src",
                direction_semantics="Mean IAT in backward direction only",
                missing_policy="nan",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Mean backward direction inter-arrival time",
            ),
            "iat_bwd_std": FeatureMeta(
                id=f"{prefix}.iat_bwd_std",
                dtype="float64",
                shape=[1],
                units="s",
                scope="direction",
                direction="dst_to_src",
                direction_semantics="Standard deviation of IAT in backward direction",
                missing_policy="nan",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Standard deviation of backward direction inter-arrival times",
            ),
            "iat_bwd_median": FeatureMeta(
                id=f"{prefix}.iat_bwd_median",
                dtype="float64",
                shape=[1],
                units="s",
                scope="direction",
                direction="dst_to_src",
                direction_semantics="Median IAT in backward direction only",
                missing_policy="nan",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Median backward direction inter-arrival time",
            ),
            # Burstiness indices
            "burstiness_index": FeatureMeta(
                id=f"{prefix}.burstiness_index",
                dtype="float64",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="Coefficient of variation of IATs for entire flow",
                missing_policy="nan",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Burstiness index (coefficient of variation of IATs)",
            ),
            "burstiness_index_fwd": FeatureMeta(
                id=f"{prefix}.burstiness_index_fwd",
                dtype="float64",
                shape=[1],
                units="",
                scope="direction",
                direction="src_to_dst",
                direction_semantics="Coefficient of variation of forward IATs",
                missing_policy="nan",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Forward direction burstiness index",
            ),
            "burstiness_index_bwd": FeatureMeta(
                id=f"{prefix}.burstiness_index_bwd",
                dtype="float64",
                shape=[1],
                units="",
                scope="direction",
                direction="dst_to_src",
                direction_semantics="Coefficient of variation of backward IATs",
                missing_policy="nan",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Backward direction burstiness index",
            ),
            # Burst metrics
            "burst_count": FeatureMeta(
                id=f"{prefix}.burst_count",
                dtype="int64",
                shape=[1],
                units="count",
                scope="burst",
                direction="bidir",
                direction_semantics="Number of bursts across entire flow",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Number of detected packet bursts",
            ),
            "avg_burst_packets": FeatureMeta(
                id=f"{prefix}.avg_burst_packets",
                dtype="float64",
                shape=[1],
                units="count",
                scope="burst",
                direction="bidir",
                direction_semantics="Average packets per burst across flow",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Average number of packets per burst",
            ),
            "avg_burst_duration": FeatureMeta(
                id=f"{prefix}.avg_burst_duration",
                dtype="float64",
                shape=[1],
                units="s",
                scope="burst",
                direction="bidir",
                direction_semantics="Average burst duration across flow",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Average duration of a burst in seconds",
            ),
            "max_burst_packets": FeatureMeta(
                id=f"{prefix}.max_burst_packets",
                dtype="int64",
                shape=[1],
                units="count",
                scope="burst",
                direction="bidir",
                direction_semantics="Maximum packets in any single burst",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Maximum number of packets in a single burst",
            ),
            "idle_count": FeatureMeta(
                id=f"{prefix}.idle_count",
                dtype="int64",
                shape=[1],
                units="count",
                scope="burst",
                direction="bidir",
                direction_semantics="Number of idle periods across flow",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Number of detected idle periods between bursts",
            ),
            "avg_idle_duration": FeatureMeta(
                id=f"{prefix}.avg_idle_duration",
                dtype="float64",
                shape=[1],
                units="s",
                scope="burst",
                direction="bidir",
                direction_semantics="Average idle period duration",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Average duration of idle periods in seconds",
            ),
            "max_idle_duration": FeatureMeta(
                id=f"{prefix}.max_idle_duration",
                dtype="float64",
                shape=[1],
                units="s",
                scope="burst",
                direction="bidir",
                direction_semantics="Maximum idle period duration",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Maximum idle period duration in seconds",
            ),
            # Response timing
            "first_response_time": FeatureMeta(
                id=f"{prefix}.first_response_time",
                dtype="float64",
                shape=[1],
                units="s",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="Time from flow start to first responder packet",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Time to first response from responder",
            ),
            # Optional sequence features
            "iat_sequence": FeatureMeta(
                id=f"{prefix}.iat_sequence",
                dtype="float64",
                shape=[self.max_sequence_length],
                units="s",
                scope="packet_seq",
                direction="bidir",
                direction_semantics="Sequence of IATs for all packets, zero-padded",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Raw inter-arrival time sequence (padded to fixed length)",
            ),
            "timestamp_sequence": FeatureMeta(
                id=f"{prefix}.timestamp_sequence",
                dtype="float64",
                shape=[self.max_sequence_length],
                units="s",
                scope="packet_seq",
                direction="bidir",
                direction_semantics="Sequence of relative timestamps, zero-padded",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Raw timestamp sequence relative to flow start (padded)",
            ),
            # SPLT features
            "splt": FeatureMeta(
                id=f"{prefix}.splt",
                dtype="float64",
                shape="variable",
                units="",
                scope="packet_seq",
                direction="bidir",
                direction_semantics="SPLT tuples for each packet in sequence",
                missing_policy="empty",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Sequence of Packet Lengths and Times (length, iat, direction)",
            ),
            "splt_lengths": FeatureMeta(
                id=f"{prefix}.splt_lengths",
                dtype="int64",
                shape=[self.max_sequence_length],
                units="bytes",
                scope="packet_seq",
                direction="bidir",
                direction_semantics="Packet lengths from SPLT encoding",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="SPLT packet length sequence",
            ),
            "splt_times": FeatureMeta(
                id=f"{prefix}.splt_times",
                dtype="float64",
                shape=[self.max_sequence_length],
                units="s",
                scope="packet_seq",
                direction="bidir",
                direction_semantics="Inter-arrival times from SPLT encoding",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="SPLT inter-arrival time sequence",
            ),
            "splt_directions": FeatureMeta(
                id=f"{prefix}.splt_directions",
                dtype="int64",
                shape=[self.max_sequence_length],
                units="",
                scope="packet_seq",
                direction="bidir",
                direction_semantics="Packet directions from SPLT (1=fwd, -1=bwd)",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="SPLT direction sequence (1=forward, -1=backward)",
            ),
        }

        # Only include metadata for features we actually produce
        for name in self.feature_names:
            if name in feature_definitions:
                meta[f"{prefix}.{name}"] = feature_definitions[name]

        return meta
