"""Packet size and directionality feature extractor."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..extensions import compute_statistics_fast
from .base import FeatureExtractor

if TYPE_CHECKING:
    from ..core.flow import Flow


class SizeExtractor(FeatureExtractor):
    """Extracts packet size and directionality features.

    Features include:
    - Packet length statistics (overall and per-direction)
    - Payload size statistics
    - Directional patterns (signed packet lengths)
    - Optional raw size sequences
    """

    def __init__(
        self,
        include_sequences: bool = False,
        max_sequence_length: int = 50,
    ) -> None:
        """Initialize the size extractor.

        Args:
            include_sequences: Whether to include raw size sequences.
            max_sequence_length: Maximum sequence length to include.
        """
        self.include_sequences = include_sequences
        self.max_sequence_length = max_sequence_length

    def extract(self, flow: Flow) -> dict[str, Any]:
        """Extract size-related features from a flow.

        Args:
            flow: The completed flow.

        Returns:
            Dictionary of size features.
        """
        features: dict[str, Any] = {}

        # Get packet sizes
        all_sizes = [p.total_len for p in flow.packets]
        fwd_sizes = [p.total_len for p in flow.initiator_packets]
        bwd_sizes = [p.total_len for p in flow.responder_packets]

        # Get payload sizes
        all_payloads = [p.payload_len for p in flow.packets]
        fwd_payloads = [p.payload_len for p in flow.initiator_packets]
        bwd_payloads = [p.payload_len for p in flow.responder_packets]

        # Overall packet size statistics
        all_stats = compute_statistics_fast(all_sizes)
        features["pkt_len_min"] = all_stats["min"]
        features["pkt_len_max"] = all_stats["max"]
        features["pkt_len_mean"] = all_stats["mean"]
        features["pkt_len_std"] = all_stats["std"]
        features["pkt_len_median"] = all_stats["median"]
        features["pkt_len_p25"] = all_stats["p25"]
        features["pkt_len_p75"] = all_stats["p75"]
        features["pkt_len_p90"] = all_stats["p90"]

        # Forward packet size statistics
        fwd_stats = compute_statistics_fast(fwd_sizes)
        features["pkt_len_fwd_min"] = fwd_stats["min"]
        features["pkt_len_fwd_max"] = fwd_stats["max"]
        features["pkt_len_fwd_mean"] = fwd_stats["mean"]
        features["pkt_len_fwd_std"] = fwd_stats["std"]
        features["pkt_len_fwd_median"] = fwd_stats["median"]

        # Backward packet size statistics
        bwd_stats = compute_statistics_fast(bwd_sizes)
        features["pkt_len_bwd_min"] = bwd_stats["min"]
        features["pkt_len_bwd_max"] = bwd_stats["max"]
        features["pkt_len_bwd_mean"] = bwd_stats["mean"]
        features["pkt_len_bwd_std"] = bwd_stats["std"]
        features["pkt_len_bwd_median"] = bwd_stats["median"]

        # Payload size statistics
        payload_stats = compute_statistics_fast(all_payloads)
        features["payload_len_min"] = payload_stats["min"]
        features["payload_len_max"] = payload_stats["max"]
        features["payload_len_mean"] = payload_stats["mean"]
        features["payload_len_std"] = payload_stats["std"]

        # Forward payload statistics
        fwd_payload_stats = compute_statistics_fast(fwd_payloads)
        features["payload_len_fwd_mean"] = fwd_payload_stats["mean"]
        features["payload_len_fwd_std"] = fwd_payload_stats["std"]

        # Backward payload statistics
        bwd_payload_stats = compute_statistics_fast(bwd_payloads)
        features["payload_len_bwd_mean"] = bwd_payload_stats["mean"]
        features["payload_len_bwd_std"] = bwd_payload_stats["std"]

        # Packet count with payload (non-zero payload)
        features["packets_with_payload"] = sum(1 for p in all_payloads if p > 0)
        features["packets_with_payload_fwd"] = sum(1 for p in fwd_payloads if p > 0)
        features["packets_with_payload_bwd"] = sum(1 for p in bwd_payloads if p > 0)

        # Header-only packet ratio
        total_pkts = len(all_sizes)
        if total_pkts > 0:
            features["header_only_ratio"] = (total_pkts - features["packets_with_payload"]) / total_pkts
        else:
            features["header_only_ratio"] = 0.0

        # Size variance analysis (useful for detecting padding/fixed-size protocols)
        if len(all_sizes) > 1:
            features["pkt_len_variance"] = all_stats["std"] ** 2
        else:
            features["pkt_len_variance"] = 0.0

        # Dominant packet size (most common size)
        if all_sizes:
            from collections import Counter

            size_counts = Counter(all_sizes)
            dominant_size, dominant_count = size_counts.most_common(1)[0]
            features["dominant_pkt_size"] = dominant_size
            features["dominant_pkt_ratio"] = dominant_count / len(all_sizes)
        else:
            features["dominant_pkt_size"] = 0
            features["dominant_pkt_ratio"] = 0.0

        # L7 (Layer 7 / payload) byte statistics - Tranalyzer compatible
        l7_bytes_fwd = sum(fwd_payloads)
        l7_bytes_bwd = sum(bwd_payloads)
        features["l7_bytes_fwd"] = l7_bytes_fwd
        features["l7_bytes_bwd"] = l7_bytes_bwd
        features["l7_bytes_total"] = l7_bytes_fwd + l7_bytes_bwd

        # Min/max L7 packet sizes
        l7_pkts_fwd = [p for p in fwd_payloads if p > 0]
        l7_pkts_bwd = [p for p in bwd_payloads if p > 0]
        features["l7_pkt_min_fwd"] = min(l7_pkts_fwd) if l7_pkts_fwd else 0
        features["l7_pkt_max_fwd"] = max(l7_pkts_fwd) if l7_pkts_fwd else 0
        features["l7_pkt_min_bwd"] = min(l7_pkts_bwd) if l7_pkts_bwd else 0
        features["l7_pkt_max_bwd"] = max(l7_pkts_bwd) if l7_pkts_bwd else 0

        # Asymmetry metrics - Tranalyzer compatible
        # pktAsm = (pkts_fwd - pkts_bwd) / (pkts_fwd + pkts_bwd)
        pkts_fwd = len(fwd_sizes)
        pkts_bwd = len(bwd_sizes)
        total_pkts = pkts_fwd + pkts_bwd
        if total_pkts > 0:
            features["pkt_asymmetry"] = (pkts_fwd - pkts_bwd) / total_pkts
        else:
            features["pkt_asymmetry"] = 0.0

        # bytAsm = (bytes_fwd - bytes_bwd) / (bytes_fwd + bytes_bwd)
        bytes_fwd = sum(fwd_sizes)
        bytes_bwd = sum(bwd_sizes)
        total_bytes = bytes_fwd + bytes_bwd
        if total_bytes > 0:
            features["byte_asymmetry"] = (bytes_fwd - bytes_bwd) / total_bytes
        else:
            features["byte_asymmetry"] = 0.0

        # Optional raw sequences (signed: positive=fwd, negative=bwd)
        if self.include_sequences:
            signed_sizes: list[int] = []
            for packet in flow.packets:
                if packet.src_ip == flow.initiator_ip:
                    signed_sizes.append(packet.total_len)
                else:
                    signed_sizes.append(-packet.total_len)

            # Pad or truncate
            seq = signed_sizes[: self.max_sequence_length]
            padded = seq + [0] * (self.max_sequence_length - len(seq))
            features["pkt_len_sequence"] = padded

        return features

    @property
    def feature_names(self) -> list[str]:
        """Get feature names produced by this extractor."""
        names = [
            # Overall size stats
            "pkt_len_min",
            "pkt_len_max",
            "pkt_len_mean",
            "pkt_len_std",
            "pkt_len_median",
            "pkt_len_p25",
            "pkt_len_p75",
            "pkt_len_p90",
            # Forward size stats
            "pkt_len_fwd_min",
            "pkt_len_fwd_max",
            "pkt_len_fwd_mean",
            "pkt_len_fwd_std",
            "pkt_len_fwd_median",
            # Backward size stats
            "pkt_len_bwd_min",
            "pkt_len_bwd_max",
            "pkt_len_bwd_mean",
            "pkt_len_bwd_std",
            "pkt_len_bwd_median",
            # Payload stats
            "payload_len_min",
            "payload_len_max",
            "payload_len_mean",
            "payload_len_std",
            "payload_len_fwd_mean",
            "payload_len_fwd_std",
            "payload_len_bwd_mean",
            "payload_len_bwd_std",
            # Payload packet counts
            "packets_with_payload",
            "packets_with_payload_fwd",
            "packets_with_payload_bwd",
            "header_only_ratio",
            # Variance and dominant size
            "pkt_len_variance",
            "dominant_pkt_size",
            "dominant_pkt_ratio",
            # L7 (payload) byte stats - Tranalyzer compatible
            "l7_bytes_fwd",
            "l7_bytes_bwd",
            "l7_bytes_total",
            "l7_pkt_min_fwd",
            "l7_pkt_max_fwd",
            "l7_pkt_min_bwd",
            "l7_pkt_max_bwd",
            # Asymmetry metrics - Tranalyzer compatible
            "pkt_asymmetry",
            "byte_asymmetry",
        ]

        if self.include_sequences:
            names.append("pkt_len_sequence")

        return names
