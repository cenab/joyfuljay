"""TCP RTT (Round-Trip Time) estimation feature extractor."""

from __future__ import annotations

import math
from typing import TYPE_CHECKING, Any

from .base import FeatureExtractor

if TYPE_CHECKING:
    from ..core.flow import Flow


class TCPRTTExtractor(FeatureExtractor):
    """Extracts TCP RTT estimation features from flows.

    Features include:
    - RTT estimation from timestamp echoes
    - RTT statistics (min, max, avg, jitter)
    - Handshake RTT

    Corresponds to Tranalyzer feature #56.
    """

    def extract(self, flow: Flow) -> dict[str, Any]:
        """Extract TCP RTT estimation features from a flow.

        Args:
            flow: The completed flow.

        Returns:
            Dictionary of TCP RTT features.
        """
        features: dict[str, Any] = {}

        # Method 1: Handshake RTT (SYN -> SYN-ACK -> ACK)
        handshake_rtt = self._compute_handshake_rtt(flow)
        features["tcp_rtt_handshake"] = handshake_rtt

        # Method 2: Timestamp-based RTT estimation
        rtt_samples = self._compute_timestamp_rtt(flow)

        if rtt_samples:
            features["tcp_rtt_min"] = min(rtt_samples)
            features["tcp_rtt_max"] = max(rtt_samples)
            features["tcp_rtt_mean"] = sum(rtt_samples) / len(rtt_samples)
            features["tcp_rtt_samples"] = len(rtt_samples)

            # RTT variance and jitter
            if len(rtt_samples) >= 2:
                mean = features["tcp_rtt_mean"]
                variance = sum((x - mean) ** 2 for x in rtt_samples) / len(rtt_samples)
                features["tcp_rtt_std"] = math.sqrt(variance)

                # Jitter: average absolute difference between consecutive RTT samples
                jitters = [
                    abs(rtt_samples[i + 1] - rtt_samples[i])
                    for i in range(len(rtt_samples) - 1)
                ]
                features["tcp_rtt_jitter_avg"] = sum(jitters) / len(jitters) if jitters else 0.0
            else:
                features["tcp_rtt_std"] = 0.0
                features["tcp_rtt_jitter_avg"] = 0.0
        else:
            features["tcp_rtt_min"] = 0.0
            features["tcp_rtt_max"] = 0.0
            features["tcp_rtt_mean"] = 0.0
            features["tcp_rtt_samples"] = 0
            features["tcp_rtt_std"] = 0.0
            features["tcp_rtt_jitter_avg"] = 0.0

        # Method 3: ACK-based RTT (data -> ACK timing)
        ack_rtt = self._compute_ack_rtt(flow)
        if ack_rtt:
            features["tcp_rtt_ack_min"] = min(ack_rtt)
            features["tcp_rtt_ack_max"] = max(ack_rtt)
            features["tcp_rtt_ack_mean"] = sum(ack_rtt) / len(ack_rtt)
        else:
            features["tcp_rtt_ack_min"] = 0.0
            features["tcp_rtt_ack_max"] = 0.0
            features["tcp_rtt_ack_mean"] = 0.0

        return features

    def _compute_handshake_rtt(self, flow: Flow) -> float:
        """Compute RTT from TCP 3-way handshake.

        Args:
            flow: The flow to analyze.

        Returns:
            Handshake RTT in seconds, or 0 if not measurable.
        """
        syn_time: float | None = None
        synack_time: float | None = None
        ack_time: float | None = None

        for pkt in flow.packets:
            if pkt.tcp_flags is None:
                continue

            flags = pkt.tcp_flags
            is_syn = bool(flags & 0x02)
            is_ack = bool(flags & 0x10)

            is_forward = (
                pkt.src_ip == flow.initiator_ip and pkt.src_port == flow.initiator_port
            )

            # SYN from initiator
            if is_syn and not is_ack and is_forward and syn_time is None:
                syn_time = pkt.timestamp

            # SYN-ACK from responder
            if is_syn and is_ack and not is_forward and synack_time is None:
                synack_time = pkt.timestamp

            # ACK from initiator (completing handshake)
            if not is_syn and is_ack and is_forward and ack_time is None:
                if synack_time is not None:
                    ack_time = pkt.timestamp
                    break

        # Compute full RTT (SYN -> SYN-ACK -> ACK)
        if syn_time is not None and synack_time is not None and ack_time is not None:
            return ack_time - syn_time

        # Compute half RTT (SYN -> SYN-ACK)
        if syn_time is not None and synack_time is not None:
            return (synack_time - syn_time) * 2  # Estimate full RTT

        return 0.0

    def _compute_timestamp_rtt(self, flow: Flow) -> list[float]:
        """Compute RTT samples from TCP timestamps.

        Uses timestamp echo reply to match packets and compute RTT.

        Args:
            flow: The flow to analyze.

        Returns:
            List of RTT samples in seconds.
        """
        rtt_samples: list[float] = []

        # Track sent timestamps by direction
        # key: (direction, ts_val), value: packet timestamp
        sent_timestamps: dict[tuple[bool, int], float] = {}

        for pkt in flow.packets:
            if pkt.tcp_timestamp is None:
                continue

            ts_val, ts_ecr = pkt.tcp_timestamp
            is_forward = (
                pkt.src_ip == flow.initiator_ip and pkt.src_port == flow.initiator_port
            )

            # Record when this timestamp was sent
            sent_timestamps[(is_forward, ts_val)] = pkt.timestamp

            # Check if the echo reply matches a previously sent timestamp
            if ts_ecr != 0:
                # Look for the original timestamp in the opposite direction
                key = (not is_forward, ts_ecr)
                if key in sent_timestamps:
                    rtt = pkt.timestamp - sent_timestamps[key]
                    if 0 < rtt < 60:  # Sanity check: RTT should be < 60s
                        rtt_samples.append(rtt)

        return rtt_samples

    def _compute_ack_rtt(self, flow: Flow) -> list[float]:
        """Compute RTT from data packet to ACK timing.

        Args:
            flow: The flow to analyze.

        Returns:
            List of RTT samples in seconds.
        """
        rtt_samples: list[float] = []

        # Track unacknowledged sequence numbers
        # key: (direction, seq + len), value: packet timestamp
        pending_acks: dict[tuple[bool, int], float] = {}

        for pkt in flow.packets:
            if pkt.tcp_seq is None:
                continue

            is_forward = (
                pkt.src_ip == flow.initiator_ip and pkt.src_port == flow.initiator_port
            )

            # Record data packets (with payload)
            if pkt.payload_len > 0:
                next_seq = (pkt.tcp_seq + pkt.payload_len) % (2**32)
                pending_acks[(is_forward, next_seq)] = pkt.timestamp

            # Check ACKs from opposite direction
            if pkt.tcp_ack is not None:
                key = (not is_forward, pkt.tcp_ack)
                if key in pending_acks:
                    rtt = pkt.timestamp - pending_acks[key]
                    if 0 < rtt < 60:  # Sanity check
                        rtt_samples.append(rtt)
                    del pending_acks[key]

        return rtt_samples

    @property
    def feature_names(self) -> list[str]:
        """Get feature names produced by this extractor."""
        return [
            # Handshake RTT
            "tcp_rtt_handshake",
            # Timestamp-based RTT
            "tcp_rtt_min",
            "tcp_rtt_max",
            "tcp_rtt_mean",
            "tcp_rtt_samples",
            "tcp_rtt_std",
            "tcp_rtt_jitter_avg",
            # ACK-based RTT
            "tcp_rtt_ack_min",
            "tcp_rtt_ack_max",
            "tcp_rtt_ack_mean",
        ]

    @property
    def name(self) -> str:
        """Get the extractor name."""
        return "tcp_rtt"
