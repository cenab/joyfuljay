"""TCP sequence number analysis feature extractor."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .base import FeatureExtractor

if TYPE_CHECKING:
    from ..core.flow import Flow


class TCPSequenceExtractor(FeatureExtractor):
    """Extracts TCP sequence and acknowledgment analysis features.

    Features include:
    - Initial sequence numbers (ISN)
    - Sequence number gaps/faults
    - ACK analysis
    - Retransmission detection

    Corresponds to Tranalyzer feature #51.
    """

    def extract(self, flow: Flow) -> dict[str, Any]:
        """Extract TCP sequence analysis features from a flow.

        Args:
            flow: The completed flow.

        Returns:
            Dictionary of TCP sequence features.
        """
        features: dict[str, Any] = {}

        # Separate packets by direction
        fwd_seq_packets: list[tuple[int, int, int]] = []  # (seq, payload_len, timestamp)
        bwd_seq_packets: list[tuple[int, int, int]] = []
        fwd_ack_packets: list[tuple[int, int]] = []  # (ack, timestamp)
        bwd_ack_packets: list[tuple[int, int]] = []

        fwd_isn: int | None = None
        bwd_isn: int | None = None

        for pkt in flow.packets:
            if pkt.tcp_seq is None:
                continue

            is_forward = (
                pkt.src_ip == flow.initiator_ip and pkt.src_port == flow.initiator_port
            )

            if is_forward:
                fwd_seq_packets.append((pkt.tcp_seq, pkt.payload_len, int(pkt.timestamp * 1000)))
                if fwd_isn is None:
                    fwd_isn = pkt.tcp_seq
                if pkt.tcp_ack is not None:
                    fwd_ack_packets.append((pkt.tcp_ack, int(pkt.timestamp * 1000)))
            else:
                bwd_seq_packets.append((pkt.tcp_seq, pkt.payload_len, int(pkt.timestamp * 1000)))
                if bwd_isn is None:
                    bwd_isn = pkt.tcp_seq
                if pkt.tcp_ack is not None:
                    bwd_ack_packets.append((pkt.tcp_ack, int(pkt.timestamp * 1000)))

        # Initial Sequence Numbers
        features["tcp_isn_fwd"] = fwd_isn if fwd_isn is not None else 0
        features["tcp_isn_bwd"] = bwd_isn if bwd_isn is not None else 0

        # Sequence number analysis - Forward direction
        fwd_analysis = self._analyze_sequence(fwd_seq_packets)
        features["tcp_seq_fwd_bytes_sent"] = fwd_analysis["bytes_sent"]
        features["tcp_seq_fwd_retrans"] = fwd_analysis["retransmissions"]
        features["tcp_seq_fwd_gaps"] = fwd_analysis["gaps"]
        features["tcp_seq_fwd_ooo"] = fwd_analysis["out_of_order"]

        # Sequence number analysis - Backward direction
        bwd_analysis = self._analyze_sequence(bwd_seq_packets)
        features["tcp_seq_bwd_bytes_sent"] = bwd_analysis["bytes_sent"]
        features["tcp_seq_bwd_retrans"] = bwd_analysis["retransmissions"]
        features["tcp_seq_bwd_gaps"] = bwd_analysis["gaps"]
        features["tcp_seq_bwd_ooo"] = bwd_analysis["out_of_order"]

        # ACK analysis - Forward direction
        fwd_ack_analysis = self._analyze_acks(fwd_ack_packets)
        features["tcp_ack_fwd_count"] = fwd_ack_analysis["ack_count"]
        features["tcp_ack_fwd_dup"] = fwd_ack_analysis["dup_acks"]

        # ACK analysis - Backward direction
        bwd_ack_analysis = self._analyze_acks(bwd_ack_packets)
        features["tcp_ack_bwd_count"] = bwd_ack_analysis["ack_count"]
        features["tcp_ack_bwd_dup"] = bwd_ack_analysis["dup_acks"]

        # Total retransmissions and anomalies
        features["tcp_total_retrans"] = (
            fwd_analysis["retransmissions"] + bwd_analysis["retransmissions"]
        )
        features["tcp_total_ooo"] = fwd_analysis["out_of_order"] + bwd_analysis["out_of_order"]
        features["tcp_total_dup_acks"] = fwd_ack_analysis["dup_acks"] + bwd_ack_analysis["dup_acks"]

        # Retransmission ratio
        total_data_packets = len(fwd_seq_packets) + len(bwd_seq_packets)
        if total_data_packets > 0:
            features["tcp_retrans_ratio"] = features["tcp_total_retrans"] / total_data_packets
        else:
            features["tcp_retrans_ratio"] = 0.0

        return features

    def _analyze_sequence(
        self, seq_packets: list[tuple[int, int, int]]
    ) -> dict[str, int]:
        """Analyze sequence numbers for anomalies.

        Args:
            seq_packets: List of (seq_num, payload_len, timestamp) tuples.

        Returns:
            Dictionary with analysis results.
        """
        if not seq_packets:
            return {
                "bytes_sent": 0,
                "retransmissions": 0,
                "gaps": 0,
                "out_of_order": 0,
            }

        bytes_sent = 0
        retransmissions = 0
        gaps = 0
        out_of_order = 0

        # Track seen sequence numbers
        seen_seqs: set[int] = set()
        expected_next = seq_packets[0][0]

        for seq, payload_len, _ in seq_packets:
            data_len = max(1, payload_len)  # At least 1 for SYN/FIN

            # Check for retransmission (only for packets with data)
            if seq in seen_seqs and payload_len > 0:
                retransmissions += 1
            else:
                if payload_len > 0:
                    seen_seqs.add(seq)
                bytes_sent += payload_len

            # Check for out-of-order or gaps
            # Account for sequence number wraparound (2^32)
            diff = (seq - expected_next) % (2**32)
            if diff > 0 and diff < 2**31:  # Gap
                gaps += 1
            elif diff > 2**31:  # Out of order (negative diff in signed)
                out_of_order += 1

            # Update expected next
            next_seq = (seq + data_len) % (2**32)
            if (next_seq - expected_next) % (2**32) < 2**31:
                expected_next = next_seq

        return {
            "bytes_sent": bytes_sent,
            "retransmissions": retransmissions,
            "gaps": gaps,
            "out_of_order": out_of_order,
        }

    def _analyze_acks(self, ack_packets: list[tuple[int, int]]) -> dict[str, int]:
        """Analyze ACK numbers for duplicates.

        Args:
            ack_packets: List of (ack_num, timestamp) tuples.

        Returns:
            Dictionary with analysis results.
        """
        if not ack_packets:
            return {"ack_count": 0, "dup_acks": 0}

        ack_count = len(ack_packets)
        dup_acks = 0

        # Track consecutive duplicate ACKs
        prev_ack: int | None = None
        consecutive_dups = 0

        for ack, _ in ack_packets:
            if ack == prev_ack:
                consecutive_dups += 1
                if consecutive_dups >= 1:  # Count as dup after first repeat
                    dup_acks += 1
            else:
                consecutive_dups = 0
            prev_ack = ack

        return {"ack_count": ack_count, "dup_acks": dup_acks}

    @property
    def feature_names(self) -> list[str]:
        """Get feature names produced by this extractor."""
        return [
            # ISN
            "tcp_isn_fwd",
            "tcp_isn_bwd",
            # Forward sequence analysis
            "tcp_seq_fwd_bytes_sent",
            "tcp_seq_fwd_retrans",
            "tcp_seq_fwd_gaps",
            "tcp_seq_fwd_ooo",
            # Backward sequence analysis
            "tcp_seq_bwd_bytes_sent",
            "tcp_seq_bwd_retrans",
            "tcp_seq_bwd_gaps",
            "tcp_seq_bwd_ooo",
            # Forward ACK analysis
            "tcp_ack_fwd_count",
            "tcp_ack_fwd_dup",
            # Backward ACK analysis
            "tcp_ack_bwd_count",
            "tcp_ack_bwd_dup",
            # Totals
            "tcp_total_retrans",
            "tcp_total_ooo",
            "tcp_total_dup_acks",
            "tcp_retrans_ratio",
        ]

    @property
    def name(self) -> str:
        """Get the extractor name."""
        return "tcp_sequence"
