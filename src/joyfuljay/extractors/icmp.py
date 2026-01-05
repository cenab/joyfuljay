"""ICMP feature extractor."""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING, Any

from .base import FeatureExtractor

if TYPE_CHECKING:
    from ..core.flow import Flow


class ICMPExtractor(FeatureExtractor):
    """Extracts ICMP features from flows.

    Features include:
    - ICMP type and code analysis
    - Echo request/reply statistics
    - ICMP status bitmap

    Corresponds to Tranalyzer feature #58.
    """

    # ICMP Type constants
    ICMP_ECHO_REPLY = 0
    ICMP_DEST_UNREACHABLE = 3
    ICMP_SOURCE_QUENCH = 4
    ICMP_REDIRECT = 5
    ICMP_ECHO_REQUEST = 8
    ICMP_TIME_EXCEEDED = 11
    ICMP_PARAMETER_PROBLEM = 12
    ICMP_TIMESTAMP_REQUEST = 13
    ICMP_TIMESTAMP_REPLY = 14

    def extract(self, flow: Flow) -> dict[str, Any]:
        """Extract ICMP features from a flow.

        Args:
            flow: The completed flow.

        Returns:
            Dictionary of ICMP features.
        """
        features: dict[str, Any] = {}

        # Collect ICMP packets
        icmp_types: list[int] = []
        icmp_codes: list[int] = []
        icmp_ids: list[int] = []
        icmp_seqs: list[int] = []

        echo_requests = 0
        echo_replies = 0
        dest_unreachable = 0
        time_exceeded = 0

        for pkt in flow.packets:
            if pkt.icmp_type is not None:
                icmp_types.append(pkt.icmp_type)

                # Count specific types
                if pkt.icmp_type == self.ICMP_ECHO_REQUEST:
                    echo_requests += 1
                elif pkt.icmp_type == self.ICMP_ECHO_REPLY:
                    echo_replies += 1
                elif pkt.icmp_type == self.ICMP_DEST_UNREACHABLE:
                    dest_unreachable += 1
                elif pkt.icmp_type == self.ICMP_TIME_EXCEEDED:
                    time_exceeded += 1

            if pkt.icmp_code is not None:
                icmp_codes.append(pkt.icmp_code)

            if pkt.icmp_id is not None:
                icmp_ids.append(pkt.icmp_id)

            if pkt.icmp_seq is not None:
                icmp_seqs.append(pkt.icmp_seq)

        # Basic ICMP counts
        features["icmp_packet_count"] = len(icmp_types)
        features["icmp_echo_request_count"] = echo_requests
        features["icmp_echo_reply_count"] = echo_replies
        features["icmp_dest_unreachable_count"] = dest_unreachable
        features["icmp_time_exceeded_count"] = time_exceeded

        # Unique type/code combinations
        type_code_pairs = list(zip(icmp_types, icmp_codes)) if icmp_types and icmp_codes else []
        features["icmp_unique_type_codes"] = len(set(type_code_pairs))

        # Most common ICMP type
        if icmp_types:
            type_counter = Counter(icmp_types)
            most_common_type, most_common_count = type_counter.most_common(1)[0]
            features["icmp_dominant_type"] = most_common_type
            features["icmp_dominant_type_count"] = most_common_count
        else:
            features["icmp_dominant_type"] = -1
            features["icmp_dominant_type_count"] = 0

        # Echo success ratio (replies / requests)
        if echo_requests > 0:
            features["icmp_echo_success_ratio"] = echo_replies / echo_requests
        else:
            features["icmp_echo_success_ratio"] = 0.0

        # ICMP ID analysis (for tracking echo sessions)
        unique_ids = set(icmp_ids)
        features["icmp_unique_ids"] = len(unique_ids)

        # Sequence number analysis
        if icmp_seqs:
            features["icmp_seq_min"] = min(icmp_seqs)
            features["icmp_seq_max"] = max(icmp_seqs)
            # Check for sequential sequence numbers (normal ping)
            sorted_seqs = sorted(icmp_seqs)
            gaps = sum(
                1 for i in range(len(sorted_seqs) - 1)
                if sorted_seqs[i + 1] - sorted_seqs[i] > 1
            )
            features["icmp_seq_gaps"] = gaps
        else:
            features["icmp_seq_min"] = 0
            features["icmp_seq_max"] = 0
            features["icmp_seq_gaps"] = 0

        # ICMP status bitmap (similar to Tranalyzer icmpStat)
        # Bit 0: Has echo requests
        # Bit 1: Has echo replies
        # Bit 2: Has destination unreachable
        # Bit 3: Has time exceeded
        # Bit 4: Has redirect
        # Bit 5: Has other types
        icmp_stat = 0
        if echo_requests > 0:
            icmp_stat |= 0x01
        if echo_replies > 0:
            icmp_stat |= 0x02
        if dest_unreachable > 0:
            icmp_stat |= 0x04
        if time_exceeded > 0:
            icmp_stat |= 0x08

        redirect_count = sum(1 for t in icmp_types if t == self.ICMP_REDIRECT)
        if redirect_count > 0:
            icmp_stat |= 0x10

        known_types = {
            self.ICMP_ECHO_REPLY,
            self.ICMP_DEST_UNREACHABLE,
            self.ICMP_REDIRECT,
            self.ICMP_ECHO_REQUEST,
            self.ICMP_TIME_EXCEEDED,
        }
        other_count = sum(1 for t in icmp_types if t not in known_types)
        if other_count > 0:
            icmp_stat |= 0x20

        features["icmp_stat"] = icmp_stat

        # Is this primarily an ICMP flow?
        total_packets = len(flow.packets)
        icmp_ratio = len(icmp_types) / total_packets if total_packets > 0 else 0.0
        features["icmp_ratio"] = icmp_ratio
        features["is_icmp_only"] = 1 if icmp_ratio == 1.0 and len(icmp_types) > 0 else 0

        return features

    @property
    def feature_names(self) -> list[str]:
        """Get feature names produced by this extractor."""
        return [
            "icmp_packet_count",
            "icmp_echo_request_count",
            "icmp_echo_reply_count",
            "icmp_dest_unreachable_count",
            "icmp_time_exceeded_count",
            "icmp_unique_type_codes",
            "icmp_dominant_type",
            "icmp_dominant_type_count",
            "icmp_echo_success_ratio",
            "icmp_unique_ids",
            "icmp_seq_min",
            "icmp_seq_max",
            "icmp_seq_gaps",
            "icmp_stat",
            "icmp_ratio",
            "is_icmp_only",
        ]

    @property
    def name(self) -> str:
        """Get the extractor name."""
        return "icmp"
