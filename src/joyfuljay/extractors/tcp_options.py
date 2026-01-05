"""TCP options feature extractor."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .base import FeatureExtractor

if TYPE_CHECKING:
    from ..core.flow import Flow


class TCPOptionsExtractor(FeatureExtractor):
    """Extracts TCP options features from flows.

    Features include:
    - MSS (Maximum Segment Size)
    - Window Scale
    - Timestamps
    - SACK (Selective Acknowledgment)

    Corresponds to Tranalyzer feature #54.
    """

    def extract(self, flow: Flow) -> dict[str, Any]:
        """Extract TCP options features from a flow.

        Args:
            flow: The completed flow.

        Returns:
            Dictionary of TCP options features.
        """
        features: dict[str, Any] = {}

        # Track options by direction
        fwd_mss: int | None = None
        bwd_mss: int | None = None
        fwd_ws: int | None = None
        bwd_ws: int | None = None
        fwd_sack_permitted = False
        bwd_sack_permitted = False

        # Timestamp analysis
        fwd_timestamps: list[tuple[int, int]] = []
        bwd_timestamps: list[tuple[int, int]] = []

        # SACK block analysis
        total_sack_blocks = 0

        # Count packets with options
        packets_with_options = 0

        for pkt in flow.packets:
            is_forward = (
                pkt.src_ip == flow.initiator_ip and pkt.src_port == flow.initiator_port
            )

            # Check if packet has any TCP options
            has_options = False

            if is_forward:
                if pkt.tcp_mss is not None and fwd_mss is None:
                    fwd_mss = pkt.tcp_mss
                    has_options = True
                if pkt.tcp_window_scale is not None and fwd_ws is None:
                    fwd_ws = pkt.tcp_window_scale
                    has_options = True
                if pkt.tcp_sack_permitted:
                    fwd_sack_permitted = True
                    has_options = True
                if pkt.tcp_timestamp is not None:
                    fwd_timestamps.append(pkt.tcp_timestamp)
                    has_options = True
            else:
                if pkt.tcp_mss is not None and bwd_mss is None:
                    bwd_mss = pkt.tcp_mss
                    has_options = True
                if pkt.tcp_window_scale is not None and bwd_ws is None:
                    bwd_ws = pkt.tcp_window_scale
                    has_options = True
                if pkt.tcp_sack_permitted:
                    bwd_sack_permitted = True
                    has_options = True
                if pkt.tcp_timestamp is not None:
                    bwd_timestamps.append(pkt.tcp_timestamp)
                    has_options = True

            # SACK blocks (can appear in any packet)
            if pkt.tcp_sack_blocks is not None:
                total_sack_blocks += len(pkt.tcp_sack_blocks)
                has_options = True

            if has_options:
                packets_with_options += 1

        # MSS features
        features["tcp_mss_fwd"] = fwd_mss if fwd_mss is not None else 0
        features["tcp_mss_bwd"] = bwd_mss if bwd_mss is not None else 0

        # Window Scale features
        features["tcp_ws_fwd"] = fwd_ws if fwd_ws is not None else 0
        features["tcp_ws_bwd"] = bwd_ws if bwd_ws is not None else 0

        # SACK features
        features["tcp_sack_permitted_fwd"] = 1 if fwd_sack_permitted else 0
        features["tcp_sack_permitted_bwd"] = 1 if bwd_sack_permitted else 0
        features["tcp_sack_blocks_total"] = total_sack_blocks

        # Timestamp analysis - Forward
        if fwd_timestamps:
            ts_vals = [ts[0] for ts in fwd_timestamps]
            ts_ecrs = [ts[1] for ts in fwd_timestamps]

            features["tcp_ts_fwd_present"] = 1
            features["tcp_ts_fwd_first"] = ts_vals[0]
            features["tcp_ts_fwd_last"] = ts_vals[-1]

            # Timestamp increment (useful for uptime estimation)
            if len(ts_vals) >= 2:
                ts_diff = ts_vals[-1] - ts_vals[0]
                # Handle wraparound
                if ts_diff < 0:
                    ts_diff += 2**32
                features["tcp_ts_fwd_diff"] = ts_diff
            else:
                features["tcp_ts_fwd_diff"] = 0

            # Echo reply analysis
            features["tcp_ts_ecr_fwd_first"] = ts_ecrs[0]
        else:
            features["tcp_ts_fwd_present"] = 0
            features["tcp_ts_fwd_first"] = 0
            features["tcp_ts_fwd_last"] = 0
            features["tcp_ts_fwd_diff"] = 0
            features["tcp_ts_ecr_fwd_first"] = 0

        # Timestamp analysis - Backward
        if bwd_timestamps:
            ts_vals = [ts[0] for ts in bwd_timestamps]
            ts_ecrs = [ts[1] for ts in bwd_timestamps]

            features["tcp_ts_bwd_present"] = 1
            features["tcp_ts_bwd_first"] = ts_vals[0]
            features["tcp_ts_bwd_last"] = ts_vals[-1]

            if len(ts_vals) >= 2:
                ts_diff = ts_vals[-1] - ts_vals[0]
                if ts_diff < 0:
                    ts_diff += 2**32
                features["tcp_ts_bwd_diff"] = ts_diff
            else:
                features["tcp_ts_bwd_diff"] = 0

            features["tcp_ts_ecr_bwd_first"] = ts_ecrs[0]
        else:
            features["tcp_ts_bwd_present"] = 0
            features["tcp_ts_bwd_first"] = 0
            features["tcp_ts_bwd_last"] = 0
            features["tcp_ts_bwd_diff"] = 0
            features["tcp_ts_ecr_bwd_first"] = 0

        # Options presence bitmap
        # Bit 0: MSS present
        # Bit 1: Window Scale present
        # Bit 2: SACK permitted
        # Bit 3: Timestamps present
        opt_bitmap = 0
        if fwd_mss is not None or bwd_mss is not None:
            opt_bitmap |= 0x01
        if fwd_ws is not None or bwd_ws is not None:
            opt_bitmap |= 0x02
        if fwd_sack_permitted or bwd_sack_permitted:
            opt_bitmap |= 0x04
        if fwd_timestamps or bwd_timestamps:
            opt_bitmap |= 0x08

        features["tcp_options_bitmap"] = opt_bitmap
        features["tcp_options_pkt_count"] = packets_with_options

        return features

    @property
    def feature_names(self) -> list[str]:
        """Get feature names produced by this extractor."""
        return [
            # MSS
            "tcp_mss_fwd",
            "tcp_mss_bwd",
            # Window Scale
            "tcp_ws_fwd",
            "tcp_ws_bwd",
            # SACK
            "tcp_sack_permitted_fwd",
            "tcp_sack_permitted_bwd",
            "tcp_sack_blocks_total",
            # Forward timestamps
            "tcp_ts_fwd_present",
            "tcp_ts_fwd_first",
            "tcp_ts_fwd_last",
            "tcp_ts_fwd_diff",
            "tcp_ts_ecr_fwd_first",
            # Backward timestamps
            "tcp_ts_bwd_present",
            "tcp_ts_bwd_first",
            "tcp_ts_bwd_last",
            "tcp_ts_bwd_diff",
            "tcp_ts_ecr_bwd_first",
            # Summary
            "tcp_options_bitmap",
            "tcp_options_pkt_count",
        ]

    @property
    def name(self) -> str:
        """Get the extractor name."""
        return "tcp_options"
