"""TCP Multipath (MPTCP) feature extractor."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .base import FeatureExtractor

if TYPE_CHECKING:
    from ..core.flow import Flow
    from ..schema.registry import FeatureMeta


class MPTCPExtractor(FeatureExtractor):
    """Extracts MPTCP (Multipath TCP) features from flows.

    Features include:
    - MPTCP capability detection
    - Subflow identification
    - MPTCP option analysis

    Corresponds to Tranalyzer feature #55.

    Note: Full MPTCP analysis requires parsing the MPTCP TCP option
    (kind 30). This extractor provides basic detection based on
    available packet fields.
    """

    # MPTCP subtypes (from RFC 6824)
    MPTCP_CAPABLE = 0
    MPTCP_JOIN = 1
    MPTCP_DSS = 2
    MPTCP_ADD_ADDR = 3
    MPTCP_REMOVE_ADDR = 4
    MPTCP_PRIO = 5
    MPTCP_FAIL = 6
    MPTCP_FASTCLOSE = 7

    def extract(self, flow: Flow) -> dict[str, Any]:
        """Extract MPTCP features from a flow.

        Args:
            flow: The completed flow.

        Returns:
            Dictionary of MPTCP features.
        """
        features: dict[str, Any] = {}

        # MPTCP detection from raw TCP options
        mptcp_detected = False
        mptcp_capable_fwd = False
        mptcp_capable_bwd = False
        mptcp_option_count = 0

        for pkt in flow.packets:
            is_forward = (
                pkt.src_ip == flow.initiator_ip and pkt.src_port == flow.initiator_port
            )

            # Check for MPTCP option in raw TCP options
            if pkt.tcp_options_raw:
                if self._has_mptcp_option(pkt.tcp_options_raw):
                    mptcp_detected = True
                    mptcp_option_count += 1

                    # Check for MP_CAPABLE in SYN packets
                    if pkt.tcp_flags and (pkt.tcp_flags & 0x02):  # SYN flag
                        if is_forward:
                            mptcp_capable_fwd = True
                        else:
                            mptcp_capable_bwd = True

        # MPTCP detection features
        features["mptcp_detected"] = 1 if mptcp_detected else 0
        features["mptcp_capable_fwd"] = 1 if mptcp_capable_fwd else 0
        features["mptcp_capable_bwd"] = 1 if mptcp_capable_bwd else 0
        features["mptcp_option_count"] = mptcp_option_count

        # MPTCP status bitmap
        # Bit 0: MPTCP detected
        # Bit 1: Forward MP_CAPABLE
        # Bit 2: Backward MP_CAPABLE
        # Bit 3: Both directions capable (full MPTCP)
        mptcp_stat = 0
        if mptcp_detected:
            mptcp_stat |= 0x01
        if mptcp_capable_fwd:
            mptcp_stat |= 0x02
        if mptcp_capable_bwd:
            mptcp_stat |= 0x04
        if mptcp_capable_fwd and mptcp_capable_bwd:
            mptcp_stat |= 0x08

        features["mptcp_stat"] = mptcp_stat

        # Estimate if this is an MPTCP session
        features["is_mptcp"] = 1 if (mptcp_capable_fwd and mptcp_capable_bwd) else 0

        return features

    def _has_mptcp_option(self, options_raw: bytes) -> bool:
        """Check if TCP options contain MPTCP option (kind 30).

        Args:
            options_raw: Raw TCP options bytes.

        Returns:
            True if MPTCP option is present.
        """
        if not options_raw:
            return False

        i = 0
        while i < len(options_raw):
            kind = options_raw[i]

            if kind == 0:  # End of options
                break
            elif kind == 1:  # NOP
                i += 1
                continue
            elif i + 1 >= len(options_raw):
                break

            length = options_raw[i + 1]
            if length < 2 or i + length > len(options_raw):
                break

            if kind == 30:  # MPTCP option
                return True

            i += length

        return False

    @property
    def feature_names(self) -> list[str]:
        """Get feature names produced by this extractor."""
        return [
            "mptcp_detected",
            "mptcp_capable_fwd",
            "mptcp_capable_bwd",
            "mptcp_option_count",
            "mptcp_stat",
            "is_mptcp",
        ]

    @property
    def extractor_id(self) -> str:
        """Return the unique identifier for this extractor."""
        return "tcp_mptcp"

    def feature_meta(self) -> dict[str, FeatureMeta]:
        """Return metadata for all features produced by this extractor.

        Returns:
            Dictionary mapping feature IDs to their FeatureMeta objects.
        """
        from ..schema.registry import FeatureMeta

        return {
            "tcp_mptcp.detected": FeatureMeta(
                id="tcp_mptcp.detected",
                dtype="int64",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="1 if any MPTCP option detected in flow",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Whether MPTCP option (kind 30) was detected in any packet",
            ),
            "tcp_mptcp.capable_fwd": FeatureMeta(
                id="tcp_mptcp.capable_fwd",
                dtype="int64",
                shape=[1],
                units="",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="1 if MP_CAPABLE seen in forward SYN",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Whether MP_CAPABLE was seen in forward direction SYN packet",
            ),
            "tcp_mptcp.capable_bwd": FeatureMeta(
                id="tcp_mptcp.capable_bwd",
                dtype="int64",
                shape=[1],
                units="",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="1 if MP_CAPABLE seen in backward SYN",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Whether MP_CAPABLE was seen in backward direction SYN packet",
            ),
            "tcp_mptcp.option_count": FeatureMeta(
                id="tcp_mptcp.option_count",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="bidir",
                direction_semantics="Count of packets containing MPTCP options",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Number of packets containing MPTCP TCP option (kind 30)",
            ),
            "tcp_mptcp.stat": FeatureMeta(
                id="tcp_mptcp.stat",
                dtype="int64",
                shape=[1],
                units="bitmap",
                scope="flow",
                direction="bidir",
                direction_semantics="Bitmap: bit0=detected, bit1=fwd_capable, bit2=bwd_capable, bit3=full_mptcp",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="MPTCP status bitmap encoding detection and capability flags",
            ),
            "tcp_mptcp.is_mptcp": FeatureMeta(
                id="tcp_mptcp.is_mptcp",
                dtype="int64",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="1 if both directions are MP_CAPABLE",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Whether this is a full MPTCP session (both directions capable)",
            ),
        }

    @property
    def name(self) -> str:
        """Get the extractor name."""
        return "tcp_mptcp"
