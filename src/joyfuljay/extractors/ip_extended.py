"""Extended IP header feature extractor."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .base import FeatureExtractor

if TYPE_CHECKING:
    from ..core.flow import Flow
    from ..schema.registry import FeatureMeta


class IPExtendedExtractor(FeatureExtractor):
    """Extracts extended IP header features from flows.

    Features include:
    - TTL statistics (min, max, changes)
    - IP identification field
    - Type of Service (ToS) / DSCP
    - IP flags
    - IP version

    Corresponds to Tranalyzer feature #46.
    """

    def extract(self, flow: Flow) -> dict[str, Any]:
        """Extract extended IP features from a flow.

        Args:
            flow: The completed flow.

        Returns:
            Dictionary of extended IP features.
        """
        features: dict[str, Any] = {}

        # Collect TTL values
        fwd_ttls: list[int] = []
        bwd_ttls: list[int] = []

        # Collect ToS values
        tos_values: set[int] = set()

        # Collect IP flags
        ip_flags_set: set[int] = set()

        # IP version
        ip_versions: set[int] = set()

        # IP IDs for analysis
        ip_ids: list[int] = []

        for pkt in flow.packets:
            # Determine direction
            is_forward = (
                pkt.src_ip == flow.initiator_ip and pkt.src_port == flow.initiator_port
            )

            if pkt.ip_ttl is not None:
                if is_forward:
                    fwd_ttls.append(pkt.ip_ttl)
                else:
                    bwd_ttls.append(pkt.ip_ttl)

            if pkt.ip_tos is not None:
                tos_values.add(pkt.ip_tos)

            if pkt.ip_flags is not None:
                ip_flags_set.add(pkt.ip_flags)

            if pkt.ip_version is not None:
                ip_versions.add(pkt.ip_version)

            if pkt.ip_id is not None:
                ip_ids.append(pkt.ip_id)

        # TTL statistics - Forward direction
        if fwd_ttls:
            features["ip_ttl_fwd_min"] = min(fwd_ttls)
            features["ip_ttl_fwd_max"] = max(fwd_ttls)
            features["ip_ttl_fwd_mean"] = sum(fwd_ttls) / len(fwd_ttls)
            # Count TTL changes (hops variation detection)
            features["ip_ttl_fwd_changes"] = len(set(fwd_ttls)) - 1
        else:
            features["ip_ttl_fwd_min"] = 0
            features["ip_ttl_fwd_max"] = 0
            features["ip_ttl_fwd_mean"] = 0.0
            features["ip_ttl_fwd_changes"] = 0

        # TTL statistics - Backward direction
        if bwd_ttls:
            features["ip_ttl_bwd_min"] = min(bwd_ttls)
            features["ip_ttl_bwd_max"] = max(bwd_ttls)
            features["ip_ttl_bwd_mean"] = sum(bwd_ttls) / len(bwd_ttls)
            features["ip_ttl_bwd_changes"] = len(set(bwd_ttls)) - 1
        else:
            features["ip_ttl_bwd_min"] = 0
            features["ip_ttl_bwd_max"] = 0
            features["ip_ttl_bwd_mean"] = 0.0
            features["ip_ttl_bwd_changes"] = 0

        # Initial TTL estimation (common values: 64, 128, 255)
        if fwd_ttls:
            first_ttl = fwd_ttls[0]
            if first_ttl <= 64:
                features["ip_ttl_fwd_initial_est"] = 64
            elif first_ttl <= 128:
                features["ip_ttl_fwd_initial_est"] = 128
            else:
                features["ip_ttl_fwd_initial_est"] = 255
            features["ip_ttl_fwd_hops_est"] = features["ip_ttl_fwd_initial_est"] - first_ttl
        else:
            features["ip_ttl_fwd_initial_est"] = 0
            features["ip_ttl_fwd_hops_est"] = 0

        # ToS / DSCP features
        features["ip_tos_value"] = min(tos_values) if tos_values else 0
        features["ip_tos_unique_count"] = len(tos_values)

        # Extract DSCP (top 6 bits) and ECN (bottom 2 bits)
        if tos_values:
            first_tos = min(tos_values)
            features["ip_dscp"] = first_tos >> 2
            features["ip_ecn"] = first_tos & 0x03
        else:
            features["ip_dscp"] = 0
            features["ip_ecn"] = 0

        # IP flags bitmap (aggregated across all packets)
        # Bit 0: Reserved (should be 0)
        # Bit 1: DF (Don't Fragment)
        # Bit 2: MF (More Fragments)
        aggregated_flags = 0
        for flag in ip_flags_set:
            aggregated_flags |= flag
        features["ip_flags"] = aggregated_flags

        # DF flag analysis
        df_count = sum(1 for pkt in flow.packets if pkt.ip_flags and pkt.ip_flags & 0x02)
        features["ip_df_count"] = df_count
        features["ip_df_ratio"] = df_count / len(flow.packets) if flow.packets else 0.0

        # IP version
        features["ip_version"] = min(ip_versions) if ip_versions else 4

        # IP ID analysis (for fragmentation/reordering detection)
        if len(ip_ids) >= 2:
            # Check for sequential IDs (normal) vs gaps (possible issues)
            id_diffs = [ip_ids[i + 1] - ip_ids[i] for i in range(len(ip_ids) - 1)]
            # Handle wraparound
            id_diffs = [d if d >= 0 else d + 65536 for d in id_diffs]
            features["ip_id_gaps"] = sum(1 for d in id_diffs if d > 1)
        else:
            features["ip_id_gaps"] = 0

        return features

    @property
    def feature_names(self) -> list[str]:
        """Get feature names produced by this extractor."""
        return [
            # Forward TTL
            "ip_ttl_fwd_min",
            "ip_ttl_fwd_max",
            "ip_ttl_fwd_mean",
            "ip_ttl_fwd_changes",
            # Backward TTL
            "ip_ttl_bwd_min",
            "ip_ttl_bwd_max",
            "ip_ttl_bwd_mean",
            "ip_ttl_bwd_changes",
            # TTL estimation
            "ip_ttl_fwd_initial_est",
            "ip_ttl_fwd_hops_est",
            # ToS/DSCP
            "ip_tos_value",
            "ip_tos_unique_count",
            "ip_dscp",
            "ip_ecn",
            # Flags
            "ip_flags",
            "ip_df_count",
            "ip_df_ratio",
            # Version
            "ip_version",
            # ID analysis
            "ip_id_gaps",
        ]

    @property
    def extractor_id(self) -> str:
        """Get the unique extractor identifier."""
        return "ip_extended"

    def feature_meta(self) -> dict[str, "FeatureMeta"]:
        """Get metadata for all features produced by this extractor.

        Returns:
            Dictionary mapping feature IDs to their metadata.
        """
        from ..schema.registry import FeatureMeta

        return {
            # Forward TTL features
            "ip_extended.ip_ttl_fwd_min": FeatureMeta(
                id="ip_extended.ip_ttl_fwd_min",
                dtype="int64",
                shape=[1],
                units="",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="initiator_to_responder",
                missing_policy="zero",
                missing_sentinel=0,
                dependencies=["ip"],
                privacy_level="safe",
                description="Minimum TTL value in forward direction packets",
            ),
            "ip_extended.ip_ttl_fwd_max": FeatureMeta(
                id="ip_extended.ip_ttl_fwd_max",
                dtype="int64",
                shape=[1],
                units="",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="initiator_to_responder",
                missing_policy="zero",
                missing_sentinel=0,
                dependencies=["ip"],
                privacy_level="safe",
                description="Maximum TTL value in forward direction packets",
            ),
            "ip_extended.ip_ttl_fwd_mean": FeatureMeta(
                id="ip_extended.ip_ttl_fwd_mean",
                dtype="float64",
                shape=[1],
                units="",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="initiator_to_responder",
                missing_policy="zero",
                missing_sentinel=0.0,
                dependencies=["ip"],
                privacy_level="safe",
                description="Mean TTL value in forward direction packets",
            ),
            "ip_extended.ip_ttl_fwd_changes": FeatureMeta(
                id="ip_extended.ip_ttl_fwd_changes",
                dtype="int64",
                shape=[1],
                units="",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="initiator_to_responder",
                missing_policy="zero",
                missing_sentinel=0,
                dependencies=["ip"],
                privacy_level="safe",
                description="Number of unique TTL values minus one in forward direction",
            ),
            # Backward TTL features
            "ip_extended.ip_ttl_bwd_min": FeatureMeta(
                id="ip_extended.ip_ttl_bwd_min",
                dtype="int64",
                shape=[1],
                units="",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="responder_to_initiator",
                missing_policy="zero",
                missing_sentinel=0,
                dependencies=["ip"],
                privacy_level="safe",
                description="Minimum TTL value in backward direction packets",
            ),
            "ip_extended.ip_ttl_bwd_max": FeatureMeta(
                id="ip_extended.ip_ttl_bwd_max",
                dtype="int64",
                shape=[1],
                units="",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="responder_to_initiator",
                missing_policy="zero",
                missing_sentinel=0,
                dependencies=["ip"],
                privacy_level="safe",
                description="Maximum TTL value in backward direction packets",
            ),
            "ip_extended.ip_ttl_bwd_mean": FeatureMeta(
                id="ip_extended.ip_ttl_bwd_mean",
                dtype="float64",
                shape=[1],
                units="",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="responder_to_initiator",
                missing_policy="zero",
                missing_sentinel=0.0,
                dependencies=["ip"],
                privacy_level="safe",
                description="Mean TTL value in backward direction packets",
            ),
            "ip_extended.ip_ttl_bwd_changes": FeatureMeta(
                id="ip_extended.ip_ttl_bwd_changes",
                dtype="int64",
                shape=[1],
                units="",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="responder_to_initiator",
                missing_policy="zero",
                missing_sentinel=0,
                dependencies=["ip"],
                privacy_level="safe",
                description="Number of unique TTL values minus one in backward direction",
            ),
            # TTL estimation features
            "ip_extended.ip_ttl_fwd_initial_est": FeatureMeta(
                id="ip_extended.ip_ttl_fwd_initial_est",
                dtype="int64",
                shape=[1],
                units="",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="initiator_to_responder",
                missing_policy="zero",
                missing_sentinel=0,
                dependencies=["ip"],
                privacy_level="safe",
                description="Estimated initial TTL value (64, 128, or 255) in forward direction",
            ),
            "ip_extended.ip_ttl_fwd_hops_est": FeatureMeta(
                id="ip_extended.ip_ttl_fwd_hops_est",
                dtype="int64",
                shape=[1],
                units="",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="initiator_to_responder",
                missing_policy="zero",
                missing_sentinel=0,
                dependencies=["ip"],
                privacy_level="safe",
                description="Estimated number of hops based on TTL in forward direction",
            ),
            # ToS/DSCP features
            "ip_extended.ip_tos_value": FeatureMeta(
                id="ip_extended.ip_tos_value",
                dtype="int64",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="combined",
                missing_policy="zero",
                missing_sentinel=0,
                dependencies=["ip"],
                privacy_level="safe",
                description="Minimum Type of Service value observed in the flow",
            ),
            "ip_extended.ip_tos_unique_count": FeatureMeta(
                id="ip_extended.ip_tos_unique_count",
                dtype="int64",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="combined",
                missing_policy="zero",
                missing_sentinel=0,
                dependencies=["ip"],
                privacy_level="safe",
                description="Number of unique ToS values observed in the flow",
            ),
            "ip_extended.ip_dscp": FeatureMeta(
                id="ip_extended.ip_dscp",
                dtype="int64",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="combined",
                missing_policy="zero",
                missing_sentinel=0,
                dependencies=["ip"],
                privacy_level="safe",
                description="Differentiated Services Code Point (top 6 bits of ToS)",
            ),
            "ip_extended.ip_ecn": FeatureMeta(
                id="ip_extended.ip_ecn",
                dtype="int64",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="combined",
                missing_policy="zero",
                missing_sentinel=0,
                dependencies=["ip"],
                privacy_level="safe",
                description="Explicit Congestion Notification (bottom 2 bits of ToS)",
            ),
            # IP flags features
            "ip_extended.ip_flags": FeatureMeta(
                id="ip_extended.ip_flags",
                dtype="int64",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="combined",
                missing_policy="zero",
                missing_sentinel=0,
                dependencies=["ip"],
                privacy_level="safe",
                description="Aggregated IP flags bitmap across all packets",
            ),
            "ip_extended.ip_df_count": FeatureMeta(
                id="ip_extended.ip_df_count",
                dtype="int64",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="combined",
                missing_policy="zero",
                missing_sentinel=0,
                dependencies=["ip"],
                privacy_level="safe",
                description="Count of packets with Don't Fragment flag set",
            ),
            "ip_extended.ip_df_ratio": FeatureMeta(
                id="ip_extended.ip_df_ratio",
                dtype="float64",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="combined",
                missing_policy="zero",
                missing_sentinel=0.0,
                dependencies=["ip"],
                privacy_level="safe",
                description="Ratio of packets with Don't Fragment flag set",
            ),
            # IP version feature
            "ip_extended.ip_version": FeatureMeta(
                id="ip_extended.ip_version",
                dtype="int64",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="combined",
                missing_policy="zero",
                missing_sentinel=4,
                dependencies=["ip"],
                privacy_level="safe",
                description="IP version (4 or 6)",
            ),
            # IP ID analysis feature
            "ip_extended.ip_id_gaps": FeatureMeta(
                id="ip_extended.ip_id_gaps",
                dtype="int64",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="combined",
                missing_policy="zero",
                missing_sentinel=0,
                dependencies=["ip"],
                privacy_level="safe",
                description="Number of gaps in IP identification sequence",
            ),
        }

    @property
    def name(self) -> str:
        """Get the extractor name."""
        return "ip_extended"
