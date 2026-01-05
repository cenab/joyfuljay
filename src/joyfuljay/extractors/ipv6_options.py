"""IPv6 extension header and options feature extractor."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .base import FeatureExtractor

if TYPE_CHECKING:
    from ..core.flow import Flow


class IPv6OptionsExtractor(FeatureExtractor):
    """Extracts IPv6-specific features from flows.

    Features include:
    - IPv6 flow label analysis
    - Traffic class analysis
    - IPv6 packet counts

    Corresponds to Tranalyzer feature #47.
    """

    def extract(self, flow: Flow) -> dict[str, Any]:
        """Extract IPv6 features from a flow.

        Args:
            flow: The completed flow.

        Returns:
            Dictionary of IPv6 features.
        """
        features: dict[str, Any] = {}

        # Count IPv6 packets
        ipv6_count = 0
        ipv4_count = 0

        # Collect flow labels and traffic classes
        flow_labels: set[int] = set()
        traffic_classes: set[int] = set()

        for pkt in flow.packets:
            if pkt.ip_version == 6:
                ipv6_count += 1
                if pkt.ipv6_flow_label is not None:
                    flow_labels.add(pkt.ipv6_flow_label)
                if pkt.ipv6_traffic_class is not None:
                    traffic_classes.add(pkt.ipv6_traffic_class)
            elif pkt.ip_version == 4:
                ipv4_count += 1

        features["ipv6_packet_count"] = ipv6_count
        features["ipv4_packet_count"] = ipv4_count

        # IPv6 flow label features
        if flow_labels:
            features["ipv6_flow_label"] = min(flow_labels)  # First/primary flow label
            features["ipv6_flow_label_unique_count"] = len(flow_labels)
            # Flow label should be constant for a flow; changes are anomalous
            features["ipv6_flow_label_changes"] = len(flow_labels) - 1
        else:
            features["ipv6_flow_label"] = 0
            features["ipv6_flow_label_unique_count"] = 0
            features["ipv6_flow_label_changes"] = 0

        # Traffic class features (DSCP + ECN for IPv6)
        if traffic_classes:
            first_tc = min(traffic_classes)
            features["ipv6_traffic_class"] = first_tc
            features["ipv6_traffic_class_unique_count"] = len(traffic_classes)
            # Extract DSCP (top 6 bits) and ECN (bottom 2 bits)
            features["ipv6_dscp"] = first_tc >> 2
            features["ipv6_ecn"] = first_tc & 0x03
        else:
            features["ipv6_traffic_class"] = 0
            features["ipv6_traffic_class_unique_count"] = 0
            features["ipv6_dscp"] = 0
            features["ipv6_ecn"] = 0

        # IPv6/IPv4 ratio
        total_packets = ipv6_count + ipv4_count
        features["ipv6_ratio"] = ipv6_count / total_packets if total_packets > 0 else 0.0

        # Is this a pure IPv6 flow?
        features["is_ipv6_only"] = 1 if ipv4_count == 0 and ipv6_count > 0 else 0

        return features

    @property
    def feature_names(self) -> list[str]:
        """Get feature names produced by this extractor."""
        return [
            "ipv6_packet_count",
            "ipv4_packet_count",
            "ipv6_flow_label",
            "ipv6_flow_label_unique_count",
            "ipv6_flow_label_changes",
            "ipv6_traffic_class",
            "ipv6_traffic_class_unique_count",
            "ipv6_dscp",
            "ipv6_ecn",
            "ipv6_ratio",
            "is_ipv6_only",
        ]

    @property
    def name(self) -> str:
        """Get the extractor name."""
        return "ipv6_options"
