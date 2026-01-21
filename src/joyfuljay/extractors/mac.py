"""Layer 2 (MAC) feature extractor."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .base import FeatureExtractor

if TYPE_CHECKING:
    from ..core.flow import Flow
    from ..schema.registry import FeatureMeta


class MACExtractor(FeatureExtractor):
    """Extracts Layer 2 (MAC) features from flows.

    Features include:
    - Source and destination MAC addresses
    - Ethernet type
    - VLAN ID
    - MAC-based statistics and status flags

    Corresponds to Tranalyzer feature #45.
    """

    def extract(self, flow: Flow) -> dict[str, Any]:
        """Extract MAC layer features from a flow.

        Args:
            flow: The completed flow.

        Returns:
            Dictionary of MAC features.
        """
        features: dict[str, Any] = {}

        # Get first packet's MAC addresses as flow-level MACs
        first_packet = flow.packets[0] if flow.packets else None

        if first_packet is not None and first_packet.src_mac is not None:
            features["mac_src"] = first_packet.src_mac
        else:
            features["mac_src"] = ""

        if first_packet is not None and first_packet.dst_mac is not None:
            features["mac_dst"] = first_packet.dst_mac
        else:
            features["mac_dst"] = ""

        # Ethernet type from first packet
        if first_packet is not None and first_packet.eth_type is not None:
            features["mac_eth_type"] = first_packet.eth_type
        else:
            features["mac_eth_type"] = 0

        # VLAN ID (if present)
        vlan_ids: set[int] = set()
        for pkt in flow.packets:
            if pkt.vlan_id is not None:
                vlan_ids.add(pkt.vlan_id)

        features["mac_vlan_id"] = min(vlan_ids) if vlan_ids else 0
        features["mac_vlan_count"] = len(vlan_ids)

        # MAC statistics
        unique_src_macs: set[str] = set()
        unique_dst_macs: set[str] = set()

        for pkt in flow.packets:
            if pkt.src_mac:
                unique_src_macs.add(pkt.src_mac)
            if pkt.dst_mac:
                unique_dst_macs.add(pkt.dst_mac)

        features["mac_unique_src_count"] = len(unique_src_macs)
        features["mac_unique_dst_count"] = len(unique_dst_macs)

        # MAC status bitmap (similar to Tranalyzer macStat)
        # Bit 0: Source MAC present
        # Bit 1: Destination MAC present
        # Bit 2: Multiple source MACs (unusual)
        # Bit 3: Multiple destination MACs (unusual)
        # Bit 4: VLAN tagged
        mac_stat = 0
        if first_packet and first_packet.src_mac:
            mac_stat |= 0x01
        if first_packet and first_packet.dst_mac:
            mac_stat |= 0x02
        if len(unique_src_macs) > 1:
            mac_stat |= 0x04
        if len(unique_dst_macs) > 1:
            mac_stat |= 0x08
        if vlan_ids:
            mac_stat |= 0x10

        features["mac_stat"] = mac_stat

        # Check for broadcast/multicast MACs
        broadcast_count = 0
        multicast_count = 0

        for pkt in flow.packets:
            if pkt.dst_mac:
                # Broadcast: ff:ff:ff:ff:ff:ff
                if pkt.dst_mac.lower() == "ff:ff:ff:ff:ff:ff":
                    broadcast_count += 1
                # Multicast: LSB of first byte is 1
                elif len(pkt.dst_mac) >= 2:
                    try:
                        first_byte = int(pkt.dst_mac.split(":")[0], 16)
                        if first_byte & 0x01:
                            multicast_count += 1
                    except (ValueError, IndexError):
                        pass

        features["mac_broadcast_count"] = broadcast_count
        features["mac_multicast_count"] = multicast_count

        return features

    @property
    def feature_names(self) -> list[str]:
        """Get feature names produced by this extractor."""
        return [
            "mac_src",
            "mac_dst",
            "mac_eth_type",
            "mac_vlan_id",
            "mac_vlan_count",
            "mac_unique_src_count",
            "mac_unique_dst_count",
            "mac_stat",
            "mac_broadcast_count",
            "mac_multicast_count",
        ]

    @property
    def extractor_id(self) -> str:
        """Get the stable identifier for this extractor."""
        return "mac"

    def feature_meta(self) -> dict[str, FeatureMeta]:
        """Get metadata for all features produced by this extractor."""
        from ..schema.registry import FeatureMeta

        meta: dict[str, FeatureMeta] = {}
        prefix = self.extractor_id

        # Define metadata for each feature
        feature_definitions = {
            "mac_src": FeatureMeta(
                id=f"{prefix}.mac_src",
                dtype="string",
                shape=[1],
                units="",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="Source MAC address from first packet",
                missing_policy="empty",
                missing_sentinel=None,
                dependencies=["eth"],
                privacy_level="high",
                description="Source MAC address of flow initiator",
            ),
            "mac_dst": FeatureMeta(
                id=f"{prefix}.mac_dst",
                dtype="string",
                shape=[1],
                units="",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="Destination MAC address from first packet",
                missing_policy="empty",
                missing_sentinel=None,
                dependencies=["eth"],
                privacy_level="high",
                description="Destination MAC address of flow responder",
            ),
            "mac_eth_type": FeatureMeta(
                id=f"{prefix}.mac_eth_type",
                dtype="int64",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="Ethernet frame type",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["eth"],
                privacy_level="safe",
                description="Ethernet type field (e.g., 0x0800=IPv4, 0x86DD=IPv6)",
            ),
            "mac_vlan_id": FeatureMeta(
                id=f"{prefix}.mac_vlan_id",
                dtype="int64",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="Minimum VLAN ID observed in flow",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["eth"],
                privacy_level="sensitive",
                description="VLAN identifier (802.1Q tag)",
            ),
            "mac_vlan_count": FeatureMeta(
                id=f"{prefix}.mac_vlan_count",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="bidir",
                direction_semantics="Number of unique VLAN IDs observed",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["eth"],
                privacy_level="safe",
                description="Count of unique VLAN IDs in flow",
            ),
            "mac_unique_src_count": FeatureMeta(
                id=f"{prefix}.mac_unique_src_count",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="bidir",
                direction_semantics="Number of unique source MACs observed",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["eth"],
                privacy_level="safe",
                description="Count of unique source MAC addresses in flow",
            ),
            "mac_unique_dst_count": FeatureMeta(
                id=f"{prefix}.mac_unique_dst_count",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="bidir",
                direction_semantics="Number of unique destination MACs observed",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["eth"],
                privacy_level="safe",
                description="Count of unique destination MAC addresses in flow",
            ),
            "mac_stat": FeatureMeta(
                id=f"{prefix}.mac_stat",
                dtype="int64",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="MAC layer status bitmap",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["eth"],
                privacy_level="safe",
                description="MAC status bitmap (bit0=src, bit1=dst, bit2=multi-src, bit3=multi-dst, bit4=VLAN)",
            ),
            "mac_broadcast_count": FeatureMeta(
                id=f"{prefix}.mac_broadcast_count",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="bidir",
                direction_semantics="Number of broadcast destination packets",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["eth"],
                privacy_level="safe",
                description="Count of packets with broadcast destination MAC (ff:ff:ff:ff:ff:ff)",
            ),
            "mac_multicast_count": FeatureMeta(
                id=f"{prefix}.mac_multicast_count",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="bidir",
                direction_semantics="Number of multicast destination packets",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["eth"],
                privacy_level="safe",
                description="Count of packets with multicast destination MAC",
            ),
        }

        # Only include metadata for features we actually produce
        for name in self.feature_names:
            if name in feature_definitions:
                meta[f"{prefix}.{name}"] = feature_definitions[name]

        return meta

    @property
    def name(self) -> str:
        """Get the extractor name."""
        return "mac"
