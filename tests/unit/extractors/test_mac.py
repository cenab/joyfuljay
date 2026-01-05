"""Tests for MAC (Layer 2) feature extractor (#45)."""

from __future__ import annotations

import pytest

from joyfuljay.core.flow import Flow
from joyfuljay.core.packet import Packet
from joyfuljay.extractors.mac import MACExtractor

from tests.fixtures.tranalyzer_packets import (
    create_broadcast_mac_packet,
    create_mac_flow,
    create_mac_packet,
    create_multicast_mac_packet,
    create_non_tcp_flow,
    create_vlan_tagged_packet,
)


class TestMACExtractor:
    """Tests for MACExtractor."""

    @pytest.fixture
    def extractor(self) -> MACExtractor:
        """Create a MAC extractor."""
        return MACExtractor()

    def test_feature_names(self, extractor: MACExtractor) -> None:
        """Test that feature names are properly defined."""
        names = extractor.feature_names
        assert isinstance(names, list)
        assert len(names) == 10
        assert "mac_src" in names
        assert "mac_dst" in names
        assert "mac_eth_type" in names
        assert "mac_vlan_id" in names
        assert "mac_vlan_count" in names
        assert "mac_unique_src_count" in names
        assert "mac_unique_dst_count" in names
        assert "mac_stat" in names
        assert "mac_broadcast_count" in names
        assert "mac_multicast_count" in names

    def test_extractor_name(self, extractor: MACExtractor) -> None:
        """Test extractor name."""
        assert extractor.name == "mac"

    def test_extract_basic_mac(self, extractor: MACExtractor) -> None:
        """Test basic MAC address extraction."""
        flow = create_mac_flow(num_packets=5, with_vlan=False)
        features = extractor.extract(flow)

        assert features["mac_src"] == "aa:bb:cc:dd:ee:01"
        assert features["mac_dst"] == "10:22:33:44:55:66"
        assert features["mac_eth_type"] == 0x0800  # IPv4

    def test_extract_vlan_tagged(self, extractor: MACExtractor) -> None:
        """Test VLAN-tagged packet extraction."""
        flow = create_mac_flow(num_packets=5, with_vlan=True)
        features = extractor.extract(flow)

        assert features["mac_vlan_id"] == 100
        assert features["mac_vlan_count"] == 1
        # VLAN bit should be set in mac_stat
        assert features["mac_stat"] & 0x10  # Bit 4: VLAN tagged

    def test_extract_no_vlan(self, extractor: MACExtractor) -> None:
        """Test packet without VLAN tag."""
        flow = create_mac_flow(num_packets=5, with_vlan=False)
        features = extractor.extract(flow)

        assert features["mac_vlan_id"] == 0
        assert features["mac_vlan_count"] == 0
        assert not (features["mac_stat"] & 0x10)

    def test_extract_unique_mac_counts(self, extractor: MACExtractor) -> None:
        """Test unique MAC counting."""
        flow = create_mac_flow(num_packets=5, with_vlan=False)
        features = extractor.extract(flow)

        # In a bidirectional flow, we expect 2 unique MACs in each direction
        assert features["mac_unique_src_count"] == 2
        assert features["mac_unique_dst_count"] == 2

    def test_extract_mac_stat_bitmap(self, extractor: MACExtractor) -> None:
        """Test MAC status bitmap."""
        flow = create_mac_flow(num_packets=5, with_vlan=False)
        features = extractor.extract(flow)

        mac_stat = features["mac_stat"]
        # Bit 0: Source MAC present
        assert mac_stat & 0x01
        # Bit 1: Destination MAC present
        assert mac_stat & 0x02
        # Bit 2: Multiple source MACs (should be set in bidirectional flow)
        assert mac_stat & 0x04
        # Bit 3: Multiple destination MACs
        assert mac_stat & 0x08

    def test_extract_broadcast_mac(self, extractor: MACExtractor) -> None:
        """Test broadcast MAC detection."""
        pkt = create_broadcast_mac_packet()
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        assert features["mac_broadcast_count"] == 1
        assert features["mac_dst"] == "ff:ff:ff:ff:ff:ff"

    def test_extract_multicast_mac(self, extractor: MACExtractor) -> None:
        """Test multicast MAC detection."""
        pkt = create_multicast_mac_packet()
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        assert features["mac_multicast_count"] == 1

    def test_extract_no_mac_info(self, extractor: MACExtractor) -> None:
        """Test flow without MAC information."""
        # Create packet without MAC fields
        pkt = Packet(
            timestamp=1000.0,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            protocol=6,
            payload_len=100,
            total_len=140,
            tcp_flags=0x18,
            # No MAC fields
        )
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        assert features["mac_src"] == ""
        assert features["mac_dst"] == ""
        assert features["mac_eth_type"] == 0
        assert features["mac_stat"] == 0

    def test_extract_single_packet_flow(self, extractor: MACExtractor) -> None:
        """Test single-packet flow (edge case)."""
        pkt = create_mac_packet()
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        assert features["mac_unique_src_count"] == 1
        assert features["mac_unique_dst_count"] == 1
        assert features["mac_broadcast_count"] == 0
        assert features["mac_multicast_count"] == 0

    def test_extract_multiple_vlans(self, extractor: MACExtractor) -> None:
        """Test flow with multiple VLAN IDs (unusual but possible)."""
        packets = [
            create_mac_packet(timestamp=1000.0, vlan_id=100),
            create_mac_packet(
                timestamp=1000.01,
                vlan_id=200,
                src_ip="10.0.0.1",
                dst_ip="192.168.1.100",
                src_port=443,
                dst_port=54321,
            ),
        ]
        flow = Flow.from_first_packet(packets[0])
        flow.add_packet(packets[1])

        features = extractor.extract(flow)

        assert features["mac_vlan_count"] == 2
        assert features["mac_vlan_id"] == 100  # Min of VLANs

    def test_extract_ipv6_eth_type(self, extractor: MACExtractor) -> None:
        """Test IPv6 Ethernet type."""
        pkt = create_mac_packet(eth_type=0x86DD)  # IPv6
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        assert features["mac_eth_type"] == 0x86DD

    def test_validate_all_features_present(self, extractor: MACExtractor) -> None:
        """Test that all feature names are present in extracted features."""
        flow = create_mac_flow()
        features = extractor.extract(flow)

        for name in extractor.feature_names:
            assert name in features, f"Missing feature: {name}"
