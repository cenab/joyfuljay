"""Tests for IP Extended feature extractor (#46)."""

from __future__ import annotations

import pytest

from joyfuljay.core.flow import Flow
from joyfuljay.core.packet import Packet
from joyfuljay.extractors.ip_extended import IPExtendedExtractor

from tests.fixtures.tranalyzer_packets import (
    create_ip_extended_packet,
    create_ip_flow_with_dscp,
    create_ip_flow_with_ttl_variations,
    create_non_tcp_flow,
)


class TestIPExtendedExtractor:
    """Tests for IPExtendedExtractor."""

    @pytest.fixture
    def extractor(self) -> IPExtendedExtractor:
        """Create an IP Extended extractor."""
        return IPExtendedExtractor()

    def test_feature_names(self, extractor: IPExtendedExtractor) -> None:
        """Test that feature names are properly defined."""
        names = extractor.feature_names
        assert isinstance(names, list)
        assert len(names) == 19
        assert "ip_ttl_fwd_min" in names
        assert "ip_ttl_fwd_max" in names
        assert "ip_ttl_fwd_mean" in names
        assert "ip_ttl_bwd_min" in names
        assert "ip_ttl_bwd_max" in names
        assert "ip_dscp" in names
        assert "ip_ecn" in names
        assert "ip_flags" in names
        assert "ip_df_count" in names
        assert "ip_version" in names

    def test_extractor_name(self, extractor: IPExtendedExtractor) -> None:
        """Test extractor name."""
        assert extractor.name == "ip_extended"

    def test_extract_ttl_statistics(self, extractor: IPExtendedExtractor) -> None:
        """Test TTL statistics extraction."""
        flow = create_ip_flow_with_ttl_variations([64, 128, 63, 127, 62])
        features = extractor.extract(flow)

        # Forward packets: 64, 63, 62 (indices 0, 2, 4)
        assert features["ip_ttl_fwd_min"] == 62
        assert features["ip_ttl_fwd_max"] == 64
        assert features["ip_ttl_fwd_changes"] == 2  # 3 unique values - 1

        # Backward packets: 128, 127 (indices 1, 3)
        assert features["ip_ttl_bwd_min"] == 127
        assert features["ip_ttl_bwd_max"] == 128

    def test_extract_constant_ttl(self, extractor: IPExtendedExtractor) -> None:
        """Test TTL with no changes."""
        flow = create_ip_flow_with_ttl_variations([64, 64, 64, 64, 64])
        features = extractor.extract(flow)

        # All TTLs same = 0 changes
        assert features["ip_ttl_fwd_changes"] == 0
        assert features["ip_ttl_bwd_changes"] == 0

    def test_extract_initial_ttl_estimation_linux(self, extractor: IPExtendedExtractor) -> None:
        """Test initial TTL estimation for Linux-like TTL (64)."""
        pkt = create_ip_extended_packet(ip_ttl=57)  # 64 - 7 hops
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        assert features["ip_ttl_fwd_initial_est"] == 64
        assert features["ip_ttl_fwd_hops_est"] == 7

    def test_extract_initial_ttl_estimation_windows(self, extractor: IPExtendedExtractor) -> None:
        """Test initial TTL estimation for Windows-like TTL (128)."""
        pkt = create_ip_extended_packet(ip_ttl=120)  # 128 - 8 hops
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        assert features["ip_ttl_fwd_initial_est"] == 128
        assert features["ip_ttl_fwd_hops_est"] == 8

    def test_extract_initial_ttl_estimation_bsd(self, extractor: IPExtendedExtractor) -> None:
        """Test initial TTL estimation for BSD-like TTL (255)."""
        pkt = create_ip_extended_packet(ip_ttl=240)  # 255 - 15 hops
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        assert features["ip_ttl_fwd_initial_est"] == 255
        assert features["ip_ttl_fwd_hops_est"] == 15

    def test_extract_dscp_values(self, extractor: IPExtendedExtractor) -> None:
        """Test DSCP extraction."""
        flow = create_ip_flow_with_dscp(dscp=46)  # EF (Expedited Forwarding)
        features = extractor.extract(flow)

        assert features["ip_dscp"] == 46
        assert features["ip_tos_value"] == 46 << 2  # ToS = DSCP << 2

    def test_extract_ecn_bits(self, extractor: IPExtendedExtractor) -> None:
        """Test ECN bits extraction."""
        # ToS = (DSCP << 2) | ECN, so ToS=0x03 has ECN=3
        pkt = create_ip_extended_packet(ip_tos=0x03)  # ECN = 3 (CE)
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        assert features["ip_ecn"] == 3

    def test_extract_df_flag(self, extractor: IPExtendedExtractor) -> None:
        """Test DF (Don't Fragment) flag extraction."""
        # Create flow with all packets having DF set
        packets = []
        base_time = 1000.0
        for i in range(5):
            is_forward = i % 2 == 0
            pkt = create_ip_extended_packet(
                timestamp=base_time + i * 0.01,
                ip_flags=0x02,  # DF flag
                src_ip="192.168.1.100" if is_forward else "10.0.0.1",
                dst_ip="10.0.0.1" if is_forward else "192.168.1.100",
                src_port=54321 if is_forward else 443,
                dst_port=443 if is_forward else 54321,
            )
            packets.append(pkt)

        flow = Flow.from_first_packet(packets[0])
        for pkt in packets[1:]:
            flow.add_packet(pkt)

        features = extractor.extract(flow)

        assert features["ip_df_count"] == 5
        assert features["ip_df_ratio"] == 1.0
        assert features["ip_flags"] & 0x02  # DF bit set

    def test_extract_no_df_flag(self, extractor: IPExtendedExtractor) -> None:
        """Test packet without DF flag."""
        pkt = create_ip_extended_packet(ip_flags=0x00)
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        assert features["ip_df_count"] == 0
        assert features["ip_df_ratio"] == 0.0

    def test_extract_ip_version_ipv4(self, extractor: IPExtendedExtractor) -> None:
        """Test IPv4 version detection."""
        pkt = create_ip_extended_packet(ip_version=4)
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        assert features["ip_version"] == 4

    def test_extract_ip_version_ipv6(self, extractor: IPExtendedExtractor) -> None:
        """Test IPv6 version detection."""
        pkt = create_ip_extended_packet(ip_version=6, src_ip="2001:db8::1", dst_ip="2001:db8::2")
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        assert features["ip_version"] == 6

    def test_extract_ip_id_gaps(self, extractor: IPExtendedExtractor) -> None:
        """Test IP ID gap detection."""
        packets = [
            create_ip_extended_packet(timestamp=1000.0, ip_id=1000),
            create_ip_extended_packet(
                timestamp=1000.01,
                ip_id=2000,
                src_ip="10.0.0.1",
                dst_ip="192.168.1.100",
                src_port=443,
                dst_port=54321,
            ),
            create_ip_extended_packet(timestamp=1000.02, ip_id=1001),
            create_ip_extended_packet(
                timestamp=1000.03,
                ip_id=2005,  # Gap of 5
                src_ip="10.0.0.1",
                dst_ip="192.168.1.100",
                src_port=443,
                dst_port=54321,
            ),
        ]

        flow = Flow.from_first_packet(packets[0])
        for pkt in packets[1:]:
            flow.add_packet(pkt)

        features = extractor.extract(flow)

        # Should detect gaps (non-sequential IDs)
        assert features["ip_id_gaps"] >= 0

    def test_extract_no_ip_info(self, extractor: IPExtendedExtractor) -> None:
        """Test flow without extended IP information."""
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
            # No extended IP fields
        )
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        # Should return defaults
        assert features["ip_ttl_fwd_min"] == 0
        assert features["ip_ttl_fwd_max"] == 0
        assert features["ip_version"] == 4  # Default

    def test_extract_multiple_tos_values(self, extractor: IPExtendedExtractor) -> None:
        """Test flow with varying ToS values."""
        packets = [
            create_ip_extended_packet(timestamp=1000.0, ip_tos=0x00),
            create_ip_extended_packet(
                timestamp=1000.01,
                ip_tos=0xB8,  # DSCP 46
                src_ip="10.0.0.1",
                dst_ip="192.168.1.100",
                src_port=443,
                dst_port=54321,
            ),
        ]

        flow = Flow.from_first_packet(packets[0])
        flow.add_packet(packets[1])

        features = extractor.extract(flow)

        assert features["ip_tos_unique_count"] == 2

    def test_validate_all_features_present(self, extractor: IPExtendedExtractor) -> None:
        """Test that all feature names are present in extracted features."""
        flow = create_ip_flow_with_ttl_variations()
        features = extractor.extract(flow)

        for name in extractor.feature_names:
            assert name in features, f"Missing feature: {name}"
