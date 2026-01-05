"""End-to-end integration tests for Tranalyzer-compatible features (#44-#58).

These tests verify that all Tranalyzer extractors work together through
the full pipeline.
"""

from __future__ import annotations

import pytest

from joyfuljay import Config, Pipeline
from joyfuljay.core.config import FeatureGroup
from joyfuljay.core.flow import Flow

from tests.fixtures.tranalyzer_packets import (
    create_full_featured_tcp_flow,
    create_ipv6_flow,
    create_mac_flow,
    create_mptcp_flow,
    create_non_tcp_flow,
    create_ping_flow,
    create_tcp_handshake_flow,
    create_tcp_options_flow,
    create_tcp_rtt_flow,
)


class TestTranalyzerPipelineIntegration:
    """Integration tests for Tranalyzer feature extractors."""

    @pytest.fixture
    def all_features_config(self) -> Config:
        """Create a config with all Tranalyzer features enabled."""
        return Config(
            flow_timeout=60.0,
            features=["all"],
        )

    @pytest.fixture
    def tranalyzer_only_config(self) -> Config:
        """Create a config with only Tranalyzer-specific features."""
        return Config(
            flow_timeout=60.0,
            features=[
                "flow_meta",
                "tcp",
                "mac",
                "ip_extended",
                "ipv6_options",
                "tcp_sequence",
                "tcp_window",
                "tcp_options",
                "tcp_mptcp",
                "tcp_rtt",
                "tcp_fingerprint",
                "icmp",
            ],
        )

    def test_pipeline_with_all_tranalyzer_extractors(self, all_features_config: Config) -> None:
        """Test that all Tranalyzer extractors are initialized."""
        pipeline = Pipeline(all_features_config)

        extractor_names = [e.name for e in pipeline.extractors]

        # Check for new Tranalyzer extractors
        assert "mac" in extractor_names or any("mac" in n.lower() for n in extractor_names)
        assert "ip_extended" in extractor_names or any("ip" in n.lower() for n in extractor_names)

    def test_extract_full_featured_tcp_flow(self, all_features_config: Config) -> None:
        """Test feature extraction from fully-featured TCP flow."""
        pipeline = Pipeline(all_features_config)
        flow = create_full_featured_tcp_flow()

        features = pipeline._extract_features(flow)

        # Should have many features
        assert len(features) > 100

        # Check for Tranalyzer-specific features
        # MAC features
        assert "mac_src" in features
        assert features["mac_src"] == "aa:bb:cc:dd:ee:01"

        # IP Extended features
        assert "ip_ttl_fwd_min" in features
        assert features["ip_ttl_fwd_min"] > 0

        # TCP features
        assert "tcp_fstat" in features
        assert features["tcp_fstat"] > 0

        # TCP Options
        assert "tcp_mss_fwd" in features
        assert features["tcp_mss_fwd"] == 1460

        # TCP Window
        assert "tcp_init_win_fwd" in features
        assert features["tcp_init_win_fwd"] == 65535

    def test_extract_ipv6_flow(self, all_features_config: Config) -> None:
        """Test feature extraction from IPv6 flow."""
        pipeline = Pipeline(all_features_config)
        flow = create_ipv6_flow()

        features = pipeline._extract_features(flow)

        # IPv6-specific features
        assert "ipv6_packet_count" in features
        assert features["ipv6_packet_count"] == 5
        assert features["ipv6_ratio"] == 1.0
        assert features["is_ipv6_only"] == 1

    def test_extract_icmp_flow(self, all_features_config: Config) -> None:
        """Test feature extraction from ICMP flow."""
        pipeline = Pipeline(all_features_config)
        flow = create_ping_flow()

        features = pipeline._extract_features(flow)

        # ICMP-specific features
        assert "icmp_packet_count" in features
        assert features["icmp_packet_count"] > 0
        assert features["icmp_echo_request_count"] > 0
        assert features["icmp_echo_success_ratio"] == 1.0

    def test_extract_mptcp_flow(self, all_features_config: Config) -> None:
        """Test feature extraction from MPTCP flow."""
        pipeline = Pipeline(all_features_config)
        flow = create_mptcp_flow()

        features = pipeline._extract_features(flow)

        # MPTCP-specific features
        assert "mptcp_detected" in features
        assert features["mptcp_detected"] == 1
        assert features["is_mptcp"] == 1

    def test_extract_tcp_options_flow(self, all_features_config: Config) -> None:
        """Test feature extraction with TCP options."""
        pipeline = Pipeline(all_features_config)
        flow = create_tcp_options_flow()

        features = pipeline._extract_features(flow)

        # TCP Options features
        assert "tcp_mss_fwd" in features
        assert "tcp_ws_fwd" in features
        assert "tcp_sack_permitted_fwd" in features
        assert "tcp_ts_fwd_present" in features

    def test_extract_tcp_rtt_flow(self, all_features_config: Config) -> None:
        """Test feature extraction with RTT estimation."""
        pipeline = Pipeline(all_features_config)
        flow = create_tcp_rtt_flow(rtt_ms=20.0)

        features = pipeline._extract_features(flow)

        # TCP RTT features
        assert "tcp_rtt_handshake" in features
        assert features["tcp_rtt_handshake"] > 0

    def test_feature_consistency(self, all_features_config: Config) -> None:
        """Test that features are consistent across extractions."""
        pipeline = Pipeline(all_features_config)
        flow = create_full_featured_tcp_flow()

        features1 = pipeline._extract_features(flow)
        features2 = pipeline._extract_features(flow)

        # Same flow should produce same features
        assert features1 == features2

    def test_feature_names_match_extracted(self, all_features_config: Config) -> None:
        """Test that all declared feature names are actually extracted."""
        pipeline = Pipeline(all_features_config)
        flow = create_full_featured_tcp_flow()

        features = pipeline._extract_features(flow)

        # Get all declared feature names from extractors
        declared_names = set()
        for extractor in pipeline.extractors:
            declared_names.update(extractor.feature_names)

        # All declared names should be in extracted features
        for name in declared_names:
            assert name in features, f"Declared feature '{name}' not in extracted features"

    def test_no_none_values(self, all_features_config: Config) -> None:
        """Test that no features have None values (should have defaults)."""
        pipeline = Pipeline(all_features_config)
        flow = create_full_featured_tcp_flow()

        features = pipeline._extract_features(flow)

        for name, value in features.items():
            assert value is not None, f"Feature '{name}' has None value"

    def test_numeric_features_are_numeric(self, all_features_config: Config) -> None:
        """Test that numeric features have numeric values."""
        pipeline = Pipeline(all_features_config)
        flow = create_full_featured_tcp_flow()

        features = pipeline._extract_features(flow)

        # These should all be numeric
        numeric_features = [
            "tcp_syn_count",
            "tcp_fstat",
            "ip_ttl_fwd_min",
            "icmp_packet_count",
            "tcp_mss_fwd",
            "duration",
            "total_packets",
        ]

        for name in numeric_features:
            if name in features:
                value = features[name]
                assert isinstance(value, (int, float)), f"Feature '{name}' is not numeric: {type(value)}"

    def test_string_features_are_strings(self, all_features_config: Config) -> None:
        """Test that string features have string values."""
        pipeline = Pipeline(all_features_config)
        flow = create_full_featured_tcp_flow()

        features = pipeline._extract_features(flow)

        # These should be strings
        string_features = [
            "mac_src",
            "mac_dst",
            "hdr_desc",
            "tcp_fp_fwd",
        ]

        for name in string_features:
            if name in features:
                value = features[name]
                assert isinstance(value, str), f"Feature '{name}' is not string: {type(value)}"

    def test_multiple_flows(self, all_features_config: Config) -> None:
        """Test extraction from multiple different flows."""
        pipeline = Pipeline(all_features_config)

        flows = [
            create_full_featured_tcp_flow(),
            create_ipv6_flow(),
            create_ping_flow(),
            create_non_tcp_flow(),
        ]

        for i, flow in enumerate(flows):
            features = pipeline._extract_features(flow)
            assert len(features) > 0, f"Flow {i} produced no features"


class TestTranalyzerFeatureGroups:
    """Tests for Tranalyzer feature group configuration."""

    def test_mac_feature_group(self) -> None:
        """Test MAC feature group selection."""
        config = Config(features=["mac"])
        pipeline = Pipeline(config)

        extractor_names = [e.name for e in pipeline.extractors]
        # Should have MAC extractor (name may vary)
        assert len(extractor_names) >= 1

    def test_ip_extended_feature_group(self) -> None:
        """Test IP Extended feature group selection."""
        config = Config(features=["ip_extended"])
        pipeline = Pipeline(config)

        flow = create_mac_flow()
        features = pipeline._extract_features(flow)

        assert "ip_ttl_fwd_min" in features

    def test_tcp_sequence_feature_group(self) -> None:
        """Test TCP Sequence feature group selection."""
        config = Config(features=["tcp_sequence"])
        pipeline = Pipeline(config)

        flow = create_tcp_handshake_flow()
        features = pipeline._extract_features(flow)

        assert "tcp_isn_fwd" in features

    def test_tcp_window_feature_group(self) -> None:
        """Test TCP Window feature group selection."""
        config = Config(features=["tcp_window"])
        pipeline = Pipeline(config)

        flow = create_tcp_handshake_flow()
        features = pipeline._extract_features(flow)

        assert "tcp_init_win_fwd" in features

    def test_tcp_options_feature_group(self) -> None:
        """Test TCP Options feature group selection."""
        config = Config(features=["tcp_options"])
        pipeline = Pipeline(config)

        flow = create_tcp_options_flow()
        features = pipeline._extract_features(flow)

        assert "tcp_mss_fwd" in features

    def test_icmp_feature_group(self) -> None:
        """Test ICMP feature group selection."""
        config = Config(features=["icmp"])
        pipeline = Pipeline(config)

        flow = create_ping_flow()
        features = pipeline._extract_features(flow)

        assert "icmp_packet_count" in features

    def test_combined_feature_groups(self) -> None:
        """Test multiple feature groups combined."""
        config = Config(features=["mac", "tcp", "icmp"])
        pipeline = Pipeline(config)

        flow = create_full_featured_tcp_flow()
        features = pipeline._extract_features(flow)

        # Should have features from all groups
        assert "mac_src" in features
        assert "tcp_is_tcp" in features


class TestTranalyzerEdgeCases:
    """Edge case tests for Tranalyzer features."""

    def test_empty_flow(self) -> None:
        """Test handling of minimal flow."""
        config = Config(features=["all"])
        pipeline = Pipeline(config)

        # Single-packet flow
        from joyfuljay.core.packet import Packet
        pkt = Packet(
            timestamp=1000.0,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            protocol=6,
            payload_len=0,
            total_len=40,
            tcp_flags=0x02,
        )
        flow = Flow.from_first_packet(pkt)

        features = pipeline._extract_features(flow)

        # Should not crash and produce valid output
        assert len(features) > 0
        assert features["total_packets"] == 1

    def test_all_fields_missing(self) -> None:
        """Test flow with no optional fields populated."""
        config = Config(features=["all"])
        pipeline = Pipeline(config)

        from joyfuljay.core.packet import Packet
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
            # All optional fields use defaults
        )
        flow = Flow.from_first_packet(pkt)

        features = pipeline._extract_features(flow)

        # Should use defaults for missing fields
        assert features["mac_src"] == ""
        assert features["ip_ttl_fwd_min"] == 0
        assert features["mptcp_detected"] == 0

    def test_large_flow(self) -> None:
        """Test flow with many packets."""
        config = Config(features=["flow_meta", "tcp"])
        pipeline = Pipeline(config)

        from joyfuljay.core.packet import Packet

        packets = []
        for i in range(1000):
            is_forward = i % 2 == 0
            pkt = Packet(
                timestamp=1000.0 + i * 0.001,
                src_ip="192.168.1.100" if is_forward else "10.0.0.1",
                dst_ip="10.0.0.1" if is_forward else "192.168.1.100",
                src_port=54321 if is_forward else 443,
                dst_port=443 if is_forward else 54321,
                protocol=6,
                payload_len=100,
                total_len=140,
                tcp_flags=0x18,
            )
            packets.append(pkt)

        flow = Flow.from_first_packet(packets[0])
        for pkt in packets[1:]:
            flow.add_packet(pkt)

        features = pipeline._extract_features(flow)

        assert features["total_packets"] == 1000
        assert features["duration"] > 0


class TestTranalyzerFeatureCounts:
    """Tests to verify feature counts match documentation."""

    def test_total_feature_count(self) -> None:
        """Test that total feature count matches expected."""
        config = Config(features=["all"])
        pipeline = Pipeline(config)

        total_features = set()
        for extractor in pipeline.extractors:
            total_features.update(extractor.feature_names)

        # Should have 300+ features total
        assert len(total_features) >= 300, f"Expected 300+ features, got {len(total_features)}"

    def test_new_extractor_feature_counts(self) -> None:
        """Test that new extractors have expected feature counts."""
        from joyfuljay.extractors import (
            ICMPExtractor,
            IPExtendedExtractor,
            IPv6OptionsExtractor,
            MACExtractor,
            MPTCPExtractor,
            TCPFingerprintExtractor,
            TCPOptionsExtractor,
            TCPRTTExtractor,
            TCPSequenceExtractor,
            TCPWindowExtractor,
        )

        expected_counts = {
            "MACExtractor": 10,
            "IPExtendedExtractor": 19,
            "IPv6OptionsExtractor": 11,
            "TCPSequenceExtractor": 18,
            "TCPWindowExtractor": 21,
            "TCPOptionsExtractor": 19,
            "MPTCPExtractor": 6,
            "TCPRTTExtractor": 10,
            "TCPFingerprintExtractor": 14,
            "ICMPExtractor": 16,
        }

        extractors = [
            MACExtractor(),
            IPExtendedExtractor(),
            IPv6OptionsExtractor(),
            TCPSequenceExtractor(),
            TCPWindowExtractor(),
            TCPOptionsExtractor(),
            MPTCPExtractor(),
            TCPRTTExtractor(),
            TCPFingerprintExtractor(),
            ICMPExtractor(),
        ]

        for extractor in extractors:
            name = extractor.__class__.__name__
            expected = expected_counts.get(name, 0)
            actual = len(extractor.feature_names)
            assert actual == expected, f"{name}: expected {expected} features, got {actual}"
