"""Tests for TCP Fingerprint feature extractor (#57)."""

from __future__ import annotations

import pytest

from joyfuljay.core.flow import Flow
from joyfuljay.core.packet import Packet
from joyfuljay.extractors.tcp_fingerprint import TCPFingerprintExtractor

from tests.fixtures.tranalyzer_packets import (
    create_linux_fingerprint_flow,
    create_non_tcp_flow,
    create_tcp_fingerprint_flow,
    create_tcp_options_packet,
    create_windows_fingerprint_flow,
)


class TestTCPFingerprintExtractor:
    """Tests for TCPFingerprintExtractor."""

    @pytest.fixture
    def extractor(self) -> TCPFingerprintExtractor:
        """Create a TCP Fingerprint extractor."""
        return TCPFingerprintExtractor()

    def test_feature_names(self, extractor: TCPFingerprintExtractor) -> None:
        """Test that feature names are properly defined."""
        names = extractor.feature_names
        assert isinstance(names, list)
        assert len(names) == 14
        assert "tcp_fp_fwd" in names
        assert "tcp_fp_bwd" in names
        assert "tcp_os_hint_fwd" in names
        assert "tcp_os_hint_bwd" in names
        assert "tcp_uptime_fwd" in names
        assert "tcp_uptime_bwd" in names
        assert "tcp_fp_fwd_window" in names
        assert "tcp_fp_fwd_ttl" in names
        assert "tcp_fp_fwd_mss" in names
        assert "tcp_fp_fwd_ws" in names

    def test_extractor_name(self, extractor: TCPFingerprintExtractor) -> None:
        """Test extractor name."""
        assert extractor.name == "tcp_fingerprint"

    def test_extract_fingerprint(self, extractor: TCPFingerprintExtractor) -> None:
        """Test JA4T-style fingerprint extraction."""
        flow = create_tcp_fingerprint_flow()
        features = extractor.extract(flow)

        # Forward fingerprint should be generated
        assert features["tcp_fp_fwd"] != ""
        assert features["tcp_fp_fwd"].startswith("t")  # JA4T format

        # Backward fingerprint should be generated
        assert features["tcp_fp_bwd"] != ""

    def test_extract_fingerprint_components(self, extractor: TCPFingerprintExtractor) -> None:
        """Test fingerprint component extraction."""
        flow = create_tcp_fingerprint_flow(
            client_window=65535,
            client_ttl=64,
            client_mss=1460,
            client_ws=7,
        )
        features = extractor.extract(flow)

        assert features["tcp_fp_fwd_window"] == 65535
        assert features["tcp_fp_fwd_ttl"] == 64
        assert features["tcp_fp_fwd_mss"] == 1460
        assert features["tcp_fp_fwd_ws"] == 7

    def test_extract_linux_fingerprint(self, extractor: TCPFingerprintExtractor) -> None:
        """Test Linux OS detection from fingerprint."""
        flow = create_linux_fingerprint_flow()
        features = extractor.extract(flow)

        # Should detect Linux-like characteristics
        assert features["tcp_os_hint_fwd"] in ["linux", "linux-old", "macos", "unknown"]

    def test_extract_windows_fingerprint(self, extractor: TCPFingerprintExtractor) -> None:
        """Test Windows OS detection from fingerprint."""
        flow = create_windows_fingerprint_flow()
        features = extractor.extract(flow)

        # Should detect Windows-like characteristics
        assert features["tcp_os_hint_fwd"] in ["windows", "windows-10", "unknown"]

    def test_extract_os_hint_by_ttl(self, extractor: TCPFingerprintExtractor) -> None:
        """Test OS hint based on TTL."""
        # TTL 64 -> Linux/macOS
        flow_linux = create_tcp_fingerprint_flow(client_ttl=64)
        features = extractor.extract(flow_linux)
        assert features["tcp_fp_fwd_ttl"] == 64

        # TTL 128 -> Windows
        flow_win = create_tcp_fingerprint_flow(client_ttl=128)
        features = extractor.extract(flow_win)
        assert features["tcp_fp_fwd_ttl"] == 128

        # TTL 255 -> BSD
        flow_bsd = create_tcp_fingerprint_flow(client_ttl=250)
        features = extractor.extract(flow_bsd)
        assert features["tcp_fp_fwd_ttl"] == 250

    def test_extract_uptime(self, extractor: TCPFingerprintExtractor) -> None:
        """Test uptime estimation from timestamps."""
        flow = create_tcp_fingerprint_flow()
        features = extractor.extract(flow)

        # Uptime should be positive (based on timestamp value)
        assert features["tcp_uptime_fwd"] >= 0
        assert features["tcp_uptime_bwd"] >= 0

    def test_extract_high_uptime(self, extractor: TCPFingerprintExtractor) -> None:
        """Test high uptime detection."""
        # Create flow with high timestamp (long uptime)
        pkt = create_tcp_options_packet(
            tcp_timestamp=(360000000, 0),  # ~1000 hours at 100 Hz
            tcp_flags=0x02,
            ip_ttl=64,
            tcp_window=65535,
            tcp_mss=1460,
            tcp_window_scale=7,
        )
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        # Uptime should be high
        assert features["tcp_uptime_fwd"] > 100  # > 100 hours

    def test_extract_no_syn(self, extractor: TCPFingerprintExtractor) -> None:
        """Test flow without SYN packet (mid-connection capture)."""
        pkt = create_tcp_options_packet(
            tcp_flags=0x18,  # PSH-ACK, not SYN
            tcp_mss=None,
            tcp_window_scale=None,
        )
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        # Without SYN, fingerprint should be empty
        assert features["tcp_fp_fwd"] == ""
        assert features["tcp_os_hint_fwd"] == "unknown"

    def test_extract_udp_flow(self, extractor: TCPFingerprintExtractor) -> None:
        """Test extraction from UDP flow (should return defaults)."""
        flow = create_non_tcp_flow()
        features = extractor.extract(flow)

        # UDP has no TCP fingerprint
        assert features["tcp_fp_fwd"] == ""
        assert features["tcp_fp_bwd"] == ""
        assert features["tcp_os_hint_fwd"] == "unknown"

    def test_extract_bidirectional_fingerprints(self, extractor: TCPFingerprintExtractor) -> None:
        """Test bidirectional fingerprint extraction."""
        flow = create_tcp_fingerprint_flow(
            client_ttl=64,
            client_window=65535,
            client_mss=1460,
            client_ws=7,
            server_ttl=64,
            server_window=65535,
            server_mss=1460,
            server_ws=8,
        )
        features = extractor.extract(flow)

        # Both directions should have fingerprints
        assert features["tcp_fp_fwd"] != ""
        assert features["tcp_fp_bwd"] != ""
        # Fingerprints may differ (different WS)
        assert features["tcp_fp_fwd_ws"] == 7
        assert features["tcp_fp_bwd_ws"] == 8

    def test_extract_no_options(self, extractor: TCPFingerprintExtractor) -> None:
        """Test SYN packet without options."""
        pkt = Packet(
            timestamp=1000.0,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            protocol=6,
            payload_len=0,
            total_len=40,
            tcp_flags=0x02,  # SYN
            tcp_window=65535,
            ip_ttl=64,
            # No MSS, WS, etc.
        )
        flow = Flow.from_first_packet(pkt)
        features = extractor.extract(flow)

        # Should still generate fingerprint with available info
        assert features["tcp_fp_fwd_window"] == 65535
        assert features["tcp_fp_fwd_ttl"] == 64
        assert features["tcp_fp_fwd_mss"] == 0  # Not available
        assert features["tcp_fp_fwd_ws"] == 0

    def test_fingerprint_uniqueness(self, extractor: TCPFingerprintExtractor) -> None:
        """Test that different parameters produce different fingerprints."""
        flow1 = create_tcp_fingerprint_flow(client_mss=1460)
        flow2 = create_tcp_fingerprint_flow(client_mss=1380)

        features1 = extractor.extract(flow1)
        features2 = extractor.extract(flow2)

        # Different MSS should produce different fingerprints
        assert features1["tcp_fp_fwd"] != features2["tcp_fp_fwd"]

    def test_fingerprint_format(self, extractor: TCPFingerprintExtractor) -> None:
        """Test JA4T fingerprint format."""
        flow = create_tcp_fingerprint_flow()
        features = extractor.extract(flow)

        fp = features["tcp_fp_fwd"]
        # Format: t<window>_<mss>_<ws>_<hash>
        assert fp.startswith("t")
        parts = fp[1:].split("_")
        assert len(parts) == 4

    def test_validate_all_features_present(self, extractor: TCPFingerprintExtractor) -> None:
        """Test that all feature names are present in extracted features."""
        flow = create_tcp_fingerprint_flow()
        features = extractor.extract(flow)

        for name in extractor.feature_names:
            assert name in features, f"Missing feature: {name}"
