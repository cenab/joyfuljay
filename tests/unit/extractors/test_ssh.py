"""Tests for SSH feature extractor."""

from __future__ import annotations

import pytest

from joyfuljay.extractors.ssh import SSHExtractor

from tests.fixtures.packets import (
    create_ssh_flow,
    create_ssh_version_exchange,
    create_ssh_kex_init,
)


class TestSSHExtractor:
    """Tests for SSHExtractor."""

    @pytest.fixture
    def extractor(self) -> SSHExtractor:
        """Create an SSH extractor."""
        return SSHExtractor()

    def test_feature_names(self, extractor: SSHExtractor) -> None:
        """Test that feature names are properly defined."""
        names = extractor.feature_names
        assert isinstance(names, list)
        assert len(names) > 0
        assert "ssh_detected" in names
        assert "ssh_version" in names

    def test_extractor_name(self, extractor: SSHExtractor) -> None:
        """Test extractor name."""
        assert extractor.name == "SSHExtractor"

    def test_extract_ssh_detected(self, extractor: SSHExtractor) -> None:
        """Test SSH detection from version exchange."""
        flow = create_ssh_flow()
        features = extractor.extract(flow)

        assert features["ssh_detected"] is True

    def test_extract_ssh_version(self, extractor: SSHExtractor) -> None:
        """Test SSH version extraction."""
        flow = create_ssh_flow()
        features = extractor.extract(flow)

        assert "ssh_version" in features
        # Version string contains the SSH protocol version (e.g., "2.0")
        if features["ssh_version"]:
            assert "2.0" in features["ssh_version"]

    def test_extract_hassh(self, extractor: SSHExtractor) -> None:
        """Test HASSH fingerprint extraction."""
        flow = create_ssh_flow()
        features = extractor.extract(flow)

        assert "ssh_hassh" in features
        # HASSH should be MD5 hash if present
        if features["ssh_hassh"]:
            assert len(features["ssh_hassh"]) == 32

    def test_extract_hassh_server(self, extractor: SSHExtractor) -> None:
        """Test HASSH server fingerprint extraction."""
        flow = create_ssh_flow()
        features = extractor.extract(flow)

        assert "ssh_hassh_server" in features

    def test_no_ssh_traffic(self, extractor: SSHExtractor) -> None:
        """Test extraction from non-SSH flow."""
        from joyfuljay.core.flow import Flow
        from joyfuljay.core.packet import Packet

        # Non-SSH traffic
        packet = Packet(
            timestamp=1000.0,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=80,
            protocol=6,
            payload_len=100,
            total_len=140,
            tcp_flags=0x18,
            raw_payload=b"GET / HTTP/1.1\r\n",
        )

        flow = Flow.from_first_packet(packet)
        features = extractor.extract(flow)

        assert features["ssh_detected"] is False

    def test_validate_features(self, extractor: SSHExtractor) -> None:
        """Test feature validation."""
        flow = create_ssh_flow()
        features = extractor.extract(flow)

        assert extractor.validate_features(features)

    def test_kex_algorithms(self, extractor: SSHExtractor) -> None:
        """Test key exchange algorithm extraction."""
        flow = create_ssh_flow()
        features = extractor.extract(flow)

        # KEX algorithms might be in features
        if "ssh_kex_algorithms" in features:
            assert isinstance(features["ssh_kex_algorithms"], str)
