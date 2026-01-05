"""Tests for QUIC feature extractor."""

from __future__ import annotations

import pytest

from joyfuljay.extractors.quic import QUICExtractor

from tests.fixtures.packets import (
    create_quic_flow,
    create_quic_initial_packet,
    create_quic_short_header_packet,
)


class TestQUICExtractor:
    """Tests for QUICExtractor."""

    @pytest.fixture
    def extractor(self) -> QUICExtractor:
        """Create a QUIC extractor."""
        return QUICExtractor()

    def test_feature_names(self, extractor: QUICExtractor) -> None:
        """Test that feature names are properly defined."""
        names = extractor.feature_names
        assert isinstance(names, list)
        assert len(names) > 0
        assert "quic_detected" in names
        assert "quic_version" in names

    def test_extractor_name(self, extractor: QUICExtractor) -> None:
        """Test extractor name."""
        assert extractor.name == "QUICExtractor"

    def test_extract_quic_detected(self, extractor: QUICExtractor) -> None:
        """Test QUIC detection from Initial packet."""
        flow = create_quic_flow()
        features = extractor.extract(flow)

        assert features["quic_detected"] is True

    def test_extract_quic_version(self, extractor: QUICExtractor) -> None:
        """Test QUIC version extraction."""
        flow = create_quic_flow()
        features = extractor.extract(flow)

        assert features["quic_version"] == 0x00000001
        assert "quic_version_str" in features

    def test_extract_connection_ids(self, extractor: QUICExtractor) -> None:
        """Test connection ID length extraction."""
        flow = create_quic_flow()
        features = extractor.extract(flow)

        assert features["quic_dcid_len"] == 4
        assert features["quic_scid_len"] == 4

    def test_extract_initial_packets(self, extractor: QUICExtractor) -> None:
        """Test Initial packet counting."""
        flow = create_quic_flow()
        features = extractor.extract(flow)

        assert features["quic_initial_packets"] >= 1

    def test_no_quic_traffic(self, extractor: QUICExtractor) -> None:
        """Test extraction from non-QUIC flow."""
        from joyfuljay.core.flow import Flow
        from joyfuljay.core.packet import Packet

        # Plain UDP traffic
        packet = Packet(
            timestamp=1000.0,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=8080,
            protocol=17,  # UDP
            payload_len=100,
            total_len=128,
            raw_payload=b"\x00" * 100,
        )

        flow = Flow.from_first_packet(packet)
        features = extractor.extract(flow)

        assert features["quic_detected"] is False

    def test_validate_features(self, extractor: QUICExtractor) -> None:
        """Test feature validation."""
        flow = create_quic_flow()
        features = extractor.extract(flow)

        assert extractor.validate_features(features)

    def test_spin_bit_detection(self, extractor: QUICExtractor) -> None:
        """Test spin bit feature if present."""
        flow = create_quic_flow()
        features = extractor.extract(flow)

        # Spin bit might be tracked
        if "quic_spin_bit_flips" in features:
            assert features["quic_spin_bit_flips"] >= 0
