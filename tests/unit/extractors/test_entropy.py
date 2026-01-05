"""Tests for entropy feature extractor."""

from __future__ import annotations

import pytest

from joyfuljay.extractors.entropy import EntropyExtractor

from tests.fixtures.packets import create_entropy_flow


class TestEntropyExtractor:
    """Tests for EntropyExtractor."""

    @pytest.fixture
    def extractor(self) -> EntropyExtractor:
        """Create an entropy extractor."""
        return EntropyExtractor()

    def test_feature_names(self, extractor: EntropyExtractor) -> None:
        """Test that feature names are properly defined."""
        names = extractor.feature_names
        assert isinstance(names, list)
        assert len(names) > 0
        assert "entropy_payload" in names or "payload_entropy" in names

    def test_extractor_name(self, extractor: EntropyExtractor) -> None:
        """Test extractor name."""
        assert extractor.name == "EntropyExtractor"

    def test_extract_high_entropy(self, extractor: EntropyExtractor) -> None:
        """Test entropy extraction from random data."""
        flow = create_entropy_flow(payload_type="random", size=256)
        features = extractor.extract(flow)

        # Random data should have high entropy (close to 8 bits/byte)
        entropy_key = "entropy_payload" if "entropy_payload" in features else "payload_entropy"
        if entropy_key in features:
            assert features[entropy_key] > 7.0

    def test_extract_low_entropy(self, extractor: EntropyExtractor) -> None:
        """Test entropy extraction from plaintext."""
        flow = create_entropy_flow(payload_type="plaintext", size=256)
        features = extractor.extract(flow)

        # Plaintext ASCII should have lower entropy
        entropy_key = "entropy_payload" if "entropy_payload" in features else "payload_entropy"
        if entropy_key in features:
            assert features[entropy_key] < 6.0

    def test_extract_zero_entropy(self, extractor: EntropyExtractor) -> None:
        """Test entropy extraction from uniform data."""
        flow = create_entropy_flow(payload_type="zeros", size=256)
        features = extractor.extract(flow)

        # All zeros should have zero entropy
        entropy_key = "entropy_payload" if "entropy_payload" in features else "payload_entropy"
        if entropy_key in features:
            assert features[entropy_key] == 0.0

    def test_extract_printable_ratio(self, extractor: EntropyExtractor) -> None:
        """Test printable character ratio."""
        flow = create_entropy_flow(payload_type="plaintext", size=256)
        features = extractor.extract(flow)

        if "printable_ratio" in features:
            # Plaintext should be mostly printable
            assert features["printable_ratio"] > 0.8

    def test_extract_random_printable_ratio(self, extractor: EntropyExtractor) -> None:
        """Test printable ratio for random data."""
        flow = create_entropy_flow(payload_type="random", size=256)
        features = extractor.extract(flow)

        if "printable_ratio" in features:
            # Random data has ~36% printable ASCII
            assert features["printable_ratio"] < 0.5

    def test_validate_features(self, extractor: EntropyExtractor) -> None:
        """Test feature validation."""
        flow = create_entropy_flow()
        features = extractor.extract(flow)

        assert extractor.validate_features(features)

    def test_entropy_bounds(self, extractor: EntropyExtractor) -> None:
        """Test that entropy is within valid bounds (0-8 bits)."""
        flow = create_entropy_flow(payload_type="random", size=256)
        features = extractor.extract(flow)

        entropy_key = "entropy_payload" if "entropy_payload" in features else "payload_entropy"
        if entropy_key in features:
            assert 0.0 <= features[entropy_key] <= 8.0

    def test_empty_payload(self, extractor: EntropyExtractor) -> None:
        """Test handling of flow with no payload."""
        from joyfuljay.core.flow import Flow
        from joyfuljay.core.packet import Packet

        packet = Packet(
            timestamp=1000.0,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=80,
            protocol=6,
            payload_len=0,
            total_len=40,
            tcp_flags=0x10,  # ACK only
            raw_payload=None,
        )

        flow = Flow.from_first_packet(packet)
        features = extractor.extract(flow)

        # Should not crash
        entropy_key = "entropy_payload" if "entropy_payload" in features else "payload_entropy"
        if entropy_key in features:
            assert features[entropy_key] == 0.0
