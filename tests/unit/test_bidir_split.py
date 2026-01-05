"""Tests for bidirectional feature splitting utilities."""

from __future__ import annotations

import pytest

from joyfuljay.utils.bidir_split import (
    BIDIRECTIONAL_FEATURES,
    DIRECTIONAL_FEATURES,
    merge_directional_features,
    split_features_bidirectional,
)


class TestDirectionalFeaturesSets:
    """Tests for feature classification sets."""

    def test_directional_features_not_empty(self) -> None:
        """Test that directional features set is populated."""
        assert len(DIRECTIONAL_FEATURES) > 0

    def test_bidirectional_features_not_empty(self) -> None:
        """Test that bidirectional features set is populated."""
        assert len(BIDIRECTIONAL_FEATURES) > 0

    def test_no_overlap(self) -> None:
        """Test that directional and bidirectional sets don't overlap."""
        overlap = DIRECTIONAL_FEATURES & BIDIRECTIONAL_FEATURES
        assert len(overlap) == 0, f"Overlapping features: {overlap}"

    def test_directional_contains_expected_features(self) -> None:
        """Test that directional features include expected items."""
        expected = {"packet_count", "total_bytes", "mean_iat", "tcp_syn_count"}
        assert expected.issubset(DIRECTIONAL_FEATURES)

    def test_bidirectional_contains_expected_features(self) -> None:
        """Test that bidirectional features include expected items."""
        expected = {"src_ip", "dst_ip", "duration", "tls_detected"}
        assert expected.issubset(BIDIRECTIONAL_FEATURES)


class TestSplitFeaturesBidirectional:
    """Tests for split_features_bidirectional function."""

    def test_keeps_bidirectional_features_unchanged(self) -> None:
        """Test that bidirectional features are preserved."""
        features = {
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "duration": 5.0,
        }
        result = split_features_bidirectional(features)

        assert result["src_ip"] == "1.1.1.1"
        assert result["dst_ip"] == "2.2.2.2"
        assert result["duration"] == 5.0

    def test_prefixes_directional_initiator_features(self) -> None:
        """Test that _initiator suffixed features get fwd_ prefix."""
        features = {
            "packet_count_initiator": 100,
            "total_bytes_initiator": 5000,
        }
        result = split_features_bidirectional(features)

        assert result["fwd_packet_count"] == 100
        assert result["fwd_total_bytes"] == 5000
        assert "packet_count_initiator" not in result

    def test_prefixes_directional_responder_features(self) -> None:
        """Test that _responder suffixed features get bwd_ prefix."""
        features = {
            "packet_count_responder": 50,
            "total_bytes_responder": 2500,
        }
        result = split_features_bidirectional(features)

        assert result["bwd_packet_count"] == 50
        assert result["bwd_total_bytes"] == 2500
        assert "packet_count_responder" not in result

    def test_prefixes_combined_directional_features(self) -> None:
        """Test that combined directional features get total_ prefix."""
        features = {
            "packet_count": 150,
            "total_bytes": 7500,
        }
        result = split_features_bidirectional(features)

        assert result["total_packet_count"] == 150
        assert result["total_total_bytes"] == 7500
        assert "packet_count" not in result

    def test_custom_prefixes(self) -> None:
        """Test using custom prefixes."""
        features = {
            "packet_count_initiator": 100,
            "packet_count_responder": 50,
        }
        result = split_features_bidirectional(
            features,
            initiator_prefix="src_",
            responder_prefix="dst_",
        )

        assert result["src_packet_count"] == 100
        assert result["dst_packet_count"] == 50

    def test_mixed_features(self) -> None:
        """Test with a mix of all feature types."""
        features = {
            # Bidirectional
            "src_ip": "1.1.1.1",
            "duration": 5.0,
            # Directional with suffix
            "packet_count_initiator": 100,
            "packet_count_responder": 50,
            # Combined directional
            "total_bytes": 7500,
            # Unknown feature (should pass through)
            "custom_feature": "value",
        }
        result = split_features_bidirectional(features)

        assert result["src_ip"] == "1.1.1.1"
        assert result["duration"] == 5.0
        assert result["fwd_packet_count"] == 100
        assert result["bwd_packet_count"] == 50
        assert result["total_total_bytes"] == 7500
        assert result["custom_feature"] == "value"

    def test_empty_features(self) -> None:
        """Test with empty input."""
        result = split_features_bidirectional({})
        assert result == {}


class TestMergeDirectionalFeatures:
    """Tests for merge_directional_features function."""

    def test_basic_merge(self) -> None:
        """Test basic merging of forward and backward features."""
        fwd = {"packet_count": 100, "bytes": 5000}
        bwd = {"packet_count": 50, "bytes": 2500}

        result = merge_directional_features(fwd, bwd)

        assert result["fwd_packet_count"] == 100
        assert result["fwd_bytes"] == 5000
        assert result["bwd_packet_count"] == 50
        assert result["bwd_bytes"] == 2500

    def test_custom_prefixes(self) -> None:
        """Test merging with custom prefixes."""
        fwd = {"count": 100}
        bwd = {"count": 50}

        result = merge_directional_features(
            fwd, bwd,
            fwd_prefix="src_",
            bwd_prefix="dst_",
        )

        assert result["src_count"] == 100
        assert result["dst_count"] == 50

    def test_empty_forward(self) -> None:
        """Test with empty forward features."""
        result = merge_directional_features({}, {"count": 50})
        assert result["bwd_count"] == 50
        assert len(result) == 1

    def test_empty_backward(self) -> None:
        """Test with empty backward features."""
        result = merge_directional_features({"count": 100}, {})
        assert result["fwd_count"] == 100
        assert len(result) == 1

    def test_empty_both(self) -> None:
        """Test with both empty."""
        result = merge_directional_features({}, {})
        assert result == {}

    def test_different_features(self) -> None:
        """Test when forward and backward have different features."""
        fwd = {"packets": 100, "flags": 5}
        bwd = {"packets": 50, "retransmits": 2}

        result = merge_directional_features(fwd, bwd)

        assert result["fwd_packets"] == 100
        assert result["fwd_flags"] == 5
        assert result["bwd_packets"] == 50
        assert result["bwd_retransmits"] == 2
