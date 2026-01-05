"""Tests for HTTP/2 extractor."""

from __future__ import annotations

import pytest

from joyfuljay.core.flow import Flow, FlowKey
from joyfuljay.core.packet import Packet
from joyfuljay.extractors.http2 import (
    HTTP2_FRAME_DATA,
    HTTP2_FRAME_HEADERS,
    HTTP2_FRAME_SETTINGS,
    HTTP2_PREFACE,
    HTTP2Extractor,
)


@pytest.fixture
def extractor() -> HTTP2Extractor:
    """Create an HTTP2Extractor instance."""
    return HTTP2Extractor()


@pytest.fixture
def tcp_flow() -> Flow:
    """Create a basic TCP flow."""
    packet = Packet(
        timestamp=1.0,
        src_ip="192.168.1.1",
        dst_ip="10.0.0.1",
        src_port=54321,
        dst_port=443,
        protocol=6,  # TCP
        payload_len=100,
        total_len=140,
    )
    return Flow.from_first_packet(packet)


@pytest.fixture
def udp_flow() -> Flow:
    """Create a basic UDP flow (for HTTP/3 testing)."""
    packet = Packet(
        timestamp=1.0,
        src_ip="192.168.1.1",
        dst_ip="10.0.0.1",
        src_port=54321,
        dst_port=443,
        protocol=17,  # UDP
        payload_len=100,
        total_len=140,
    )
    return Flow.from_first_packet(packet)


def make_http2_frame(frame_type: int, stream_id: int, payload: bytes = b"") -> bytes:
    """Create an HTTP/2 frame.

    Args:
        frame_type: Frame type (0-9).
        stream_id: Stream identifier.
        payload: Frame payload.

    Returns:
        Encoded HTTP/2 frame.
    """
    length = len(payload)
    flags = 0
    header = (
        length.to_bytes(3, "big")
        + bytes([frame_type, flags])
        + (stream_id & 0x7FFFFFFF).to_bytes(4, "big")
    )
    return header + payload


class TestHTTP2Extractor:
    """Tests for HTTP2Extractor."""

    def test_feature_names(self, extractor: HTTP2Extractor) -> None:
        """Test that all expected features are declared."""
        names = extractor.feature_names
        assert "http2_detected" in names
        assert "http3_detected" in names
        assert "http2_preface_seen" in names
        assert "http2_frame_count" in names
        assert "http2_data_frames" in names
        assert "http2_headers_frames" in names
        assert "http2_settings_frames" in names
        assert "http2_push_promise_frames" in names
        assert "http2_streams_estimate" in names
        assert "http2_server_push" in names
        assert "http2_multiplexed" in names
        assert "http_version" in names

    def test_extract_empty_flow(self, extractor: HTTP2Extractor, tcp_flow: Flow) -> None:
        """Test extraction on flow without payload."""
        features = extractor.extract(tcp_flow)

        assert features["http2_detected"] is False
        assert features["http3_detected"] is False
        assert features["http2_frame_count"] == 0
        assert features["http_version"] == ""

    def test_detect_http2_preface(self, extractor: HTTP2Extractor, tcp_flow: Flow) -> None:
        """Test detection of HTTP/2 connection preface."""
        packet = Packet(
            timestamp=1.1,
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            protocol=6,
            payload_len=len(HTTP2_PREFACE),
            total_len=len(HTTP2_PREFACE) + 40,
            raw_payload=HTTP2_PREFACE,
        )
        tcp_flow.add_packet(packet)

        features = extractor.extract(tcp_flow)

        assert features["http2_detected"] is True
        assert features["http2_preface_seen"] is True
        assert features["http_version"] == "h2"

    def test_parse_http2_frames(self, extractor: HTTP2Extractor, tcp_flow: Flow) -> None:
        """Test parsing of HTTP/2 frames."""
        # First packet: HTTP/2 preface
        preface_packet = Packet(
            timestamp=1.1,
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            protocol=6,
            payload_len=len(HTTP2_PREFACE),
            total_len=len(HTTP2_PREFACE) + 40,
            raw_payload=HTTP2_PREFACE,
        )
        tcp_flow.add_packet(preface_packet)

        # Second packet: HTTP/2 frames
        frames = (
            make_http2_frame(HTTP2_FRAME_SETTINGS, 0, b"\x00\x03\x00\x00\x00\x64")
            + make_http2_frame(HTTP2_FRAME_HEADERS, 1, b"compressed headers")
            + make_http2_frame(HTTP2_FRAME_DATA, 1, b"response body data")
        )

        frames_packet = Packet(
            timestamp=1.2,
            src_ip="10.0.0.1",
            dst_ip="192.168.1.1",
            src_port=443,
            dst_port=54321,
            protocol=6,
            payload_len=len(frames),
            total_len=len(frames) + 40,
            raw_payload=frames,
        )
        tcp_flow.add_packet(frames_packet)

        features = extractor.extract(tcp_flow)

        assert features["http2_detected"] is True
        assert features["http2_frame_count"] >= 3
        assert features["http2_settings_frames"] >= 1
        assert features["http2_headers_frames"] >= 1
        assert features["http2_data_frames"] >= 1

    def test_detect_multiplexed_streams(
        self, extractor: HTTP2Extractor, tcp_flow: Flow
    ) -> None:
        """Test detection of multiplexed streams."""
        # First packet: HTTP/2 preface
        preface_packet = Packet(
            timestamp=1.1,
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            protocol=6,
            payload_len=len(HTTP2_PREFACE),
            total_len=len(HTTP2_PREFACE) + 40,
            raw_payload=HTTP2_PREFACE,
        )
        tcp_flow.add_packet(preface_packet)

        # Second packet: frames on different streams
        frames = (
            make_http2_frame(HTTP2_FRAME_HEADERS, 1, b"stream 1 headers")
            + make_http2_frame(HTTP2_FRAME_HEADERS, 3, b"stream 3 headers")
            + make_http2_frame(HTTP2_FRAME_DATA, 1, b"stream 1 data")
            + make_http2_frame(HTTP2_FRAME_DATA, 3, b"stream 3 data")
        )

        frames_packet = Packet(
            timestamp=1.2,
            src_ip="10.0.0.1",
            dst_ip="192.168.1.1",
            src_port=443,
            dst_port=54321,
            protocol=6,
            payload_len=len(frames),
            total_len=len(frames) + 40,
            raw_payload=frames,
        )
        tcp_flow.add_packet(frames_packet)

        features = extractor.extract(tcp_flow)

        assert features["http2_detected"] is True
        assert features["http2_streams_estimate"] >= 2
        assert features["http2_multiplexed"] is True

    def test_detect_http3_alpn(self, extractor: HTTP2Extractor, udp_flow: Flow) -> None:
        """Test detection of HTTP/3 via ALPN."""
        # Payload containing h3 ALPN
        payload = b"\x00\x00\x00\x02h3some other quic data"

        packet = Packet(
            timestamp=1.1,
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            protocol=17,  # UDP
            payload_len=len(payload),
            total_len=len(payload) + 40,
            raw_payload=payload,
        )
        udp_flow.add_packet(packet)

        features = extractor.extract(udp_flow)

        assert features["http3_detected"] is True
        assert features["http_version"] == "h3"

    def test_udp_non_443_not_http3(self, extractor: HTTP2Extractor) -> None:
        """Test that non-443 UDP traffic is not marked as HTTP/3."""
        packet = Packet(
            timestamp=1.0,
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=8080,  # Not 443
            protocol=17,  # UDP
            payload_len=100,
            total_len=140,
            raw_payload=b"\x02h3some data",
        )
        flow = Flow.from_first_packet(packet)

        features = extractor.extract(flow)

        assert features["http3_detected"] is False

    def test_returns_all_features(self, extractor: HTTP2Extractor, tcp_flow: Flow) -> None:
        """Test that all declared features are returned."""
        features = extractor.extract(tcp_flow)

        for name in extractor.feature_names:
            assert name in features, f"Missing feature: {name}"

    def test_looks_like_http2_frames(self, extractor: HTTP2Extractor) -> None:
        """Test the _looks_like_http2_frames heuristic."""
        # Valid SETTINGS frame (type 4)
        valid_frame = make_http2_frame(HTTP2_FRAME_SETTINGS, 0, b"\x00\x01\x00\x00\x10\x00")
        assert extractor._looks_like_http2_frames(valid_frame) is True

        # Invalid frame type (> 9)
        invalid_frame = b"\x00\x00\x06" + bytes([15, 0]) + b"\x00\x00\x00\x00"
        assert extractor._looks_like_http2_frames(invalid_frame) is False

        # Too short
        assert extractor._looks_like_http2_frames(b"\x00\x00") is False
