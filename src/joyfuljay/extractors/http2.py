"""HTTP/2 and HTTP/3 feature extractor.

Detects HTTP/2 and HTTP/3 (QUIC-based) traffic and extracts protocol-specific
features useful for traffic classification and analysis.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .base import FeatureExtractor

if TYPE_CHECKING:
    from ..core.flow import Flow
    from ..schema.registry import FeatureMeta

# HTTP/2 connection preface (client magic)
HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
HTTP2_PREFACE_PREFIX = b"PRI * HTTP/2"

# HTTP/2 frame types
HTTP2_FRAME_DATA = 0x00
HTTP2_FRAME_HEADERS = 0x01
HTTP2_FRAME_PRIORITY = 0x02
HTTP2_FRAME_RST_STREAM = 0x03
HTTP2_FRAME_SETTINGS = 0x04
HTTP2_FRAME_PUSH_PROMISE = 0x05
HTTP2_FRAME_PING = 0x06
HTTP2_FRAME_GOAWAY = 0x07
HTTP2_FRAME_WINDOW_UPDATE = 0x08
HTTP2_FRAME_CONTINUATION = 0x09

HTTP2_FRAME_NAMES = {
    HTTP2_FRAME_DATA: "DATA",
    HTTP2_FRAME_HEADERS: "HEADERS",
    HTTP2_FRAME_PRIORITY: "PRIORITY",
    HTTP2_FRAME_RST_STREAM: "RST_STREAM",
    HTTP2_FRAME_SETTINGS: "SETTINGS",
    HTTP2_FRAME_PUSH_PROMISE: "PUSH_PROMISE",
    HTTP2_FRAME_PING: "PING",
    HTTP2_FRAME_GOAWAY: "GOAWAY",
    HTTP2_FRAME_WINDOW_UPDATE: "WINDOW_UPDATE",
    HTTP2_FRAME_CONTINUATION: "CONTINUATION",
}


class HTTP2Extractor(FeatureExtractor):
    """Extracts HTTP/2 and HTTP/3 protocol features.

    Features include:
    - Protocol detection (HTTP/2, HTTP/3)
    - Frame type analysis
    - Stream count estimation
    - Server push detection
    - Multiplexing indicators
    """

    def extract(self, flow: Flow) -> dict[str, Any]:
        """Extract HTTP/2 and HTTP/3 features from a flow.

        Args:
            flow: The completed flow.

        Returns:
            Dictionary of HTTP/2 and HTTP/3 features.
        """
        features: dict[str, Any] = {
            "http2_detected": False,
            "http3_detected": False,
            "http2_preface_seen": False,
            "http2_frame_count": 0,
            "http2_data_frames": 0,
            "http2_headers_frames": 0,
            "http2_settings_frames": 0,
            "http2_push_promise_frames": 0,
            "http2_goaway_frames": 0,
            "http2_window_update_frames": 0,
            "http2_streams_estimate": 0,
            "http2_server_push": False,
            "http2_multiplexed": False,
            "http_version": "",
        }

        # Check for QUIC-based HTTP/3 (already detected in QUIC extractor)
        # HTTP/3 runs over UDP port 443 with QUIC
        if flow.key.protocol == 17:  # UDP
            if flow.key.port_a == 443 or flow.key.port_b == 443:
                # Check if ALPN indicates h3
                features["http3_detected"] = self._detect_http3(flow)
                if features["http3_detected"]:
                    features["http_version"] = "h3"
                    return features

        # Check for HTTP/2 (TCP-based)
        if flow.key.protocol == 6:  # TCP
            self._analyze_http2(flow, features)

        return features

    def _detect_http3(self, flow: Flow) -> bool:
        """Detect HTTP/3 in QUIC traffic.

        HTTP/3 is indicated by ALPN "h3" or "h3-29" etc in QUIC.

        Args:
            flow: The flow to analyze.

        Returns:
            True if HTTP/3 is detected.
        """
        # Look for QUIC Initial packets with ALPN
        for packet in flow.packets:
            if packet.raw_payload and len(packet.raw_payload) > 10:
                payload = packet.raw_payload
                # Look for h3 ALPN in QUIC ClientHello
                if b"\x02h3" in payload or b"\x05h3-29" in payload or b"\x05h3-34" in payload:
                    return True
        return False

    def _analyze_http2(self, flow: Flow, features: dict[str, Any]) -> None:
        """Analyze flow for HTTP/2 characteristics.

        Args:
            flow: The flow to analyze.
            features: Features dict to update.
        """
        stream_ids: set[int] = set()

        for packet in flow.packets:
            if not packet.raw_payload:
                continue

            payload = packet.raw_payload

            # Check for HTTP/2 connection preface
            if HTTP2_PREFACE_PREFIX in payload or payload.startswith(HTTP2_PREFACE_PREFIX):
                features["http2_preface_seen"] = True
                features["http2_detected"] = True
                features["http_version"] = "h2"

            # Try to parse HTTP/2 frames
            if features["http2_detected"] or self._looks_like_http2_frames(payload):
                if not features["http2_detected"]:
                    features["http2_detected"] = True
                    features["http_version"] = "h2"

                frame_info = self._parse_http2_frames(payload)
                features["http2_frame_count"] += frame_info["frame_count"]
                features["http2_data_frames"] += frame_info["data_frames"]
                features["http2_headers_frames"] += frame_info["headers_frames"]
                features["http2_settings_frames"] += frame_info["settings_frames"]
                features["http2_push_promise_frames"] += frame_info["push_promise_frames"]
                features["http2_goaway_frames"] += frame_info["goaway_frames"]
                features["http2_window_update_frames"] += frame_info["window_update_frames"]
                stream_ids.update(frame_info["stream_ids"])

                if frame_info["push_promise_frames"] > 0:
                    features["http2_server_push"] = True

        # Estimate stream count and multiplexing
        features["http2_streams_estimate"] = len(stream_ids)
        if len(stream_ids) > 1:
            features["http2_multiplexed"] = True

    def _looks_like_http2_frames(self, payload: bytes) -> bool:
        """Check if payload looks like HTTP/2 frames.

        HTTP/2 frames have a specific structure:
        - 3 bytes: length
        - 1 byte: type (0-9 for standard frames)
        - 1 byte: flags
        - 4 bytes: stream ID (R + 31 bits)

        Args:
            payload: Raw payload bytes.

        Returns:
            True if it looks like HTTP/2 frames.
        """
        if len(payload) < 9:
            return False

        # Check first frame header
        frame_type = payload[3] if len(payload) > 3 else 255

        # Valid HTTP/2 frame types are 0-9
        if frame_type > 9:
            return False

        # Length should be reasonable
        length = int.from_bytes(payload[:3], "big")
        if length > 16384 and frame_type not in (HTTP2_FRAME_DATA,):
            # Non-DATA frames typically have reasonable sizes
            return False

        return True

    def _parse_http2_frames(self, payload: bytes) -> dict[str, Any]:
        """Parse HTTP/2 frames from payload.

        Args:
            payload: Raw payload bytes.

        Returns:
            Dictionary with frame analysis results.
        """
        result = {
            "frame_count": 0,
            "data_frames": 0,
            "headers_frames": 0,
            "settings_frames": 0,
            "push_promise_frames": 0,
            "goaway_frames": 0,
            "window_update_frames": 0,
            "stream_ids": set(),
        }

        offset = 0
        while offset + 9 <= len(payload):
            # Parse frame header (9 bytes)
            length = int.from_bytes(payload[offset : offset + 3], "big")
            frame_type = payload[offset + 3]
            # flags = payload[offset + 4]
            stream_id = int.from_bytes(payload[offset + 5 : offset + 9], "big") & 0x7FFFFFFF

            result["frame_count"] += 1
            result["stream_ids"].add(stream_id)

            if frame_type == HTTP2_FRAME_DATA:
                result["data_frames"] += 1
            elif frame_type == HTTP2_FRAME_HEADERS:
                result["headers_frames"] += 1
            elif frame_type == HTTP2_FRAME_SETTINGS:
                result["settings_frames"] += 1
            elif frame_type == HTTP2_FRAME_PUSH_PROMISE:
                result["push_promise_frames"] += 1
            elif frame_type == HTTP2_FRAME_GOAWAY:
                result["goaway_frames"] += 1
            elif frame_type == HTTP2_FRAME_WINDOW_UPDATE:
                result["window_update_frames"] += 1

            # Move to next frame
            offset += 9 + length

            # Safety limit
            if result["frame_count"] > 100:
                break

        return result

    @property
    def feature_names(self) -> list[str]:
        """Get feature names produced by this extractor."""
        return [
            "http2_detected",
            "http3_detected",
            "http2_preface_seen",
            "http2_frame_count",
            "http2_data_frames",
            "http2_headers_frames",
            "http2_settings_frames",
            "http2_push_promise_frames",
            "http2_goaway_frames",
            "http2_window_update_frames",
            "http2_streams_estimate",
            "http2_server_push",
            "http2_multiplexed",
            "http_version",
        ]

    @property
    def extractor_id(self) -> str:
        """Get the stable identifier for this extractor."""
        return "http2"

    def feature_meta(self) -> dict[str, FeatureMeta]:
        """Get metadata for all features produced by this extractor."""
        from ..schema.registry import FeatureMeta

        meta: dict[str, FeatureMeta] = {}
        prefix = self.extractor_id

        feature_definitions = {
            "http2_detected": FeatureMeta(
                id=f"{prefix}.http2_detected",
                dtype="bool",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="HTTP/2 detected in bidirectional flow",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="Whether HTTP/2 protocol was detected in flow",
            ),
            "http3_detected": FeatureMeta(
                id=f"{prefix}.http3_detected",
                dtype="bool",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="HTTP/3 detected in bidirectional flow",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="Whether HTTP/3 (QUIC-based) protocol was detected in flow",
            ),
            "http2_preface_seen": FeatureMeta(
                id=f"{prefix}.http2_preface_seen",
                dtype="bool",
                shape=[1],
                units="",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="HTTP/2 connection preface from client",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="Whether HTTP/2 connection preface (client magic) was seen",
            ),
            "http2_frame_count": FeatureMeta(
                id=f"{prefix}.http2_frame_count",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="bidir",
                direction_semantics="Total HTTP/2 frames in both directions",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="Total number of HTTP/2 frames observed",
            ),
            "http2_data_frames": FeatureMeta(
                id=f"{prefix}.http2_data_frames",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="bidir",
                direction_semantics="HTTP/2 DATA frames in both directions",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="Number of HTTP/2 DATA frames",
            ),
            "http2_headers_frames": FeatureMeta(
                id=f"{prefix}.http2_headers_frames",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="bidir",
                direction_semantics="HTTP/2 HEADERS frames in both directions",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="Number of HTTP/2 HEADERS frames",
            ),
            "http2_settings_frames": FeatureMeta(
                id=f"{prefix}.http2_settings_frames",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="bidir",
                direction_semantics="HTTP/2 SETTINGS frames in both directions",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="Number of HTTP/2 SETTINGS frames",
            ),
            "http2_push_promise_frames": FeatureMeta(
                id=f"{prefix}.http2_push_promise_frames",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="HTTP/2 PUSH_PROMISE frames from server",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="Number of HTTP/2 PUSH_PROMISE frames (server push)",
            ),
            "http2_goaway_frames": FeatureMeta(
                id=f"{prefix}.http2_goaway_frames",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="bidir",
                direction_semantics="HTTP/2 GOAWAY frames in both directions",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="Number of HTTP/2 GOAWAY frames",
            ),
            "http2_window_update_frames": FeatureMeta(
                id=f"{prefix}.http2_window_update_frames",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="bidir",
                direction_semantics="HTTP/2 WINDOW_UPDATE frames in both directions",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="Number of HTTP/2 WINDOW_UPDATE frames (flow control)",
            ),
            "http2_streams_estimate": FeatureMeta(
                id=f"{prefix}.http2_streams_estimate",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="bidir",
                direction_semantics="Estimated HTTP/2 streams in both directions",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="Estimated number of HTTP/2 streams (unique stream IDs)",
            ),
            "http2_server_push": FeatureMeta(
                id=f"{prefix}.http2_server_push",
                dtype="bool",
                shape=[1],
                units="",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="Server push detected from server",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="Whether HTTP/2 server push was detected",
            ),
            "http2_multiplexed": FeatureMeta(
                id=f"{prefix}.http2_multiplexed",
                dtype="bool",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="Multiple streams detected in bidirectional flow",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="Whether HTTP/2 stream multiplexing was detected",
            ),
            "http_version": FeatureMeta(
                id=f"{prefix}.http_version",
                dtype="string",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="Detected HTTP version string",
                missing_policy="empty",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="HTTP version string (e.g., 'h2', 'h3')",
            ),
        }

        # Build metadata dict for all feature names
        for name in self.feature_names:
            if name in feature_definitions:
                meta[f"{prefix}.{name}"] = feature_definitions[name]

        return meta
