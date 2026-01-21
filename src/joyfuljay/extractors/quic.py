"""QUIC protocol metadata feature extractor."""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING, Any

from .base import FeatureExtractor

if TYPE_CHECKING:
    from ..core.flow import Flow
    from ..schema.registry import FeatureMeta

# QUIC packet types (long header)
QUIC_INITIAL = 0x00
QUIC_0RTT = 0x01
QUIC_HANDSHAKE = 0x02
QUIC_RETRY = 0x03


class QUICExtractor(FeatureExtractor):
    """Extracts QUIC protocol metadata features.

    Parses QUIC Initial packets to extract:
    - QUIC version
    - Connection ID information
    - Handshake indicators
    """

    def extract(self, flow: Flow) -> dict[str, Any]:
        """Extract QUIC metadata features from a flow.

        Args:
            flow: The completed flow.

        Returns:
            Dictionary of QUIC features.
        """
        features: dict[str, Any] = {
            "quic_detected": False,
            "quic_version": 0,
            "quic_version_str": "",
            "quic_dcid_len": 0,
            "quic_scid_len": 0,
            "quic_pn_length": 0,  # Packet Number length (1-4 bytes)
            "quic_initial_packets": 0,
            "quic_0rtt_detected": False,
            "quic_retry_detected": False,
            "quic_spin_bit": False,  # Spin bit for RTT estimation
            "quic_alpn": "",
            "quic_sni": "",
        }

        # Check if this looks like QUIC (UDP port 443 or known QUIC)
        if flow.key.protocol != 17:  # Not UDP
            return features

        # Look for QUIC packets
        for packet in flow.packets:
            if packet.raw_payload and len(packet.raw_payload) > 0:
                if self._is_quic_long_header(packet.raw_payload):
                    features["quic_detected"] = True
                    self._parse_quic_header(packet.raw_payload, features)
                    # Try to extract ALPN and SNI from Initial packet
                    self._parse_quic_crypto(packet.raw_payload, features)
                    break
                elif self._is_quic_short_header(packet.raw_payload):
                    features["quic_detected"] = True
                    self._parse_quic_short_header(packet.raw_payload, features)
                    break

        # Count Initial packets
        features["quic_initial_packets"] = self._count_initial_packets(flow)

        # Detect spin bit from short header packets
        self._detect_spin_bit(flow, features)

        return features

    def _is_quic_long_header(self, data: bytes) -> bool:
        """Check if packet has QUIC long header format."""
        if len(data) < 5:
            return False
        # Long header: first bit is 1, second bit (fixed) is 1
        # Form: 1FTTXXXX where F=1 (fixed), TT=type
        first_byte = data[0]
        return (first_byte & 0x80) != 0 and (first_byte & 0x40) != 0

    def _parse_quic_header(
        self,
        data: bytes,
        features: dict[str, Any],
    ) -> None:
        """Parse QUIC long header."""
        try:
            if len(data) < 6:
                return

            first_byte = data[0]

            # Extract packet type (bits 4-5)
            packet_type = (first_byte & 0x30) >> 4

            if packet_type == QUIC_0RTT:
                features["quic_0rtt_detected"] = True
            elif packet_type == QUIC_RETRY:
                features["quic_retry_detected"] = True

            # Version (4 bytes)
            version = struct.unpack("!I", data[1:5])[0]
            features["quic_version"] = version
            features["quic_version_str"] = self._version_string(version)

            offset = 5

            if len(data) < offset + 1:
                return

            # Destination Connection ID length
            dcid_len = data[offset]
            features["quic_dcid_len"] = dcid_len
            offset += 1 + dcid_len

            if len(data) < offset + 1:
                return

            # Source Connection ID length
            scid_len = data[offset]
            features["quic_scid_len"] = scid_len

            # Extract packet number length from first byte (bits 0-1)
            # The actual length is (bits + 1), so 00=1, 01=2, 10=3, 11=4
            pn_length_bits = first_byte & 0x03
            features["quic_pn_length"] = pn_length_bits + 1

        except (struct.error, IndexError):
            pass

    def _is_quic_short_header(self, data: bytes) -> bool:
        """Check if packet has QUIC short header format."""
        if len(data) < 2:
            return False
        # Short header: first bit is 0, second bit (fixed) is 1
        # Form: 0FSRKPPP where F=1 (fixed)
        first_byte = data[0]
        return (first_byte & 0x80) == 0 and (first_byte & 0x40) != 0

    def _parse_quic_short_header(
        self,
        data: bytes,
        features: dict[str, Any],
    ) -> None:
        """Parse QUIC short header."""
        try:
            if len(data) < 1:
                return

            first_byte = data[0]

            # Extract packet number length from first byte (bits 0-1)
            pn_length_bits = first_byte & 0x03
            features["quic_pn_length"] = pn_length_bits + 1

            # Extract spin bit (bit 5) - used for RTT estimation
            features["quic_spin_bit"] = bool(first_byte & 0x20)

        except (struct.error, IndexError):
            pass

    def _detect_spin_bit(self, flow: Flow, features: dict[str, Any]) -> None:
        """Detect spin bit usage in QUIC short header packets."""
        spin_values: list[bool] = []

        for packet in flow.packets:
            if packet.raw_payload and len(packet.raw_payload) > 0:
                if self._is_quic_short_header(packet.raw_payload):
                    spin_bit = bool(packet.raw_payload[0] & 0x20)
                    spin_values.append(spin_bit)

        # If we see spin bit transitions, the connection uses spin bit
        if len(spin_values) >= 2:
            for i in range(1, len(spin_values)):
                if spin_values[i] != spin_values[i - 1]:
                    features["quic_spin_bit"] = True
                    break

    def _count_initial_packets(self, flow: Flow) -> int:
        """Count QUIC Initial packets in the flow."""
        count = 0
        for packet in flow.packets:
            if packet.raw_payload and len(packet.raw_payload) > 5:
                if self._is_quic_long_header(packet.raw_payload):
                    first_byte = packet.raw_payload[0]
                    packet_type = (first_byte & 0x30) >> 4
                    if packet_type == QUIC_INITIAL:
                        count += 1
        return count

    def _version_string(self, version: int) -> str:
        """Convert QUIC version to string."""
        # Common QUIC versions
        versions = {
            0x00000001: "QUIC v1",
            0xFF000000: "QUIC draft (negotiation)",
            0x6B3343CF: "QUIC v2",
        }

        # Draft versions (0xFF0000XX pattern)
        if (version & 0xFFFFFF00) == 0xFF000000:
            draft = version & 0xFF
            return f"QUIC draft-{draft}"

        return versions.get(version, f"Unknown (0x{version:08x})")

    def _parse_quic_crypto(
        self,
        data: bytes,
        features: dict[str, Any],
    ) -> None:
        """Parse QUIC crypto frames to extract ALPN and SNI.

        QUIC Initial packets contain encrypted TLS 1.3 ClientHello.
        We attempt to find ALPN and SNI by looking for common patterns.
        """
        try:
            # Look for SNI extension pattern in the payload
            # SNI extension has type 0x0000 followed by length
            sni = self._find_sni_in_payload(data)
            if sni:
                features["quic_sni"] = sni

            # Look for ALPN extension pattern (type 0x0010)
            alpn = self._find_alpn_in_payload(data)
            if alpn:
                features["quic_alpn"] = alpn

        except (struct.error, IndexError):
            pass

    def _find_sni_in_payload(self, data: bytes) -> str:
        """Search for SNI pattern in QUIC payload."""
        # SNI extension: 00 00 (type) followed by length, then list
        # Look for the pattern and extract hostname
        try:
            # Search for SNI extension header pattern
            idx = 0
            while idx < len(data) - 10:
                # Look for SNI extension type (0x0000)
                if data[idx] == 0x00 and data[idx + 1] == 0x00:
                    # Check if this could be SNI extension
                    if idx + 4 <= len(data):
                        ext_len = struct.unpack("!H", data[idx + 2 : idx + 4])[0]
                        if 3 < ext_len < 256 and idx + 4 + ext_len <= len(data):
                            # Try to parse as SNI list
                            ext_data = data[idx + 4 : idx + 4 + ext_len]
                            if len(ext_data) >= 5:
                                list_len = struct.unpack("!H", ext_data[0:2])[0]
                                if ext_data[2] == 0 and list_len > 0:  # host_name type
                                    name_len = struct.unpack("!H", ext_data[3:5])[0]
                                    if 0 < name_len <= 253 and len(ext_data) >= 5 + name_len:
                                        hostname = ext_data[5 : 5 + name_len]
                                        # Validate it looks like a hostname
                                        try:
                                            decoded = hostname.decode("ascii")
                                            if self._is_valid_hostname(decoded):
                                                return decoded
                                        except UnicodeDecodeError:
                                            pass
                idx += 1
        except (struct.error, IndexError):
            pass
        return ""

    def _find_alpn_in_payload(self, data: bytes) -> str:
        """Search for ALPN pattern in QUIC payload."""
        # ALPN extension: 00 10 (type) followed by length
        try:
            idx = 0
            while idx < len(data) - 8:
                # Look for ALPN extension type (0x0010)
                if data[idx] == 0x00 and data[idx + 1] == 0x10:
                    if idx + 4 <= len(data):
                        ext_len = struct.unpack("!H", data[idx + 2 : idx + 4])[0]
                        if 2 < ext_len < 100 and idx + 4 + ext_len <= len(data):
                            ext_data = data[idx + 4 : idx + 4 + ext_len]
                            if len(ext_data) >= 3:
                                alpn_list_len = struct.unpack("!H", ext_data[0:2])[0]
                                if alpn_list_len > 0 and len(ext_data) >= 3:
                                    proto_len = ext_data[2]
                                    if 0 < proto_len < 50 and len(ext_data) >= 3 + proto_len:
                                        proto = ext_data[3 : 3 + proto_len]
                                        try:
                                            decoded = proto.decode("ascii")
                                            # Common QUIC ALPN values
                                            if decoded in ("h3", "h3-29", "h3-28", "h3-27",
                                                          "hq-interop", "hq-29", "hq-28",
                                                          "http/1.1", "h2", "spdy/3.1"):
                                                return decoded
                                            # Accept other printable ASCII
                                            if all(32 <= ord(c) <= 126 for c in decoded):
                                                return decoded
                                        except UnicodeDecodeError:
                                            pass
                idx += 1
        except (struct.error, IndexError):
            pass
        return ""

    def _is_valid_hostname(self, hostname: str) -> bool:
        """Check if string looks like a valid hostname."""
        if not hostname or len(hostname) > 253:
            return False
        # Must contain at least one dot for a domain
        if "." not in hostname:
            return False
        # Check valid characters
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")
        return all(c in allowed for c in hostname)

    @property
    def feature_names(self) -> list[str]:
        """Get feature names produced by this extractor."""
        return [
            "quic_detected",
            "quic_version",
            "quic_version_str",
            "quic_dcid_len",
            "quic_scid_len",
            "quic_pn_length",
            "quic_initial_packets",
            "quic_0rtt_detected",
            "quic_retry_detected",
            "quic_spin_bit",
            "quic_alpn",
            "quic_sni",
        ]

    @property
    def extractor_id(self) -> str:
        """Get the stable identifier for this extractor."""
        return "quic"

    def feature_meta(self) -> dict[str, FeatureMeta]:
        """Get metadata for all features produced by this extractor."""
        from ..schema.registry import FeatureMeta

        meta: dict[str, FeatureMeta] = {}
        prefix = self.extractor_id

        feature_definitions = {
            "quic_detected": FeatureMeta(
                id=f"{prefix}.quic_detected",
                dtype="bool",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="Whether QUIC protocol was detected",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["udp", "quic"],
                privacy_level="safe",
                description="QUIC protocol detection flag",
            ),
            "quic_version": FeatureMeta(
                id=f"{prefix}.quic_version",
                dtype="int64",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="QUIC protocol version number",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["udp", "quic"],
                privacy_level="safe",
                description="QUIC version as integer",
            ),
            "quic_version_str": FeatureMeta(
                id=f"{prefix}.quic_version_str",
                dtype="string",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="Human-readable QUIC version",
                missing_policy="empty",
                missing_sentinel=None,
                dependencies=["udp", "quic"],
                privacy_level="safe",
                description="QUIC version as human-readable string",
            ),
            "quic_dcid_len": FeatureMeta(
                id=f"{prefix}.quic_dcid_len",
                dtype="int64",
                shape=[1],
                units="bytes",
                scope="flow",
                direction="bidir",
                direction_semantics="Destination connection ID length",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["udp", "quic"],
                privacy_level="safe",
                description="Length of destination connection ID",
            ),
            "quic_scid_len": FeatureMeta(
                id=f"{prefix}.quic_scid_len",
                dtype="int64",
                shape=[1],
                units="bytes",
                scope="flow",
                direction="bidir",
                direction_semantics="Source connection ID length",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["udp", "quic"],
                privacy_level="safe",
                description="Length of source connection ID",
            ),
            "quic_pn_length": FeatureMeta(
                id=f"{prefix}.quic_pn_length",
                dtype="int64",
                shape=[1],
                units="bytes",
                scope="flow",
                direction="bidir",
                direction_semantics="Packet number field length",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["udp", "quic"],
                privacy_level="safe",
                description="QUIC packet number length (1-4 bytes)",
            ),
            "quic_initial_packets": FeatureMeta(
                id=f"{prefix}.quic_initial_packets",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="bidir",
                direction_semantics="Count of QUIC Initial packets",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["udp", "quic"],
                privacy_level="safe",
                description="Number of QUIC Initial packets in flow",
            ),
            "quic_0rtt_detected": FeatureMeta(
                id=f"{prefix}.quic_0rtt_detected",
                dtype="bool",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="Whether 0-RTT was detected",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["udp", "quic"],
                privacy_level="safe",
                description="QUIC 0-RTT early data detection flag",
            ),
            "quic_retry_detected": FeatureMeta(
                id=f"{prefix}.quic_retry_detected",
                dtype="bool",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="Whether Retry packet was detected",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["udp", "quic"],
                privacy_level="safe",
                description="QUIC Retry packet detection flag",
            ),
            "quic_spin_bit": FeatureMeta(
                id=f"{prefix}.quic_spin_bit",
                dtype="bool",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="Whether spin bit is in use",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["udp", "quic"],
                privacy_level="safe",
                description="QUIC spin bit detection for RTT estimation",
            ),
            "quic_alpn": FeatureMeta(
                id=f"{prefix}.quic_alpn",
                dtype="string",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="Application-Layer Protocol Negotiation value",
                missing_policy="empty",
                missing_sentinel=None,
                dependencies=["udp", "quic"],
                privacy_level="safe",
                description="QUIC ALPN protocol identifier (e.g., h3)",
            ),
            "quic_sni": FeatureMeta(
                id=f"{prefix}.quic_sni",
                dtype="string",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="Server Name Indication hostname",
                missing_policy="empty",
                missing_sentinel=None,
                dependencies=["udp", "quic"],
                privacy_level="sensitive",
                description="QUIC SNI hostname from ClientHello",
            ),
        }

        # Include metadata for all features
        for name in self.feature_names:
            if name in feature_definitions:
                meta[f"{prefix}.{name}"] = feature_definitions[name]

        return meta
