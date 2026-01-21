"""TLS handshake metadata feature extractor."""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING, Any

from ..utils.hashing import compute_ja3_hash, compute_ja3s_hash
from .base import FeatureExtractor

if TYPE_CHECKING:
    from ..core.flow import Flow
    from ..schema.registry import FeatureMeta

# TLS record types
TLS_HANDSHAKE = 22

# TLS handshake message types
TLS_CLIENT_HELLO = 1
TLS_SERVER_HELLO = 2
TLS_CERTIFICATE = 11
TLS_NEW_SESSION_TICKET = 4

# TLS extension types for session resumption
TLS_EXT_SESSION_TICKET = 35
TLS_EXT_PRE_SHARED_KEY = 41
TLS_EXT_EARLY_DATA = 42

# TLS extension types
TLS_EXT_SNI = 0
TLS_EXT_SUPPORTED_GROUPS = 10
TLS_EXT_EC_POINT_FORMATS = 11
TLS_EXT_ALPN = 16
TLS_EXT_KEY_SHARE = 51  # TLS 1.3 key share

# TLS handshake message types for key exchange
TLS_CLIENT_KEY_EXCHANGE = 16
TLS_SERVER_KEY_EXCHANGE = 12


class TLSExtractor(FeatureExtractor):
    """Extracts TLS handshake metadata features.

    Parses TLS ClientHello and ServerHello messages to extract:
    - TLS version
    - Cipher suites
    - Extensions (including SNI)
    - JA3/JA3S fingerprints
    """

    def extract(self, flow: Flow) -> dict[str, Any]:
        """Extract TLS metadata features from a flow.

        Args:
            flow: The completed flow.

        Returns:
            Dictionary of TLS features.
        """
        features: dict[str, Any] = {
            "tls_detected": False,
            "tls_version": 0,
            "tls_version_str": "",
            "tls_cipher_suite": 0,
            "tls_cipher_count": 0,
            "tls_extension_count": 0,
            "tls_sni": "",
            "tls_alpn": "",
            "ja3_hash": "",
            "ja3s_hash": "",
            "tls_handshake_packets": 0,
            # Certificate metadata
            "tls_cert_count": 0,
            "tls_cert_total_length": 0,
            "tls_cert_first_length": 0,
            "tls_cert_chain_length": 0,
            # Session resumption
            "tls_session_id_len": 0,
            "tls_session_ticket_ext": False,
            "tls_session_resumed": False,
            "tls_psk_ext": False,
            "tls_early_data_ext": False,
            # Key exchange / DH parameters
            "tls_key_exchange_group": 0,
            "tls_key_exchange_group_name": "",
            "tls_key_exchange_length": 0,
        }

        # Track session resumption state
        client_session_id_len = 0
        client_has_ticket_ext = False
        client_has_psk_ext = False
        client_has_early_data = False

        # Look for TLS handshake in initiator packets
        client_hello_data = self._find_client_hello(flow)
        if client_hello_data:
            features["tls_detected"] = True
            client_session_id_len, client_has_ticket_ext, client_has_psk_ext, client_has_early_data = (
                self._parse_client_hello(client_hello_data, features)
            )

        # Look for ServerHello in responder packets
        server_hello_data = self._find_server_hello(flow)
        if server_hello_data:
            self._parse_server_hello(server_hello_data, features)

        # Look for ServerKeyExchange (TLS 1.2 DHE/ECDHE)
        ske_data = self._find_server_key_exchange(flow)
        if ske_data:
            self._parse_server_key_exchange(ske_data, features)

        # Look for Certificate message
        cert_data = self._find_certificate(flow)
        if cert_data:
            self._parse_certificate(cert_data, features)

        # Detect session resumption
        features["tls_session_id_len"] = client_session_id_len
        features["tls_session_ticket_ext"] = client_has_ticket_ext
        features["tls_psk_ext"] = client_has_psk_ext
        features["tls_early_data_ext"] = client_has_early_data

        # Session is resumed if:
        # 1. Client sent session ID and no Certificate message seen
        # 2. Client sent session ticket extension and abbreviated handshake
        # 3. TLS 1.3 with PSK extension
        if features["tls_detected"] and features["tls_cert_count"] == 0:
            if client_session_id_len > 0 or client_has_ticket_ext or client_has_psk_ext:
                features["tls_session_resumed"] = True

        # Count handshake packets
        features["tls_handshake_packets"] = self._count_handshake_packets(flow)

        return features

    def _find_client_hello(self, flow: Flow) -> bytes | None:
        """Find ClientHello message in flow packets."""
        for packet in flow.initiator_packets:
            if packet.raw_payload and len(packet.raw_payload) > 5:
                # Check for TLS handshake record
                if (
                    packet.raw_payload[0] == TLS_HANDSHAKE
                    and len(packet.raw_payload) > 9
                ):
                    # Check for ClientHello message type
                    if packet.raw_payload[5] == TLS_CLIENT_HELLO:
                        return packet.raw_payload
        return None

    def _find_server_hello(self, flow: Flow) -> bytes | None:
        """Find ServerHello message in flow packets."""
        for packet in flow.responder_packets:
            if packet.raw_payload and len(packet.raw_payload) > 5:
                if (
                    packet.raw_payload[0] == TLS_HANDSHAKE
                    and len(packet.raw_payload) > 9
                ):
                    if packet.raw_payload[5] == TLS_SERVER_HELLO:
                        return packet.raw_payload
        return None

    def _find_certificate(self, flow: Flow) -> bytes | None:
        """Find Certificate message in flow packets."""
        for packet in flow.responder_packets:
            if packet.raw_payload and len(packet.raw_payload) > 5:
                if packet.raw_payload[0] == TLS_HANDSHAKE:
                    # Certificate message might be in the same record or a separate one
                    # Search through the payload for Certificate message type
                    payload = packet.raw_payload
                    offset = 5  # Skip TLS record header
                    while offset + 4 <= len(payload):
                        msg_type = payload[offset]
                        if msg_type == TLS_CERTIFICATE:
                            return payload[offset:]
                        # Get message length and skip to next message
                        if offset + 4 > len(payload):
                            break
                        msg_len = struct.unpack("!I", b"\x00" + payload[offset + 1 : offset + 4])[0]
                        offset += 4 + msg_len
        return None

    def _find_server_key_exchange(self, flow: Flow) -> bytes | None:
        """Find ServerKeyExchange message in flow packets (TLS 1.2 DHE/ECDHE)."""
        for packet in flow.responder_packets:
            if packet.raw_payload and len(packet.raw_payload) > 5:
                if packet.raw_payload[0] == TLS_HANDSHAKE:
                    payload = packet.raw_payload
                    offset = 5  # Skip TLS record header
                    while offset + 4 <= len(payload):
                        msg_type = payload[offset]
                        if msg_type == TLS_SERVER_KEY_EXCHANGE:
                            return payload[offset:]
                        if offset + 4 > len(payload):
                            break
                        msg_len = struct.unpack("!I", b"\x00" + payload[offset + 1 : offset + 4])[0]
                        offset += 4 + msg_len
        return None

    def _parse_server_key_exchange(
        self,
        data: bytes,
        features: dict[str, Any],
    ) -> None:
        """Parse ServerKeyExchange to extract DH/ECDH parameters.

        For ECDHE, the format is:
        - 1 byte: curve type (3 = named_curve)
        - 2 bytes: named curve ID
        - 1 byte: public key length
        - N bytes: public key

        For DHE, the format is:
        - 2 bytes: p length
        - N bytes: p (prime)
        - 2 bytes: g length
        - N bytes: g (generator)
        - 2 bytes: Ys length
        - N bytes: Ys (public value)
        """
        try:
            if len(data) < 8:
                return

            # Skip message type (1 byte) and length (3 bytes)
            offset = 4

            # Check for ECDHE (curve_type = 3 means named_curve)
            if data[offset] == 3:  # named_curve
                offset += 1
                if len(data) < offset + 3:
                    return

                # Named curve ID
                curve_id = struct.unpack("!H", data[offset : offset + 2])[0]
                features["tls_key_exchange_group"] = curve_id
                features["tls_key_exchange_group_name"] = self._named_group_string(curve_id)
                offset += 2

                # Public key length
                pubkey_len = data[offset]
                features["tls_key_exchange_length"] = pubkey_len * 8  # Convert to bits

            else:
                # DHE - first field is p_length
                if len(data) < offset + 2:
                    return
                p_len = struct.unpack("!H", data[offset : offset + 2])[0]
                features["tls_key_exchange_length"] = p_len * 8  # DH prime size in bits
                # Use a placeholder group ID for finite field DH
                features["tls_key_exchange_group"] = 0x0100  # ffdhe2048 placeholder
                features["tls_key_exchange_group_name"] = f"ffdhe{p_len * 8}"

        except (struct.error, IndexError):
            pass

    def _parse_client_hello(
        self,
        data: bytes,
        features: dict[str, Any],
    ) -> tuple[int, bool, bool, bool]:
        """Parse TLS ClientHello message.

        Returns:
            Tuple of (session_id_len, has_session_ticket, has_psk, has_early_data)
        """
        session_id_len = 0
        has_session_ticket = False
        has_psk = False
        has_early_data = False

        try:
            # Skip TLS record header (5 bytes)
            # Skip handshake type + length (4 bytes)
            offset = 9

            if len(data) < offset + 2:
                return session_id_len, has_session_ticket, has_psk, has_early_data

            # Client version (2 bytes)
            version = struct.unpack("!H", data[offset : offset + 2])[0]
            features["tls_version"] = version
            features["tls_version_str"] = self._version_string(version)
            offset += 2

            # Skip random (32 bytes)
            offset += 32

            if len(data) < offset + 1:
                return session_id_len, has_session_ticket, has_psk, has_early_data

            # Session ID
            session_id_len = data[offset]
            offset += 1 + session_id_len

            if len(data) < offset + 2:
                return session_id_len, has_session_ticket, has_psk, has_early_data

            # Cipher suites
            cipher_len = struct.unpack("!H", data[offset : offset + 2])[0]
            offset += 2

            if len(data) < offset + cipher_len:
                return session_id_len, has_session_ticket, has_psk, has_early_data

            cipher_suites = []
            for i in range(0, cipher_len, 2):
                if offset + i + 2 <= len(data):
                    cs = struct.unpack("!H", data[offset + i : offset + i + 2])[0]
                    cipher_suites.append(cs)
            features["tls_cipher_count"] = len(cipher_suites)
            offset += cipher_len

            if len(data) < offset + 1:
                return session_id_len, has_session_ticket, has_psk, has_early_data

            # Compression methods
            comp_len = data[offset]
            offset += 1 + comp_len

            if len(data) < offset + 2:
                return session_id_len, has_session_ticket, has_psk, has_early_data

            # Extensions
            ext_len = struct.unpack("!H", data[offset : offset + 2])[0]
            offset += 2

            extensions, elliptic_curves, ec_formats, has_session_ticket, has_psk, has_early_data = (
                self._parse_extensions_with_resumption(
                    data[offset : offset + ext_len],
                    features,
                )
            )
            features["tls_extension_count"] = len(extensions)

            # Compute JA3
            features["ja3_hash"] = compute_ja3_hash(
                version,
                cipher_suites,
                extensions,
                elliptic_curves,
                ec_formats,
            )

        except (struct.error, IndexError):
            pass  # Malformed packet, leave defaults

        return session_id_len, has_session_ticket, has_psk, has_early_data

    def _parse_server_hello(
        self,
        data: bytes,
        features: dict[str, Any],
    ) -> None:
        """Parse TLS ServerHello message."""
        try:
            offset = 9  # Skip record + handshake headers

            if len(data) < offset + 2:
                return

            # Server version
            version = struct.unpack("!H", data[offset : offset + 2])[0]
            offset += 2

            # Skip random (32 bytes)
            offset += 32

            if len(data) < offset + 1:
                return

            # Session ID
            session_id_len = data[offset]
            offset += 1 + session_id_len

            if len(data) < offset + 2:
                return

            # Selected cipher suite
            cipher = struct.unpack("!H", data[offset : offset + 2])[0]
            features["tls_cipher_suite"] = cipher
            offset += 2

            # Skip compression method
            offset += 1

            if len(data) < offset + 2:
                return

            # Extensions
            ext_len = struct.unpack("!H", data[offset : offset + 2])[0]
            offset += 2

            extensions, _, _ = self._parse_extensions(
                data[offset : offset + ext_len],
                {},  # Don't update features from server
            )

            # Compute JA3S
            features["ja3s_hash"] = compute_ja3s_hash(version, cipher, extensions)

        except (struct.error, IndexError):
            pass

    def _parse_extensions(
        self,
        data: bytes,
        features: dict[str, Any],
    ) -> tuple[list[int], list[int], list[int]]:
        """Parse TLS extensions."""
        extensions, elliptic_curves, ec_formats, _, _, _ = self._parse_extensions_with_resumption(
            data, features
        )
        return extensions, elliptic_curves, ec_formats

    def _parse_extensions_with_resumption(
        self,
        data: bytes,
        features: dict[str, Any],
    ) -> tuple[list[int], list[int], list[int], bool, bool, bool]:
        """Parse TLS extensions including session resumption indicators.

        Returns:
            Tuple of (extensions, elliptic_curves, ec_formats, has_session_ticket, has_psk, has_early_data)
        """
        extensions: list[int] = []
        elliptic_curves: list[int] = []
        ec_formats: list[int] = []
        has_session_ticket = False
        has_psk = False
        has_early_data = False

        offset = 0
        while offset + 4 <= len(data):
            try:
                ext_type = struct.unpack("!H", data[offset : offset + 2])[0]
                ext_len = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
                extensions.append(ext_type)

                ext_data = data[offset + 4 : offset + 4 + ext_len]

                # Parse specific extensions
                if ext_type == TLS_EXT_SNI and len(ext_data) >= 5:
                    # SNI extension
                    sni_list_len = struct.unpack("!H", ext_data[0:2])[0]
                    if sni_list_len > 0 and ext_data[2] == 0:  # host_name type
                        name_len = struct.unpack("!H", ext_data[3:5])[0]
                        if len(ext_data) >= 5 + name_len:
                            features["tls_sni"] = ext_data[5 : 5 + name_len].decode(
                                "ascii", errors="ignore"
                            )

                elif ext_type == TLS_EXT_SUPPORTED_GROUPS and len(ext_data) >= 2:
                    # Elliptic curves
                    curves_len = struct.unpack("!H", ext_data[0:2])[0]
                    for i in range(0, min(curves_len, len(ext_data) - 2), 2):
                        curve = struct.unpack("!H", ext_data[2 + i : 4 + i])[0]
                        elliptic_curves.append(curve)

                elif ext_type == TLS_EXT_EC_POINT_FORMATS and len(ext_data) >= 1:
                    # EC point formats
                    formats_len = ext_data[0]
                    for i in range(min(formats_len, len(ext_data) - 1)):
                        ec_formats.append(ext_data[1 + i])

                elif ext_type == TLS_EXT_ALPN and len(ext_data) >= 2:
                    # ALPN extension
                    alpn_len = struct.unpack("!H", ext_data[0:2])[0]
                    if alpn_len > 0 and len(ext_data) >= 3:
                        proto_len = ext_data[2]
                        if len(ext_data) >= 3 + proto_len:
                            features["tls_alpn"] = ext_data[3 : 3 + proto_len].decode(
                                "ascii", errors="ignore"
                            )

                # Session resumption extensions
                elif ext_type == TLS_EXT_SESSION_TICKET:
                    has_session_ticket = True

                elif ext_type == TLS_EXT_PRE_SHARED_KEY:
                    has_psk = True

                elif ext_type == TLS_EXT_EARLY_DATA:
                    has_early_data = True

                # TLS 1.3 key_share extension
                elif ext_type == TLS_EXT_KEY_SHARE and len(ext_data) >= 4:
                    # Client key_share format:
                    # 2 bytes: client shares length
                    # For each share:
                    #   2 bytes: group
                    #   2 bytes: key exchange length
                    #   N bytes: key exchange data
                    try:
                        shares_len = struct.unpack("!H", ext_data[0:2])[0]
                        if shares_len > 0 and len(ext_data) >= 6:
                            # Get first key share (typically the one that will be used)
                            group = struct.unpack("!H", ext_data[2:4])[0]
                            key_len = struct.unpack("!H", ext_data[4:6])[0]
                            features["tls_key_exchange_group"] = group
                            features["tls_key_exchange_group_name"] = self._named_group_string(group)
                            features["tls_key_exchange_length"] = key_len * 8  # Convert to bits
                    except (struct.error, IndexError):
                        pass

                offset += 4 + ext_len

            except (struct.error, IndexError):
                break

        return extensions, elliptic_curves, ec_formats, has_session_ticket, has_psk, has_early_data

    def _parse_certificate(
        self,
        data: bytes,
        features: dict[str, Any],
    ) -> None:
        """Parse TLS Certificate message to extract certificate metadata."""
        try:
            # Certificate message format:
            # - 1 byte: message type (11)
            # - 3 bytes: message length
            # - 3 bytes: certificates length
            # - For each certificate:
            #   - 3 bytes: certificate length
            #   - N bytes: certificate data

            if len(data) < 7:
                return

            # Skip message type and length (4 bytes)
            offset = 4

            # Certificates total length
            certs_len = struct.unpack("!I", b"\x00" + data[offset : offset + 3])[0]
            offset += 3

            cert_count = 0
            total_cert_length = 0
            first_cert_length = 0

            while offset + 3 <= len(data) and offset < 4 + 3 + certs_len:
                # Individual certificate length
                cert_len = struct.unpack("!I", b"\x00" + data[offset : offset + 3])[0]
                offset += 3

                if cert_len > 0:
                    cert_count += 1
                    total_cert_length += cert_len
                    if cert_count == 1:
                        first_cert_length = cert_len

                offset += cert_len

            features["tls_cert_count"] = cert_count
            features["tls_cert_total_length"] = total_cert_length
            features["tls_cert_first_length"] = first_cert_length
            features["tls_cert_chain_length"] = cert_count

        except (struct.error, IndexError):
            pass  # Malformed certificate message

    def _count_handshake_packets(self, flow: Flow) -> int:
        """Count packets that appear to be TLS handshake."""
        count = 0
        for packet in flow.packets:
            if packet.raw_payload and len(packet.raw_payload) > 0:
                if packet.raw_payload[0] == TLS_HANDSHAKE:
                    count += 1
        return count

    def _version_string(self, version: int) -> str:
        """Convert TLS version number to string."""
        versions = {
            0x0300: "SSL 3.0",
            0x0301: "TLS 1.0",
            0x0302: "TLS 1.1",
            0x0303: "TLS 1.2",
            0x0304: "TLS 1.3",
        }
        return versions.get(version, f"Unknown (0x{version:04x})")

    def _named_group_string(self, group: int) -> str:
        """Convert TLS named group (curve) ID to string."""
        groups = {
            # ECDHE curves
            0x0017: "secp256r1",
            0x0018: "secp384r1",
            0x0019: "secp521r1",
            0x001D: "x25519",
            0x001E: "x448",
            # Finite field DH groups
            0x0100: "ffdhe2048",
            0x0101: "ffdhe3072",
            0x0102: "ffdhe4096",
            0x0103: "ffdhe6144",
            0x0104: "ffdhe8192",
            # Post-quantum / hybrid
            0x6399: "X25519Kyber768Draft00",
            0x0200: "secp256r1_kyber768",
        }
        return groups.get(group, f"unknown(0x{group:04x})")

    @property
    def feature_names(self) -> list[str]:
        """Get feature names produced by this extractor."""
        return [
            "tls_detected",
            "tls_version",
            "tls_version_str",
            "tls_cipher_suite",
            "tls_cipher_count",
            "tls_extension_count",
            "tls_sni",
            "tls_alpn",
            "ja3_hash",
            "ja3s_hash",
            "tls_handshake_packets",
            # Certificate metadata
            "tls_cert_count",
            "tls_cert_total_length",
            "tls_cert_first_length",
            "tls_cert_chain_length",
            # Session resumption
            "tls_session_id_len",
            "tls_session_ticket_ext",
            "tls_session_resumed",
            "tls_psk_ext",
            "tls_early_data_ext",
            # Key exchange / DH parameters
            "tls_key_exchange_group",
            "tls_key_exchange_group_name",
            "tls_key_exchange_length",
        ]

    @property
    def extractor_id(self) -> str:
        """Get the stable identifier for this extractor."""
        return "tls"

    def feature_meta(self) -> dict[str, FeatureMeta]:
        """Get metadata for all features produced by this extractor."""
        from ..schema.registry import FeatureMeta

        meta: dict[str, FeatureMeta] = {}
        prefix = self.extractor_id

        feature_definitions = {
            "tls_detected": FeatureMeta(
                id=f"{prefix}.tls_detected",
                dtype="bool",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="TLS detected in bidirectional flow",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="Whether TLS handshake was detected in flow",
            ),
            "tls_version": FeatureMeta(
                id=f"{prefix}.tls_version",
                dtype="int64",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="TLS version from ClientHello",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="TLS version number (e.g., 0x0303 for TLS 1.2)",
            ),
            "tls_version_str": FeatureMeta(
                id=f"{prefix}.tls_version_str",
                dtype="string",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="Human-readable TLS version",
                missing_policy="empty",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="TLS version string (e.g., 'TLS 1.2')",
            ),
            "tls_cipher_suite": FeatureMeta(
                id=f"{prefix}.tls_cipher_suite",
                dtype="int64",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="Selected cipher suite from ServerHello",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="Negotiated cipher suite code",
            ),
            "tls_cipher_count": FeatureMeta(
                id=f"{prefix}.tls_cipher_count",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="Cipher suites offered by client",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="Number of cipher suites in ClientHello",
            ),
            "tls_extension_count": FeatureMeta(
                id=f"{prefix}.tls_extension_count",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="Extensions in ClientHello",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="Number of TLS extensions in ClientHello",
            ),
            "tls_sni": FeatureMeta(
                id=f"{prefix}.tls_sni",
                dtype="string",
                shape=[1],
                units="",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="Server Name Indication from client",
                missing_policy="empty",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="sensitive",
                description="Server Name Indication (SNI) hostname",
            ),
            "tls_alpn": FeatureMeta(
                id=f"{prefix}.tls_alpn",
                dtype="string",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="Application Layer Protocol Negotiation",
                missing_policy="empty",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="ALPN protocol (e.g., 'h2', 'http/1.1')",
            ),
            "ja3_hash": FeatureMeta(
                id=f"{prefix}.ja3_hash",
                dtype="string",
                shape=[1],
                units="",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="JA3 fingerprint of ClientHello",
                missing_policy="empty",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="sensitive",
                description="JA3 hash fingerprint of TLS ClientHello",
            ),
            "ja3s_hash": FeatureMeta(
                id=f"{prefix}.ja3s_hash",
                dtype="string",
                shape=[1],
                units="",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="JA3S fingerprint of ServerHello",
                missing_policy="empty",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="sensitive",
                description="JA3S hash fingerprint of TLS ServerHello",
            ),
            "tls_handshake_packets": FeatureMeta(
                id=f"{prefix}.tls_handshake_packets",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="bidir",
                direction_semantics="TLS handshake packets in both directions",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="Number of TLS handshake packets",
            ),
            "tls_cert_count": FeatureMeta(
                id=f"{prefix}.tls_cert_count",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="Certificates sent by server",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="Number of certificates in server Certificate message",
            ),
            "tls_cert_total_length": FeatureMeta(
                id=f"{prefix}.tls_cert_total_length",
                dtype="int64",
                shape=[1],
                units="bytes",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="Total certificate data from server",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="Total length of all certificates in bytes",
            ),
            "tls_cert_first_length": FeatureMeta(
                id=f"{prefix}.tls_cert_first_length",
                dtype="int64",
                shape=[1],
                units="bytes",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="First certificate from server",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="Length of the first (leaf) certificate",
            ),
            "tls_cert_chain_length": FeatureMeta(
                id=f"{prefix}.tls_cert_chain_length",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="Certificate chain depth from server",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="Number of certificates in chain",
            ),
            "tls_session_id_len": FeatureMeta(
                id=f"{prefix}.tls_session_id_len",
                dtype="int64",
                shape=[1],
                units="bytes",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="Session ID length from client",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="Length of session ID in ClientHello",
            ),
            "tls_session_ticket_ext": FeatureMeta(
                id=f"{prefix}.tls_session_ticket_ext",
                dtype="bool",
                shape=[1],
                units="",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="Session ticket extension present in ClientHello",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="Whether session ticket extension was present",
            ),
            "tls_session_resumed": FeatureMeta(
                id=f"{prefix}.tls_session_resumed",
                dtype="bool",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="Session resumption detected",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="Whether TLS session was resumed",
            ),
            "tls_psk_ext": FeatureMeta(
                id=f"{prefix}.tls_psk_ext",
                dtype="bool",
                shape=[1],
                units="",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="Pre-shared key extension in ClientHello",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="Whether PSK extension was present (TLS 1.3)",
            ),
            "tls_early_data_ext": FeatureMeta(
                id=f"{prefix}.tls_early_data_ext",
                dtype="bool",
                shape=[1],
                units="",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="Early data (0-RTT) extension in ClientHello",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="Whether early data extension was present (TLS 1.3)",
            ),
            "tls_key_exchange_group": FeatureMeta(
                id=f"{prefix}.tls_key_exchange_group",
                dtype="int64",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="Key exchange group/curve ID",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="Named group ID for key exchange (e.g., x25519)",
            ),
            "tls_key_exchange_group_name": FeatureMeta(
                id=f"{prefix}.tls_key_exchange_group_name",
                dtype="string",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="Human-readable key exchange group name",
                missing_policy="empty",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="Key exchange group name (e.g., 'x25519', 'secp256r1')",
            ),
            "tls_key_exchange_length": FeatureMeta(
                id=f"{prefix}.tls_key_exchange_length",
                dtype="int64",
                shape=[1],
                units="bits",
                scope="flow",
                direction="bidir",
                direction_semantics="Key exchange key size",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp", "tls"],
                privacy_level="safe",
                description="Key exchange public key length in bits",
            ),
        }

        # Build metadata dict for all feature names
        for name in self.feature_names:
            if name in feature_definitions:
                meta[f"{prefix}.{name}"] = feature_definitions[name]

        return meta
