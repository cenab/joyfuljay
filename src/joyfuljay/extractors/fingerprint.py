"""Traffic pattern fingerprinting feature extractor."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .base import FeatureExtractor

if TYPE_CHECKING:
    from ..core.flow import Flow
    from ..schema.registry import FeatureMeta

# Known DoH server SNIs
DOH_PROVIDERS = {
    "cloudflare-dns.com",
    "dns.google",
    "dns.google.com",
    "doh.opendns.com",
    "dns.quad9.net",
    "doh.cleanbrowsing.org",
    "dns.adguard.com",
    "doh.dns.sb",
    "dns.nextdns.io",
}

# Known Tor JA3 fingerprints (partial list, these change over time)
TOR_JA3_PATTERNS = {
    # Tor Browser common fingerprints - these are examples
    "e7d705a3286e19ea42f587b344ee6865",
    "a0e9f5d64349fb13191bc781f81f42e1",
}


class FingerprintExtractor(FeatureExtractor):
    """Extracts traffic pattern fingerprinting features.

    Classifies traffic based on behavioral patterns:
    - Tor detection (JA3 + packet patterns)
    - VPN detection (protocol patterns)
    - DoH detection (DNS over HTTPS)
    """

    def __init__(
        self,
        detect_tor: bool = True,
        detect_vpn: bool = True,
        detect_doh: bool = True,
    ) -> None:
        """Initialize the fingerprint extractor.

        Args:
            detect_tor: Whether to detect Tor traffic.
            detect_vpn: Whether to detect VPN traffic.
            detect_doh: Whether to detect DoH traffic.
        """
        self.detect_tor = detect_tor
        self.detect_vpn = detect_vpn
        self.detect_doh = detect_doh

    def extract(self, flow: Flow) -> dict[str, Any]:
        """Extract fingerprinting features from a flow.

        Args:
            flow: The completed flow.

        Returns:
            Dictionary of fingerprint features.
        """
        features: dict[str, Any] = {
            "likely_tor": False,
            "tor_confidence": 0.0,
            "likely_vpn": False,
            "vpn_confidence": 0.0,
            "vpn_type": "",
            "likely_doh": False,
            "doh_confidence": 0.0,
            "traffic_type": "unknown",
        }

        if self.detect_tor:
            self._detect_tor(flow, features)

        if self.detect_vpn:
            self._detect_vpn(flow, features)

        if self.detect_doh:
            self._detect_doh(flow, features)

        # Determine overall traffic type
        features["traffic_type"] = self._determine_traffic_type(features)

        return features

    def _detect_tor(self, flow: Flow, features: dict[str, Any]) -> None:
        """Detect Tor traffic patterns."""
        confidence = 0.0

        # Check packet sizes for Tor cell pattern
        sizes = [p.total_len for p in flow.packets]
        tor_size_count = sum(1 for s in sizes if 580 <= s <= 600)
        if sizes:
            tor_ratio = tor_size_count / len(sizes)
            if tor_ratio > 0.7:
                confidence += 0.4

        # Check for uniform packet sizes (low variance)
        if sizes:
            import numpy as np

            cv = np.std(sizes) / np.mean(sizes) if np.mean(sizes) > 0 else 1.0
            if cv < 0.1:
                confidence += 0.3

        # Check destination ports (Tor commonly uses 443, 9001, 9030)
        tor_ports = {443, 9001, 9030, 9050, 9051}
        if flow.responder_port in tor_ports:
            confidence += 0.1

        # Check TLS metadata if available
        if hasattr(flow, "tls_client_hello") and flow.tls_client_hello:
            # Could check JA3 here if we had it computed
            pass

        features["tor_confidence"] = min(confidence, 1.0)
        features["likely_tor"] = confidence >= 0.5

    def _detect_vpn(self, flow: Flow, features: dict[str, Any]) -> None:
        """Detect VPN traffic patterns."""
        confidence = 0.0
        vpn_type = ""

        # OpenVPN detection (UDP port 1194 or TCP 443 with specific patterns)
        if flow.key.protocol == 17:  # UDP
            if flow.responder_port == 1194 or flow.initiator_port == 1194:
                confidence += 0.5
                vpn_type = "openvpn"

            # WireGuard detection (UDP, port 51820 default)
            if flow.responder_port == 51820:
                confidence += 0.5
                vpn_type = "wireguard"

        # IPSec detection
        if flow.key.protocol == 50:  # ESP
            confidence += 0.7
            vpn_type = "ipsec-esp"
        elif flow.key.protocol == 51:  # AH
            confidence += 0.7
            vpn_type = "ipsec-ah"

        # Check for IKE (UDP 500, 4500)
        if flow.key.protocol == 17:
            if flow.responder_port in {500, 4500}:
                confidence += 0.4
                vpn_type = "ipsec-ike"

        # Check for L2TP (UDP 1701)
        if flow.key.protocol == 17 and flow.responder_port == 1701:
            confidence += 0.4
            vpn_type = "l2tp"

        # Packet size patterns for VPN (often near MTU)
        sizes = [p.total_len for p in flow.packets]
        if sizes:
            import numpy as np

            # Many VPN packets are close to MTU
            large_count = sum(1 for s in sizes if 1400 <= s <= 1500)
            if large_count / len(sizes) > 0.5:
                confidence += 0.2

        features["vpn_confidence"] = min(confidence, 1.0)
        features["likely_vpn"] = confidence >= 0.4
        features["vpn_type"] = vpn_type

    def _detect_doh(self, flow: Flow, features: dict[str, Any]) -> None:
        """Detect DNS over HTTPS traffic patterns.

        DoH detection is now more conservative to reduce false positives.
        Primary signals are:
        1. SNI matching known DoH providers (strong signal)
        2. Specific packet size patterns for DNS queries/responses
        3. Very specific flow characteristics
        """
        confidence = 0.0
        sni_matched = False

        # Must be TCP 443 (HTTPS)
        if flow.key.protocol != 6 or flow.responder_port != 443:
            return

        # Check SNI against known DoH providers (strongest signal)
        if hasattr(flow, "tls_sni") and flow.tls_sni:
            sni = flow.tls_sni.lower()
            for provider in DOH_PROVIDERS:
                if provider in sni or sni.endswith(provider):
                    confidence += 0.6
                    sni_matched = True
                    break

        # If no SNI match, apply stricter behavioral checks
        initiator_sizes = [p.total_len for p in flow.initiator_packets]
        responder_sizes = [p.total_len for p in flow.responder_packets]

        # Require very specific packet count pattern for DoH
        # Typical DoH: TLS handshake (3-5 pkts each way) + 1-2 query/response
        initiator_count = len(flow.initiator_packets)
        responder_count = len(flow.responder_packets)

        if not sni_matched:
            # Without SNI, require extremely strict criteria

            # Must be very short flow (< 15 packets total)
            if len(flow.packets) > 15:
                return

            # Must have balanced packet count (not a bulk transfer)
            if initiator_count < 2 or responder_count < 2:
                return
            if abs(initiator_count - responder_count) > 3:
                return

            # Check for DNS-like payload sizes
            # DoH query: typically 100-512 bytes (with HTTP/2 framing)
            # DoH response: typically 200-1500 bytes
            if initiator_sizes and responder_sizes:
                max_req_payload = max(initiator_sizes) if initiator_sizes else 0
                total_req_bytes = sum(initiator_sizes)
                total_resp_bytes = sum(responder_sizes)

                # Request should be small
                if max_req_payload > 600:
                    return

                # Total request bytes should be small
                if total_req_bytes > 2000:
                    return

                # Response should be moderate (not a file download)
                if total_resp_bytes > 5000:
                    return

                # Response/request ratio typical for DNS
                if total_req_bytes > 0:
                    ratio = total_resp_bytes / total_req_bytes
                    if 0.5 < ratio < 10:
                        confidence += 0.15

            # Very quick exchange (under 500ms for a single query)
            if flow.duration < 0.5:
                confidence += 0.15

            # Few packets characteristic
            if initiator_count <= 6 and responder_count <= 6:
                confidence += 0.1
        else:
            # With SNI match, add supporting signals
            if flow.duration < 1.0:
                confidence += 0.1

            if len(flow.packets) < 20:
                confidence += 0.1

        # Clamp confidence and set threshold
        features["doh_confidence"] = min(confidence, 1.0)
        # Require SNI match or very high behavioral confidence
        features["likely_doh"] = sni_matched or confidence >= 0.35

    def _determine_traffic_type(self, features: dict[str, Any]) -> str:
        """Determine overall traffic type classification."""
        if features.get("likely_tor"):
            return "tor"
        if features.get("likely_vpn"):
            vpn_type = features.get("vpn_type", "")
            return f"vpn:{vpn_type}" if vpn_type else "vpn"
        if features.get("likely_doh"):
            return "doh"
        return "encrypted"

    @property
    def feature_names(self) -> list[str]:
        """Get feature names produced by this extractor."""
        return [
            "likely_tor",
            "tor_confidence",
            "likely_vpn",
            "vpn_confidence",
            "vpn_type",
            "likely_doh",
            "doh_confidence",
            "traffic_type",
        ]

    @property
    def extractor_id(self) -> str:
        """Get the stable identifier for this extractor."""
        return "fingerprint"

    def feature_meta(self) -> dict[str, FeatureMeta]:
        """Get metadata for all features produced by this extractor."""
        from ..schema.registry import FeatureMeta

        prefix = self.extractor_id

        meta: dict[str, FeatureMeta] = {
            f"{prefix}.likely_tor": FeatureMeta(
                id=f"{prefix}.likely_tor",
                dtype="bool",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="Bidirectional Tor detection flag",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Whether flow is likely Tor traffic based on packet patterns",
            ),
            f"{prefix}.tor_confidence": FeatureMeta(
                id=f"{prefix}.tor_confidence",
                dtype="float64",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="Bidirectional Tor detection confidence",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Confidence score (0-1) for Tor traffic detection",
            ),
            f"{prefix}.likely_vpn": FeatureMeta(
                id=f"{prefix}.likely_vpn",
                dtype="bool",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="Bidirectional VPN detection flag",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Whether flow is likely VPN traffic based on protocol patterns",
            ),
            f"{prefix}.vpn_confidence": FeatureMeta(
                id=f"{prefix}.vpn_confidence",
                dtype="float64",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="Bidirectional VPN detection confidence",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Confidence score (0-1) for VPN traffic detection",
            ),
            f"{prefix}.vpn_type": FeatureMeta(
                id=f"{prefix}.vpn_type",
                dtype="string",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="Detected VPN protocol type",
                missing_policy="empty",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="VPN type if detected (openvpn, wireguard, ipsec-esp, ipsec-ah, ipsec-ike, l2tp)",
            ),
            f"{prefix}.likely_doh": FeatureMeta(
                id=f"{prefix}.likely_doh",
                dtype="bool",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="Bidirectional DoH detection flag",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Whether flow is likely DNS over HTTPS traffic",
            ),
            f"{prefix}.doh_confidence": FeatureMeta(
                id=f"{prefix}.doh_confidence",
                dtype="float64",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="Bidirectional DoH detection confidence",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Confidence score (0-1) for DoH traffic detection",
            ),
            f"{prefix}.traffic_type": FeatureMeta(
                id=f"{prefix}.traffic_type",
                dtype="string",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="Overall traffic classification",
                missing_policy="empty",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Traffic type classification (tor, vpn:*, doh, encrypted, unknown)",
            ),
        }

        return meta
