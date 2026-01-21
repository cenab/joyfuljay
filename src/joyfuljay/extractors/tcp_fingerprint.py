"""TCP fingerprinting feature extractor."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Any

from .base import FeatureExtractor

if TYPE_CHECKING:
    from ..core.flow import Flow
    from ..schema.registry import FeatureMeta


class TCPFingerprintExtractor(FeatureExtractor):
    """Extracts TCP fingerprinting features from flows.

    Features include:
    - JA4T-style fingerprint (TCP fingerprint based on JA4 methodology)
    - OS fingerprint hints from TCP parameters
    - Uptime estimation from timestamps

    Corresponds to Tranalyzer feature #57.
    """

    def extract(self, flow: Flow) -> dict[str, Any]:
        """Extract TCP fingerprinting features from a flow.

        Args:
            flow: The completed flow.

        Returns:
            Dictionary of TCP fingerprint features.
        """
        features: dict[str, Any] = {}

        # Collect SYN packet parameters for fingerprinting
        fwd_syn_params = self._get_syn_params(flow, forward=True)
        bwd_syn_params = self._get_syn_params(flow, forward=False)

        # Generate JA4T-style fingerprints
        features["tcp_fp_fwd"] = self._generate_ja4t(fwd_syn_params) if fwd_syn_params else ""
        features["tcp_fp_bwd"] = self._generate_ja4t(bwd_syn_params) if bwd_syn_params else ""

        # OS hints based on common TTL values and options
        features["tcp_os_hint_fwd"] = self._guess_os(fwd_syn_params) if fwd_syn_params else "unknown"
        features["tcp_os_hint_bwd"] = self._guess_os(bwd_syn_params) if bwd_syn_params else "unknown"

        # Uptime estimation from TCP timestamps
        uptime_fwd, uptime_bwd = self._estimate_uptime(flow)
        features["tcp_uptime_fwd"] = uptime_fwd
        features["tcp_uptime_bwd"] = uptime_bwd

        # Raw fingerprint components for custom analysis
        if fwd_syn_params:
            features["tcp_fp_fwd_window"] = fwd_syn_params.get("window", 0)
            features["tcp_fp_fwd_ttl"] = fwd_syn_params.get("ttl", 0)
            features["tcp_fp_fwd_mss"] = fwd_syn_params.get("mss", 0)
            features["tcp_fp_fwd_ws"] = fwd_syn_params.get("ws", 0)
        else:
            features["tcp_fp_fwd_window"] = 0
            features["tcp_fp_fwd_ttl"] = 0
            features["tcp_fp_fwd_mss"] = 0
            features["tcp_fp_fwd_ws"] = 0

        if bwd_syn_params:
            features["tcp_fp_bwd_window"] = bwd_syn_params.get("window", 0)
            features["tcp_fp_bwd_ttl"] = bwd_syn_params.get("ttl", 0)
            features["tcp_fp_bwd_mss"] = bwd_syn_params.get("mss", 0)
            features["tcp_fp_bwd_ws"] = bwd_syn_params.get("ws", 0)
        else:
            features["tcp_fp_bwd_window"] = 0
            features["tcp_fp_bwd_ttl"] = 0
            features["tcp_fp_bwd_mss"] = 0
            features["tcp_fp_bwd_ws"] = 0

        return features

    def _get_syn_params(
        self, flow: Flow, forward: bool
    ) -> dict[str, Any] | None:
        """Extract TCP parameters from SYN packet.

        Args:
            flow: The flow to analyze.
            forward: Whether to look for forward (True) or backward (False) SYN.

        Returns:
            Dictionary of SYN parameters, or None if not found.
        """
        for pkt in flow.packets:
            if pkt.tcp_flags is None:
                continue

            is_syn = bool(pkt.tcp_flags & 0x02)
            is_ack = bool(pkt.tcp_flags & 0x10)

            is_forward = (
                pkt.src_ip == flow.initiator_ip and pkt.src_port == flow.initiator_port
            )

            # For forward: look for SYN (no ACK)
            # For backward: look for SYN-ACK
            if forward:
                if is_syn and not is_ack and is_forward:
                    return {
                        "window": pkt.tcp_window or 0,
                        "ttl": pkt.ip_ttl or 0,
                        "mss": pkt.tcp_mss or 0,
                        "ws": pkt.tcp_window_scale or 0,
                        "sack": pkt.tcp_sack_permitted,
                        "ts": pkt.tcp_timestamp is not None,
                        "options_raw": pkt.tcp_options_raw,
                    }
            else:
                if is_syn and is_ack and not is_forward:
                    return {
                        "window": pkt.tcp_window or 0,
                        "ttl": pkt.ip_ttl or 0,
                        "mss": pkt.tcp_mss or 0,
                        "ws": pkt.tcp_window_scale or 0,
                        "sack": pkt.tcp_sack_permitted,
                        "ts": pkt.tcp_timestamp is not None,
                        "options_raw": pkt.tcp_options_raw,
                    }

        return None

    def _generate_ja4t(self, params: dict[str, Any]) -> str:
        """Generate a JA4T-style TCP fingerprint.

        JA4T format: window_ttl_mss_ws_options
        where options is a bitmap of TCP options present.

        Args:
            params: SYN packet parameters.

        Returns:
            JA4T fingerprint string.
        """
        window = params.get("window", 0)
        ttl = params.get("ttl", 0)
        mss = params.get("mss", 0)
        ws = params.get("ws", 0)

        # Options bitmap
        # Bit 0: SACK permitted
        # Bit 1: Timestamps
        options = 0
        if params.get("sack"):
            options |= 0x01
        if params.get("ts"):
            options |= 0x02

        # Format: window_ttl_mss_ws_options
        fp_string = f"{window}_{ttl}_{mss}_{ws}_{options}"

        # Generate short hash for compactness
        fp_hash = hashlib.md5(fp_string.encode()).hexdigest()[:12]

        return f"t{window}_{mss}_{ws}_{fp_hash}"

    def _guess_os(self, params: dict[str, Any]) -> str:
        """Attempt to guess OS from TCP parameters.

        This is a simplified heuristic based on common patterns.

        Args:
            params: SYN packet parameters.

        Returns:
            OS guess string.
        """
        ttl = params.get("ttl", 0)
        window = params.get("window", 0)
        mss = params.get("mss", 0)

        # Initial TTL estimation
        if ttl <= 64:
            initial_ttl = 64
        elif ttl <= 128:
            initial_ttl = 128
        else:
            initial_ttl = 255

        # Common OS patterns (simplified)
        # Linux: TTL 64, various windows
        if initial_ttl == 64:
            if window == 29200 or window == 65535:
                return "linux"
            if window == 5840:
                return "linux-old"

        # Windows: TTL 128
        if initial_ttl == 128:
            if window == 65535 or window == 8192:
                return "windows"
            if window == 65520:
                return "windows-10"

        # macOS: TTL 64, window 65535
        if initial_ttl == 64 and window == 65535:
            return "macos"

        # BSD: TTL 255
        if initial_ttl == 255:
            return "bsd"

        return "unknown"

    def _estimate_uptime(self, flow: Flow) -> tuple[float, float]:
        """Estimate host uptime from TCP timestamps.

        Uses the difference between first and last timestamps
        and typical timestamp frequency (100-1000 Hz).

        Args:
            flow: The flow to analyze.

        Returns:
            Tuple of (forward uptime, backward uptime) estimates in hours.
        """
        fwd_first_ts: int | None = None
        bwd_first_ts: int | None = None

        for pkt in flow.packets:
            if pkt.tcp_timestamp is None:
                continue

            ts_val = pkt.tcp_timestamp[0]
            is_forward = (
                pkt.src_ip == flow.initiator_ip and pkt.src_port == flow.initiator_port
            )

            if is_forward and fwd_first_ts is None:
                fwd_first_ts = ts_val
            elif not is_forward and bwd_first_ts is None:
                bwd_first_ts = ts_val

        # Estimate uptime assuming 100 Hz timestamp frequency
        # uptime_seconds = ts_value / frequency
        # Most systems use 100, 250, or 1000 Hz
        freq = 100  # Conservative estimate

        fwd_uptime = (fwd_first_ts / freq / 3600) if fwd_first_ts else 0.0
        bwd_uptime = (bwd_first_ts / freq / 3600) if bwd_first_ts else 0.0

        return fwd_uptime, bwd_uptime

    @property
    def feature_names(self) -> list[str]:
        """Get feature names produced by this extractor."""
        return [
            # Fingerprints
            "tcp_fp_fwd",
            "tcp_fp_bwd",
            # OS hints
            "tcp_os_hint_fwd",
            "tcp_os_hint_bwd",
            # Uptime estimates
            "tcp_uptime_fwd",
            "tcp_uptime_bwd",
            # Raw components - Forward
            "tcp_fp_fwd_window",
            "tcp_fp_fwd_ttl",
            "tcp_fp_fwd_mss",
            "tcp_fp_fwd_ws",
            # Raw components - Backward
            "tcp_fp_bwd_window",
            "tcp_fp_bwd_ttl",
            "tcp_fp_bwd_mss",
            "tcp_fp_bwd_ws",
        ]

    @property
    def extractor_id(self) -> str:
        """Get the stable identifier for this extractor."""
        return "tcp_fingerprint"

    def feature_meta(self) -> dict[str, FeatureMeta]:
        """Get metadata for all features produced by this extractor."""
        from ..schema.registry import FeatureMeta

        meta: dict[str, FeatureMeta] = {}
        prefix = self.extractor_id

        # Define metadata for each feature
        feature_definitions = {
            # Fingerprints
            "tcp_fp_fwd": FeatureMeta(
                id=f"{prefix}.tcp_fp_fwd",
                dtype="string",
                shape=[1],
                units="",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="JA4T-style TCP fingerprint from forward SYN packet",
                missing_policy="empty",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="JA4T-style TCP fingerprint for forward direction (from SYN)",
            ),
            "tcp_fp_bwd": FeatureMeta(
                id=f"{prefix}.tcp_fp_bwd",
                dtype="string",
                shape=[1],
                units="",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="JA4T-style TCP fingerprint from backward SYN-ACK packet",
                missing_policy="empty",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="JA4T-style TCP fingerprint for backward direction (from SYN-ACK)",
            ),
            # OS hints
            "tcp_os_hint_fwd": FeatureMeta(
                id=f"{prefix}.tcp_os_hint_fwd",
                dtype="string",
                shape=[1],
                units="",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="OS guess based on forward SYN TCP parameters",
                missing_policy="sentinel",
                missing_sentinel="unknown",
                dependencies=["tcp"],
                privacy_level="sensitive",
                description="Operating system hint inferred from forward TCP parameters",
            ),
            "tcp_os_hint_bwd": FeatureMeta(
                id=f"{prefix}.tcp_os_hint_bwd",
                dtype="string",
                shape=[1],
                units="",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="OS guess based on backward SYN-ACK TCP parameters",
                missing_policy="sentinel",
                missing_sentinel="unknown",
                dependencies=["tcp"],
                privacy_level="sensitive",
                description="Operating system hint inferred from backward TCP parameters",
            ),
            # Uptime estimates
            "tcp_uptime_fwd": FeatureMeta(
                id=f"{prefix}.tcp_uptime_fwd",
                dtype="float64",
                shape=[1],
                units="hours",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="Estimated uptime of forward host from TCP timestamps",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="sensitive",
                description="Estimated uptime of initiator host in hours (from TCP timestamps)",
            ),
            "tcp_uptime_bwd": FeatureMeta(
                id=f"{prefix}.tcp_uptime_bwd",
                dtype="float64",
                shape=[1],
                units="hours",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="Estimated uptime of backward host from TCP timestamps",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="sensitive",
                description="Estimated uptime of responder host in hours (from TCP timestamps)",
            ),
            # Raw components - Forward
            "tcp_fp_fwd_window": FeatureMeta(
                id=f"{prefix}.tcp_fp_fwd_window",
                dtype="int64",
                shape=[1],
                units="bytes",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="TCP window size from forward SYN packet",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="TCP window size from forward SYN packet",
            ),
            "tcp_fp_fwd_ttl": FeatureMeta(
                id=f"{prefix}.tcp_fp_fwd_ttl",
                dtype="int64",
                shape=[1],
                units="hops",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="IP TTL from forward SYN packet",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="IP TTL value from forward SYN packet",
            ),
            "tcp_fp_fwd_mss": FeatureMeta(
                id=f"{prefix}.tcp_fp_fwd_mss",
                dtype="int64",
                shape=[1],
                units="bytes",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="TCP MSS option from forward SYN packet",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="TCP Maximum Segment Size from forward SYN packet",
            ),
            "tcp_fp_fwd_ws": FeatureMeta(
                id=f"{prefix}.tcp_fp_fwd_ws",
                dtype="int64",
                shape=[1],
                units="",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="TCP window scale option from forward SYN packet",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="TCP window scale factor from forward SYN packet",
            ),
            # Raw components - Backward
            "tcp_fp_bwd_window": FeatureMeta(
                id=f"{prefix}.tcp_fp_bwd_window",
                dtype="int64",
                shape=[1],
                units="bytes",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="TCP window size from backward SYN-ACK packet",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="TCP window size from backward SYN-ACK packet",
            ),
            "tcp_fp_bwd_ttl": FeatureMeta(
                id=f"{prefix}.tcp_fp_bwd_ttl",
                dtype="int64",
                shape=[1],
                units="hops",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="IP TTL from backward SYN-ACK packet",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="IP TTL value from backward SYN-ACK packet",
            ),
            "tcp_fp_bwd_mss": FeatureMeta(
                id=f"{prefix}.tcp_fp_bwd_mss",
                dtype="int64",
                shape=[1],
                units="bytes",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="TCP MSS option from backward SYN-ACK packet",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="TCP Maximum Segment Size from backward SYN-ACK packet",
            ),
            "tcp_fp_bwd_ws": FeatureMeta(
                id=f"{prefix}.tcp_fp_bwd_ws",
                dtype="int64",
                shape=[1],
                units="",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="TCP window scale option from backward SYN-ACK packet",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="TCP window scale factor from backward SYN-ACK packet",
            ),
        }

        # Only include metadata for features we actually produce
        for name in self.feature_names:
            if name in feature_definitions:
                meta[f"{prefix}.{name}"] = feature_definitions[name]

        return meta

    @property
    def name(self) -> str:
        """Get the extractor name."""
        return "tcp_fingerprint"
