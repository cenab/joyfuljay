"""TCP window analysis feature extractor."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .base import FeatureExtractor

if TYPE_CHECKING:
    from ..core.flow import Flow
    from ..schema.registry import FeatureMeta


class TCPWindowExtractor(FeatureExtractor):
    """Extracts TCP window analysis features from flows.

    Features include:
    - Initial window size
    - Window size statistics (min, max, avg)
    - Window size changes
    - Zero window events
    - Bytes in flight estimation

    Corresponds to Tranalyzer feature #52.
    """

    def extract(self, flow: Flow) -> dict[str, Any]:
        """Extract TCP window analysis features from a flow.

        Args:
            flow: The completed flow.

        Returns:
            Dictionary of TCP window features.
        """
        features: dict[str, Any] = {}

        # Collect window sizes by direction
        fwd_windows: list[int] = []
        bwd_windows: list[int] = []

        fwd_init_window: int | None = None
        bwd_init_window: int | None = None

        # Track window scale factors
        fwd_ws: int | None = None
        bwd_ws: int | None = None

        for pkt in flow.packets:
            if pkt.tcp_window is None:
                continue

            is_forward = (
                pkt.src_ip == flow.initiator_ip and pkt.src_port == flow.initiator_port
            )

            if is_forward:
                fwd_windows.append(pkt.tcp_window)
                if fwd_init_window is None:
                    fwd_init_window = pkt.tcp_window
                if pkt.tcp_window_scale is not None and fwd_ws is None:
                    fwd_ws = pkt.tcp_window_scale
            else:
                bwd_windows.append(pkt.tcp_window)
                if bwd_init_window is None:
                    bwd_init_window = pkt.tcp_window
                if pkt.tcp_window_scale is not None and bwd_ws is None:
                    bwd_ws = pkt.tcp_window_scale

        # Initial window sizes
        features["tcp_init_win_fwd"] = fwd_init_window if fwd_init_window is not None else 0
        features["tcp_init_win_bwd"] = bwd_init_window if bwd_init_window is not None else 0

        # Window scale factors
        features["tcp_win_scale_fwd"] = fwd_ws if fwd_ws is not None else 0
        features["tcp_win_scale_bwd"] = bwd_ws if bwd_ws is not None else 0

        # Forward window statistics
        if fwd_windows:
            features["tcp_win_fwd_min"] = min(fwd_windows)
            features["tcp_win_fwd_max"] = max(fwd_windows)
            features["tcp_win_fwd_mean"] = sum(fwd_windows) / len(fwd_windows)
            features["tcp_win_fwd_zero_count"] = sum(1 for w in fwd_windows if w == 0)
        else:
            features["tcp_win_fwd_min"] = 0
            features["tcp_win_fwd_max"] = 0
            features["tcp_win_fwd_mean"] = 0.0
            features["tcp_win_fwd_zero_count"] = 0

        # Backward window statistics
        if bwd_windows:
            features["tcp_win_bwd_min"] = min(bwd_windows)
            features["tcp_win_bwd_max"] = max(bwd_windows)
            features["tcp_win_bwd_mean"] = sum(bwd_windows) / len(bwd_windows)
            features["tcp_win_bwd_zero_count"] = sum(1 for w in bwd_windows if w == 0)
        else:
            features["tcp_win_bwd_min"] = 0
            features["tcp_win_bwd_max"] = 0
            features["tcp_win_bwd_mean"] = 0.0
            features["tcp_win_bwd_zero_count"] = 0

        # Window size change analysis - Forward
        fwd_changes = self._analyze_window_changes(fwd_windows)
        features["tcp_win_fwd_up_count"] = fwd_changes["up_count"]
        features["tcp_win_fwd_down_count"] = fwd_changes["down_count"]
        features["tcp_win_fwd_change_count"] = fwd_changes["change_count"]

        # Window size change analysis - Backward
        bwd_changes = self._analyze_window_changes(bwd_windows)
        features["tcp_win_bwd_up_count"] = bwd_changes["up_count"]
        features["tcp_win_bwd_down_count"] = bwd_changes["down_count"]
        features["tcp_win_bwd_change_count"] = bwd_changes["change_count"]

        # Scaled window sizes (actual receive buffer)
        if fwd_windows and fwd_ws is not None:
            scale_factor = 1 << fwd_ws
            features["tcp_scaled_win_fwd_max"] = max(fwd_windows) * scale_factor
        else:
            features["tcp_scaled_win_fwd_max"] = features["tcp_win_fwd_max"]

        if bwd_windows and bwd_ws is not None:
            scale_factor = 1 << bwd_ws
            features["tcp_scaled_win_bwd_max"] = max(bwd_windows) * scale_factor
        else:
            features["tcp_scaled_win_bwd_max"] = features["tcp_win_bwd_max"]

        # Zero window ratio
        total_windows = len(fwd_windows) + len(bwd_windows)
        total_zero = features["tcp_win_fwd_zero_count"] + features["tcp_win_bwd_zero_count"]
        features["tcp_zero_win_ratio"] = total_zero / total_windows if total_windows > 0 else 0.0

        return features

    def _analyze_window_changes(self, windows: list[int]) -> dict[str, int]:
        """Analyze window size changes.

        Args:
            windows: List of window sizes in order.

        Returns:
            Dictionary with change analysis.
        """
        if len(windows) < 2:
            return {"up_count": 0, "down_count": 0, "change_count": 0}

        up_count = 0
        down_count = 0

        for i in range(1, len(windows)):
            if windows[i] > windows[i - 1]:
                up_count += 1
            elif windows[i] < windows[i - 1]:
                down_count += 1

        return {
            "up_count": up_count,
            "down_count": down_count,
            "change_count": up_count + down_count,
        }

    @property
    def feature_names(self) -> list[str]:
        """Get feature names produced by this extractor."""
        return [
            # Initial windows
            "tcp_init_win_fwd",
            "tcp_init_win_bwd",
            # Window scale factors
            "tcp_win_scale_fwd",
            "tcp_win_scale_bwd",
            # Forward window stats
            "tcp_win_fwd_min",
            "tcp_win_fwd_max",
            "tcp_win_fwd_mean",
            "tcp_win_fwd_zero_count",
            # Backward window stats
            "tcp_win_bwd_min",
            "tcp_win_bwd_max",
            "tcp_win_bwd_mean",
            "tcp_win_bwd_zero_count",
            # Forward changes
            "tcp_win_fwd_up_count",
            "tcp_win_fwd_down_count",
            "tcp_win_fwd_change_count",
            # Backward changes
            "tcp_win_bwd_up_count",
            "tcp_win_bwd_down_count",
            "tcp_win_bwd_change_count",
            # Scaled windows
            "tcp_scaled_win_fwd_max",
            "tcp_scaled_win_bwd_max",
            # Ratios
            "tcp_zero_win_ratio",
        ]

    @property
    def extractor_id(self) -> str:
        """Return the unique identifier for this extractor."""
        return "tcp_window"

    def feature_meta(self) -> dict[str, FeatureMeta]:
        """Return metadata for all features produced by this extractor.

        Returns:
            Dictionary mapping feature IDs to their FeatureMeta objects.
        """
        from ..schema.registry import FeatureMeta

        return {
            "tcp_window.tcp_init_win_fwd": FeatureMeta(
                id="tcp_window.tcp_init_win_fwd",
                dtype="int64",
                shape=[1],
                units="bytes",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="Initial TCP window size from initiator",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Initial TCP window size advertised by the flow initiator",
            ),
            "tcp_window.tcp_init_win_bwd": FeatureMeta(
                id="tcp_window.tcp_init_win_bwd",
                dtype="int64",
                shape=[1],
                units="bytes",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="Initial TCP window size from responder",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Initial TCP window size advertised by the flow responder",
            ),
            "tcp_window.tcp_win_scale_fwd": FeatureMeta(
                id="tcp_window.tcp_win_scale_fwd",
                dtype="int64",
                shape=[1],
                units="",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="TCP window scale factor from initiator",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="TCP window scale factor advertised by the flow initiator",
            ),
            "tcp_window.tcp_win_scale_bwd": FeatureMeta(
                id="tcp_window.tcp_win_scale_bwd",
                dtype="int64",
                shape=[1],
                units="",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="TCP window scale factor from responder",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="TCP window scale factor advertised by the flow responder",
            ),
            "tcp_window.tcp_win_fwd_min": FeatureMeta(
                id="tcp_window.tcp_win_fwd_min",
                dtype="int64",
                shape=[1],
                units="bytes",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="Minimum TCP window size from initiator",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Minimum TCP window size observed from the flow initiator",
            ),
            "tcp_window.tcp_win_fwd_max": FeatureMeta(
                id="tcp_window.tcp_win_fwd_max",
                dtype="int64",
                shape=[1],
                units="bytes",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="Maximum TCP window size from initiator",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Maximum TCP window size observed from the flow initiator",
            ),
            "tcp_window.tcp_win_fwd_mean": FeatureMeta(
                id="tcp_window.tcp_win_fwd_mean",
                dtype="float64",
                shape=[1],
                units="bytes",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="Mean TCP window size from initiator",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Mean TCP window size observed from the flow initiator",
            ),
            "tcp_window.tcp_win_fwd_zero_count": FeatureMeta(
                id="tcp_window.tcp_win_fwd_zero_count",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="Count of zero window packets from initiator",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Number of packets with zero window size from the flow initiator",
            ),
            "tcp_window.tcp_win_bwd_min": FeatureMeta(
                id="tcp_window.tcp_win_bwd_min",
                dtype="int64",
                shape=[1],
                units="bytes",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="Minimum TCP window size from responder",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Minimum TCP window size observed from the flow responder",
            ),
            "tcp_window.tcp_win_bwd_max": FeatureMeta(
                id="tcp_window.tcp_win_bwd_max",
                dtype="int64",
                shape=[1],
                units="bytes",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="Maximum TCP window size from responder",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Maximum TCP window size observed from the flow responder",
            ),
            "tcp_window.tcp_win_bwd_mean": FeatureMeta(
                id="tcp_window.tcp_win_bwd_mean",
                dtype="float64",
                shape=[1],
                units="bytes",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="Mean TCP window size from responder",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Mean TCP window size observed from the flow responder",
            ),
            "tcp_window.tcp_win_bwd_zero_count": FeatureMeta(
                id="tcp_window.tcp_win_bwd_zero_count",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="Count of zero window packets from responder",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Number of packets with zero window size from the flow responder",
            ),
            "tcp_window.tcp_win_fwd_up_count": FeatureMeta(
                id="tcp_window.tcp_win_fwd_up_count",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="Count of window size increases from initiator",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Number of times window size increased from the flow initiator",
            ),
            "tcp_window.tcp_win_fwd_down_count": FeatureMeta(
                id="tcp_window.tcp_win_fwd_down_count",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="Count of window size decreases from initiator",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Number of times window size decreased from the flow initiator",
            ),
            "tcp_window.tcp_win_fwd_change_count": FeatureMeta(
                id="tcp_window.tcp_win_fwd_change_count",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="Total count of window size changes from initiator",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Total number of window size changes from the flow initiator",
            ),
            "tcp_window.tcp_win_bwd_up_count": FeatureMeta(
                id="tcp_window.tcp_win_bwd_up_count",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="Count of window size increases from responder",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Number of times window size increased from the flow responder",
            ),
            "tcp_window.tcp_win_bwd_down_count": FeatureMeta(
                id="tcp_window.tcp_win_bwd_down_count",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="Count of window size decreases from responder",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Number of times window size decreased from the flow responder",
            ),
            "tcp_window.tcp_win_bwd_change_count": FeatureMeta(
                id="tcp_window.tcp_win_bwd_change_count",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="Total count of window size changes from responder",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Total number of window size changes from the flow responder",
            ),
            "tcp_window.tcp_scaled_win_fwd_max": FeatureMeta(
                id="tcp_window.tcp_scaled_win_fwd_max",
                dtype="int64",
                shape=[1],
                units="bytes",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="Maximum scaled TCP window size from initiator",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Maximum TCP window size with scale factor applied from the flow initiator",
            ),
            "tcp_window.tcp_scaled_win_bwd_max": FeatureMeta(
                id="tcp_window.tcp_scaled_win_bwd_max",
                dtype="int64",
                shape=[1],
                units="bytes",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="Maximum scaled TCP window size from responder",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Maximum TCP window size with scale factor applied from the flow responder",
            ),
            "tcp_window.tcp_zero_win_ratio": FeatureMeta(
                id="tcp_window.tcp_zero_win_ratio",
                dtype="float64",
                shape=[1],
                units="ratio",
                scope="flow",
                direction="bidir",
                direction_semantics="Ratio of zero window packets to total window packets",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Ratio of zero window packets to total packets with window information",
            ),
        }

    @property
    def name(self) -> str:
        """Get the extractor name."""
        return "tcp_window"
