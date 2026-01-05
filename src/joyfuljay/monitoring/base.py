"""Metrics sink interfaces."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from ..core.flow import Flow
    from ..core.packet import Packet


@runtime_checkable
class MetricsSink(Protocol):
    """Protocol for metrics sinks used by the pipeline."""

    def observe_packet(self, packet: "Packet") -> None:
        """Record a processed packet."""

    def observe_flow(self, flow: "Flow", reason: str) -> None:
        """Record a completed flow with a reason label."""

    def observe_processing_time(self, mode: str, seconds: float) -> None:
        """Record total processing time for a run."""

    def observe_error(self, stage: str, error: Exception | None = None) -> None:
        """Record an error from a pipeline stage."""

    def set_active_flows(self, count: int) -> None:
        """Record number of active flows."""
