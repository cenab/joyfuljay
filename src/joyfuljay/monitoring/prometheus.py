"""Prometheus metrics for JoyfulJay processing."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from prometheus_client import CollectorRegistry
    from ..core.flow import Flow
    from ..core.packet import Packet

from .base import MetricsSink


class PrometheusMetrics(MetricsSink):
    """Prometheus-backed metrics sink."""

    def __init__(
        self,
        namespace: str = "joyfuljay",
        registry: "CollectorRegistry | None" = None,
    ) -> None:
        """Initialize Prometheus metrics.

        Args:
            namespace: Metric namespace prefix.
            registry: Optional CollectorRegistry for isolated metrics.
        """
        try:
            from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram
        except ImportError as exc:
            raise ImportError(
                "Prometheus metrics require prometheus-client. "
                "Install with: pip install prometheus-client"
            ) from exc

        self.registry = registry or CollectorRegistry()

        self.packets_total = Counter(
            "packets_total",
            "Total packets processed",
            namespace=namespace,
            registry=self.registry,
        )
        self.bytes_total = Counter(
            "bytes_total",
            "Total bytes processed",
            namespace=namespace,
            registry=self.registry,
        )
        self.flows_total = Counter(
            "flows_total",
            "Total flows processed",
            ["reason"],
            namespace=namespace,
            registry=self.registry,
        )
        self.errors_total = Counter(
            "errors_total",
            "Total errors by stage",
            ["stage"],
            namespace=namespace,
            registry=self.registry,
        )
        self.processing_seconds = Histogram(
            "processing_duration_seconds",
            "Processing duration in seconds",
            ["mode"],
            namespace=namespace,
            registry=self.registry,
        )
        self.active_flows = Gauge(
            "active_flows",
            "Current active flows",
            namespace=namespace,
            registry=self.registry,
        )

    def observe_packet(self, packet: "Packet") -> None:
        self.packets_total.inc()
        self.bytes_total.inc(packet.total_len)

    def observe_flow(self, flow: "Flow", reason: str) -> None:
        self.flows_total.labels(reason=reason).inc()

    def observe_processing_time(self, mode: str, seconds: float) -> None:
        self.processing_seconds.labels(mode=mode).observe(seconds)

    def observe_error(self, stage: str, error: Exception | None = None) -> None:
        self.errors_total.labels(stage=stage).inc()

    def set_active_flows(self, count: int) -> None:
        self.active_flows.set(count)


def start_prometheus_server(
    port: int,
    addr: str = "0.0.0.0",
    registry: "CollectorRegistry | None" = None,
) -> None:
    """Start a Prometheus HTTP metrics server."""
    try:
        from prometheus_client import start_http_server
    except ImportError as exc:
        raise ImportError(
            "Prometheus metrics require prometheus-client. "
            "Install with: pip install prometheus-client"
        ) from exc

    if registry is None:
        start_http_server(port, addr=addr)
    else:
        start_http_server(port, addr=addr, registry=registry)
