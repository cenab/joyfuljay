"""Tests for Prometheus metrics integration."""

from __future__ import annotations

import pytest

prometheus_client = pytest.importorskip("prometheus_client")

from prometheus_client import CollectorRegistry, generate_latest

from joyfuljay.core.packet import Packet
from joyfuljay.monitoring.prometheus import PrometheusMetrics


def test_prometheus_metrics_counters() -> None:
    registry = CollectorRegistry()
    metrics = PrometheusMetrics(registry=registry)

    packet = Packet(
        timestamp=1.0,
        src_ip="1.1.1.1",
        dst_ip="2.2.2.2",
        src_port=1234,
        dst_port=443,
        protocol=6,
        payload_len=10,
        total_len=42,
    )

    metrics.observe_packet(packet)
    metrics.observe_flow(object(), "completed")
    metrics.observe_processing_time("pcap", 1.5)
    metrics.set_active_flows(3)

    output = generate_latest(registry).decode("utf-8")

    assert "joyfuljay_packets_total 1.0" in output
    assert "joyfuljay_bytes_total 42.0" in output
    assert 'joyfuljay_flows_total{reason="completed"} 1.0' in output
    assert "joyfuljay_active_flows 3.0" in output
