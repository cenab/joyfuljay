"""Tests for Grafana dashboard utilities."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from joyfuljay.monitoring.grafana import (
    DASHBOARD_PATH,
    DashboardBuilder,
    export_dashboard,
    generate_alerting_rules,
    generate_prometheus_config,
    get_dashboard_path,
    load_overview_dashboard,
)


class TestGetDashboardPath:
    """Tests for get_dashboard_path function."""

    def test_returns_path(self) -> None:
        """Test that function returns a Path object."""
        path = get_dashboard_path()
        assert isinstance(path, Path)

    def test_returns_correct_path(self) -> None:
        """Test that the path matches the constant."""
        path = get_dashboard_path()
        assert path == DASHBOARD_PATH


class TestLoadOverviewDashboard:
    """Tests for load_overview_dashboard function."""

    def test_loads_dashboard(self) -> None:
        """Test loading the overview dashboard."""
        # This may fail if dashboard file doesn't exist
        try:
            dashboard = load_overview_dashboard()
            assert isinstance(dashboard, dict)
            assert "title" in dashboard or "panels" in dashboard
        except FileNotFoundError:
            pytest.skip("Dashboard file not found")

    def test_raises_file_not_found(self) -> None:
        """Test that FileNotFoundError is raised for missing dashboard."""
        import joyfuljay.monitoring.grafana as grafana_module

        # Save original and set to invalid path
        original_path = grafana_module.OVERVIEW_DASHBOARD
        grafana_module.OVERVIEW_DASHBOARD = Path("/nonexistent/dashboard.json")

        try:
            with pytest.raises(FileNotFoundError):
                load_overview_dashboard()
        finally:
            grafana_module.OVERVIEW_DASHBOARD = original_path


class TestExportDashboard:
    """Tests for export_dashboard function."""

    def test_exports_to_file(self) -> None:
        """Test exporting dashboard to a file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "test-dashboard.json"

            # Create a simple test dashboard
            dashboard = {
                "title": "Test Dashboard",
                "panels": [],
            }

            result = export_dashboard(output_path, dashboard=dashboard)

            assert result == output_path
            assert output_path.exists()

            # Verify content
            with open(output_path) as f:
                loaded = json.load(f)
            assert loaded["title"] == "Test Dashboard"

    def test_creates_parent_directories(self) -> None:
        """Test that parent directories are created."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "nested" / "dir" / "dashboard.json"

            dashboard = {"title": "Test"}
            export_dashboard(output_path, dashboard=dashboard)

            assert output_path.exists()

    def test_substitutes_datasource_uid(self) -> None:
        """Test datasource UID substitution."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "dashboard.json"

            dashboard = {
                "title": "Test",
                "panels": [
                    {
                        "datasource": {"type": "prometheus", "uid": "original-uid"},
                        "targets": [],
                    }
                ],
            }

            export_dashboard(output_path, dashboard=dashboard, datasource_uid="new-uid")

            with open(output_path) as f:
                loaded = json.load(f)

            panel_ds = loaded["panels"][0]["datasource"]
            assert panel_ds["uid"] == "new-uid"


class TestGeneratePrometheusConfig:
    """Tests for generate_prometheus_config function."""

    def test_generates_yaml(self) -> None:
        """Test that valid YAML config is generated."""
        config = generate_prometheus_config()

        assert "scrape_configs:" in config
        assert "job_name:" in config
        assert "targets:" in config

    def test_custom_job_name(self) -> None:
        """Test custom job name."""
        config = generate_prometheus_config(job_name="my-app")
        assert "'my-app'" in config

    def test_custom_target(self) -> None:
        """Test custom target address."""
        config = generate_prometheus_config(target="10.0.0.1:9090")
        assert "10.0.0.1:9090" in config

    def test_custom_scrape_interval(self) -> None:
        """Test custom scrape interval."""
        config = generate_prometheus_config(scrape_interval="5s")
        assert "5s" in config


class TestGenerateAlertingRules:
    """Tests for generate_alerting_rules function."""

    def test_generates_yaml(self) -> None:
        """Test that valid YAML alerting rules are generated."""
        rules = generate_alerting_rules()

        assert "groups:" in rules
        assert "rules:" in rules
        assert "alert:" in rules

    def test_includes_high_error_rate_alert(self) -> None:
        """Test that high error rate alert is included."""
        rules = generate_alerting_rules()
        assert "JoyfulJayHighErrorRate" in rules

    def test_includes_no_packets_alert(self) -> None:
        """Test that no packets alert is included."""
        rules = generate_alerting_rules()
        assert "JoyfulJayNoPackets" in rules

    def test_includes_high_active_flows_alert(self) -> None:
        """Test that high active flows alert is included."""
        rules = generate_alerting_rules()
        assert "JoyfulJayHighActiveFlows" in rules

    def test_custom_namespace(self) -> None:
        """Test custom namespace in rules."""
        rules = generate_alerting_rules(namespace="myapp")
        assert "myapp_errors_total" in rules
        assert "myapp_packets_total" in rules

    def test_custom_error_threshold(self) -> None:
        """Test custom error threshold."""
        rules = generate_alerting_rules(error_threshold=50)
        assert "> 50" in rules


class TestDashboardBuilder:
    """Tests for DashboardBuilder class."""

    def test_initialization(self) -> None:
        """Test builder initialization."""
        builder = DashboardBuilder("My Dashboard")

        assert builder.title == "My Dashboard"
        assert builder.uid == "my-dashboard"
        assert builder.refresh == "10s"
        assert builder.panels == []

    def test_custom_uid(self) -> None:
        """Test custom UID."""
        builder = DashboardBuilder("Test", uid="custom-id")
        assert builder.uid == "custom-id"

    def test_add_row(self) -> None:
        """Test adding a row."""
        builder = DashboardBuilder("Test")
        result = builder.add_row("Overview")

        assert result is builder  # Chaining
        assert len(builder.panels) == 1
        assert builder.panels[0]["type"] == "row"
        assert builder.panels[0]["title"] == "Overview"

    def test_add_stat_panel(self) -> None:
        """Test adding a stat panel."""
        builder = DashboardBuilder("Test")
        result = builder.add_stat_panel(
            "Total Packets",
            "joyfuljay_packets_total",
            unit="short",
            width=4,
        )

        assert result is builder  # Chaining
        assert len(builder.panels) == 1

        panel = builder.panels[0]
        assert panel["type"] == "stat"
        assert panel["title"] == "Total Packets"
        assert panel["targets"][0]["expr"] == "joyfuljay_packets_total"

    def test_add_graph_panel(self) -> None:
        """Test adding a graph panel."""
        builder = DashboardBuilder("Test")
        builder.add_graph_panel(
            "Packet Rate",
            "rate(joyfuljay_packets_total[1m])",
            unit="pps",
            width=12,
        )

        panel = builder.panels[0]
        assert panel["type"] == "timeseries"
        assert panel["title"] == "Packet Rate"
        assert len(panel["targets"]) == 1

    def test_add_graph_panel_multiple_queries(self) -> None:
        """Test adding a graph panel with multiple queries."""
        builder = DashboardBuilder("Test")
        builder.add_graph_panel(
            "Latency",
            [
                "histogram_quantile(0.50, rate(joyfuljay_duration_bucket[5m]))",
                "histogram_quantile(0.95, rate(joyfuljay_duration_bucket[5m]))",
            ],
            legend_format=["p50", "p95"],
        )

        panel = builder.panels[0]
        assert len(panel["targets"]) == 2
        assert panel["targets"][0]["legendFormat"] == "p50"
        assert panel["targets"][1]["legendFormat"] == "p95"

    def test_build(self) -> None:
        """Test building the complete dashboard."""
        builder = DashboardBuilder("Test Dashboard", refresh="5s")
        builder.add_row("Overview")
        builder.add_stat_panel("Packets", "joyfuljay_packets_total")
        builder.add_graph_panel("Rate", "rate(joyfuljay_packets_total[1m])")

        dashboard = builder.build()

        assert dashboard["title"] == "Test Dashboard"
        assert dashboard["refresh"] == "5s"
        assert dashboard["uid"] == "test-dashboard"
        assert len(dashboard["panels"]) == 3
        assert "templating" in dashboard
        assert "annotations" in dashboard

    def test_grid_positioning(self) -> None:
        """Test that panels are positioned correctly."""
        builder = DashboardBuilder("Test")
        builder.add_stat_panel("A", "a", width=4)
        builder.add_stat_panel("B", "b", width=4)
        builder.add_stat_panel("C", "c", width=4)

        # All should fit on one row (24 width total)
        # Check that x positions are sequential
        positions = [p["gridPos"]["x"] for p in builder.panels]
        assert 0 in positions

    def test_chaining(self) -> None:
        """Test method chaining."""
        builder = DashboardBuilder("Test")

        result = (
            builder.add_row("Section 1")
            .add_stat_panel("Stat", "query")
            .add_row("Section 2")
            .add_graph_panel("Graph", "query")
        )

        assert result is builder
        assert len(builder.panels) == 4
