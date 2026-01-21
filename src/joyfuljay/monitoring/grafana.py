"""Grafana dashboard utilities for JoyfulJay."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

# Path to bundled dashboard (repo root /dashboards)
DASHBOARD_PATH = Path(__file__).resolve().parents[3] / "dashboards"
OVERVIEW_DASHBOARD = DASHBOARD_PATH / "joyfuljay-overview.json"


def get_dashboard_path() -> Path:
    """Get the path to the bundled dashboards directory.

    Returns:
        Path to the dashboards directory.
    """
    return DASHBOARD_PATH


def load_overview_dashboard() -> dict[str, Any]:
    """Load the JoyfulJay overview dashboard.

    Returns:
        Dashboard JSON as a dictionary.

    Raises:
        FileNotFoundError: If the dashboard file is not found.
    """
    if not OVERVIEW_DASHBOARD.exists():
        raise FileNotFoundError(
            f"Dashboard not found at {OVERVIEW_DASHBOARD}. "
            "Ensure the dashboards directory is included in your installation."
        )

    with open(OVERVIEW_DASHBOARD, encoding="utf-8") as f:
        return cast(dict[str, Any], json.load(f))


def export_dashboard(
    output_path: str | Path,
    dashboard: dict[str, Any] | None = None,
    datasource_uid: str | None = None,
) -> Path:
    """Export a dashboard to a file.

    Args:
        output_path: Path to write the dashboard JSON.
        dashboard: Dashboard dict to export. Defaults to overview dashboard.
        datasource_uid: Optional datasource UID to substitute.

    Returns:
        Path to the exported file.
    """
    if dashboard is None:
        dashboard = load_overview_dashboard()

    # Make a copy to avoid modifying the original
    dashboard = json.loads(json.dumps(dashboard))

    # Substitute datasource UID if provided
    if datasource_uid:
        dashboard = _substitute_datasource(dashboard, datasource_uid)

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(dashboard, f, indent=2)

    return output_path


def _substitute_datasource(dashboard: dict[str, Any], uid: str) -> dict[str, Any]:
    """Recursively substitute datasource UIDs in a dashboard.

    Args:
        dashboard: Dashboard dictionary.
        uid: New datasource UID to use.

    Returns:
        Modified dashboard dictionary.
    """

    def _replace(obj: Any) -> Any:
        if isinstance(obj, dict):
            result = {}
            for key, value in obj.items():
                if key == "datasource" and isinstance(value, dict):
                    if value.get("type") == "prometheus":
                        result[key] = {"type": "prometheus", "uid": uid}
                    else:
                        result[key] = _replace(value)
                else:
                    result[key] = _replace(value)
            return result
        elif isinstance(obj, list):
            return [_replace(item) for item in obj]
        else:
            return obj

    return cast(dict[str, Any], _replace(dashboard))


def generate_prometheus_config(
    job_name: str = "joyfuljay",
    target: str = "localhost:9090",
    scrape_interval: str = "15s",
) -> str:
    """Generate a Prometheus scrape config for JoyfulJay.

    Args:
        job_name: Name for the scrape job.
        target: Target address (host:port).
        scrape_interval: How often to scrape.

    Returns:
        YAML configuration string.
    """
    return f"""# JoyfulJay Prometheus scrape config
# Add this to your prometheus.yml under scrape_configs:

scrape_configs:
  - job_name: '{job_name}'
    scrape_interval: {scrape_interval}
    static_configs:
      - targets: ['{target}']
    metrics_path: /metrics
"""


def generate_alerting_rules(
    namespace: str = "joyfuljay",
    error_threshold: int = 10,
    packet_rate_threshold: float = 0,
) -> str:
    """Generate Prometheus alerting rules for JoyfulJay.

    Args:
        namespace: Metrics namespace.
        error_threshold: Number of errors to trigger alert.
        packet_rate_threshold: Minimum packet rate (0 = no packets alert).

    Returns:
        YAML alerting rules string.
    """
    return f"""# JoyfulJay Alerting Rules
# Add this to your Prometheus rules file

groups:
  - name: joyfuljay
    rules:
      - alert: JoyfulJayHighErrorRate
        expr: sum(rate({namespace}_errors_total[5m])) > {error_threshold}
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High error rate in JoyfulJay"
          description: "Error rate is {{ $value | printf \\"%.2f\\" }} errors/sec"

      - alert: JoyfulJayNoPackets
        expr: rate({namespace}_packets_total[5m]) <= {packet_rate_threshold}
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "No packets being processed"
          description: "JoyfulJay has not processed any packets in the last 5 minutes"

      - alert: JoyfulJayHighActiveFlows
        expr: {namespace}_active_flows > 1000
        for: 5m
        labels:
          severity: info
        annotations:
          summary: "High number of active flows"
          description: "{{ $value }} active flows may indicate high traffic or slow processing"
"""


class DashboardBuilder:
    """Builder for creating custom Grafana dashboards.

    Example:
        builder = DashboardBuilder("My Custom Dashboard")
        builder.add_stat_panel("Total Packets", "joyfuljay_packets_total")
        builder.add_graph_panel("Packet Rate", "rate(joyfuljay_packets_total[1m])")
        dashboard = builder.build()
    """

    def __init__(
        self,
        title: str,
        uid: str | None = None,
        refresh: str = "10s",
    ) -> None:
        """Initialize the dashboard builder.

        Args:
            title: Dashboard title.
            uid: Optional unique identifier.
            refresh: Auto-refresh interval.
        """
        self.title = title
        self.uid = uid or title.lower().replace(" ", "-")
        self.refresh = refresh
        self.panels: list[dict[str, Any]] = []
        self._next_id = 1
        self._current_y = 0

    def add_row(self, title: str) -> "DashboardBuilder":
        """Add a collapsible row.

        Args:
            title: Row title.

        Returns:
            Self for chaining.
        """
        self.panels.append(
            {
                "collapsed": False,
                "gridPos": {"h": 1, "w": 24, "x": 0, "y": self._current_y},
                "id": self._next_id,
                "panels": [],
                "title": title,
                "type": "row",
            }
        )
        self._next_id += 1
        self._current_y += 1
        return self

    def add_stat_panel(
        self,
        title: str,
        expr: str,
        unit: str = "short",
        width: int = 4,
        height: int = 4,
    ) -> "DashboardBuilder":
        """Add a stat panel.

        Args:
            title: Panel title.
            expr: PromQL expression.
            unit: Grafana unit type.
            width: Panel width (1-24).
            height: Panel height.

        Returns:
            Self for chaining.
        """
        x = sum(p.get("gridPos", {}).get("w", 0) for p in self.panels if p.get("type") != "row") % 24
        if x + width > 24:
            self._current_y += height
            x = 0

        self.panels.append(
            {
                "datasource": {"type": "prometheus", "uid": "${datasource}"},
                "fieldConfig": {
                    "defaults": {
                        "color": {"mode": "thresholds"},
                        "thresholds": {
                            "mode": "absolute",
                            "steps": [{"color": "green", "value": None}],
                        },
                        "unit": unit,
                    }
                },
                "gridPos": {"h": height, "w": width, "x": x, "y": self._current_y},
                "id": self._next_id,
                "options": {
                    "colorMode": "value",
                    "graphMode": "area",
                    "reduceOptions": {"calcs": ["lastNotNull"]},
                },
                "targets": [
                    {
                        "datasource": {"type": "prometheus", "uid": "${datasource}"},
                        "expr": expr,
                        "refId": "A",
                    }
                ],
                "title": title,
                "type": "stat",
            }
        )
        self._next_id += 1
        return self

    def add_graph_panel(
        self,
        title: str,
        expr: str | list[str],
        unit: str = "short",
        width: int = 12,
        height: int = 8,
        legend_format: str | list[str] | None = None,
    ) -> "DashboardBuilder":
        """Add a time series graph panel.

        Args:
            title: Panel title.
            expr: PromQL expression(s).
            unit: Grafana unit type.
            width: Panel width (1-24).
            height: Panel height.
            legend_format: Legend format string(s).

        Returns:
            Self for chaining.
        """
        if isinstance(expr, str):
            expr = [expr]
        if legend_format is None:
            legend_format = ["{{instance}}"] * len(expr)
        elif isinstance(legend_format, str):
            legend_format = [legend_format]

        x = 0
        for p in reversed(self.panels):
            if p.get("type") == "row":
                break
            gp = p.get("gridPos", {})
            if gp.get("y", 0) == self._current_y:
                x = gp.get("x", 0) + gp.get("w", 0)
                break

        if x + width > 24:
            self._current_y += height
            x = 0

        targets = []
        for i, (e, lf) in enumerate(zip(expr, legend_format)):
            targets.append(
                {
                    "datasource": {"type": "prometheus", "uid": "${datasource}"},
                    "expr": e,
                    "legendFormat": lf,
                    "refId": chr(65 + i),
                }
            )

        self.panels.append(
            {
                "datasource": {"type": "prometheus", "uid": "${datasource}"},
                "fieldConfig": {
                    "defaults": {
                        "color": {"mode": "palette-classic"},
                        "custom": {
                            "drawStyle": "line",
                            "fillOpacity": 20,
                            "lineWidth": 2,
                        },
                        "unit": unit,
                    }
                },
                "gridPos": {"h": height, "w": width, "x": x, "y": self._current_y},
                "id": self._next_id,
                "options": {
                    "legend": {"displayMode": "table", "placement": "bottom"},
                    "tooltip": {"mode": "multi"},
                },
                "targets": targets,
                "title": title,
                "type": "timeseries",
            }
        )
        self._next_id += 1
        return self

    def build(self) -> dict[str, Any]:
        """Build the dashboard JSON.

        Returns:
            Complete dashboard dictionary.
        """
        return {
            "annotations": {"list": []},
            "editable": True,
            "panels": self.panels,
            "refresh": self.refresh,
            "schemaVersion": 38,
            "tags": ["joyfuljay", "custom"],
            "templating": {
                "list": [
                    {
                        "current": {"text": "Prometheus", "value": "prometheus"},
                        "hide": 0,
                        "label": "Datasource",
                        "name": "datasource",
                        "query": "prometheus",
                        "type": "datasource",
                    }
                ]
            },
            "time": {"from": "now-1h", "to": "now"},
            "title": self.title,
            "uid": self.uid,
            "version": 1,
        }
