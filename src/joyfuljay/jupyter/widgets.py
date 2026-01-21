"""Jupyter widgets for interactive visualization.

Provides IPython widgets and plotting functions for exploring
network traffic data in Jupyter notebooks.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    import pandas as pd


def _check_jupyter_deps() -> bool:
    """Check if Jupyter dependencies are available."""
    try:
        import ipywidgets  # noqa: F401
        import pandas  # noqa: F401
        return True
    except ImportError:
        return False


def _check_plotly() -> bool:
    """Check if Plotly is available."""
    try:
        import plotly  # noqa: F401
        return True
    except ImportError:
        return False


def _display(obj: Any) -> None:
    """Display an object in Jupyter without strict typing errors."""
    from IPython.display import display as ipy_display

    display_fn = cast(Callable[[Any], Any], ipy_display)
    display_fn(obj)


class FlowExplorer:
    """Interactive widget for exploring network flows.

    Provides a searchable, filterable table view of flows
    with drill-down capabilities.
    """

    def __init__(self, flows: list[Any] | None = None, pcap_path: str | None = None) -> None:
        """Initialize the flow explorer.

        Args:
            flows: List of Flow objects to explore.
            pcap_path: Path to PCAP file to load.
        """
        if not _check_jupyter_deps():
            raise ImportError(
                "Jupyter widgets require ipywidgets and pandas. "
                "Install with: pip install ipywidgets pandas"
            )

        self.flows = flows or []
        self.pcap_path = pcap_path
        self._df: pd.DataFrame | None = None

        if pcap_path and not flows:
            self._load_pcap(pcap_path)

    def _load_pcap(self, path: str) -> None:
        """Load flows from a PCAP file."""
        from ..capture.scapy_backend import ScapyBackend
        from ..core.flow import FlowTable

        backend = ScapyBackend(store_raw_payload=True)
        flow_table = FlowTable()

        for packet in backend.iter_packets_offline(path):
            flow_table.add_packet(packet)

        self.flows = list(flow_table.get_all_flows())

    def to_dataframe(self) -> pd.DataFrame:
        """Convert flows to a pandas DataFrame.

        Returns:
            DataFrame with flow information.
        """
        import pandas as pd

        if self._df is not None:
            return self._df

        data = []
        for i, flow in enumerate(self.flows):
            data.append({
                "id": i,
                "protocol": {6: "TCP", 17: "UDP"}.get(flow.key.protocol, str(flow.key.protocol)),
                "src_ip": flow.initiator_ip,
                "src_port": flow.initiator_port,
                "dst_ip": flow.responder_ip,
                "dst_port": flow.responder_port,
                "packets": flow.total_packets,
                "bytes": flow.total_bytes,
                "duration": round(flow.duration, 3),
                "packets_fwd": len(flow.initiator_packets),
                "packets_bwd": len(flow.responder_packets),
            })

        self._df = pd.DataFrame(data)
        return self._df

    def display(self) -> Any:
        """Display the interactive explorer widget.

        Returns:
            IPython widget for display.
        """
        import ipywidgets as widgets
        df = self.to_dataframe()

        # Create filter widgets
        protocol_filter = widgets.Dropdown(
            options=["All"] + list(df["protocol"].unique()),
            value="All",
            description="Protocol:",
        )

        search_box = widgets.Text(
            value="",
            placeholder="Search IP or port...",
            description="Search:",
        )

        output = widgets.Output()

        def update_display(*args: Any) -> None:
            with output:
                output.clear_output()
                filtered = df.copy()

                if protocol_filter.value != "All":
                    filtered = filtered[filtered["protocol"] == protocol_filter.value]

                if search_box.value:
                    mask = (
                        filtered["src_ip"].str.contains(search_box.value, case=False)
                        | filtered["dst_ip"].str.contains(search_box.value, case=False)
                        | filtered["src_port"].astype(str).str.contains(search_box.value)
                        | filtered["dst_port"].astype(str).str.contains(search_box.value)
                    )
                    filtered = filtered[mask]

                _display(filtered.head(50))
                print(f"Showing {min(50, len(filtered))} of {len(filtered)} flows")

        protocol_filter.observe(update_display, names="value")
        search_box.observe(update_display, names="value")

        # Initial display
        update_display()

        return widgets.VBox([
            widgets.HBox([protocol_filter, search_box]),
            output,
        ])


class FeatureVisualizer:
    """Interactive visualization of extracted features."""

    def __init__(self, features: list[dict[str, Any]] | pd.DataFrame) -> None:
        """Initialize the visualizer.

        Args:
            features: Feature data as list of dicts or DataFrame.
        """
        import pandas as pd

        if isinstance(features, pd.DataFrame):
            self.df = features
        else:
            self.df = pd.DataFrame(features)

    def display(self) -> Any:
        """Display the interactive visualizer widget.

        Returns:
            IPython widget for display.
        """
        import ipywidgets as widgets
        # Get numeric columns
        numeric_cols = self.df.select_dtypes(include=["number"]).columns.tolist()

        feature_selector = widgets.Dropdown(
            options=numeric_cols,
            value=numeric_cols[0] if numeric_cols else None,
            description="Feature:",
        )

        chart_type = widgets.Dropdown(
            options=["histogram", "box", "scatter"],
            value="histogram",
            description="Chart:",
        )

        output = widgets.Output()

        def update_chart(*args: Any) -> None:
            with output:
                output.clear_output()
                if not feature_selector.value:
                    print("No numeric features available")
                    return

                if _check_plotly():
                    import plotly.express as px

                    if chart_type.value == "histogram":
                        fig = px.histogram(self.df, x=feature_selector.value)
                    elif chart_type.value == "box":
                        fig = px.box(self.df, y=feature_selector.value)
                    else:
                        fig = px.scatter(
                            self.df,
                            x=self.df.index,
                            y=feature_selector.value,
                            title=feature_selector.value,
                        )
                    fig.show()
                else:
                    # Fallback to matplotlib
                    import matplotlib.pyplot as plt

                    fig, ax = plt.subplots(figsize=(10, 4))
                    if chart_type.value == "histogram":
                        self.df[feature_selector.value].hist(ax=ax, bins=30)
                    elif chart_type.value == "box":
                        self.df.boxplot(column=feature_selector.value, ax=ax)
                    else:
                        ax.scatter(range(len(self.df)), self.df[feature_selector.value])
                    ax.set_title(feature_selector.value)
                    plt.show()

        feature_selector.observe(update_chart, names="value")
        chart_type.observe(update_chart, names="value")
        update_chart()

        return widgets.VBox([
            widgets.HBox([feature_selector, chart_type]),
            output,
        ])


class PcapViewer:
    """Quick PCAP file viewer for Jupyter."""

    def __init__(self, path: str | Path) -> None:
        """Initialize the viewer.

        Args:
            path: Path to PCAP file.
        """
        self.path = Path(path)
        self.explorer = FlowExplorer(pcap_path=str(self.path))

    def display(self) -> Any:
        """Display the PCAP viewer.

        Returns:
            IPython widget.
        """
        import ipywidgets as widgets

        header = widgets.HTML(f"<h3>PCAP: {self.path.name}</h3>")
        return widgets.VBox([header, self.explorer.display()])


def display_flow_table(flows: list[Any], limit: int = 50) -> None:
    """Display a formatted table of flows.

    Args:
        flows: List of Flow objects.
        limit: Maximum rows to display.
    """
    import pandas as pd
    data = []
    for i, flow in enumerate(flows[:limit]):
        data.append({
            "ID": i,
            "Protocol": {6: "TCP", 17: "UDP"}.get(flow.key.protocol, str(flow.key.protocol)),
            "Source": f"{flow.initiator_ip}:{flow.initiator_port}",
            "Destination": f"{flow.responder_ip}:{flow.responder_port}",
            "Packets": flow.total_packets,
            "Bytes": flow.total_bytes,
            "Duration": f"{flow.duration:.3f}s",
        })

    df = pd.DataFrame(data)
    _display(df)

    if len(flows) > limit:
        print(f"Showing {limit} of {len(flows)} flows")


def display_feature_summary(features: list[dict[str, Any]] | pd.DataFrame) -> None:
    """Display summary statistics for features.

    Args:
        features: Feature data.
    """
    import pandas as pd
    if isinstance(features, list):
        df = pd.DataFrame(features)
    else:
        df = features

    # Numeric summary
    print("Numeric Feature Summary:")
    _display(df.describe())

    # Non-numeric
    non_numeric = df.select_dtypes(exclude=["number"])
    if not non_numeric.empty:
        print("\nCategorical Features:")
        for col in non_numeric.columns[:5]:
            print(f"  {col}: {df[col].nunique()} unique values")


def plot_flow_timeline(flows: list[Any]) -> None:
    """Plot a timeline of flow start times.

    Args:
        flows: List of Flow objects.
    """
    import pandas as pd

    if _check_plotly():
        import plotly.express as px

        data = [{
            "start": flow.start_time,
            "duration": flow.duration,
            "protocol": {6: "TCP", 17: "UDP"}.get(flow.key.protocol, "Other"),
            "bytes": flow.total_bytes,
        } for flow in flows]

        df = pd.DataFrame(data)
        fig = px.scatter(
            df,
            x="start",
            y="bytes",
            color="protocol",
            size="duration",
            title="Flow Timeline",
        )
        fig.show()
    else:
        import matplotlib.pyplot as plt

        starts = [f.start_time for f in flows]
        bytes_vals = [f.total_bytes for f in flows]

        plt.figure(figsize=(12, 4))
        plt.scatter(starts, bytes_vals, alpha=0.5)
        plt.xlabel("Time")
        plt.ylabel("Bytes")
        plt.title("Flow Timeline")
        plt.show()


def plot_feature_distribution(
    features: list[dict[str, Any]] | pd.DataFrame,
    feature_name: str,
) -> None:
    """Plot distribution of a specific feature.

    Args:
        features: Feature data.
        feature_name: Name of feature to plot.
    """
    import pandas as pd

    if isinstance(features, list):
        df = pd.DataFrame(features)
    else:
        df = features

    if feature_name not in df.columns:
        print(f"Feature '{feature_name}' not found")
        return

    if _check_plotly():
        import plotly.express as px

        fig = px.histogram(df, x=feature_name, title=f"Distribution: {feature_name}")
        fig.show()
    else:
        import matplotlib.pyplot as plt

        plt.figure(figsize=(10, 4))
        df[feature_name].hist(bins=30)
        plt.title(f"Distribution: {feature_name}")
        plt.xlabel(feature_name)
        plt.ylabel("Count")
        plt.show()
