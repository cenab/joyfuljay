"""Jupyter notebook integration for JoyfulJay.

Provides interactive widgets and visualizations for exploring
network traffic data in Jupyter notebooks.
"""

from .widgets import (
    FlowExplorer,
    FeatureVisualizer,
    PcapViewer,
    display_flow_table,
    display_feature_summary,
    plot_flow_timeline,
    plot_feature_distribution,
)

__all__ = [
    "FlowExplorer",
    "FeatureVisualizer",
    "PcapViewer",
    "display_flow_table",
    "display_feature_summary",
    "plot_flow_timeline",
    "plot_feature_distribution",
]
