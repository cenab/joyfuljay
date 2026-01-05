"""Connection graph feature extractor.

This extractor provides connection graph metrics for each flow,
analyzing how flows relate to each other in the overall traffic.

Features include:
- Simple connection counts (Tier 1, no dependencies)
- Graph metrics like centrality and communities (Tier 2, requires NetworkX)
- Temporal connection patterns (Tier 3, optional)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .base import FeatureExtractor

if TYPE_CHECKING:
    from ..analysis.connection_graph import ConnectionGraph
    from ..core.flow import Flow


class ConnectionExtractor(FeatureExtractor):
    """Extracts connection graph features from flows.

    This extractor differs from others in that it requires a pre-built
    ConnectionGraph to be injected via set_graph(). The pipeline handles
    this automatically when connection features are enabled.

    Features are grouped into tiers:

    Tier 1 (Simple, no dependencies):
    - conn_src_unique_dsts: Unique destinations from source
    - conn_dst_unique_srcs: Unique sources to destination
    - conn_src_dst_flows: Flows between this exact pair
    - conn_src_port_flows: Flows to this specific port
    - conn_src_total_flows: Total outbound flows from source
    - conn_dst_total_flows: Total inbound flows to destination
    - conn_src_total_packets: Total packets sent by source
    - conn_src_total_bytes: Total bytes sent by source
    - conn_dst_total_packets: Total packets received by destination
    - conn_dst_total_bytes: Total bytes received by destination
    - conn_src_unique_ports: Unique destination ports from source

    Tier 2 (Graph metrics, requires NetworkX):
    - conn_src_out_degree: Out-degree of source node
    - conn_dst_in_degree: In-degree of destination node
    - conn_src_betweenness: Betweenness centrality of source
    - conn_dst_betweenness: Betweenness centrality of destination
    - conn_src_community: Community ID of source
    - conn_dst_community: Community ID of destination
    - conn_same_community: Whether src and dst in same community
    - conn_src_clustering: Clustering coefficient of source
    - conn_dst_clustering: Clustering coefficient of destination

    Tier 3 (Temporal, optional):
    - conn_src_flow_rate: Flows per second from source
    - conn_temporal_spread: Time spread of connections
    - conn_burst_connections: Max connections in 1-second window

    Example:
        >>> extractor = ConnectionExtractor(include_graph_metrics=True)
        >>> graph = ConnectionGraph()
        >>> for flow in flows:
        ...     graph.add_flow(flow)
        >>> extractor.set_graph(graph)
        >>> features = extractor.extract(flows[0])
    """

    def __init__(
        self,
        include_graph_metrics: bool = True,
        include_temporal: bool = False,
        use_ports: bool = False,
        community_algorithm: str = "louvain",
    ) -> None:
        """Initialize the connection extractor.

        Args:
            include_graph_metrics: Whether to compute graph metrics
                (requires NetworkX). If False, only simple counters
                are extracted.
            include_temporal: Whether to compute temporal patterns.
            use_ports: If True, graph nodes include port numbers.
            community_algorithm: Algorithm for community detection.
                Options: "louvain", "greedy", "label_propagation"
        """
        self.include_graph_metrics = include_graph_metrics
        self.include_temporal = include_temporal
        self.use_ports = use_ports
        self.community_algorithm = community_algorithm
        self._graph: ConnectionGraph | None = None

    def set_graph(self, graph: ConnectionGraph) -> None:
        """Inject the pre-built connection graph.

        This must be called before extract() can be used. The pipeline
        handles this automatically.

        Args:
            graph: The ConnectionGraph built from all flows.
        """
        self._graph = graph

    def extract(self, flow: Flow) -> dict[str, Any]:
        """Extract connection features for a flow.

        Args:
            flow: The completed flow.

        Returns:
            Dictionary of connection features.

        Raises:
            RuntimeError: If set_graph() was not called first.
        """
        if self._graph is None:
            raise RuntimeError(
                "ConnectionGraph not set. Call set_graph() before extract(). "
                "This is normally handled automatically by the Pipeline."
            )

        return self._graph.get_flow_metrics(
            flow,
            include_graph_metrics=self.include_graph_metrics,
            include_temporal=self.include_temporal,
        )

    @property
    def feature_names(self) -> list[str]:
        """Get list of feature names produced by this extractor."""
        names = [
            # Tier 1: Simple metrics
            "conn_src_unique_dsts",
            "conn_dst_unique_srcs",
            "conn_src_dst_flows",
            "conn_src_port_flows",
            "conn_src_total_flows",
            "conn_dst_total_flows",
            "conn_src_total_packets",
            "conn_src_total_bytes",
            "conn_dst_total_packets",
            "conn_dst_total_bytes",
            "conn_src_unique_ports",
        ]

        if self.include_graph_metrics:
            names.extend([
                # Tier 2: Graph metrics
                "conn_src_out_degree",
                "conn_dst_in_degree",
                "conn_src_betweenness",
                "conn_dst_betweenness",
                "conn_src_community",
                "conn_dst_community",
                "conn_same_community",
                "conn_src_clustering",
                "conn_dst_clustering",
            ])

        if self.include_temporal:
            names.extend([
                # Tier 3: Temporal patterns
                "conn_src_flow_rate",
                "conn_temporal_spread",
                "conn_burst_connections",
            ])

        return names

    @property
    def name(self) -> str:
        """Get extractor name."""
        return "connection"

    @property
    def requires_graph(self) -> bool:
        """Indicate this extractor needs a pre-built graph."""
        return True
