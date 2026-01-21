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
    from ..schema.registry import FeatureMeta


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
    def extractor_id(self) -> str:
        """Get the stable identifier for this extractor."""
        return "connection"

    def feature_meta(self) -> dict[str, FeatureMeta]:
        """Get metadata for all features produced by this extractor."""
        from ..schema.registry import FeatureMeta

        meta: dict[str, FeatureMeta] = {}
        prefix = self.extractor_id

        # Define metadata for each feature
        feature_definitions = {
            # Tier 1: Simple metrics
            "conn_src_unique_dsts": FeatureMeta(
                id=f"{prefix}.conn_src_unique_dsts",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="Unique destinations contacted by source",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Number of unique destination IPs contacted by source",
            ),
            "conn_dst_unique_srcs": FeatureMeta(
                id=f"{prefix}.conn_dst_unique_srcs",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="Unique sources contacting destination",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Number of unique source IPs contacting destination",
            ),
            "conn_src_dst_flows": FeatureMeta(
                id=f"{prefix}.conn_src_dst_flows",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="bidir",
                direction_semantics="Flows between this exact src-dst pair",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Number of flows between this exact source-destination pair",
            ),
            "conn_src_port_flows": FeatureMeta(
                id=f"{prefix}.conn_src_port_flows",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="Flows from source to this specific port",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Number of flows from source to this specific destination port",
            ),
            "conn_src_total_flows": FeatureMeta(
                id=f"{prefix}.conn_src_total_flows",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="Total outbound flows from source",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Total number of outbound flows from source IP",
            ),
            "conn_dst_total_flows": FeatureMeta(
                id=f"{prefix}.conn_dst_total_flows",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="Total inbound flows to destination",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Total number of inbound flows to destination IP",
            ),
            "conn_src_total_packets": FeatureMeta(
                id=f"{prefix}.conn_src_total_packets",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="Total packets sent by source",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Total number of packets sent by source IP across all flows",
            ),
            "conn_src_total_bytes": FeatureMeta(
                id=f"{prefix}.conn_src_total_bytes",
                dtype="int64",
                shape=[1],
                units="bytes",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="Total bytes sent by source",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Total bytes sent by source IP across all flows",
            ),
            "conn_dst_total_packets": FeatureMeta(
                id=f"{prefix}.conn_dst_total_packets",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="Total packets received by destination",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Total packets received by destination IP across all flows",
            ),
            "conn_dst_total_bytes": FeatureMeta(
                id=f"{prefix}.conn_dst_total_bytes",
                dtype="int64",
                shape=[1],
                units="bytes",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="Total bytes received by destination",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Total bytes received by destination IP across all flows",
            ),
            "conn_src_unique_ports": FeatureMeta(
                id=f"{prefix}.conn_src_unique_ports",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="Unique destination ports from source",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Number of unique destination ports contacted by source",
            ),
            # Tier 2: Graph metrics
            "conn_src_out_degree": FeatureMeta(
                id=f"{prefix}.conn_src_out_degree",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="Out-degree of source node in connection graph",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Out-degree of source node in the connection graph",
            ),
            "conn_dst_in_degree": FeatureMeta(
                id=f"{prefix}.conn_dst_in_degree",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="In-degree of destination node in connection graph",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="In-degree of destination node in the connection graph",
            ),
            "conn_src_betweenness": FeatureMeta(
                id=f"{prefix}.conn_src_betweenness",
                dtype="float64",
                shape=[1],
                units="",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="Betweenness centrality of source node",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Betweenness centrality of source node in connection graph",
            ),
            "conn_dst_betweenness": FeatureMeta(
                id=f"{prefix}.conn_dst_betweenness",
                dtype="float64",
                shape=[1],
                units="",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="Betweenness centrality of destination node",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Betweenness centrality of destination node in connection graph",
            ),
            "conn_src_community": FeatureMeta(
                id=f"{prefix}.conn_src_community",
                dtype="int64",
                shape=[1],
                units="",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="Community ID of source node",
                missing_policy="sentinel",
                missing_sentinel=-1,
                dependencies=["ip"],
                privacy_level="safe",
                description="Community identifier of source node from community detection",
            ),
            "conn_dst_community": FeatureMeta(
                id=f"{prefix}.conn_dst_community",
                dtype="int64",
                shape=[1],
                units="",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="Community ID of destination node",
                missing_policy="sentinel",
                missing_sentinel=-1,
                dependencies=["ip"],
                privacy_level="safe",
                description="Community identifier of destination node from community detection",
            ),
            "conn_same_community": FeatureMeta(
                id=f"{prefix}.conn_same_community",
                dtype="bool",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="Whether source and destination are in same community",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="True if source and destination are in the same community",
            ),
            "conn_src_clustering": FeatureMeta(
                id=f"{prefix}.conn_src_clustering",
                dtype="float64",
                shape=[1],
                units="",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="Clustering coefficient of source node",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Clustering coefficient of source node in connection graph",
            ),
            "conn_dst_clustering": FeatureMeta(
                id=f"{prefix}.conn_dst_clustering",
                dtype="float64",
                shape=[1],
                units="",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="Clustering coefficient of destination node",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Clustering coefficient of destination node in connection graph",
            ),
            # Tier 3: Temporal patterns
            "conn_src_flow_rate": FeatureMeta(
                id=f"{prefix}.conn_src_flow_rate",
                dtype="float64",
                shape=[1],
                units="flows/s",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="Flow rate from source",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Number of flows per second from source IP",
            ),
            "conn_temporal_spread": FeatureMeta(
                id=f"{prefix}.conn_temporal_spread",
                dtype="float64",
                shape=[1],
                units="s",
                scope="flow",
                direction="bidir",
                direction_semantics="Time spread of connections",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Time spread of connections from source to destination",
            ),
            "conn_burst_connections": FeatureMeta(
                id=f"{prefix}.conn_burst_connections",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="Max connections in 1-second window",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["ip"],
                privacy_level="safe",
                description="Maximum number of connections in a 1-second sliding window",
            ),
        }

        # Only include metadata for features we actually produce
        for name in self.feature_names:
            if name in feature_definitions:
                meta[f"{prefix}.{name}"] = feature_definitions[name]

        return meta

    @property
    def name(self) -> str:
        """Get extractor name."""
        return "connection"

    @property
    def requires_graph(self) -> bool:
        """Indicate this extractor needs a pre-built graph."""
        return True
