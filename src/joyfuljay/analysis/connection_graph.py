"""Connection graph builder and analyzer for multi-flow analysis.

This module provides graph-based analysis of network connections,
computing metrics like fan-out, community detection, and centrality.

The ConnectionGraph accumulates flows incrementally and can compute:
- Simple metrics without external dependencies (Tier 1)
- Graph metrics requiring NetworkX (Tier 2)
- Temporal patterns (Tier 3)
"""

from __future__ import annotations

import logging
import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..core.flow import Flow

logger = logging.getLogger(__name__)

# Optional NetworkX import
try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    nx = None  # type: ignore
    NETWORKX_AVAILABLE = False


def is_networkx_available() -> bool:
    """Check if NetworkX is available."""
    return NETWORKX_AVAILABLE


@dataclass
class NodeStats:
    """Statistics for a single node (IP address) in the connection graph."""

    # Flow counts
    outbound_flows: int = 0
    inbound_flows: int = 0

    # Unique peer counts
    unique_destinations: set[str] = field(default_factory=set)
    unique_sources: set[str] = field(default_factory=set)

    # Unique destination ports (from this node)
    unique_dst_ports: set[int] = field(default_factory=set)

    # Packet/byte totals
    total_packets_sent: int = 0
    total_packets_received: int = 0
    total_bytes_sent: int = 0
    total_bytes_received: int = 0

    # Temporal tracking
    first_seen: float = float("inf")
    last_seen: float = 0.0
    flow_timestamps: list[float] = field(default_factory=list)


@dataclass
class EdgeStats:
    """Statistics for an edge (connection pair) in the graph."""

    flow_count: int = 0
    total_packets: int = 0
    total_bytes: int = 0

    # Temporal
    first_seen: float = float("inf")
    last_seen: float = 0.0

    # Port-specific flow counts
    port_flows: dict[int, int] = field(default_factory=lambda: defaultdict(int))


class ConnectionGraph:
    """Builds and analyzes connection graphs from network flows.

    The graph is built incrementally as flows are added. Simple metrics
    (Tier 1) are computed using only internal counters. Graph metrics
    (Tier 2) require NetworkX and are computed lazily when needed.

    Example:
        >>> graph = ConnectionGraph()
        >>> for flow in flows:
        ...     graph.add_flow(flow)
        >>> metrics = graph.get_flow_metrics(flows[0])
        >>> print(metrics["conn_src_unique_dsts"])
    """

    def __init__(
        self,
        use_ports: bool = False,
        include_graph_metrics: bool = True,
        include_temporal: bool = False,
        community_algorithm: str = "louvain",
    ) -> None:
        """Initialize the connection graph.

        Args:
            use_ports: If True, nodes include port numbers (IP:port).
                      If False, nodes are just IP addresses.
            include_graph_metrics: Whether to compute NetworkX graph metrics.
            include_temporal: Whether to compute temporal patterns.
            community_algorithm: Algorithm for community detection.
                                Options: "louvain", "greedy", "label_propagation"
        """
        self.use_ports = use_ports
        self.include_graph_metrics = include_graph_metrics
        self.include_temporal = include_temporal
        self.community_algorithm = community_algorithm

        # Internal state
        self._node_stats: dict[str, NodeStats] = defaultdict(NodeStats)
        self._edge_stats: dict[tuple[str, str], EdgeStats] = defaultdict(EdgeStats)

        # NetworkX graph (built lazily)
        self._graph: Any = None  # nx.DiGraph when built
        self._graph_built = False

        # Cached graph metrics
        self._betweenness: dict[str, float] = {}
        self._communities: dict[str, int] = {}
        self._clustering: dict[str, float] = {}

    def _get_node_id(self, ip: str, port: int | None = None) -> str:
        """Get node identifier for an IP/port combination."""
        if self.use_ports and port is not None:
            return f"{ip}:{port}"
        return ip

    def add_flow(self, flow: Flow) -> None:
        """Add a flow to the connection graph.

        This updates internal counters incrementally. Graph metrics
        are not computed until get_flow_metrics() is called.

        Args:
            flow: The completed flow to add.
        """
        src_ip = flow.initiator_ip
        dst_ip = flow.responder_ip
        src_port = flow.initiator_port
        dst_port = flow.responder_port

        src_node = self._get_node_id(src_ip, src_port if self.use_ports else None)
        dst_node = self._get_node_id(dst_ip, dst_port if self.use_ports else None)

        # Update source node stats
        src_stats = self._node_stats[src_node]
        src_stats.outbound_flows += 1
        src_stats.unique_destinations.add(dst_node)
        src_stats.unique_dst_ports.add(dst_port)
        src_stats.total_packets_sent += flow.total_packets
        src_stats.total_bytes_sent += flow.total_bytes
        src_stats.first_seen = min(src_stats.first_seen, flow.start_time)
        src_stats.last_seen = max(src_stats.last_seen, flow.last_seen)
        if self.include_temporal:
            src_stats.flow_timestamps.append(flow.start_time)

        # Update destination node stats
        dst_stats = self._node_stats[dst_node]
        dst_stats.inbound_flows += 1
        dst_stats.unique_sources.add(src_node)
        dst_stats.total_packets_received += flow.total_packets
        dst_stats.total_bytes_received += flow.total_bytes
        dst_stats.first_seen = min(dst_stats.first_seen, flow.start_time)
        dst_stats.last_seen = max(dst_stats.last_seen, flow.last_seen)
        if self.include_temporal:
            dst_stats.flow_timestamps.append(flow.start_time)

        # Update edge stats
        edge_key = (src_node, dst_node)
        edge_stats = self._edge_stats[edge_key]
        edge_stats.flow_count += 1
        edge_stats.total_packets += flow.total_packets
        edge_stats.total_bytes += flow.total_bytes
        edge_stats.first_seen = min(edge_stats.first_seen, flow.start_time)
        edge_stats.last_seen = max(edge_stats.last_seen, flow.last_seen)
        edge_stats.port_flows[dst_port] += 1

        # Invalidate cached graph
        self._graph_built = False

    def build_graph(self) -> None:
        """Build the NetworkX graph from accumulated statistics.

        This is called automatically when graph metrics are requested.

        Raises:
            ImportError: If NetworkX is not installed.
        """
        if not NETWORKX_AVAILABLE:
            raise ImportError(
                "NetworkX is required for graph metrics. "
                "Install with: pip install joyfuljay[graphs]"
            )

        if self._graph_built:
            return

        logger.debug("Building NetworkX graph from %d nodes, %d edges",
                    len(self._node_stats), len(self._edge_stats))

        self._graph = nx.DiGraph()

        # Add nodes with attributes
        for node_id, stats in self._node_stats.items():
            self._graph.add_node(
                node_id,
                outbound_flows=stats.outbound_flows,
                inbound_flows=stats.inbound_flows,
                total_packets=stats.total_packets_sent + stats.total_packets_received,
                total_bytes=stats.total_bytes_sent + stats.total_bytes_received,
            )

        # Add edges with weights
        for (src, dst), stats in self._edge_stats.items():
            self._graph.add_edge(
                src, dst,
                flow_count=stats.flow_count,
                packets=stats.total_packets,
                bytes=stats.total_bytes,
                weight=stats.flow_count,  # Weight for algorithms
            )

        # Compute cached metrics
        self._compute_graph_metrics()
        self._graph_built = True

    def _compute_graph_metrics(self) -> None:
        """Compute and cache graph metrics."""
        if self._graph is None or len(self._graph) == 0:
            return

        # Betweenness centrality
        try:
            self._betweenness = nx.betweenness_centrality(self._graph)
        except Exception as e:
            logger.warning("Failed to compute betweenness centrality: %s", e)
            self._betweenness = {}

        # Clustering coefficient (for undirected version)
        try:
            undirected = self._graph.to_undirected()
            self._clustering = nx.clustering(undirected)
        except Exception as e:
            logger.warning("Failed to compute clustering: %s", e)
            self._clustering = {}

        # Community detection
        try:
            self._compute_communities()
        except Exception as e:
            logger.warning("Failed to compute communities: %s", e)
            self._communities = {}

    def _compute_communities(self) -> None:
        """Compute community assignments using the configured algorithm."""
        if self._graph is None or len(self._graph) == 0:
            self._communities = {}
            return

        # Need undirected graph for community detection
        undirected = self._graph.to_undirected()

        if self.community_algorithm == "louvain":
            # Louvain algorithm (best for most cases)
            try:
                communities = nx.community.louvain_communities(undirected)
                self._communities = {}
                for i, community in enumerate(communities):
                    for node in community:
                        self._communities[node] = i
            except AttributeError:
                # Older NetworkX version without louvain
                self._communities = self._fallback_communities(undirected)

        elif self.community_algorithm == "greedy":
            # Greedy modularity optimization
            communities = nx.community.greedy_modularity_communities(undirected)
            self._communities = {}
            for i, community in enumerate(communities):
                for node in community:
                    self._communities[node] = i

        elif self.community_algorithm == "label_propagation":
            # Label propagation (fast but less accurate)
            communities = nx.community.label_propagation_communities(undirected)
            self._communities = {}
            for i, community in enumerate(communities):
                for node in community:
                    self._communities[node] = i

        else:
            logger.warning("Unknown community algorithm: %s", self.community_algorithm)
            self._communities = {}

    def _fallback_communities(self, graph: Any) -> dict[str, int]:
        """Fallback community detection for older NetworkX versions."""
        try:
            communities = nx.community.greedy_modularity_communities(graph)
            result = {}
            for i, community in enumerate(communities):
                for node in community:
                    result[node] = i
            return result
        except Exception:
            return {}

    def get_flow_metrics(
        self,
        flow: Flow,
        include_graph_metrics: bool | None = None,
        include_temporal: bool | None = None,
    ) -> dict[str, Any]:
        """Get connection graph metrics for a specific flow.

        Args:
            flow: The flow to get metrics for.
            include_graph_metrics: Override instance setting.
            include_temporal: Override instance setting.

        Returns:
            Dictionary of connection metrics for this flow.
        """
        if include_graph_metrics is None:
            include_graph_metrics = self.include_graph_metrics
        if include_temporal is None:
            include_temporal = self.include_temporal

        src_ip = flow.initiator_ip
        dst_ip = flow.responder_ip
        src_port = flow.initiator_port
        dst_port = flow.responder_port

        src_node = self._get_node_id(src_ip, src_port if self.use_ports else None)
        dst_node = self._get_node_id(dst_ip, dst_port if self.use_ports else None)

        src_stats = self._node_stats.get(src_node)
        dst_stats = self._node_stats.get(dst_node)
        edge_key = (src_node, dst_node)
        edge_stats = self._edge_stats.get(edge_key)

        # Tier 1: Simple metrics (no NetworkX needed)
        features: dict[str, Any] = {
            # Unique connection counts (Tranalyzer compatible)
            "conn_src_unique_dsts": len(src_stats.unique_destinations) if src_stats else 0,
            "conn_dst_unique_srcs": len(dst_stats.unique_sources) if dst_stats else 0,
            "conn_src_dst_flows": edge_stats.flow_count if edge_stats else 0,
            "conn_src_port_flows": edge_stats.port_flows.get(dst_port, 0) if edge_stats else 0,

            # Total flow counts
            "conn_src_total_flows": src_stats.outbound_flows if src_stats else 0,
            "conn_dst_total_flows": dst_stats.inbound_flows if dst_stats else 0,

            # Packet/byte totals
            "conn_src_total_packets": src_stats.total_packets_sent if src_stats else 0,
            "conn_src_total_bytes": src_stats.total_bytes_sent if src_stats else 0,
            "conn_dst_total_packets": dst_stats.total_packets_received if dst_stats else 0,
            "conn_dst_total_bytes": dst_stats.total_bytes_received if dst_stats else 0,

            # Unique port count
            "conn_src_unique_ports": len(src_stats.unique_dst_ports) if src_stats else 0,
        }

        # Tier 2: Graph metrics (requires NetworkX)
        if include_graph_metrics:
            if not self._graph_built and NETWORKX_AVAILABLE:
                self.build_graph()

            if self._graph_built and self._graph is not None:
                # Degree metrics
                features["conn_src_out_degree"] = self._graph.out_degree(src_node) if src_node in self._graph else 0
                features["conn_dst_in_degree"] = self._graph.in_degree(dst_node) if dst_node in self._graph else 0

                # Centrality
                features["conn_src_betweenness"] = self._betweenness.get(src_node, 0.0)
                features["conn_dst_betweenness"] = self._betweenness.get(dst_node, 0.0)

                # Community
                src_community = self._communities.get(src_node, -1)
                dst_community = self._communities.get(dst_node, -1)
                features["conn_src_community"] = src_community
                features["conn_dst_community"] = dst_community
                features["conn_same_community"] = 1 if src_community == dst_community and src_community >= 0 else 0

                # Clustering
                features["conn_src_clustering"] = self._clustering.get(src_node, 0.0)
                features["conn_dst_clustering"] = self._clustering.get(dst_node, 0.0)
            else:
                # NetworkX not available - set defaults
                features["conn_src_out_degree"] = 0
                features["conn_dst_in_degree"] = 0
                features["conn_src_betweenness"] = 0.0
                features["conn_dst_betweenness"] = 0.0
                features["conn_src_community"] = -1
                features["conn_dst_community"] = -1
                features["conn_same_community"] = 0
                features["conn_src_clustering"] = 0.0
                features["conn_dst_clustering"] = 0.0

        # Tier 3: Temporal patterns
        if include_temporal and src_stats:
            duration = src_stats.last_seen - src_stats.first_seen
            if duration > 0:
                features["conn_src_flow_rate"] = src_stats.outbound_flows / duration
            else:
                features["conn_src_flow_rate"] = 0.0

            # Temporal spread (std dev of flow timestamps)
            if len(src_stats.flow_timestamps) > 1:
                mean_ts = sum(src_stats.flow_timestamps) / len(src_stats.flow_timestamps)
                variance = sum((ts - mean_ts) ** 2 for ts in src_stats.flow_timestamps) / len(src_stats.flow_timestamps)
                features["conn_temporal_spread"] = math.sqrt(variance)
            else:
                features["conn_temporal_spread"] = 0.0

            # Burst connections (flows within 1 second window)
            if src_stats.flow_timestamps:
                sorted_ts = sorted(src_stats.flow_timestamps)
                max_burst = 1
                current_burst = 1
                for i in range(1, len(sorted_ts)):
                    if sorted_ts[i] - sorted_ts[i - 1] <= 1.0:
                        current_burst += 1
                        max_burst = max(max_burst, current_burst)
                    else:
                        current_burst = 1
                features["conn_burst_connections"] = max_burst
            else:
                features["conn_burst_connections"] = 0

        return features

    def get_all_feature_names(
        self,
        include_graph_metrics: bool | None = None,
        include_temporal: bool | None = None,
    ) -> list[str]:
        """Get list of all feature names produced.

        Args:
            include_graph_metrics: Override instance setting.
            include_temporal: Override instance setting.

        Returns:
            List of feature names.
        """
        if include_graph_metrics is None:
            include_graph_metrics = self.include_graph_metrics
        if include_temporal is None:
            include_temporal = self.include_temporal

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

        if include_graph_metrics:
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

        if include_temporal:
            names.extend([
                # Tier 3: Temporal patterns
                "conn_src_flow_rate",
                "conn_temporal_spread",
                "conn_burst_connections",
            ])

        return names

    @property
    def node_count(self) -> int:
        """Number of unique nodes in the graph."""
        return len(self._node_stats)

    @property
    def edge_count(self) -> int:
        """Number of unique edges in the graph."""
        return len(self._edge_stats)

    def clear(self) -> None:
        """Clear all accumulated data."""
        self._node_stats.clear()
        self._edge_stats.clear()
        self._graph = None
        self._graph_built = False
        self._betweenness.clear()
        self._communities.clear()
        self._clustering.clear()
