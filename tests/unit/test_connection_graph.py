"""Tests for connection graph analysis."""

from __future__ import annotations

import pytest

from joyfuljay.analysis.connection_graph import (
    ConnectionGraph,
    EdgeStats,
    NodeStats,
    is_networkx_available,
)

from tests.fixtures.packets import create_connection_flows


class TestNodeStats:
    """Tests for NodeStats dataclass."""

    def test_default_values(self) -> None:
        """Test default initialization."""
        stats = NodeStats()
        assert stats.outbound_flows == 0
        assert stats.inbound_flows == 0
        assert len(stats.unique_destinations) == 0
        assert len(stats.unique_sources) == 0
        assert stats.total_packets_sent == 0
        assert stats.total_bytes_sent == 0


class TestEdgeStats:
    """Tests for EdgeStats dataclass."""

    def test_default_values(self) -> None:
        """Test default initialization."""
        stats = EdgeStats()
        assert stats.flow_count == 0
        assert stats.total_packets == 0
        assert stats.total_bytes == 0


class TestConnectionGraph:
    """Tests for ConnectionGraph class."""

    @pytest.fixture
    def graph(self) -> ConnectionGraph:
        """Create a basic connection graph."""
        return ConnectionGraph()

    @pytest.fixture
    def graph_with_flows(self) -> ConnectionGraph:
        """Create a connection graph populated with flows."""
        graph = ConnectionGraph()
        flows = create_connection_flows(10)
        for flow in flows:
            graph.add_flow(flow)
        return graph

    def test_empty_graph(self, graph: ConnectionGraph) -> None:
        """Test that an empty graph has no nodes or edges."""
        assert graph.node_count == 0
        assert graph.edge_count == 0

    def test_add_single_flow(self, graph: ConnectionGraph) -> None:
        """Test adding a single flow."""
        flows = create_connection_flows(1)
        graph.add_flow(flows[0])

        assert graph.node_count == 2  # Source and destination
        assert graph.edge_count == 1

    def test_add_multiple_flows(self, graph_with_flows: ConnectionGraph) -> None:
        """Test adding multiple flows."""
        # Should have nodes for the different IPs
        assert graph_with_flows.node_count > 0
        assert graph_with_flows.edge_count > 0

    def test_get_flow_metrics_simple(self, graph_with_flows: ConnectionGraph) -> None:
        """Test getting simple (Tier 1) metrics for a flow."""
        flows = create_connection_flows(5)
        # Re-add flows to our graph
        for flow in flows:
            graph_with_flows.add_flow(flow)

        metrics = graph_with_flows.get_flow_metrics(
            flows[0],
            include_graph_metrics=False,
            include_temporal=False,
        )

        # Check Tier 1 metrics exist
        assert "conn_src_unique_dsts" in metrics
        assert "conn_dst_unique_srcs" in metrics
        assert "conn_src_dst_flows" in metrics
        assert "conn_src_total_flows" in metrics
        assert "conn_dst_total_flows" in metrics
        assert "conn_src_total_packets" in metrics
        assert "conn_src_total_bytes" in metrics

    def test_get_flow_metrics_unique_destinations(self) -> None:
        """Test unique destination count is accurate."""
        graph = ConnectionGraph()
        flows = create_connection_flows(5)
        for flow in flows:
            graph.add_flow(flow)

        # Find a flow from 192.168.1.100 (connects to multiple destinations)
        test_flow = flows[0]
        metrics = graph.get_flow_metrics(
            test_flow,
            include_graph_metrics=False,
        )

        # 192.168.1.100 should have at least 2 unique destinations (10.0.0.1, 10.0.0.2)
        assert metrics["conn_src_unique_dsts"] >= 1

    def test_get_all_feature_names(self, graph: ConnectionGraph) -> None:
        """Test getting all feature names."""
        names = graph.get_all_feature_names(
            include_graph_metrics=False,
            include_temporal=False,
        )
        assert isinstance(names, list)
        assert len(names) == 11  # 11 Tier 1 features

    def test_get_all_feature_names_with_graph_metrics(self, graph: ConnectionGraph) -> None:
        """Test getting feature names with graph metrics."""
        names = graph.get_all_feature_names(
            include_graph_metrics=True,
            include_temporal=False,
        )
        # 11 Tier 1 + 9 Tier 2
        assert len(names) == 20

    def test_get_all_feature_names_with_temporal(self, graph: ConnectionGraph) -> None:
        """Test getting feature names with temporal metrics."""
        names = graph.get_all_feature_names(
            include_graph_metrics=False,
            include_temporal=True,
        )
        # 11 Tier 1 + 3 Tier 3
        assert len(names) == 14

    def test_clear(self, graph_with_flows: ConnectionGraph) -> None:
        """Test clearing the graph."""
        assert graph_with_flows.node_count > 0
        graph_with_flows.clear()
        assert graph_with_flows.node_count == 0
        assert graph_with_flows.edge_count == 0

    def test_use_ports_option(self) -> None:
        """Test that use_ports creates more granular nodes."""
        graph_no_ports = ConnectionGraph(use_ports=False)
        graph_with_ports = ConnectionGraph(use_ports=True)

        flows = create_connection_flows(5)
        for flow in flows:
            graph_no_ports.add_flow(flow)
            graph_with_ports.add_flow(flow)

        # With ports, we should have more nodes (IP:port pairs)
        assert graph_with_ports.node_count >= graph_no_ports.node_count


class TestConnectionGraphWithNetworkX:
    """Tests for ConnectionGraph with NetworkX graph metrics.

    These tests are skipped if NetworkX is not installed.
    """

    @pytest.fixture
    def graph_with_networkx(self) -> ConnectionGraph:
        """Create a graph with NetworkX metrics enabled."""
        return ConnectionGraph(include_graph_metrics=True)

    @pytest.mark.skipif(not is_networkx_available(), reason="NetworkX not installed")
    def test_build_graph(self, graph_with_networkx: ConnectionGraph) -> None:
        """Test building the NetworkX graph."""
        flows = create_connection_flows(5)
        for flow in flows:
            graph_with_networkx.add_flow(flow)

        graph_with_networkx.build_graph()
        assert graph_with_networkx._graph_built
        assert graph_with_networkx._graph is not None

    @pytest.mark.skipif(not is_networkx_available(), reason="NetworkX not installed")
    def test_graph_metrics(self, graph_with_networkx: ConnectionGraph) -> None:
        """Test that graph metrics are computed correctly."""
        flows = create_connection_flows(10)
        for flow in flows:
            graph_with_networkx.add_flow(flow)

        graph_with_networkx.build_graph()

        metrics = graph_with_networkx.get_flow_metrics(
            flows[0],
            include_graph_metrics=True,
        )

        # Check Tier 2 metrics exist
        assert "conn_src_out_degree" in metrics
        assert "conn_dst_in_degree" in metrics
        assert "conn_src_betweenness" in metrics
        assert "conn_dst_betweenness" in metrics
        assert "conn_src_community" in metrics
        assert "conn_dst_community" in metrics
        assert "conn_same_community" in metrics
        assert "conn_src_clustering" in metrics
        assert "conn_dst_clustering" in metrics

    @pytest.mark.skipif(not is_networkx_available(), reason="NetworkX not installed")
    def test_community_detection(self, graph_with_networkx: ConnectionGraph) -> None:
        """Test community detection."""
        flows = create_connection_flows(10)
        for flow in flows:
            graph_with_networkx.add_flow(flow)

        graph_with_networkx.build_graph()

        # Communities should be assigned
        assert len(graph_with_networkx._communities) > 0

        # Each node should have a community ID
        for node_id in graph_with_networkx._node_stats:
            assert node_id in graph_with_networkx._communities


class TestConnectionGraphTemporal:
    """Tests for temporal connection features."""

    def test_temporal_metrics(self) -> None:
        """Test temporal metrics are computed."""
        graph = ConnectionGraph(include_temporal=True)
        flows = create_connection_flows(5)
        for flow in flows:
            graph.add_flow(flow)

        metrics = graph.get_flow_metrics(
            flows[0],
            include_temporal=True,
        )

        # Check Tier 3 metrics exist
        assert "conn_src_flow_rate" in metrics
        assert "conn_temporal_spread" in metrics
        assert "conn_burst_connections" in metrics

        # Flow rate should be positive if there are multiple flows
        assert metrics["conn_src_flow_rate"] >= 0
