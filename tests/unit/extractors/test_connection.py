"""Tests for connection feature extractor."""

from __future__ import annotations

import pytest

from joyfuljay.analysis.connection_graph import ConnectionGraph, is_networkx_available
from joyfuljay.extractors.connection import ConnectionExtractor

from tests.fixtures.packets import create_connection_flows


class TestConnectionExtractor:
    """Tests for ConnectionExtractor."""

    @pytest.fixture
    def extractor(self) -> ConnectionExtractor:
        """Create a connection extractor with graph metrics disabled."""
        return ConnectionExtractor(include_graph_metrics=False)

    @pytest.fixture
    def extractor_with_graph(self) -> ConnectionExtractor:
        """Create a connection extractor with graph metrics enabled."""
        return ConnectionExtractor(include_graph_metrics=True)

    @pytest.fixture
    def graph(self) -> ConnectionGraph:
        """Create a populated connection graph."""
        graph = ConnectionGraph()
        flows = create_connection_flows(10)
        for flow in flows:
            graph.add_flow(flow)
        return graph

    def test_feature_names(self, extractor: ConnectionExtractor) -> None:
        """Test that feature names are properly defined."""
        names = extractor.feature_names
        assert isinstance(names, list)
        assert len(names) > 0
        # Check some expected feature names
        assert "conn_src_unique_dsts" in names
        assert "conn_dst_unique_srcs" in names

    def test_feature_names_with_graph_metrics(
        self, extractor_with_graph: ConnectionExtractor
    ) -> None:
        """Test feature names include graph metrics when enabled."""
        names = extractor_with_graph.feature_names
        # Should include Tier 2 metrics
        assert "conn_src_out_degree" in names
        assert "conn_src_betweenness" in names
        assert "conn_src_community" in names

    def test_extractor_name(self, extractor: ConnectionExtractor) -> None:
        """Test extractor name."""
        assert extractor.name == "connection"

    def test_requires_graph(self, extractor: ConnectionExtractor) -> None:
        """Test that extractor indicates it requires a graph."""
        assert extractor.requires_graph is True

    def test_extract_without_graph_raises(self, extractor: ConnectionExtractor) -> None:
        """Test that extracting without setting graph raises error."""
        flows = create_connection_flows(1)
        with pytest.raises(RuntimeError, match="ConnectionGraph not set"):
            extractor.extract(flows[0])

    def test_set_graph(
        self, extractor: ConnectionExtractor, graph: ConnectionGraph
    ) -> None:
        """Test setting the graph."""
        extractor.set_graph(graph)
        assert extractor._graph is graph

    def test_extract_simple_metrics(
        self, extractor: ConnectionExtractor, graph: ConnectionGraph
    ) -> None:
        """Test extracting simple (Tier 1) metrics."""
        extractor.set_graph(graph)
        flows = create_connection_flows(5)
        for flow in flows:
            graph.add_flow(flow)

        features = extractor.extract(flows[0])

        # Check that we get expected features
        assert "conn_src_unique_dsts" in features
        assert "conn_dst_unique_srcs" in features
        assert "conn_src_dst_flows" in features
        assert "conn_src_total_flows" in features
        assert "conn_src_total_packets" in features
        assert "conn_src_total_bytes" in features

        # Values should be reasonable
        assert features["conn_src_unique_dsts"] >= 1
        assert features["conn_src_total_flows"] >= 1

    def test_extract_returns_dict(
        self, extractor: ConnectionExtractor, graph: ConnectionGraph
    ) -> None:
        """Test that extract returns a dictionary."""
        extractor.set_graph(graph)
        flows = create_connection_flows(1)
        graph.add_flow(flows[0])

        result = extractor.extract(flows[0])
        assert isinstance(result, dict)


class TestConnectionExtractorWithNetworkX:
    """Tests for ConnectionExtractor with NetworkX metrics.

    These tests are skipped if NetworkX is not installed.
    """

    @pytest.fixture
    def extractor(self) -> ConnectionExtractor:
        """Create extractor with graph metrics enabled."""
        return ConnectionExtractor(
            include_graph_metrics=True,
            include_temporal=False,
        )

    @pytest.fixture
    def graph(self) -> ConnectionGraph:
        """Create a graph with NetworkX enabled."""
        graph = ConnectionGraph(include_graph_metrics=True)
        flows = create_connection_flows(10)
        for flow in flows:
            graph.add_flow(flow)
        if is_networkx_available():
            graph.build_graph()
        return graph

    @pytest.mark.skipif(not is_networkx_available(), reason="NetworkX not installed")
    def test_extract_graph_metrics(
        self, extractor: ConnectionExtractor, graph: ConnectionGraph
    ) -> None:
        """Test extracting graph (Tier 2) metrics."""
        extractor.set_graph(graph)
        flows = create_connection_flows(5)

        features = extractor.extract(flows[0])

        # Check Tier 2 metrics
        assert "conn_src_out_degree" in features
        assert "conn_dst_in_degree" in features
        assert "conn_src_betweenness" in features
        assert "conn_dst_betweenness" in features
        assert "conn_src_community" in features
        assert "conn_dst_community" in features
        assert "conn_same_community" in features
        assert "conn_src_clustering" in features
        assert "conn_dst_clustering" in features


class TestConnectionExtractorTemporal:
    """Tests for ConnectionExtractor with temporal features."""

    @pytest.fixture
    def extractor(self) -> ConnectionExtractor:
        """Create extractor with temporal features enabled."""
        return ConnectionExtractor(
            include_graph_metrics=False,
            include_temporal=True,
        )

    @pytest.fixture
    def graph(self) -> ConnectionGraph:
        """Create a graph with temporal tracking enabled."""
        graph = ConnectionGraph(include_temporal=True)
        flows = create_connection_flows(10)
        for flow in flows:
            graph.add_flow(flow)
        return graph

    def test_feature_names_include_temporal(
        self, extractor: ConnectionExtractor
    ) -> None:
        """Test that temporal feature names are included."""
        names = extractor.feature_names
        assert "conn_src_flow_rate" in names
        assert "conn_temporal_spread" in names
        assert "conn_burst_connections" in names

    def test_extract_temporal_metrics(
        self, extractor: ConnectionExtractor, graph: ConnectionGraph
    ) -> None:
        """Test extracting temporal metrics."""
        extractor.set_graph(graph)
        flows = create_connection_flows(5)

        features = extractor.extract(flows[0])

        # Check temporal metrics exist
        assert "conn_src_flow_rate" in features
        assert "conn_temporal_spread" in features
        assert "conn_burst_connections" in features


class TestConnectionExtractorIntegration:
    """Integration tests for ConnectionExtractor."""

    def test_full_workflow(self) -> None:
        """Test complete workflow: create flows, build graph, extract features."""
        # Create flows
        flows = create_connection_flows(20)

        # Build graph
        graph = ConnectionGraph(
            include_graph_metrics=False,  # No NetworkX required
            include_temporal=True,
        )
        for flow in flows:
            graph.add_flow(flow)

        # Create extractor and inject graph
        extractor = ConnectionExtractor(
            include_graph_metrics=False,
            include_temporal=True,
        )
        extractor.set_graph(graph)

        # Extract features for all flows
        all_features = []
        for flow in flows:
            features = extractor.extract(flow)
            all_features.append(features)

        # Verify all flows got features
        assert len(all_features) == 20

        # Verify each feature dict has expected keys
        expected_keys = [
            "conn_src_unique_dsts",
            "conn_src_total_flows",
            "conn_src_flow_rate",
        ]
        for features in all_features:
            for key in expected_keys:
                assert key in features

    def test_reuse_extractor(self) -> None:
        """Test reusing extractor with new graph."""
        extractor = ConnectionExtractor(include_graph_metrics=False)

        # First graph
        graph1 = ConnectionGraph()
        flows1 = create_connection_flows(5)
        for flow in flows1:
            graph1.add_flow(flow)
        extractor.set_graph(graph1)
        features1 = extractor.extract(flows1[0])

        # Second graph (new flows)
        graph2 = ConnectionGraph()
        flows2 = create_connection_flows(10)
        for flow in flows2:
            graph2.add_flow(flow)
        extractor.set_graph(graph2)
        features2 = extractor.extract(flows2[0])

        # Both should work and give valid results
        assert features1["conn_src_total_flows"] > 0
        assert features2["conn_src_total_flows"] > 0
