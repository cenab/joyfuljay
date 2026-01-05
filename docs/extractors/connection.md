# ConnectionExtractor

The `ConnectionExtractor` analyzes relationships between network flows to provide graph-based features. These features capture how hosts communicate with each other, identifying patterns like fan-out (one source connecting to many destinations), central nodes, and community structures.

---

## Overview

Unlike other extractors that analyze individual flows in isolation, the `ConnectionExtractor` considers the entire traffic graph. It can identify:

- **Scanning behavior**: High fan-out from a single source
- **Server endpoints**: High fan-in to a single destination
- **Communication communities**: Groups of hosts that frequently communicate
- **Central nodes**: Hosts that connect different parts of the network

---

## Requirements

The `ConnectionExtractor` requires the optional `graphs` dependency:

```bash
pip install joyfuljay[graphs]
```

This installs NetworkX for graph analysis.

---

## Features

### Tier 1: Simple Metrics (No Dependencies)

These features work without NetworkX:

| Feature | Type | Description |
|---------|------|-------------|
| `conn_src_unique_dsts` | int | Number of unique destinations from this source |
| `conn_dst_unique_srcs` | int | Number of unique sources to this destination |
| `conn_src_dst_flows` | int | Number of flows between this exact source-destination pair |
| `conn_src_port_flows` | int | Number of flows to this specific destination port |
| `conn_src_total_flows` | int | Total outbound flows from source |
| `conn_dst_total_flows` | int | Total inbound flows to destination |
| `conn_src_total_packets` | int | Total packets sent by source across all flows |
| `conn_src_total_bytes` | int | Total bytes sent by source across all flows |
| `conn_dst_total_packets` | int | Total packets received by destination across all flows |
| `conn_dst_total_bytes` | int | Total bytes received by destination across all flows |
| `conn_src_unique_ports` | int | Number of unique destination ports from source |

### Tier 2: Graph Metrics (Requires NetworkX)

These features provide deeper graph analysis:

| Feature | Type | Description |
|---------|------|-------------|
| `conn_src_out_degree` | int | Out-degree of source node in the graph |
| `conn_dst_in_degree` | int | In-degree of destination node in the graph |
| `conn_src_betweenness` | float | Betweenness centrality of source (0-1) |
| `conn_dst_betweenness` | float | Betweenness centrality of destination (0-1) |
| `conn_src_community` | int | Community ID of source |
| `conn_dst_community` | int | Community ID of destination |
| `conn_same_community` | bool | Whether source and destination are in the same community |
| `conn_src_clustering` | float | Clustering coefficient of source (0-1) |
| `conn_dst_clustering` | float | Clustering coefficient of destination (0-1) |

### Tier 3: Temporal Metrics (Optional)

| Feature | Type | Description |
|---------|------|-------------|
| `conn_src_flow_rate` | float | Flows per second from source |
| `conn_temporal_spread` | float | Time span of source's connections (seconds) |
| `conn_burst_connections` | int | Maximum connections in any 1-second window |

---

## Usage

### Basic Usage

```python
import joyfuljay as jj

# Enable connection features
config = jj.Config(features=["flow_meta", "timing", "connection"])
pipeline = jj.Pipeline(config)

# Process PCAP - connection graph is built automatically
df = pipeline.process_pcap("capture.pcap")

# Connection features are included in the output
print(df[['conn_src_unique_dsts', 'conn_dst_unique_srcs']].head())
```

### With Configuration Options

```python
import joyfuljay as jj

config = jj.Config(
    features=["connection"],
    connection_include_graph_metrics=True,  # Enable Tier 2 features
    connection_include_temporal=True,  # Enable Tier 3 features
    connection_community_algorithm="louvain",  # Community detection algorithm
)

pipeline = jj.Pipeline(config)
df = pipeline.process_pcap("capture.pcap")
```

### Without NetworkX (Tier 1 Only)

If NetworkX is not installed, only Tier 1 features are available:

```python
import joyfuljay as jj

config = jj.Config(
    features=["connection"],
    connection_include_graph_metrics=False,  # Disable graph metrics
)

pipeline = jj.Pipeline(config)
df = pipeline.process_pcap("capture.pcap")
```

---

## Use Cases

### Detecting Port Scanning

High `conn_src_unique_dsts` combined with high `conn_src_unique_ports` indicates scanning:

```python
import joyfuljay as jj

df = jj.extract("capture.pcap", features=["flow_meta", "connection"])

# Find potential scanners
scanners = df[
    (df['conn_src_unique_dsts'] > 10) &
    (df['conn_src_unique_ports'] > 5)
]
print(f"Potential scanners: {scanners['src_ip'].unique()}")
```

### Identifying Server Endpoints

High `conn_dst_unique_srcs` indicates a server receiving connections from many clients:

```python
import joyfuljay as jj

df = jj.extract("capture.pcap", features=["flow_meta", "connection"])

# Find likely servers (high fan-in)
servers = df[df['conn_dst_unique_srcs'] > 10]
print(servers.groupby('dst_ip')['conn_dst_unique_srcs'].max())
```

### Community Detection

Identify groups of hosts that frequently communicate:

```python
import joyfuljay as jj

config = jj.Config(
    features=["flow_meta", "connection"],
    connection_include_graph_metrics=True,
)
pipeline = jj.Pipeline(config)
df = pipeline.process_pcap("capture.pcap")

# Analyze community structure
communities = df.groupby('conn_src_community').size()
print(f"Found {len(communities)} communities")

# Flows within same community vs. cross-community
same_community = df['conn_same_community'].mean()
print(f"{same_community:.1%} of flows are within-community")
```

### Finding Central Nodes

Nodes with high betweenness centrality are important for network connectivity:

```python
import joyfuljay as jj

config = jj.Config(
    features=["flow_meta", "connection"],
    connection_include_graph_metrics=True,
)
pipeline = jj.Pipeline(config)
df = pipeline.process_pcap("capture.pcap")

# Find high-centrality nodes
central_sources = df.nlargest(10, 'conn_src_betweenness')[
    ['src_ip', 'conn_src_betweenness']
].drop_duplicates()
print("Most central source hosts:")
print(central_sources)
```

---

## Understanding Graph Metrics

### Betweenness Centrality

Measures how often a node appears on shortest paths between other nodes. High values indicate nodes that act as bridges or gateways.

- **Range**: 0 to 1
- **High value**: Node connects different parts of the network
- **Low value**: Node is at the periphery

### Clustering Coefficient

Measures how connected a node's neighbors are to each other.

- **Range**: 0 to 1
- **High value**: Node's connections form tight-knit groups
- **Low value**: Node's connections are spread across the network

### Community Detection

Groups nodes that have more connections within the group than outside. Algorithms available:

- **louvain** (default): Fast, hierarchical community detection
- **greedy**: Modularity-based greedy algorithm
- **label_propagation**: Fast semi-supervised approach

---

## Important Notes

### Two-Phase Processing

The `ConnectionExtractor` requires all flows to be collected before analysis. This means:

1. **Not available in streaming mode**: Cannot be used with `iter_features()` or live streaming
2. **Memory usage**: Entire graph must fit in memory
3. **Processing order**: Graph is built in the first pass, then features are computed

### Performance Considerations

- Tier 1 features are O(1) lookups
- Tier 2 features require graph construction (O(n) for nodes, O(m) for edges)
- Betweenness centrality can be slow for large graphs (O(n*m))
- Community detection is typically O(m) to O(n*m)

For very large captures (millions of flows), consider:
- Disabling `include_graph_metrics`
- Sampling flows before analysis
- Processing in time windows

---

## See Also

- [Features Reference](../features.md) - Complete feature documentation
- [Configuration](../configuration.md) - All configuration options
- [Architecture](../architecture.md) - Pipeline design details
