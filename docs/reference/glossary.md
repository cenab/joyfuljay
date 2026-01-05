# Glossary

A comprehensive glossary of terms used throughout the JoyfulJay documentation.

---

## A

### ALPN
**Application-Layer Protocol Negotiation**. A TLS extension that allows the application layer to negotiate which protocol should be performed over a secure connection. JoyfulJay extracts ALPN values from TLS handshakes.

### Anomaly Detection
The identification of unusual patterns in network traffic that do not conform to expected behavior. JoyfulJay features are designed to enable ML-based anomaly detection.

---

## B

### Backend
A capture backend in JoyfulJay is a module responsible for reading packets from PCAP files or network interfaces. Available backends include Scapy (default), DPKT (fast), and Remote (network streaming).

### BPF Filter
**Berkeley Packet Filter**. A filtering mechanism for network packets. JoyfulJay supports BPF filter expressions like `tcp port 443` to capture only specific traffic.

### Burst
A sequence of packets with small inter-arrival times. JoyfulJay calculates burst metrics including `burst_count`, `burst_mean_size`, and `burst_duration`.

### Bidirectional Flow
A flow that includes packets in both directions (client-to-server and server-to-client). JoyfulJay aggregates bidirectional flows by default.

---

## C

### Cipher Suite
A set of cryptographic algorithms used for TLS/SSL connections. JoyfulJay extracts cipher suite information from TLS handshakes for fingerprinting.

### ClientHello
The first message sent by a TLS client during the handshake. JoyfulJay parses ClientHello messages to extract JA3 fingerprints.

### Connection Graph
A graph representation of network connections where nodes are IP addresses and edges are flows. JoyfulJay can compute graph metrics using NetworkX.

---

## D

### DataFrame
A pandas DataFrame is the default output format for JoyfulJay. Each row represents a flow, and each column represents a feature.

### DoH
**DNS over HTTPS**. A protocol for performing DNS resolution via HTTPS. JoyfulJay's fingerprint extractor can detect DoH traffic patterns.

### DPKT
A fast Python packet parsing library. JoyfulJay's DPKT backend offers ~10x faster processing than the default Scapy backend.

---

## E

### Entropy
A measure of randomness in data. JoyfulJay calculates payload entropy to help distinguish encrypted traffic from plaintext.

### Extractor
A module in JoyfulJay that computes specific features from flow data. There are 24 built-in extractors covering different aspects of network traffic.

### Eviction Strategy
The method used to remove flows from the flow table when limits are reached. Options are `lru` (Least Recently Used) or `oldest` (by start time).

---

## F

### Feature
A numeric or categorical value extracted from network traffic that can be used for machine learning. JoyfulJay extracts 387 features.

### Feature Group
A logical grouping of related features. Groups include `timing`, `size`, `tls`, `tcp`, `fingerprint`, etc.

### Five-Tuple
The combination of source IP, destination IP, source port, destination port, and protocol that uniquely identifies a flow.

### Flow
A bidirectional network conversation identified by a five-tuple. Flows are the primary unit of analysis in JoyfulJay.

### Flow ID
A unique identifier for a flow, typically a hash of the five-tuple. Used to correlate flows without exposing IP addresses.

### Flow Table
The internal data structure that tracks active flows. Manages flow creation, packet aggregation, and expiration.

### Flow Timeout
The duration of inactivity after which a flow is considered complete. Default is 60 seconds.

---

## G

### Grafana
An open-source platform for monitoring and observability. JoyfulJay can export metrics to Prometheus for visualization in Grafana.

---

## H

### HASSH
A fingerprinting method for SSH clients and servers based on key exchange parameters. Similar to JA3 for TLS.

### HASSH Server
The server-side HASSH fingerprint extracted from SSH server responses.

---

## I

### IAT
**Inter-Arrival Time**. The time between consecutive packets in a flow. JoyfulJay calculates IAT statistics including mean, standard deviation, min, max, and percentiles.

### ICMP
**Internet Control Message Protocol**. Used for network diagnostics (ping, traceroute). JoyfulJay extracts ICMP type, code, and echo metrics.

---

## J

### JA3
A method for fingerprinting TLS clients based on the ClientHello message. The JA3 hash is computed from TLS version, cipher suites, extensions, elliptic curves, and EC point formats.

### JA3S
The server-side counterpart to JA3, fingerprinting TLS servers based on the ServerHello message.

### Jupyter
JoyfulJay integrates with Jupyter notebooks for interactive analysis and visualization.

---

## K

### Kafka
Apache Kafka is a distributed streaming platform. JoyfulJay can stream features directly to Kafka topics for real-time processing.

---

## L

### Layer 2
The data link layer of the OSI model. JoyfulJay's MAC extractor captures Layer 2 information including MAC addresses and VLAN tags.

### Live Capture
Real-time packet capture from a network interface, as opposed to processing PCAP files.

### LRU
**Least Recently Used**. An eviction strategy that removes the flow that hasn't seen traffic for the longest time.

---

## M

### MAC Address
**Media Access Control** address. A unique identifier for network interfaces. JoyfulJay can extract source and destination MAC addresses.

### mDNS
**Multicast DNS**. Used by JoyfulJay for zero-configuration discovery of remote capture servers on the local network.

### ML-Ready
Features formatted and preprocessed for direct use in machine learning models. JoyfulJay outputs are designed to be ML-ready.

### MPTCP
**Multipath TCP**. An extension to TCP that allows multiple paths for a single connection. JoyfulJay extracts MPTCP-related features.

### MSS
**Maximum Segment Size**. The largest amount of data that can be received in a single TCP segment. Extracted from TCP options.

---

## N

### NetworkX
A Python library for network analysis. JoyfulJay uses NetworkX (optional) for connection graph analysis and community detection.

### NumPy
A Python library for numerical computing. JoyfulJay can output features as NumPy arrays for direct use in ML pipelines.

---

## P

### Packet
A unit of data transmitted over a network. JoyfulJay analyzes packet headers and metadata without decrypting payload content.

### Parquet
A columnar storage format. JoyfulJay can output features in Parquet format for efficient big data processing.

### PCAP
**Packet Capture**. A file format for storing captured network packets. JoyfulJay processes both PCAP and PCAPNG files.

### Pipeline
The main processing object in JoyfulJay that orchestrates packet capture, flow management, feature extraction, and output formatting.

### Prometheus
An open-source monitoring system. JoyfulJay can export processing metrics to Prometheus for monitoring.

---

## Q

### QUIC
**Quick UDP Internet Connections**. A transport protocol developed by Google, used by HTTP/3. JoyfulJay extracts QUIC-specific features including version and connection IDs.

---

## R

### Remote Capture
JoyfulJay's capability to capture packets from remote devices over a secure WebSocket connection.

### RTT
**Round-Trip Time**. The time for a packet to travel from source to destination and back. JoyfulJay estimates RTT from TCP acknowledgments.

---

## S

### Scapy
A Python packet manipulation library. JoyfulJay's default capture backend uses Scapy for comprehensive protocol parsing.

### ServerHello
The TLS server's response to a ClientHello, containing selected cipher suite and other parameters. Used for JA3S fingerprinting.

### SNI
**Server Name Indication**. A TLS extension that specifies the hostname being connected to. Extracted by JoyfulJay's TLS extractor.

### SPLT
**Sequence of Packet Lengths and Times**. A representation of flow data as sequences, useful for deep learning models.

### Streaming
JoyfulJay's ability to process packets and output features in a streaming fashion without loading entire files into memory.

---

## T

### TCP Flags
Control bits in TCP headers (SYN, ACK, FIN, RST, PSH, URG). JoyfulJay analyzes flag patterns for flow characterization.

### TLS
**Transport Layer Security**. A cryptographic protocol for secure communication. JoyfulJay extracts extensive TLS metadata without decryption.

### Tor
**The Onion Router**. An anonymity network. JoyfulJay's fingerprint extractor can detect Tor traffic patterns.

### Traffic Classification
The process of categorizing network traffic into types (e.g., web, video, VoIP). JoyfulJay features are designed for ML-based classification.

### Tranalyzer
A network traffic analysis tool. JoyfulJay provides feature compatibility with Tranalyzer2.

---

## V

### VLAN
**Virtual Local Area Network**. JoyfulJay extracts VLAN tags from 802.1Q frames.

### VPN
**Virtual Private Network**. JoyfulJay's fingerprint extractor can detect VPN traffic patterns.

---

## W

### WebSocket
A communication protocol providing full-duplex channels over TCP. JoyfulJay uses WebSocket for remote capture streaming.

### Window Size
The TCP receive window size, indicating how much data the receiver can accept. JoyfulJay extracts window size statistics.

---

## Z

### Zero-RTT
A TLS 1.3 feature allowing data transmission in the first flight. JoyfulJay detects zero-RTT QUIC connections.

### Zeroconf
Zero-configuration networking. JoyfulJay uses zeroconf (mDNS) for discovering remote capture servers.

---

## See Also

- [Feature Reference](../features/complete-reference.md) - Complete list of all features
- [FAQ](faq.md) - Frequently asked questions
- [API Reference](../api-reference/index.md) - Technical API documentation
