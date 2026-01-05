<div align="center">

# JoyfulJay Roadmap & Improvements

**Encrypted Traffic Feature Extraction Library**

[![Status](https://img.shields.io/badge/Status-Active%20Development-brightgreen)]()
[![Version](https://img.shields.io/badge/Version-0.1.0--beta-blue)]()

</div>

---

## Overview

| Metric | Count |
|:-------|------:|
| Total Items | 63 |
| Completed | 60 |
| In Progress | 0 |
| Remaining | 3 |

```
Progress: [███████████████████░] 95%
```

**Remaining Items:**
- #26 SQLite/PostgreSQL - Deferred (user choice)
- #41 Sandboxed parsing - Deferred (major architectural effort)
- #43 Audit logging - Not yet implemented

---

## Legend

| Symbol | Meaning |
|:------:|:--------|
| ✅ | Completed |
| 🔄 | In Progress |
| ⬚ | Not Started |
| 🔴 | Critical Priority |
| 🟠 | High Priority |
| 🟡 | Medium Priority |
| 🟢 | Low Priority |
| ⚡ | Quick Win (< 1 day) |
| 🏗️ | Major Effort (> 1 week) |

**Effort Scale:**
- `Low` = Hours to 1 day
- `Medium` = 2-5 days
- `High` = 1+ weeks

---

## 🔴 Critical Fixes

> Issues that affect correctness or completeness of core functionality

| # | Status | Improvement | Impact | Effort | Tags |
|:-:|:------:|:------------|:-------|:------:|:-----|
| 1 | ✅ | **SSH HASSH computation buggy** — field ordering/selection incorrect | Fingerprinting accuracy | `Low` | ⚡ |
| 2 | ✅ | **DoH detection false positives** — heuristics too broad, matches normal HTTPS | Fingerprinting accuracy | `Medium` | |
| 3 | ✅ | **TLS DH parameter extraction** — mentioned in spec but not implemented | Feature completeness | `Medium` | |
| 4 | ✅ | **QUIC packet number length** — important fingerprint signal not extracted | Feature completeness | `Low` | ⚡ |

---

## ⚡ Performance

> Optimizations for speed, memory, and efficiency

| # | Status | Improvement | Impact | Effort | Tags |
|:-:|:------:|:------------|:-------|:------:|:-----|
| 5 | ✅ | **dpkt backend option** — 10x faster than Scapy for large PCAPs | Major speedup | `Medium` | 🟠 |
| 6 | ✅ | **Streaming output** — avoid OOM on large captures (millions of flows) | Memory efficiency | `Medium` | 🟠 |
| 7 | ✅ | **Cython extensions** — native code for statistics, entropy, byte analysis | 25-50x speedup | `High` | 🏗️ |
| 8 | ✅ | **Cross-platform efficient PID filtering** — eBPF (Linux), ETW (Windows), nettop/lsof (macOS), /proc (Android) | Much more efficient | `High` | 🏗️ |
| 9 | ✅ | **Process name filtering** — `--process chrome` instead of `--pid 12345` | Usability | `Low` | ⚡ |

---

## 🆕 Feature Additions

> New capabilities and extractors

| # | Status | Feature | Description | Effort | Tags |
|:-:|:------:|:--------|:------------|:------:|:-----|
| 10 | ✅ | **DNS extraction** | Query names, types, TTLs, response codes | `Medium` | 🟠 |
| 11 | ✅ | **HTTP/2 & HTTP/3** | Frame detection, server push, multiplexing | `Medium` | |
| 12 | ✅ | **Certificate chain** | Subject/issuer/CN, validation, CT logs | `Medium` | |
| 13 | ✅ | **Entropy extractor** | Payload entropy (feature group exists, not implemented) | `Low` | ⚡ |
| 14 | ✅ | **TCP analysis extractor** | TCP flags, handshake detection, anomalies | `Medium` | |
| 15 | ✅ | **Bidirectional splitting** | Separate fwd/bwd feature sets option | `Low` | ⚡ |
| 16 | ✅ | **Connection graphs** | Fan-out, temporal patterns, communities | `High` | 🏗️ |
| 17 | ✅ | **Labeled data support** | Accept labels with PCAPs for ML training | `Medium` | |

---

## 🔬 Tranalyzer-Compatible Features

> Comprehensive feature set matching Tranalyzer's ~100+ flow features for research compatibility

| # | Status | Category | Features | Effort | Tags |
|:-:|:------:|:---------|:---------|:------:|:-----|
| 44 | ✅ | **Flow Metadata** | `flowInd`, `flowStat`, `timeFirst`, `timeLast`, `duration`, `numHdrDesc`, `numHdrs`, `hdrDesc` | `Low` | ⚡ |
| 45 | ✅ | **Layer 2 (MAC)** | `srcMac`, `dstMac`, `ethType`, `vlanID`, `macStat`, `macPairs`, `srcMac_dstMac_numP`, `srcMacLbl_dstMacLbl` | `Medium` | |
| 46 | ✅ | **Layer 3 (IP) Extended** | `srcIPCC`, `srcIPOrg`, `dstIPCC`, `dstIPOrg` (GeoIP), `ipMindIPID`, `ipMaxdIPID`, `ipMinTTL`, `ipMaxTTL`, `ipTTLChg`, `ipToS`, `ipFlags`, `ipOptCnt`, `ipOptCpCl_Num` | `Medium` | |
| 47 | ✅ | **IPv6 Options** | `ip6OptCntHH_D`, `ip6OptHH_D` | `Low` | ⚡ |
| 48 | ✅ | **Port Classification** | `dstPortClassN`, `dstPortClass` (well-known port labeling) | `Low` | ⚡ |
| 49 | ✅ | **L7 Byte Stats** | `padBytesSnt`, `l7BytesSnt`, `l7BytesRcvd`, `minL7PktSz`, `maxL7PktSz`, `avgL7PktSz`, `stdL7PktSz` | `Low` | ⚡ |
| 50 | ✅ | **Asymmetry Metrics** | `pktAsm`, `bytAsm` (packet/byte asymmetry ratios) | `Low` | ⚡ |
| 51 | ✅ | **TCP Sequence Analysis** | `tcpISeqN`, `tcpPSeqCnt`, `tcpSeqSntBytes`, `tcpSeqFaultCnt`, `tcpPAckCnt`, `tcpFlwLssAckRcvdBytes`, `tcpAckFaultCnt` | `Medium` | |
| 52 | ✅ | **TCP Window Analysis** | `tcpInitWinSz`, `tcpAvgWinSz`, `tcpMinWinSz`, `tcpMaxWinSz`, `tcpWinSzDwnCnt`, `tcpWinSzUpCnt`, `tcpWinSzChgDirCnt`, `tcpWinSzThRt`, `tcpBFlgtMx` | `Medium` | |
| 53 | ✅ | **TCP Flags & Anomalies** | `tcpFStat`, `tcpFlags`, `tcpAnomaly`, `tcpStatesAFlags` | `Low` | ⚡ |
| 54 | ✅ | **TCP Options** | `tcpOptPktCnt`, `tcpOptCnt`, `tcpOptions`, `tcpMSS`, `tcpWS`, `tcpTmS`, `tcpTmER`, `tcpEcI` | `Medium` | |
| 55 | ✅ | **TCP Multipath** | `tcpMPTBF`, `tcpMPF`, `tcpMPAID`, `tcpMPDSSF` | `Medium` | |
| 56 | ✅ | **TCP RTT Metrics** | `tcpSSASAATrip`, `tcpRTTAckTripMin`, `tcpRTTAckTripMax`, `tcpRTTAckTripAvg`, `tcpRTTAckTripJitAvg`, `tcpRTTSseqAA`, `tcpRTTAckJitAvg` | `Medium` | |
| 57 | ✅ | **TCP Fingerprinting** | `tcpJA4T`, `tcpUtm`, `tcpBtm` (uptime/boot time estimation) | `Medium` | |
| 58 | ✅ | **ICMP Features** | `icmpStat`, `icmpTCcnt`, `icmpBFTypH_TypL_Code`, `icmpTmGtw`, `icmpEchoSuccRatio`, `icmpPFindex` | `Medium` | |
| 59 | ✅ | **Connection Graphs** | `connSip`, `connDip`, `connSipDip`, `connSipDprt`, `connF`, `connG`, `connNumPCnt`, `connNumBCnt` | `High` | 🏗️ |

### Tranalyzer Compatibility Mode

When enabled (`--features tranalyzer`), outputs all ~100+ features in Tranalyzer-compatible CSV format:

```bash
# Enable Tranalyzer-compatible output
jj extract capture.pcap --features tranalyzer -o features.csv

# Combine with JoyfulJay-specific features
jj extract capture.pcap --features tranalyzer,tls,fingerprint -o features.csv
```

**Benefits:**
- Direct comparison with Tranalyzer on same datasets
- Migration of existing Tranalyzer ML pipelines to JoyfulJay
- Reproduction of published research using Tranalyzer features
- Academic research compatibility

---

## 🎨 Usability & Developer Experience

> Making JoyfulJay easier and more pleasant to use

| # | Status | Improvement | Description | Effort | Tags |
|:-:|:------:|:------------|:------------|:------:|:-----|
| 18 | ✅ | **Progress bars** | tqdm/rich for large PCAP processing | `Low` | ⚡ 🟠 |
| 19 | ✅ | **Config file loading** | Load settings from YAML/JSON | `Low` | ⚡ |
| 20 | ✅ | **Feature schema export** | `jj schema` — names, types, descriptions | `Low` | ⚡ |
| 21 | ✅ | **Specific feature selection** | `--feature ja3_hash` not just groups | `Low` | ⚡ |
| 22 | ✅ | **Watch mode** | Monitor directory, auto-process new PCAPs | `Medium` | |
| 23 | ✅ | **Interactive REPL** | Explore PCAP contents interactively | `Medium` | |
| 24 | ✅ | **Jupyter widgets** | Interactive visualization in notebooks | `Medium` | |

---

## 📊 Output & Integration

> Export formats and external system integration

| # | Status | Improvement | Description | Effort | Tags |
|:-:|:------:|:------------|:------------|:------:|:-----|
| 25 | ✅ | **Parquet output** | Columnar format for big data pipelines | `Low` | ⚡ 🟠 |
| 26 | ⬚ | **SQLite/PostgreSQL** | Direct database insertion | `Medium` | |
| 27 | ✅ | **Kafka streaming** | Real-time feature streaming to queues | `Medium` | |
| 28 | ✅ | **Prometheus metrics** | Export processing metrics for monitoring | `Low` | ⚡ |
| 29 | ✅ | **Grafana dashboard** | Pre-built visualization dashboard with 20+ panels | `Medium` | |

---

## 🌐 Remote Capture

> Enhancements for the remote capture server/client

| # | Status | Improvement | Description | Effort | Tags |
|:-:|:------:|:------------|:------------|:------:|:-----|
| 30 | ✅ | **TLS/WSS encryption** | Secure WebSocket with certificate support | `Medium` | 🟠 |
| 31 | ✅ | **Stream compression** | LZ4/zstd for bandwidth efficiency | `Low` | ⚡ |
| 32 | ✅ | **Auto-reconnection** | Reconnect on drops with exponential backoff | `Low` | ⚡ |
| 33 | ✅ | **Server discovery** | mDNS/Bonjour for automatic LAN discovery | `Medium` | |
| 34 | ✅ | **Multi-client support** | Multiple clients receive same stream (max 5) | `Medium` | |
| 35 | ✅ | **Bandwidth throttling** | Limit streaming bandwidth usage | `Low` | ⚡ |

---

## 🧪 Testing & Quality

> Test coverage and quality assurance

| # | Status | Improvement | Description | Effort | Tags |
|:-:|:------:|:------------|:------------|:------:|:-----|
| 36 | ✅ | **Integration tests** | End-to-end PCAP → features with real captures | `Medium` | 🔴 |
| 37 | ✅ | **Extractor tests** | TLS, QUIC, SSH, Padding, Fingerprint, Entropy, DNS | `Medium` | 🔴 |
| 38 | ✅ | **Fuzzing** | Hypothesis-based fuzz testing for protocol extractors | `Medium` | |
| 39 | ✅ | **Performance benchmarks** | Pipeline benchmarks with timing metrics | `Low` | ⚡ |
| 40 | ✅ | **Property-based testing** | Hypothesis tests for statistics and entropy | `Medium` | |

---

## 🔒 Security

> Security hardening and compliance

| # | Status | Improvement | Description | Effort | Tags |
|:-:|:------:|:------------|:------------|:------:|:-----|
| 41 | ⬚ | **Sandboxed parsing** | Run packet parsing in isolated process | `High` | 🏗️ |
| 42 | ✅ | **Rate limiting** | Limit remote server connections | `Low` | ⚡ |
| 43 | ⬚ | **Audit logging** | Log all operations for compliance | `Low` | ⚡ |

---

## 🎯 Implementation Phases

### Phase 1: Stabilization
> Fix critical bugs and add essential tests

| Priority | Item | Effort | Quick Win |
|:--------:|:-----|:------:|:---------:|
| 1 | Fix SSH HASSH computation | `Low` | ⚡ |
| 2 | Add integration tests | `Medium` | |
| 3 | Add extractor unit tests | `Medium` | |
| 4 | Fix QUIC packet number extraction | `Low` | ⚡ |

### Phase 2: Performance
> Enable processing of large captures

| Priority | Item | Effort | Quick Win |
|:--------:|:-----|:------:|:---------:|
| 5 | Implement streaming output | `Medium` | |
| 6 | Add dpkt backend option | `Medium` | |
| 7 | Add progress bars | `Low` | ⚡ |

### Phase 3: Features
> Complete the feature set

| Priority | Item | Effort | Quick Win |
|:--------:|:-----|:------:|:---------:|
| 8 | TLS DH parameter extraction | `Medium` | |
| 9 | Entropy extractor | `Low` | ⚡ |
| 10 | DNS feature extraction | `Medium` | |
| 11 | Process name filtering | `Low` | ⚡ |

### Phase 4: Integration
> Output formats and ecosystem

| Priority | Item | Effort | Quick Win |
|:--------:|:-----|:------:|:---------:|
| 12 | Parquet output | `Low` | ⚡ |
| 13 | Feature schema export | `Low` | ⚡ |
| 14 | WSS encryption for remote | `Medium` | |

### Phase 5: Polish
> Developer experience and advanced features

| Priority | Item | Effort | Quick Win |
|:--------:|:-----|:------:|:---------:|
| 15 | Watch mode | `Medium` | |
| 16 | Jupyter widgets | `Medium` | |
| 17 | Grafana dashboard | `Medium` | |

---

## ⚡ Quick Wins

> Items that can be completed in less than a day

| # | Item | Category | Status |
|:-:|:-----|:---------|:------:|
| 1 | Fix SSH HASSH | Critical | ✅ |
| 4 | QUIC packet number length | Critical | ✅ |
| 9 | Process name filtering | Performance | ✅ |
| 13 | Entropy extractor | Features | ✅ |
| 15 | Bidirectional splitting | Features | ✅ |
| 18 | Progress bars | UX | ✅ |
| 20 | Feature schema export | UX | ✅ |
| 21 | Specific feature selection | UX | ✅ |
| 25 | Parquet output | Output | ✅ |
| 28 | Prometheus metrics | Output | ✅ |
| 31 | Stream compression | Remote | ✅ |
| 32 | Auto-reconnection | Remote | ✅ |
| 35 | Bandwidth throttling | Remote | ✅ |
| 39 | Performance benchmarks | Testing | ✅ |
| 42 | Rate limiting | Security | ✅ |
| 43 | Audit logging | Security | ⬚ |
| 44 | Flow Metadata (Tranalyzer) | Tranalyzer | ✅ |
| 47 | IPv6 Options | Tranalyzer | ✅ |
| 48 | Port Classification | Tranalyzer | ✅ |
| 49 | L7 Byte Stats | Tranalyzer | ✅ |
| 50 | Asymmetry Metrics | Tranalyzer | ✅ |
| 53 | TCP Flags & Anomalies | Tranalyzer | ✅ |

**Total Quick Wins: 22 items (1 remaining: #43 Audit Logging)**

---

## 🏗️ Major Efforts

> Items requiring significant development time (1+ weeks)

| # | Item | Category | Notes |
|:-:|:-----|:---------|:------|
| ~~7~~ | ~~Cython extensions~~ | ~~Performance~~ | ✅ Completed - 25-50x speedup for entropy/byte analysis |
| ~~8~~ | ~~eBPF PID filtering~~ | ~~Performance~~ | ✅ Completed - Cross-platform (Linux/Windows/macOS/Android) |
| ~~16~~ | ~~Connection graphs~~ | ~~Features~~ | ✅ Completed - NetworkX integration, community detection, centrality metrics |
| 41 | Sandboxed parsing | Security | Major architectural change |
| ~~59~~ | ~~Tranalyzer Connection Graphs~~ | ~~Tranalyzer~~ | ✅ Completed - `connSip`, `connDip`, `connSipDip` etc. |

**Total Major Efforts: 1 item remaining (#41 Sandboxed Parsing - deferred)**

---

## 📝 Notes

### Dependencies to Add
```toml
# For quick wins
tqdm = ">=4.65.0"           # Progress bars
pyarrow = ">=14.0.0"        # Parquet output
rich = ">=13.0.0"           # Better CLI output

# For performance phase
dpkt = ">=1.9.8"            # Fast packet parsing

# For advanced features
hypothesis = ">=6.0.0"      # Property-based testing

# For Tranalyzer-compatible features
geoip2 = ">=4.0.0"          # GeoIP lookups (srcIPCC, dstIPCC, srcIPOrg, dstIPOrg)
maxminddb = ">=2.0.0"       # MaxMind database reader
```

### Files Most Likely to Change
```
src/joyfuljay/extractors/ssh.py         → HASSH fix
src/joyfuljay/extractors/fingerprint.py → DoH fix
src/joyfuljay/extractors/tls.py         → DH params
src/joyfuljay/extractors/quic.py        → packet number
src/joyfuljay/core/pipeline.py          → streaming output
src/joyfuljay/cli/main.py               → UX improvements
```

### Cython Extensions Package (Completed in #7)
```
src/joyfuljay/extensions/
├── __init__.py           → Package with fallbacks to pure Python
├── _fast_stats.pyx       → Statistics (25-50x faster for small arrays)
├── _fast_entropy.pyx     → Entropy/byte analysis (25-50x faster)
└── build_extensions.py   → Build script for compiling extensions
```

**Performance gains:**
- `shannon_entropy_fast`: 25-51x faster
- `byte_distribution_fast`: 43-61x faster
- `character_class_counts_fast`: 23-40x faster
- `compute_statistics_fast`: 1-5x faster (bigger gains on small arrays)

### New PID Filter Package (Completed in #8)
```
src/joyfuljay/utils/pid_filter/
├── __init__.py        → Package exports + backward compat API
├── base.py            → PIDFilterBase, ConnectionInfo, FilterMethod
├── cache.py           → Smart connection cache with TTL/LRU
├── factory.py         → create_pid_filter(), platform detection
├── linux.py           → eBPF + ss + /proc implementations
├── macos.py           → nettop + lsof implementations
├── windows.py         → ETW + PowerShell + netstat implementations
└── android.py         → /proc + ss implementations
```

### Connection Graph Package (Completed in #16 + #59)
```
src/joyfuljay/analysis/
├── __init__.py                → Package exports
└── connection_graph.py        → ConnectionGraph, NodeStats, EdgeStats

src/joyfuljay/extractors/
└── connection.py              → ConnectionExtractor (requires graph injection)
```

**Features implemented:**
- **Tier 1 (Simple, no dependencies):** `conn_src_unique_dsts`, `conn_dst_unique_srcs`, `conn_src_dst_flows`, `conn_src_port_flows`, `conn_src_total_flows`, `conn_dst_total_flows`, `conn_src_total_packets`, `conn_src_total_bytes`, `conn_dst_total_packets`, `conn_dst_total_bytes`, `conn_src_unique_ports`
- **Tier 2 (Graph metrics, requires NetworkX):** `conn_src_out_degree`, `conn_dst_in_degree`, `conn_src_betweenness`, `conn_dst_betweenness`, `conn_src_community`, `conn_dst_community`, `conn_same_community`, `conn_src_clustering`, `conn_dst_clustering`
- **Tier 3 (Temporal patterns):** `conn_src_flow_rate`, `conn_temporal_spread`, `conn_burst_connections`

**Optional dependency:** `pip install joyfuljay[graphs]` for NetworkX

### Tranalyzer-Compatible Extractors (Completed in #44-#58)
```
src/joyfuljay/extractors/mac.py            → Layer 2 MAC features (10 features)
src/joyfuljay/extractors/ip_extended.py    → Extended IP features (19 features)
src/joyfuljay/extractors/ipv6_options.py   → IPv6 options (11 features)
src/joyfuljay/extractors/tcp_sequence.py   → TCP sequence analysis (18 features)
src/joyfuljay/extractors/tcp_window.py     → TCP window analysis (21 features)
src/joyfuljay/extractors/tcp_options.py    → TCP options parsing (19 features)
src/joyfuljay/extractors/tcp_mptcp.py      → Multipath TCP features (6 features)
src/joyfuljay/extractors/tcp_rtt.py        → TCP RTT estimation (10 features)
src/joyfuljay/extractors/tcp_fingerprint.py → TCP fingerprinting (14 features)
src/joyfuljay/extractors/icmp.py           → ICMP features (16 features)
```

**Enhanced Packet class fields:**
- Layer 2: `src_mac`, `dst_mac`, `eth_type`, `vlan_id`
- Layer 3: `ip_ttl`, `ip_id`, `ip_tos`, `ip_flags`, `ip_version`
- IPv6: `ipv6_flow_label`, `ipv6_traffic_class`
- TCP: `tcp_seq`, `tcp_ack`, `tcp_window`, `tcp_mss`, `tcp_window_scale`, `tcp_timestamp`, `tcp_sack_permitted`, `tcp_sack_blocks`
- ICMP: `icmp_type`, `icmp_code`, `icmp_id`, `icmp_seq`

**Enhanced extractors:**
- `flow_meta.py`: Added `time_first`, `time_last`, `flow_stat`, `num_hdrs`, `hdr_desc`
- `tcp.py`: Added `tcp_fstat`, `tcp_flags_agg`, `tcp_flags_fwd`, `tcp_flags_bwd`

**Total new features: 144 (from 10 new extractors + enhancements)**
**Total feature count: 387 features across 21 extractors**

### Kafka Streaming (Completed in #27)
```
src/joyfuljay/output/kafka.py
├── KafkaWriter          → Context manager for streaming to Kafka
├── to_kafka()           → Convenience function for batch writes
└── is_kafka_available() → Check if kafka-python is installed
```

**Features:**
- Batched writes with configurable flush intervals
- Message key extraction from feature fields
- Compression support (gzip, snappy, lz4)
- Proper serialization of numpy types

**Usage:** `pip install joyfuljay[kafka]`

### Prometheus Metrics (Completed in #28)
```
src/joyfuljay/monitoring/
├── __init__.py         → Package exports
├── base.py             → MetricsSink protocol
└── prometheus.py       → PrometheusMetrics implementation
```

**Metrics exposed:**
- `joyfuljay_packets_total` (Counter) - Total packets processed
- `joyfuljay_bytes_total` (Counter) - Total bytes processed
- `joyfuljay_flows_total` (Counter, labeled by reason) - Flows completed
- `joyfuljay_errors_total` (Counter, labeled by stage) - Processing errors
- `joyfuljay_processing_duration_seconds` (Histogram) - Processing time
- `joyfuljay_active_flows` (Gauge) - Current active flows

**Usage:** `pip install joyfuljay[monitoring]`

### TLS/WSS Encryption (Completed in #30)
```
src/joyfuljay/remote/server.py
└── _build_ssl_context() → Creates SSL context from cert/key files
```

**Server options:**
- `--tls-cert PATH` - Path to TLS certificate file
- `--tls-key PATH` - Path to TLS private key file

**Connection URL:** `jj://host:port?token=xxx&tls=1`

### mDNS Server Discovery (Completed in #33)
```
src/joyfuljay/remote/discovery.py
├── MDNSAnnouncer       → Advertise server via Bonjour/mDNS
├── discover_servers()  → Find servers on local network
└── DiscoveredServer    → Dataclass for discovered server info
```

**Service type:** `_joyfuljay._tcp.local.`

**Server options:**
- `--announce` - Enable mDNS advertisement
- `--announce-name NAME` - Custom service name
- `--announce-properties KEY=VAL` - Custom TXT records

**Usage:** `pip install joyfuljay[discovery]`

### Fuzzing & Property Testing (Completed in #38, #40)
```
tests/fuzz/
└── test_extractors_fuzz.py  → Hypothesis-based fuzzing for protocol extractors

tests/unit/
├── test_stats_property.py   → Property tests for statistics functions
└── test_entropy_property.py → Property tests for entropy calculations
```

**Fuzz targets:** TLSExtractor, SSHExtractor, QUICExtractor, DNSExtractor

**Property invariants tested:**
- Statistics: min ≤ mean ≤ max, std ≥ 0, count consistency
- Entropy: non-negative, bounded by log₂(n)
- Interarrival: length = n-1, all values ≥ 0

### Performance Benchmarks (Completed in #39)
```
benchmarks/
├── benchmark_stats.py    → Statistics function benchmarks
└── benchmark_pipeline.py → End-to-end pipeline benchmarks
```

**Run benchmarks:**
```bash
python benchmarks/benchmark_pipeline.py
python benchmarks/benchmark_stats.py
```

### Grafana Dashboard (Completed in #29)
```
dashboards/
└── joyfuljay-overview.json → Pre-built Grafana dashboard

src/joyfuljay/monitoring/grafana.py
├── load_overview_dashboard()  → Load bundled dashboard
├── export_dashboard()         → Export with custom settings
├── DashboardBuilder           → Programmatic dashboard creation
├── generate_alerting_rules()  → Generate Prometheus alerts
└── generate_prometheus_config() → Generate scrape config
```

**Dashboard Sections:**
- **Overview**: 6 stat panels (packets, bytes, flows, active, errors, rate)
- **Throughput**: 4 time series (packet rate, byte rate, flows/min, active flows)
- **Latency**: 2 panels (p50/p95/p99 percentiles, processing jobs by mode)
- **Errors**: 4 panels (errors by stage, flow reasons pie, error distribution pie)
- **Efficiency**: 2 panels (avg packet size, success rate)

**Usage:**
```bash
# Export dashboard
jj export-dashboard -o dashboard.json

# Or via Python
from joyfuljay.monitoring import export_dashboard
export_dashboard("dashboard.json")
```

---

<div align="center">

**Last Updated:** January 2025

*This roadmap is a living document and will be updated as development progresses.*

</div>
