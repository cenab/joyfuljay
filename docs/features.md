# Complete Feature Reference

This document provides a **comprehensive reference** for every feature extracted by JoyfulJay. Understanding these features is essential for building effective ML models for network traffic analysis.

---

## Why These Features Matter

Network traffic analysis traditionally required decrypting traffic to understand its contents. JoyfulJay takes a different approach: it extracts **behavioral features** from encrypted traffic that reveal patterns without exposing content. These features capture:

- **How fast** packets are sent (timing)
- **How large** packets are (size)
- **What protocols** are negotiated (TLS, SSH, QUIC)
- **How connections** behave (TCP state, handshakes)
- **What patterns** emerge (bursts, padding, fingerprints)

These behavioral signals are remarkably consistent within application types and can distinguish encrypted Tor traffic from VPN traffic from regular HTTPS - all without decryption.

---

## Feature Overview

JoyfulJay extracts **200+ features** organized into **13 feature groups**:

| Group | Features | Description |
|-------|----------|-------------|
| [flow_meta](#flow-metadata-features) | 27 | Flow identification, timing, packet/byte counts |
| [timing](#timing-features) | 35 | Inter-arrival times, bursts, idle periods |
| [size](#size-features) | 39 | Packet lengths, payload statistics |
| [tcp](#tcp-features) | 26 | TCP flags, handshake, connection state |
| [tls](#tls-features) | 23 | TLS version, ciphers, JA3/JA3S fingerprints |
| [quic](#quic-features) | 12 | QUIC version, connection IDs |
| [ssh](#ssh-features) | 10 | SSH version, HASSH fingerprints |
| [dns](#dns-features) | 15 | DNS queries, response codes |
| [fingerprint](#fingerprint-features) | 8 | Tor, VPN, DoH detection |
| [entropy](#entropy-features) | 9 | Payload entropy, byte distribution |
| [padding](#padding-features) | 17 | Padding detection, obfuscation |
| [connection](#connection-features) | 20 | Graph-based network analysis |

---

## Flow Metadata Features

The `flow_meta` group provides fundamental flow identification and statistics. These features form the foundation for understanding any network connection.

### What is a "Flow"?

A **flow** represents a bidirectional network conversation between two endpoints. JoyfulJay identifies flows by the **5-tuple**: source IP, source port, destination IP, destination port, and protocol. All packets matching this tuple are grouped into the same flow.

The **initiator** (source) is the endpoint that sent the first packet - typically the client. The **responder** (destination) is the endpoint that received the first packet - typically the server.

### Identification Features

| Feature | Type | Description |
|---------|------|-------------|
| `flow_id` | str | **Unique 32-character hash** identifying this flow. Computed from the 5-tuple (IPs, ports, protocol). Useful for cross-referencing flows without exposing raw addresses. Only included if `include_flow_id=True`. |
| `src_ip` | str | **Source IP address** (flow initiator). The endpoint that sent the first packet. Can be anonymized with `anonymize_ips=True` to produce a SHA-256 hash instead. |
| `dst_ip` | str | **Destination IP address** (flow responder). The endpoint that received the first packet. Can be anonymized with `anonymize_ips=True`. |
| `src_port` | int | **Source port number** (ephemeral port). Usually a high-numbered port (49152-65535) assigned by the OS. |
| `dst_port` | int | **Destination port number** (service port). Indicates the service: 443=HTTPS, 80=HTTP, 22=SSH, 53=DNS, etc. |
| `dst_port_class` | str | **Service classification** based on destination port. Values: `"well_known"` (0-1023), `"registered"` (1024-49151), `"dynamic"` (49152-65535). |
| `dst_port_class_num` | int | **Numeric port classification**: 0=well_known, 1=registered, 2=dynamic. Useful for ML models. |
| `protocol` | int | **IP protocol number**: 6=TCP, 17=UDP, 1=ICMP, 50=ESP (IPSec), 51=AH (IPSec). |

**Example values:**
```
src_ip: "192.168.1.100"
dst_ip: "142.250.189.46"
src_port: 52341
dst_port: 443
dst_port_class: "well_known"
protocol: 6  (TCP)
```

### Timing Features

| Feature | Type | Description |
|---------|------|-------------|
| `start_time` | float | **Unix timestamp** (seconds since 1970-01-01) when the first packet was observed. |
| `end_time` | float | **Unix timestamp** when the last packet was observed. |
| `duration` | float | **Flow duration in seconds** (`end_time - start_time`). Short flows (<1s) often indicate DNS queries, handshakes, or failed connections. Long flows (>60s) indicate persistent connections like streaming or SSH sessions. |
| `time_first` | float | Alias for `start_time` (Tranalyzer compatibility). |
| `time_last` | float | Alias for `end_time` (Tranalyzer compatibility). |

**What duration tells you:**
- **< 0.1s**: DNS query, failed connection, port scan
- **0.1s - 1s**: Short HTTP request, API call
- **1s - 60s**: Typical web browsing session
- **> 60s**: Streaming video, SSH session, file download

### Packet Count Features

| Feature | Type | Description |
|---------|------|-------------|
| `total_packets` | int | **Total packets** in the flow (both directions combined). |
| `packets_fwd` | int | **Packets from initiator to responder** (client-to-server). Typically requests, uploads, commands. |
| `packets_bwd` | int | **Packets from responder to initiator** (server-to-client). Typically responses, downloads, data. |
| `packets_ratio` | float | **Ratio of forward to backward packets** (`packets_fwd / packets_bwd`). Values >1 indicate client-heavy traffic (uploads, commands); <1 indicate server-heavy (downloads, streaming). |

**What packet ratios tell you:**
- **~1.0**: Interactive session (SSH, chat) with balanced exchange
- **< 0.5**: Download-heavy (streaming video, file download)
- **> 2.0**: Upload-heavy (file upload, POST requests)
- **Very high (>10)**: Scanning, one-way traffic, or failed connection

### Byte Count Features

| Feature | Type | Description |
|---------|------|-------------|
| `total_bytes` | int | **Total bytes** including all headers (Ethernet, IP, TCP/UDP, payload). |
| `bytes_fwd` | int | **Bytes sent by initiator**. Includes protocol headers. |
| `bytes_bwd` | int | **Bytes sent by responder**. Includes protocol headers. |
| `payload_bytes_fwd` | int | **Application-layer bytes** sent by initiator. Excludes IP and TCP/UDP headers - just the actual data. |
| `payload_bytes_bwd` | int | **Application-layer bytes** sent by responder. |
| `payload_bytes_total` | int | **Total application-layer bytes** both directions. |
| `bytes_ratio` | float | **Ratio of forward to backward bytes** (`bytes_fwd / bytes_bwd`). |

**Understanding the difference:**
- `total_bytes` includes all overhead (headers, ACKs)
- `payload_bytes_total` is just application data
- A TLS handshake might have `total_bytes=5000` but `payload_bytes_total=3000` due to header overhead

### Rate Features

| Feature | Type | Description |
|---------|------|-------------|
| `packets_per_second` | float | **Average packet rate** over the flow duration (`total_packets / duration`). High rates (>1000 pps) may indicate streaming or bulk transfer. Low rates (<10 pps) indicate interactive sessions. |
| `bytes_per_second` | float | **Average throughput** in bytes/second (`total_bytes / duration`). |
| `avg_packet_size` | float | **Average packet size** in bytes (`total_bytes / total_packets`). Small averages (~100-200) indicate interactive traffic; large averages (~1000-1400) indicate bulk transfers. |

### Protocol Stack Features (Tranalyzer-compatible)

| Feature | Type | Description |
|---------|------|-------------|
| `flow_stat` | int | **TCP connection state bitmap**. Encodes what TCP events were observed. Bits: 0=SYN seen, 1=SYN-ACK seen, 2=FIN from initiator, 3=FIN from responder, 4=RST seen, 6=proper termination. |
| `num_hdrs` | int | **Number of protocol layers** detected. Typically 2-3: Ethernet, IP, TCP/UDP. |
| `hdr_desc` | str | **Protocol stack description** string like `"ETH-IP-TCP"` or `"ETH-IP6-UDP"`. Indicates which protocols are present. |

**Interpreting `flow_stat`:**
- `0x43` (binary 1000011) = SYN + SYN-ACK + proper termination = Normal complete TCP connection
- `0x11` (binary 10001) = SYN + RST = Connection refused
- `0x03` (binary 11) = SYN + SYN-ACK but no FIN/RST = Connection still active or timed out

---

## Timing Features

The `timing` group captures the temporal behavior of network flows. These features are **crucial for detecting application types and anomalies** based on communication patterns.

### Understanding Inter-Arrival Time (IAT)

**Inter-Arrival Time (IAT)** is the time between consecutive packets. It reveals the "rhythm" of communication:

- **Very low IAT** (< 1ms): Burst of data, likely bulk transfer
- **Regular IAT** (~10-50ms): Streaming video, audio
- **Variable IAT**: Interactive session, human-paced
- **Long IAT** (> 1s): Idle connection, keep-alive

### IAT Statistics (Overall)

| Feature | Type | Description |
|---------|------|-------------|
| `iat_min` | float | **Minimum IAT** in seconds. Very small values (<1ms) indicate burst transmission or fast server response. |
| `iat_max` | float | **Maximum IAT** in seconds. Large values indicate idle periods, timeouts, or user think time. |
| `iat_mean` | float | **Mean IAT**. Characterizes the typical pace of communication. |
| `iat_std` | float | **Standard deviation of IAT**. Low std indicates regular/constant timing (streaming); high std indicates bursty or variable patterns (browsing). |
| `iat_median` | float | **Median IAT** (50th percentile). Less sensitive to outliers than mean - better represents "typical" timing. |
| `iat_sum` | float | **Sum of all IATs**. Approximately equals flow duration. |
| `iat_p25` | float | **25th percentile IAT**. Fast packets. |
| `iat_p75` | float | **75th percentile IAT**. Slower packets. |
| `iat_p90` | float | **90th percentile IAT**. Captures "slow" packet gaps. |
| `iat_p99` | float | **99th percentile IAT**. Captures extreme delays. |

**Typical patterns:**
- **Video streaming**: `iat_mean` ~30-40ms, `iat_std` low
- **Web browsing**: `iat_mean` ~100-500ms, `iat_std` high
- **File download**: `iat_min` very low (bursts), `iat_max` moderate

### Directional IAT Statistics

Separate statistics for each direction reveal asymmetric behavior - essential for understanding client-server dynamics.

| Feature | Type | Description |
|---------|------|-------------|
| `iat_fwd_min` | float | Minimum IAT for **forward (client-to-server)** packets. |
| `iat_fwd_max` | float | Maximum IAT for forward packets. |
| `iat_fwd_mean` | float | Mean IAT for forward packets. **High values** indicate slow client typing or "think time". |
| `iat_fwd_std` | float | Standard deviation of forward IAT. |
| `iat_fwd_median` | float | Median forward IAT. |
| `iat_bwd_min` | float | Minimum IAT for **backward (server-to-client)** packets. |
| `iat_bwd_max` | float | Maximum IAT for backward packets. |
| `iat_bwd_mean` | float | Mean IAT for backward packets. **Low values** indicate streaming server response. |
| `iat_bwd_std` | float | Standard deviation of backward IAT. |
| `iat_bwd_median` | float | Median backward IAT. |

**Example interpretation:**
- SSH session: High `iat_fwd_mean` (human typing), low `iat_bwd_mean` (instant echo)
- Video streaming: Low `iat_bwd_mean` (constant stream), high `iat_fwd_mean` (occasional ACKs)

### Burstiness Features

**Burstiness** measures how irregular the traffic pattern is. The coefficient of variation (CV = std/mean) quantifies this.

| Feature | Type | Description |
|---------|------|-------------|
| `burstiness_index` | float | **CV of IAT**. Values near 0 = constant rate (streaming); values >1 = highly bursty (web browsing). |
| `burstiness_index_fwd` | float | Burstiness of forward traffic. |
| `burstiness_index_bwd` | float | Burstiness of backward traffic. |

**Interpreting burstiness:**
- **< 0.5**: Very regular timing (constant bitrate streaming)
- **0.5 - 1.0**: Moderately variable (adaptive streaming)
- **> 1.0**: Highly bursty (web requests, interactive)
- **> 2.0**: Extremely variable (browsing with long pauses)

### Burst and Idle Metrics

JoyfulJay identifies **bursts** (sequences of rapid packets) and **idle periods** (gaps between bursts).

| Feature | Type | Description |
|---------|------|-------------|
| `burst_count` | int | **Number of distinct bursts** in the flow. Many short bursts indicate interactive traffic. |
| `avg_burst_packets` | float | **Average packets per burst**. Large bursts (>10 packets) indicate bulk transfers within each burst. |
| `avg_burst_duration` | float | **Average burst duration** in seconds. |
| `max_burst_packets` | int | **Maximum packets** in any single burst. |
| `idle_count` | int | **Number of idle periods** (gaps exceeding threshold). |
| `avg_idle_duration` | float | **Average idle period** duration in seconds. |
| `max_idle_duration` | float | **Maximum idle period**. Very long idles may indicate keep-alive connections or user abandonment. |
| `first_response_time` | float | **Time from first packet to first response**. Estimates RTT + server processing time. |

**Burst threshold**: Configurable via `burst_threshold_ms` (default: 50ms). Packets closer than this are considered part of the same burst.

### Sequence Features (Optional)

When `include_sequences=True`, raw sequences are included for deep learning models:

| Feature | Type | Description |
|---------|------|-------------|
| `iat_sequence` | list[float] | **Raw IAT sequence**, padded/truncated to `max_sequence_length`. Useful for RNNs/LSTMs. |
| `timestamp_sequence` | list[float] | **Relative timestamps** from flow start. |

### SPLT Features (Optional)

When `include_splt=True`, the **Sequence of Packet Lengths and Times** format is included:

| Feature | Type | Description |
|---------|------|-------------|
| `splt` | list[tuple] | List of `(length, IAT, direction)` tuples. Direction: 1=forward, -1=backward. |
| `splt_lengths` | list[int] | Just the packet lengths from SPLT. |
| `splt_times` | list[float] | Just the IATs from SPLT. |
| `splt_directions` | list[int] | Just the directions from SPLT. |

**SPLT example:**
```python
# First 5 packets of a TLS handshake
[(512, 0.0, 1),      # ClientHello, first packet (IAT=0)
 (1400, 0.015, -1),  # ServerHello, 15ms later
 (100, 0.002, 1),    # Client response, 2ms later
 (1500, 0.001, -1),  # Certificate, 1ms later
 (50, 0.003, 1)]     # Finished, 3ms later
```

---

## Size Features

The `size` group analyzes packet size distributions. Size features are **highly discriminative** for application identification because different applications have characteristic packet sizes.

### Why Size Matters

- **DNS queries**: Small packets (~100 bytes)
- **HTTP requests**: Medium packets (~500-1000 bytes)
- **Bulk data transfer**: Large packets (~1400-1500 bytes, near MTU)
- **TLS handshakes**: Specific sizes based on cipher suite
- **Tor cells**: Fixed 586-byte cells

### Overall Packet Size Statistics

| Feature | Type | Description |
|---------|------|-------------|
| `pkt_len_min` | int | **Minimum packet size**. Often TCP ACK at ~40-60 bytes. |
| `pkt_len_max` | int | **Maximum packet size**. Often near MTU (~1500) for bulk transfer. |
| `pkt_len_mean` | float | **Mean packet size**. Small mean (<200) = interactive; large (>1000) = bulk transfer. |
| `pkt_len_std` | float | **Standard deviation**. Low std = uniform sizes (padding/encryption). |
| `pkt_len_median` | float | **Median packet size**. |
| `pkt_len_p25` | float | 25th percentile packet size. |
| `pkt_len_p75` | float | 75th percentile packet size. |
| `pkt_len_p90` | float | 90th percentile packet size. |
| `pkt_len_variance` | float | Variance of packet sizes (`std^2`). |

### Directional Size Statistics

| Feature | Type | Description |
|---------|------|-------------|
| `pkt_len_fwd_min` | int | Minimum **forward** packet size. |
| `pkt_len_fwd_max` | int | Maximum forward packet size. |
| `pkt_len_fwd_mean` | float | Mean forward packet size. Small = requests; large = uploads. |
| `pkt_len_fwd_std` | float | Standard deviation of forward sizes. |
| `pkt_len_fwd_median` | float | Median forward size. |
| `pkt_len_bwd_min` | int | Minimum **backward** packet size. |
| `pkt_len_bwd_max` | int | Maximum backward packet size. |
| `pkt_len_bwd_mean` | float | Mean backward packet size. Large = downloads, responses. |
| `pkt_len_bwd_std` | float | Standard deviation of backward sizes. |
| `pkt_len_bwd_median` | float | Median backward size. |

### Payload Statistics

**Payload** excludes protocol headers, measuring only application data.

| Feature | Type | Description |
|---------|------|-------------|
| `payload_len_min` | int | Minimum payload size (0 for pure ACKs). |
| `payload_len_max` | int | Maximum payload size. |
| `payload_len_mean` | float | Mean payload size. |
| `payload_len_std` | float | Standard deviation of payload sizes. |
| `payload_len_fwd_mean` | float | Mean forward payload size. |
| `payload_len_fwd_std` | float | Std dev of forward payload. |
| `payload_len_bwd_mean` | float | Mean backward payload size. |
| `payload_len_bwd_std` | float | Std dev of backward payload. |

### Payload Packet Counts

| Feature | Type | Description |
|---------|------|-------------|
| `packets_with_payload` | int | Packets containing application data (payload > 0). |
| `packets_with_payload_fwd` | int | Forward packets with payload. |
| `packets_with_payload_bwd` | int | Backward packets with payload. |
| `header_only_ratio` | float | **Fraction of packets without payload** (pure ACKs, control packets). High ratio indicates acknowledgment-heavy flow. |

### Distribution Analysis

| Feature | Type | Description |
|---------|------|-------------|
| `dominant_pkt_size` | int | **Most common packet size** (mode). |
| `dominant_pkt_ratio` | float | **Fraction of packets at dominant size**. High values (>0.5) indicate fixed-size protocols like Tor. |

### Layer 7 (Application) Statistics

L7 = Layer 7 = Application layer (payload only, no headers).

| Feature | Type | Description |
|---------|------|-------------|
| `l7_bytes_fwd` | int | Total application-layer bytes forward. |
| `l7_bytes_bwd` | int | Total application-layer bytes backward. |
| `l7_bytes_total` | int | Total application-layer bytes. |
| `l7_pkt_min_fwd` | int | Minimum non-zero forward payload. |
| `l7_pkt_max_fwd` | int | Maximum forward payload. |
| `l7_pkt_min_bwd` | int | Minimum non-zero backward payload. |
| `l7_pkt_max_bwd` | int | Maximum backward payload. |

### Asymmetry Metrics

| Feature | Type | Description |
|---------|------|-------------|
| `pkt_asymmetry` | float | **Packet count asymmetry**: `(fwd - bwd) / (fwd + bwd)`. Range -1 to +1. Positive = more client packets. |
| `byte_asymmetry` | float | **Byte count asymmetry**. Positive = upload-heavy, negative = download-heavy. |

**Asymmetry patterns:**
- **~0**: Balanced exchange (chat, gaming)
- **< -0.5**: Download-heavy (streaming, web)
- **> +0.5**: Upload-heavy (backup, file upload)

---

## TCP Features

The `tcp` group analyzes TCP-specific behavior. Essential for understanding connection health, detecting attacks, and identifying anomalies.

### Why TCP Analysis Matters

TCP has a rich set of control flags that reveal connection state:
- **SYN**: "I want to connect"
- **SYN-ACK**: "OK, I accept"
- **ACK**: "I received your data"
- **FIN**: "I'm done, closing gracefully"
- **RST**: "Abort! Something's wrong"
- **PSH**: "Process this immediately"

Analyzing these flags reveals connection health, attack patterns, and application behavior.

### Basic Detection

| Feature | Type | Description |
|---------|------|-------------|
| `tcp_is_tcp` | bool | True if this is a TCP flow (protocol=6). False for UDP, ICMP, etc. |

### Flag Counts

| Feature | Type | Description |
|---------|------|-------------|
| `tcp_syn_count` | int | **SYN packets** (without ACK). Normal: 1. Multiple SYNs indicate retransmission or SYN flood attack. |
| `tcp_synack_count` | int | **SYN-ACK packets**. Normal: 1. Should match successful connection acceptance. |
| `tcp_fin_count` | int | **FIN packets**. Normal termination has 2 (one per direction). |
| `tcp_rst_count` | int | **RST packets**. Any non-zero value indicates abnormal termination - connection refused, timeout, or error. |
| `tcp_ack_count` | int | **ACK packets**. Most data packets have ACK flag set. |
| `tcp_psh_count` | int | **PSH (push) packets**. Indicates application wants immediate delivery. High counts indicate interactive traffic. |
| `tcp_urg_count` | int | **URG (urgent) packets**. Rarely used in modern applications. Non-zero may indicate legacy protocols or attacks. |
| `tcp_ece_count` | int | **ECN Echo**. Indicates network congestion notification. |
| `tcp_cwr_count` | int | **Congestion Window Reduced**. Response to ECE, indicates sender backed off. |

### Flag Ratios

| Feature | Type | Description |
|---------|------|-------------|
| `tcp_syn_ratio` | float | Fraction of packets with SYN. Should be very low for normal flows. |
| `tcp_fin_ratio` | float | Fraction of packets with FIN. |
| `tcp_rst_ratio` | float | Fraction of packets with RST. **High values indicate connection problems or attacks.** |
| `tcp_psh_ratio` | float | Fraction of packets with PSH. High values indicate interactive traffic. |

### Connection State

| Feature | Type | Description |
|---------|------|-------------|
| `tcp_initiator_syn` | bool | True if initiator sent SYN (normal connection start). |
| `tcp_responder_synack` | bool | True if responder sent SYN-ACK (server accepted connection). |
| `tcp_complete_handshake` | bool | True if **3-way handshake completed** (SYN + SYN-ACK seen). False indicates failed connection attempt. |
| `tcp_graceful_close` | bool | True if **both sides sent FIN** (proper termination). |
| `tcp_reset_close` | bool | True if connection was **aborted via RST**. |

### Packet Categories

| Feature | Type | Description |
|---------|------|-------------|
| `tcp_data_packets` | int | Packets containing application data (payload > 0). |
| `tcp_ack_only_packets` | int | **Pure ACK packets** (no data, no control flags). Used for flow control. |

### Anomaly Detection

| Feature | Type | Description |
|---------|------|-------------|
| `tcp_flags_anomaly` | bool | True if **anomalous flag combinations** detected, indicating potential attacks: |

**Detected anomalies:**
- **Null scan**: No flags set (used for OS fingerprinting)
- **XMAS scan**: FIN+PSH+URG set (Christmas tree pattern)
- **SYN+FIN**: Invalid combination (scan technique)
- **SYN+RST**: Invalid combination (scan technique)

### Aggregate Flags (Tranalyzer-compatible)

| Feature | Type | Description |
|---------|------|-------------|
| `tcp_fstat` | int | **Flow status bitmap**: bit 0=SYN, 1=SYN-ACK, 2=ACK beyond handshake, 3=FIN fwd, 4=FIN bwd, 5=RST, 6=data transferred, 7=anomaly. |
| `tcp_flags_agg` | int | **OR of all TCP flags** seen in the flow. |
| `tcp_flags_fwd` | int | OR of all TCP flags in forward direction. |
| `tcp_flags_bwd` | int | OR of all TCP flags in backward direction. |

---

## TLS Features

The `tls` group extracts metadata from TLS handshakes **without decrypting traffic**. This is essential for HTTPS analysis, certificate monitoring, and client fingerprinting.

### How TLS Analysis Works

When a TLS connection starts, the client and server exchange **unencrypted handshake messages** that negotiate encryption parameters. JoyfulJay parses these messages to extract:

1. **ClientHello**: Client's supported versions, ciphers, extensions
2. **ServerHello**: Server's chosen parameters
3. **Certificate**: Server's certificate chain
4. **Key Exchange**: Cryptographic parameters

### Detection and Version

| Feature | Type | Description |
|---------|------|-------------|
| `tls_detected` | bool | True if TLS handshake was detected. |
| `tls_version` | int | TLS version as hex value: `0x0301`=TLS 1.0, `0x0302`=TLS 1.1, `0x0303`=TLS 1.2, `0x0304`=TLS 1.3. |
| `tls_version_str` | str | Human-readable: "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3". |

### Cipher Information

| Feature | Type | Description |
|---------|------|-------------|
| `tls_cipher_suite` | int | **Selected cipher suite** code from ServerHello. Identifies the encryption algorithm used. |
| `tls_cipher_count` | int | **Number of cipher suites** offered in ClientHello. Browsers offer many (20+); specific apps offer few (3-5). Useful for fingerprinting. |
| `tls_extension_count` | int | **Number of TLS extensions**. Part of the JA3 fingerprint. |

### Server Name Indication (SNI)

| Feature | Type | Description |
|---------|------|-------------|
| `tls_sni` | str | **Server Name Indication** - the hostname the client is connecting to. Critical for identifying the destination website without decryption. Empty for IP-only connections. |
| `tls_alpn` | str | **Application-Layer Protocol Negotiation** - the protocol being used. Common values: `"h2"` (HTTP/2), `"http/1.1"`, `"h3"` (HTTP/3 over QUIC). |

**SNI is extremely valuable:**
- Identifies which website the user is visiting
- Essential for virtual hosting (multiple sites on one IP)
- Used by firewalls for domain-based filtering

### JA3 Fingerprinting

**JA3** creates a fingerprint from the TLS ClientHello that identifies the client application. Different browsers, operating systems, and applications produce different JA3 hashes.

| Feature | Type | Description |
|---------|------|-------------|
| `ja3_hash` | str | **MD5 hash** of client fingerprint (32 hex characters). Same application typically produces the same JA3. |
| `ja3s_hash` | str | **JA3S** - server fingerprint from ServerHello. |

**JA3 composition:**
```
MD5(TLS_Version + Cipher_Suites + Extensions + Elliptic_Curves + EC_Point_Formats)
```

**JA3 applications:**
- Identify browsers vs. malware vs. bots
- Detect TLS-based C2 communication
- Fingerprint devices and applications
- Detect anomalous client behavior

### Certificate Metadata

| Feature | Type | Description |
|---------|------|-------------|
| `tls_cert_count` | int | **Number of certificates** in chain. 0 indicates session resumption (no certificate exchange needed). |
| `tls_cert_total_length` | int | Total bytes of certificate data. Large values indicate long certificate chains. |
| `tls_cert_first_length` | int | Size of the **server's certificate** (first in chain). |
| `tls_cert_chain_length` | int | Certificate chain depth. |

### Session Resumption

TLS session resumption allows clients to reconnect faster by reusing previous session parameters.

| Feature | Type | Description |
|---------|------|-------------|
| `tls_session_id_len` | int | Length of session ID. Non-zero indicates client requesting resumption. |
| `tls_session_ticket_ext` | bool | True if **session ticket extension** present (TLS 1.2 resumption). |
| `tls_session_resumed` | bool | True if session was **actually resumed** (no certificate exchange). |
| `tls_psk_ext` | bool | True if **Pre-Shared Key extension** present (TLS 1.3 resumption). |
| `tls_early_data_ext` | bool | True if **0-RTT early data** extension present (TLS 1.3 optimization). |

### Key Exchange

| Feature | Type | Description |
|---------|------|-------------|
| `tls_key_exchange_group` | int | Named group/curve ID. Common values: `0x001D`=x25519, `0x0017`=secp256r1 (P-256). |
| `tls_key_exchange_group_name` | str | Human-readable name: "x25519", "secp256r1", "secp384r1", "ffdhe2048". |
| `tls_key_exchange_length` | int | Key exchange data length in bits. |
| `tls_handshake_packets` | int | Number of TLS handshake packets observed. |

---

## QUIC Features

The `quic` group analyzes **QUIC protocol** traffic (HTTP/3). QUIC is Google's UDP-based protocol that combines TLS 1.3 with transport layer functionality.

| Feature | Type | Description |
|---------|------|-------------|
| `quic_detected` | bool | True if QUIC traffic detected. |
| `quic_version` | int | QUIC version as 32-bit integer. |
| `quic_version_str` | str | Human-readable: "QUIC v1", "QUIC v2", "QUIC draft-29". |
| `quic_dcid_len` | int | **Destination Connection ID** length (bytes). Used for connection migration. |
| `quic_scid_len` | int | **Source Connection ID** length (bytes). |
| `quic_pn_length` | int | **Packet Number** length (1-4 bytes). |
| `quic_initial_packets` | int | Count of Initial (handshake) packets. |
| `quic_0rtt_detected` | bool | True if **0-RTT packets** detected (session resumption). |
| `quic_retry_detected` | bool | True if **Retry packets** detected (address validation). |
| `quic_spin_bit` | bool | True if **spin bit** is being used for RTT measurement. |
| `quic_alpn` | str | Application protocol: "h3", "h3-29", etc. |
| `quic_sni` | str | Server Name Indication (if extracted from Initial packet). |

---

## SSH Features

The `ssh` group analyzes **SSH protocol** traffic, extracting version information and HASSH fingerprints.

| Feature | Type | Description |
|---------|------|-------------|
| `ssh_detected` | bool | True if SSH traffic detected. |
| `ssh_version` | str | SSH protocol version ("2.0"). |
| `ssh_client_software` | str | Client software name (e.g., "OpenSSH_8.9", "PuTTY"). |
| `ssh_server_software` | str | Server software name (e.g., "OpenSSH_9.1", "dropbear"). |
| `ssh_client_version` | str | Client SSH version string. |
| `ssh_server_version` | str | Server SSH version string. |
| `ssh_hassh` | str | **HASSH client fingerprint** - MD5 hash of key exchange algorithms. Identifies SSH client implementations. |
| `ssh_hassh_server` | str | **HASSH server fingerprint**. |
| `ssh_kex_packets` | int | Number of key exchange packets. |
| `ssh_encrypted_packets` | int | Number of encrypted data packets (after key exchange completes). |

**HASSH** is like JA3 for SSH - it fingerprints clients based on their cryptographic algorithm preferences.

---

## Fingerprint Features

The `fingerprint` group **detects specific traffic types** like Tor, VPN, and DNS-over-HTTPS based on behavioral patterns.

### Tor Detection

Tor traffic has distinctive characteristics:
- Fixed-size cells (~586 bytes)
- Low packet size variance
- Specific timing patterns
- Known ports (443, 9001, 9030)

| Feature | Type | Description |
|---------|------|-------------|
| `likely_tor` | bool | True if traffic pattern matches Tor. |
| `tor_confidence` | float | Confidence score (0.0-1.0). |

### VPN Detection

Different VPN protocols have unique signatures:
- **OpenVPN**: UDP/TCP port 1194, specific header patterns
- **WireGuard**: UDP port 51820, small handshake
- **IPSec**: ESP (protocol 50), IKE (UDP 500/4500)
- **L2TP**: UDP port 1701

| Feature | Type | Description |
|---------|------|-------------|
| `likely_vpn` | bool | True if VPN traffic detected. |
| `vpn_confidence` | float | Confidence score (0.0-1.0). |
| `vpn_type` | str | Detected type: "openvpn", "wireguard", "ipsec-esp", "ipsec-ah", "ipsec-ike", "l2tp", or empty. |

### DNS-over-HTTPS (DoH) Detection

DoH encrypts DNS queries in HTTPS, making them harder to monitor. Detection uses:
- Known DoH provider SNIs (dns.google, cloudflare-dns.com)
- Short flow duration
- Small payload sizes typical of DNS

| Feature | Type | Description |
|---------|------|-------------|
| `likely_doh` | bool | True if DNS-over-HTTPS detected. |
| `doh_confidence` | float | Confidence score (0.0-1.0). |

### Overall Classification

| Feature | Type | Description |
|---------|------|-------------|
| `traffic_type` | str | Classification: "tor", "vpn:wireguard", "vpn:openvpn", "doh", or "encrypted". |

---

## Entropy Features

The `entropy` group analyzes **payload randomness** to distinguish encrypted, compressed, and plaintext traffic.

### Understanding Entropy

**Shannon entropy** measures randomness on a scale of 0-8 bits per byte:
- **~8 bits**: Maximum entropy - encrypted or compressed data
- **~5-7 bits**: High entropy - mixed binary data
- **~4-5 bits**: Medium - text with structure
- **~1-3 bits**: Low - repetitive patterns, sparse data

| Feature | Type | Description |
|---------|------|-------------|
| `entropy_payload` | float | **Shannon entropy** of payload (0-8 bits/byte). ~8 = encrypted/compressed, ~4-6 = text. |
| `entropy_initiator` | float | Entropy of initiator's payload. |
| `entropy_responder` | float | Entropy of responder's payload. |
| `entropy_ratio` | float | Ratio of initiator to responder entropy. |
| `byte_distribution_uniformity` | float | How uniform the byte distribution is (0-1). 1 = perfectly uniform (encrypted). |
| `printable_ratio` | float | Fraction of printable ASCII bytes (32-126). High values indicate text. |
| `null_ratio` | float | Fraction of null bytes (0x00). Binary formats often have many nulls. |
| `high_byte_ratio` | float | Fraction of bytes in range 128-255. High values indicate binary or encrypted data. |
| `payload_bytes_sampled` | int | Number of bytes analyzed (limited by `entropy_sample_bytes` config). |

---

## Padding Features

The `padding` group detects **traffic obfuscation and padding techniques** used to hide traffic patterns.

### Size Distribution

| Feature | Type | Description |
|---------|------|-------------|
| `pkt_size_variance` | float | Variance of packet sizes. Low variance indicates fixed-size padding. |
| `pkt_size_cv` | float | Coefficient of variation (std/mean). |
| `is_constant_size` | bool | True if >95% of packets have the same size. |
| `dominant_size_mode` | int | Most common packet size. |
| `dominant_size_ratio` | float | Fraction at dominant size. |
| `unique_size_count` | int | Number of unique sizes. Low = padding. |
| `size_entropy` | float | Normalized entropy of size distribution. |

### Timing Analysis

| Feature | Type | Description |
|---------|------|-------------|
| `iat_variance` | float | Variance of inter-arrival times. |
| `iat_cv` | float | CV of IAT. Low values indicate constant-rate traffic shaping. |
| `is_constant_rate` | bool | True if traffic is constant-rate (CV < 0.1). |

### Tor Cell Detection

| Feature | Type | Description |
|---------|------|-------------|
| `tor_cell_count` | int | Packets matching Tor cell size (580-600 bytes). |
| `tor_cell_ratio` | float | Fraction of Tor-cell-sized packets. |
| `is_tor_like` | bool | True if pattern strongly suggests Tor. |

### Burst Analysis

| Feature | Type | Description |
|---------|------|-------------|
| `burst_padding_ratio` | float | Overhead (header) bytes as fraction of burst. |
| `burst_overhead_bytes` | int | Total header bytes in bursts. |
| `avg_burst_payload_efficiency` | float | Payload/total ratio per burst. Low efficiency suggests padding. |
| `padding_score` | float | **Combined padding score** (0-1). Higher = more likely padded/obfuscated. |

---

## Connection Features

The `connection` group provides **graph-based analysis** across all flows. Requires: `pip install joyfuljay[graphs]`

### Simple Metrics

| Feature | Type | Description |
|---------|------|-------------|
| `conn_src_unique_dsts` | int | Unique destinations from source. **High = scanning behavior.** |
| `conn_dst_unique_srcs` | int | Unique sources to destination. **High = server endpoint.** |
| `conn_src_dst_flows` | int | Flows between this exact pair. |
| `conn_src_port_flows` | int | Flows to this destination port. |
| `conn_src_total_flows` | int | Total outbound flows from source. |
| `conn_dst_total_flows` | int | Total inbound flows to destination. |
| `conn_src_total_packets` | int | Total packets sent by source. |
| `conn_src_total_bytes` | int | Total bytes sent by source. |
| `conn_dst_total_packets` | int | Total packets received by destination. |
| `conn_dst_total_bytes` | int | Total bytes received by destination. |
| `conn_src_unique_ports` | int | Unique destination ports from source. |

### Graph Metrics (NetworkX)

| Feature | Type | Description |
|---------|------|-------------|
| `conn_src_out_degree` | int | Out-degree in connection graph. |
| `conn_dst_in_degree` | int | In-degree in connection graph. |
| `conn_src_betweenness` | float | **Betweenness centrality** (0-1). High = bridge/gateway node. |
| `conn_dst_betweenness` | float | Betweenness of destination. |
| `conn_src_community` | int | Community ID of source. |
| `conn_dst_community` | int | Community ID of destination. |
| `conn_same_community` | bool | True if same community. |
| `conn_src_clustering` | float | Clustering coefficient of source. |
| `conn_dst_clustering` | float | Clustering coefficient of destination. |

---

## Feature Selection for ML

### Traffic Classification (App Identification)

```python
config = jj.Config(
    features=["flow_meta", "timing", "size", "tls"],
    bidirectional_split=True,
)
```

### Encrypted Traffic Detection (Tor, VPN)

```python
config = jj.Config(
    features=["timing", "size", "fingerprint", "padding"],
)
```

### Anomaly Detection

```python
config = jj.Config(
    features=["timing", "size", "entropy", "tcp"],
    include_raw_sequences=True,
)
```

### Most Discriminative Features

Based on research and experiments:

1. **Timing**: `iat_mean`, `iat_std`, `burstiness_index`
2. **Size**: `pkt_len_mean`, `pkt_len_std`, `pkt_asymmetry`
3. **TLS**: `ja3_hash`, `tls_sni`, `tls_cipher_count`
4. **Connection**: `tcp_complete_handshake`, `duration`

---

## See Also

- [Extractors Reference](extractors/index.md) - Per-extractor documentation
- [Configuration](configuration.md) - All configuration options
- [Tutorials](tutorials/index.md) - Step-by-step guides
