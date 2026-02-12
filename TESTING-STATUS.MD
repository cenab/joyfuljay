# JoyfulJay End-to-End Testing Status (2026-02-10)

This document is an end-to-end (E2E) verification report for **every CLI feature JoyfulJay exposes**, using **real PCAPs and real live traffic**, plus real external sinks (Postgres, Kafka, Prometheus scrape). It also lists all bugs found during this E2E pass and the fixes applied in the working tree.

## Environment

Command evidence:

```text
$ uname -a
Darwin Mac-mini.local 25.1.0 ... arm64

$ sw_vers
ProductName:            macOS
ProductVersion:         26.1
BuildVersion:           25B78

$ .venv/bin/python -V
Python 3.10.10

$ uv --version
uv 0.8.23 (00d3aa378 2025-10-04)

$ .venv/bin/jj --version
joyfuljay, version 0.1.6.1
```

## Setup / Install

Environment was synced with all optional extras to enable DB/Kafka/remote/Parquet/etc:

```bash
uv sync --all-extras --frozen
```

Notes:
- The repo already contains a `.venv/` at the project root.
- This repo is currently a **dirty git worktree** with multiple modified files (some may have pre-existed before this E2E run). I did not reset/revert any unrelated modifications.

## Skills Discovery ($find-skills)

The user requested using `$find-skills` to discover skills that help with end-to-end and real-data testing. Commands executed:

```bash
npx -y skills find "e2e testing"
npx -y skills find "playwright"
npx -y skills find "playwright e2e"
npx -y skills find "api contract testing"
npx -y skills find "docker compose"
npx -y skills find "kafka"
npx -y skills find "prometheus"
```

Results (excerpt; install with `npx skills add <owner/repo@skill>`):

```text
aj-geddes/useful-ai-prompts@e2e-testing-automation
sickn33/antigravity-awesome-skills@e2e-testing-patterns
rmyndharis/antigravity-skills@e2e-testing-patterns
redpanda-data/console@e2e-tester
```

```text
bobmatnyc/claude-mpm-skills@playwright-e2e-testing
cin12211/orca-q@playwright-expert
shipshitdev/library@playwright-e2e-init
```

```text
aj-geddes/useful-ai-prompts@api-contract-testing
vasilyu1983/ai-agents-public@qa-api-testing-contracts
```

```text
manutej/luxor-claude-marketplace@docker-compose-orchestration
josiahsiegel/claude-plugin-marketplace@compose-patterns-2025
```

```text
manutej/luxor-claude-marketplace@kafka-stream-processing
anton-abyzov/specweave@kafka-observability
anton-abyzov/specweave@kafka-cli-tools
```

```text
wshobson/agents@prometheus-configuration
sickn33/antigravity-awesome-skills@prometheus-configuration
personamanagmentlayer/pcl@prometheus-expert
```

## Automated Test Suite (Unit/Integration)

```text
$ .venv/bin/pytest
682 passed in 6.13s
```

## Real Data Used (PCAPs + Live Traffic)

Offline (PCAP files):
- `tests/data/sample.pcap` (small deterministic sample used across many checks)
- `benchmarks/data/smallFlows.pcap` (streaming mode test: 1,253 flows)
- `benchmarks/data/bigFlows.pcap` (streaming + Prometheus: 52,670 flows, 791,615 packets)
- `benchmarks/data/wireshark_samples/http2-16-ssl.pcapng` (TLS + HTTP/2 evidence)
- `benchmarks/data/wireshark_samples/ssh_curve25519-aes128-ctr_opensshS.pcapng` (SSH evidence)
- `benchmarks/data/wireshark_samples/dns.cap` (DNS evidence)

Batch directory extraction:
- `.tmp_e2e/batch/sample.pcap`
- `.tmp_e2e/batch/amqps.pcapng`
- `.tmp_e2e/batch/http2-16-ssl.pcapng`

Live traffic:
- Local loopback HTTP server (`python3 -m http.server ...`) + `curl` requests during capture.

Remote traffic:
- Local JoyfulJay server on `lo0` + client connect, with loopback HTTP traffic generated during capture.

## CLI Command E2E Verification

This section validates **all `jj` subcommands** shown in `jj --help`:
`cite`, `connect`, `discover`, `extract`, `features`, `info`, `live`, `profiles`, `repl`, `schema`, `serve`, `status`, `tui`, `validate`, `watch`.

### `jj status`

```text
$ .venv/bin/jj status
JoyfulJay v0.1.6.1
Platform: Darwin 25.1.0
Python: 3.10.10

Live capture: [OK] libpcap available (28 interfaces)

Available interfaces:
  - lo0
  - en0
  ...
PCAP file processing: [OK] Always available
```

### `jj info`

```text
$ .venv/bin/jj info tests/data/sample.pcap
Packets: 18
Duration: 1.20 seconds
Protocols:
  TCP: 16 (88.9%)
  UDP: 2 (11.1%)
```

### `jj features`

Verified command executes and prints Markdown documentation:

```text
$ .venv/bin/jj features | wc -l
518
```

Captured output:
- `.tmp_e2e/verify_20260210/features.md`

Notes:
- `jj features` documentation is generated from the feature registry metadata and covers the full feature set used by extraction.

### `jj schema`

Exported schema to multiple formats (written under `.tmp_e2e/verify_20260210/`):
- `.tmp_e2e/verify_20260210/schema.json` (401 features; 23 groups)
- `.tmp_e2e/verify_20260210/schema.csv`
- `.tmp_e2e/verify_20260210/schema.md`

Verified group filtering works:
- `.tmp_e2e/verify_20260210/schema_tls.json` contains 23 TLS features (`groups: ['tls']`)

Command evidence:

```text
$ .venv/bin/jj schema -f json -o .tmp_e2e/verify_20260210/schema.json
Schema written to: .tmp_e2e/verify_20260210/schema.json

$ .venv/bin/jj schema --group tls -f json -o .tmp_e2e/verify_20260210/schema_tls.json
Schema written to: .tmp_e2e/verify_20260210/schema_tls.json
```

### `jj tui`

Verified TUI command wiring and dependency checks:

```text
$ .venv/bin/jj tui --check
TUI OK (textual 7.5.0)
```

Verified help output (option surface):

```text
$ .venv/bin/jj tui --help
Usage: jj tui [OPTIONS]
...
  --cwd DIRECTORY  Working directory used when running commands from the TUI.
  --check          Validate that the TUI dependencies are installed and exit.
```

Verified TUI app import/introspection smoke:
- CLI leaf command count: 17
- `tui` present in command tree
- `JoyfulJayTUI` class import/construct succeeds

Artifacts:
- `.tmp_e2e/verify_20260210/tui_help.txt`
- `.tmp_e2e/verify_20260210/tui_check.txt`
- `.tmp_e2e/verify_20260210/tui_smoke_verify.txt`

### `jj profiles`

List + validate:

```text
$ .venv/bin/jj profiles list
JJ-CORE: 151 features
JJ-EXTENDED: 148 features
JJ-EXPERIMENTAL: 102 features

$ .venv/bin/jj profiles validate
Validation passed: All features are assigned to exactly one profile.
```

Show (text + JSON + group filtering):

```text
$ .venv/bin/jj profiles show JJ-CORE | head -n 1
JJ-CORE (151 features):

$ .venv/bin/jj profiles show JJ-EXTENDED --group ip_extended | head -n 5
JJ-EXTENDED (19 features):

  ip_extended:
    - ip_version
    - ip_ttl_fwd_min
```

Verified JSON output is valid and matches the profile size:

```text
$ .venv/bin/jj profiles show JJ-CORE --json > .tmp_e2e/verify_20260210/profiles_show_core.json

$ .venv/bin/python -c "import json; print(len(json.load(open('.tmp_e2e/verify_20260210/profiles_show_core.json'))))"
151
```

Artifacts:
- `.tmp_e2e/verify_20260210/profiles_show_core.txt`
- `.tmp_e2e/verify_20260210/profiles_show_core.json`
- `.tmp_e2e/verify_20260210/profiles_show_extended_ip_extended.txt`

Profile E2E validation via extraction column counts (from `tests/data/sample.pcap`):
- JJ-CORE: **151** columns (`.tmp_e2e/verify_20260210/sample_core.csv`)
- JJ-EXTENDED: **148** columns (`.tmp_e2e/verify_20260210/sample_extended.csv`)
- JJ-EXPERIMENTAL: **102** columns (`.tmp_e2e/verify_20260210/sample_experimental.csv`)

### `jj extract` (Offline PCAP extraction)

#### Output formats (CSV / JSON / Parquet) + parity

Important detail: `-f json` currently produces **JSON Lines (one flow per line)**, not a single JSON array.

Commands run:

```bash
.venv/bin/jj extract tests/data/sample.pcap -f csv    -o .tmp_e2e/verify_20260210/sample_all.csv
.venv/bin/jj extract tests/data/sample.pcap -f json   -o .tmp_e2e/verify_20260210/sample_all.json
.venv/bin/jj extract tests/data/sample.pcap -f parquet -o .tmp_e2e/verify_20260210/sample_all.parquet
```

Verified counts and column parity:
- Rows: 4 flows in all 3 outputs
- Columns/keys: **401** in CSV/JSONL/Parquet
- Column sets match across formats

Artifacts:
- `.tmp_e2e/verify_20260210/sample_all.csv`
- `.tmp_e2e/verify_20260210/sample_all.json`
- `.tmp_e2e/verify_20260210/sample_all.parquet`

#### Feature filtering (`--profile`, `--features`, `--feature`)

1) Profile filtering:
- `--profile JJ-CORE` -> 151 columns (see above)
- `--profile JJ-EXTENDED` -> 148 columns (see above)
- `--profile JJ-EXPERIMENTAL` -> 102 columns (see above)

2) Group filtering:

```text
$ .venv/bin/jj extract tests/data/sample.pcap -f csv -o .tmp_e2e/verify_20260210/sample_flowmeta_timing.csv --features flow_meta --features timing

# Verified column/row counts:
$ .venv/bin/python -c "import csv; p='.tmp_e2e/verify_20260210/sample_flowmeta_timing.csv'; r=csv.reader(open(p,newline='')); h=next(r); print('rows', sum(1 for _ in r)); print('cols', len(h))"
rows 4
cols 60
```

3) Specific feature filtering:

```text
$ .venv/bin/jj extract tests/data/sample.pcap -f csv -o .tmp_e2e/verify_20260210/sample_specific_cols.csv --feature duration --feature tls_detected --feature ja3_hash

# Verified header:
$ head -n 1 .tmp_e2e/verify_20260210/sample_specific_cols.csv
duration,tls_detected,ja3_hash
```

#### Privacy options (`--no-ips`, `--no-ports`)

Verified removal of IP/port columns:
- `.tmp_e2e/verify_20260210/sample_noips_noports.csv` does **not** contain `src_ip`, `dst_ip`, `src_port`, `dst_port`.

#### Sequences (`--include-sequences`)

Verified raw sequences are included:
- `.tmp_e2e/verify_20260210/sample_sequences.json` contains `iat_sequence`, `timestamp_sequence`, `pkt_len_sequence` arrays.

Config-file based extraction also verified:

```text
$ .venv/bin/jj extract tests/data/sample.pcap -c .tmp_e2e/config.yaml -f json -o .tmp_e2e/verify_20260210/sample_from_config.json

# Verified from first JSONL row:
$ .venv/bin/python -c "import json; p='.tmp_e2e/verify_20260210/sample_from_config.json'; d=json.loads(open(p).read().splitlines()[0]); print('iat_sequence_len', len(d.get('iat_sequence', [])))"
iat_sequence_len 10
```

#### Bidirectional split (`--bidir-split`)

Verified command executes and produces `fwd_` and `bwd_` prefixed fields as implemented by `src/joyfuljay/utils/bidir_split.py`. Output artifact:
- `.tmp_e2e/verify_20260210/sample_bidir.csv`

Note:
- For combined directional keys like `total_bytes`, current implementation renames to `total_total_bytes` (this behavior is explicitly asserted by unit tests in `tests/unit/test_bidir_split.py`).

#### Batch directory extraction (`-w/--workers`)

Verified multi-PCAP directory extraction with parallel workers:

```text
$ .venv/bin/jj extract .tmp_e2e/batch -w 2 -f csv -o .tmp_e2e/verify_20260210/batch_out.csv
Completed: .tmp_e2e/batch/sample.pcap (4 flows)
Completed: .tmp_e2e/batch/amqps.pcapng (2 flows)
Completed: .tmp_e2e/batch/http2-16-ssl.pcapng (3 flows)
Extracted 9 flows
```

Artifact:
- `.tmp_e2e/verify_20260210/batch_out.csv` (9 rows, 401 columns)

### `jj extract` (Streaming mode) + Prometheus metrics

#### Streaming (smallFlows)

```text
$ .venv/bin/jj extract benchmarks/data/smallFlows.pcap --streaming -f csv -o .tmp_e2e/verify_20260210/small_stream.csv &> .tmp_e2e/verify_20260210/small_stream.log

$ tail -n 5 .tmp_e2e/verify_20260210/small_stream.log
2026-02-10 03:23:37,656 - joyfuljay.core.pipeline - WARNING - Connection features are not available in streaming mode. Use process_pcap() for batch processing with connection features.
2026-02-10 03:23:37,656 - joyfuljay.core.pipeline - INFO - Processing PCAP (streaming): benchmarks/data/smallFlows.pcap
2026-02-10 03:23:40,026 - joyfuljay.core.pipeline - INFO - Processed 14243 packets, 1253 flows in 2.37s (streaming)
Extracted 1253 flows (streaming)
Written to: .tmp_e2e/verify_20260210/small_stream.csv
```

Verified:
- `.tmp_e2e/verify_20260210/small_stream.csv` has 1253 rows
- 381 columns (no `conn_*` features, as expected for streaming)

#### Streaming (bigFlows) + Prometheus scrape

Command run (with `--features flow_meta` to keep output compact):

```bash
.venv/bin/jj extract benchmarks/data/bigFlows.pcap --streaming --features flow_meta \
  -f csv -o .tmp_e2e/verify_20260210/big_stream_flowmeta.csv \
  --prometheus-addr 127.0.0.1 --prometheus-port 8013
```

Evidence (tail of extraction log):

```text
Prometheus metrics available at http://127.0.0.1:8013
Processed 791615 packets, 52670 flows in 120.35s (streaming)
Written to: .tmp_e2e/verify_20260210/big_stream_flowmeta.csv
```

Verified output:
- `.tmp_e2e/verify_20260210/big_stream_flowmeta.csv`: 52,670 rows, 29 columns

Verified Prometheus endpoint (captured early during processing):
- `.tmp_e2e/verify_20260210/big_stream_metrics_head.txt` contains counters/gauges like:

```text
# HELP joyfuljay_packets_total Total packets processed
joyfuljay_packets_total ...
# HELP joyfuljay_flows_total Total flows processed
joyfuljay_flows_total{reason="completed"} ...
joyfuljay_active_flows ...
```

### Database outputs (`sqlite`, `postgres`)

#### SQLite

Command run:

```bash
.venv/bin/jj extract tests/data/sample.pcap -f sqlite \
  -o .tmp_e2e/verify_20260210/sample.sqlite \
  --db-table joyfuljay_features --db-if-exists replace
```

Verified via Python `sqlite3`:
- Table: `joyfuljay_features`
- Rows: 4
- Columns: 401
- Evidence: `.tmp_e2e/verify_20260210/sample_sqlite_verify.txt`

#### Postgres

Command run against an ephemeral docker `postgres:16-alpine` instance (port 55433):

```bash
.venv/bin/jj extract tests/data/sample.pcap -f postgres \
  -o "postgresql://postgres:postgres@127.0.0.1:55433/postgres" \
  --db-table joyfuljay_features --db-if-exists replace
```

Verified via `psycopg`:
- Rows: 4
- Columns: 401
- Evidence: `.tmp_e2e/verify_20260210/extract_postgres_verify.txt`

### Kafka output (`kafka`)

Verified using an ephemeral docker `redpandadata/redpanda` broker (Kafka-compatible):
- Broker: `127.0.0.1:19092`
- Topic: `joyfuljay_test_1770719470` (see `.tmp_e2e/verify_20260210/extract_kafka_topic.txt`)

Command run:

```bash
.venv/bin/jj extract tests/data/sample.pcap -f kafka \
  --kafka-brokers 127.0.0.1:19092 \
  --kafka-topic joyfuljay_test_1770719470 \
  --kafka-batch-size 1
```

Verified consumption (kafka-python):
- Messages consumed: 4 (one per flow)
- First message keys: 381 (Kafka uses streaming semantics, so no connection features)
- `http2_detected` present in message payload
- Evidence: `.tmp_e2e/verify_20260210/extract_kafka_verify.txt`, `.tmp_e2e/verify_20260210/extract_kafka.log`

### `jj validate`

Validated golden determinism check against expected JSON:

```text
$ .venv/bin/jj validate tests/data/sample.pcap --expected tests/golden/sample.json
Validation PASSED: Output matches expected golden output.
```

### `jj watch`

Verified directory watch picks up new PCAP and writes output:
- Input directory: `.tmp_e2e/verify_20260210/watch_in/`
- Output directory: `.tmp_e2e/verify_20260210/watch_out/`
- Created file: `.tmp_e2e/verify_20260210/watch_in/test_1770714939.pcap`
- Output created: `.tmp_e2e/verify_20260210/watch_out/test_1770714939.json` with **4 lines** (JSONL)

Also verified `--no-recursive` + config file behavior:
- Watch command: `jj watch .tmp_e2e/verify_20260210/watch_cfg_in -o .tmp_e2e/verify_20260210/watch_cfg_out -f json --no-recursive -c .tmp_e2e/config.yaml`
- A file created in a subdirectory was **not** processed:
- Input: `.tmp_e2e/verify_20260210/watch_cfg_in/sub/sub_1770715785.pcap`
- Output: no `.tmp_e2e/verify_20260210/watch_cfg_out/sub_1770715785.json`
- A file created at the watch root **was** processed:
- Input: `.tmp_e2e/verify_20260210/watch_cfg_in/root_1770715785.pcap`
- Output: `.tmp_e2e/verify_20260210/watch_cfg_out/root_1770715785.json` with `iat_sequence_len 10`

### `jj repl`

Verified non-interactive scripted REPL session:
- Loads `tests/data/sample.pcap`
- Reports 18 packets / 4 flows
- `features` extraction succeeds and prints sample feature keys

Artifact:
- `.tmp_e2e/verify_20260210/repl_output.txt`

### `jj live`

Live capture verified on `lo0` without sudo (macOS/libpcap):

Command (run while generating loopback HTTP traffic):

```bash
.venv/bin/jj live lo0 -d 2 -f csv -o .tmp_e2e/verify_20260210/live.csv \
  --save-pcap .tmp_e2e/verify_20260210/live_capture.pcap
```

Verified:
- `.tmp_e2e/verify_20260210/live.csv`: 35 flows, 401 columns (includes `conn_*` features in batch output)
- `.tmp_e2e/verify_20260210/live_capture.pcap`: non-empty (size 35,981 bytes)
- Evidence: `.tmp_e2e/verify_20260210/live.log`, `.tmp_e2e/verify_20260210/live_verify.txt`

Also verified BPF filtering + Prometheus for live capture:
- Command: `jj live lo0 -d 4 --filter "tcp port 8004" --prometheus-addr 127.0.0.1 --prometheus-port 8014 -f csv -o .tmp_e2e/verify_20260210/live_filter.csv --save-pcap .tmp_e2e/verify_20260210/live_filter.pcap`
- Output: 483 flows (ports show destination 8004), PCAP non-empty
- Metrics scraped during capture: `.tmp_e2e/verify_20260210/live_filter_metrics.txt`
- Evidence: `.tmp_e2e/verify_20260210/live_filter.log`, `.tmp_e2e/verify_20260210/live_filter_pid_verify.txt`

Also verified PID filtering on macOS:
- Command: `jj live lo0 -d 3 --pid 16668 -f csv -o .tmp_e2e/verify_20260210/live_pid.csv`
- Output: 336 flows; ports include 8008; PID filter method logged as `LSOF_CACHED`
- Evidence: `.tmp_e2e/verify_20260210/live_pid.log`, `.tmp_e2e/verify_20260210/live_filter_pid_verify.txt`

Also verified database output for live capture (SQLite):
- Command: `jj live lo0 -d 3 -f sqlite -o .tmp_e2e/verify_20260210/live.sqlite --db-table live_features --db-if-exists replace`
- Verified table `live_features`: 413 rows, 381 columns
- Evidence: `.tmp_e2e/verify_20260210/live_sqlite_verify.txt`, `.tmp_e2e/verify_20260210/live_sqlite.log`

Also verified Kafka output for live capture:
- Command: `jj live lo0 -d 3 -f kafka --kafka-brokers 127.0.0.1:19092 --kafka-topic joyfuljay_live_test_1770720040 --kafka-batch-size 1`
- Verified consumption: 283 messages produced; first message has 381 keys
- Evidence: `.tmp_e2e/verify_20260210/live_kafka_verify.txt`, `.tmp_e2e/verify_20260210/live_kafka.log`, `.tmp_e2e/verify_20260210/live_kafka_topic.txt`

Also verified Postgres output for live capture:
- Command: `jj live lo0 -d 3 -f postgres -o "postgresql://postgres:postgres@127.0.0.1:55433/postgres" --db-table live_pg_features --db-if-exists replace`
- Verified table `live_pg_features`: 483 rows, 381 columns
- Evidence: `.tmp_e2e/verify_20260210/live_postgres_verify.txt`, `.tmp_e2e/verify_20260210/live_postgres.log`

### `jj serve` + `jj connect` (remote capture)

#### Basic ws:// serve/connect

Server:
- `.venv/bin/jj serve lo0 -p 9889 --host 127.0.0.1 --no-compress`

Client:
- `.venv/bin/jj connect "jj://127.0.0.1:9889?token=..." -d 2 -f csv -o .tmp_e2e/verify_20260210/remote2.csv --save-pcap .tmp_e2e/verify_20260210/remote_capture2.pcap`

Verified:
- `.tmp_e2e/verify_20260210/remote2.csv`: 225 flows, 401 columns (includes `conn_*` features in batch output)
- `.tmp_e2e/verify_20260210/remote_capture2.pcap`: created and non-empty (size 509,053 bytes)
- Evidence: `.tmp_e2e/verify_20260210/connect2.log`, `.tmp_e2e/verify_20260210/serve2.log`, `.tmp_e2e/verify_20260210/remote2_verify.txt`

Note on remote `--save-pcap`:
- The remote protocol does not include full raw frames, so the saved PCAP is a **best-effort synthetic reconstruction** (IP/TCP/UDP headers + available payload bytes). It is still useful for debugging and sanity checks, but it is not byte-identical to the server-side capture.

#### Compression

Verified server `--compress` works end-to-end:
- `.tmp_e2e/verify_20260210/remote_compress.csv`: 188 flows, 401 columns
- Evidence: `.tmp_e2e/verify_20260210/connect_compress.log`, `.tmp_e2e/verify_20260210/serve_compress.log`, `.tmp_e2e/verify_20260210/remote_compress_verify.txt`

#### JSON output + Prometheus (connect)

Verified `jj connect` supports JSON output (JSONL) and Prometheus metrics:
- Output: `.tmp_e2e/verify_20260210/remote_json.json` (287 JSON lines; first row has 401 keys)
- Metrics scraped during connect: `.tmp_e2e/verify_20260210/connect_metrics.txt`
- Evidence: `.tmp_e2e/verify_20260210/connect_json.log`, `.tmp_e2e/verify_20260210/serve_connect_json.log`, `.tmp_e2e/verify_20260210/remote_json_verify.txt`

#### Database output (connect -> SQLite)

Verified remote connect can write directly to SQLite:
- Command: `jj connect ... -d 3 -f sqlite -o .tmp_e2e/verify_20260210/remote.sqlite --db-table remote_features --db-if-exists replace`
- Verified table `remote_features`: 246 rows, 381 columns
- Evidence: `.tmp_e2e/verify_20260210/connect_sqlite_verify.txt`, `.tmp_e2e/verify_20260210/connect_sqlite.log`, `.tmp_e2e/verify_20260210/serve_sqlite.log`

#### Kafka output (connect -> Kafka)

Verified remote connect can publish flows to Kafka:
- Command: `jj connect ... -d 3 -f kafka --kafka-brokers 127.0.0.1:19092 --kafka-topic joyfuljay_connect_test_1770719906 --kafka-batch-size 1`
- Verified consumption: 276 messages produced; first message has 381 keys
- Evidence: `.tmp_e2e/verify_20260210/connect_kafka_verify.txt`, `.tmp_e2e/verify_20260210/connect_kafka.log`, `.tmp_e2e/verify_20260210/serve_kafka.log`, `.tmp_e2e/verify_20260210/connect_kafka_topic.txt`

#### Postgres output (connect -> Postgres)

Verified remote connect can write directly to Postgres:
- Command: `jj connect ... -d 3 -f postgres -o "postgresql://postgres:postgres@127.0.0.1:55433/postgres" --db-table remote_pg_features --db-if-exists replace`
- Verified table `remote_pg_features`: 229 rows, 381 columns
- Evidence: `.tmp_e2e/verify_20260210/connect_postgres_verify.txt`, `.tmp_e2e/verify_20260210/connect_pg.log`, `.tmp_e2e/verify_20260210/serve_pg.log`

#### Server-side BPF filter (`jj serve --filter`)

Verified server-side BPF filtering works and excludes unrelated traffic:
- Server: `jj serve lo0 -p 9893 --host 127.0.0.1 --filter "tcp port 8006" --no-compress`
- Client: `jj connect ... -d 3 -f csv -o .tmp_e2e/verify_20260210/remote_filter.csv`
- While capturing, traffic was generated on ports 8006 and 8007.
- Result: output contains port 8006 flows and **no** port 8007 flows.
- Evidence: `.tmp_e2e/verify_20260210/remote_filter_pid_verify.txt`, `.tmp_e2e/verify_20260210/connect_filter.log`, `.tmp_e2e/verify_20260210/serve_filter.log`

#### Server-side PID filter (`jj serve --pid`)

Verified server-side PID filtering on macOS:
- Server: `jj serve lo0 -p 9894 --host 127.0.0.1 --pid 42452 --no-compress`
- Client: `jj connect ... -d 3 -f csv -o .tmp_e2e/verify_20260210/remote_pid.csv`
- Result: 303 flows; ports include 8009; PID filter method logged as `LSOF_CACHED`
- Evidence: `.tmp_e2e/verify_20260210/remote_filter_pid_verify.txt`, `.tmp_e2e/verify_20260210/connect_pid.log`, `.tmp_e2e/verify_20260210/serve_pid.log`

#### Server connection limits (`jj serve --max-clients`)

Verified server enforces client capacity:
- Server: `jj serve lo0 -p 9898 --host 127.0.0.1 --max-clients 1 --no-compress`
- Client #1: connect succeeds and receives flows (output: `.tmp_e2e/verify_20260210/remote_maxclients_1.csv`)
- Client #2 (over capacity): connect fails with `Authentication failed: Server at capacity` (exit code 1) and does **not** create the output file `.tmp_e2e/verify_20260210/remote_maxclients_2_afterfix.csv`
- Evidence: `.tmp_e2e/verify_20260210/connect_maxclients_1.log`, `.tmp_e2e/verify_20260210/connect_maxclients_2.log`, `.tmp_e2e/verify_20260210/serve_maxclients.log`

#### TLS / WSS (`jj serve --tls-cert/--tls-key` + `jj connect --tls-insecure`)

Verified TLS-enabled remote capture works end-to-end with a self-signed cert:
- Server: `jj serve lo0 -p 9900 --host 127.0.0.1 --tls-cert .tmp_e2e/verify_20260210/server_cert.pem --tls-key .tmp_e2e/verify_20260210/server_key.pem --no-compress`
- Printed URL contains `&tls=1`, client uses `wss://...` automatically
- Client: `jj connect ... --tls-insecure -d 3 -f csv -o .tmp_e2e/verify_20260210/remote_tls.csv`
- Result: 24 flows, 401 columns
- Evidence: `.tmp_e2e/verify_20260210/remote_tls_verify.txt`, `.tmp_e2e/verify_20260210/connect_tls.log`, `.tmp_e2e/verify_20260210/serve_tls.log`

### `jj discover` (mDNS)

Verified `jj serve --announce` + `jj discover`:
- Server: `.venv/bin/jj serve lo0 -p 9890 --host 0.0.0.0 --announce --announce-name JoyfulJayMDNSTest --no-compress`
- Client: `.venv/bin/jj discover --timeout 3 --json`

Result evidence:
- `.tmp_e2e/verify_20260210/discover.json` contains an entry matching `JoyfulJayMDNSTest._joyfuljay._tcp.local.` with correct port.

### `jj cite`

Verified all cite formats:

```text
$ .venv/bin/jj cite -f bibtex
@software{joyfuljay, ... version = {0.1.6.1} ...}

$ .venv/bin/jj cite -f apa
JoyfulJay Contributors. (2025). ... (Version 0.1.6.1) ...

$ .venv/bin/jj cite -f cff
cff-version: 1.2.0
title: "JoyfulJay: Encrypted Traffic Feature Extraction Library"
...
```

## Protocol/Extractor Spot Checks (Real Data)

TLS + HTTP/2 evidence (`benchmarks/data/wireshark_samples/http2-16-ssl.pcapng`):

```text
tls_detected,tls_version_str,tls_sni,tls_alpn,ja3_hash,ja3s_hash,http2_detected,http_version
True,TLS 1.2,localhost,,05209f4f81916ea99f857b3d998b7644,957ca065469c0e8ba08f0b2d0244f092,True,h2
```

SSH evidence (`benchmarks/data/wireshark_samples/ssh_curve25519-aes128-ctr_opensshS.pcapng`):

```text
ssh_detected,ssh_version,ssh_client_software,ssh_server_software,ssh_hassh,ssh_hassh_server
True,2.0,OpenSSH_7.6p1,OpenSSH_8.3,8f7d7390101f5e1d99f8d411f4896a8c,
```

DNS evidence (`benchmarks/data/wireshark_samples/dns.cap`):

```text
dns_detected,dns_query_name,dns_query_type_str,dns_answer_count,dns_is_query,dns_is_response
True,google.com,TXT,0,True,False
...
```

## Bugs Found During E2E + Fixes Applied

All fixes listed below are applied in the current working tree.

1) `jj validate` false-negative mismatches on NaN vs empty/None:
- Fixed tolerant comparisons to match golden-test behavior.
- File: `src/joyfuljay/cli/main.py`

2) `jj cite -f cff` failed to locate `CITATION.cff` in a source checkout:
- Fixed by searching parent directories for `CITATION.cff`.
- File: `src/joyfuljay/cli/main.py`

3) JJ-EXTENDED profile was incomplete in actual extraction output:
- Root cause: `HTTP2Extractor` existed in schema/registry/profiles but was never wired into the pipeline.
- Fix: added `FeatureGroup.HTTP2` and enabled `HTTP2Extractor` in pipeline; ensured raw payload capture is enabled when HTTP2 features are requested.
- Files:
  - `src/joyfuljay/core/config.py`
  - `src/joyfuljay/core/pipeline.py`

4) `jj connect --save-pcap` did not create any file:
- Implemented best-effort synthetic PCAP writing in remote backend.
- File: `src/joyfuljay/capture/remote_backend.py`

5) `jj schema --group` option was accepted but ignored:
- Implemented group filtering for JSON/CSV/Markdown schema exports.
- Files:
  - `src/joyfuljay/output/schema.py`
  - `src/joyfuljay/cli/main.py`

6) Remote connect could silently succeed with 0 flows on auth/capacity errors:
- Root cause: `RemoteCaptureBackend.iter_packets_live()` consumed the end-of-stream sentinel without surfacing `_error`.
- Fix: raise `_error` when the sentinel is encountered so CLI exits non-zero on auth failures (e.g. `--max-clients` capacity).
- File: `src/joyfuljay/capture/remote_backend.py`

7) `jj schema` / `jj features` docs could not be generated from the registry (drift + incomplete metadata):
- Root cause: several extractors returned `feature_meta()` IDs that did not match their `feature_names`/stable IDs (e.g. `tcp.is_tcp` vs `tcp.tcp_is_tcp`), causing strict registry metadata (`all_feature_meta()`) to fail and blocking accurate schema/docs generation.
- Fix: normalized feature meta IDs to match stable feature IDs and switched `jj schema`/`jj features` generation to use the registry metadata (full 401-feature coverage).
- Files:
  - `src/joyfuljay/output/schema.py`
  - `src/joyfuljay/extractors/tcp.py`
  - `src/joyfuljay/extractors/ip_extended.py`
  - `src/joyfuljay/extractors/tcp_window.py`
  - `src/joyfuljay/extractors/tcp_options.py`
  - `src/joyfuljay/extractors/tcp_mptcp.py`
  - `src/joyfuljay/extractors/tcp_rtt.py`
  - `src/joyfuljay/schema/v1.0/feature_schema.json`
  - `src/joyfuljay/resources/schema/v1.0/feature_schema.json`

8) Live/remote batch outputs were missing connection (`conn_*`) features:
- Root cause: `Pipeline._process_live_batch()` collected streaming outputs and never performed the connection-graph two-pass extraction required for `conn_*` features.
- Fix: added a batch live path that collects completed flows, builds the `ConnectionGraph`, and injects connection features for `process_live(..., output_format='dataframe')`.
- File: `src/joyfuljay/core/pipeline.py`

9) `jj profiles show --help` contained an example that could never work as written:
- Root cause: the example used `jj profiles show JJ-EXTENDED --group tls`, but the JJ-EXTENDED profile contains no TLS group features.
- Fix: updated the help example to a group that exists in JJ-EXTENDED (`ip_extended`).
- File: `src/joyfuljay/cli/main.py`

Additional E2E-driven fixes applied earlier in this session (kept as-is):
- Version reporting parity: `src/joyfuljay/__init__.py`
- Kafka writer robustness: `src/joyfuljay/output/kafka.py`
- Profile/specific-feature filtering after connection features: `src/joyfuljay/core/pipeline.py`
- Live/remote duration enforcement + backend lifecycle: `src/joyfuljay/core/pipeline.py`, `src/joyfuljay/capture/scapy_backend.py`, `src/joyfuljay/capture/remote_backend.py`
- REPL flow completion parity with pipeline: `src/joyfuljay/repl/interactive.py`
- Remote server compatibility with websockets v16 + mDNS announcer thread offload: `src/joyfuljay/remote/server.py`

## Known Limitations / Improvement Opportunities

1) Remote `--save-pcap` is synthetic (best-effort reconstruction).
A true PCAP would require extending the remote protocol to transmit raw frames (or server-side save and transfer).

2) Connection graph features (`conn_*`) require a batch (two-pass) finalize step.
They are present in offline `jj extract` outputs and in `jj live`/`jj connect` when writing CSV/JSON at the end (401 columns/keys; see `.tmp_e2e/verify_20260210/live_verify.txt` and `.tmp_e2e/verify_20260210/remote2_verify.txt`). They are intentionally absent from streaming mode (`jj extract --streaming`) and streaming sinks (`-f kafka`, and DB sinks for `live`/`connect`) which emit per-flow results as flows complete (381 columns/keys; see `.tmp_e2e/verify_20260210/small_stream.log`, `.tmp_e2e/verify_20260210/extract_kafka_verify.txt`, `.tmp_e2e/verify_20260210/live_sqlite_verify.txt`, `.tmp_e2e/verify_20260210/connect_sqlite_verify.txt`).

## Generated Verification Artifacts

Primary artifacts for this report live under:
- `.tmp_e2e/verify_20260210/`

### Schema / Docs

- `.tmp_e2e/verify_20260210/features.md`
- `.tmp_e2e/verify_20260210/schema.json`
- `.tmp_e2e/verify_20260210/schema.csv`
- `.tmp_e2e/verify_20260210/schema.md`
- `.tmp_e2e/verify_20260210/schema_tls.json`

### TUI

- `.tmp_e2e/verify_20260210/tui_help.txt`
- `.tmp_e2e/verify_20260210/tui_check.txt`
- `.tmp_e2e/verify_20260210/tui_smoke_verify.txt`

### Profiles

- `.tmp_e2e/verify_20260210/profiles_show_core.txt`
- `.tmp_e2e/verify_20260210/profiles_show_core.json`
- `.tmp_e2e/verify_20260210/profiles_show_extended_ip_extended.txt`

### Offline Extraction (Batch)

- `.tmp_e2e/verify_20260210/sample_all.csv`
- `.tmp_e2e/verify_20260210/sample_all.json`
- `.tmp_e2e/verify_20260210/sample_all.parquet`
- `.tmp_e2e/verify_20260210/sample_core.csv`
- `.tmp_e2e/verify_20260210/sample_extended.csv`
- `.tmp_e2e/verify_20260210/sample_experimental.csv`
- `.tmp_e2e/verify_20260210/sample_flowmeta_timing.csv`
- `.tmp_e2e/verify_20260210/sample_specific_cols.csv`
- `.tmp_e2e/verify_20260210/sample_noips_noports.csv`
- `.tmp_e2e/verify_20260210/sample_sequences.json`
- `.tmp_e2e/verify_20260210/sample_from_config.json`
- `.tmp_e2e/verify_20260210/sample_bidir.csv`
- `.tmp_e2e/verify_20260210/batch_out.csv`

### Streaming Extraction + Prometheus

- `.tmp_e2e/verify_20260210/small_stream.csv`
- `.tmp_e2e/verify_20260210/small_stream.log`
- `.tmp_e2e/verify_20260210/big_stream_flowmeta.csv`
- `.tmp_e2e/verify_20260210/big_stream_flowmeta.log`
- `.tmp_e2e/verify_20260210/big_stream_metrics_head.txt`

### Offline Sinks (SQLite/Postgres/Kafka)

- `.tmp_e2e/verify_20260210/sample.sqlite`
- `.tmp_e2e/verify_20260210/sample_sqlite_verify.txt`
- `.tmp_e2e/verify_20260210/extract_postgres.log`
- `.tmp_e2e/verify_20260210/extract_postgres_verify.txt`
- `.tmp_e2e/verify_20260210/extract_kafka.log`
- `.tmp_e2e/verify_20260210/extract_kafka_topic.txt`
- `.tmp_e2e/verify_20260210/extract_kafka_verify.txt`

### Watch + REPL

- `.tmp_e2e/verify_20260210/watch.log`
- `.tmp_e2e/verify_20260210/watch_in/`
- `.tmp_e2e/verify_20260210/watch_out/`
- `.tmp_e2e/verify_20260210/watch_cfg.log`
- `.tmp_e2e/verify_20260210/watch_cfg_in/`
- `.tmp_e2e/verify_20260210/watch_cfg_out/`
- `.tmp_e2e/verify_20260210/repl_output.txt`

### Live Capture (Local)

- `.tmp_e2e/verify_20260210/live.log`
- `.tmp_e2e/verify_20260210/live.csv`
- `.tmp_e2e/verify_20260210/live_verify.txt`
- `.tmp_e2e/verify_20260210/live_capture.pcap`
- `.tmp_e2e/verify_20260210/live_filter.log`
- `.tmp_e2e/verify_20260210/live_filter.csv`
- `.tmp_e2e/verify_20260210/live_filter.pcap`
- `.tmp_e2e/verify_20260210/live_filter_metrics.txt`
- `.tmp_e2e/verify_20260210/live_filter_pid_verify.txt`
- `.tmp_e2e/verify_20260210/live_pid.log`
- `.tmp_e2e/verify_20260210/live_pid.csv`
- `.tmp_e2e/verify_20260210/live_sqlite.log`
- `.tmp_e2e/verify_20260210/live.sqlite`
- `.tmp_e2e/verify_20260210/live_sqlite_verify.txt`
- `.tmp_e2e/verify_20260210/live_postgres.log`
- `.tmp_e2e/verify_20260210/live_postgres_verify.txt`
- `.tmp_e2e/verify_20260210/live_kafka.log`
- `.tmp_e2e/verify_20260210/live_kafka_topic.txt`
- `.tmp_e2e/verify_20260210/live_kafka_verify.txt`

### Remote Capture (Serve/Connect)

- `.tmp_e2e/verify_20260210/serve2.log`
- `.tmp_e2e/verify_20260210/connect2.log`
- `.tmp_e2e/verify_20260210/remote2.csv`
- `.tmp_e2e/verify_20260210/remote2_verify.txt`
- `.tmp_e2e/verify_20260210/remote_capture2.pcap`
- `.tmp_e2e/verify_20260210/serve_compress.log`
- `.tmp_e2e/verify_20260210/connect_compress.log`
- `.tmp_e2e/verify_20260210/remote_compress.csv`
- `.tmp_e2e/verify_20260210/remote_compress_verify.txt`
- `.tmp_e2e/verify_20260210/serve_connect_json.log`
- `.tmp_e2e/verify_20260210/connect_json.log`
- `.tmp_e2e/verify_20260210/connect_metrics.txt`
- `.tmp_e2e/verify_20260210/remote_json.json`
- `.tmp_e2e/verify_20260210/remote_json_verify.txt`
- `.tmp_e2e/verify_20260210/serve_filter.log`
- `.tmp_e2e/verify_20260210/connect_filter.log`
- `.tmp_e2e/verify_20260210/remote_filter.csv`
- `.tmp_e2e/verify_20260210/remote_filter_pid_verify.txt`
- `.tmp_e2e/verify_20260210/serve_pid.log`
- `.tmp_e2e/verify_20260210/connect_pid.log`
- `.tmp_e2e/verify_20260210/remote_pid.csv`
- `.tmp_e2e/verify_20260210/serve_maxclients.log`
- `.tmp_e2e/verify_20260210/connect_maxclients_1.log`
- `.tmp_e2e/verify_20260210/connect_maxclients_2.log`
- `.tmp_e2e/verify_20260210/remote_maxclients_1.csv`
- `.tmp_e2e/verify_20260210/serve_tls.log`
- `.tmp_e2e/verify_20260210/connect_tls.log`
- `.tmp_e2e/verify_20260210/server_cert.pem`
- `.tmp_e2e/verify_20260210/server_key.pem`
- `.tmp_e2e/verify_20260210/remote_tls.csv`
- `.tmp_e2e/verify_20260210/remote_tls_verify.txt`
- `.tmp_e2e/verify_20260210/serve_mdns.log`
- `.tmp_e2e/verify_20260210/discover.json`
- `.tmp_e2e/verify_20260210/serve_sqlite.log`
- `.tmp_e2e/verify_20260210/connect_sqlite.log`
- `.tmp_e2e/verify_20260210/connect_sqlite_verify.txt`
- `.tmp_e2e/verify_20260210/serve_kafka.log`
- `.tmp_e2e/verify_20260210/connect_kafka.log`
- `.tmp_e2e/verify_20260210/connect_kafka_topic.txt`
- `.tmp_e2e/verify_20260210/connect_kafka_verify.txt`
- `.tmp_e2e/verify_20260210/serve_pg.log`
- `.tmp_e2e/verify_20260210/connect_pg.log`
- `.tmp_e2e/verify_20260210/connect_postgres_verify.txt`

### Expected Missing Files (Negative Assertions)

- `.tmp_e2e/verify_20260210/remote_maxclients_2_afterfix.csv` (not created because `jj connect` exits non-zero when the server is at capacity)
- `.tmp_e2e/verify_20260210/watch_cfg_out/sub_1770715785.json` (not created because `jj watch --no-recursive` does not process subdirectories)
