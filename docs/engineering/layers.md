# Architecture Layers

!!! info "Engineering Documentation"
    This is internal engineering documentation. For general usage, see the [Architecture](../architecture.md) page.

## Package Structure

JoyfulJay is organized into clear architectural layers:

```
src/joyfuljay/
├── core/           # Core abstractions (Flow, Packet, Pipeline, Config)
├── capture/        # Packet capture backends (Scapy, dpkt, remote)
├── extractors/     # Feature extraction modules
├── schema/         # Feature registry, profiles, schema generation
├── resources/      # Runtime resources (profiles, schemas)
├── output/         # Output formats (CSV, JSON, Parquet, database)
├── remote/         # Remote capture protocol and server
├── monitoring/     # Prometheus metrics integration
├── utils/          # Shared utilities
├── cli/            # Command-line interface
└── extensions/     # Optional Cython accelerators
```

## Layer Responsibilities

### Core Layer (`core/`)

The foundation of JoyfulJay:

- **`packet.py`**: `Packet` dataclass representing parsed network packets
- **`flow.py`**: `Flow` and `FlowKey` for bidirectional flow tracking
- **`pipeline.py`**: `Pipeline` orchestrates extraction from capture to output
- **`config.py`**: `Config` dataclass for all configuration options

**Dependency rule**: Core depends only on stdlib and typing.

### Capture Layer (`capture/`)

Packet capture backends:

- **`scapy_backend.py`**: Primary backend using Scapy (default)
- **`dpkt_backend.py`**: Alternative backend using dpkt (faster for some workloads)
- **`remote_backend.py`**: Client for remote capture from `remote/` servers

**Dependency rule**: Capture depends on Core and external capture libraries.

### Extractors Layer (`extractors/`)

Feature extraction modules:

- **`base.py`**: `BaseExtractor` abstract class defining the extractor interface
- Each extractor file implements one feature group (timing, tls, quic, etc.)

**Extractor contract**:
```python
class MyExtractor(BaseExtractor):
    @staticmethod
    def feature_ids() -> list[str]:
        """Return list of feature IDs this extractor produces."""

    @staticmethod
    def feature_meta() -> list[FeatureMeta]:
        """Return metadata for all features."""

    def extract(self, flow: Flow) -> dict[str, Any]:
        """Extract features from a flow."""
```

**Dependency rule**: Extractors depend on Core and Schema (for FeatureMeta).

### Schema Layer (`schema/`)

Feature registry and profiles:

- **`registry.py`**: `FeatureMeta` dataclass, feature ID collection
- **`profiles.py`**: Profile loading (JJ-CORE, JJ-EXTENDED, JJ-EXPERIMENTAL)
- **`tiering.py`**: Validation that all features are assigned to profiles
- **`generate.py`**: Schema JSON generation

**Dependency rule**: Schema depends only on Core and resources.

### Resources Layer (`resources/`)

Runtime resources shipped with the package:

- **`profiles/`**: Profile text files listing feature IDs
- **`schema/v1.0/`**: Generated feature schema JSON

Loaded via `importlib.resources` for reliable access in installed packages.

### Remote Layer (`remote/`)

Remote capture protocol:

- **`protocol.py`**: Message types and serialization (msgpack)
- **`server.py`**: WebSocket server for streaming packets
- **`discovery.py`**: mDNS/Bonjour service discovery

**Relationship to capture**:
- `remote/` defines the transport protocol and server
- `capture/remote_backend.py` is a capture backend that consumes `remote/`

```
┌─────────────────┐     WebSocket      ┌─────────────────┐
│ capture/        │ ◄────────────────► │ remote/         │
│ remote_backend  │   (msgpack proto)  │ server          │
└─────────────────┘                    └─────────────────┘
```

### Output Layer (`output/`)

Output format handlers:

- **`formats.py`**: CSV, JSON, Parquet writers
- **`database.py`**: SQLite, PostgreSQL writers
- **`kafka.py`**: Kafka streaming output
- **`schema.py`**: Feature documentation generation

### Extensions Layer (`extensions/`)

Optional Cython accelerators:

- **`_fast_entropy.pyx`**: Accelerated entropy calculation
- **`_fast_stats.pyx`**: Accelerated statistical computations
- **`build_extensions.py`**: Build script for Cython modules

**Pure Python fallback**: All accelerated code has pure Python alternatives.
If Cython modules aren't available, the library works with slightly lower performance.

## Dependency Graph

```
                    ┌──────────┐
                    │   CLI    │
                    └────┬─────┘
                         │
         ┌───────────────┼───────────────┐
         │               │               │
         ▼               ▼               ▼
    ┌─────────┐    ┌──────────┐    ┌──────────┐
    │ Output  │    │ Pipeline │    │ Monitoring│
    └────┬────┘    └────┬─────┘    └────┬─────┘
         │              │               │
         │    ┌─────────┴─────────┐     │
         │    │                   │     │
         ▼    ▼                   ▼     │
    ┌─────────┐              ┌─────────┐│
    │ Schema  │◄─────────────│Extractors││
    └────┬────┘              └────┬────┘│
         │                        │     │
         ├────────────────────────┤     │
         │                        │     │
         ▼                        ▼     │
    ┌─────────┐              ┌─────────┐│
    │Resources│              │ Capture │◄┘
    └─────────┘              └────┬────┘
                                  │
                             ┌────┴────┐
                             │  Core   │
                             └─────────┘
```

## Extension Points

### Adding a New Extractor

1. Create `extractors/my_feature.py`
2. Implement `BaseExtractor` with `feature_ids()`, `feature_meta()`, `extract()`
3. Register in `extractors/__init__.py`
4. Add feature IDs to appropriate profile in `resources/profiles/`
5. Add tests in `tests/unit/extractors/test_my_feature.py`

### Adding a New Capture Backend

1. Create `capture/my_backend.py`
2. Implement the backend interface (iter_packets_offline, iter_packets_live)
3. Register in `capture/__init__.py`
4. Add to `Config.backend` choices

### Adding a New Output Format

1. Add writer function to `output/formats.py` or create new module
2. Register in CLI `--format` choices
3. Add tests
