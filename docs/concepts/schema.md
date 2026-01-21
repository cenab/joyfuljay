# Feature Schema

This is the canonical reference for JoyfulJay's feature schema system. The schema defines all extracted features, their types, units, and metadata.

## Overview

JoyfulJay extracts **401 features** organized into three stability profiles:

| Profile | Features | Stability |
|---------|----------|-----------|
| JJ-CORE | 151 | Frozen |
| JJ-EXTENDED | 148 | Stable |
| JJ-EXPERIMENTAL | 102 | Unstable |

## Schema Location

The current schema is stored at:

```
src/joyfuljay/schema/v1.0/feature_schema.json
```

## Feature Metadata

Each feature includes the following metadata (`FeatureMeta`):

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique feature identifier (e.g., `tls.ja3_hash`) |
| `dtype` | string | Data type (`int64`, `float64`, `str`, `bool`) |
| `shape` | tuple | Shape for array features (e.g., `(10,)`) |
| `units` | string | Units if applicable (e.g., `bytes`, `seconds`) |
| `direction` | string | `fwd`, `bwd`, `bidir`, or `none` |
| `missing` | any | Default value for missing data |
| `privacy` | string | Privacy level (`public`, `sensitive`, `pii`) |
| `profile` | string | Stability profile (`JJ-CORE`, `JJ-EXTENDED`, `JJ-EXPERIMENTAL`) |
| `description` | string | Human-readable description |

## Generating Schema

### Python API

```python
from joyfuljay.schema import write_schema

# Generate full schema
write_schema("schema/v1.0/feature_schema.json")

# Generate minimal schema (types and profiles only)
write_schema("schema/v1.0/feature_schema.json", minimal=True)
```

### CLI

```bash
python -m joyfuljay.schema.generate -o schema/v1.0/feature_schema.json
```

## Loading Schema

### Python API

```python
from joyfuljay.schema import load_schema, get_feature_meta

# Load full schema
schema = load_schema("v1.0")

# Get metadata for a specific feature
meta = get_feature_meta("tls.ja3_hash")
print(meta.dtype)       # str
print(meta.profile)     # JJ-CORE
print(meta.description) # JA3 fingerprint hash
```

### Listing Features

```python
from joyfuljay.schema import list_features, list_profiles

# List all feature IDs
features = list_features()

# List features in a profile
core_features = list_features(profile="JJ-CORE")

# List available profiles
profiles = list_profiles()
```

## Schema Example

```json
{
  "version": "v1.0",
  "joyfuljay_version": "0.1.0",
  "feature_count": 401,
  "features": {
    "flow_meta.src_ip": {
      "id": "flow_meta.src_ip",
      "dtype": "str",
      "units": null,
      "direction": "none",
      "missing": null,
      "privacy": "pii",
      "profile": "JJ-CORE",
      "description": "Source IP address"
    },
    "tls.ja3_hash": {
      "id": "tls.ja3_hash",
      "dtype": "str",
      "units": null,
      "direction": "fwd",
      "missing": null,
      "privacy": "public",
      "profile": "JJ-CORE",
      "description": "JA3 fingerprint hash of client TLS handshake"
    }
  }
}
```

## Feature Naming Convention

Features follow the pattern: `extractor.feature_name`

| Extractor | Prefix | Example |
|-----------|--------|---------|
| Flow Metadata | `flow_meta.` | `flow_meta.duration` |
| Timing | `timing.` | `timing.iat_mean` |
| Size | `size.` | `size.pkt_len_mean` |
| TLS | `tls.` | `tls.ja3_hash` |
| TCP | `tcp.` | `tcp.flags_syn` |
| DNS | `dns.` | `dns.query_count` |
| SSH | `ssh.` | `ssh.hassh_client` |
| QUIC | `quic.` | `quic.version` |

## Direction Semantics

Features may be directional:

| Direction | Meaning | Example |
|-----------|---------|---------|
| `fwd` | Initiator to responder | `timing.fwd_iat_mean` |
| `bwd` | Responder to initiator | `timing.bwd_iat_mean` |
| `bidir` | Both directions combined | `timing.iat_mean` |
| `none` | Not directional | `flow_meta.protocol` |

## Privacy Levels

Features are classified by privacy sensitivity:

| Level | Description | Example |
|-------|-------------|---------|
| `public` | No privacy concerns | `timing.iat_mean` |
| `sensitive` | May reveal behavior | `dns.query_name` |
| `pii` | Personally identifiable | `flow_meta.src_ip` |

## Validation

Validate that features match the schema:

```bash
jj validate features.csv --schema v1.0
```

## Schema Versioning

Schema versions are independent of library versions:

- **v1.x**: Compatible within major version
- **v2.0**: Breaking schema changes

See [Versioning](../release/versioning.md) for version compatibility.

## Related Documentation

- [Reproducibility](../release/reproducibility.md) - Feature profiles and stability
- [Determinism](determinism.md) - Reproducibility guarantees
- [Citation](../citation.md) - How to cite schema versions
