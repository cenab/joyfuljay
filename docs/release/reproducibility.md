# Feature Freeze Policy

## Overview

JoyfulJay follows a strict feature freeze policy to ensure reproducibility in research.
This document outlines the rules for feature changes across the three stability tiers.

## Feature Profiles

JoyfulJay organizes its 401 features into three profiles:

| Profile | Features | Stability | Purpose |
|---------|----------|-----------|---------|
| **JJ-CORE** | 151 | Frozen | Production ML pipelines, published research |
| **JJ-EXTENDED** | 148 | Stable | Advanced analysis, extended research |
| **JJ-EXPERIMENTAL** | 102 | Unstable | Research prototyping, new feature development |

### Profile Contents

**JJ-CORE** includes:

- Flow metadata (src/dst IPs, ports, duration, packet counts)
- Timing features (IAT statistics, burst analysis)
- Packet size features (length statistics, payload sizes)
- Basic TCP features (flags, handshake, connection state)
- TLS features (version, cipher, certificates, JA3/JA3S)

**JJ-EXTENDED** includes:

- DNS features (queries, responses, TTL)
- SSH features (version, HASSH fingerprints)
- QUIC features (version, connection IDs)
- HTTP/2 features (frame counts, multiplexing)
- TCP options, sequence, window, and RTT analysis
- Entropy analysis
- Extended IP header features

**JJ-EXPERIMENTAL** includes:

- Traffic fingerprinting (VPN, Tor, DoH detection)
- TCP OS fingerprinting
- Padding analysis
- Connection graph metrics
- MAC address features
- MPTCP features
- IPv6 extension headers
- ICMP features

## Stability Guarantees

### JJ-CORE (Frozen)

Features in JJ-CORE are **semantically frozen**:

- Feature IDs will not change
- Feature semantics (what they measure) will not change
- Data types will not change
- Units will not change
- Direction semantics will not change

**Breaking changes require a major version bump** (e.g., v1.0 -> v2.0).

Allowed changes:
- Bug fixes (with documented errata)
- Performance optimizations (same output)
- Additional metadata

### JJ-EXTENDED (Stable)

Features in JJ-EXTENDED have **soft stability**:

- Feature IDs are stable within minor versions
- Semantics may be refined with documentation
- Features may be promoted to JJ-CORE
- Features may be deprecated with notice

**Breaking changes require a minor version bump** (e.g., v1.0 -> v1.1).

### JJ-EXPERIMENTAL (Unstable)

Features in JJ-EXPERIMENTAL have **no stability guarantees**:

- Features may change at any time
- Features may be removed without notice
- Features may be promoted to JJ-EXTENDED

**Use at your own risk in production.**

## Adding New Features

New features must:

1. Start in JJ-EXPERIMENTAL
2. Include complete FeatureMeta with:
   - Unique feature ID
   - Data type and shape
   - Units (if applicable)
   - Direction semantics
   - Missing value policy
   - Privacy level
   - Description
3. Have test coverage
4. Be documented

## Promoting Features

Features can be promoted through the tiers:

```
JJ-EXPERIMENTAL -> JJ-EXTENDED -> JJ-CORE
```

Promotion criteria:

**To JJ-EXTENDED:**
- Used in at least one research project
- Stable implementation for 2+ minor versions
- Complete metadata and documentation
- No known bugs

**To JJ-CORE:**
- Used in published research
- Stable in JJ-EXTENDED for 1+ major version
- Critical for common use cases
- Complete test coverage

## Deprecating Features

Deprecated features:
- Are marked with deprecation warnings
- Remain available for 2 minor versions
- Are removed in the next major version

## Using Profiles

### CLI Usage

```bash
# List available profiles
jj profiles list

# Show features in a profile
jj profiles show JJ-CORE

# Show features by extractor group
jj profiles show JJ-CORE --group tls

# Extract with profile filtering
jj extract capture.pcap --profile JJ-CORE -o features.csv
```

### Python API

```python
import joyfuljay as jj

# Extract with profile
config = jj.Config(profile="JJ-CORE")
pipeline = jj.Pipeline(config)
features = pipeline.process_pcap("capture.pcap")

# List profiles programmatically
from joyfuljay.schema import list_profiles, load_profile
for profile in list_profiles():
    features = load_profile(profile)
    print(f"{profile}: {len(features)} features")
```

## Profile Files

Profiles are defined in text files at `profiles/`:

```
profiles/
├── JJ-CORE.txt
├── JJ-EXTENDED.txt
└── JJ-EXPERIMENTAL.txt
```

Each file lists feature IDs (one per line) in `extractor.feature_name` format:

```
# profiles/JJ-CORE.txt
flow_meta.src_ip
flow_meta.dst_ip
timing.iat_mean
tls.ja3_hash
...
```

## Validation

Run `jj profiles validate` to verify:

- All features are assigned to exactly one profile
- No duplicate feature IDs
- All profile files are valid

```bash
$ jj profiles validate
Validation passed: All features are assigned to exactly one profile.
```

## CI Guards

CI pipelines enforce:

- Profile validation on every commit
- Schema regeneration check
- Test coverage for new features

## For Researchers

When citing JoyfulJay results, include:

- JoyfulJay version
- Profile used (JJ-CORE recommended)
- Schema version
- Any configuration overrides

```bash
# Get citation in BibTeX format
jj cite

# Get citation in APA format
jj cite -f apa
```

See the [Versioning](versioning.md) guide for version compatibility information.
