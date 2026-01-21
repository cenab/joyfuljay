# Determinism Guarantees

## Overview

JoyfulJay provides determinism guarantees for reproducible research. This document
describes how deterministic behavior is achieved and what guarantees are provided.

## Determinism Levels

### Level 1: Same PCAP, Same Output

Given the same:
- PCAP file
- JoyfulJay version
- Configuration

JoyfulJay produces **identical feature values**.

### Level 2: Reproducible Flow Keys

Flow identification is deterministic:
- Flows are keyed by (src_ip, dst_ip, src_port, dst_port, protocol)
- Bidirectional flows use canonical ordering (lower IP first)
- Flow timestamps are from the first packet

### Level 3: Consistent Direction

Forward/backward direction is consistently defined:
- Forward = direction of first packet (initiator)
- Backward = response direction (responder)
- `src_to_dst` = initiator to responder
- `dst_to_src` = responder to initiator

## Flow Key Computation

```python
def compute_flow_key(packet):
    # Canonical ordering: lower IP is always "source"
    if packet.src_ip < packet.dst_ip:
        return (packet.src_ip, packet.dst_ip,
                packet.src_port, packet.dst_port,
                packet.protocol)
    elif packet.src_ip > packet.dst_ip:
        return (packet.dst_ip, packet.src_ip,
                packet.dst_port, packet.src_port,
                packet.protocol)
    else:
        # Same IP: use port ordering
        if packet.src_port <= packet.dst_port:
            return (packet.src_ip, packet.dst_ip,
                    packet.src_port, packet.dst_port,
                    packet.protocol)
        else:
            return (packet.dst_ip, packet.src_ip,
                    packet.dst_port, packet.src_port,
                    packet.protocol)
```

## Rounding and Precision

### Floating Point Values

- All floating point features use IEEE 754 double precision
- Time values are in seconds with nanosecond precision (when available)
- Statistical features (mean, std) use stable algorithms

### Rounding Rules

- Timestamps: No rounding (full precision)
- Durations: No rounding (full precision)
- Counts: Integer (no rounding needed)
- Ratios: No rounding (full precision)
- Hashes: Deterministic string output

## Configuration Hash

Each extraction includes a configuration hash for reproducibility:

```python
from joyfuljay.provenance import compute_config_hash

config_dict = {
    "flow_timeout": 60.0,
    "profile": "JJ-CORE",
    ...
}
hash = compute_config_hash(config_dict)
# Returns: "sha256:abc123..."
```

## Provenance Metadata

Every extraction can include provenance metadata for reproducibility tracking:

```python
from joyfuljay.provenance import build_provenance, write_provenance_sidecar

# Build provenance metadata
provenance = build_provenance(
    profile="JJ-CORE",
    schema_version="v1.0",
    backend="scapy",
    capture_mode="offline",
    config=config.to_dict(),
    ip_anonymization=False,
    port_redaction=False,
)

# Write as sidecar JSON file
sidecar_path = write_provenance_sidecar("features.csv", provenance)
# Creates: features.csv.provenance.json
```

Example provenance output:

```json
{
  "jj_version": "0.1.0",
  "schema_version": "v1.0",
  "profile": "JJ-CORE",
  "backend": "scapy",
  "capture_mode": "offline",
  "config_hash": "sha256:abc123...",
  "timestamp_generated": "2025-01-06T12:00:00Z",
  "privacy": {
    "ip_anonymization": false,
    "port_redaction": false
  }
}
```

## Non-Deterministic Scenarios

The following scenarios may produce different results:

### Live Capture
- Packet arrival order may vary
- Timestamps depend on system clock
- Flow timeouts are wall-clock based

### Parallel Processing
- Flow order in output may vary
- Feature values remain identical

### Different Backends
- Different backends may parse packets differently
- Use the same backend for reproducibility

## Verification

### Golden Tests

JoyfulJay includes golden test PCAPs with expected outputs:

```bash
jj validate tests/golden/sample.pcap --expected tests/golden/sample.json
```

### Config Reproducibility

```python
# Save config for reproducibility
config.to_json("extraction_config.json")

# Reload and re-run
config2 = Config.from_json("extraction_config.json")
# Produces identical output
```

## Best Practices

1. **Pin JoyfulJay version** in requirements.txt
2. **Use offline mode** for reproducible research
3. **Save configuration** with each extraction
4. **Include provenance** in published results
5. **Validate with golden tests** before releases
