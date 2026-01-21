"""Golden tests for determinism validation.

Golden tests verify that JoyfulJay produces identical output across runs
for the same input PCAP and configuration. This is critical for reproducible
research.

Each golden test includes:
- A PCAP file
- Expected output JSON
- Configuration used

To regenerate golden outputs:
    python -m tests.golden.generate

To validate against golden outputs:
    jj validate tests/golden/sample.pcap --expected tests/golden/sample.json
"""
