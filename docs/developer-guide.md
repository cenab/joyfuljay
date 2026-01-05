# Developer Guide

This guide provides detailed tutorials for extending JoyfulJay with custom functionality. For contribution guidelines, see [CONTRIBUTING.md](../CONTRIBUTING.md). For architecture overview, see [Architecture](architecture.md).

## Table of Contents

- [Creating a New Extractor](#creating-a-new-extractor)
- [Adding CLI Commands](#adding-cli-commands)
- [Adding Output Formats](#adding-output-formats)
- [Creating Capture Backends](#creating-capture-backends)
- [Utility Functions](#utility-functions)
- [Testing Patterns](#testing-patterns)
- [Debugging Tips](#debugging-tips)

---

## Creating a New Extractor

This tutorial walks through creating a custom feature extractor from scratch.

### Step 1: Understand the Data Model

Extractors receive a `Flow` object containing:

```python
# Available data in a Flow
flow.key              # FlowKey (ip_a, port_a, ip_b, port_b, protocol)
flow.start_time       # float: First packet timestamp
flow.last_seen        # float: Last packet timestamp
flow.duration         # float: Flow duration in seconds
flow.total_packets    # int: Total packet count
flow.total_bytes      # int: Total bytes

flow.initiator_ip     # str: Connection initiator IP
flow.initiator_port   # int: Connection initiator port
flow.responder_ip     # str: Connection responder IP
flow.responder_port   # int: Connection responder port

flow.packets          # list[Packet]: All packets (both directions)
flow.initiator_packets # list[Packet]: Initiator → Responder packets
flow.responder_packets # list[Packet]: Responder → Initiator packets

flow.tls_client_hello # bytes | None: TLS ClientHello (if captured)
flow.tls_server_hello # bytes | None: TLS ServerHello (if captured)
flow.terminated       # bool: Flow ended with FIN/RST
```

Each `Packet` contains 60+ fields. Common ones:

```python
packet.timestamp      # float: Unix timestamp
packet.src_ip         # str: Source IP
packet.dst_ip         # str: Destination IP
packet.src_port       # int: Source port
packet.dst_port       # int: Destination port
packet.protocol       # int: IP protocol (6=TCP, 17=UDP)
packet.payload_len    # int: Transport payload bytes
packet.total_len      # int: Total IP packet length
packet.tcp_flags      # int | None: TCP flag bitmap
packet.raw_payload    # bytes | None: Raw payload (if enabled)
```

### Step 2: Create the Extractor File

Create `src/joyfuljay/extractors/my_protocol.py`:

```python
"""My Protocol feature extractor."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .base import FeatureExtractor

if TYPE_CHECKING:
    from ..core.flow import Flow
    from ..core.packet import Packet


class MyProtocolExtractor(FeatureExtractor):
    """Extract features from My Protocol traffic.

    This extractor analyzes [description of what it does].

    Features:
        my_protocol_count: Number of My Protocol messages detected.
        my_protocol_bytes: Total bytes in My Protocol payloads.
        my_protocol_ratio: Ratio of My Protocol to total traffic.
        my_protocol_version: Detected protocol version (or None).
    """

    def __init__(self, threshold: int = 100) -> None:
        """Initialize the extractor.

        Args:
            threshold: Minimum bytes to consider as My Protocol.
        """
        self._threshold = threshold
        # Define feature names (must match what extract() returns)
        self._feature_names = [
            "my_protocol_count",
            "my_protocol_bytes",
            "my_protocol_ratio",
            "my_protocol_version",
        ]

    @property
    def feature_names(self) -> list[str]:
        """Get the list of feature names this extractor produces."""
        return self._feature_names

    @property
    def name(self) -> str:
        """Get the extractor name."""
        return "my_protocol"

    def extract(self, flow: Flow) -> dict[str, Any]:
        """Extract My Protocol features from a flow.

        Args:
            flow: The completed flow to analyze.

        Returns:
            Dictionary of feature names to values.
        """
        # Initialize counters
        count = 0
        protocol_bytes = 0
        version: str | None = None

        # Process all packets in the flow
        for packet in flow.packets:
            if self._is_my_protocol(packet):
                count += 1
                protocol_bytes += packet.payload_len

                # Try to detect version from first matching packet
                if version is None:
                    version = self._detect_version(packet)

        # Calculate derived features
        total_bytes = flow.total_bytes or 1  # Avoid division by zero
        ratio = protocol_bytes / total_bytes

        return {
            "my_protocol_count": count,
            "my_protocol_bytes": protocol_bytes,
            "my_protocol_ratio": ratio,
            "my_protocol_version": version,
        }

    def _is_my_protocol(self, packet: Packet) -> bool:
        """Check if a packet contains My Protocol data.

        Args:
            packet: Packet to check.

        Returns:
            True if packet appears to be My Protocol.
        """
        # Example: Check for specific port
        if packet.dst_port != 9999 and packet.src_port != 9999:
            return False

        # Example: Check payload magic bytes
        if packet.raw_payload and len(packet.raw_payload) >= 4:
            magic = packet.raw_payload[:4]
            return magic == b"MYPR"

        return False

    def _detect_version(self, packet: Packet) -> str | None:
        """Detect protocol version from packet payload.

        Args:
            packet: Packet to analyze.

        Returns:
            Version string or None if not detected.
        """
        if not packet.raw_payload or len(packet.raw_payload) < 5:
            return None

        # Example: Version is 5th byte
        version_byte = packet.raw_payload[4]
        return f"{version_byte >> 4}.{version_byte & 0x0F}"
```

### Step 3: Register the Extractor

Add to `src/joyfuljay/core/config.py`:

```python
class FeatureGroup(str, Enum):
    # ... existing groups ...
    MY_PROTOCOL = "my_protocol"  # Add your group
```

Add to `src/joyfuljay/core/pipeline.py`:

```python
# At top of file
from ..extractors.my_protocol import MyProtocolExtractor

# In _init_extractors() method
if self.config.should_extract(FeatureGroup.MY_PROTOCOL):
    extractors.append(MyProtocolExtractor(
        threshold=self.config.my_protocol_threshold,  # If configurable
    ))
```

### Step 4: Add Tests

Create `tests/unit/extractors/test_my_protocol.py`:

```python
"""Tests for MyProtocolExtractor."""

import pytest

from joyfuljay.core.flow import Flow, FlowKey
from joyfuljay.core.packet import Packet
from joyfuljay.extractors.my_protocol import MyProtocolExtractor


@pytest.fixture
def extractor():
    """Create a MyProtocolExtractor instance."""
    return MyProtocolExtractor()


@pytest.fixture
def my_protocol_packet():
    """Create a packet with My Protocol data."""
    return Packet(
        timestamp=1.0,
        src_ip="192.168.1.1",
        dst_ip="10.0.0.1",
        src_port=12345,
        dst_port=9999,
        protocol=6,
        payload_len=100,
        total_len=140,
        raw_payload=b"MYPR\x10some data here",
    )


@pytest.fixture
def regular_packet():
    """Create a regular (non-My Protocol) packet."""
    return Packet(
        timestamp=1.0,
        src_ip="192.168.1.1",
        dst_ip="10.0.0.1",
        src_port=12345,
        dst_port=443,
        protocol=6,
        payload_len=100,
        total_len=140,
    )


class TestMyProtocolExtractor:
    """Tests for MyProtocolExtractor."""

    def test_feature_names(self, extractor):
        """Test that feature names are correctly defined."""
        assert "my_protocol_count" in extractor.feature_names
        assert "my_protocol_bytes" in extractor.feature_names
        assert "my_protocol_ratio" in extractor.feature_names
        assert "my_protocol_version" in extractor.feature_names

    def test_extract_with_protocol(self, extractor, my_protocol_packet):
        """Test extraction with My Protocol traffic."""
        flow = Flow.from_first_packet(my_protocol_packet)

        features = extractor.extract(flow)

        assert features["my_protocol_count"] == 1
        assert features["my_protocol_bytes"] == 100
        assert features["my_protocol_version"] == "1.0"
        assert features["my_protocol_ratio"] > 0

    def test_extract_without_protocol(self, extractor, regular_packet):
        """Test extraction with non-My Protocol traffic."""
        flow = Flow.from_first_packet(regular_packet)

        features = extractor.extract(flow)

        assert features["my_protocol_count"] == 0
        assert features["my_protocol_bytes"] == 0
        assert features["my_protocol_version"] is None
        assert features["my_protocol_ratio"] == 0.0

    def test_extract_returns_all_features(self, extractor, regular_packet):
        """Test that all declared features are returned."""
        flow = Flow.from_first_packet(regular_packet)

        features = extractor.extract(flow)

        for name in extractor.feature_names:
            assert name in features, f"Missing feature: {name}"
```

### Step 5: Add Documentation

Create `docs/extractors/my-protocol.md`:

```markdown
# My Protocol Extractor

The My Protocol extractor analyzes traffic using the My Protocol format.

## Features

| Feature | Type | Description |
|---------|------|-------------|
| `my_protocol_count` | int | Number of My Protocol messages |
| `my_protocol_bytes` | int | Total bytes in My Protocol payloads |
| `my_protocol_ratio` | float | Ratio of My Protocol to total bytes |
| `my_protocol_version` | str | None | Detected protocol version |

## Usage

### Enable via Config

```python
from joyfuljay import Pipeline, Config

config = Config(features=["my_protocol"])
pipeline = Pipeline(config)
```

### Enable with Other Features

```python
config = Config(features=["flow_meta", "timing", "my_protocol"])
```

## Example Output

```python
{
    "my_protocol_count": 5,
    "my_protocol_bytes": 1250,
    "my_protocol_ratio": 0.45,
    "my_protocol_version": "1.0"
}
```

## Use Cases

- Detecting My Protocol traffic in network captures
- Analyzing My Protocol version distribution
- Identifying My Protocol-heavy flows
```

---

## Adding CLI Commands

### Step 1: Create Command Module

Create `src/joyfuljay/cli/commands/my_command.py`:

```python
"""My custom CLI command."""

from __future__ import annotations

import click

from ...core.config import Config
from ...core.pipeline import Pipeline


@click.command("my-command")
@click.argument("input_file", type=click.Path(exists=True))
@click.option(
    "--output", "-o",
    type=click.Path(),
    default="output.csv",
    help="Output file path."
)
@click.option(
    "--threshold", "-t",
    type=int,
    default=100,
    help="Detection threshold."
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Enable verbose output."
)
def my_command(
    input_file: str,
    output: str,
    threshold: int,
    verbose: bool,
) -> None:
    """Process a PCAP file with My Protocol analysis.

    INPUT_FILE is the path to the PCAP file to process.

    Example:
        jj my-command capture.pcap -o results.csv
    """
    if verbose:
        click.echo(f"Processing {input_file}...")
        click.echo(f"Threshold: {threshold}")

    # Create configuration
    config = Config(
        features=["flow_meta", "my_protocol"],
        # my_protocol_threshold=threshold,  # If configurable
    )

    # Process file
    pipeline = Pipeline(config)
    features_df = pipeline.process_pcap(input_file)

    # Save output
    features_df.to_csv(output, index=False)

    click.echo(f"Extracted {len(features_df)} flows to {output}")
```

### Step 2: Register Command

Add to `src/joyfuljay/cli/main.py`:

```python
from .commands.my_command import my_command

# In the cli group setup
cli.add_command(my_command)
```

### Step 3: Test the Command

```python
# tests/unit/test_cli.py
from click.testing import CliRunner
from joyfuljay.cli.main import cli

def test_my_command():
    runner = CliRunner()
    with runner.isolated_filesystem():
        # Create a test PCAP or use a fixture
        result = runner.invoke(cli, ["my-command", "test.pcap", "-o", "out.csv"])
        assert result.exit_code == 0
```

---

## Adding Output Formats

### StreamingWriter Pattern

Create `src/joyfuljay/output/my_format.py`:

```python
"""My Format output writer."""

from __future__ import annotations

from pathlib import Path
from typing import Any


class MyFormatWriter:
    """Write features to My Format.

    Example:
        with MyFormatWriter("output.myf") as writer:
            for features in pipeline.iter_features("capture.pcap"):
                writer.write(features)
    """

    def __init__(
        self,
        path: str | Path,
        delimiter: str = "|",
        include_header: bool = True,
    ) -> None:
        """Initialize the writer.

        Args:
            path: Output file path.
            delimiter: Field delimiter.
            include_header: Whether to write header row.
        """
        self.path = Path(path)
        self.delimiter = delimiter
        self.include_header = include_header
        self._file = None
        self._header_written = False
        self._columns: list[str] | None = None

    def __enter__(self) -> "MyFormatWriter":
        """Open file for writing."""
        self._file = self.path.open("w", encoding="utf-8")
        return self

    def __exit__(self, *args: Any) -> None:
        """Close file."""
        if self._file:
            self._file.close()
            self._file = None

    def write(self, features: dict[str, Any]) -> None:
        """Write a single feature record.

        Args:
            features: Feature dictionary to write.
        """
        if self._file is None:
            raise RuntimeError("Writer not opened. Use 'with' statement.")

        # Write header on first record
        if not self._header_written and self.include_header:
            self._columns = list(features.keys())
            header = self.delimiter.join(self._columns)
            self._file.write(f"# {header}\n")
            self._header_written = True

        # Ensure consistent column order
        if self._columns is None:
            self._columns = list(features.keys())

        values = [str(features.get(col, "")) for col in self._columns]
        line = self.delimiter.join(values)
        self._file.write(f"{line}\n")

    def flush(self) -> None:
        """Flush buffered data to disk."""
        if self._file:
            self._file.flush()
```

---

## Utility Functions

JoyfulJay provides utility functions for common operations.

### Statistics (`utils/stats.py`)

```python
from joyfuljay.utils.stats import (
    safe_mean,
    safe_std,
    safe_min,
    safe_max,
    safe_percentile,
)

# These functions handle empty lists gracefully
values = [1.5, 2.3, 4.1, 3.2]
mean = safe_mean(values)           # 2.775
std = safe_std(values)             # ~1.07
p95 = safe_percentile(values, 95)  # ~4.0

# Empty list returns default
empty_mean = safe_mean([])         # 0.0
empty_mean = safe_mean([], default=None)  # None
```

### Entropy (`utils/entropy.py`)

```python
from joyfuljay.utils.entropy import calculate_entropy

# Calculate Shannon entropy of bytes (0.0 to 8.0)
data = b"\x00\x01\x02\x03\x04\x05"
entropy = calculate_entropy(data)  # Low entropy (sequential)

random_data = bytes(range(256)) * 4
entropy = calculate_entropy(random_data)  # ~8.0 (high entropy)
```

### Hashing (`utils/hashing.py`)

```python
from joyfuljay.utils.hashing import (
    compute_ja3_hash,
    compute_ja3s_hash,
    compute_hassh_hash,
    anonymize_ip,
)

# JA3 fingerprint from TLS ClientHello
ja3 = compute_ja3_hash(client_hello_bytes)  # "abc123..."

# HASSH fingerprint from SSH packet
hassh = compute_hassh_hash(ssh_kex_init)    # "def456..."

# IP anonymization
anon_ip = anonymize_ip("192.168.1.1", salt="mysalt")
```

---

## Testing Patterns

### Fixture-Based Testing

```python
# tests/conftest.py provides common fixtures
@pytest.fixture
def sample_packet():
    """Create a sample TCP packet."""
    return Packet(
        timestamp=1000.0,
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        src_port=54321,
        dst_port=443,
        protocol=6,
        payload_len=100,
        total_len=140,
        tcp_flags=0x18,  # PSH+ACK
    )

@pytest.fixture
def sample_flow(sample_packet):
    """Create a sample flow with packets."""
    flow = Flow.from_first_packet(sample_packet)
    # Add more packets...
    return flow
```

### Property-Based Testing with Hypothesis

```python
from hypothesis import given, strategies as st

@given(st.lists(st.floats(min_value=0, max_value=1e6), min_size=1))
def test_mean_bounds(values):
    """Property: mean is always within [min, max]."""
    result = safe_mean(values)
    assert min(values) <= result <= max(values)

@given(st.binary(min_size=1, max_size=1000))
def test_entropy_bounds(data):
    """Property: entropy is always in [0, 8]."""
    entropy = calculate_entropy(data)
    assert 0.0 <= entropy <= 8.0
```

### Fuzz Testing

```python
# tests/fuzz/test_extractors_fuzz.py
from hypothesis import given, strategies as st

@given(
    payload=st.binary(max_size=10000),
    port=st.integers(min_value=0, max_value=65535),
)
def test_tls_extractor_handles_garbage(payload, port):
    """TLS extractor should not crash on random data."""
    packet = Packet(
        timestamp=1.0,
        src_ip="1.1.1.1",
        dst_ip="2.2.2.2",
        src_port=port,
        dst_port=443,
        protocol=6,
        payload_len=len(payload),
        total_len=len(payload) + 40,
        raw_payload=payload,
    )
    flow = Flow.from_first_packet(packet)

    extractor = TLSExtractor()
    # Should not raise exception
    features = extractor.extract(flow)
    assert isinstance(features, dict)
```

---

## Debugging Tips

### Enable Logging

```python
import logging

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("joyfuljay")
logger.setLevel(logging.DEBUG)

# Now run your pipeline
pipeline = Pipeline(config)
features = pipeline.process_pcap("capture.pcap")
```

### Inspect Individual Flows

```python
# Use iter_features for debugging
for i, features in enumerate(pipeline.iter_features("capture.pcap")):
    print(f"Flow {i}: {features['src_ip']} -> {features['dst_ip']}")
    print(f"  Duration: {features.get('duration', 'N/A')}")
    print(f"  Packets: {features.get('total_packets', 'N/A')}")

    if i > 10:  # Limit output
        break
```

### Check Extractor Output

```python
from joyfuljay.extractors.tls import TLSExtractor
from joyfuljay.core.flow import Flow

# Create flow manually
flow = Flow.from_first_packet(my_packet)
flow.add_packet(another_packet)

# Test single extractor
extractor = TLSExtractor()
features = extractor.extract(flow)
print(features)
```

### Profile Performance

```python
import cProfile
import pstats

# Profile the pipeline
profiler = cProfile.Profile()
profiler.enable()

features = pipeline.process_pcap("capture.pcap")

profiler.disable()
stats = pstats.Stats(profiler)
stats.sort_stats("cumtime")
stats.print_stats(20)  # Top 20 functions
```

### Memory Profiling

```python
# Install: pip install memory-profiler
from memory_profiler import profile

@profile
def process_large_pcap():
    pipeline = Pipeline(config)
    return pipeline.process_pcap("large.pcap")

process_large_pcap()
```

---

## Common Pitfalls

### 1. Forgetting to Handle Empty Flows

```python
# Bad: May crash on empty flow
def extract(self, flow):
    first_packet = flow.packets[0]  # IndexError if empty!

# Good: Check for empty flows
def extract(self, flow):
    if not flow.packets:
        return self._empty_features()
    first_packet = flow.packets[0]
```

### 2. Not Handling None Raw Payload

```python
# Bad: Crashes if raw_payload is None
def extract(self, flow):
    for packet in flow.packets:
        if b"HTTP" in packet.raw_payload:  # TypeError!

# Good: Check for None
def extract(self, flow):
    for packet in flow.packets:
        if packet.raw_payload and b"HTTP" in packet.raw_payload:
```

### 3. Division by Zero

```python
# Bad: Division by zero
ratio = protocol_bytes / flow.total_bytes

# Good: Use safe division
ratio = protocol_bytes / max(flow.total_bytes, 1)
```

### 4. Feature Name Mismatch

```python
# Bad: feature_names doesn't match extract() output
@property
def feature_names(self):
    return ["feature_a", "feature_b"]

def extract(self, flow):
    return {"feature_a": 1, "feature_c": 2}  # Mismatch!

# Good: Keep them synchronized
@property
def feature_names(self):
    return ["feature_a", "feature_b"]

def extract(self, flow):
    return {"feature_a": 1, "feature_b": 2}
```

---

For more examples, see the [examples/](../examples/) directory and existing extractors in `src/joyfuljay/extractors/`.
