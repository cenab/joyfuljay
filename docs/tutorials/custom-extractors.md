# Creating Custom Extractors

Build your own feature extractors to extend JoyfulJay.

---

## Overview

Extractors transform flows into feature dictionaries. JoyfulJay's plugin architecture lets you add custom extractors without modifying the core library.

---

## Basic Extractor

```python
from joyfuljay.extractors import FeatureExtractor
from joyfuljay.core import Flow

class MyExtractor(FeatureExtractor):
    """Example custom extractor."""

    def extract(self, flow: Flow) -> dict:
        """Extract features from a flow.

        Args:
            flow: A completed network flow

        Returns:
            Dictionary of feature_name -> value
        """
        return {
            "my_packet_count": flow.packet_count,
            "my_byte_count": flow.byte_count,
            "my_duration": flow.duration,
        }

    @property
    def feature_names(self) -> list[str]:
        """Return list of feature names this extractor produces."""
        return ["my_packet_count", "my_byte_count", "my_duration"]
```

---

## Registering Your Extractor

### Option 1: Direct Registration

```python
import joyfuljay as jj
from joyfuljay.pipeline import register_extractor

# Register with a group name
register_extractor("my_features", MyExtractor)

# Now use it
config = jj.Config(features=["flow_meta", "my_features"])
pipeline = jj.Pipeline(config)
df = pipeline.process_pcap("capture.pcap")
```

### Option 2: Plugin Entry Point

Add to your `pyproject.toml`:

```toml
[project.entry-points."joyfuljay.extractors"]
my_features = "my_package.extractors:MyExtractor"
```

The extractor will be automatically discovered when JoyfulJay loads.

---

## Accessing Flow Data

### Flow Object

```python
class Flow:
    key: FlowKey           # 5-tuple identifier
    packets: list[Packet]  # All packets in flow
    start_time: float      # First packet timestamp
    end_time: float        # Last packet timestamp
    duration: float        # Duration in seconds
    packet_count: int      # Total packets
    byte_count: int        # Total bytes
    terminated: bool       # FIN/RST seen
```

### FlowKey Object

```python
class FlowKey:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int  # 6=TCP, 17=UDP
```

### Packet Object

```python
class Packet:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    payload_len: int
    total_len: int
    tcp_flags: int
    raw_payload: bytes
```

---

## Example: Payload Pattern Extractor

```python
import re
from joyfuljay.extractors import FeatureExtractor
from joyfuljay.core import Flow

class PayloadPatternExtractor(FeatureExtractor):
    """Detect patterns in packet payloads."""

    def __init__(self):
        self.patterns = {
            "http_request": re.compile(rb"^(GET|POST|PUT|DELETE|HEAD)\s"),
            "http_response": re.compile(rb"^HTTP/\d\.\d\s\d{3}"),
            "ssh_banner": re.compile(rb"^SSH-\d\.\d"),
            "smtp_greeting": re.compile(rb"^220\s"),
        }

    def extract(self, flow: Flow) -> dict:
        results = {
            "has_http_request": False,
            "has_http_response": False,
            "has_ssh_banner": False,
            "has_smtp_greeting": False,
            "first_payload_bytes": 0,
        }

        for packet in flow.packets:
            if not packet.raw_payload:
                continue

            # Check first packet with payload
            if results["first_payload_bytes"] == 0:
                results["first_payload_bytes"] = len(packet.raw_payload)

            # Check patterns
            for name, pattern in self.patterns.items():
                if pattern.search(packet.raw_payload[:100]):
                    results[f"has_{name}"] = True

        return results

    @property
    def feature_names(self) -> list[str]:
        return [
            "has_http_request",
            "has_http_response",
            "has_ssh_banner",
            "has_smtp_greeting",
            "first_payload_bytes",
        ]
```

---

## Example: Statistical Extractor

```python
from joyfuljay.extractors import FeatureExtractor
from joyfuljay.core import Flow
from joyfuljay.utils import compute_statistics

class AdvancedTimingExtractor(FeatureExtractor):
    """Advanced timing statistics."""

    def extract(self, flow: Flow) -> dict:
        if len(flow.packets) < 2:
            return self._empty_result()

        # Compute inter-arrival times
        timestamps = [p.timestamp for p in flow.packets]
        iats = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]

        # Get statistics
        stats = compute_statistics(iats)

        # Compute burst metrics
        burst_threshold = 0.05  # 50ms
        bursts = self._count_bursts(iats, burst_threshold)

        return {
            "adv_iat_mean": stats.mean,
            "adv_iat_std": stats.std,
            "adv_iat_skew": self._skewness(iats),
            "adv_iat_kurtosis": self._kurtosis(iats),
            "adv_burst_count": bursts,
            "adv_burst_ratio": bursts / len(iats) if iats else 0,
        }

    def _empty_result(self) -> dict:
        return {name: 0.0 for name in self.feature_names}

    def _count_bursts(self, iats: list[float], threshold: float) -> int:
        return sum(1 for iat in iats if iat < threshold)

    def _skewness(self, values: list[float]) -> float:
        if len(values) < 3:
            return 0.0
        n = len(values)
        mean = sum(values) / n
        std = (sum((x - mean) ** 2 for x in values) / n) ** 0.5
        if std == 0:
            return 0.0
        return sum(((x - mean) / std) ** 3 for x in values) / n

    def _kurtosis(self, values: list[float]) -> float:
        if len(values) < 4:
            return 0.0
        n = len(values)
        mean = sum(values) / n
        std = (sum((x - mean) ** 2 for x in values) / n) ** 0.5
        if std == 0:
            return 0.0
        return sum(((x - mean) / std) ** 4 for x in values) / n - 3

    @property
    def feature_names(self) -> list[str]:
        return [
            "adv_iat_mean",
            "adv_iat_std",
            "adv_iat_skew",
            "adv_iat_kurtosis",
            "adv_burst_count",
            "adv_burst_ratio",
        ]
```

---

## Example: Protocol-Specific Extractor

```python
from joyfuljay.extractors import FeatureExtractor
from joyfuljay.core import Flow

class GameTrafficExtractor(FeatureExtractor):
    """Detect and analyze gaming traffic patterns."""

    GAME_PORTS = {
        27015: "source_engine",  # CS:GO, TF2
        3478: "stun",           # Many games
        3074: "xbox_live",
        3658: "playstation",
    }

    def extract(self, flow: Flow) -> dict:
        # Check if likely game traffic
        dst_port = flow.key.dst_port
        src_port = flow.key.src_port

        game_type = self.GAME_PORTS.get(dst_port) or self.GAME_PORTS.get(src_port)

        if not game_type:
            return self._not_game()

        # Analyze game traffic patterns
        packet_sizes = [p.payload_len for p in flow.packets]
        timestamps = [p.timestamp for p in flow.packets]

        # Games have regular packet rates
        if len(timestamps) >= 2:
            iats = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            avg_iat = sum(iats) / len(iats) if iats else 0
            pps = 1 / avg_iat if avg_iat > 0 else 0
        else:
            pps = 0

        return {
            "is_game_traffic": True,
            "game_type": game_type,
            "game_pps": pps,
            "game_avg_pkt_size": sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0,
            "game_pkt_size_variance": self._variance(packet_sizes),
        }

    def _not_game(self) -> dict:
        return {
            "is_game_traffic": False,
            "game_type": "",
            "game_pps": 0.0,
            "game_avg_pkt_size": 0.0,
            "game_pkt_size_variance": 0.0,
        }

    def _variance(self, values: list[int]) -> float:
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        return sum((x - mean) ** 2 for x in values) / len(values)

    @property
    def feature_names(self) -> list[str]:
        return [
            "is_game_traffic",
            "game_type",
            "game_pps",
            "game_avg_pkt_size",
            "game_pkt_size_variance",
        ]
```

---

## Testing Your Extractor

```python
import pytest
from joyfuljay.core import Flow, Packet, FlowKey

def test_my_extractor():
    # Create test flow
    key = FlowKey(
        src_ip="192.168.1.10",
        dst_ip="10.0.0.1",
        src_port=12345,
        dst_port=443,
        protocol=6,
    )

    packets = [
        Packet(
            timestamp=0.0,
            src_ip="192.168.1.10",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=443,
            protocol=6,
            payload_len=100,
            total_len=140,
            tcp_flags=0x02,  # SYN
            raw_payload=b"",
        ),
        Packet(
            timestamp=0.1,
            src_ip="192.168.1.10",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=443,
            protocol=6,
            payload_len=500,
            total_len=540,
            tcp_flags=0x10,  # ACK
            raw_payload=b"GET / HTTP/1.1\r\n",
        ),
    ]

    flow = Flow.from_first_packet(packets[0])
    flow.add_packet(packets[1])

    # Test extractor
    extractor = MyExtractor()
    features = extractor.extract(flow)

    assert features["my_packet_count"] == 2
    assert features["my_byte_count"] > 0
    assert "my_duration" in features
```

---

## Best Practices

1. **Return consistent types**: Always return the same keys, use default values for missing data
2. **Handle edge cases**: Empty flows, single-packet flows, missing payloads
3. **Use utilities**: Import from `joyfuljay.utils` for statistics, entropy, etc.
4. **Document features**: Describe what each feature represents
5. **Test thoroughly**: Cover edge cases in unit tests

---

## See Also

- [Developer Guide](../developer-guide.md) - Full development reference
- [Architecture](../architecture.md) - Extractor framework design
- [API Reference](../api.md) - Core classes documentation
