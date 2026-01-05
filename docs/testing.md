# Testing Guide

JoyfulJay includes comprehensive testing infrastructure including unit tests, integration tests, property-based testing with Hypothesis, fuzz testing, and performance benchmarks.

## Test Organization

```
tests/
├── unit/                          # Unit tests for individual components
│   ├── test_stats_property.py     # Property-based tests for statistics
│   ├── test_entropy_property.py   # Property-based tests for entropy
│   ├── test_prometheus_metrics.py # Prometheus integration tests
│   └── extractors/                # Extractor unit tests
│       ├── test_tls.py
│       ├── test_quic.py
│       └── ...
├── integration/                   # End-to-end tests
│   ├── test_e2e_extraction.py
│   └── test_tranalyzer_e2e.py
├── fuzz/                          # Fuzz testing
│   └── test_extractors_fuzz.py
└── fixtures/                      # Shared test fixtures
    └── tranalyzer_packets.py

benchmarks/
├── benchmark_stats.py             # Statistics function benchmarks
└── benchmark_pipeline.py          # Pipeline processing benchmarks
```

## Running Tests

### All Tests

```bash
# Run all tests
pytest tests/

# With coverage
pytest tests/ --cov=src/joyfuljay --cov-report=html

# Verbose output
pytest tests/ -v
```

### Specific Test Categories

```bash
# Unit tests only
pytest tests/unit/

# Integration tests only
pytest tests/integration/

# Fuzz tests (slow)
pytest tests/fuzz/ -m slow

# Skip slow tests
pytest tests/ -m "not slow"
```

### Single Test File

```bash
pytest tests/unit/test_stats_property.py -v
```

## Property-Based Testing

Property-based testing uses [Hypothesis](https://hypothesis.readthedocs.io/) to automatically generate test inputs and verify that properties hold for all inputs.

### Installation

```bash
pip install joyfuljay[dev]  # Includes hypothesis>=6.0
```

### Statistics Properties

Located in `tests/unit/test_stats_property.py`:

```python
from hypothesis import given, strategies as st
from joyfuljay.utils.stats import compute_statistics

@given(st.lists(st.floats(allow_nan=False, allow_infinity=False), min_size=1))
def test_statistics_invariants(values):
    """Verify statistical invariants hold for any valid input."""
    stats = compute_statistics(values)

    # Property 1: min <= mean <= max
    assert stats.min <= stats.mean <= stats.max

    # Property 2: standard deviation is non-negative
    assert stats.std >= 0.0

    # Property 3: count equals input length
    assert stats.count == len(values)
```

### Tested Properties

#### Statistics (`test_stats_property.py`)

| Property | Description |
|----------|-------------|
| Ordering | `min <= mean <= max` always holds |
| Non-negative std | `std >= 0` for all inputs |
| Count consistency | `count == len(input)` |
| Sum accuracy | `sum` matches `sum(input)` within tolerance |

#### Entropy (`test_entropy_property.py`)

| Property | Description |
|----------|-------------|
| Non-negative | Entropy is always >= 0 |
| Upper bound | Entropy <= log2(alphabet_size) |
| Zero for uniform | Single-value input has entropy 0 |

#### Inter-arrival Times

| Property | Description |
|----------|-------------|
| Length | Output has length n-1 for n inputs |
| Non-negative | All gaps are >= 0 for sorted input |

### Writing Property Tests

```python
from hypothesis import given, settings, strategies as st

# Define strategies for generating test data
packet_strategy = st.fixed_dictionaries({
    "timestamp": st.floats(min_value=0, max_value=1e9),
    "payload_len": st.integers(min_value=0, max_value=65535),
    "protocol": st.sampled_from([6, 17]),  # TCP or UDP
})

@given(st.lists(packet_strategy, min_size=1, max_size=100))
@settings(max_examples=100)  # Control test iterations
def test_flow_properties(packets):
    """Test that flow properties hold for any packet sequence."""
    # Your assertions here
    pass
```

## Fuzz Testing

Fuzz testing generates random, potentially malformed inputs to find crashes and edge cases in parsers.

### Protocol Extractor Fuzzing

Located in `tests/fuzz/test_extractors_fuzz.py`:

```python
@pytest.mark.slow
@given(
    st.lists(st.binary(min_size=0, max_size=512), min_size=1, max_size=5),
    st.sampled_from([6, 17]),  # TCP or UDP
)
@settings(max_examples=50)
def test_protocol_extractors_fuzz(payloads, protocol):
    """Fuzz all protocol extractors with random payloads."""
    flow = build_flow(payloads, protocol)

    extractors = [
        TLSExtractor(),
        SSHExtractor(),
        QUICExtractor(),
        DNSExtractor(),
    ]

    for extractor in extractors:
        # Should never crash, even with garbage input
        features = extractor.extract(flow)
        assert isinstance(features, dict)
```

### Fuzz Targets

| Extractor | Attack Surface |
|-----------|---------------|
| `TLSExtractor` | ClientHello parsing, extension handling |
| `SSHExtractor` | Banner parsing, key exchange |
| `QUICExtractor` | Long/short header parsing, version negotiation |
| `DNSExtractor` | Query/response parsing, compression pointers |

### Running Fuzz Tests

```bash
# Run fuzz tests (marked as slow)
pytest tests/fuzz/ -v -m slow

# Increase examples for deeper testing
pytest tests/fuzz/ -v --hypothesis-seed=42 \
  --hypothesis-settings='{"max_examples": 1000}'
```

### Writing Fuzz Tests

```python
from hypothesis import given, strategies as st

# Strategy for generating potentially malicious TLS data
tls_fuzz_strategy = st.one_of(
    st.binary(min_size=0, max_size=1024),  # Random bytes
    st.builds(  # Structured but invalid
        lambda: b'\x16\x03\x01' + os.urandom(100),
    ),
)

@given(tls_fuzz_strategy)
def test_tls_parser_robustness(data):
    """TLS parser should handle any input without crashing."""
    try:
        result = parse_tls_record(data)
    except ParseError:
        pass  # Expected for invalid input
    # Should never raise other exceptions
```

## Performance Benchmarks

### Running Benchmarks

```bash
# Pipeline benchmark
python benchmarks/benchmark_pipeline.py

# Statistics benchmark
python benchmarks/benchmark_stats.py
```

### Pipeline Benchmark

Located in `benchmarks/benchmark_pipeline.py`:

```python
def run_benchmark():
    """Benchmark end-to-end pipeline processing."""
    pcap_path = Path("tests/data/sample.pcap")
    config = Config()
    pipeline = Pipeline(config)

    start = time.perf_counter()
    features = pipeline.process_pcap(str(pcap_path), output_format="dict")
    elapsed = time.perf_counter() - start

    print(f"Flows: {len(features)}")
    print(f"Elapsed: {elapsed:.2f}s")
    print(f"Flows/sec: {len(features) / elapsed:.2f}")
```

### Sample Output

```
======================================================================
JoyfulJay Pipeline Benchmark
======================================================================
PCAP: tests/data/sample.pcap
Flows: 1234
Elapsed: 2.45s
Flows/sec: 503.67
======================================================================
```

### Statistics Benchmark

Tests performance of statistical functions:

```python
from joyfuljay.utils.stats import compute_statistics

def benchmark_statistics():
    data_sizes = [10, 100, 1000, 10000]

    for size in data_sizes:
        data = [random.random() for _ in range(size)]

        start = time.perf_counter()
        for _ in range(1000):
            compute_statistics(data)
        elapsed = time.perf_counter() - start

        print(f"Size {size}: {elapsed/1000*1e6:.2f} us/call")
```

## Test Markers

JoyfulJay uses pytest markers to categorize tests:

| Marker | Description |
|--------|-------------|
| `@pytest.mark.slow` | Long-running tests (fuzz, large data) |
| `@pytest.mark.integration` | End-to-end integration tests |

### pytest.ini Configuration

```ini
[pytest]
markers =
    slow: marks tests as slow (deselect with '-m "not slow"')
    integration: marks tests as integration tests

addopts = -ra -q --strict-markers --strict-config
testpaths = tests
pythonpath = src
```

## Test Fixtures

### Shared Packet Fixtures

Located in `tests/fixtures/tranalyzer_packets.py`:

```python
def create_tcp_flow(num_packets=10):
    """Create a synthetic TCP flow for testing."""
    packets = []
    for i in range(num_packets):
        pkt = Packet(
            timestamp=1000.0 + i * 0.01,
            src_ip="192.168.1.100" if i % 2 == 0 else "10.0.0.1",
            dst_ip="10.0.0.1" if i % 2 == 0 else "192.168.1.100",
            src_port=54321 if i % 2 == 0 else 443,
            dst_port=443 if i % 2 == 0 else 54321,
            protocol=6,
            payload_len=100,
            total_len=140,
            tcp_flags=0x18,
        )
        packets.append(pkt)

    flow = Flow.from_first_packet(packets[0])
    for pkt in packets[1:]:
        flow.add_packet(pkt)
    return flow
```

### Using Fixtures

```python
from tests.fixtures.tranalyzer_packets import create_tcp_flow

def test_tcp_extractor():
    flow = create_tcp_flow(num_packets=20)
    extractor = TCPExtractor()
    features = extractor.extract(flow)

    assert features["tcp_is_tcp"] is True
    assert features["tcp_data_packets"] > 0
```

## Coverage

### Generating Coverage Reports

```bash
# Run tests with coverage
pytest tests/ --cov=src/joyfuljay --cov-report=html --cov-report=term

# Open HTML report
open htmlcov/index.html
```

### Coverage Configuration

In `pyproject.toml`:

```toml
[tool.coverage.run]
source = ["src/joyfuljay"]
branch = true

[tool.coverage.report]
exclude_lines = [
    "pragma: no cover",
    "if TYPE_CHECKING:",
    "@abstractmethod",
]
```

## Continuous Integration

### GitHub Actions Example

```yaml
name: Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: pip install -e ".[dev]"

      - name: Run tests
        run: pytest tests/ -v --cov=src/joyfuljay

      - name: Upload coverage
        uses: codecov/codecov-action@v4
```

## Best Practices

### Writing Good Tests

1. **Test one thing per test** - Keep tests focused
2. **Use descriptive names** - `test_tls_extracts_ja3_from_valid_handshake`
3. **Test edge cases** - Empty inputs, boundary values, malformed data
4. **Use fixtures** - Share setup code via pytest fixtures
5. **Mark slow tests** - Use `@pytest.mark.slow` for long-running tests

### Property Test Guidelines

1. **Identify invariants** - What should ALWAYS be true?
2. **Use appropriate strategies** - Match input constraints
3. **Set reasonable limits** - `max_examples=100` is often enough
4. **Reproduce failures** - Use `--hypothesis-seed` for reproducibility

### Fuzz Test Guidelines

1. **Never crash** - Extractors should handle any input
2. **Return valid types** - Always return a dict, even if empty
3. **Log interesting inputs** - Use `hypothesis.note()` for debugging
4. **Set timeouts** - Prevent infinite loops with deadline settings
