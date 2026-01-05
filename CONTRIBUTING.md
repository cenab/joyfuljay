# Contributing to JoyfulJay

Thank you for your interest in contributing to JoyfulJay! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Code Standards](#code-standards)
- [Testing](#testing)
- [Adding Features](#adding-features)
- [Pull Request Process](#pull-request-process)

---

## Getting Started

### Fork & Clone

1. Fork the repository on GitHub
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/joyfuljay.git
   cd joyfuljay
   ```
3. Add the upstream remote:
   ```bash
   git remote add upstream https://github.com/joyfuljay/joyfuljay.git
   ```

### Development Environment Setup

1. Create a virtual environment (Python 3.10+):
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/macOS
   # or: venv\Scripts\activate  # Windows
   ```

2. Install in development mode with all extras:
   ```bash
   pip install -e ".[dev,fast,kafka,monitoring,discovery,graphs]"
   ```

3. Verify installation:
   ```bash
   jj status
   pytest tests/ -x
   ```

---

## Code Standards

### Style Guide

We use **ruff** for linting and formatting, and **mypy** for type checking in strict mode.

```bash
# Format code
ruff format src tests

# Lint code
ruff check src tests

# Type check
mypy src
```

#### Key Style Rules

- **Line length**: 100 characters max
- **Quotes**: Double quotes for strings
- **Imports**: Sorted by isort (handled by ruff)
- **Type hints**: Required for all public functions
- **Docstrings**: Google style for public APIs

#### Example Code Style

```python
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

def calculate_entropy(data: bytes, sample_size: int = 1024) -> float:
    """Calculate Shannon entropy of byte data.

    Args:
        data: Raw bytes to analyze.
        sample_size: Maximum bytes to sample.

    Returns:
        Entropy value between 0.0 and 8.0.

    Raises:
        ValueError: If data is empty.
    """
    if not data:
        raise ValueError("Data cannot be empty")
    # Implementation...
```

### Commit Message Conventions

Use conventional commit format:

```
type(scope): description

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style (formatting, no logic change)
- `refactor`: Code change (no feature/fix)
- `test`: Adding/updating tests
- `perf`: Performance improvement
- `chore`: Build, CI, dependencies

**Examples:**
```
feat(extractors): add HTTP/2 protocol extractor
fix(tls): handle missing SNI in ClientHello
docs(readme): update installation instructions
test(entropy): add property-based tests
```

---

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src/joyfuljay --cov-report=html

# Run specific test file
pytest tests/unit/test_flow.py

# Run tests matching pattern
pytest -k "test_entropy"

# Skip slow tests
pytest -m "not slow"

# Run only integration tests
pytest -m integration
```

### Test Organization

```
tests/
├── conftest.py              # Shared fixtures
├── fixtures/                # Test data generators
│   ├── packets.py           # Packet factory fixtures
│   └── tranalyzer_packets.py
├── unit/                    # Unit tests
│   ├── test_*.py            # Core module tests
│   └── extractors/          # Extractor-specific tests
│       └── test_*.py
├── integration/             # End-to-end tests
│   └── test_*.py
└── fuzz/                    # Fuzz/property tests
    └── test_*.py
```

### Writing Tests

#### Unit Test Example

```python
import pytest
from joyfuljay.core.packet import Packet

def test_packet_creation():
    """Test basic packet creation with required fields."""
    packet = Packet(
        timestamp=1.0,
        src_ip="192.168.1.1",
        dst_ip="10.0.0.1",
        src_port=12345,
        dst_port=443,
        protocol=6,
        payload_len=100,
        total_len=140,
    )
    assert packet.src_ip == "192.168.1.1"
    assert packet.total_len == 140


def test_packet_requires_protocol():
    """Test that protocol field is required."""
    with pytest.raises(TypeError):
        Packet(timestamp=1.0, src_ip="1.1.1.1", dst_ip="2.2.2.2")
```

#### Using Fixtures

```python
def test_extractor_with_fixtures(sample_flow):
    """Test extractor using the sample_flow fixture from conftest.py."""
    extractor = MyExtractor()
    features = extractor.extract(sample_flow)
    assert "my_feature" in features
```

#### Property-Based Testing (Hypothesis)

```python
from hypothesis import given, strategies as st

@given(st.lists(st.floats(min_value=0, max_value=1e6), min_size=1, max_size=1000))
def test_mean_is_within_range(values):
    """Property: mean is always between min and max."""
    result = calculate_mean(values)
    assert min(values) <= result <= max(values)
```

### Coverage Requirements

- **New code**: Must have >90% test coverage
- **Bug fixes**: Include a regression test
- **Extractors**: Test all extracted features

---

## Adding Features

### Adding a New Extractor

1. **Create the extractor file** in `src/joyfuljay/extractors/`:

```python
# src/joyfuljay/extractors/my_protocol.py
"""My Protocol feature extractor."""

from __future__ import annotations

from typing import Any

from joyfuljay.core.flow import Flow
from joyfuljay.extractors.base import FeatureExtractor


class MyProtocolExtractor(FeatureExtractor):
    """Extract features from My Protocol traffic."""

    # Feature group name (used in config.features list)
    name = "my_protocol"

    # Features this extractor produces
    features = [
        "my_protocol_feature_a",
        "my_protocol_feature_b",
        "my_protocol_ratio",
    ]

    def extract(self, flow: Flow) -> dict[str, Any]:
        """Extract My Protocol features from a flow.

        Args:
            flow: Network flow to analyze.

        Returns:
            Dictionary of feature names to values.
        """
        # Initialize defaults
        feature_a = 0
        feature_b = 0

        # Process packets
        for packet in flow.packets:
            if self._is_my_protocol(packet):
                feature_a += 1
                feature_b += packet.payload_len

        # Calculate derived features
        ratio = feature_a / max(feature_b, 1)

        return {
            "my_protocol_feature_a": feature_a,
            "my_protocol_feature_b": feature_b,
            "my_protocol_ratio": ratio,
        }

    def _is_my_protocol(self, packet) -> bool:
        """Check if packet is My Protocol."""
        # Implementation
        return False
```

2. **Register the extractor** in `src/joyfuljay/extractors/__init__.py`:

```python
from .my_protocol import MyProtocolExtractor

EXTRACTORS = {
    # ... existing extractors ...
    "my_protocol": MyProtocolExtractor,
}
```

3. **Add tests** in `tests/unit/extractors/test_my_protocol.py`:

```python
import pytest
from joyfuljay.extractors.my_protocol import MyProtocolExtractor

def test_my_protocol_extractor_features():
    """Test that extractor defines expected features."""
    extractor = MyProtocolExtractor()
    assert "my_protocol_feature_a" in extractor.features


def test_my_protocol_extraction(sample_flow):
    """Test feature extraction on sample flow."""
    extractor = MyProtocolExtractor()
    features = extractor.extract(sample_flow)

    assert "my_protocol_feature_a" in features
    assert isinstance(features["my_protocol_feature_a"], (int, float))
```

4. **Add documentation** in `docs/extractors/my-protocol.md`

### Adding CLI Commands

1. **Create the command** in `src/joyfuljay/cli/`:

```python
# src/joyfuljay/cli/commands/my_command.py
import click

@click.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
def my_command(input_file: str, verbose: bool) -> None:
    """Short description of the command.

    Longer description explaining what the command does,
    when to use it, and any important notes.
    """
    if verbose:
        click.echo(f"Processing {input_file}...")

    # Implementation
    click.echo("Done!")
```

2. **Register in main CLI** (`src/joyfuljay/cli/main.py`):

```python
from joyfuljay.cli.commands.my_command import my_command

cli.add_command(my_command)
```

### Adding Output Formats

1. **Implement the StreamingWriter protocol**:

```python
# src/joyfuljay/output/my_format.py
from __future__ import annotations

from typing import Any

class MyFormatWriter:
    """Write features to My Format."""

    def __init__(self, path: str, **options: Any) -> None:
        self.path = path
        self.options = options
        self._file = None

    def __enter__(self) -> "MyFormatWriter":
        self._file = open(self.path, "w")
        return self

    def __exit__(self, *args: Any) -> None:
        if self._file:
            self._file.close()

    def write(self, features: dict[str, Any]) -> None:
        """Write a single feature record."""
        # Implementation
        pass

    def flush(self) -> None:
        """Flush any buffered data."""
        if self._file:
            self._file.flush()
```

---

## Pull Request Process

### Before Submitting

1. **Sync with upstream**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run all checks**:
   ```bash
   ruff format src tests
   ruff check src tests
   mypy src
   pytest
   ```

3. **Update documentation** if needed

### PR Requirements

- [ ] All tests pass
- [ ] Code is formatted (`ruff format`)
- [ ] No linting errors (`ruff check`)
- [ ] Type checks pass (`mypy src`)
- [ ] New code has tests (>90% coverage)
- [ ] Docstrings for public APIs
- [ ] Documentation updated (if applicable)
- [ ] Commit messages follow conventions

### PR Description Template

```markdown
## Summary
Brief description of changes.

## Changes
- Change 1
- Change 2

## Testing
How was this tested?

## Checklist
- [ ] Tests added
- [ ] Documentation updated
- [ ] Type hints added
```

### Review Process

1. A maintainer will review your PR
2. Address any feedback
3. Once approved, a maintainer will merge

---

## Getting Help

- **Questions**: Open a [Discussion](https://github.com/joyfuljay/joyfuljay/discussions)
- **Bugs**: Open an [Issue](https://github.com/joyfuljay/joyfuljay/issues)
- **Security**: Email security@joyfuljay.dev (do not open public issues)

---

## Code of Conduct

We follow the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

Be respectful, inclusive, and constructive in all interactions.

---

Thank you for contributing to JoyfulJay!
