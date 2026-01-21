# Versioning Guide

## Semantic Versioning

JoyfulJay follows [Semantic Versioning 2.0.0](https://semver.org/):

```
MAJOR.MINOR.PATCH
```

### Version Components

- **MAJOR**: Breaking changes to JJ-CORE features
- **MINOR**: New features, JJ-EXTENDED changes, deprecations
- **PATCH**: Bug fixes, documentation, performance improvements

## Schema Versioning

Feature schemas are versioned separately from the library and stored at:

```
src/joyfuljay/schema/v1.0/feature_schema.json
```

### Generating Schema

```python
from joyfuljay.schema import write_schema

# Generate full schema
write_schema("schema/v1.0/feature_schema.json")

# Generate minimal schema (just types and profiles)
write_schema("schema/v1.0/feature_schema.json", minimal=True)
```

Or via CLI:

```bash
python -m joyfuljay.schema.generate -o schema/v1.0/feature_schema.json
```

### Schema Contents

The generated schema includes:

- All 401 feature definitions
- FeatureMeta for each feature (dtype, units, direction, privacy, etc.)
- Profile membership for each feature
- JoyfulJay version and total feature count

Schema version changes:
- **v1.x**: Compatible within major version
- **v2.0**: Breaking schema changes

## Profile Versioning

Profiles are tied to schema versions:

| Profile | Schema v1.0 | Notes |
|---------|-------------|-------|
| JJ-CORE | 151 features | Frozen |
| JJ-EXTENDED | 148 features | Stable |
| JJ-EXPERIMENTAL | 102 features | Unstable |

## Breaking Changes

### What Counts as Breaking

**JJ-CORE breaking changes:**
- Removing a feature
- Changing feature ID
- Changing feature semantics
- Changing data type
- Changing units

**Non-breaking changes:**
- Adding new features (to any profile)
- Bug fixes with documented errata
- Performance improvements
- Additional metadata

### Handling Breaking Changes

When breaking changes are necessary:

1. Document in CHANGELOG.md
2. Bump major version
3. Create new schema version
4. Provide migration guide

## Compatibility Matrix

| JoyfulJay | Schema | Python | Scapy |
|-----------|--------|--------|-------|
| 0.1.x | v1.0 | >=3.10 | >=2.5 |

## Release Process

1. Update version in `pyproject.toml`
2. Update version in `src/joyfuljay/__init__.py`
3. Update CITATION.cff
4. Regenerate schema if needed
5. Update CHANGELOG.md
6. Tag release

## Checking Version

```python
import joyfuljay as jj
print(jj.__version__)
```

```bash
jj --version
```

## Upgrading

### Minor Version Upgrades

```bash
pip install --upgrade joyfuljay
```

Generally safe for JJ-CORE and JJ-EXTENDED features.

### Major Version Upgrades

1. Read the CHANGELOG.md
2. Check for deprecated features
3. Test with your data
4. Update configuration if needed

## Deprecation Policy

Deprecated features:
- Are announced in CHANGELOG.md
- Include deprecation warnings
- Remain available for 2 minor versions
- Are removed in the next major version

## Version Pinning

For reproducible research, pin versions:

```
# requirements.txt
joyfuljay==0.1.0
```

Or use a range for minor updates:

```
joyfuljay>=0.1.0,<0.2.0
```

## Changelog

See [CHANGELOG.md](../../CHANGELOG.md) for detailed version history.
