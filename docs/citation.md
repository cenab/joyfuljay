# Citing JoyfulJay

When using JoyfulJay in your research, please cite it appropriately. Proper citation helps reproducibility and acknowledges the work of contributors.

## Citation Formats

### BibTeX

```bibtex
@software{joyfuljay2025,
  author       = {{JoyfulJay Contributors}},
  title        = {JoyfulJay: ML-Ready Feature Extraction from Encrypted Network Traffic},
  year         = {2025},
  publisher    = {GitHub},
  url          = {https://github.com/cenab/joyfuljay},
  version      = {0.1.0}
}
```

### APA Style

JoyfulJay Contributors. (2025). *JoyfulJay: ML-Ready Feature Extraction from Encrypted Network Traffic* (Version 0.1.0) [Computer software]. https://github.com/cenab/joyfuljay

### IEEE Style

JoyfulJay Contributors, "JoyfulJay: ML-Ready Feature Extraction from Encrypted Network Traffic," GitHub, 2025. [Online]. Available: https://github.com/cenab/joyfuljay

## Reporting Results

!!! important "Reproducibility Requirements"
    When reporting results obtained using JoyfulJay, you **must** specify:

    1. **JoyfulJay version** (e.g., `0.1.0`)
    2. **Feature profile** (e.g., `JJ-CORE v1.0`)
    3. **Schema version** (e.g., `v1.0`)

### Example Methods Section

> Feature extraction was performed using JoyfulJay v0.1.0 with the JJ-CORE v1.0
> feature profile (151 features) and schema version v1.0. Flow timeout was set
> to 120 seconds with bidirectional flow aggregation.

### Why This Matters

Different versions of JoyfulJay may:
- Have different feature sets
- Use different extraction algorithms
- Produce different output schemas

By specifying the exact version and profile, others can reproduce your results.

## Getting Version Information

### Command Line

```bash
# Show version
jj --version

# Get citation in BibTeX format
jj cite

# Get citation in APA format
jj cite -f apa

# Show provenance metadata for a feature file
jj info features.csv
```

### Python API

```python
import joyfuljay as jj

# Get version
print(jj.__version__)

# Get profile info
from joyfuljay.schema import get_profile_info
info = get_profile_info("JJ-CORE")
print(f"Profile: {info['name']}, Features: {info['count']}")
```

## Provenance Metadata

JoyfulJay can automatically generate provenance metadata with each extraction:

```python
from joyfuljay.provenance import build_provenance

provenance = build_provenance(
    profile="JJ-CORE",
    schema_version="v1.0",
    backend="dpkt",
    capture_mode="offline",
    config=config.to_dict()
)
```

This produces a sidecar JSON file containing all information needed for reproducibility.

## CITATION.cff

The repository includes a `CITATION.cff` file for automatic citation by GitHub and other tools.

## Related Documentation

- [Determinism Guarantees](concepts/determinism.md) - How JoyfulJay ensures reproducible output
- [Versioning Guide](release/versioning.md) - Understanding version numbers
- [Reproducibility](release/reproducibility.md) - Feature freeze policy and profiles
