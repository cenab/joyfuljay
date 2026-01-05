# Batch Processing

Process large PCAP datasets efficiently.

---

## Overview

When processing multiple PCAP files or large datasets:
- Use parallel processing for multiple files
- Use streaming for memory efficiency
- Use the fast DPKT backend for speed

---

## Processing Multiple Files

### Sequential Processing

```python
import joyfuljay as jj
import pandas as pd
from pathlib import Path

config = jj.Config(features=["timing", "tls"])
pipeline = jj.Pipeline(config)

all_data = []
pcap_dir = Path("./captures")

for pcap_file in pcap_dir.glob("*.pcap"):
    print(f"Processing {pcap_file.name}...")
    df = pipeline.process_pcap(str(pcap_file))
    df["source_file"] = pcap_file.name
    all_data.append(df)

combined = pd.concat(all_data, ignore_index=True)
combined.to_csv("all_features.csv", index=False)
print(f"Total flows: {len(combined)}")
```

### Parallel Processing

```python
import joyfuljay as jj
from pathlib import Path

config = jj.Config(features=["timing", "tls"])
pipeline = jj.Pipeline(config)

# Get all PCAP files
pcap_files = list(Path("./captures").glob("*.pcap"))

# Process in parallel (uses multiple CPU cores)
df = pipeline.process_pcaps_batch(
    [str(f) for f in pcap_files],
    num_workers=4,  # Number of parallel workers
)

df.to_csv("all_features.csv", index=False)
print(f"Processed {len(pcap_files)} files, {len(df)} flows")
```

---

## Memory-Efficient Processing

### Streaming to File

For large files that don't fit in memory:

```python
import joyfuljay as jj
from joyfuljay.output import StreamingWriter

config = jj.Config(features=["timing", "tls"])
pipeline = jj.Pipeline(config)

# Write directly to CSV without loading all data into memory
with StreamingWriter("output.csv", format="csv") as writer:
    for features in pipeline.iter_features("large_capture.pcap"):
        writer.write(features)

print("Processing complete")
```

### Streaming Multiple Files

```python
import joyfuljay as jj
from joyfuljay.output import StreamingWriter
from pathlib import Path

config = jj.Config(features=["timing", "tls"])
pipeline = jj.Pipeline(config)

pcap_files = list(Path("./captures").glob("*.pcap"))

with StreamingWriter("all_features.csv", format="csv") as writer:
    for pcap_file in pcap_files:
        print(f"Processing {pcap_file.name}...")
        for features in pipeline.iter_features(str(pcap_file)):
            features["source_file"] = pcap_file.name
            writer.write(features)

print(f"Processed {len(pcap_files)} files")
```

---

## Fast Processing with DPKT

The DPKT backend is 10x faster than Scapy:

```bash
# Install fast backend
pip install joyfuljay[fast]
```

```python
import joyfuljay as jj
from joyfuljay.capture import DpktBackend

# Use fast backend explicitly
config = jj.Config(
    features=["timing", "size"],
    capture_backend="dpkt",  # 10x faster
)
pipeline = jj.Pipeline(config)

df = pipeline.process_pcap("large_capture.pcap")
```

---

## Database Output

### SQLite

```python
import joyfuljay as jj
from joyfuljay.output import DatabaseWriter
from pathlib import Path

config = jj.Config(features=["timing", "tls"])
pipeline = jj.Pipeline(config)

with DatabaseWriter("sqlite:///features.db", table="flows") as writer:
    for pcap_file in Path("./captures").glob("*.pcap"):
        for features in pipeline.iter_features(str(pcap_file)):
            features["source_file"] = pcap_file.name
            writer.write(features)

print("Data written to features.db")
```

### PostgreSQL

```python
from joyfuljay.output import DatabaseWriter

connection_string = "postgresql://user:password@localhost/traffic_db"

with DatabaseWriter(connection_string, table="network_flows") as writer:
    for features in pipeline.iter_features("capture.pcap"):
        writer.write(features)
```

---

## Parquet Output

Parquet is efficient for large datasets:

```bash
# Install parquet support
pip install pyarrow
```

```python
import joyfuljay as jj
import pandas as pd

config = jj.Config(features=["timing", "tls"])
pipeline = jj.Pipeline(config)

df = pipeline.process_pcap("capture.pcap")
df.to_parquet("features.parquet", index=False)

# Read back efficiently
df_loaded = pd.read_parquet("features.parquet")
```

### Streaming to Parquet

```python
import joyfuljay as jj
from joyfuljay.output import StreamingWriter

config = jj.Config(features=["timing", "tls"])
pipeline = jj.Pipeline(config)

with StreamingWriter("features.parquet", format="parquet") as writer:
    for features in pipeline.iter_features("large_capture.pcap"):
        writer.write(features)
```

---

## Progress Monitoring

### With Rich Progress Bar

```bash
pip install rich
```

```python
import joyfuljay as jj
from joyfuljay.utils import create_progress
from pathlib import Path

config = jj.Config(features=["timing", "tls"])
pipeline = jj.Pipeline(config)

pcap_files = list(Path("./captures").glob("*.pcap"))

with create_progress() as progress:
    task = progress.add_task("Processing PCAPs", total=len(pcap_files))

    all_data = []
    for pcap_file in pcap_files:
        df = pipeline.process_pcap(str(pcap_file))
        all_data.append(df)
        progress.advance(task)
```

### Simple Progress

```python
import joyfuljay as jj
from joyfuljay.utils import SimpleProgress
from pathlib import Path

config = jj.Config(features=["timing", "tls"])
pipeline = jj.Pipeline(config)

pcap_files = list(Path("./captures").glob("*.pcap"))

progress = SimpleProgress(total=len(pcap_files), description="Processing")

for pcap_file in pcap_files:
    df = pipeline.process_pcap(str(pcap_file))
    progress.update(1)

progress.close()
```

---

## Sampling for Large Datasets

Process a subset of packets:

```python
import joyfuljay as jj

config = jj.Config(
    features=["timing", "tls"],
    sampling_rate=0.1,  # Process 10% of packets
)
pipeline = jj.Pipeline(config)

df = pipeline.process_pcap("very_large_capture.pcap")
```

---

## Complete Batch Processing Script

```python
#!/usr/bin/env python3
"""Batch process PCAP files with progress and error handling."""

import argparse
import sys
from pathlib import Path

import joyfuljay as jj
from joyfuljay.output import StreamingWriter
from joyfuljay.utils import create_progress, is_rich_available

def main():
    parser = argparse.ArgumentParser(description="Batch PCAP processor")
    parser.add_argument("input_dir", help="Directory containing PCAP files")
    parser.add_argument("-o", "--output", default="features.csv", help="Output file")
    parser.add_argument("-f", "--format", default="csv", choices=["csv", "parquet", "json"])
    parser.add_argument("-w", "--workers", type=int, default=1, help="Parallel workers")
    parser.add_argument("--features", nargs="+", default=["timing", "tls"])
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    if not input_dir.exists():
        print(f"Error: {input_dir} does not exist")
        sys.exit(1)

    pcap_files = list(input_dir.glob("**/*.pcap")) + list(input_dir.glob("**/*.pcapng"))
    if not pcap_files:
        print(f"No PCAP files found in {input_dir}")
        sys.exit(1)

    print(f"Found {len(pcap_files)} PCAP files")
    print(f"Features: {args.features}")
    print(f"Output: {args.output} ({args.format})")

    config = jj.Config(features=args.features)
    pipeline = jj.Pipeline(config)

    errors = []

    if args.workers > 1:
        # Parallel processing
        print(f"Processing with {args.workers} workers...")
        df = pipeline.process_pcaps_batch(
            [str(f) for f in pcap_files],
            num_workers=args.workers,
        )
        if args.format == "csv":
            df.to_csv(args.output, index=False)
        elif args.format == "parquet":
            df.to_parquet(args.output, index=False)
        else:
            df.to_json(args.output, orient="records", lines=True)
    else:
        # Streaming processing
        with StreamingWriter(args.output, format=args.format) as writer:
            if is_rich_available():
                with create_progress() as progress:
                    task = progress.add_task("Processing", total=len(pcap_files))
                    for pcap_file in pcap_files:
                        try:
                            for features in pipeline.iter_features(str(pcap_file)):
                                features["source_file"] = pcap_file.name
                                writer.write(features)
                        except Exception as e:
                            errors.append((pcap_file.name, str(e)))
                        progress.advance(task)
            else:
                for i, pcap_file in enumerate(pcap_files, 1):
                    print(f"[{i}/{len(pcap_files)}] {pcap_file.name}")
                    try:
                        for features in pipeline.iter_features(str(pcap_file)):
                            features["source_file"] = pcap_file.name
                            writer.write(features)
                    except Exception as e:
                        errors.append((pcap_file.name, str(e)))

    print(f"\nProcessing complete: {args.output}")

    if errors:
        print(f"\nErrors ({len(errors)}):")
        for filename, error in errors:
            print(f"  {filename}: {error}")

if __name__ == "__main__":
    main()
```

---

## CLI Batch Commands

```bash
# Process all PCAPs in directory
jj extract ./captures/*.pcap -o features.csv

# With specific features
jj extract ./captures/*.pcap -o features.csv --features timing tls fingerprint

# Watch directory for new files
jj watch ./incoming --output ./processed --format parquet
```

---

## See Also

- [CLI Reference](../cli-reference.md) - Command-line options
- [Configuration](../configuration.md) - All config options
- [API Reference](../api.md) - Pipeline methods
