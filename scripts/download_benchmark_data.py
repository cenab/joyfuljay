#!/usr/bin/env python3
"""Download benchmark datasets on demand.

This script downloads large benchmark datasets that are not included in the
git repository to reduce clone size and improve adoption.

Usage:
    python scripts/download_benchmark_data.py
    python scripts/download_benchmark_data.py --suite quick
    python scripts/download_benchmark_data.py --suite full --output benchmarks/_data_cache
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
import urllib.request
from pathlib import Path

# Dataset definitions: (name, url, sha256, size_mb)
DATASETS = {
    # Quick suite: small files for rapid testing
    "quick": [
        # Wireshark sample captures (small)
        (
            "http_simple.pcap",
            "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/http.cap",
            None,  # No hash verification for external files
            0.1,
        ),
    ],
    # Full suite: comprehensive benchmarking
    "full": [
        # MAWI traffic archive samples
        (
            "mawi_sample.pcap.gz",
            "https://mawi.wide.ad.jp/mawi/samplepoint-F/2023/202301011400.pcap.gz",
            None,
            50.0,
        ),
        # CICIDS dataset samples
        (
            "cicids_sample.pcap",
            "https://www.unb.ca/cic/datasets/ids-2017.html",  # Manual download required
            None,
            100.0,
        ),
    ],
}

# Default cache directory
DEFAULT_CACHE_DIR = Path(__file__).parent.parent / "benchmarks" / "_data_cache"


def download_file(url: str, dest: Path, expected_sha256: str | None = None) -> bool:
    """Download a file with optional hash verification.

    Args:
        url: URL to download from.
        dest: Destination path.
        expected_sha256: Expected SHA256 hash (optional).

    Returns:
        True if download succeeded, False otherwise.
    """
    print(f"Downloading: {url}")
    print(f"  -> {dest}")

    try:
        # Create parent directory
        dest.parent.mkdir(parents=True, exist_ok=True)

        # Download with progress
        with urllib.request.urlopen(url, timeout=60) as response:
            total_size = int(response.headers.get("Content-Length", 0))
            downloaded = 0
            block_size = 8192

            with open(dest, "wb") as f:
                while True:
                    chunk = response.read(block_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)

                    if total_size > 0:
                        pct = (downloaded / total_size) * 100
                        print(f"\r  Progress: {pct:.1f}%", end="", flush=True)

        print()  # Newline after progress

        # Verify hash if provided
        if expected_sha256:
            actual_hash = hashlib.sha256(dest.read_bytes()).hexdigest()
            if actual_hash != expected_sha256:
                print(f"  ERROR: Hash mismatch!")
                print(f"    Expected: {expected_sha256}")
                print(f"    Got: {actual_hash}")
                dest.unlink()
                return False
            print(f"  Hash verified: {expected_sha256[:16]}...")

        return True

    except Exception as e:
        print(f"  ERROR: {e}")
        if dest.exists():
            dest.unlink()
        return False


def download_suite(suite: str, cache_dir: Path) -> tuple[int, int]:
    """Download all datasets in a suite.

    Args:
        suite: Suite name ("quick" or "full").
        cache_dir: Cache directory for downloads.

    Returns:
        Tuple of (success_count, total_count).
    """
    if suite not in DATASETS:
        print(f"Unknown suite: {suite}")
        print(f"Available suites: {', '.join(DATASETS.keys())}")
        return 0, 0

    datasets = DATASETS[suite]
    success = 0

    print(f"\nDownloading {suite} suite ({len(datasets)} files)...")
    print(f"Cache directory: {cache_dir}\n")

    for name, url, sha256, size_mb in datasets:
        dest = cache_dir / suite / name

        if dest.exists():
            print(f"Skipping (exists): {name}")
            success += 1
            continue

        # Check for manual download requirement
        if "Manual download" in url or not url.startswith("http"):
            print(f"MANUAL: {name}")
            print(f"  Please download from: {url}")
            print(f"  Save to: {dest}")
            continue

        if download_file(url, dest, sha256):
            success += 1

    return success, len(datasets)


def list_cached_files(cache_dir: Path) -> None:
    """List all cached benchmark files."""
    if not cache_dir.exists():
        print("No cached files found.")
        return

    print(f"Cached files in {cache_dir}:\n")
    total_size = 0

    for path in sorted(cache_dir.rglob("*")):
        if path.is_file():
            size = path.stat().st_size
            total_size += size
            size_str = f"{size / 1024 / 1024:.1f} MB" if size > 1024 * 1024 else f"{size / 1024:.1f} KB"
            print(f"  {path.relative_to(cache_dir)}: {size_str}")

    print(f"\nTotal: {total_size / 1024 / 1024:.1f} MB")


def clean_cache(cache_dir: Path) -> None:
    """Remove all cached files."""
    if not cache_dir.exists():
        print("Cache directory does not exist.")
        return

    size = sum(f.stat().st_size for f in cache_dir.rglob("*") if f.is_file())
    shutil.rmtree(cache_dir)
    print(f"Removed {size / 1024 / 1024:.1f} MB from cache.")


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Download benchmark datasets for JoyfulJay."
    )
    parser.add_argument(
        "--suite",
        choices=["quick", "full", "all"],
        default="quick",
        help="Dataset suite to download (default: quick).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_CACHE_DIR,
        help=f"Cache directory (default: {DEFAULT_CACHE_DIR}).",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List cached files instead of downloading.",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Remove all cached files.",
    )

    args = parser.parse_args()

    if args.clean:
        clean_cache(args.output)
        return 0

    if args.list:
        list_cached_files(args.output)
        return 0

    # Download
    suites = ["quick", "full"] if args.suite == "all" else [args.suite]
    total_success = 0
    total_files = 0

    for suite in suites:
        success, count = download_suite(suite, args.output)
        total_success += success
        total_files += count

    print(f"\nDownloaded {total_success}/{total_files} files.")

    if total_success < total_files:
        print("\nSome files require manual download. See messages above.")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
