"""Utility functions for feature extraction."""

from __future__ import annotations

from .bidir_split import (
    merge_directional_features,
    split_features_bidirectional,
)
from .certificate_parser import (
    CertificateInfo,
    compute_cert_fingerprint,
    extract_certificate_features,
    parse_certificate,
)
from .entropy import byte_entropy, byte_histogram
from .file_watcher import FileWatcher, watch_directory
from .hashing import compute_ja3_hash, compute_ja3s_hash, compute_ja3_string
from .label_loader import LabelLoader, LabelMapping, load_labels_from_file
from .port_classifier import classify_port, get_port_class_name, get_port_class_number
from .progress import SimpleProgress, create_progress, create_multi_progress, is_rich_available
from .stats import compute_percentiles, compute_statistics

__all__ = [
    # Entropy
    "byte_entropy",
    "byte_histogram",
    # Statistics
    "compute_percentiles",
    "compute_statistics",
    # Bidirectional splitting
    "merge_directional_features",
    "split_features_bidirectional",
    # Certificate parsing
    "CertificateInfo",
    "compute_cert_fingerprint",
    "extract_certificate_features",
    "parse_certificate",
    # File watching
    "FileWatcher",
    "watch_directory",
    # Hashing (JA3/JA3S fingerprints)
    "compute_ja3_hash",
    "compute_ja3s_hash",
    "compute_ja3_string",
    # Label loading
    "LabelLoader",
    "LabelMapping",
    "load_labels_from_file",
    # Port classification
    "classify_port",
    "get_port_class_name",
    "get_port_class_number",
    # Progress reporting
    "SimpleProgress",
    "create_progress",
    "create_multi_progress",
    "is_rich_available",
]
