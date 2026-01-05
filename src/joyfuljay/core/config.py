"""Configuration classes for JoyfulJay."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Literal

EvictionStrategy = Literal["lru", "oldest"]
CaptureBackendType = Literal["scapy", "dpkt", "auto"]


class FeatureGroup(str, Enum):
    """Available feature extraction groups."""

    ALL = "all"
    FLOW_META = "flow_meta"
    TIMING = "timing"
    SIZE = "size"
    BURST = "burst"
    TCP = "tcp"
    TLS = "tls"
    QUIC = "quic"
    SSH = "ssh"
    DNS = "dns"
    PADDING = "padding"
    FINGERPRINT = "fingerprint"
    ENTROPY = "entropy"
    CONNECTION = "connection"

    # Tranalyzer-compatible feature groups (#44-#58)
    MAC = "mac"  # #45 - Layer 2 MAC features
    IP_EXTENDED = "ip_extended"  # #46 - Extended IP header fields
    IPV6_OPTIONS = "ipv6_options"  # #47 - IPv6 extension headers
    TCP_SEQUENCE = "tcp_sequence"  # #51 - TCP sequence analysis
    TCP_WINDOW = "tcp_window"  # #52 - TCP window analysis
    TCP_OPTIONS = "tcp_options"  # #54 - TCP options parsing
    TCP_MPTCP = "tcp_mptcp"  # #55 - Multipath TCP features
    TCP_RTT = "tcp_rtt"  # #56 - TCP RTT estimation
    TCP_FINGERPRINT = "tcp_fingerprint"  # #57 - TCP fingerprinting
    ICMP = "icmp"  # #58 - ICMP features


@dataclass
class Config:
    """Configuration for JoyfulJay feature extraction.

    Attributes:
        flow_timeout: Inactivity timeout in seconds before a flow expires.
        features: List of feature groups to extract. Use ["all"] for all features.
        specific_features: List of specific feature names to include. If set, only
            these features will be included in output (filtering happens post-extraction).
        include_raw_sequences: Whether to include raw packet sequences (IAT, sizes).
        include_splt: Whether to include SPLT (Sequence of Packet Lengths and Times).
        max_sequence_length: Maximum length of raw sequences to include.
        bpf_filter: BPF filter expression for packet capture.
        include_ip_addresses: Whether to include IP addresses in output.
        include_ports: Whether to include port numbers in output.
        anonymize_ips: Whether to hash IP addresses for privacy.
        anonymization_salt: Salt for IP hashing (for reproducibility).
        include_flow_id: Whether to include a hashed flow identifier.
        burst_threshold_ms: Minimum inter-packet gap (ms) to define burst boundary.
        entropy_sample_bytes: Number of payload bytes to sample for entropy.
        num_workers: Number of worker processes for parallel processing.
        max_concurrent_flows: Maximum concurrent flows before eviction (0 = unlimited).
        flow_eviction_strategy: Strategy for evicting flows when limit reached.
        sampling_rate: Packet sampling rate (0.0-1.0, None = no sampling).
        connection_use_ports: Include ports in connection graph nodes.
        connection_include_graph_metrics: Compute graph metrics (requires NetworkX).
        connection_include_temporal: Compute temporal connection patterns.
        connection_community_algorithm: Algorithm for community detection.
    """

    flow_timeout: float = 60.0
    max_concurrent_flows: int = 0
    flow_eviction_strategy: EvictionStrategy = "lru"
    terminate_on_fin_rst: bool = True  # If False, flows continue after FIN/RST (NFStream-compatible)
    sampling_rate: float | None = None
    features: list[str] = field(default_factory=lambda: ["all"])
    specific_features: list[str] | None = None
    bidirectional_split: bool = False
    include_raw_sequences: bool = False
    include_splt: bool = False
    max_sequence_length: int = 50
    bpf_filter: str | None = None
    include_ip_addresses: bool = True
    include_ports: bool = True
    anonymize_ips: bool = False
    anonymization_salt: str = ""
    include_flow_id: bool = False
    burst_threshold_ms: float = 50.0
    entropy_sample_bytes: int = 256
    num_workers: int = 1
    # Connection graph options
    connection_use_ports: bool = False
    connection_include_graph_metrics: bool = True
    connection_include_temporal: bool = False
    connection_community_algorithm: str = "louvain"

    def __post_init__(self) -> None:
        """Validate configuration after initialization."""
        if self.flow_timeout <= 0:
            raise ValueError("flow_timeout must be positive")
        if self.max_sequence_length <= 0:
            raise ValueError("max_sequence_length must be positive")
        if self.burst_threshold_ms <= 0:
            raise ValueError("burst_threshold_ms must be positive")
        if self.max_concurrent_flows < 0:
            raise ValueError("max_concurrent_flows must be non-negative")
        if self.sampling_rate is not None and not (0.0 <= self.sampling_rate <= 1.0):
            raise ValueError("sampling_rate must be between 0.0 and 1.0")

    def should_extract(self, group: str | FeatureGroup) -> bool:
        """Check if a feature group should be extracted.

        Args:
            group: Feature group name or enum value.

        Returns:
            True if the group should be extracted.
        """
        if isinstance(group, FeatureGroup):
            group = group.value

        if "all" in self.features:
            return True
        return group in self.features

    @property
    def burst_threshold_seconds(self) -> float:
        """Get burst threshold in seconds."""
        return self.burst_threshold_ms / 1000.0

    def should_include_feature(self, feature_name: str) -> bool:
        """Check if a specific feature should be included in output.

        Args:
            feature_name: Name of the feature.

        Returns:
            True if the feature should be included.
        """
        if self.specific_features is None:
            return True
        return feature_name in self.specific_features

    def filter_features(self, features: dict[str, Any]) -> dict[str, Any]:
        """Filter a feature dictionary to include only specified features.

        Args:
            features: Dictionary of all extracted features.

        Returns:
            Filtered dictionary with only requested features.
        """
        if self.specific_features is None:
            return features
        return {k: v for k, v in features.items() if k in self.specific_features}

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary.

        Returns:
            Dictionary representation of configuration.
        """
        return {
            "flow_timeout": self.flow_timeout,
            "max_concurrent_flows": self.max_concurrent_flows,
            "flow_eviction_strategy": self.flow_eviction_strategy,
            "terminate_on_fin_rst": self.terminate_on_fin_rst,
            "sampling_rate": self.sampling_rate,
            "features": self.features,
            "specific_features": self.specific_features,
            "bidirectional_split": self.bidirectional_split,
            "include_raw_sequences": self.include_raw_sequences,
            "include_splt": self.include_splt,
            "max_sequence_length": self.max_sequence_length,
            "bpf_filter": self.bpf_filter,
            "include_ip_addresses": self.include_ip_addresses,
            "include_ports": self.include_ports,
            "anonymize_ips": self.anonymize_ips,
            "anonymization_salt": self.anonymization_salt,
            "include_flow_id": self.include_flow_id,
            "burst_threshold_ms": self.burst_threshold_ms,
            "entropy_sample_bytes": self.entropy_sample_bytes,
            "num_workers": self.num_workers,
            "connection_use_ports": self.connection_use_ports,
            "connection_include_graph_metrics": self.connection_include_graph_metrics,
            "connection_include_temporal": self.connection_include_temporal,
            "connection_community_algorithm": self.connection_community_algorithm,
        }

    def to_json(self, path: str | Path) -> None:
        """Save configuration to JSON file.

        Args:
            path: Path to output JSON file.
        """
        path = Path(path)
        with path.open("w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    def to_yaml(self, path: str | Path) -> None:
        """Save configuration to YAML file.

        Args:
            path: Path to output YAML file.

        Raises:
            ImportError: If PyYAML is not installed.
        """
        try:
            import yaml
        except ImportError as e:
            raise ImportError("PyYAML is required for YAML config files. Install with: pip install pyyaml") from e

        path = Path(path)
        with path.open("w", encoding="utf-8") as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Config:
        """Create configuration from dictionary.

        Args:
            data: Dictionary with configuration values.

        Returns:
            Config instance.
        """
        return cls(
            flow_timeout=data.get("flow_timeout", 60.0),
            max_concurrent_flows=data.get("max_concurrent_flows", 0),
            flow_eviction_strategy=data.get("flow_eviction_strategy", "lru"),
            terminate_on_fin_rst=data.get("terminate_on_fin_rst", True),
            sampling_rate=data.get("sampling_rate"),
            features=data.get("features", ["all"]),
            specific_features=data.get("specific_features"),
            bidirectional_split=data.get("bidirectional_split", False),
            include_raw_sequences=data.get("include_raw_sequences", False),
            include_splt=data.get("include_splt", False),
            max_sequence_length=data.get("max_sequence_length", 50),
            bpf_filter=data.get("bpf_filter"),
            include_ip_addresses=data.get("include_ip_addresses", True),
            include_ports=data.get("include_ports", True),
            anonymize_ips=data.get("anonymize_ips", False),
            anonymization_salt=data.get("anonymization_salt", ""),
            include_flow_id=data.get("include_flow_id", False),
            burst_threshold_ms=data.get("burst_threshold_ms", 50.0),
            entropy_sample_bytes=data.get("entropy_sample_bytes", 256),
            num_workers=data.get("num_workers", 1),
            connection_use_ports=data.get("connection_use_ports", False),
            connection_include_graph_metrics=data.get("connection_include_graph_metrics", True),
            connection_include_temporal=data.get("connection_include_temporal", False),
            connection_community_algorithm=data.get("connection_community_algorithm", "louvain"),
        )

    @classmethod
    def from_json(cls, path: str | Path) -> Config:
        """Load configuration from JSON file.

        Args:
            path: Path to JSON configuration file.

        Returns:
            Config instance.

        Raises:
            FileNotFoundError: If file does not exist.
            json.JSONDecodeError: If file is not valid JSON.
        """
        path = Path(path)
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)

    @classmethod
    def from_yaml(cls, path: str | Path) -> Config:
        """Load configuration from YAML file.

        Args:
            path: Path to YAML configuration file.

        Returns:
            Config instance.

        Raises:
            FileNotFoundError: If file does not exist.
            ImportError: If PyYAML is not installed.
        """
        try:
            import yaml
        except ImportError as e:
            raise ImportError("PyYAML is required for YAML config files. Install with: pip install pyyaml") from e

        path = Path(path)
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls.from_dict(data or {})

    @classmethod
    def from_file(cls, path: str | Path) -> Config:
        """Load configuration from file (auto-detect format).

        Supports JSON (.json) and YAML (.yaml, .yml) files.

        Args:
            path: Path to configuration file.

        Returns:
            Config instance.

        Raises:
            ValueError: If file extension is not recognized.
        """
        path = Path(path)
        suffix = path.suffix.lower()

        if suffix == ".json":
            return cls.from_json(path)
        elif suffix in (".yaml", ".yml"):
            return cls.from_yaml(path)
        else:
            raise ValueError(f"Unsupported config file format: {suffix}. Use .json or .yaml/.yml")


OutputFormat = Literal["dataframe", "numpy", "dict", "csv", "json"]
