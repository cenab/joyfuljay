"""Feature registry - single source of truth for all features."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, Optional

if TYPE_CHECKING:
    from ..extractors.base import FeatureExtractor

DType = Literal["float32", "float64", "int64", "bool", "string", "categorical"]
Scope = Literal["flow", "direction", "burst", "packet_seq"]
Privacy = Literal["safe", "sensitive", "high"]


@dataclass(frozen=True)
class FeatureMeta:
    """Metadata for a single feature.

    Attributes:
        id: Stable feature identifier (e.g., "timing.iat_mean_ms").
        dtype: Data type of the feature.
        shape: Shape of the feature ([1] for scalar, [N] for fixed array, "variable" for variable).
        units: Unit of measurement (e.g., "ms", "bytes", "count", "").
        scope: Scope of the feature (flow, direction, burst, packet_seq).
        direction: Direction semantics (bidir, src_to_dst, dst_to_src, both).
        direction_semantics: Human-readable description of direction handling.
        missing_policy: How to handle missing values (nan, zero, empty, sentinel).
        missing_sentinel: Sentinel value if missing_policy is "sentinel".
        dependencies: List of protocol/layer dependencies (e.g., ["tcp"], ["tls"]).
        privacy_level: Privacy sensitivity (safe, sensitive, high).
        description: Human-readable description of the feature.
    """

    id: str
    dtype: DType
    shape: list[int] | Literal["variable"]
    units: str
    scope: Scope
    direction: Literal["bidir", "src_to_dst", "dst_to_src", "both"]
    direction_semantics: str
    missing_policy: Literal["nan", "zero", "empty", "sentinel"]
    missing_sentinel: Optional[float | int | str]
    dependencies: list[str]
    privacy_level: Privacy
    description: str


# Extractor name to class mapping for deterministic ordering
_EXTRACTOR_ORDER = [
    "flow_meta",
    "timing",
    "size",
    "tcp",
    "tls",
    "quic",
    "ssh",
    "dns",
    "entropy",
    "padding",
    "fingerprint",
    "connection",
    "mac",
    "ip_extended",
    "ipv6_options",
    "icmp",
    "tcp_sequence",
    "tcp_window",
    "tcp_options",
    "tcp_mptcp",
    "tcp_rtt",
    "tcp_fingerprint",
    "http2",
]


def get_extractors() -> list[FeatureExtractor]:
    """Return instantiated extractor objects in deterministic order.

    Returns:
        List of extractor instances in stable order.
    """
    from ..extractors import (
        ConnectionExtractor,
        DNSExtractor,
        EntropyExtractor,
        FingerprintExtractor,
        FlowMetaExtractor,
        HTTP2Extractor,
        ICMPExtractor,
        IPExtendedExtractor,
        IPv6OptionsExtractor,
        MACExtractor,
        MPTCPExtractor,
        PaddingExtractor,
        QUICExtractor,
        SizeExtractor,
        SSHExtractor,
        TCPExtractor,
        TCPFingerprintExtractor,
        TCPOptionsExtractor,
        TCPRTTExtractor,
        TCPSequenceExtractor,
        TCPWindowExtractor,
        TimingExtractor,
        TLSExtractor,
    )

    # Return extractors in deterministic order
    return [
        FlowMetaExtractor(),
        TimingExtractor(),
        SizeExtractor(),
        TCPExtractor(),
        TLSExtractor(),
        QUICExtractor(),
        SSHExtractor(),
        DNSExtractor(),
        EntropyExtractor(),
        PaddingExtractor(),
        FingerprintExtractor(),
        ConnectionExtractor(),
        MACExtractor(),
        IPExtendedExtractor(),
        IPv6OptionsExtractor(),
        ICMPExtractor(),
        TCPSequenceExtractor(),
        TCPWindowExtractor(),
        TCPOptionsExtractor(),
        MPTCPExtractor(),
        TCPRTTExtractor(),
        TCPFingerprintExtractor(),
        HTTP2Extractor(),
    ]


def all_feature_ids() -> set[str]:
    """Get all feature IDs from all extractors.

    Returns:
        Set of all feature IDs.

    Raises:
        ValueError: If duplicate feature IDs are found.
    """
    ids: set[str] = set()
    for ex in get_extractors():
        for fid in ex.feature_ids():
            if fid in ids:
                raise ValueError(f"Duplicate feature id: {fid}")
            ids.add(fid)
    return ids


def all_feature_meta() -> dict[str, FeatureMeta]:
    """Get metadata for all features from all extractors.

    Returns:
        Dictionary mapping feature ID to FeatureMeta.

    Raises:
        ValueError: If duplicate feature IDs or missing metadata.
    """
    meta: dict[str, FeatureMeta] = {}
    for ex in get_extractors():
        m = ex.feature_meta()
        for fid, fmeta in m.items():
            if fid in meta:
                raise ValueError(f"Duplicate feature meta id: {fid}")
            meta[fid] = fmeta

    # Ensure meta covers all IDs
    feature_ids = all_feature_ids()
    missing = feature_ids - set(meta.keys())
    if missing:
        raise ValueError(f"Missing meta for feature ids: {sorted(missing)}")

    return meta


def get_feature_ids_ordered() -> list[str]:
    """Get all feature IDs in deterministic order.

    Returns:
        List of feature IDs ordered by extractor, then by feature within extractor.
    """
    ids: list[str] = []
    for ex in get_extractors():
        ids.extend(ex.feature_ids())
    return ids
