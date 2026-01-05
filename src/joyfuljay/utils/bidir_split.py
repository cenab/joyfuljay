"""Utilities for bidirectional feature splitting."""

from __future__ import annotations

from typing import Any

# Features that are directional and should be split
DIRECTIONAL_FEATURES = {
    # Size features
    "packet_count",
    "total_bytes",
    "payload_bytes",
    "mean_packet_size",
    "min_packet_size",
    "max_packet_size",
    "std_packet_size",
    "mean_payload_size",
    # Timing features
    "mean_iat",
    "min_iat",
    "max_iat",
    "std_iat",
    "iat_sequence",
    "size_sequence",
    # Burst features
    "burst_count",
    "mean_burst_duration",
    "mean_burst_packets",
    "mean_burst_bytes",
    # TCP features
    "tcp_syn_count",
    "tcp_ack_count",
    "tcp_fin_count",
    "tcp_rst_count",
    "tcp_psh_count",
    "tcp_urg_count",
    # Entropy features
    "entropy_payload",
    "byte_distribution_uniformity",
    "printable_ratio",
    "null_ratio",
    "high_byte_ratio",
}

# Features that are inherently bidirectional (kept as-is)
BIDIRECTIONAL_FEATURES = {
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "duration",
    "flow_id",
    # TLS features (based on handshake from both sides)
    "tls_detected",
    "tls_version",
    "tls_cipher_suite",
    "tls_server_name",
    "tls_ja3",
    "tls_ja3s",
    "tls_ja3_hash",
    "tls_ja3s_hash",
    "ja4",
    # SSH features
    "ssh_detected",
    "ssh_version_initiator",
    "ssh_version_responder",
    "hassh",
    "hasshs",
    "hassh_hash",
    "hasshs_hash",
    # QUIC features
    "quic_detected",
    "quic_version",
    # DNS features
    "dns_detected",
    "dns_query_name",
    "dns_query_type",
    "dns_response_code",
    # Fingerprint features
    "ja3_hash",
    "doh_detected",
    # TCP connection state
    "tcp_complete_handshake",
    "tcp_graceful_close",
    "tcp_flags_anomaly",
}


def split_features_bidirectional(
    features: dict[str, Any],
    initiator_prefix: str = "fwd_",
    responder_prefix: str = "bwd_",
) -> dict[str, Any]:
    """Split features into forward (initiator) and backward (responder) components.

    Takes a feature dictionary and creates separate prefixed versions for
    directional features while keeping bidirectional features unchanged.

    Args:
        features: Original feature dictionary.
        initiator_prefix: Prefix for initiator-to-responder features.
        responder_prefix: Prefix for responder-to-initiator features.

    Returns:
        New feature dictionary with split directional features.
    """
    result: dict[str, Any] = {}

    for key, value in features.items():
        # Check if this is a directional feature that already has _initiator/_responder suffix
        if key.endswith("_initiator"):
            base_name = key[:-10]  # Remove _initiator
            result[f"{initiator_prefix}{base_name}"] = value
        elif key.endswith("_responder"):
            base_name = key[:-10]  # Remove _responder
            result[f"{responder_prefix}{base_name}"] = value
        elif key in DIRECTIONAL_FEATURES:
            # This is a combined directional feature - keep as total
            result[f"total_{key}"] = value
        else:
            # Non-directional feature - keep as-is
            result[key] = value

    return result


def merge_directional_features(
    fwd_features: dict[str, Any],
    bwd_features: dict[str, Any],
    fwd_prefix: str = "fwd_",
    bwd_prefix: str = "bwd_",
) -> dict[str, Any]:
    """Merge two directional feature dictionaries into one.

    Args:
        fwd_features: Forward direction features.
        bwd_features: Backward direction features.
        fwd_prefix: Prefix for forward features.
        bwd_prefix: Prefix for backward features.

    Returns:
        Merged feature dictionary.
    """
    result: dict[str, Any] = {}

    # Add forward features with prefix
    for key, value in fwd_features.items():
        result[f"{fwd_prefix}{key}"] = value

    # Add backward features with prefix
    for key, value in bwd_features.items():
        result[f"{bwd_prefix}{key}"] = value

    return result
