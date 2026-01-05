"""Entropy and byte distribution computation utilities."""

from __future__ import annotations

import math
from collections import Counter

import numpy as np


def byte_histogram(data: bytes) -> list[int]:
    """Compute a histogram of byte values (256 bins).

    Args:
        data: Raw bytes to analyze.

    Returns:
        List of 256 counts, one for each possible byte value (0-255).
    """
    if len(data) == 0:
        return [0] * 256

    histogram = [0] * 256
    for byte in data:
        histogram[byte] += 1

    return histogram


def byte_entropy(data: bytes) -> float:
    """Compute Shannon entropy of byte distribution.

    For encrypted/random data, entropy approaches 8.0 bits.
    For structured/compressible data, entropy is lower.

    Args:
        data: Raw bytes to analyze.

    Returns:
        Shannon entropy in bits (0.0 to 8.0).
    """
    if len(data) == 0:
        return 0.0

    # Count byte frequencies
    counter = Counter(data)
    total = len(data)

    # Compute entropy
    entropy = 0.0
    for count in counter.values():
        if count > 0:
            probability = count / total
            entropy -= probability * math.log2(probability)

    return entropy


def normalized_entropy(data: bytes) -> float:
    """Compute normalized Shannon entropy (0.0 to 1.0).

    Normalized entropy divides by the maximum possible entropy (8 bits),
    making it easier to compare across different data sizes.

    Args:
        data: Raw bytes to analyze.

    Returns:
        Normalized entropy (0.0 to 1.0).
    """
    return byte_entropy(data) / 8.0


def byte_distribution_uniformity(data: bytes) -> float:
    """Measure how uniform the byte distribution is.

    Uses chi-squared statistic to compare observed distribution
    to a uniform distribution. Lower values indicate more uniform
    (random/encrypted) data.

    Args:
        data: Raw bytes to analyze.

    Returns:
        Chi-squared statistic normalized by data length.
        Lower values (< 1.0) suggest uniform/encrypted data.
    """
    if len(data) < 256:
        # Not enough data for meaningful analysis
        return 0.0

    histogram = byte_histogram(data)
    expected = len(data) / 256.0

    chi_squared = sum((obs - expected) ** 2 / expected for obs in histogram)

    # Normalize by data length
    return chi_squared / len(data)


def compute_payload_entropy_features(payloads: list[bytes]) -> dict[str, float]:
    """Compute entropy features from a list of payloads.

    Args:
        payloads: List of raw payload bytes from packets.

    Returns:
        Dictionary of entropy-related features.
    """
    if not payloads:
        return {
            "payload_entropy": 0.0,
            "payload_entropy_normalized": 0.0,
            "payload_uniformity": 0.0,
        }

    # Concatenate all payloads
    combined = b"".join(payloads)

    return {
        "payload_entropy": byte_entropy(combined),
        "payload_entropy_normalized": normalized_entropy(combined),
        "payload_uniformity": byte_distribution_uniformity(combined),
    }


# --- Fallback functions for Cython extension compatibility ---


def shannon_entropy_fallback(data: bytes) -> float:
    """Compute Shannon entropy of byte data.

    Pure Python fallback for Cython shannon_entropy_fast.
    This is an alias for byte_entropy with the same interface.

    Args:
        data: Bytes to analyze.

    Returns:
        Shannon entropy in bits (0.0 to 8.0).
    """
    return byte_entropy(data)


def byte_distribution_fallback(data: bytes) -> dict[str, float | int]:
    """Analyze byte distribution for encryption/compression detection.

    Pure Python fallback for Cython byte_distribution_fast.

    Args:
        data: Bytes to analyze.

    Returns:
        Dictionary with entropy, unique_bytes, uniformity,
        most_common_byte, most_common_count.
    """
    length = len(data)

    if length == 0:
        return {
            "entropy": 0.0,
            "unique_bytes": 0,
            "uniformity": 0.0,
            "most_common_byte": 0,
            "most_common_count": 0,
        }

    # Count byte frequencies
    counts = [0] * 256
    for b in data:
        counts[b] += 1

    # Compute metrics
    unique_bytes = 0
    max_count = 0
    most_common_byte = 0
    entropy = 0.0
    expected_uniform = length / 256.0
    variance = 0.0

    for i in range(256):
        count = counts[i]
        if count > 0:
            unique_bytes += 1
            probability = count / length
            entropy -= probability * math.log2(probability)

            if count > max_count:
                max_count = count
                most_common_byte = i

            variance += (count - expected_uniform) ** 2
        else:
            variance += expected_uniform ** 2

    # Uniformity: 1.0 = perfectly uniform, 0.0 = very non-uniform
    uniformity = 0.0
    if length >= 256:
        max_variance = length * length
        uniformity = 1.0 - (variance / max_variance)
        if uniformity < 0.0:
            uniformity = 0.0

    return {
        "entropy": entropy,
        "unique_bytes": unique_bytes,
        "uniformity": uniformity,
        "most_common_byte": most_common_byte,
        "most_common_count": max_count,
    }


def character_class_counts_fallback(data: bytes) -> dict[str, int]:
    """Count bytes by character class in a single pass.

    Pure Python fallback for Cython character_class_counts_fast.

    Args:
        data: Bytes to analyze.

    Returns:
        Dictionary with printable_count, null_count, high_byte_count,
        control_count, total.
    """
    length = len(data)

    if length == 0:
        return {
            "printable_count": 0,
            "null_count": 0,
            "high_byte_count": 0,
            "control_count": 0,
            "total": 0,
        }

    printable_count = 0
    null_count = 0
    high_byte_count = 0
    control_count = 0

    for b in data:
        if b >= 0x80:
            high_byte_count += 1
        elif b == 0x00:
            null_count += 1
        elif (0x20 <= b <= 0x7E) or b in (0x09, 0x0A, 0x0D):
            # Printable ASCII or tab/newline/carriage return
            printable_count += 1
        else:
            control_count += 1

    return {
        "printable_count": printable_count,
        "null_count": null_count,
        "high_byte_count": high_byte_count,
        "control_count": control_count,
        "total": length,
    }
