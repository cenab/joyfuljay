# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True
# cython: initializedcheck=False
"""
Fast entropy and byte distribution analysis using Cython.

This module provides optimized implementations of entropy calculations
and byte distribution analysis for payload analysis.

Key optimizations:
- Single-pass byte counting using fixed-size array
- Vectorized probability calculations
- Compiled loops instead of Python Counter
"""

import numpy as np
cimport numpy as np
cimport cython
from libc.math cimport log2

np.import_array()


@cython.boundscheck(False)
@cython.wraparound(False)
cpdef double shannon_entropy_fast(bytes data):
    """
    Compute Shannon entropy of byte data in a single pass.

    This replaces the Counter-based implementation with a direct
    byte counting loop that is much faster for large payloads.

    Args:
        data: Bytes to analyze.

    Returns:
        Shannon entropy in bits (0.0 to 8.0 for byte data).
    """
    cdef:
        Py_ssize_t length = len(data)
        Py_ssize_t i
        unsigned char b
        double entropy = 0.0
        double probability
        long counts[256]
        const unsigned char* data_ptr

    if length == 0:
        return 0.0

    # Initialize counts to zero
    for i in range(256):
        counts[i] = 0

    # Count byte frequencies in single pass
    data_ptr = data
    for i in range(length):
        counts[data_ptr[i]] += 1

    # Compute entropy from counts
    for i in range(256):
        if counts[i] > 0:
            probability = <double>counts[i] / <double>length
            entropy -= probability * log2(probability)

    return entropy


@cython.boundscheck(False)
@cython.wraparound(False)
cpdef dict byte_distribution_fast(bytes data):
    """
    Analyze byte distribution for encryption/compression detection.

    Returns multiple metrics in a single pass through the data.

    Args:
        data: Bytes to analyze.

    Returns:
        Dictionary with:
        - entropy: Shannon entropy
        - unique_bytes: Number of distinct byte values
        - uniformity: How uniform the distribution is (0-1)
        - most_common_byte: Most frequent byte value
        - most_common_count: Count of most common byte
    """
    cdef:
        Py_ssize_t length = len(data)
        Py_ssize_t i
        double entropy = 0.0
        double probability
        double expected_uniform
        double variance = 0.0
        double uniformity = 0.0
        long counts[256]
        const unsigned char* data_ptr
        int unique_bytes = 0
        long max_count = 0
        int most_common_byte = 0

    if length == 0:
        return {
            "entropy": 0.0,
            "unique_bytes": 0,
            "uniformity": 0.0,
            "most_common_byte": 0,
            "most_common_count": 0,
        }

    # Initialize counts
    for i in range(256):
        counts[i] = 0

    # Count byte frequencies
    data_ptr = data
    for i in range(length):
        counts[data_ptr[i]] += 1

    # Analyze distribution
    expected_uniform = <double>length / 256.0

    for i in range(256):
        if counts[i] > 0:
            unique_bytes += 1

            # Entropy
            probability = <double>counts[i] / <double>length
            entropy -= probability * log2(probability)

            # Track most common
            if counts[i] > max_count:
                max_count = counts[i]
                most_common_byte = i

            # Variance for uniformity
            variance += (counts[i] - expected_uniform) ** 2
        else:
            # Zero counts also contribute to variance
            variance += expected_uniform ** 2

    # Uniformity: 1.0 = perfectly uniform, 0.0 = very non-uniform
    if length >= 256:
        # Normalize variance to 0-1 scale
        max_variance = length * length  # Theoretical maximum variance
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


@cython.boundscheck(False)
@cython.wraparound(False)
cpdef dict character_class_counts_fast(bytes data):
    """
    Count bytes by character class in a single pass.

    This replaces three separate list comprehensions with a single loop.

    Args:
        data: Bytes to analyze.

    Returns:
        Dictionary with:
        - printable_count: ASCII printable characters (0x20-0x7E + whitespace)
        - null_count: Null bytes (0x00)
        - high_byte_count: High bytes (>= 0x80)
        - control_count: Control characters (< 0x20, excluding whitespace)
        - total: Total byte count
    """
    cdef:
        Py_ssize_t length = len(data)
        Py_ssize_t i
        unsigned char b
        const unsigned char* data_ptr
        long printable_count = 0
        long null_count = 0
        long high_byte_count = 0
        long control_count = 0

    if length == 0:
        return {
            "printable_count": 0,
            "null_count": 0,
            "high_byte_count": 0,
            "control_count": 0,
            "total": 0,
        }

    data_ptr = data
    for i in range(length):
        b = data_ptr[i]

        if b >= 0x80:
            high_byte_count += 1
        elif b == 0x00:
            null_count += 1
        elif (0x20 <= b <= 0x7E) or b == 0x09 or b == 0x0A or b == 0x0D:
            # Printable ASCII or tab/newline/carriage return
            printable_count += 1
        else:
            # Other control characters
            control_count += 1

    return {
        "printable_count": printable_count,
        "null_count": null_count,
        "high_byte_count": high_byte_count,
        "control_count": control_count,
        "total": length,
    }


@cython.boundscheck(False)
@cython.wraparound(False)
cpdef tuple analyze_payload_fast(bytes data):
    """
    Comprehensive payload analysis in a single pass.

    Combines entropy, byte distribution, and character class analysis
    into a single loop through the data.

    Args:
        data: Bytes to analyze.

    Returns:
        Tuple of (entropy, byte_stats_dict, char_class_dict).
    """
    cdef:
        Py_ssize_t length = len(data)
        Py_ssize_t i
        unsigned char b
        const unsigned char* data_ptr
        double entropy = 0.0
        double probability
        long counts[256]
        int unique_bytes = 0
        long max_count = 0
        int most_common_byte = 0
        long printable_count = 0
        long null_count = 0
        long high_byte_count = 0
        long control_count = 0

    if length == 0:
        return (
            0.0,
            {"unique_bytes": 0, "most_common_byte": 0, "most_common_count": 0},
            {"printable_count": 0, "null_count": 0, "high_byte_count": 0, "control_count": 0, "total": 0},
        )

    # Initialize counts
    for i in range(256):
        counts[i] = 0

    # Single pass: count bytes and classify
    data_ptr = data
    for i in range(length):
        b = data_ptr[i]
        counts[b] += 1

        # Character class
        if b >= 0x80:
            high_byte_count += 1
        elif b == 0x00:
            null_count += 1
        elif (0x20 <= b <= 0x7E) or b == 0x09 or b == 0x0A or b == 0x0D:
            printable_count += 1
        else:
            control_count += 1

    # Compute entropy and find most common
    for i in range(256):
        if counts[i] > 0:
            unique_bytes += 1
            probability = <double>counts[i] / <double>length
            entropy -= probability * log2(probability)

            if counts[i] > max_count:
                max_count = counts[i]
                most_common_byte = i

    return (
        entropy,
        {
            "unique_bytes": unique_bytes,
            "most_common_byte": most_common_byte,
            "most_common_count": max_count,
        },
        {
            "printable_count": printable_count,
            "null_count": null_count,
            "high_byte_count": high_byte_count,
            "control_count": control_count,
            "total": length,
        },
    )
