# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True
# cython: initializedcheck=False
"""
Fast statistics computation using Cython.

This module provides optimized implementations of statistical calculations
that are called frequently during flow feature extraction.

Key optimizations:
- Single-pass algorithms where possible
- Avoiding redundant array allocations
- Direct memory access for NumPy arrays
- Compiled C code instead of Python loops
"""

import numpy as np
cimport numpy as np
cimport cython
from libc.math cimport sqrt, log2, fabs

# NumPy type definitions
np.import_array()

ctypedef np.float64_t DOUBLE
ctypedef np.int64_t INT64


@cython.boundscheck(False)
@cython.wraparound(False)
cpdef dict compute_statistics_fast(list values):
    """
    Compute comprehensive statistics in minimal passes.

    This is the main optimization target - the original implementation
    made 10+ separate passes over the data. This version does:
    - One pass for sum, min, max, count
    - One sort (required for median/percentiles)
    - Percentiles computed via O(1) index lookup

    Args:
        values: List of numeric values.

    Returns:
        Dictionary with count, min, max, mean, std, median, sum,
        p25, p75, p90, p99.
    """
    cdef:
        Py_ssize_t n = len(values)
        Py_ssize_t i
        double total = 0.0
        double val
        double min_val, max_val
        double mean, variance, std
        double[:] arr
        double[:] sorted_arr

    if n == 0:
        return {
            "count": 0,
            "min": 0.0,
            "max": 0.0,
            "mean": 0.0,
            "std": 0.0,
            "median": 0.0,
            "sum": 0.0,
            "p25": 0.0,
            "p75": 0.0,
            "p90": 0.0,
            "p99": 0.0,
        }

    # Convert to numpy array once
    arr_np = np.array(values, dtype=np.float64)
    arr = arr_np

    # Single pass for sum, min, max
    min_val = arr[0]
    max_val = arr[0]
    total = 0.0

    for i in range(n):
        val = arr[i]
        total += val
        if val < min_val:
            min_val = val
        if val > max_val:
            max_val = val

    mean = total / n

    # Second pass for variance (need mean first)
    variance = 0.0
    for i in range(n):
        val = arr[i] - mean
        variance += val * val
    variance /= n
    std = sqrt(variance)

    # Sort once for median and percentiles
    sorted_np = np.sort(arr_np)
    sorted_arr = sorted_np

    return {
        "count": n,
        "min": min_val,
        "max": max_val,
        "mean": mean,
        "std": std,
        "median": _percentile_from_sorted(sorted_arr, n, 50.0),
        "sum": total,
        "p25": _percentile_from_sorted(sorted_arr, n, 25.0),
        "p75": _percentile_from_sorted(sorted_arr, n, 75.0),
        "p90": _percentile_from_sorted(sorted_arr, n, 90.0),
        "p99": _percentile_from_sorted(sorted_arr, n, 99.0),
    }


@cython.boundscheck(False)
@cython.wraparound(False)
cdef inline double _percentile_from_sorted(double[:] sorted_arr, Py_ssize_t n, double percentile) noexcept:
    """
    Compute percentile from a sorted array using linear interpolation.

    This is O(1) since we just do index lookups, unlike np.percentile
    which sorts the array every time.
    """
    cdef:
        double idx = (n - 1) * percentile / 100.0
        Py_ssize_t lower = <Py_ssize_t>idx
        Py_ssize_t upper = lower + 1
        double frac = idx - lower

    if upper >= n:
        upper = n - 1

    return sorted_arr[lower] * (1.0 - frac) + sorted_arr[upper] * frac


@cython.boundscheck(False)
@cython.wraparound(False)
cpdef list compute_interarrival_times_fast(list timestamps):
    """
    Compute inter-arrival times from timestamps.

    Args:
        timestamps: List of float timestamps in order.

    Returns:
        List of inter-arrival times (differences between consecutive timestamps).
    """
    cdef:
        Py_ssize_t n = len(timestamps)
        Py_ssize_t i
        double[:] arr
        list result

    if n <= 1:
        return []

    arr_np = np.array(timestamps, dtype=np.float64)
    arr = arr_np

    result = []
    for i in range(1, n):
        result.append(arr[i] - arr[i - 1])

    return result


@cython.boundscheck(False)
@cython.wraparound(False)
cpdef dict compute_percentiles_fast(list values, list percentiles):
    """
    Compute multiple percentiles efficiently with single sort.

    Args:
        values: List of numeric values.
        percentiles: List of percentile values (0-100).

    Returns:
        Dictionary mapping "pXX" to percentile value.
    """
    cdef:
        Py_ssize_t n = len(values)
        Py_ssize_t i
        double[:] sorted_arr
        dict result = {}
        double p

    if n == 0:
        for p in percentiles:
            result[f"p{int(p)}"] = 0.0
        return result

    # Single sort
    sorted_np = np.sort(np.array(values, dtype=np.float64))
    sorted_arr = sorted_np

    for p in percentiles:
        result[f"p{int(p)}"] = _percentile_from_sorted(sorted_arr, n, p)

    return result


@cython.boundscheck(False)
@cython.wraparound(False)
cpdef tuple extract_packet_attributes_fast(list packets, str attr_name):
    """
    Extract a numeric attribute from a list of packets efficiently.

    This replaces multiple list comprehensions like:
        [p.total_len for p in packets]
        [p.timestamp for p in packets]
        [p.payload_len for p in packets]

    With a single compiled function that returns both the list and basic stats.

    Args:
        packets: List of Packet objects.
        attr_name: Name of attribute to extract ("total_len", "timestamp", "payload_len").

    Returns:
        Tuple of (values_list, sum, min, max, count).
    """
    cdef:
        Py_ssize_t n = len(packets)
        Py_ssize_t i
        list values = []
        double total = 0.0
        double min_val = 0.0
        double max_val = 0.0
        double val
        bint first = True

    if n == 0:
        return ([], 0.0, 0.0, 0.0, 0)

    for i in range(n):
        packet = packets[i]
        val = getattr(packet, attr_name)
        values.append(val)
        total += val

        if first:
            min_val = val
            max_val = val
            first = False
        else:
            if val < min_val:
                min_val = val
            if val > max_val:
                max_val = val

    return (values, total, min_val, max_val, n)
