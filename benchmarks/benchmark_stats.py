#!/usr/bin/env python3
"""Benchmark for Cython extensions vs pure Python implementations."""

import random
import time
from typing import Callable

import numpy as np


def benchmark(func: Callable, data, iterations: int = 1000) -> float:
    """Benchmark a function, return average time in microseconds."""
    # Warmup
    for _ in range(10):
        func(data)

    start = time.perf_counter()
    for _ in range(iterations):
        func(data)
    elapsed = time.perf_counter() - start

    return (elapsed / iterations) * 1_000_000  # microseconds


def run_benchmarks():
    """Run all benchmarks comparing Cython vs pure Python."""
    print("=" * 70)
    print("JoyfulJay Cython Extensions Benchmark")
    print("=" * 70)

    # Import Cython implementations
    from joyfuljay.extensions import (
        compute_statistics_fast,
        compute_interarrival_times_fast,
        shannon_entropy_fast,
        byte_distribution_fast,
        character_class_counts_fast,
        is_cython_available,
        get_available_extensions,
    )

    # Import pure Python fallbacks
    from joyfuljay.utils.stats import (
        compute_statistics_dict as stats_python,
        compute_interarrival_times_list as iat_python,
    )
    from joyfuljay.utils.entropy import (
        shannon_entropy_fallback as entropy_python,
        byte_distribution_fallback as byte_dist_python,
        character_class_counts_fallback as char_class_python,
    )

    print(f"\nCython available: {is_cython_available()}")
    print(f"Extensions status: {get_available_extensions()}")

    if not is_cython_available():
        print("\nWARNING: Cython extensions not compiled!")
        print("Run: python src/joyfuljay/extensions/build_extensions.py")
        return

    # ===== Statistics Benchmark =====
    print("\n1. compute_statistics() - Cython vs Pure Python")
    print("-" * 70)
    print(f"{'Size':>8} {'Python (μs)':>15} {'Cython (μs)':>15} {'Speedup':>10}")
    print("-" * 70)

    sizes = [10, 50, 100, 500, 1000, 5000]
    for size in sizes:
        data = [random.uniform(0, 1000) for _ in range(size)]

        python_time = benchmark(stats_python, data)
        cython_time = benchmark(compute_statistics_fast, data)
        speedup = python_time / cython_time

        print(f"{size:>8} {python_time:>15.2f} {cython_time:>15.2f} {speedup:>9.2f}x")

    # ===== Inter-arrival Times Benchmark =====
    print("\n2. compute_interarrival_times() - Cython vs Pure Python")
    print("-" * 70)
    print(f"{'Size':>8} {'Python (μs)':>15} {'Cython (μs)':>15} {'Speedup':>10}")
    print("-" * 70)

    for size in sizes:
        data = sorted([random.uniform(0, 100) for _ in range(size)])

        python_time = benchmark(iat_python, data)
        cython_time = benchmark(compute_interarrival_times_fast, data)
        speedup = python_time / cython_time

        print(f"{size:>8} {python_time:>15.2f} {cython_time:>15.2f} {speedup:>9.2f}x")

    # ===== Shannon Entropy Benchmark =====
    print("\n3. shannon_entropy() - Cython vs Pure Python")
    print("-" * 70)
    print(f"{'Size':>8} {'Python (μs)':>15} {'Cython (μs)':>15} {'Speedup':>10}")
    print("-" * 70)

    byte_sizes = [256, 1024, 4096, 16384, 65536]
    for size in byte_sizes:
        data = bytes(random.randint(0, 255) for _ in range(size))

        python_time = benchmark(entropy_python, data)
        cython_time = benchmark(shannon_entropy_fast, data)
        speedup = python_time / cython_time

        print(f"{size:>8} {python_time:>15.2f} {cython_time:>15.2f} {speedup:>9.2f}x")

    # ===== Byte Distribution Benchmark =====
    print("\n4. byte_distribution() - Cython vs Pure Python")
    print("-" * 70)
    print(f"{'Size':>8} {'Python (μs)':>15} {'Cython (μs)':>15} {'Speedup':>10}")
    print("-" * 70)

    for size in byte_sizes:
        data = bytes(random.randint(0, 255) for _ in range(size))

        python_time = benchmark(byte_dist_python, data)
        cython_time = benchmark(byte_distribution_fast, data)
        speedup = python_time / cython_time

        print(f"{size:>8} {python_time:>15.2f} {cython_time:>15.2f} {speedup:>9.2f}x")

    # ===== Character Class Counts Benchmark =====
    print("\n5. character_class_counts() - Cython vs Pure Python")
    print("-" * 70)
    print(f"{'Size':>8} {'Python (μs)':>15} {'Cython (μs)':>15} {'Speedup':>10}")
    print("-" * 70)

    for size in byte_sizes:
        data = bytes(random.randint(0, 255) for _ in range(size))

        python_time = benchmark(char_class_python, data)
        cython_time = benchmark(character_class_counts_fast, data)
        speedup = python_time / cython_time

        print(f"{size:>8} {python_time:>15.2f} {cython_time:>15.2f} {speedup:>9.2f}x")

    # ===== Correctness Verification =====
    print("\n6. Correctness Verification")
    print("-" * 70)

    # Verify statistics
    test_data = [random.uniform(0, 1000) for _ in range(100)]
    py_result = stats_python(test_data)
    cy_result = compute_statistics_fast(test_data)

    stats_ok = True
    for key in py_result:
        if not np.isclose(py_result[key], cy_result[key], rtol=1e-5):
            print(f"  MISMATCH {key}: Python={py_result[key]} Cython={cy_result[key]}")
            stats_ok = False
    if stats_ok:
        print("  ✓ Statistics match between Python and Cython")

    # Verify entropy
    test_bytes = bytes(random.randint(0, 255) for _ in range(1000))
    py_ent = entropy_python(test_bytes)
    cy_ent = shannon_entropy_fast(test_bytes)
    if np.isclose(py_ent, cy_ent, rtol=1e-5):
        print("  ✓ Shannon entropy matches between Python and Cython")
    else:
        print(f"  MISMATCH entropy: Python={py_ent} Cython={cy_ent}")

    # Verify byte distribution
    py_dist = byte_dist_python(test_bytes)
    cy_dist = byte_distribution_fast(test_bytes)
    dist_ok = True
    for key in py_dist:
        py_val = py_dist[key]
        cy_val = cy_dist[key]
        if isinstance(py_val, float):
            if not np.isclose(py_val, cy_val, rtol=1e-5):
                print(f"  MISMATCH byte_dist[{key}]: Python={py_val} Cython={cy_val}")
                dist_ok = False
        else:
            if py_val != cy_val:
                print(f"  MISMATCH byte_dist[{key}]: Python={py_val} Cython={cy_val}")
                dist_ok = False
    if dist_ok:
        print("  ✓ Byte distribution matches between Python and Cython")

    # Verify character classes
    py_chars = char_class_python(test_bytes)
    cy_chars = character_class_counts_fast(test_bytes)
    if py_chars == cy_chars:
        print("  ✓ Character class counts match between Python and Cython")
    else:
        print(f"  MISMATCH character_classes: Python={py_chars} Cython={cy_chars}")

    print("\n" + "=" * 70)
    print("SUMMARY: Cython extensions provide significant speedups for")
    print("performance-critical operations in flow feature extraction.")
    print("=" * 70)


if __name__ == "__main__":
    run_benchmarks()
