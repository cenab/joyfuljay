"""JoyfulJay benchmark suite."""

from .speed_benchmark import run_benchmarks as run_speed_benchmarks
from .memory_benchmark import run_benchmarks as run_memory_benchmarks
from .feature_benchmark import compare_features

__all__ = [
    "run_speed_benchmarks",
    "run_memory_benchmarks",
    "compare_features",
]
