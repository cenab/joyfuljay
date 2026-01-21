"""JoyfulJay benchmark suite.

Canonical entrypoint:
    python -m benchmarks.run --suite quick
    python -m benchmarks.run --suite full --data-dir /path/to/data
    python -m benchmarks.run --list

For benchmark data:
    python scripts/download_benchmark_data.py --suite quick

Legacy interfaces (still available):
    from benchmarks import run_speed_benchmarks, run_memory_benchmarks
"""

from .speed_benchmark import run_benchmarks as run_speed_benchmarks
from .memory_benchmark import run_benchmarks as run_memory_benchmarks
from .feature_benchmark import compare_features

__all__ = [
    "run_speed_benchmarks",
    "run_memory_benchmarks",
    "compare_features",
]
