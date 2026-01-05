"""Cross-platform efficient PID-based network filtering.

This package provides efficient, event-driven PID filtering across all platforms:

- **Linux**: eBPF-based socket tracking (with /proc fallback)
- **macOS**: nettop streaming or optimized lsof
- **Windows**: ETW event tracing (with netstat fallback)
- **Android**: Optimized /proc and ss-based tracking

Usage:
    from joyfuljay.utils.pid_filter import create_pid_filter

    # Create a filter for a specific PID
    filter = create_pid_filter(pid=12345)
    filter.start()

    # Check if a packet belongs to the PID
    if filter.matches_packet(packet):
        process_packet(packet)

    filter.stop()
"""

from .base import (
    ConnectionInfo,
    PIDFilterBase,
    FilterMethod,
    FilterCapabilities,
)
from .cache import ConnectionCache
from .factory import (
    create_pid_filter,
    get_best_filter_method,
    get_filter_capabilities,
    validate_pid,
    find_pids_by_name,
    get_process_name,
)

__all__ = [
    "ConnectionInfo",
    "PIDFilterBase",
    "FilterMethod",
    "FilterCapabilities",
    "ConnectionCache",
    "create_pid_filter",
    "get_best_filter_method",
    "get_filter_capabilities",
    "validate_pid",
    "find_pids_by_name",
    "get_process_name",
]
