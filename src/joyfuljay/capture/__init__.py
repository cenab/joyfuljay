"""Capture backends for reading PCAP files and live traffic."""

from __future__ import annotations

from .base import CaptureBackend
from .remote_backend import RemoteCaptureBackend
from .scapy_backend import ScapyBackend

# Convenient alias
RemoteBackend = RemoteCaptureBackend

# Conditional import for dpkt backend
try:
    from .dpkt_backend import DpktBackend, is_dpkt_available
except ImportError:
    DpktBackend = None  # type: ignore
    def is_dpkt_available() -> bool:
        return False

__all__ = [
    "CaptureBackend",
    "DpktBackend",
    "RemoteBackend",
    "RemoteCaptureBackend",
    "ScapyBackend",
    "is_dpkt_available",
]
