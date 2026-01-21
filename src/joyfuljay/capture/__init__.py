"""Capture backends for reading PCAP files and live traffic."""

from __future__ import annotations

from .base import CaptureBackend
from .scapy_backend import ScapyBackend

# Optional remote backend (requires websockets)
RemoteCaptureBackend: type[CaptureBackend] | None
RemoteBackend: type[CaptureBackend] | None
try:
    from .remote_backend import RemoteCaptureBackend as _RemoteCaptureBackend
    from .remote_backend import is_remote_available
except ImportError:
    RemoteCaptureBackend = None
    RemoteBackend = None

    def is_remote_available() -> bool:
        return False
else:
    RemoteCaptureBackend = _RemoteCaptureBackend
    RemoteBackend = _RemoteCaptureBackend

# Conditional import for dpkt backend
DpktBackend: type[CaptureBackend] | None
try:
    from .dpkt_backend import DpktBackend as _DpktBackend
    from .dpkt_backend import is_dpkt_available
except ImportError:
    DpktBackend = None

    def is_dpkt_available() -> bool:
        return False
else:
    DpktBackend = _DpktBackend

__all__ = [
    "CaptureBackend",
    "DpktBackend",
    "RemoteBackend",
    "RemoteCaptureBackend",
    "ScapyBackend",
    "is_dpkt_available",
    "is_remote_available",
]
