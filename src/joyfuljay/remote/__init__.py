"""Remote capture module for streaming packets over the network."""

from __future__ import annotations

from typing import Any

from .discovery import DiscoveredServer, MDNSAnnouncer, discover_servers

# Protocol constants (kept in sync with protocol.py)
MSG_AUTH = 1
MSG_AUTH_OK = 2
MSG_AUTH_FAIL = 3
MSG_PACKET = 4
MSG_END = 5
MSG_ERROR = 6
MSG_COMPRESSED = 7

_protocol_import_error: Exception | None = None
try:
    from . import protocol as _protocol
except ImportError as exc:
    _protocol_import_error = exc

    def _missing_protocol(*args: Any, **kwargs: Any) -> Any:
        raise ImportError(
            "Remote protocol requires msgpack. Install with: pip install joyfuljay[remote]"
        ) from _protocol_import_error

    serialize_message = _missing_protocol
    deserialize_message = _missing_protocol
    serialize_auth = _missing_protocol
    is_auth_ok = _missing_protocol
    serialize_packet = _missing_protocol
    serialize_packet_compressed = _missing_protocol
    deserialize_packet = _missing_protocol
    deserialize_packet_compressed = _missing_protocol
else:
    serialize_message = _protocol.serialize_message
    deserialize_message = _protocol.deserialize_message
    serialize_auth = _protocol.serialize_auth
    is_auth_ok = _protocol.is_auth_ok
    serialize_packet = _protocol.serialize_packet
    serialize_packet_compressed = _protocol.serialize_packet_compressed
    deserialize_packet = _protocol.deserialize_packet
    deserialize_packet_compressed = _protocol.deserialize_packet_compressed

_server_import_error: Exception | None = None
try:
    from .server import Server
except ImportError as exc:
    _server_import_error = exc

    class Server:  # type: ignore[no-redef]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise ImportError(
                "Remote server requires websockets. Install with: pip install joyfuljay[remote]"
            ) from _server_import_error

__all__ = [
    "Server",
    "MSG_AUTH",
    "MSG_AUTH_OK",
    "MSG_AUTH_FAIL",
    "MSG_COMPRESSED",
    "MSG_PACKET",
    "MSG_END",
    "MSG_ERROR",
    "DiscoveredServer",
    "MDNSAnnouncer",
    "serialize_packet",
    "serialize_packet_compressed",
    "deserialize_packet",
    "deserialize_packet_compressed",
    "serialize_message",
    "deserialize_message",
    "serialize_auth",
    "is_auth_ok",
    "discover_servers",
]
