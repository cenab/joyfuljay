"""Protocol definitions for remote packet streaming."""

from __future__ import annotations

import zlib
from typing import Any, cast

import msgpack

from ..core.packet import Packet

# Message types
MSG_AUTH = 1  # Client -> Server: authentication token
MSG_AUTH_OK = 2  # Server -> Client: authentication successful
MSG_AUTH_FAIL = 3  # Server -> Client: authentication failed
MSG_PACKET = 4  # Server -> Client: packet data
MSG_END = 5  # Server -> Client: capture ended
MSG_ERROR = 6  # Either direction: error message
MSG_COMPRESSED = 7  # Wrapper for compressed data

# Compression settings
COMPRESSION_THRESHOLD = 256  # Only compress if data is larger than this
COMPRESSION_LEVEL = 6  # zlib compression level (1-9, higher = more compression)

# Try to use lz4 for faster compression (optional dependency)
lz4_frame: Any | None
try:
    import lz4.frame as _lz4_frame

    lz4_frame = _lz4_frame
    LZ4_AVAILABLE = True
except ImportError:
    lz4_frame = None
    LZ4_AVAILABLE = False


def serialize_message(msg_type: int, data: Any = None) -> bytes:
    """Serialize a control message.

    Args:
        msg_type: Message type constant.
        data: Optional data payload.

    Returns:
        MessagePack-encoded bytes.
    """
    return cast(bytes, msgpack.packb({"type": msg_type, "data": data}))


def deserialize_message(data: bytes) -> dict[str, Any]:
    """Deserialize a message.

    Args:
        data: MessagePack-encoded bytes.

    Returns:
        Dictionary with 'type' and optional 'data' keys.
    """
    return cast(dict[str, Any], msgpack.unpackb(data, raw=False))


def serialize_auth(token: str) -> bytes:
    """Serialize an authentication message.

    Args:
        token: Authentication token.

    Returns:
        MessagePack-encoded bytes.
    """
    return serialize_message(MSG_AUTH, {"token": token})


def serialize_packet(packet: Packet) -> bytes:
    """Serialize a Packet to msgpack bytes.

    Args:
        packet: The Packet to serialize.

    Returns:
        MessagePack-encoded bytes.
    """
    data = {
        "ts": packet.timestamp,
        "src_ip": packet.src_ip,
        "dst_ip": packet.dst_ip,
        "src_port": packet.src_port,
        "dst_port": packet.dst_port,
        "proto": packet.protocol,
        "payload_len": packet.payload_len,
        "total_len": packet.total_len,
        "tcp_flags": packet.tcp_flags,
        "raw_payload": packet.raw_payload,
    }
    return cast(bytes, msgpack.packb({"type": MSG_PACKET, "data": data}))


def deserialize_packet(data: bytes) -> Packet:
    """Deserialize msgpack bytes to a Packet.

    Args:
        data: MessagePack-encoded bytes.

    Returns:
        Reconstructed Packet object.
    """
    msg = cast(dict[str, Any], msgpack.unpackb(data, raw=False))
    d = msg["data"]
    return Packet(
        timestamp=d["ts"],
        src_ip=d["src_ip"],
        dst_ip=d["dst_ip"],
        src_port=d["src_port"],
        dst_port=d["dst_port"],
        protocol=d["proto"],
        payload_len=d["payload_len"],
        total_len=d["total_len"],
        tcp_flags=d["tcp_flags"],
        raw_payload=d["raw_payload"],
    )


def is_auth_ok(data: bytes) -> bool:
    """Check if a message is an AUTH_OK response.

    Args:
        data: MessagePack-encoded bytes.

    Returns:
        True if the message indicates successful authentication.
    """
    msg = deserialize_message(data)
    return msg.get("type") == MSG_AUTH_OK


def compress_data(data: bytes, use_lz4: bool = True) -> tuple[bytes, str]:
    """Compress data using available compression.

    Args:
        data: Raw bytes to compress.
        use_lz4: Prefer lz4 if available (faster but slightly less compression).

    Returns:
        Tuple of (compressed_data, compression_type).
        compression_type is "lz4", "zlib", or "none".
    """
    if len(data) < COMPRESSION_THRESHOLD:
        return data, "none"

    if use_lz4 and LZ4_AVAILABLE and lz4_frame is not None:
        compressed = cast(bytes, lz4_frame.compress(data))
        return compressed, "lz4"

    compressed = zlib.compress(data, COMPRESSION_LEVEL)
    return compressed, "zlib"


def decompress_data(data: bytes, compression_type: str) -> bytes:
    """Decompress data.

    Args:
        data: Compressed bytes.
        compression_type: Type of compression used ("lz4", "zlib", or "none").

    Returns:
        Decompressed bytes.
    """
    if compression_type == "none":
        return data
    elif compression_type == "lz4":
        if not LZ4_AVAILABLE:
            raise RuntimeError("lz4 compression not available")
        if lz4_frame is None:
            raise RuntimeError("lz4 compression not available")
        return cast(bytes, lz4_frame.decompress(data))
    elif compression_type == "zlib":
        return zlib.decompress(data)
    else:
        raise ValueError(f"Unknown compression type: {compression_type}")


def serialize_packet_compressed(packet: Packet, compress: bool = True) -> bytes:
    """Serialize a Packet to msgpack bytes with optional compression.

    Args:
        packet: The Packet to serialize.
        compress: Whether to apply compression.

    Returns:
        MessagePack-encoded bytes (possibly compressed).
    """
    data = {
        "ts": packet.timestamp,
        "src_ip": packet.src_ip,
        "dst_ip": packet.dst_ip,
        "src_port": packet.src_port,
        "dst_port": packet.dst_port,
        "proto": packet.protocol,
        "payload_len": packet.payload_len,
        "total_len": packet.total_len,
        "tcp_flags": packet.tcp_flags,
        "raw_payload": packet.raw_payload,
    }
    raw = cast(bytes, msgpack.packb({"type": MSG_PACKET, "data": data}))

    if not compress:
        return raw

    compressed, comp_type = compress_data(raw)

    if comp_type == "none":
        return raw

    # Wrap compressed data
    return cast(bytes, msgpack.packb({
        "type": MSG_COMPRESSED,
        "compression": comp_type,
        "data": compressed,
    }))


def deserialize_packet_compressed(data: bytes) -> Packet:
    """Deserialize msgpack bytes to a Packet (handles compression).

    Args:
        data: MessagePack-encoded bytes (possibly compressed).

    Returns:
        Reconstructed Packet object.
    """
    msg = cast(dict[str, Any], msgpack.unpackb(data, raw=False))

    # Check if compressed
    if msg.get("type") == MSG_COMPRESSED:
        comp_type = msg.get("compression", "none")
        inner_data = decompress_data(msg["data"], comp_type)
        msg = cast(dict[str, Any], msgpack.unpackb(inner_data, raw=False))

    d = msg["data"]
    return Packet(
        timestamp=d["ts"],
        src_ip=d["src_ip"],
        dst_ip=d["dst_ip"],
        src_port=d["src_port"],
        dst_port=d["dst_port"],
        protocol=d["proto"],
        payload_len=d["payload_len"],
        total_len=d["total_len"],
        tcp_flags=d["tcp_flags"],
        raw_payload=d["raw_payload"],
    )


def is_compression_available() -> dict[str, bool]:
    """Check which compression methods are available.

    Returns:
        Dictionary mapping compression type to availability.
    """
    return {
        "zlib": True,  # Always available in Python
        "lz4": LZ4_AVAILABLE,
    }
