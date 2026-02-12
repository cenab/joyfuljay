"""Remote capture backend that receives packets from a JoyfulJay server."""

from __future__ import annotations

import asyncio
import logging
import random
import ssl
import threading
import time
from queue import Empty, Queue
from typing import TYPE_CHECKING, Any, Iterator
from urllib.parse import parse_qs, urlparse

try:
    import websockets
except ImportError:
    websockets = None  # type: ignore[assignment]

from ..core.packet import Packet
from ..remote.protocol import (
    MSG_AUTH_FAIL,
    MSG_AUTH_OK,
    MSG_END,
    MSG_PACKET,
    MSG_COMPRESSED,
    deserialize_message,
    deserialize_packet_compressed,
    serialize_auth,
)
from .base import CaptureBackend

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Default reconnection settings
DEFAULT_MAX_RETRIES = 5
DEFAULT_BASE_DELAY = 1.0  # seconds
DEFAULT_MAX_DELAY = 60.0  # seconds
DEFAULT_JITTER = 0.1  # fraction of delay to randomize


def _require_websockets() -> Any:
    if websockets is None:
        raise ImportError(
            "Remote capture requires websockets. Install with: pip install joyfuljay[remote]"
        )
    return websockets


def is_remote_available() -> bool:
    """Check if remote capture dependencies are available."""
    return websockets is not None


class RemoteCaptureBackend(CaptureBackend):
    """Backend that receives packets from a remote JoyfulJay server.

    This backend connects to a JoyfulJay server running on another device
    (e.g., Android phone) and receives streamed packets over WebSocket.

    Example:
        >>> backend = RemoteCaptureBackend.from_jj_url(
        ...     "jj://192.168.1.100:8765?token=abc123"
        ... )
        >>> for packet in backend.iter_packets_live():
        ...     print(packet)
    """

    def __init__(
        self,
        ws_url: str,
        token: str,
        ssl_context: ssl.SSLContext | None = None,
        auto_reconnect: bool = True,
        max_retries: int = DEFAULT_MAX_RETRIES,
        base_delay: float = DEFAULT_BASE_DELAY,
        max_delay: float = DEFAULT_MAX_DELAY,
    ) -> None:
        """Initialize the remote backend.

        Args:
            ws_url: WebSocket URL (ws://host:port or wss://host:port).
            token: Authentication token.
            ssl_context: Optional SSL context for WSS connections.
            auto_reconnect: Whether to automatically reconnect on connection drops.
            max_retries: Maximum number of reconnection attempts (0 for infinite).
            base_delay: Initial delay between reconnection attempts (seconds).
            max_delay: Maximum delay between reconnection attempts (seconds).
        """
        self.ws_url = ws_url
        self.token = token
        self.ssl_context = ssl_context
        self.auto_reconnect = auto_reconnect
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay

        self._stop_event = threading.Event()
        self._receive_thread: threading.Thread | None = None
        self._packet_queue: Queue[Packet | None] = Queue(maxsize=10000)
        self._error: Exception | None = None
        self._connection_attempts = 0
        self._total_reconnects = 0

    @classmethod
    def from_jj_url(
        cls,
        jj_url: str,
        *,
        tls_ca: str | None = None,
        tls_verify: bool = True,
    ) -> RemoteCaptureBackend:
        """Create a backend from a jj:// URL.

        Args:
            jj_url: URL in format jj://host:port?token=xxx
            tls_ca: Optional CA bundle path for WSS verification.
            tls_verify: Whether to verify server certificate for WSS.

        Returns:
            Configured RemoteCaptureBackend instance.

        Raises:
            ValueError: If URL format is invalid.
        """
        parsed = urlparse(jj_url)

        if parsed.scheme not in {"jj", "jjs"}:
            raise ValueError(f"Invalid URL scheme: {parsed.scheme}. Expected 'jj' or 'jjs'")

        host = parsed.hostname
        if not host:
            raise ValueError("Missing host in URL")

        port = parsed.port or 8765
        query = parse_qs(parsed.query)
        token = query.get("token", [""])[0]
        tls_flag = query.get("tls", ["0"])[0]
        use_tls = parsed.scheme == "jjs" or tls_flag.lower() in {"1", "true", "yes"}

        if not token:
            raise ValueError("Missing token in URL query string")

        ws_scheme = "wss" if use_tls else "ws"
        ws_url = f"{ws_scheme}://{host}:{port}"

        ssl_context = None
        if use_tls:
            ssl_context = cls._build_ssl_context(tls_ca, tls_verify)

        return cls(ws_url, token, ssl_context=ssl_context)

    @staticmethod
    def _build_ssl_context(
        tls_ca: str | None,
        tls_verify: bool,
    ) -> ssl.SSLContext:
        if tls_verify:
            return ssl.create_default_context(cafile=tls_ca)

        context = ssl.create_default_context(cafile=tls_ca)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    def iter_packets_offline(self, path: str) -> Iterator[Packet]:
        """Not supported for remote backend.

        Raises:
            NotImplementedError: Always.
        """
        raise NotImplementedError(
            "Remote backend only supports live capture. "
            "Use iter_packets_live() instead."
        )

    def iter_packets_live(
        self,
        interface: str = "",
        bpf_filter: str | None = None,
        packet_count: int | None = None,
        save_pcap: str | None = None,
        pid: int | None = None,
    ) -> Iterator[Packet]:
        """Connect to remote server and yield packets.

        Args:
            interface: Ignored for remote backend.
            bpf_filter: Ignored (filtering happens on server).
            packet_count: Optional maximum number of packets.
            save_pcap: Optional path to save *received* packets to a PCAP file.
                Note: Remote protocol does not carry full raw frames. If enabled,
                JoyfulJay will write a best-effort synthetic PCAP containing
                reconstructed IP/TCP/UDP headers plus whatever payload bytes are
                available.

        Yields:
            Packets received from the remote server.

        Raises:
            PermissionError: If authentication fails.
            ConnectionError: If connection fails.
        """
        self._stop_event.clear()
        self._error = None
        packets_received = 0

        pcap_writer: Any | None = None
        pcap_write: Any | None = None
        if save_pcap:
            try:
                import ipaddress
                from pathlib import Path

                from scapy.layers.inet import ICMP, IP, TCP, UDP  # type: ignore[import-untyped]
                from scapy.layers.inet6 import IPv6  # type: ignore[import-untyped]
                from scapy.layers.l2 import Ether  # type: ignore[import-untyped]
                from scapy.packet import Raw  # type: ignore[import-untyped]
                from scapy.utils import PcapWriter  # type: ignore[import-untyped]

                Path(save_pcap).parent.mkdir(parents=True, exist_ok=True)
                pcap_writer = PcapWriter(save_pcap, append=False, sync=True)

                def _write(packet: Packet) -> None:
                    payload = packet.raw_payload or b""
                    if packet.payload_len and len(payload) < packet.payload_len:
                        payload = payload + (b"\x00" * (packet.payload_len - len(payload)))
                    elif packet.payload_len and len(payload) > packet.payload_len:
                        payload = payload[: packet.payload_len]

                    try:
                        ip_obj = ipaddress.ip_address(packet.src_ip)
                        is_v6 = ip_obj.version == 6
                    except ValueError:
                        is_v6 = ":" in packet.src_ip

                    ip_layer = IPv6(src=packet.src_ip, dst=packet.dst_ip) if is_v6 else IP(
                        src=packet.src_ip, dst=packet.dst_ip
                    )

                    l4 = None
                    if packet.protocol == Packet.PROTO_TCP:
                        l4 = TCP(
                            sport=packet.src_port,
                            dport=packet.dst_port,
                            flags=int(packet.tcp_flags or 0),
                        )
                    elif packet.protocol == Packet.PROTO_UDP:
                        l4 = UDP(sport=packet.src_port, dport=packet.dst_port)
                    elif packet.protocol == Packet.PROTO_ICMP:
                        l4 = ICMP()

                    eth = Ether(src="00:00:00:00:00:00", dst="00:00:00:00:00:00")
                    scapy_pkt = eth / ip_layer
                    if l4 is not None:
                        scapy_pkt = scapy_pkt / l4
                    if payload:
                        scapy_pkt = scapy_pkt / Raw(load=payload)

                    scapy_pkt.time = float(packet.timestamp)
                    pcap_writer.write(scapy_pkt)

                pcap_write = _write
            except Exception as exc:
                logger.warning(f"Failed to enable save_pcap for remote capture: {exc}")
                pcap_writer = None
                pcap_write = None

        # Start receive thread
        self._receive_thread = threading.Thread(
            target=self._receive_loop, daemon=True
        )
        self._receive_thread.start()

        # Yield packets from queue
        try:
            while True:
                try:
                    packet = self._packet_queue.get(timeout=0.1)

                    # Check for end signal
                    if packet is None:
                        if self._error is not None:
                            raise self._error
                        break

                    if pcap_write is not None:
                        try:
                            pcap_write(packet)
                        except Exception as exc:
                            logger.warning(f"Failed to write packet to PCAP: {exc}")
                            pcap_write = None

                    yield packet
                    packets_received += 1

                    # Check packet count limit
                    if packet_count and packets_received >= packet_count:
                        break

                except Empty:
                    if self._stop_event.is_set():
                        break
                    # Check if receive thread is still alive
                    thread = self._receive_thread
                    if thread is None or not thread.is_alive():
                        # Check for errors
                        if self._error:
                            raise self._error
                        break

        finally:
            if pcap_writer is not None:
                try:
                    pcap_writer.close()
                except Exception:
                    pass
            self.stop()

    def _receive_loop(self) -> None:
        """Run the async receive loop in a thread."""
        try:
            asyncio.run(self._async_receive())
        except Exception as e:
            self._error = e
            logger.error(f"Receive loop error: {e}")
        finally:
            # Signal end of packets
            try:
                self._packet_queue.put(None, timeout=1.0)
            except Exception:
                pass

    def _calculate_backoff_delay(self, attempt: int) -> float:
        """Calculate delay for exponential backoff with jitter.

        Args:
            attempt: The current attempt number (0-indexed).

        Returns:
            Delay in seconds.
        """
        # Exponential backoff: base_delay * 2^attempt
        delay = self.base_delay * (2 ** attempt)
        delay = min(delay, self.max_delay)

        # Add jitter to avoid thundering herd
        jitter = delay * DEFAULT_JITTER * random.random()
        return float(delay + jitter)

    async def _async_receive(self) -> None:
        """Async coroutine that receives packets from WebSocket with auto-reconnect."""
        ws = _require_websockets()
        self._connection_attempts = 0

        while not self._stop_event.is_set():
            try:
                await self._connect_and_receive()

                # If we get here normally (server ended), don't reconnect
                break

            except PermissionError:
                # Auth failure - don't retry
                raise

            except (
                ConnectionError,
                ws.exceptions.ConnectionClosed,
                ws.exceptions.InvalidURI,
                OSError,
                asyncio.TimeoutError,
            ) as e:
                if not self.auto_reconnect:
                    raise

                self._connection_attempts += 1

                # Check retry limit
                if self.max_retries > 0 and self._connection_attempts > self.max_retries:
                    logger.error(f"Max reconnection attempts ({self.max_retries}) exceeded")
                    raise ConnectionError(
                        f"Failed to connect after {self.max_retries} attempts: {e}"
                    )

                # Calculate backoff delay
                delay = self._calculate_backoff_delay(self._connection_attempts - 1)
                logger.warning(
                    f"Connection lost ({e}). Reconnecting in {delay:.1f}s "
                    f"(attempt {self._connection_attempts}/{self.max_retries or '∞'})"
                )

                # Wait before reconnecting
                await asyncio.sleep(delay)
                self._total_reconnects += 1

    async def _connect_and_receive(self) -> None:
        """Connect to server and receive packets until connection closes."""
        ws = _require_websockets()
        logger.info(f"Connecting to {self.ws_url}")

        try:
            async with ws.connect(
                self.ws_url,
                ping_interval=30,
                ping_timeout=10,
                ssl=self.ssl_context,
            ) as socket:
                # Send authentication
                await socket.send(serialize_auth(self.token))

                # Wait for auth response
                auth_response = await asyncio.wait_for(socket.recv(), timeout=10.0)
                msg = deserialize_message(auth_response)

                if msg.get("type") == MSG_AUTH_FAIL:
                    raise PermissionError(
                        f"Authentication failed: {msg.get('data', 'Invalid token')}"
                    )

                if msg.get("type") != MSG_AUTH_OK:
                    raise ConnectionError(
                        f"Unexpected auth response: {msg.get('type')}"
                    )

                logger.info("Authentication successful")

                # Reset connection attempts on successful connect
                self._connection_attempts = 0

                # Receive packets
                async for message in socket:
                    if self._stop_event.is_set():
                        return

                    msg = deserialize_message(message)
                    msg_type = msg.get("type")

                    if msg_type in {MSG_PACKET, MSG_COMPRESSED}:
                        packet = deserialize_packet_compressed(message)
                        try:
                            self._packet_queue.put(packet, timeout=1.0)
                        except Exception:
                            # Queue full, drop packet
                            pass

                    elif msg_type == MSG_END:
                        logger.info("Server signaled end of capture")
                        return

        except asyncio.TimeoutError:
            raise ConnectionError("Connection timed out during authentication")

    def stop(self) -> None:
        """Stop receiving packets and close connection."""
        self._stop_event.set()

        if self._receive_thread and self._receive_thread.is_alive():
            self._receive_thread.join(timeout=2.0)

        self._receive_thread = None

    def supports_live_capture(self) -> bool:
        """Remote backend supports live capture.

        Returns:
            True.
        """
        return True

    def supports_pcapng(self) -> bool:
        """Remote backend doesn't directly read files.

        Returns:
            False.
        """
        return False

    @property
    def reconnect_count(self) -> int:
        """Get the total number of reconnection attempts.

        Returns:
            Number of times the client has reconnected.
        """
        return self._total_reconnects
