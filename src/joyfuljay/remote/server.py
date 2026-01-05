"""WebSocket server for remote packet streaming."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
import socket
import ssl
import threading
import time
from typing import TYPE_CHECKING

import websockets
from websockets.server import serve

from ..capture.scapy_backend import ScapyBackend
from .protocol import (
    MSG_AUTH,
    MSG_AUTH_FAIL,
    MSG_AUTH_OK,
    MSG_END,
    deserialize_message,
    serialize_message,
    serialize_packet_compressed,
)

if TYPE_CHECKING:
    from websockets.server import WebSocketServerProtocol

logger = logging.getLogger(__name__)


class TokenBucketRateLimiter:
    """Token bucket rate limiter for bandwidth throttling.

    Allows bursts up to bucket capacity, then limits to tokens_per_second rate.
    """

    def __init__(
        self,
        tokens_per_second: float,
        bucket_capacity: float | None = None,
    ) -> None:
        """Initialize the rate limiter.

        Args:
            tokens_per_second: Rate at which tokens are added (bytes/second).
            bucket_capacity: Maximum tokens in bucket. Defaults to 2x tokens_per_second.
        """
        self.tokens_per_second = tokens_per_second
        self.bucket_capacity = bucket_capacity or (tokens_per_second * 2)
        self.tokens = self.bucket_capacity
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float) -> float:
        """Acquire tokens, waiting if necessary.

        Args:
            tokens: Number of tokens (bytes) to acquire.

        Returns:
            Time waited in seconds.
        """
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.last_update = now

            # Add tokens based on elapsed time
            self.tokens = min(
                self.bucket_capacity,
                self.tokens + elapsed * self.tokens_per_second
            )

            wait_time = 0.0
            if tokens > self.tokens:
                # Calculate wait time needed
                tokens_needed = tokens - self.tokens
                wait_time = tokens_needed / self.tokens_per_second

            self.tokens -= tokens

        if wait_time > 0:
            await asyncio.sleep(wait_time)

        return wait_time

    @property
    def available_tokens(self) -> float:
        """Get current available tokens."""
        return max(0, self.tokens)


class Server:
    """WebSocket server that captures and streams packets to remote clients.

    This server runs on the device where traffic capture occurs (e.g., Android).
    Clients connect via WebSocket, authenticate with a token, and receive
    a stream of captured packets.

    Example:
        >>> import joyfuljay as jj
        >>> server = jj.remote.Server("wlan0", port=8765)
        >>> print(f"Connect with: {server.get_connection_url()}")
        >>> asyncio.run(server.run())
    """

    def __init__(
        self,
        interface: str,
        host: str = "0.0.0.0",
        port: int = 8765,
        bpf_filter: str | None = None,
        token: str | None = None,
        pid: int | None = None,
        max_clients: int = 5,
        max_bandwidth: float | None = None,
        compress: bool = True,
        tls_cert: str | None = None,
        tls_key: str | None = None,
        announce: bool = False,
        announce_name: str | None = None,
        announce_properties: dict[str, str] | None = None,
        client_queue_size: int = 1000,
    ) -> None:
        """Initialize the JoyfulJay server.

        Args:
            interface: Network interface to capture from.
            host: Host address to bind to.
            port: Port to listen on.
            bpf_filter: Optional BPF filter expression.
            token: Optional authentication token. Generated if not provided.
            pid: Optional process ID to filter traffic by.
            max_clients: Maximum number of concurrent clients (0 for unlimited).
            max_bandwidth: Maximum bandwidth in bytes/second per client (None for unlimited).
            compress: Whether to compress packet payloads before sending.
            tls_cert: Path to TLS certificate (enables WSS).
            tls_key: Path to TLS private key (enables WSS).
            announce: Advertise server via mDNS/Bonjour.
            announce_name: Optional mDNS service name override.
            announce_properties: Optional mDNS TXT records.
            client_queue_size: Per-client packet queue size.
        """
        self.interface = interface
        self.host = host
        self.port = port
        self.bpf_filter = bpf_filter
        self.pid = pid
        self.token = token or secrets.token_urlsafe(32)
        self.max_clients = max_clients
        self.max_bandwidth = max_bandwidth
        self.compress = compress
        self.client_queue_size = max(1, client_queue_size)
        self.announce = announce
        self.announce_name = announce_name
        self.announce_properties = announce_properties or {}
        self.ssl_context = self._build_ssl_context(tls_cert, tls_key)
        self.backend = ScapyBackend(store_raw_payload=True)
        self.clients: set[WebSocketServerProtocol] = set()
        self._stop_event = asyncio.Event()
        self._packet_queue: asyncio.Queue = asyncio.Queue(maxsize=10000)
        self._client_rate_limiters: dict[WebSocketServerProtocol, TokenBucketRateLimiter] = {}
        self._client_queues: dict[WebSocketServerProtocol, asyncio.Queue[bytes]] = {}
        self._client_tasks: dict[WebSocketServerProtocol, asyncio.Task] = {}
        self._loop: asyncio.AbstractEventLoop | None = None
        self._broadcast_task: asyncio.Task | None = None
        self._announcer = None

    def get_local_ip(self) -> str:
        """Get the local IP address for client connections.

        Returns:
            Local IP address as string.
        """
        try:
            # Create a socket to determine the local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def get_connection_url(self) -> str:
        """Generate the jj:// connection URL.

        Returns:
            Connection URL with embedded token.
        """
        ip = self.get_local_ip()
        suffix = f"token={self.token}"
        if self.ssl_context is not None:
            suffix += "&tls=1"
        return f"jj://{ip}:{self.port}?{suffix}"

    def _build_ssl_context(
        self,
        tls_cert: str | None,
        tls_key: str | None,
    ) -> ssl.SSLContext | None:
        if not tls_cert and not tls_key:
            return None
        if not tls_cert or not tls_key:
            raise ValueError("Both tls_cert and tls_key must be provided for TLS.")

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=tls_cert, keyfile=tls_key)
        return context

    async def handle_client(self, websocket: WebSocketServerProtocol) -> None:
        """Handle a connected client.

        Args:
            websocket: The WebSocket connection.
        """
        client_addr = websocket.remote_address
        logger.info(f"Client connecting from: {client_addr}")

        # Check max clients limit
        if self.max_clients > 0 and len(self.clients) >= self.max_clients:
            logger.warning(
                f"Rejecting client {client_addr}: max clients ({self.max_clients}) reached"
            )
            await websocket.send(serialize_message(MSG_AUTH_FAIL, "Server at capacity"))
            return

        try:
            # First message must be authentication
            auth_msg = await asyncio.wait_for(websocket.recv(), timeout=10.0)
            msg = deserialize_message(auth_msg)

            if msg.get("type") != MSG_AUTH:
                logger.warning(f"Invalid first message from {client_addr}")
                await websocket.send(serialize_message(MSG_AUTH_FAIL, "Expected auth"))
                return

            # Verify token
            client_token = msg.get("data", {}).get("token", "")
            if not secrets.compare_digest(client_token, self.token):
                logger.warning(f"Authentication failed from {client_addr}")
                await websocket.send(serialize_message(MSG_AUTH_FAIL, "Invalid token"))
                return

            # Authentication successful
            logger.info(f"Client authenticated: {client_addr}")
            await websocket.send(serialize_message(MSG_AUTH_OK))
            self.clients.add(websocket)

            # Create rate limiter for this client if bandwidth limit is set
            rate_limiter = None
            if self.max_bandwidth:
                rate_limiter = TokenBucketRateLimiter(self.max_bandwidth)
                self._client_rate_limiters[websocket] = rate_limiter

            queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=self.client_queue_size)
            self._client_queues[websocket] = queue
            task = asyncio.create_task(
                self._client_send_loop(websocket, queue, rate_limiter)
            )
            self._client_tasks[websocket] = task
            await task

        except asyncio.TimeoutError:
            logger.warning(f"Client {client_addr} timed out during auth")
        except Exception as e:
            logger.error(f"Error handling client {client_addr}: {e}")
        finally:
            self.clients.discard(websocket)
            self._client_queues.pop(websocket, None)
            task = self._client_tasks.pop(websocket, None)
            if task and not task.done():
                task.cancel()
            self._client_rate_limiters.pop(websocket, None)
            logger.info(f"Client disconnected: {client_addr}")

    async def _client_send_loop(
        self,
        websocket: WebSocketServerProtocol,
        queue: asyncio.Queue[bytes],
        rate_limiter: TokenBucketRateLimiter | None,
    ) -> None:
        """Send packets from queue to a client with keepalive."""
        try:
            while not self._stop_event.is_set():
                try:
                    packet_data = await asyncio.wait_for(queue.get(), timeout=0.5)
                except asyncio.TimeoutError:
                    try:
                        await websocket.ping()
                    except Exception:
                        break
                    continue

                if rate_limiter:
                    await rate_limiter.acquire(len(packet_data))

                await websocket.send(packet_data)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Error sending packet: {e}")
        finally:
            try:
                await websocket.send(serialize_message(MSG_END))
            except Exception:
                pass

    def _enqueue_packet(self, packet) -> None:
        try:
            self._packet_queue.put_nowait(packet)
        except asyncio.QueueFull:
            pass

    async def _broadcast_loop(self) -> None:
        """Broadcast captured packets to all connected clients."""
        try:
            while not self._stop_event.is_set():
                try:
                    packet = await asyncio.wait_for(self._packet_queue.get(), timeout=0.5)
                except asyncio.TimeoutError:
                    continue

                packet_data = serialize_packet_compressed(packet, compress=self.compress)
                if not self._client_queues:
                    continue

                for websocket, queue in list(self._client_queues.items()):
                    if websocket.closed:
                        continue
                    try:
                        queue.put_nowait(packet_data)
                    except asyncio.QueueFull:
                        # Drop packet for slow client
                        continue
        except asyncio.CancelledError:
            pass

    def _capture_thread(self) -> None:
        """Run packet capture in a separate thread."""
        if self._loop is None:
            return

        try:
            for packet in self.backend.iter_packets_live(
                self.interface,
                bpf_filter=self.bpf_filter,
                pid=self.pid,
            ):
                if self._stop_event.is_set():
                    break

                self._loop.call_soon_threadsafe(self._enqueue_packet, packet)

        except Exception as e:
            logger.error(f"Capture error: {e}")

    async def run(self) -> None:
        """Start the server and begin capturing.

        This is the main entry point. It starts the WebSocket server
        and the packet capture thread.
        """
        self._loop = asyncio.get_running_loop()

        if self.announce:
            try:
                from .discovery import MDNSAnnouncer
                from .. import __version__
            except ImportError as exc:
                raise RuntimeError(
                    "mDNS discovery requires zeroconf. Install with: pip install zeroconf"
                ) from exc

            props = {
                "protocol": "jj",
                "version": __version__,
                "tls": "1" if self.ssl_context is not None else "0",
            }
            props.update(self.announce_properties)
            name = self.announce_name or f"JoyfulJay-{socket.gethostname()}-{self.port}"
            self._announcer = MDNSAnnouncer(
                name=name,
                port=self.port,
                address=self.get_local_ip(),
                properties=props,
            )
            self._announcer.start()

        # Start capture thread
        capture_thread = threading.Thread(
            target=self._capture_thread, daemon=True
        )
        capture_thread.start()
        logger.info(f"Started capture on interface: {self.interface}")

        self._broadcast_task = asyncio.create_task(self._broadcast_loop())

        # Start WebSocket server
        async with serve(
            self.handle_client,
            self.host,
            self.port,
            ping_interval=30,
            ping_timeout=10,
            ssl=self.ssl_context,
        ):
            logger.info(f"Server listening on {self.host}:{self.port}")
            try:
                # Wait until stop is signaled
                await self._stop_event.wait()
            except asyncio.CancelledError:
                pass

        if self._broadcast_task:
            self._broadcast_task.cancel()
            with contextlib.suppress(Exception):
                await self._broadcast_task

        # Stop capture
        self.backend.stop()
        logger.info("Server stopped")

        if self._announcer is not None:
            self._announcer.stop()
            self._announcer = None

    def stop(self) -> None:
        """Signal the server to stop."""
        self._stop_event.set()
