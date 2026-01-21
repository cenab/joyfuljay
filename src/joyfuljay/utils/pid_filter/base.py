"""Base classes and types for PID filtering."""

from __future__ import annotations

import logging
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from ...core.packet import Packet

logger = logging.getLogger(__name__)


class FilterMethod(Enum):
    """Available filtering methods, ordered by efficiency."""

    # Event-driven (most efficient)
    EBPF = auto()  # Linux eBPF - kernel-level, zero polling
    ETW = auto()  # Windows Event Tracing - kernel events
    NETTOP = auto()  # macOS nettop - streaming updates

    # Efficient polling
    SS_NETLINK = auto()  # Linux ss command - uses netlink, fast
    LSOF_CACHED = auto()  # macOS lsof with smart caching
    POWERSHELL = auto()  # Windows PowerShell cmdlets

    # Fallback polling
    PROC_NET = auto()  # Linux /proc/net/* parsing
    NETSTAT = auto()  # Cross-platform netstat
    PSUTIL = auto()  # psutil library


@dataclass
class FilterCapabilities:
    """Describes capabilities of the current platform/environment."""

    platform: str
    available_methods: list[FilterMethod]
    best_method: FilterMethod
    requires_root: bool
    has_ebpf: bool = False
    has_etw: bool = False
    has_nettop: bool = False
    has_ss: bool = False
    has_psutil: bool = False
    kernel_version: str = ""
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ConnectionInfo:
    """Represents a network connection with PID information.

    Attributes:
        local_ip: Local IP address.
        local_port: Local port number.
        remote_ip: Remote IP address.
        remote_port: Remote port number.
        protocol: Protocol number (6=TCP, 17=UDP).
        pid: Process ID owning this connection.
        state: Connection state (e.g., ESTABLISHED, LISTEN).
        inode: Socket inode (Linux-specific).
        created_at: Timestamp when connection was detected.
    """

    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    protocol: int
    pid: int
    state: str = ""
    inode: str = ""
    created_at: float = 0.0

    def matches_packet(self, packet: Packet) -> bool:
        """Check if this connection matches a packet.

        Args:
            packet: The packet to check.

        Returns:
            True if the packet belongs to this connection.
        """
        if packet.protocol != self.protocol:
            return False

        # Check forward direction (local -> remote)
        if (
            packet.src_ip == self.local_ip
            and packet.src_port == self.local_port
            and packet.dst_ip == self.remote_ip
            and packet.dst_port == self.remote_port
        ):
            return True

        # Check reverse direction (remote -> local)
        if (
            packet.dst_ip == self.local_ip
            and packet.dst_port == self.local_port
            and packet.src_ip == self.remote_ip
            and packet.src_port == self.remote_port
        ):
            return True

        # For listening sockets, match by local port only
        if self.remote_ip in ("0.0.0.0", "::", "*") and self.remote_port == 0:
            if packet.dst_port == self.local_port or packet.src_port == self.local_port:
                return True

        return False

    @property
    def key(self) -> tuple[str, int, str, int, int]:
        """Return a unique key for this connection."""
        return (self.local_ip, self.local_port, self.remote_ip, self.remote_port, self.protocol)


class PIDFilterBase(ABC):
    """Abstract base class for PID-based packet filtering.

    All platform-specific implementations must inherit from this class
    and implement the abstract methods.
    """

    def __init__(
        self,
        pid: int,
        refresh_interval: float = 0.5,
        on_connection_added: Callable[[ConnectionInfo], None] | None = None,
        on_connection_removed: Callable[[ConnectionInfo], None] | None = None,
    ) -> None:
        """Initialize the PID filter.

        Args:
            pid: Process ID to monitor.
            refresh_interval: How often to refresh connections (for polling methods).
            on_connection_added: Callback when a new connection is detected.
            on_connection_removed: Callback when a connection is closed.
        """
        self.pid = pid
        self.refresh_interval = refresh_interval
        self.on_connection_added = on_connection_added
        self.on_connection_removed = on_connection_removed

        self._connections: dict[tuple[str, int, str, int, int], ConnectionInfo] = {}
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._running = False
        self._method: FilterMethod = FilterMethod.PROC_NET
        self._stats: dict[str, Any] = {
            "connections_tracked": 0,
            "packets_matched": 0,
            "packets_checked": 0,
            "refresh_count": 0,
            "errors": 0,
        }

    @property
    def method(self) -> FilterMethod:
        """Return the filtering method being used."""
        return self._method

    @property
    def is_event_driven(self) -> bool:
        """Return True if using event-driven (not polling) method."""
        return self._method in (FilterMethod.EBPF, FilterMethod.ETW, FilterMethod.NETTOP)

    @property
    def stats(self) -> dict[str, Any]:
        """Return filter statistics."""
        with self._lock:
            return {
                **self._stats,
                "connections_active": len(self._connections),
                "method": self._method.name,
                "is_event_driven": self.is_event_driven,
            }

    @abstractmethod
    def start(self) -> None:
        """Start the filter.

        This should initialize any background threads or event handlers.
        """

    @abstractmethod
    def stop(self) -> None:
        """Stop the filter.

        This should clean up all resources and stop background threads.
        """

    @abstractmethod
    def refresh_connections(self) -> None:
        """Refresh the connection list.

        This is called periodically for polling-based methods,
        or may be a no-op for event-driven methods.
        """

    def matches_packet(self, packet: Packet) -> bool:
        """Check if a packet belongs to the monitored PID.

        Args:
            packet: The packet to check.

        Returns:
            True if the packet belongs to a connection owned by the PID.
        """
        with self._lock:
            self._stats["packets_checked"] += 1

            for conn in self._connections.values():
                if conn.matches_packet(packet):
                    self._stats["packets_matched"] += 1
                    return True

        return False

    def get_connections(self) -> list[ConnectionInfo]:
        """Get the current list of connections.

        Returns:
            List of ConnectionInfo objects for the monitored PID.
        """
        with self._lock:
            return list(self._connections.values())

    def _add_connection(self, conn: ConnectionInfo) -> bool:
        """Add a connection to the tracking set.

        Args:
            conn: Connection to add.

        Returns:
            True if this was a new connection.
        """
        key = conn.key
        with self._lock:
            if key not in self._connections:
                self._connections[key] = conn
                self._stats["connections_tracked"] += 1

                if self.on_connection_added:
                    try:
                        self.on_connection_added(conn)
                    except Exception as e:
                        logger.warning(f"Error in connection added callback: {e}")

                return True
            return False

    def _remove_connection(self, conn: ConnectionInfo) -> bool:
        """Remove a connection from the tracking set.

        Args:
            conn: Connection to remove.

        Returns:
            True if the connection was being tracked.
        """
        key = conn.key
        with self._lock:
            if key in self._connections:
                del self._connections[key]

                if self.on_connection_removed:
                    try:
                        self.on_connection_removed(conn)
                    except Exception as e:
                        logger.warning(f"Error in connection removed callback: {e}")

                return True
            return False

    def _update_connections(self, new_connections: set[ConnectionInfo]) -> None:
        """Update the connection set, tracking additions and removals.

        Args:
            new_connections: The new set of connections.
        """
        with self._lock:
            current_keys = set(self._connections.keys())
            new_keys = {c.key for c in new_connections}

            # Find removed connections
            for key in current_keys - new_keys:
                conn = self._connections[key]
                self._remove_connection(conn)

            # Find added connections
            new_conn_map = {c.key: c for c in new_connections}
            for key in new_keys - current_keys:
                self._add_connection(new_conn_map[key])

            self._stats["refresh_count"] += 1

    def __enter__(self) -> PIDFilterBase:
        """Context manager entry."""
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        """Context manager exit."""
        self.stop()
