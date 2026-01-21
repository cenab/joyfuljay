"""macOS-specific PID filtering implementations.

Supports multiple methods in order of efficiency:
1. nettop - Streaming network statistics (requires root)
2. lsof with smart caching - Optimized subprocess calls
3. netstat - Fallback
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import threading
import time
from typing import TYPE_CHECKING, Any

from .base import ConnectionInfo, FilterMethod, PIDFilterBase
from .cache import ConnectionCache

if TYPE_CHECKING:
    from typing import Callable
    from ...core.packet import Packet

logger = logging.getLogger(__name__)


class MacOSLsofFilter(PIDFilterBase):
    """macOS lsof-based PID filtering with smart caching.

    Uses the lsof command to enumerate network connections for a PID.
    Implements intelligent caching to reduce subprocess overhead.
    """

    def __init__(
        self,
        pid: int,
        refresh_interval: float = 0.5,
        on_connection_added: Callable[[ConnectionInfo], None] | None = None,
        on_connection_removed: Callable[[ConnectionInfo], None] | None = None,
    ) -> None:
        super().__init__(pid, refresh_interval, on_connection_added, on_connection_removed)
        self._method = FilterMethod.LSOF_CACHED
        self._cache = ConnectionCache(max_size=10000, ttl_seconds=300.0)
        self._refresh_thread: threading.Thread | None = None
        self._lsof_path = shutil.which("lsof")

    def start(self) -> None:
        """Start the filter."""
        if self._running:
            return

        if not self._lsof_path:
            raise RuntimeError("lsof command not found")

        self._running = True
        self._stop_event.clear()

        # Initial refresh
        self.refresh_connections()

        # Start background refresh thread
        self._refresh_thread = threading.Thread(
            target=self._refresh_loop,
            daemon=True,
            name=f"lsof-filter-{self.pid}",
        )
        self._refresh_thread.start()
        logger.info(f"Started macOS lsof filter for PID {self.pid}")

    def stop(self) -> None:
        """Stop the filter."""
        if not self._running:
            return

        self._running = False
        self._stop_event.set()

        if self._refresh_thread:
            self._refresh_thread.join(timeout=2.0)
            self._refresh_thread = None

        self._cache.clear()
        logger.info(f"Stopped macOS lsof filter for PID {self.pid}")

    def _refresh_loop(self) -> None:
        """Background refresh loop."""
        while not self._stop_event.is_set():
            try:
                self.refresh_connections()
                self._cache.cleanup()
            except Exception as e:
                logger.warning(f"Error refreshing connections: {e}")
                self._stats["errors"] += 1

            self._stop_event.wait(self.refresh_interval)

    def refresh_connections(self) -> None:
        """Refresh connections using lsof."""
        if not self._lsof_path:
            return
        try:
            # Use -n for no DNS resolution, -P for numeric ports
            # -a -p for AND with PID filter
            # -i for internet files only
            result = subprocess.run(
                [self._lsof_path, "-n", "-P", "-a", "-p", str(self.pid), "-i"],
                capture_output=True,
                text=True,
                timeout=10.0,
            )

            if result.returncode == 0:
                connections = self._parse_lsof_output(result.stdout)
                self._update_connections(connections)
                self._cache.update_from_connections(connections)
            elif result.returncode == 1:
                # No connections found (normal)
                self._update_connections(set())
                self._cache.clear()

        except subprocess.TimeoutExpired:
            logger.warning("lsof command timed out")
            self._stats["errors"] += 1
        except Exception as e:
            logger.debug(f"Error running lsof: {e}")
            self._stats["errors"] += 1

    def _parse_lsof_output(self, output: str) -> set[ConnectionInfo]:
        """Parse lsof output.

        Example output:
        COMMAND   PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
        python3 12345 user  3u  IPv4 0x1234567890abcdef      0t0  TCP 127.0.0.1:8080->127.0.0.1:54321 (ESTABLISHED)
        python3 12345 user  4u  IPv6 0x1234567890abcdef      0t0  UDP [::1]:5353

        Args:
            output: Raw lsof output.

        Returns:
            Set of ConnectionInfo objects.
        """
        connections: set[ConnectionInfo] = set()

        for line in output.split("\n")[1:]:  # Skip header
            if not line.strip():
                continue

            parts = line.split()
            if len(parts) < 9:
                continue

            # Find the TYPE column (IPv4, IPv6)
            try:
                type_idx = next(i for i, p in enumerate(parts) if p in ("IPv4", "IPv6"))
            except StopIteration:
                continue

            # NODE column is after TYPE and DEVICE
            node_idx = type_idx + 3
            if node_idx >= len(parts):
                continue

            proto = parts[node_idx]
            if proto not in ("TCP", "UDP"):
                continue

            protocol = 6 if proto == "TCP" else 17

            # NAME column is the rest
            name_idx = node_idx + 1
            if name_idx >= len(parts):
                continue

            name = " ".join(parts[name_idx:])

            # Parse state if present
            state = ""
            if "(" in name and ")" in name:
                state_match = re.search(r"\(([^)]+)\)", name)
                if state_match:
                    state = state_match.group(1)
                    name = name.split("(")[0].strip()

            # Parse addresses
            if "->" in name:
                # Connected socket
                local_part, remote_part = name.split("->")
                local_ip, local_port = self._parse_lsof_addr(local_part)
                remote_ip, remote_port = self._parse_lsof_addr(remote_part)
            else:
                # Listening socket
                local_ip, local_port = self._parse_lsof_addr(name)
                remote_ip = "0.0.0.0"
                remote_port = 0

            if local_ip is None or local_port is None:
                continue

            conn = ConnectionInfo(
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip or "0.0.0.0",
                remote_port=remote_port or 0,
                protocol=protocol,
                pid=self.pid,
                state=state,
                created_at=time.time(),
            )
            connections.add(conn)

        return connections

    def _parse_lsof_addr(self, addr: str) -> tuple[str | None, int | None]:
        """Parse lsof address format.

        Formats:
        - 192.168.1.1:8080
        - [::1]:443
        - *:8080

        Args:
            addr: Address string from lsof.

        Returns:
            Tuple of (ip, port).
        """
        addr = addr.strip()

        if addr.startswith("*:"):
            port = int(addr[2:])
            return "0.0.0.0", port

        if addr.startswith("["):
            # IPv6
            match = re.match(r"\[([^\]]+)\]:(\d+)", addr)
            if match:
                return match.group(1), int(match.group(2))
            return None, None

        # IPv4
        if ":" in addr:
            parts = addr.rsplit(":", 1)
            return parts[0], int(parts[1])

        return None, None


class MacOSNettopFilter(PIDFilterBase):
    """macOS nettop-based streaming PID filtering.

    Uses nettop for streaming network updates. More efficient than
    polling with lsof as it receives push notifications.

    Requires root privileges.
    """

    def __init__(
        self,
        pid: int,
        refresh_interval: float = 0.5,
        on_connection_added: Callable[[ConnectionInfo], None] | None = None,
        on_connection_removed: Callable[[ConnectionInfo], None] | None = None,
    ) -> None:
        super().__init__(pid, refresh_interval, on_connection_added, on_connection_removed)
        self._method = FilterMethod.NETTOP
        self._cache = ConnectionCache(max_size=10000, ttl_seconds=300.0)
        self._nettop_process: subprocess.Popen[str] | None = None
        self._reader_thread: threading.Thread | None = None
        self._nettop_path = shutil.which("nettop")

    def start(self) -> None:
        """Start the nettop streaming filter."""
        if self._running:
            return

        if not self._nettop_path:
            raise RuntimeError("nettop command not found")

        self._running = True
        self._stop_event.clear()

        try:
            # Start nettop in non-interactive mode
            # -P for parsable output
            # -L 0 for no limit
            # -J bytes_in,bytes_out for minimal output
            self._nettop_process = subprocess.Popen(
                [
                    self._nettop_path,
                    "-P",  # Parsable output
                    "-L", "0",  # No output limit
                    "-n",  # No names, numeric only
                    "-p", str(self.pid),  # Filter by PID (if supported)
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )

            # Start reader thread
            self._reader_thread = threading.Thread(
                target=self._read_nettop_output,
                daemon=True,
                name=f"nettop-reader-{self.pid}",
            )
            self._reader_thread.start()

            logger.info(f"Started macOS nettop filter for PID {self.pid}")

        except PermissionError:
            logger.warning("nettop requires root privileges")
            self._running = False
            raise RuntimeError("nettop requires root privileges")
        except Exception as e:
            logger.warning(f"Failed to start nettop: {e}")
            self._running = False
            raise

    def stop(self) -> None:
        """Stop the nettop filter."""
        if not self._running:
            return

        self._running = False
        self._stop_event.set()

        if self._nettop_process:
            self._nettop_process.terminate()
            try:
                self._nettop_process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                self._nettop_process.kill()
            self._nettop_process = None

        if self._reader_thread:
            self._reader_thread.join(timeout=2.0)
            self._reader_thread = None

        self._cache.clear()
        logger.info(f"Stopped macOS nettop filter for PID {self.pid}")

    def _read_nettop_output(self) -> None:
        """Read nettop output and update connections."""
        if not self._nettop_process or not self._nettop_process.stdout:
            return

        try:
            for line in self._nettop_process.stdout:
                if self._stop_event.is_set():
                    break

                line = line.strip()
                if not line:
                    continue

                # Parse nettop output line
                conn = self._parse_nettop_line(line)
                if conn and conn.pid == self.pid:
                    self._add_connection(conn)
                    self._cache.add(conn)

        except Exception as e:
            if self._running:
                logger.warning(f"Error reading nettop output: {e}")
                self._stats["errors"] += 1

    def _parse_nettop_line(self, line: str) -> ConnectionInfo | None:
        """Parse a nettop output line.

        nettop output format varies by macOS version.
        This handles the common parsable format.

        Args:
            line: A line from nettop output.

        Returns:
            ConnectionInfo or None if unparseable.
        """
        # nettop parsable format:
        # time,interface,proto,state,local_addr,remote_addr,pid,rcvd,sent,...
        parts = line.split(",")

        if len(parts) < 7:
            return None

        try:
            proto_str = parts[2]
            if proto_str not in ("tcp", "udp", "TCP", "UDP"):
                return None

            protocol = 6 if proto_str.lower() == "tcp" else 17
            state = parts[3]
            local_addr = parts[4]
            remote_addr = parts[5]
            pid = int(parts[6])

            local_ip, local_port = self._parse_nettop_addr(local_addr)
            remote_ip, remote_port = self._parse_nettop_addr(remote_addr)

            if local_ip is None or local_port is None:
                return None

            return ConnectionInfo(
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip or "0.0.0.0",
                remote_port=remote_port or 0,
                protocol=protocol,
                pid=pid,
                state=state,
                created_at=time.time(),
            )

        except (ValueError, IndexError):
            return None

    def _parse_nettop_addr(self, addr: str) -> tuple[str | None, int | None]:
        """Parse nettop address format."""
        if not addr or addr == "*":
            return "0.0.0.0", 0

        # Handle IPv6
        if addr.startswith("["):
            match = re.match(r"\[([^\]]+)\]:(\d+)", addr)
            if match:
                return match.group(1), int(match.group(2))
            return None, None

        # Handle IPv4
        if ":" in addr:
            parts = addr.rsplit(":", 1)
            try:
                return parts[0], int(parts[1])
            except ValueError:
                return None, None

        return None, None

    def refresh_connections(self) -> None:
        """For nettop, connections are updated via streaming."""
        # Clean up stale entries
        self._cache.cleanup(force=True)

        # Sync cache to connections
        with self._lock:
            current_keys = set(self._connections.keys())
            # Remove any connections not in cache
            for key in list(current_keys):
                if self._cache.get(key) is None:
                    if key in self._connections:
                        self._remove_connection(self._connections[key])


class MacOSNetstatFilter(PIDFilterBase):
    """macOS netstat-based PID filtering.

    Fallback using netstat command. Less efficient than lsof
    as netstat on macOS doesn't directly show PIDs.
    """

    def __init__(
        self,
        pid: int,
        refresh_interval: float = 0.5,
        on_connection_added: Callable[[ConnectionInfo], None] | None = None,
        on_connection_removed: Callable[[ConnectionInfo], None] | None = None,
    ) -> None:
        super().__init__(pid, refresh_interval, on_connection_added, on_connection_removed)
        self._method = FilterMethod.NETSTAT
        self._cache = ConnectionCache(max_size=10000, ttl_seconds=300.0)
        self._refresh_thread: threading.Thread | None = None

        # On macOS, we need to use lsof to get PID info anyway
        # So this falls back to lsof-based filtering
        self._lsof_filter = MacOSLsofFilter(
            pid, refresh_interval, on_connection_added, on_connection_removed
        )

    def start(self) -> None:
        """Start the filter."""
        self._lsof_filter.start()
        self._running = True

    def stop(self) -> None:
        """Stop the filter."""
        self._lsof_filter.stop()
        self._running = False

    def refresh_connections(self) -> None:
        """Refresh connections."""
        self._lsof_filter.refresh_connections()
        with self._lock:
            self._connections = self._lsof_filter._connections.copy()

    def matches_packet(self, packet: "Packet") -> bool:
        """Check if packet belongs to the monitored PID."""
        return self._lsof_filter.matches_packet(packet)

    def get_connections(self) -> list[ConnectionInfo]:
        """Get current connections."""
        return self._lsof_filter.get_connections()

    @property
    def stats(self) -> dict[str, Any]:
        """Get statistics."""
        return self._lsof_filter.stats


def get_best_macos_filter(
    pid: int,
    refresh_interval: float = 0.5,
    on_connection_added: Callable[[ConnectionInfo], None] | None = None,
    on_connection_removed: Callable[[ConnectionInfo], None] | None = None,
    prefer_method: FilterMethod | None = None,
) -> PIDFilterBase:
    """Get the best available macOS filter.

    Args:
        pid: Process ID to monitor.
        refresh_interval: How often to refresh connections.
        on_connection_added: Callback for new connections.
        on_connection_removed: Callback for closed connections.
        prefer_method: Preferred method (if available).

    Returns:
        The best available PID filter for macOS.
    """
    import os

    # Check preferred method
    if prefer_method == FilterMethod.LSOF_CACHED:
        if shutil.which("lsof"):
            return MacOSLsofFilter(pid, refresh_interval, on_connection_added, on_connection_removed)

    if prefer_method == FilterMethod.NETTOP:
        if shutil.which("nettop") and os.geteuid() == 0:
            try:
                return MacOSNettopFilter(pid, refresh_interval, on_connection_added, on_connection_removed)
            except RuntimeError:
                pass

    # Try nettop first (requires root)
    if os.geteuid() == 0 and shutil.which("nettop"):
        try:
            return MacOSNettopFilter(pid, refresh_interval, on_connection_added, on_connection_removed)
        except RuntimeError:
            pass

    # Fall back to lsof
    if shutil.which("lsof"):
        return MacOSLsofFilter(pid, refresh_interval, on_connection_added, on_connection_removed)

    # Last resort: netstat (which uses lsof anyway on macOS)
    return MacOSNetstatFilter(pid, refresh_interval, on_connection_added, on_connection_removed)
