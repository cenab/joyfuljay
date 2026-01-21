"""Windows-specific PID filtering implementations.

Supports multiple methods in order of efficiency:
1. ETW (Event Tracing for Windows) - Kernel-level events
2. PowerShell Get-NetTCPConnection - Fast WMI-based
3. netstat -ano - Fallback
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


class WindowsNetstatFilter(PIDFilterBase):
    """Windows netstat-based PID filtering.

    Uses `netstat -ano` to enumerate connections with PIDs.
    This is the most compatible method but slowest.
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

    def start(self) -> None:
        """Start the filter."""
        if self._running:
            return

        self._running = True
        self._stop_event.clear()

        # Initial refresh
        self.refresh_connections()

        # Start background refresh thread
        self._refresh_thread = threading.Thread(
            target=self._refresh_loop,
            daemon=True,
            name=f"netstat-filter-{self.pid}",
        )
        self._refresh_thread.start()
        logger.info(f"Started Windows netstat filter for PID {self.pid}")

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
        logger.info(f"Stopped Windows netstat filter for PID {self.pid}")

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
        """Refresh connections using netstat."""
        connections: set[ConnectionInfo] = set()

        try:
            # Run netstat -ano for all connections with PIDs
            result = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True,
                text=True,
                timeout=30.0,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
            )

            if result.returncode == 0:
                connections = self._parse_netstat_output(result.stdout)

        except subprocess.TimeoutExpired:
            logger.warning("netstat command timed out")
            self._stats["errors"] += 1
        except Exception as e:
            logger.debug(f"Error running netstat: {e}")
            self._stats["errors"] += 1

        self._update_connections(connections)
        self._cache.update_from_connections(connections)

    def _parse_netstat_output(self, output: str) -> set[ConnectionInfo]:
        """Parse netstat -ano output.

        Example output:
        Active Connections

          Proto  Local Address          Foreign Address        State           PID
          TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1052
          TCP    192.168.1.100:49152    93.184.216.34:443      ESTABLISHED     12345

        Args:
            output: Raw netstat output.

        Returns:
            Set of ConnectionInfo objects for our PID.
        """
        connections: set[ConnectionInfo] = set()

        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue

            parts = line.split()
            if len(parts) < 5:
                continue

            proto = parts[0].upper()
            if proto not in ("TCP", "UDP"):
                continue

            protocol = 6 if proto == "TCP" else 17

            try:
                pid = int(parts[-1])
            except ValueError:
                continue

            if pid != self.pid:
                continue

            # Parse local address
            local_addr = parts[1]
            local_ip, local_port = self._parse_netstat_addr(local_addr)

            # Parse foreign address
            foreign_addr = parts[2]
            remote_ip, remote_port = self._parse_netstat_addr(foreign_addr)

            # State is only present for TCP
            state = ""
            if protocol == 6 and len(parts) >= 5:
                state = parts[3]

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

    def _parse_netstat_addr(self, addr: str) -> tuple[str | None, int | None]:
        """Parse netstat address format.

        Formats:
        - 192.168.1.1:8080
        - [::1]:443
        - 0.0.0.0:0
        - *:*

        Args:
            addr: Address string from netstat.

        Returns:
            Tuple of (ip, port).
        """
        if addr == "*:*":
            return "0.0.0.0", 0

        # Handle IPv6 with brackets
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


class WindowsPowerShellFilter(PIDFilterBase):
    """Windows PowerShell-based PID filtering.

    Uses Get-NetTCPConnection and Get-NetUDPEndpoint cmdlets.
    Faster than netstat for filtering by PID.
    """

    def __init__(
        self,
        pid: int,
        refresh_interval: float = 0.5,
        on_connection_added: Callable[[ConnectionInfo], None] | None = None,
        on_connection_removed: Callable[[ConnectionInfo], None] | None = None,
    ) -> None:
        super().__init__(pid, refresh_interval, on_connection_added, on_connection_removed)
        self._method = FilterMethod.POWERSHELL
        self._cache = ConnectionCache(max_size=10000, ttl_seconds=300.0)
        self._refresh_thread: threading.Thread | None = None
        self._powershell_path = shutil.which("powershell") or shutil.which("pwsh")

    def start(self) -> None:
        """Start the filter."""
        if self._running:
            return

        if not self._powershell_path:
            raise RuntimeError("PowerShell not found")

        self._running = True
        self._stop_event.clear()

        # Initial refresh
        self.refresh_connections()

        # Start background refresh thread
        self._refresh_thread = threading.Thread(
            target=self._refresh_loop,
            daemon=True,
            name=f"powershell-filter-{self.pid}",
        )
        self._refresh_thread.start()
        logger.info(f"Started Windows PowerShell filter for PID {self.pid}")

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
        logger.info(f"Stopped Windows PowerShell filter for PID {self.pid}")

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
        """Refresh connections using PowerShell."""
        if not self._powershell_path:
            return
        connections: set[ConnectionInfo] = set()

        # Get TCP connections
        tcp_script = f"""
        Get-NetTCPConnection -OwningProcess {self.pid} -ErrorAction SilentlyContinue |
        Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State |
        ConvertTo-Csv -NoTypeInformation
        """

        try:
            result = subprocess.run(
                [self._powershell_path, "-NoProfile", "-Command", tcp_script],
                capture_output=True,
                text=True,
                timeout=10.0,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
            )

            if result.returncode == 0:
                tcp_conns = self._parse_powershell_csv(result.stdout, 6)
                connections.update(tcp_conns)

        except subprocess.TimeoutExpired:
            logger.warning("PowerShell TCP command timed out")
        except Exception as e:
            logger.debug(f"Error running PowerShell TCP: {e}")

        # Get UDP endpoints
        udp_script = f"""
        Get-NetUDPEndpoint -OwningProcess {self.pid} -ErrorAction SilentlyContinue |
        Select-Object LocalAddress,LocalPort |
        ConvertTo-Csv -NoTypeInformation
        """

        try:
            result = subprocess.run(
                [self._powershell_path, "-NoProfile", "-Command", udp_script],
                capture_output=True,
                text=True,
                timeout=10.0,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
            )

            if result.returncode == 0:
                udp_conns = self._parse_powershell_udp_csv(result.stdout)
                connections.update(udp_conns)

        except subprocess.TimeoutExpired:
            logger.warning("PowerShell UDP command timed out")
        except Exception as e:
            logger.debug(f"Error running PowerShell UDP: {e}")

        self._update_connections(connections)
        self._cache.update_from_connections(connections)

    def _parse_powershell_csv(self, output: str, protocol: int) -> set[ConnectionInfo]:
        """Parse PowerShell CSV output for TCP connections.

        Args:
            output: CSV output from PowerShell.
            protocol: Protocol number (6=TCP).

        Returns:
            Set of ConnectionInfo objects.
        """
        connections: set[ConnectionInfo] = set()
        lines = output.strip().split("\n")

        if len(lines) < 2:
            return connections

        # Skip header
        for line in lines[1:]:
            line = line.strip().strip('"')
            if not line:
                continue

            # Parse CSV (handling quoted values)
            parts = self._parse_csv_line(line)
            if len(parts) < 5:
                continue

            local_ip = parts[0].strip('"')
            local_port = int(parts[1].strip('"'))
            remote_ip = parts[2].strip('"')
            remote_port = int(parts[3].strip('"'))
            state = parts[4].strip('"')

            conn = ConnectionInfo(
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                protocol=protocol,
                pid=self.pid,
                state=state,
                created_at=time.time(),
            )
            connections.add(conn)

        return connections

    def _parse_powershell_udp_csv(self, output: str) -> set[ConnectionInfo]:
        """Parse PowerShell CSV output for UDP endpoints.

        Args:
            output: CSV output from PowerShell.

        Returns:
            Set of ConnectionInfo objects.
        """
        connections: set[ConnectionInfo] = set()
        lines = output.strip().split("\n")

        if len(lines) < 2:
            return connections

        # Skip header
        for line in lines[1:]:
            line = line.strip().strip('"')
            if not line:
                continue

            parts = self._parse_csv_line(line)
            if len(parts) < 2:
                continue

            local_ip = parts[0].strip('"')
            local_port = int(parts[1].strip('"'))

            conn = ConnectionInfo(
                local_ip=local_ip,
                local_port=local_port,
                remote_ip="0.0.0.0",
                remote_port=0,
                protocol=17,  # UDP
                pid=self.pid,
                state="",
                created_at=time.time(),
            )
            connections.add(conn)

        return connections

    def _parse_csv_line(self, line: str) -> list[str]:
        """Parse a CSV line handling quoted values.

        Args:
            line: CSV line.

        Returns:
            List of field values.
        """
        parts = []
        current = ""
        in_quotes = False

        for char in line:
            if char == '"':
                in_quotes = not in_quotes
            elif char == "," and not in_quotes:
                parts.append(current)
                current = ""
            else:
                current += char

        parts.append(current)
        return parts


class WindowsETWFilter(PIDFilterBase):
    """Windows ETW (Event Tracing for Windows) based PID filtering.

    Uses kernel-level event tracing for real-time socket events.
    Most efficient method but requires administrator privileges.

    Falls back to PowerShell if ETW is not available.
    """

    def __init__(
        self,
        pid: int,
        refresh_interval: float = 0.5,
        on_connection_added: Callable[[ConnectionInfo], None] | None = None,
        on_connection_removed: Callable[[ConnectionInfo], None] | None = None,
    ) -> None:
        super().__init__(pid, refresh_interval, on_connection_added, on_connection_removed)
        self._method = FilterMethod.ETW
        self._cache = ConnectionCache(max_size=10000, ttl_seconds=300.0)
        self._etw_available = self._check_etw_support()
        self._fallback: PIDFilterBase | None = None
        self._etw_session = None

        if not self._etw_available:
            logger.info("ETW not available, using PowerShell fallback")
            self._method = FilterMethod.POWERSHELL
            self._fallback = WindowsPowerShellFilter(
                pid, refresh_interval, on_connection_added, on_connection_removed
            )

    def _check_etw_support(self) -> bool:
        """Check if ETW is available and we have permissions."""
        try:
            # Check if we're running as administrator
            import ctypes
            windll = getattr(ctypes, "windll", None)
            if windll is None:
                return False
            is_admin = windll.shell32.IsUserAnAdmin() != 0

            if not is_admin:
                logger.debug("ETW requires administrator privileges")
                return False

            # Check for pyetw or similar library
            import importlib.util

            if importlib.util.find_spec("pywintrace") is not None:
                return True

            # Could also check for other ETW libraries
            return False

        except Exception:
            return False

    def start(self) -> None:
        """Start the filter."""
        if self._fallback:
            self._fallback.start()
            self._running = True
            return

        # TODO: Implement actual ETW session
        # For now, fall back to PowerShell
        if shutil.which("powershell") or shutil.which("pwsh"):
            self._fallback = WindowsPowerShellFilter(
                self.pid,
                self.refresh_interval,
                self.on_connection_added,
                self.on_connection_removed,
            )
        else:
            self._fallback = WindowsNetstatFilter(
                self.pid,
                self.refresh_interval,
                self.on_connection_added,
                self.on_connection_removed,
            )

        self._fallback.start()
        self._running = True

    def stop(self) -> None:
        """Stop the filter."""
        if self._etw_session:
            # Stop ETW session
            self._etw_session = None

        if self._fallback:
            self._fallback.stop()

        self._running = False

    def refresh_connections(self) -> None:
        """Refresh connections."""
        if self._fallback:
            self._fallback.refresh_connections()
            with self._lock:
                self._connections = self._fallback._connections.copy()

    def matches_packet(self, packet: "Packet") -> bool:
        """Check if packet belongs to the monitored PID."""
        if self._fallback:
            return self._fallback.matches_packet(packet)
        return super().matches_packet(packet)

    def get_connections(self) -> list[ConnectionInfo]:
        """Get current connections."""
        if self._fallback:
            return self._fallback.get_connections()
        return super().get_connections()

    @property
    def stats(self) -> dict[str, Any]:
        """Get statistics."""
        if self._fallback:
            return self._fallback.stats
        return super().stats


def get_best_windows_filter(
    pid: int,
    refresh_interval: float = 0.5,
    on_connection_added: Callable[[ConnectionInfo], None] | None = None,
    on_connection_removed: Callable[[ConnectionInfo], None] | None = None,
    prefer_method: FilterMethod | None = None,
) -> PIDFilterBase:
    """Get the best available Windows filter.

    Args:
        pid: Process ID to monitor.
        refresh_interval: How often to refresh connections.
        on_connection_added: Callback for new connections.
        on_connection_removed: Callback for closed connections.
        prefer_method: Preferred method (if available).

    Returns:
        The best available PID filter for Windows.
    """
    # Check preferred method
    if prefer_method == FilterMethod.NETSTAT:
        return WindowsNetstatFilter(pid, refresh_interval, on_connection_added, on_connection_removed)

    if prefer_method == FilterMethod.POWERSHELL:
        if shutil.which("powershell") or shutil.which("pwsh"):
            return WindowsPowerShellFilter(pid, refresh_interval, on_connection_added, on_connection_removed)

    # Try ETW first (will fall back automatically)
    if prefer_method == FilterMethod.ETW or prefer_method is None:
        etw_filter = WindowsETWFilter(pid, refresh_interval, on_connection_added, on_connection_removed)
        if etw_filter._etw_available:
            return etw_filter

    # Try PowerShell
    if shutil.which("powershell") or shutil.which("pwsh"):
        return WindowsPowerShellFilter(pid, refresh_interval, on_connection_added, on_connection_removed)

    # Fall back to netstat
    return WindowsNetstatFilter(pid, refresh_interval, on_connection_added, on_connection_removed)
