"""Android-specific PID filtering implementations.

Android uses a Linux kernel, so similar methods apply:
1. /proc/net/* parsing - Works on all Android versions
2. ss command - Available on newer Android versions (if busybox/toybox)

Note: Android has additional restrictions on accessing /proc
for other processes unless running as root or with shell UID.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING

from .base import ConnectionInfo, FilterMethod, PIDFilterBase
from .cache import ConnectionCache

if TYPE_CHECKING:
    from typing import Callable

logger = logging.getLogger(__name__)


class AndroidProcFilter(PIDFilterBase):
    """/proc/net/* based PID filtering for Android.

    This is similar to Linux but handles Android-specific paths
    and permission restrictions.
    """

    def __init__(
        self,
        pid: int,
        refresh_interval: float = 0.5,
        on_connection_added: Callable[[ConnectionInfo], None] | None = None,
        on_connection_removed: Callable[[ConnectionInfo], None] | None = None,
    ) -> None:
        super().__init__(pid, refresh_interval, on_connection_added, on_connection_removed)
        self._method = FilterMethod.PROC_NET
        self._cache = ConnectionCache(max_size=10000, ttl_seconds=300.0)
        self._refresh_thread: threading.Thread | None = None
        self._is_rooted = self._check_root_access()

    def _check_root_access(self) -> bool:
        """Check if we have root access on Android."""
        # Check if running as root
        if os.geteuid() == 0:
            return True

        # Check for su binary
        for path in ["/system/bin/su", "/system/xbin/su", "/sbin/su"]:
            if os.path.exists(path):
                return True

        return False

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
            name=f"android-filter-{self.pid}",
        )
        self._refresh_thread.start()
        logger.info(f"Started Android /proc filter for PID {self.pid}")

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
        logger.info(f"Stopped Android /proc filter for PID {self.pid}")

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
        """Refresh connection list from /proc."""
        try:
            # Get socket inodes for the target PID
            inodes = self._get_process_inodes(self.pid)
            if not inodes:
                return

            # Parse /proc/net/* files for connections
            connections = set()

            for proto, path in [
                (6, "/proc/net/tcp"),
                (6, "/proc/net/tcp6"),
                (17, "/proc/net/udp"),
                (17, "/proc/net/udp6"),
            ]:
                if Path(path).exists():
                    conns = self._parse_proc_net(path, proto, inodes)
                    connections.update(conns)

            self._update_connections(connections)
            self._cache.update_from_connections(connections)

        except Exception as e:
            logger.debug(f"Error refreshing connections: {e}")
            self._stats["errors"] += 1

    def _get_process_inodes(self, pid: int) -> set[str]:
        """Get socket inodes for a process.

        On Android, accessing /proc/<pid>/fd may require root
        for processes not owned by the current user.

        Args:
            pid: Process ID.

        Returns:
            Set of socket inode strings.
        """
        inodes = set()
        fd_path = Path(f"/proc/{pid}/fd")

        if not fd_path.exists():
            return inodes

        try:
            # Try direct access first
            for fd in fd_path.iterdir():
                try:
                    link = os.readlink(fd)
                    if link.startswith("socket:["):
                        inode = link[8:-1]
                        inodes.add(inode)
                except (OSError, PermissionError):
                    continue

        except PermissionError:
            # Try using run-as for app processes
            if self._is_rooted:
                inodes = self._get_inodes_with_su(pid)
            else:
                logger.debug(f"Permission denied reading /proc/{pid}/fd")

        return inodes

    def _get_inodes_with_su(self, pid: int) -> set[str]:
        """Get socket inodes using su command.

        Args:
            pid: Process ID.

        Returns:
            Set of socket inode strings.
        """
        inodes = set()

        try:
            result = subprocess.run(
                ["su", "-c", f"ls -la /proc/{pid}/fd"],
                capture_output=True,
                text=True,
                timeout=5.0,
            )

            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "socket:[" in line:
                        match = re.search(r"socket:\[(\d+)\]", line)
                        if match:
                            inodes.add(match.group(1))

        except Exception as e:
            logger.debug(f"Error getting inodes with su: {e}")

        return inodes

    def _parse_proc_net(
        self,
        path: str,
        protocol: int,
        target_inodes: set[str],
    ) -> set[ConnectionInfo]:
        """Parse a /proc/net/* file for connections.

        Args:
            path: Path to /proc/net/tcp, /proc/net/udp, etc.
            protocol: Protocol number (6=TCP, 17=UDP).
            target_inodes: Set of socket inodes to match.

        Returns:
            Set of ConnectionInfo objects.
        """
        connections = set()

        try:
            with open(path, "r") as f:
                # Skip header line
                next(f)

                for line in f:
                    parts = line.split()
                    if len(parts) < 10:
                        continue

                    inode = parts[9]
                    if inode not in target_inodes:
                        continue

                    # Parse local address
                    local_addr = parts[1]
                    local_ip, local_port = self._parse_hex_addr(local_addr)

                    # Parse remote address
                    remote_addr = parts[2]
                    remote_ip, remote_port = self._parse_hex_addr(remote_addr)

                    # Parse state
                    state = self._get_tcp_state(int(parts[3], 16)) if protocol == 6 else ""

                    conn = ConnectionInfo(
                        local_ip=local_ip,
                        local_port=local_port,
                        remote_ip=remote_ip,
                        remote_port=remote_port,
                        protocol=protocol,
                        pid=self.pid,
                        state=state,
                        inode=inode,
                        created_at=time.time(),
                    )
                    connections.add(conn)

        except (OSError, PermissionError) as e:
            logger.debug(f"Error reading {path}: {e}")

        return connections

    def _parse_hex_addr(self, addr: str) -> tuple[str, int]:
        """Parse hex-encoded address from /proc/net/*.

        Args:
            addr: Address in format "HHHHHHHH:PPPP" (IPv4) or
                  "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH:PPPP" (IPv6).

        Returns:
            Tuple of (ip_string, port).
        """
        ip_hex, port_hex = addr.split(":")
        port = int(port_hex, 16)

        if len(ip_hex) == 8:
            # IPv4: Little-endian
            ip_int = int(ip_hex, 16)
            ip = socket.inet_ntoa(struct.pack("<I", ip_int))
        else:
            # IPv6: 4 little-endian 32-bit words
            ip_bytes = bytes.fromhex(ip_hex)
            # Reverse each 4-byte group
            ip_bytes = (
                ip_bytes[3::-1] + ip_bytes[7:3:-1] +
                ip_bytes[11:7:-1] + ip_bytes[15:11:-1]
            )
            ip = socket.inet_ntop(socket.AF_INET6, ip_bytes)

        return ip, port

    def _get_tcp_state(self, state_code: int) -> str:
        """Convert TCP state code to string."""
        states = {
            1: "ESTABLISHED",
            2: "SYN_SENT",
            3: "SYN_RECV",
            4: "FIN_WAIT1",
            5: "FIN_WAIT2",
            6: "TIME_WAIT",
            7: "CLOSE",
            8: "CLOSE_WAIT",
            9: "LAST_ACK",
            10: "LISTEN",
            11: "CLOSING",
        }
        return states.get(state_code, "UNKNOWN")


class AndroidSSFilter(PIDFilterBase):
    """Android ss/toybox-based PID filtering.

    Uses ss command if available (via toybox or busybox).
    Falls back to /proc parsing if not available.
    """

    def __init__(
        self,
        pid: int,
        refresh_interval: float = 0.5,
        on_connection_added: Callable[[ConnectionInfo], None] | None = None,
        on_connection_removed: Callable[[ConnectionInfo], None] | None = None,
    ) -> None:
        super().__init__(pid, refresh_interval, on_connection_added, on_connection_removed)
        self._method = FilterMethod.SS_NETLINK
        self._cache = ConnectionCache(max_size=10000, ttl_seconds=300.0)
        self._refresh_thread: threading.Thread | None = None
        self._ss_path = self._find_ss_command()

    def _find_ss_command(self) -> str | None:
        """Find ss command on Android.

        Android may have ss via:
        - toybox (modern Android)
        - busybox
        - standalone ss binary
        """
        # Check standard locations
        for cmd in ["ss", "toybox ss", "busybox ss"]:
            parts = cmd.split()
            binary = parts[0]
            path = shutil.which(binary)
            if path:
                return cmd

        # Check Android-specific paths
        for path in [
            "/system/bin/ss",
            "/system/xbin/ss",
            "/system/bin/toybox",
            "/system/bin/busybox",
        ]:
            if os.path.exists(path):
                if "toybox" in path or "busybox" in path:
                    return f"{path} ss"
                return path

        return None

    def start(self) -> None:
        """Start the filter."""
        if self._running:
            return

        if not self._ss_path:
            raise RuntimeError("ss command not found on Android")

        self._running = True
        self._stop_event.clear()

        self.refresh_connections()

        self._refresh_thread = threading.Thread(
            target=self._refresh_loop,
            daemon=True,
            name=f"android-ss-filter-{self.pid}",
        )
        self._refresh_thread.start()
        logger.info(f"Started Android ss filter for PID {self.pid}")

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
        logger.info(f"Stopped Android ss filter for PID {self.pid}")

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
        """Refresh connections using ss command."""
        connections = set()

        for proto, flag in [("tcp", "-t"), ("udp", "-u")]:
            try:
                # Handle multi-word commands (toybox ss, busybox ss)
                cmd_parts = self._ss_path.split() + ["-anp", flag]

                result = subprocess.run(
                    cmd_parts,
                    capture_output=True,
                    text=True,
                    timeout=5.0,
                )

                if result.returncode == 0:
                    conns = self._parse_ss_output(result.stdout, proto)
                    connections.update(conns)

            except subprocess.TimeoutExpired:
                logger.warning("ss command timed out")
            except Exception as e:
                logger.debug(f"Error running ss: {e}")

        self._update_connections(connections)
        self._cache.update_from_connections(connections)

    def _parse_ss_output(self, output: str, proto: str) -> set[ConnectionInfo]:
        """Parse ss command output.

        Args:
            output: Raw ss output.
            proto: Protocol name ("tcp" or "udp").

        Returns:
            Set of ConnectionInfo objects for our PID.
        """
        connections = set()
        protocol = 6 if proto == "tcp" else 17

        # Pattern to match PID in process info
        pid_pattern = re.compile(rf'pid={self.pid}\b')

        for line in output.split("\n")[1:]:  # Skip header
            if not line.strip():
                continue

            # Check if this line is for our PID
            if not pid_pattern.search(line):
                continue

            parts = line.split()
            if len(parts) < 5:
                continue

            state = parts[0]
            local_addr = parts[4]
            remote_addr = parts[5] if len(parts) > 5 else "*:*"

            # Parse addresses
            local_ip, local_port = self._parse_ss_addr(local_addr)
            remote_ip, remote_port = self._parse_ss_addr(remote_addr)

            if local_ip is None:
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

    def _parse_ss_addr(self, addr: str) -> tuple[str | None, int | None]:
        """Parse ss address format.

        Args:
            addr: Address like "192.168.1.1:8080" or "[::1]:443" or "*:*".

        Returns:
            Tuple of (ip, port) or (None, None) if unparseable.
        """
        if addr == "*:*":
            return "0.0.0.0", 0

        # Handle IPv6 with brackets
        if addr.startswith("["):
            match = re.match(r"\[([^\]]+)\]:(\d+|\*)", addr)
            if match:
                ip = match.group(1)
                port_str = match.group(2)
                port = 0 if port_str == "*" else int(port_str)
                return ip, port
            return None, None

        # Handle IPv4
        if ":" in addr:
            parts = addr.rsplit(":", 1)
            ip = parts[0]
            port_str = parts[1]
            port = 0 if port_str == "*" else int(port_str)
            return ip, port

        return None, None


class AndroidNetcatFilter(PIDFilterBase):
    """Android netcat-based connection checking.

    Uses /proc directly without needing ss.
    Suitable for non-rooted devices monitoring own PID.
    """

    def __init__(
        self,
        pid: int,
        refresh_interval: float = 0.5,
        on_connection_added: Callable[[ConnectionInfo], None] | None = None,
        on_connection_removed: Callable[[ConnectionInfo], None] | None = None,
    ) -> None:
        super().__init__(pid, refresh_interval, on_connection_added, on_connection_removed)
        # Fall back to proc-based filtering
        self._delegate = AndroidProcFilter(
            pid, refresh_interval, on_connection_added, on_connection_removed
        )
        self._method = self._delegate._method

    def start(self) -> None:
        """Start the filter."""
        self._delegate.start()
        self._running = True

    def stop(self) -> None:
        """Stop the filter."""
        self._delegate.stop()
        self._running = False

    def refresh_connections(self) -> None:
        """Refresh connections."""
        self._delegate.refresh_connections()
        with self._lock:
            self._connections = self._delegate._connections.copy()

    def matches_packet(self, packet) -> bool:
        """Check if packet belongs to the monitored PID."""
        return self._delegate.matches_packet(packet)

    def get_connections(self) -> list[ConnectionInfo]:
        """Get current connections."""
        return self._delegate.get_connections()

    @property
    def stats(self) -> dict:
        """Get statistics."""
        return self._delegate.stats


def get_best_android_filter(
    pid: int,
    refresh_interval: float = 0.5,
    on_connection_added: Callable[[ConnectionInfo], None] | None = None,
    on_connection_removed: Callable[[ConnectionInfo], None] | None = None,
    prefer_method: FilterMethod | None = None,
) -> PIDFilterBase:
    """Get the best available Android filter.

    Args:
        pid: Process ID to monitor.
        refresh_interval: How often to refresh connections.
        on_connection_added: Callback for new connections.
        on_connection_removed: Callback for closed connections.
        prefer_method: Preferred method (if available).

    Returns:
        The best available PID filter for Android.
    """
    # Check preferred method
    if prefer_method == FilterMethod.PROC_NET:
        return AndroidProcFilter(pid, refresh_interval, on_connection_added, on_connection_removed)

    if prefer_method == FilterMethod.SS_NETLINK:
        ss_filter = AndroidSSFilter(pid, refresh_interval, on_connection_added, on_connection_removed)
        if ss_filter._ss_path:
            return ss_filter

    # Try ss first (if available)
    ss_filter = AndroidSSFilter(pid, refresh_interval, on_connection_added, on_connection_removed)
    if ss_filter._ss_path:
        return ss_filter

    # Fall back to /proc
    return AndroidProcFilter(pid, refresh_interval, on_connection_added, on_connection_removed)
