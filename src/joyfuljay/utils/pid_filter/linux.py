"""Linux-specific PID filtering implementations.

Supports multiple methods in order of efficiency:
1. eBPF - Kernel-level socket tracking (requires root + kernel 4.4+)
2. ss with netlink - Fast socket enumeration
3. /proc/net/* parsing - Universal fallback
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
from typing import TYPE_CHECKING, Any

from .base import ConnectionInfo, FilterMethod, PIDFilterBase
from .cache import ConnectionCache

if TYPE_CHECKING:
    from typing import Callable
    from ...core.packet import Packet

logger = logging.getLogger(__name__)


class LinuxProcFilter(PIDFilterBase):
    """/proc/net/* based PID filtering for Linux.

    This is the fallback method that works on any Linux system.
    It parses /proc/net/tcp, /proc/net/udp, etc. and matches
    socket inodes to process file descriptors.
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

    def start(self) -> None:
        """Start the filter with background refresh thread."""
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
            name=f"pid-filter-{self.pid}",
        )
        self._refresh_thread.start()
        logger.info(f"Started Linux /proc filter for PID {self.pid}")

    def stop(self) -> None:
        """Stop the filter and cleanup."""
        if not self._running:
            return

        self._running = False
        self._stop_event.set()

        if self._refresh_thread:
            self._refresh_thread.join(timeout=2.0)
            self._refresh_thread = None

        self._cache.clear()
        logger.info(f"Stopped Linux /proc filter for PID {self.pid}")

    def _refresh_loop(self) -> None:
        """Background thread to periodically refresh connections."""
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
            connections: set[ConnectionInfo] = set()

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

        Args:
            pid: Process ID.

        Returns:
            Set of socket inode strings.
        """
        inodes: set[str] = set()
        fd_path = Path(f"/proc/{pid}/fd")

        if not fd_path.exists():
            return inodes

        try:
            for fd in fd_path.iterdir():
                try:
                    link = os.readlink(fd)
                    if link.startswith("socket:["):
                        inode = link[8:-1]
                        inodes.add(inode)
                except (OSError, PermissionError):
                    continue
        except PermissionError:
            logger.debug(f"Permission denied reading /proc/{pid}/fd")

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
        connections: set[ConnectionInfo] = set()

        try:
            with open(path, "r") as f:
                header = next(f).strip().split()
                inode_idx = header.index("inode") if "inode" in header else 9

                for line in f:
                    parts = line.split()
                    if len(parts) <= inode_idx:
                        continue

                    inode = parts[inode_idx]
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


class LinuxSSFilter(PIDFilterBase):
    """Linux ss command based PID filtering.

    Uses the `ss` command with netlink for faster socket enumeration
    than parsing /proc/net/* directly.
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
        self._ss_path = shutil.which("ss")
        self._fallback: LinuxProcFilter | None = None

    def start(self) -> None:
        """Start the filter."""
        if self._running:
            return

        if not self._ss_path:
            raise RuntimeError("ss command not found")

        self._running = True
        self._stop_event.clear()

        self.refresh_connections()

        self._refresh_thread = threading.Thread(
            target=self._refresh_loop,
            daemon=True,
            name=f"ss-filter-{self.pid}",
        )
        self._refresh_thread.start()
        logger.info(f"Started Linux ss filter for PID {self.pid}")

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
        logger.info(f"Stopped Linux ss filter for PID {self.pid}")

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
        if self._fallback is not None:
            self._refresh_from_fallback()
            return
        if not self._ss_path:
            return
        connections: set[ConnectionInfo] = set()
        pid_pattern = re.compile(rf"pid={self.pid}\b")
        pid_seen = False

        for proto, flag in [("tcp", "-t"), ("udp", "-u")]:
            try:
                result = subprocess.run(
                    [self._ss_path, "-anp", flag],
                    capture_output=True,
                    text=True,
                    timeout=5.0,
                )

                if result.returncode == 0:
                    if pid_pattern.search(result.stdout):
                        pid_seen = True
                    conns = self._parse_ss_output(result.stdout, proto)
                    connections.update(conns)

            except subprocess.TimeoutExpired:
                logger.warning("ss command timed out")
            except Exception as e:
                logger.debug(f"Error running ss: {e}")

        if not pid_seen or not connections:
            logger.info("ss did not return PID details; falling back to /proc parsing")
            self._fallback = LinuxProcFilter(
                self.pid,
                self.refresh_interval,
                self.on_connection_added,
                self.on_connection_removed,
            )
            self._method = FilterMethod.PROC_NET
            self._refresh_from_fallback()
            return

        self._update_connections(connections)
        self._cache.update_from_connections(connections)

    def _refresh_from_fallback(self) -> None:
        if self._fallback is None:
            return
        self._fallback.refresh_connections()
        connections = set(self._fallback.get_connections())
        self._update_connections(connections)
        self._cache.update_from_connections(connections)

    def matches_packet(self, packet: "Packet") -> bool:
        """Check if packet belongs to the monitored PID."""
        if self._fallback is not None:
            return self._fallback.matches_packet(packet)
        return super().matches_packet(packet)

    def get_connections(self) -> list[ConnectionInfo]:
        """Get current connections."""
        if self._fallback is not None:
            return self._fallback.get_connections()
        return super().get_connections()

    @property
    def stats(self) -> dict[str, Any]:
        """Get statistics."""
        if self._fallback is not None:
            return self._fallback.stats
        return super().stats

    def _parse_ss_output(self, output: str, proto: str) -> set[ConnectionInfo]:
        """Parse ss command output.

        Args:
            output: Raw ss output.
            proto: Protocol name ("tcp" or "udp").

        Returns:
            Set of ConnectionInfo objects for our PID.
        """
        connections: set[ConnectionInfo] = set()
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

        # Handle IPv4 or hostname
        if ":" in addr:
            parts = addr.rsplit(":", 1)
            ip = parts[0]
            port_str = parts[1]
            port = 0 if port_str == "*" else int(port_str)
            return ip, port

        return None, None


class LinuxEBPFFilter(PIDFilterBase):
    """eBPF-based PID filtering for Linux.

    This is the most efficient method, using kernel-level socket
    tracking. Requires root privileges and kernel 4.4+.

    Falls back to /proc parsing if eBPF is not available.
    """

    # eBPF programs would be loaded here
    # For now, we implement the structure but fall back to /proc

    def __init__(
        self,
        pid: int,
        refresh_interval: float = 0.5,
        on_connection_added: Callable[[ConnectionInfo], None] | None = None,
        on_connection_removed: Callable[[ConnectionInfo], None] | None = None,
    ) -> None:
        super().__init__(pid, refresh_interval, on_connection_added, on_connection_removed)
        self._method = FilterMethod.EBPF
        self._cache = ConnectionCache(max_size=10000, ttl_seconds=300.0)
        self._ebpf_available = self._check_ebpf_support()
        self._fallback: PIDFilterBase | None = None

        if not self._ebpf_available:
            logger.info("eBPF not available, using /proc fallback")
            self._method = FilterMethod.PROC_NET
            self._fallback = LinuxProcFilter(
                pid, refresh_interval, on_connection_added, on_connection_removed
            )

    def _check_ebpf_support(self) -> bool:
        """Check if eBPF is available on this system."""
        # Check kernel version >= 4.4
        try:
            uname = os.uname()
            version_parts = uname.release.split(".")
            major = int(version_parts[0])
            minor = int(version_parts[1].split("-")[0])

            if major < 4 or (major == 4 and minor < 4):
                logger.debug(f"Kernel {uname.release} too old for eBPF")
                return False

        except (ValueError, IndexError):
            return False

        # Check if we have CAP_BPF or root
        if os.geteuid() != 0:
            # Check for CAP_BPF capability
            try:
                with open(f"/proc/{os.getpid()}/status", "r") as f:
                    for line in f:
                        if line.startswith("CapEff:"):
                            cap_eff = int(line.split()[1], 16)
                            # CAP_BPF is bit 39
                            if not (cap_eff & (1 << 39)):
                                logger.debug("Missing CAP_BPF capability")
                                return False
                            break
            except Exception:
                return False

        # Check for BPF syscall
        try:
            # Try to check if BPF syscall exists
            bpf_path = Path("/sys/kernel/btf/vmlinux")
            if not bpf_path.exists():
                # BTF not available, eBPF may still work but with limitations
                pass
        except Exception:
            pass

        # For now, we don't actually load eBPF programs
        # This would require the bcc library or similar
        return False

    def start(self) -> None:
        """Start the filter."""
        if self._fallback:
            self._fallback.start()
            self._running = True
            return

        # TODO: Load eBPF programs for socket tracking
        # For now, fall back to /proc
        self._fallback = LinuxProcFilter(
            self.pid,
            self.refresh_interval,
            self.on_connection_added,
            self.on_connection_removed,
        )
        self._fallback.start()
        self._running = True

    def stop(self) -> None:
        """Stop the filter."""
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


def get_best_linux_filter(
    pid: int,
    refresh_interval: float = 0.5,
    on_connection_added: Callable[[ConnectionInfo], None] | None = None,
    on_connection_removed: Callable[[ConnectionInfo], None] | None = None,
    prefer_method: FilterMethod | None = None,
) -> PIDFilterBase:
    """Get the best available Linux filter.

    Args:
        pid: Process ID to monitor.
        refresh_interval: How often to refresh connections.
        on_connection_added: Callback for new connections.
        on_connection_removed: Callback for closed connections.
        prefer_method: Preferred method (if available).

    Returns:
        The best available PID filter for Linux.
    """
    # Check preferred method first
    if prefer_method == FilterMethod.PROC_NET:
        return LinuxProcFilter(pid, refresh_interval, on_connection_added, on_connection_removed)

    if prefer_method == FilterMethod.SS_NETLINK:
        if shutil.which("ss"):
            return LinuxSSFilter(pid, refresh_interval, on_connection_added, on_connection_removed)

    # Try eBPF first (will fall back automatically)
    if prefer_method == FilterMethod.EBPF or prefer_method is None:
        ebpf_filter = LinuxEBPFFilter(pid, refresh_interval, on_connection_added, on_connection_removed)
        if ebpf_filter._ebpf_available:
            return ebpf_filter

    # Try ss if available
    if shutil.which("ss"):
        return LinuxSSFilter(pid, refresh_interval, on_connection_added, on_connection_removed)

    # Fall back to /proc
    return LinuxProcFilter(pid, refresh_interval, on_connection_added, on_connection_removed)
