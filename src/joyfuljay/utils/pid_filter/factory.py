"""Factory functions for creating platform-appropriate PID filters."""

from __future__ import annotations

import logging
import os
import platform
import sys
from typing import TYPE_CHECKING, Callable

from .base import (
    ConnectionInfo,
    FilterCapabilities,
    FilterMethod,
    PIDFilterBase,
)

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


def detect_platform() -> str:
    """Detect the current platform.

    Returns:
        Platform string: "linux", "macos", "windows", "android", or "unknown".
    """
    system = platform.system().lower()

    if system == "linux":
        # Check if running on Android
        if os.path.exists("/system/build.prop"):
            return "android"
        # Check for Android in uname
        if "android" in platform.release().lower():
            return "android"
        return "linux"

    if system == "darwin":
        return "macos"

    if system == "windows":
        return "windows"

    return "unknown"


def get_filter_capabilities() -> FilterCapabilities:
    """Get filtering capabilities for the current platform.

    Returns:
        FilterCapabilities describing what's available.
    """
    plat = detect_platform()
    available_methods: list[FilterMethod] = []
    notes: list[str] = []
    requires_root = False
    has_ebpf = False
    has_etw = False
    has_nettop = False
    has_ss = False
    has_psutil = False
    kernel_version = ""

    if plat == "linux":
        kernel_version = platform.release()

        # Check for psutil
        try:
            import psutil  # noqa: F401
            has_psutil = True
            available_methods.append(FilterMethod.PSUTIL)
        except ImportError:
            pass

        # /proc/net is always available on Linux
        available_methods.append(FilterMethod.PROC_NET)

        # Check for ss command
        import shutil
        if shutil.which("ss"):
            has_ss = True
            available_methods.append(FilterMethod.SS_NETLINK)

        # Check for eBPF support
        try:
            version_parts = kernel_version.split(".")
            major = int(version_parts[0])
            minor = int(version_parts[1].split("-")[0])

            if major > 4 or (major == 4 and minor >= 4):
                has_ebpf = os.geteuid() == 0
                if has_ebpf:
                    available_methods.append(FilterMethod.EBPF)
                else:
                    notes.append("eBPF available but requires root")
        except (ValueError, IndexError):
            pass

        requires_root = os.geteuid() != 0
        if requires_root:
            notes.append("Root recommended for full PID visibility")

        best_method = (
            FilterMethod.EBPF if has_ebpf
            else FilterMethod.SS_NETLINK if has_ss
            else FilterMethod.PROC_NET
        )

    elif plat == "macos":
        import shutil

        # Check for psutil
        try:
            import psutil  # noqa: F401
            has_psutil = True
            available_methods.append(FilterMethod.PSUTIL)
        except ImportError:
            pass

        # lsof is always available on macOS
        if shutil.which("lsof"):
            available_methods.append(FilterMethod.LSOF_CACHED)

        # Check for nettop (requires root)
        if shutil.which("nettop"):
            has_nettop = True
            if os.geteuid() == 0:
                available_methods.append(FilterMethod.NETTOP)
            else:
                notes.append("nettop available but requires root")

        # netstat is always available but less useful on macOS
        available_methods.append(FilterMethod.NETSTAT)

        requires_root = os.geteuid() != 0
        if requires_root:
            notes.append("Root provides access to nettop streaming")

        best_method = (
            FilterMethod.NETTOP if has_nettop and os.geteuid() == 0
            else FilterMethod.LSOF_CACHED
        )

    elif plat == "windows":
        import shutil

        # Check for psutil
        try:
            import psutil  # noqa: F401
            has_psutil = True
            available_methods.append(FilterMethod.PSUTIL)
        except ImportError:
            pass

        # netstat is always available
        available_methods.append(FilterMethod.NETSTAT)

        # Check for PowerShell
        if shutil.which("powershell") or shutil.which("pwsh"):
            available_methods.append(FilterMethod.POWERSHELL)

        # Check for ETW (requires admin)
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if is_admin:
                has_etw = True
                available_methods.append(FilterMethod.ETW)
            else:
                notes.append("ETW available but requires administrator")
        except Exception:
            pass

        requires_root = not has_etw  # "root" = admin on Windows
        if requires_root:
            notes.append("Administrator recommended for ETW")

        best_method = (
            FilterMethod.ETW if has_etw
            else FilterMethod.POWERSHELL if shutil.which("powershell")
            else FilterMethod.NETSTAT
        )

    elif plat == "android":
        import shutil

        # /proc/net is available on Android
        available_methods.append(FilterMethod.PROC_NET)

        # Check for ss via toybox/busybox
        for cmd in ["ss", "toybox", "busybox"]:
            if shutil.which(cmd):
                has_ss = True
                available_methods.append(FilterMethod.SS_NETLINK)
                break

        # Check Android-specific paths
        for path in ["/system/bin/toybox", "/system/bin/busybox"]:
            if os.path.exists(path):
                has_ss = True
                if FilterMethod.SS_NETLINK not in available_methods:
                    available_methods.append(FilterMethod.SS_NETLINK)
                break

        # Root check on Android
        requires_root = os.geteuid() != 0
        if requires_root:
            notes.append("Root required for cross-process PID filtering")

        best_method = (
            FilterMethod.SS_NETLINK if has_ss
            else FilterMethod.PROC_NET
        )

    else:
        # Unknown platform, try psutil as fallback
        try:
            import psutil  # noqa: F401
            has_psutil = True
            available_methods.append(FilterMethod.PSUTIL)
            best_method = FilterMethod.PSUTIL
        except ImportError:
            available_methods.append(FilterMethod.NETSTAT)
            best_method = FilterMethod.NETSTAT
            notes.append("Unknown platform, using netstat fallback")

    return FilterCapabilities(
        platform=plat,
        available_methods=available_methods,
        best_method=best_method,
        requires_root=requires_root,
        has_ebpf=has_ebpf,
        has_etw=has_etw,
        has_nettop=has_nettop,
        has_ss=has_ss,
        has_psutil=has_psutil,
        kernel_version=kernel_version,
        notes=notes,
    )


def get_best_filter_method() -> FilterMethod:
    """Get the best available filter method for the current platform.

    Returns:
        The most efficient FilterMethod available.
    """
    return get_filter_capabilities().best_method


def create_pid_filter(
    pid: int,
    refresh_interval: float = 0.5,
    on_connection_added: Callable[[ConnectionInfo], None] | None = None,
    on_connection_removed: Callable[[ConnectionInfo], None] | None = None,
    prefer_method: FilterMethod | None = None,
) -> PIDFilterBase:
    """Create a PID filter appropriate for the current platform.

    This factory function automatically selects the best available
    filtering method for the current platform. You can optionally
    specify a preferred method.

    Args:
        pid: Process ID to monitor.
        refresh_interval: How often to refresh connections (seconds).
            Lower values increase CPU usage but provide faster updates.
        on_connection_added: Optional callback when a new connection
            is detected. Called with ConnectionInfo.
        on_connection_removed: Optional callback when a connection
            is closed. Called with ConnectionInfo.
        prefer_method: Optional preferred filtering method. If the
            method is not available, falls back to the best available.

    Returns:
        A PIDFilterBase subclass appropriate for the platform.

    Example:
        >>> from joyfuljay.utils.pid_filter import create_pid_filter
        >>>
        >>> # Create filter for PID 12345
        >>> filter = create_pid_filter(12345)
        >>> filter.start()
        >>>
        >>> # Check if a packet belongs to this PID
        >>> if filter.matches_packet(packet):
        ...     process_packet(packet)
        >>>
        >>> filter.stop()

    Example with callbacks:
        >>> def on_new_conn(conn):
        ...     print(f"New connection: {conn.local_ip}:{conn.local_port}")
        >>>
        >>> filter = create_pid_filter(
        ...     pid=12345,
        ...     on_connection_added=on_new_conn,
        ... )
    """
    plat = detect_platform()

    logger.debug(f"Creating PID filter for platform: {plat}, PID: {pid}")

    if plat == "linux":
        from .linux import get_best_linux_filter
        return get_best_linux_filter(
            pid, refresh_interval, on_connection_added, on_connection_removed, prefer_method
        )

    if plat == "macos":
        from .macos import get_best_macos_filter
        return get_best_macos_filter(
            pid, refresh_interval, on_connection_added, on_connection_removed, prefer_method
        )

    if plat == "windows":
        from .windows import get_best_windows_filter
        return get_best_windows_filter(
            pid, refresh_interval, on_connection_added, on_connection_removed, prefer_method
        )

    if plat == "android":
        from .android import get_best_android_filter
        return get_best_android_filter(
            pid, refresh_interval, on_connection_added, on_connection_removed, prefer_method
        )

    # Unknown platform - try psutil fallback
    logger.warning(f"Unknown platform '{plat}', trying psutil fallback")
    return _create_psutil_fallback(
        pid, refresh_interval, on_connection_added, on_connection_removed
    )


def _create_psutil_fallback(
    pid: int,
    refresh_interval: float = 0.5,
    on_connection_added: Callable[[ConnectionInfo], None] | None = None,
    on_connection_removed: Callable[[ConnectionInfo], None] | None = None,
) -> PIDFilterBase:
    """Create a psutil-based fallback filter.

    This works on any platform where psutil is installed.
    """

    class PsutilFilter(PIDFilterBase):
        """psutil-based PID filtering fallback."""

        def __init__(self, pid: int, refresh_interval: float, on_added, on_removed):
            super().__init__(pid, refresh_interval, on_added, on_removed)
            self._method = FilterMethod.PSUTIL
            self._refresh_thread = None

            try:
                import psutil
                self._psutil = psutil
            except ImportError:
                raise RuntimeError("psutil is required for this platform")

        def start(self) -> None:
            if self._running:
                return

            self._running = True
            self._stop_event.clear()

            self.refresh_connections()

            import threading
            self._refresh_thread = threading.Thread(
                target=self._refresh_loop,
                daemon=True,
                name=f"psutil-filter-{self.pid}",
            )
            self._refresh_thread.start()

        def stop(self) -> None:
            if not self._running:
                return

            self._running = False
            self._stop_event.set()

            if self._refresh_thread:
                self._refresh_thread.join(timeout=2.0)
                self._refresh_thread = None

        def _refresh_loop(self) -> None:
            while not self._stop_event.is_set():
                try:
                    self.refresh_connections()
                except Exception as e:
                    logger.warning(f"Error refreshing connections: {e}")
                    self._stats["errors"] += 1

                self._stop_event.wait(self.refresh_interval)

        def refresh_connections(self) -> None:
            import time
            connections = set()

            try:
                proc = self._psutil.Process(self.pid)
                for conn in proc.connections(kind="all"):
                    local_ip = conn.laddr.ip if conn.laddr else "0.0.0.0"
                    local_port = conn.laddr.port if conn.laddr else 0
                    remote_ip = conn.raddr.ip if conn.raddr else "0.0.0.0"
                    remote_port = conn.raddr.port if conn.raddr else 0

                    # Map psutil type to protocol number
                    proto_map = {
                        self._psutil.SOCK_STREAM: 6,  # TCP
                        self._psutil.SOCK_DGRAM: 17,  # UDP
                    }
                    protocol = proto_map.get(conn.type, 0)

                    if protocol == 0:
                        continue

                    conn_info = ConnectionInfo(
                        local_ip=local_ip,
                        local_port=local_port,
                        remote_ip=remote_ip,
                        remote_port=remote_port,
                        protocol=protocol,
                        pid=self.pid,
                        state=conn.status if hasattr(conn, "status") else "",
                        created_at=time.time(),
                    )
                    connections.add(conn_info)

            except self._psutil.NoSuchProcess:
                logger.warning(f"Process {self.pid} no longer exists")
            except self._psutil.AccessDenied:
                logger.warning(f"Access denied to process {self.pid}")
            except Exception as e:
                logger.debug(f"Error getting connections: {e}")

            self._update_connections(connections)

    return PsutilFilter(pid, refresh_interval, on_connection_added, on_connection_removed)


def list_available_methods() -> list[tuple[FilterMethod, str]]:
    """List all available filter methods with descriptions.

    Returns:
        List of (FilterMethod, description) tuples.
    """
    caps = get_filter_capabilities()
    descriptions = {
        FilterMethod.EBPF: "Linux eBPF - kernel-level, zero polling (best)",
        FilterMethod.ETW: "Windows Event Tracing - kernel events (best)",
        FilterMethod.NETTOP: "macOS nettop - streaming updates (best)",
        FilterMethod.SS_NETLINK: "Linux ss - fast netlink-based",
        FilterMethod.LSOF_CACHED: "macOS lsof - optimized subprocess",
        FilterMethod.POWERSHELL: "Windows PowerShell - WMI-based",
        FilterMethod.PROC_NET: "Linux /proc/net - universal fallback",
        FilterMethod.NETSTAT: "Cross-platform netstat - slowest",
        FilterMethod.PSUTIL: "psutil library - portable fallback",
    }

    return [
        (method, descriptions.get(method, "Unknown method"))
        for method in caps.available_methods
    ]


def print_capabilities() -> None:
    """Print current platform capabilities to stdout."""
    caps = get_filter_capabilities()

    print(f"Platform: {caps.platform}")
    print(f"Kernel: {caps.kernel_version or 'N/A'}")
    print(f"Best method: {caps.best_method.name}")
    print(f"Requires root: {caps.requires_root}")
    print()
    print("Available methods:")
    for method, desc in list_available_methods():
        marker = "→" if method == caps.best_method else " "
        print(f"  {marker} {method.name}: {desc}")

    if caps.notes:
        print()
        print("Notes:")
        for note in caps.notes:
            print(f"  • {note}")


def validate_pid(pid: int) -> bool:
    """Check if a PID exists and is accessible.

    Args:
        pid: Process ID to check.

    Returns:
        True if the process exists and is accessible.
    """
    plat = detect_platform()

    if plat in ("linux", "android"):
        return os.path.exists(f"/proc/{pid}")
    elif plat in ("macos", "windows"):
        try:
            os.kill(pid, 0)
            return True
        except (OSError, PermissionError):
            return False
    return False


def find_pids_by_name(process_name: str) -> list[int]:
    """Find all PIDs matching a process name.

    The search is case-insensitive and matches partial names.

    Args:
        process_name: Process name to search for (e.g., "chrome", "firefox").

    Returns:
        List of matching PIDs.
    """
    import subprocess

    pids: list[int] = []
    process_name_lower = process_name.lower()
    plat = detect_platform()

    if plat in ("linux", "android"):
        try:
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue

                pid = int(entry)
                try:
                    with open(f"/proc/{pid}/comm", "r") as f:
                        comm = f.read().strip().lower()
                        if process_name_lower in comm:
                            pids.append(pid)
                            continue

                    with open(f"/proc/{pid}/cmdline", "r") as f:
                        cmdline = f.read().replace("\x00", " ").lower()
                        if process_name_lower in cmdline:
                            pids.append(pid)

                except (OSError, PermissionError):
                    continue
        except PermissionError:
            logger.warning("Permission denied reading /proc")

    elif plat == "macos":
        try:
            result = subprocess.run(
                ["ps", "-axo", "pid,comm"],
                capture_output=True,
                text=True,
                timeout=5.0,
            )

            for line in result.stdout.splitlines()[1:]:
                parts = line.split(None, 1)
                if len(parts) < 2:
                    continue

                pid_str, comm = parts
                if process_name_lower in comm.lower():
                    try:
                        pids.append(int(pid_str))
                    except ValueError:
                        continue

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.warning(f"Error running ps: {e}")

    elif plat == "windows":
        # Try psutil first
        try:
            import psutil

            for proc in psutil.process_iter(["pid", "name", "cmdline"]):
                try:
                    info = proc.info
                    name = info.get("name", "").lower()
                    cmdline = " ".join(info.get("cmdline", []) or []).lower()

                    if process_name_lower in name or process_name_lower in cmdline:
                        pids.append(info["pid"])

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except ImportError:
            # Fall back to tasklist
            try:
                result = subprocess.run(
                    ["tasklist", "/FO", "CSV", "/NH"],
                    capture_output=True,
                    text=True,
                    timeout=10.0,
                )

                for line in result.stdout.splitlines():
                    parts = line.strip().strip('"').split('","')
                    if len(parts) < 2:
                        continue

                    image_name = parts[0].lower()
                    if process_name_lower in image_name:
                        try:
                            pids.append(int(parts[1]))
                        except ValueError:
                            continue

            except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                logger.warning(f"Error running tasklist: {e}")

    return pids


def get_process_name(pid: int) -> str | None:
    """Get the process name for a PID.

    Args:
        pid: Process ID.

    Returns:
        Process name or None if not found.
    """
    import subprocess

    plat = detect_platform()

    if plat in ("linux", "android"):
        try:
            with open(f"/proc/{pid}/comm", "r") as f:
                return f.read().strip()
        except (OSError, PermissionError):
            return None

    elif plat == "macos":
        try:
            result = subprocess.run(
                ["ps", "-p", str(pid), "-o", "comm="],
                capture_output=True,
                text=True,
                timeout=2.0,
            )
            return result.stdout.strip() or None
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None

    elif plat == "windows":
        try:
            import psutil
            proc = psutil.Process(pid)
            return proc.name()
        except ImportError:
            try:
                result = subprocess.run(
                    ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                    capture_output=True,
                    text=True,
                    timeout=5.0,
                )
                for line in result.stdout.splitlines():
                    parts = line.strip().strip('"').split('","')
                    if len(parts) >= 2:
                        return parts[0]
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
        except Exception:
            return None

    return None
