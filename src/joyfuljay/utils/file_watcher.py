"""File system watcher for automatic PCAP processing.

Monitors directories for new PCAP files and triggers processing
automatically when files are added or modified.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class FileWatcher:
    """Watch directories for new PCAP files.

    Monitors one or more directories for new or modified PCAP files
    and calls a callback function when changes are detected.
    """

    # Supported PCAP extensions
    PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap"}

    def __init__(
        self,
        paths: list[str | Path],
        callback: Callable[[Path], Any],
        recursive: bool = True,
        poll_interval: float = 1.0,
        debounce_seconds: float = 2.0,
    ) -> None:
        """Initialize the file watcher.

        Args:
            paths: Directories to watch.
            callback: Function to call when a new PCAP is detected.
            recursive: Whether to watch subdirectories.
            poll_interval: Seconds between polling checks.
            debounce_seconds: Wait time after file modification before processing.
        """
        self.paths = [Path(p) for p in paths]
        self.callback = callback
        self.recursive = recursive
        self.poll_interval = poll_interval
        self.debounce_seconds = debounce_seconds

        self._stop_event = threading.Event()
        self._watch_thread: threading.Thread | None = None
        self._processed_files: set[str] = set()
        self._file_mtimes: dict[str, float] = {}
        self._pending_files: dict[str, float] = {}  # path -> detection time

        # Try to use watchdog for efficient watching
        self._use_watchdog = False
        try:
            import watchdog  # noqa: F401
            self._use_watchdog = True
        except ImportError:
            logger.info(
                "watchdog not installed, using polling mode. "
                "Install with: pip install watchdog"
            )

    def start(self) -> None:
        """Start watching for file changes."""
        if self._watch_thread and self._watch_thread.is_alive():
            logger.warning("Watcher already running")
            return

        self._stop_event.clear()

        if self._use_watchdog:
            self._start_watchdog()
        else:
            self._start_polling()

    def _start_watchdog(self) -> None:
        """Start watching using watchdog library."""
        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer

        watcher = self

        class PcapHandler(FileSystemEventHandler):
            def on_created(self, event: Any) -> None:
                if not event.is_directory:
                    watcher._handle_file_event(Path(event.src_path))

            def on_modified(self, event: Any) -> None:
                if not event.is_directory:
                    watcher._handle_file_event(Path(event.src_path))

        self._observer = Observer()
        handler = PcapHandler()

        for path in self.paths:
            if path.is_dir():
                self._observer.schedule(handler, str(path), recursive=self.recursive)
                logger.info(f"Watching directory: {path}")

        self._observer.start()

        # Start debounce processor thread
        self._watch_thread = threading.Thread(target=self._debounce_processor, daemon=True)
        self._watch_thread.start()

    def _start_polling(self) -> None:
        """Start watching using polling."""
        self._watch_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._watch_thread.start()

    def _poll_loop(self) -> None:
        """Polling loop for file changes."""
        # Initial scan
        self._scan_directories()

        while not self._stop_event.is_set():
            time.sleep(self.poll_interval)
            self._scan_directories()
            self._process_pending_files()

    def _scan_directories(self) -> None:
        """Scan directories for PCAP files."""
        for base_path in self.paths:
            if not base_path.is_dir():
                continue

            if self.recursive:
                files = base_path.rglob("*")
            else:
                files = base_path.glob("*")

            for file_path in files:
                if file_path.is_file() and file_path.suffix.lower() in self.PCAP_EXTENSIONS:
                    str_path = str(file_path)

                    try:
                        mtime = file_path.stat().st_mtime
                    except OSError:
                        continue

                    # Check if file is new or modified
                    if str_path not in self._file_mtimes:
                        self._file_mtimes[str_path] = mtime
                        if str_path not in self._processed_files:
                            self._pending_files[str_path] = time.time()
                            logger.debug(f"New file detected: {file_path.name}")
                    elif mtime > self._file_mtimes[str_path]:
                        self._file_mtimes[str_path] = mtime
                        self._pending_files[str_path] = time.time()
                        logger.debug(f"File modified: {file_path.name}")

    def _handle_file_event(self, file_path: Path) -> None:
        """Handle a file system event.

        Args:
            file_path: Path to the file.
        """
        if file_path.suffix.lower() not in self.PCAP_EXTENSIONS:
            return

        str_path = str(file_path)
        self._pending_files[str_path] = time.time()
        logger.debug(f"File event: {file_path.name}")

    def _debounce_processor(self) -> None:
        """Process pending files after debounce delay."""
        while not self._stop_event.is_set():
            time.sleep(0.5)
            self._process_pending_files()

    def _process_pending_files(self) -> None:
        """Process files that have passed debounce period."""
        now = time.time()
        ready_files = [
            path
            for path, detect_time in list(self._pending_files.items())
            if now - detect_time >= self.debounce_seconds
        ]

        for str_path in ready_files:
            del self._pending_files[str_path]

            if str_path in self._processed_files:
                continue

            file_path = Path(str_path)
            if not file_path.exists():
                continue

            # Check if file is still being written
            try:
                current_size = file_path.stat().st_size
                time.sleep(0.5)
                new_size = file_path.stat().st_size
                if new_size != current_size:
                    # File still being written
                    self._pending_files[str_path] = now
                    continue
            except OSError:
                continue

            logger.info(f"Processing new file: {file_path.name}")
            self._processed_files.add(str_path)

            try:
                self.callback(file_path)
            except Exception as e:
                logger.error(f"Error processing {file_path.name}: {e}")

    def stop(self) -> None:
        """Stop watching for file changes."""
        self._stop_event.set()

        if self._use_watchdog and hasattr(self, "_observer"):
            self._observer.stop()
            self._observer.join(timeout=2.0)

        if self._watch_thread and self._watch_thread.is_alive():
            self._watch_thread.join(timeout=2.0)

        logger.info("File watcher stopped")

    def mark_processed(self, path: str | Path) -> None:
        """Mark a file as already processed.

        Args:
            path: Path to mark as processed.
        """
        self._processed_files.add(str(path))

    def clear_processed(self) -> None:
        """Clear the list of processed files."""
        self._processed_files.clear()

    @property
    def pending_count(self) -> int:
        """Number of files pending processing."""
        return len(self._pending_files)

    @property
    def processed_count(self) -> int:
        """Number of files processed."""
        return len(self._processed_files)


def watch_directory(
    path: str | Path,
    callback: Callable[[Path], Any],
    recursive: bool = True,
    blocking: bool = True,
) -> FileWatcher:
    """Watch a directory for new PCAP files.

    Args:
        path: Directory to watch.
        callback: Function to call for each new PCAP.
        recursive: Watch subdirectories.
        blocking: If True, block until stopped.

    Returns:
        FileWatcher instance.
    """
    watcher = FileWatcher([path], callback, recursive=recursive)
    watcher.start()

    if blocking:
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            watcher.stop()

    return watcher
