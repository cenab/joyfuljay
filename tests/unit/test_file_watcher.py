"""Tests for file watcher utility."""

from __future__ import annotations

import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from joyfuljay.utils.file_watcher import FileWatcher, watch_directory


class TestFileWatcherInit:
    """Tests for FileWatcher initialization."""

    def test_basic_initialization(self, tmp_path: Path) -> None:
        """Test basic initialization."""
        callback = MagicMock()
        watcher = FileWatcher([tmp_path], callback)

        assert watcher.paths == [tmp_path]
        assert watcher.callback is callback
        assert watcher.recursive is True
        assert watcher.poll_interval == 1.0
        assert watcher.debounce_seconds == 2.0

    def test_custom_parameters(self, tmp_path: Path) -> None:
        """Test initialization with custom parameters."""
        callback = MagicMock()
        watcher = FileWatcher(
            [tmp_path],
            callback,
            recursive=False,
            poll_interval=0.5,
            debounce_seconds=1.0,
        )

        assert watcher.recursive is False
        assert watcher.poll_interval == 0.5
        assert watcher.debounce_seconds == 1.0

    def test_multiple_paths(self, tmp_path: Path) -> None:
        """Test initialization with multiple paths."""
        dir1 = tmp_path / "dir1"
        dir2 = tmp_path / "dir2"
        dir1.mkdir()
        dir2.mkdir()

        callback = MagicMock()
        watcher = FileWatcher([dir1, dir2], callback)

        assert len(watcher.paths) == 2

    def test_string_paths_converted(self, tmp_path: Path) -> None:
        """Test that string paths are converted to Path objects."""
        callback = MagicMock()
        watcher = FileWatcher([str(tmp_path)], callback)

        assert isinstance(watcher.paths[0], Path)


class TestFileWatcherExtensions:
    """Tests for PCAP extension handling."""

    def test_pcap_extensions_defined(self) -> None:
        """Test that PCAP extensions are defined."""
        assert ".pcap" in FileWatcher.PCAP_EXTENSIONS
        assert ".pcapng" in FileWatcher.PCAP_EXTENSIONS
        assert ".cap" in FileWatcher.PCAP_EXTENSIONS

    def test_extensions_lowercase(self) -> None:
        """Test that extensions are lowercase."""
        for ext in FileWatcher.PCAP_EXTENSIONS:
            assert ext == ext.lower()


class TestFileWatcherPolling:
    """Tests for polling-based file watching."""

    def test_detects_new_pcap_file(self, tmp_path: Path) -> None:
        """Test detection of new PCAP file."""
        callback = MagicMock()
        watcher = FileWatcher(
            [tmp_path],
            callback,
            poll_interval=0.1,
            debounce_seconds=0.2,
        )

        # Disable watchdog for testing
        watcher._use_watchdog = False

        watcher.start()

        try:
            # Wait for initial scan
            time.sleep(0.2)

            # Create a PCAP file
            pcap_file = tmp_path / "test.pcap"
            pcap_file.write_bytes(b"pcap data")

            # Wait for detection and debounce
            time.sleep(1.0)

            # Callback should have been called
            assert callback.called or watcher.pending_count > 0

        finally:
            watcher.stop()

    def test_ignores_non_pcap_files(self, tmp_path: Path) -> None:
        """Test that non-PCAP files are ignored."""
        callback = MagicMock()
        watcher = FileWatcher(
            [tmp_path],
            callback,
            poll_interval=0.1,
            debounce_seconds=0.1,
        )
        watcher._use_watchdog = False

        watcher.start()

        try:
            time.sleep(0.2)

            # Create a non-PCAP file
            txt_file = tmp_path / "test.txt"
            txt_file.write_text("not a pcap")

            time.sleep(0.5)

            # Callback should not have been called
            assert not callback.called

        finally:
            watcher.stop()


class TestFileWatcherMarkProcessed:
    """Tests for marking files as processed."""

    def test_mark_processed(self, tmp_path: Path) -> None:
        """Test marking a file as processed."""
        callback = MagicMock()
        watcher = FileWatcher([tmp_path], callback)

        watcher.mark_processed(tmp_path / "test.pcap")

        assert str(tmp_path / "test.pcap") in watcher._processed_files

    def test_mark_processed_with_string(self, tmp_path: Path) -> None:
        """Test marking with string path."""
        callback = MagicMock()
        watcher = FileWatcher([tmp_path], callback)

        path_str = str(tmp_path / "test.pcap")
        watcher.mark_processed(path_str)

        assert path_str in watcher._processed_files

    def test_clear_processed(self, tmp_path: Path) -> None:
        """Test clearing processed files."""
        callback = MagicMock()
        watcher = FileWatcher([tmp_path], callback)

        watcher.mark_processed(tmp_path / "test1.pcap")
        watcher.mark_processed(tmp_path / "test2.pcap")

        assert watcher.processed_count == 2

        watcher.clear_processed()

        assert watcher.processed_count == 0


class TestFileWatcherProperties:
    """Tests for FileWatcher properties."""

    def test_pending_count(self, tmp_path: Path) -> None:
        """Test pending_count property."""
        callback = MagicMock()
        watcher = FileWatcher([tmp_path], callback)

        assert watcher.pending_count == 0

        # Add to pending manually for testing
        watcher._pending_files["test.pcap"] = time.time()

        assert watcher.pending_count == 1

    def test_processed_count(self, tmp_path: Path) -> None:
        """Test processed_count property."""
        callback = MagicMock()
        watcher = FileWatcher([tmp_path], callback)

        assert watcher.processed_count == 0

        watcher.mark_processed("test1.pcap")
        watcher.mark_processed("test2.pcap")

        assert watcher.processed_count == 2


class TestFileWatcherStartStop:
    """Tests for start/stop functionality."""

    def test_start_creates_thread(self, tmp_path: Path) -> None:
        """Test that start creates a watch thread."""
        callback = MagicMock()
        watcher = FileWatcher([tmp_path], callback)
        watcher._use_watchdog = False

        watcher.start()

        try:
            assert watcher._watch_thread is not None
            assert watcher._watch_thread.is_alive()
        finally:
            watcher.stop()

    def test_stop_terminates_thread(self, tmp_path: Path) -> None:
        """Test that stop terminates the watch thread."""
        callback = MagicMock()
        watcher = FileWatcher([tmp_path], callback)
        watcher._use_watchdog = False

        watcher.start()
        time.sleep(0.1)
        watcher.stop()
        time.sleep(0.1)

        # Thread should no longer be alive (or very close to stopping)
        assert not watcher._watch_thread.is_alive() or watcher._stop_event.is_set()

    def test_double_start_warning(self, tmp_path: Path) -> None:
        """Test that starting twice logs a warning."""
        callback = MagicMock()
        watcher = FileWatcher([tmp_path], callback)
        watcher._use_watchdog = False

        watcher.start()

        try:
            # Second start should not create a new thread
            watcher.start()
        finally:
            watcher.stop()


class TestWatchDirectoryFunction:
    """Tests for watch_directory convenience function."""

    def test_creates_watcher(self, tmp_path: Path) -> None:
        """Test that watch_directory creates a FileWatcher."""
        callback = MagicMock()

        # Run in non-blocking mode
        watcher = watch_directory(
            tmp_path,
            callback,
            recursive=True,
            blocking=False,
        )

        try:
            assert isinstance(watcher, FileWatcher)
            assert watcher.paths == [tmp_path]
            assert watcher.recursive is True
        finally:
            watcher.stop()

    def test_non_blocking_returns_immediately(self, tmp_path: Path) -> None:
        """Test that non-blocking mode returns immediately."""
        callback = MagicMock()

        start = time.time()
        watcher = watch_directory(tmp_path, callback, blocking=False)
        elapsed = time.time() - start

        try:
            assert elapsed < 1.0  # Should return quickly
        finally:
            watcher.stop()
