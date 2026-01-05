"""Tests for the cross-platform PID filter."""

import os
import socket
import time

import pytest

from joyfuljay.core.packet import Packet
from joyfuljay.utils.pid_filter import (
    ConnectionInfo,
    FilterCapabilities,
    FilterMethod,
    PIDFilterBase,
    create_pid_filter,
    find_pids_by_name,
    get_best_filter_method,
    get_filter_capabilities,
    get_process_name,
    validate_pid,
)


class TestPlatformDetection:
    """Tests for platform detection and capabilities."""

    def test_get_filter_capabilities(self):
        """Test that we can get platform capabilities."""
        caps = get_filter_capabilities()

        assert isinstance(caps, FilterCapabilities)
        assert caps.platform in ("linux", "macos", "windows", "android", "unknown")
        assert len(caps.available_methods) > 0
        assert caps.best_method in caps.available_methods

    def test_get_best_filter_method(self):
        """Test that best method is returned."""
        method = get_best_filter_method()
        assert isinstance(method, FilterMethod)


class TestPIDValidation:
    """Tests for PID validation utilities."""

    def test_validate_current_pid(self):
        """Test that current process PID is valid."""
        my_pid = os.getpid()
        assert validate_pid(my_pid) is True

    def test_validate_invalid_pid(self):
        """Test that invalid PID returns False."""
        # Very high PID unlikely to exist
        assert validate_pid(999999999) is False

    def test_get_current_process_name(self):
        """Test getting name of current process."""
        my_pid = os.getpid()
        name = get_process_name(my_pid)
        assert name is not None
        assert len(name) > 0

    def test_find_pids_by_name(self):
        """Test finding PIDs by process name."""
        # Should find at least our Python process
        pids = find_pids_by_name("python")
        assert len(pids) > 0
        assert os.getpid() in pids


class TestPIDFilter:
    """Tests for the PID filter functionality."""

    def test_create_pid_filter(self):
        """Test creating a PID filter."""
        my_pid = os.getpid()
        pid_filter = create_pid_filter(my_pid)

        assert isinstance(pid_filter, PIDFilterBase)
        assert pid_filter.pid == my_pid

    def test_filter_start_stop(self):
        """Test starting and stopping a filter."""
        my_pid = os.getpid()
        pid_filter = create_pid_filter(my_pid)

        pid_filter.start()
        assert pid_filter._running is True

        pid_filter.stop()
        assert pid_filter._running is False

    def test_filter_context_manager(self):
        """Test filter as context manager."""
        my_pid = os.getpid()

        with create_pid_filter(my_pid) as f:
            assert f._running is True

        assert f._running is False

    def test_filter_detects_connections(self):
        """Test that filter detects TCP connections."""
        my_pid = os.getpid()

        # Create a listening socket
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        # Connect to it
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(("127.0.0.1", port))
        conn, _ = server.accept()

        try:
            # Start filter and check connections
            with create_pid_filter(my_pid, refresh_interval=0.1) as f:
                time.sleep(0.3)  # Wait for refresh
                connections = f.get_connections()

                # Should have at least the listening socket and established connection
                assert len(connections) >= 2

                # Check that we found our port
                ports = {c.local_port for c in connections}
                assert port in ports

        finally:
            conn.close()
            client.close()
            server.close()

    def test_filter_matches_packet(self):
        """Test that filter correctly matches packets."""
        my_pid = os.getpid()

        # Create a connection
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server_port = server.getsockname()[1]

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(("127.0.0.1", server_port))
        client_port = client.getsockname()[1]
        conn, _ = server.accept()

        try:
            with create_pid_filter(my_pid, refresh_interval=0.1) as f:
                time.sleep(0.3)

                # Packet from our connection should match
                matching_packet = Packet(
                    timestamp=time.time(),
                    src_ip="127.0.0.1",
                    src_port=client_port,
                    dst_ip="127.0.0.1",
                    dst_port=server_port,
                    protocol=6,
                    payload_len=100,
                    total_len=140,
                )
                assert f.matches_packet(matching_packet) is True

                # Random packet should not match
                non_matching_packet = Packet(
                    timestamp=time.time(),
                    src_ip="8.8.8.8",
                    src_port=12345,
                    dst_ip="1.1.1.1",
                    dst_port=443,
                    protocol=6,
                    payload_len=100,
                    total_len=140,
                )
                assert f.matches_packet(non_matching_packet) is False

        finally:
            conn.close()
            client.close()
            server.close()

    def test_filter_stats(self):
        """Test that filter tracks statistics."""
        my_pid = os.getpid()

        with create_pid_filter(my_pid, refresh_interval=0.1) as f:
            time.sleep(0.2)
            stats = f.stats

            assert "connections_tracked" in stats
            assert "packets_matched" in stats
            assert "packets_checked" in stats
            assert "method" in stats


class TestConnectionInfo:
    """Tests for ConnectionInfo dataclass."""

    def test_connection_key(self):
        """Test that connection key is unique tuple."""
        conn = ConnectionInfo(
            local_ip="192.168.1.1",
            local_port=8080,
            remote_ip="10.0.0.1",
            remote_port=443,
            protocol=6,
            pid=1234,
        )

        key = conn.key
        assert isinstance(key, tuple)
        assert len(key) == 5
        assert key == ("192.168.1.1", 8080, "10.0.0.1", 443, 6)

    def test_connection_matches_packet_forward(self):
        """Test matching packet in forward direction."""
        conn = ConnectionInfo(
            local_ip="192.168.1.1",
            local_port=8080,
            remote_ip="10.0.0.1",
            remote_port=443,
            protocol=6,
            pid=1234,
        )

        packet = Packet(
            timestamp=time.time(),
            src_ip="192.168.1.1",
            src_port=8080,
            dst_ip="10.0.0.1",
            dst_port=443,
            protocol=6,
            payload_len=100,
            total_len=140,
        )

        assert conn.matches_packet(packet) is True

    def test_connection_matches_packet_reverse(self):
        """Test matching packet in reverse direction."""
        conn = ConnectionInfo(
            local_ip="192.168.1.1",
            local_port=8080,
            remote_ip="10.0.0.1",
            remote_port=443,
            protocol=6,
            pid=1234,
        )

        packet = Packet(
            timestamp=time.time(),
            src_ip="10.0.0.1",
            src_port=443,
            dst_ip="192.168.1.1",
            dst_port=8080,
            protocol=6,
            payload_len=100,
            total_len=140,
        )

        assert conn.matches_packet(packet) is True

    def test_connection_no_match_wrong_protocol(self):
        """Test that wrong protocol doesn't match."""
        conn = ConnectionInfo(
            local_ip="192.168.1.1",
            local_port=8080,
            remote_ip="10.0.0.1",
            remote_port=443,
            protocol=6,  # TCP
            pid=1234,
        )

        packet = Packet(
            timestamp=time.time(),
            src_ip="192.168.1.1",
            src_port=8080,
            dst_ip="10.0.0.1",
            dst_port=443,
            protocol=17,  # UDP
            payload_len=100,
            total_len=140,
        )

        assert conn.matches_packet(packet) is False
