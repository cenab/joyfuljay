"""Tests for port classification utility."""

from __future__ import annotations

import pytest

from joyfuljay.utils.port_classifier import (
    WELL_KNOWN_PORTS,
    classify_port,
    get_port_class_name,
    get_port_class_number,
)


class TestWellKnownPorts:
    """Tests for the well-known ports dictionary."""

    def test_has_common_ports(self) -> None:
        """Test that common ports are defined."""
        common_ports = [22, 53, 80, 443, 3306, 5432, 8080]
        for port in common_ports:
            assert port in WELL_KNOWN_PORTS, f"Port {port} not in well-known ports"

    def test_port_entries_have_correct_format(self) -> None:
        """Test that all entries are (name, class_number) tuples."""
        for port, entry in WELL_KNOWN_PORTS.items():
            assert isinstance(port, int)
            assert isinstance(entry, tuple)
            assert len(entry) == 2
            assert isinstance(entry[0], str)
            assert isinstance(entry[1], int)
            assert entry[1] in (1, 2)  # System or registered


class TestClassifyPort:
    """Tests for classify_port function."""

    def test_well_known_http(self) -> None:
        """Test HTTP port classification."""
        name, num = classify_port(80)
        assert name == "http"
        assert num == 1

    def test_well_known_https(self) -> None:
        """Test HTTPS port classification."""
        name, num = classify_port(443)
        assert name == "https"
        assert num == 1

    def test_well_known_ssh(self) -> None:
        """Test SSH port classification."""
        name, num = classify_port(22)
        assert name == "ssh"
        assert num == 1

    def test_well_known_dns(self) -> None:
        """Test DNS port classification."""
        name, num = classify_port(53)
        assert name == "dns"
        assert num == 1

    def test_registered_mysql(self) -> None:
        """Test MySQL port classification."""
        name, num = classify_port(3306)
        assert name == "mysql"
        assert num == 2

    def test_registered_redis(self) -> None:
        """Test Redis port classification."""
        name, num = classify_port(6379)
        assert name == "redis"
        assert num == 2

    def test_unknown_system_port(self) -> None:
        """Test unknown port in system range."""
        # Port 7 (echo) is not in our dictionary
        name, num = classify_port(7)
        assert name == "system"
        assert num == 1

    def test_unknown_registered_port(self) -> None:
        """Test unknown port in registered range."""
        name, num = classify_port(12345)
        assert name == "registered"
        assert num == 2

    def test_dynamic_port(self) -> None:
        """Test dynamic/ephemeral port."""
        name, num = classify_port(50000)
        assert name == "dynamic"
        assert num == 3

    def test_high_dynamic_port(self) -> None:
        """Test high dynamic port."""
        name, num = classify_port(65535)
        assert name == "dynamic"
        assert num == 3

    def test_port_zero(self) -> None:
        """Test port 0."""
        name, num = classify_port(0)
        assert name == "system"
        assert num == 1

    def test_edge_of_system_range(self) -> None:
        """Test port 1023 (last system port)."""
        name, num = classify_port(1023)
        assert name == "system"
        assert num == 1

    def test_first_registered_port(self) -> None:
        """Test port 1024 (first registered port)."""
        name, num = classify_port(1024)
        assert name == "registered"
        assert num == 2

    def test_last_registered_port(self) -> None:
        """Test port 49151 (last registered port)."""
        name, num = classify_port(49151)
        assert name == "registered"
        assert num == 2

    def test_first_dynamic_port(self) -> None:
        """Test port 49152 (first dynamic port)."""
        name, num = classify_port(49152)
        assert name == "dynamic"
        assert num == 3


class TestGetPortClassName:
    """Tests for get_port_class_name function."""

    def test_returns_string(self) -> None:
        """Test that function returns a string."""
        result = get_port_class_name(80)
        assert isinstance(result, str)

    def test_http(self) -> None:
        """Test HTTP port."""
        assert get_port_class_name(80) == "http"

    def test_https(self) -> None:
        """Test HTTPS port."""
        assert get_port_class_name(443) == "https"

    def test_dynamic(self) -> None:
        """Test dynamic port."""
        assert get_port_class_name(55555) == "dynamic"


class TestGetPortClassNumber:
    """Tests for get_port_class_number function."""

    def test_returns_int(self) -> None:
        """Test that function returns an integer."""
        result = get_port_class_number(80)
        assert isinstance(result, int)

    def test_well_known_returns_1(self) -> None:
        """Test that well-known ports return 1."""
        assert get_port_class_number(80) == 1
        assert get_port_class_number(443) == 1

    def test_registered_returns_2(self) -> None:
        """Test that registered ports return 2."""
        assert get_port_class_number(3306) == 2
        assert get_port_class_number(8080) == 2

    def test_dynamic_returns_3(self) -> None:
        """Test that dynamic ports return 3."""
        assert get_port_class_number(50000) == 3
        assert get_port_class_number(65535) == 3
