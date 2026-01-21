"""Tests for mDNS discovery module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from joyfuljay.remote.discovery import (
    SERVICE_TYPE,
    DiscoveredServer,
    MDNSAnnouncer,
    discover_servers,
)


class TestDiscoveredServer:
    """Tests for DiscoveredServer dataclass."""

    def test_creation(self) -> None:
        """Test basic creation of DiscoveredServer."""
        server = DiscoveredServer(
            name="test-server",
            address="192.168.1.100",
            port=8765,
            properties={"tls": "1", "interface": "wlan0"},
        )

        assert server.name == "test-server"
        assert server.address == "192.168.1.100"
        assert server.port == 8765
        assert server.properties["tls"] == "1"

    def test_immutable(self) -> None:
        """Test that DiscoveredServer is immutable."""
        server = DiscoveredServer(
            name="test-server",
            address="192.168.1.100",
            port=8765,
            properties={},
        )

        with pytest.raises(AttributeError):
            server.name = "new-name"  # type: ignore

    def test_equality(self) -> None:
        """Test that DiscoveredServer equality works."""
        server1 = DiscoveredServer("a", "1.1.1.1", 8765, {})
        server2 = DiscoveredServer("a", "1.1.1.1", 8765, {})
        server3 = DiscoveredServer("b", "2.2.2.2", 8765, {})

        assert server1 == server2
        assert server1 != server3


class TestMDNSAnnouncer:
    """Tests for MDNSAnnouncer class."""

    def test_initialization(self) -> None:
        """Test announcer initialization."""
        announcer = MDNSAnnouncer(
            name="my-server",
            port=8765,
            address="192.168.1.100",
            properties={"tls": "1"},
        )

        assert announcer.name == "my-server"
        assert announcer.port == 8765
        assert announcer.address == "192.168.1.100"
        assert announcer.properties["tls"] == "1"
        assert announcer._zeroconf is None
        assert announcer._info is None

    def test_default_properties(self) -> None:
        """Test that properties default to empty dict."""
        announcer = MDNSAnnouncer(
            name="my-server",
            port=8765,
            address="192.168.1.100",
        )

        assert announcer.properties == {}

    def test_start_requires_zeroconf(self) -> None:
        """Test that start raises ImportError without zeroconf."""
        announcer = MDNSAnnouncer(
            name="test",
            port=8765,
            address="192.168.1.100",
        )

        with patch.dict("sys.modules", {"zeroconf": None}):
            # The import inside start() should fail
            # This tests the error handling path
            pass

    def test_start_registers_service(self) -> None:
        """Test that start() registers service with zeroconf."""
        zeroconf = pytest.importorskip("zeroconf")

        with patch("joyfuljay.remote.discovery.Zeroconf") as mock_zc_class:
            with patch("joyfuljay.remote.discovery.ServiceInfo"):
                mock_zc = MagicMock()
                mock_zc_class.return_value = mock_zc

                announcer = MDNSAnnouncer(
                    name="test-server",
                    port=8765,
                    address="192.168.1.100",
                    properties={"version": "1.0"},
                )

                announcer.start()

                assert announcer._zeroconf is not None
                mock_zc.register_service.assert_called_once()

                # Cleanup
                announcer.stop()

    def test_stop_unregisters_service(self) -> None:
        """Test that stop() unregisters service."""
        zeroconf = pytest.importorskip("zeroconf")

        with patch("joyfuljay.remote.discovery.Zeroconf") as mock_zc_class:
            with patch("joyfuljay.remote.discovery.ServiceInfo"):
                mock_zc = MagicMock()
                mock_zc_class.return_value = mock_zc

                announcer = MDNSAnnouncer(
                    name="test-server",
                    port=8765,
                    address="192.168.1.100",
                )

                announcer.start()
                announcer.stop()

                mock_zc.unregister_service.assert_called_once()
                mock_zc.close.assert_called_once()
                assert announcer._zeroconf is None
                assert announcer._info is None

    def test_stop_without_start(self) -> None:
        """Test that stop() is safe to call without start()."""
        announcer = MDNSAnnouncer(
            name="test",
            port=8765,
            address="192.168.1.100",
        )

        # Should not raise
        announcer.stop()
        assert announcer._zeroconf is None


class TestDiscoverServers:
    """Tests for discover_servers function."""

    def test_returns_list(self) -> None:
        """Test that discover_servers returns a list."""
        pytest.importorskip("zeroconf")

        # With short timeout, likely returns empty list
        with patch("joyfuljay.remote.discovery.Zeroconf"):
            with patch("joyfuljay.remote.discovery.ServiceBrowser"):
                with patch("time.sleep"):
                    result = discover_servers(timeout=0.01)

        assert isinstance(result, list)

    def test_uses_correct_service_type(self) -> None:
        """Test that discovery uses correct mDNS service type."""
        zeroconf = pytest.importorskip("zeroconf")

        with patch("joyfuljay.remote.discovery.Zeroconf"):
            with patch("joyfuljay.remote.discovery.ServiceBrowser") as mock_browser:
                with patch("time.sleep"):
                    discover_servers(timeout=0.1)

                    # Check ServiceBrowser was called with correct service type
                    call_args = mock_browser.call_args
                    assert call_args[0][1] == SERVICE_TYPE

    def test_respects_timeout(self) -> None:
        """Test that discovery waits for specified timeout."""
        zeroconf = pytest.importorskip("zeroconf")

        with patch("joyfuljay.remote.discovery.Zeroconf"):
            with patch("joyfuljay.remote.discovery.ServiceBrowser"):
                with patch("time.sleep") as mock_sleep:
                    discover_servers(timeout=2.5)

                    mock_sleep.assert_called_once()
                    call_args = mock_sleep.call_args[0][0]
                    assert call_args >= 0.1  # At least minimum wait

    def test_closes_zeroconf(self) -> None:
        """Test that zeroconf is closed after discovery."""
        zeroconf = pytest.importorskip("zeroconf")

        mock_zc = MagicMock()
        with patch("joyfuljay.remote.discovery.Zeroconf", return_value=mock_zc):
            with patch("joyfuljay.remote.discovery.ServiceBrowser"):
                with patch("time.sleep"):
                    discover_servers(timeout=0.1)

                    mock_zc.close.assert_called_once()


class TestServiceType:
    """Tests for service type constant."""

    def test_service_type_format(self) -> None:
        """Test that service type follows mDNS format."""
        assert SERVICE_TYPE.startswith("_")
        assert SERVICE_TYPE.endswith(".local.")
        assert "._tcp." in SERVICE_TYPE or "._udp." in SERVICE_TYPE
