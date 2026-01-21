"""mDNS/Bonjour discovery for JoyfulJay servers."""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import Mock

if TYPE_CHECKING:
    from zeroconf import (
        ServiceBrowser as ServiceBrowserType,
        ServiceInfo as ServiceInfoType,
        ServiceListener as ServiceListenerType,
        Zeroconf as ZeroconfType,
    )
else:
    ServiceBrowserType = ServiceInfoType = ServiceListenerType = ZeroconfType = Any

ServiceBrowser: Any | None = None
ServiceInfo: Any | None = None
ServiceListener: Any | None = None
Zeroconf: Any | None = None


def _get_zeroconf_module() -> Any:
    try:
        import zeroconf as zc
    except ImportError as exc:
        raise ImportError(
            "mDNS discovery requires zeroconf. Install with: pip install zeroconf"
        ) from exc
    return zc


def _resolve_zeroconf_class(name: str) -> Any:
    candidate = globals().get(name)
    if isinstance(candidate, Mock):
        return candidate
    zc = _get_zeroconf_module()
    return getattr(zc, name)

SERVICE_TYPE = "_joyfuljay._tcp.local."


@dataclass(frozen=True)
class DiscoveredServer:
    """Discovered JoyfulJay server entry."""

    name: str
    address: str
    port: int
    properties: dict[str, str]


class MDNSAnnouncer:
    """Advertise JoyfulJay server via mDNS."""

    def __init__(
        self,
        name: str,
        port: int,
        address: str,
        properties: dict[str, str] | None = None,
    ) -> None:
        self.name = name
        self.port = port
        self.address = address
        self.properties = properties or {}
        self._zeroconf: ZeroconfType | None = None
        self._info: ServiceInfoType | None = None

    def start(self) -> None:
        zeroconf_cls = _resolve_zeroconf_class("Zeroconf")
        service_info_cls = _resolve_zeroconf_class("ServiceInfo")

        props = {k: v.encode("utf-8") for k, v in self.properties.items()}
        service_name = f"{self.name}.{SERVICE_TYPE}"
        self._zeroconf = zeroconf_cls()
        self._info = service_info_cls(
            SERVICE_TYPE,
            service_name,
            addresses=[socket.inet_aton(self.address)],
            port=self.port,
            properties=props,
            server=f"{self.name}.local.",
        )
        self._zeroconf.register_service(self._info)

    def stop(self) -> None:
        if self._zeroconf and self._info:
            self._zeroconf.unregister_service(self._info)
            self._zeroconf.close()
        self._zeroconf = None
        self._info = None


def discover_servers(timeout: float = 2.0) -> list[DiscoveredServer]:
    """Discover JoyfulJay servers on the local network.

    Args:
        timeout: Discovery time window in seconds.

    Returns:
        List of discovered servers.
    """
    zeroconf_cls = _resolve_zeroconf_class("Zeroconf")
    service_browser_cls = _resolve_zeroconf_class("ServiceBrowser")

    discovered: dict[str, DiscoveredServer] = {}

    class Listener:
        def add_service(self, zc: ZeroconfType, service_type: str, name: str) -> None:
            info = zc.get_service_info(service_type, name)
            if not info or not info.addresses:
                return
            if info.port is None:
                return

            address = socket.inet_ntoa(info.addresses[0])
            properties: dict[str, str] = {}
            for key, value in info.properties.items():
                if value is None:
                    continue
                key_str = key.decode("utf-8", errors="replace")
                if isinstance(value, bytes):
                    value_str = value.decode("utf-8", errors="replace")
                else:
                    value_str = str(value)
                properties[key_str] = value_str
            discovered[name] = DiscoveredServer(
                name=name,
                address=address,
                port=info.port,
                properties=properties,
            )

        def update_service(self, zc: ZeroconfType, service_type: str, name: str) -> None:
            self.add_service(zc, service_type, name)

        def remove_service(self, zc: ZeroconfType, service_type: str, name: str) -> None:
            discovered.pop(name, None)

    zeroconf = zeroconf_cls()
    listener = Listener()
    service_browser_cls(zeroconf, SERVICE_TYPE, cast(ServiceListenerType, listener))

    time.sleep(max(0.1, timeout))
    zeroconf.close()

    return list(discovered.values())
