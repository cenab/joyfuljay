"""mDNS/Bonjour discovery for JoyfulJay servers."""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass

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
        self._zeroconf = None
        self._info = None

    def start(self) -> None:
        try:
            from zeroconf import ServiceInfo, Zeroconf
        except ImportError as exc:
            raise ImportError(
                "mDNS discovery requires zeroconf. Install with: pip install zeroconf"
            ) from exc

        props = {k: v.encode("utf-8") for k, v in self.properties.items()}
        service_name = f"{self.name}.{SERVICE_TYPE}"
        self._zeroconf = Zeroconf()
        self._info = ServiceInfo(
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
    try:
        from zeroconf import ServiceBrowser, ServiceListener, Zeroconf
    except ImportError as exc:
        raise ImportError(
            "mDNS discovery requires zeroconf. Install with: pip install zeroconf"
        ) from exc

    discovered: dict[str, DiscoveredServer] = {}

    class Listener(ServiceListener):
        def add_service(self, zc: Zeroconf, service_type: str, name: str) -> None:
            info = zc.get_service_info(service_type, name)
            if not info or not info.addresses:
                return

            address = socket.inet_ntoa(info.addresses[0])
            properties = {
                key.decode("utf-8"): value.decode("utf-8")
                for key, value in info.properties.items()
            }
            discovered[name] = DiscoveredServer(
                name=name,
                address=address,
                port=info.port,
                properties=properties,
            )

        def update_service(self, zc: Zeroconf, service_type: str, name: str) -> None:
            self.add_service(zc, service_type, name)

        def remove_service(self, zc: Zeroconf, service_type: str, name: str) -> None:
            discovered.pop(name, None)

    zeroconf = Zeroconf()
    ServiceBrowser(zeroconf, SERVICE_TYPE, Listener())

    time.sleep(max(0.1, timeout))
    zeroconf.close()

    return list(discovered.values())
