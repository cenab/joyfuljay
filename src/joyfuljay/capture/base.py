"""Abstract base class for capture backends."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Iterator

if TYPE_CHECKING:
    from ..core.packet import Packet


class CaptureBackend(ABC):
    """Abstract interface for packet capture backends.

    Implementations of this class provide the ability to read packets
    from PCAP files or capture them from live network interfaces.
    All backends must yield Packet objects in a streaming fashion
    to avoid loading entire captures into memory.
    """

    @abstractmethod
    def iter_packets_offline(self, path: str) -> Iterator[Packet]:
        """Stream packets from a PCAP file.

        This method must not load the entire file into memory.
        Packets should be yielded one at a time as they are read.

        Args:
            path: Path to the PCAP or PCAPNG file.

        Yields:
            Packet objects parsed from the file.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the file format is not supported.
        """

    @abstractmethod
    def iter_packets_live(
        self,
        interface: str,
        bpf_filter: str | None = None,
        packet_count: int | None = None,
        save_pcap: str | None = None,
        pid: int | None = None,
    ) -> Iterator[Packet]:
        """Capture packets from a live network interface.

        This method captures packets in real-time and yields them
        as they are received. It runs until stopped or the optional
        packet count is reached.

        Args:
            interface: Network interface name (e.g., "eth0", "en0").
            bpf_filter: Optional BPF filter expression.
            packet_count: Optional maximum number of packets to capture.
            save_pcap: Optional path to save captured packets to a PCAP file.
            pid: Optional process ID to filter traffic by.

        Yields:
            Packet objects captured from the interface.

        Raises:
            PermissionError: If insufficient privileges for capture.
            ValueError: If the interface does not exist.
        """

    @abstractmethod
    def stop(self) -> None:
        """Stop any active live capture.

        This method should safely terminate live packet capture.
        It is safe to call even if no capture is active.
        """

    def supports_live_capture(self) -> bool:
        """Check if this backend supports live capture.

        Returns:
            True if live capture is supported, False otherwise.
        """
        return True

    def supports_pcapng(self) -> bool:
        """Check if this backend supports PCAPNG format.

        Returns:
            True if PCAPNG is supported, False otherwise.
        """
        return True
