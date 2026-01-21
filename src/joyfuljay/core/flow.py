"""Flow data structures and flow table management."""

from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from .packet import Packet

EvictionStrategy = Literal["lru", "oldest"]


@dataclass(slots=True, frozen=True)
class FlowKey:
    """Bidirectional flow identifier based on 5-tuple.

    The flow key is normalized so that packets in either direction
    of a conversation share the same key.

    Attributes:
        ip_a: First IP address (lexicographically smaller or initiator).
        port_a: Port associated with ip_a.
        ip_b: Second IP address.
        port_b: Port associated with ip_b.
        protocol: IP protocol number (6=TCP, 17=UDP).
    """

    ip_a: str
    port_a: int
    ip_b: str
    port_b: int
    protocol: int

    @classmethod
    def from_packet(cls, packet: Packet) -> FlowKey:
        """Create a FlowKey from a packet, normalizing direction.

        The key is normalized by sorting the (IP, port) pairs to ensure
        packets in either direction produce the same key.

        Args:
            packet: The packet to create a key from.

        Returns:
            A normalized FlowKey.
        """
        # Normalize by sorting (ip, port) pairs
        endpoint_a = (packet.src_ip, packet.src_port)
        endpoint_b = (packet.dst_ip, packet.dst_port)

        if endpoint_a <= endpoint_b:
            return cls(
                ip_a=packet.src_ip,
                port_a=packet.src_port,
                ip_b=packet.dst_ip,
                port_b=packet.dst_port,
                protocol=packet.protocol,
            )
        else:
            return cls(
                ip_a=packet.dst_ip,
                port_a=packet.dst_port,
                ip_b=packet.src_ip,
                port_b=packet.src_port,
                protocol=packet.protocol,
            )

    def to_tuple(self) -> tuple[str, int, str, int, int]:
        """Convert to a tuple for hashing or comparison."""
        return (self.ip_a, self.port_a, self.ip_b, self.port_b, self.protocol)


@dataclass
class Flow:
    """Represents a bidirectional network flow (conversation).

    A flow aggregates all packets between two endpoints and tracks
    directional information for feature extraction.

    Attributes:
        key: The bidirectional flow key.
        start_time: Timestamp of the first packet.
        last_seen: Timestamp of the most recent packet.
        initiator_ip: IP of the connection initiator (first packet sender).
        initiator_port: Port of the connection initiator.
        packets: All packets in this flow (both directions).
        initiator_packets: Packets from initiator to responder.
        responder_packets: Packets from responder to initiator.
        tls_client_hello: Raw bytes of TLS ClientHello if captured.
        tls_server_hello: Raw bytes of TLS ServerHello if captured.
        terminated: Whether flow is terminated (FIN/RST or timeout).
    """

    key: FlowKey
    start_time: float
    last_seen: float
    initiator_ip: str
    initiator_port: int
    packets: list[Packet] = field(default_factory=list)
    initiator_packets: list[Packet] = field(default_factory=list)
    responder_packets: list[Packet] = field(default_factory=list)
    tls_client_hello: bytes | None = None
    tls_server_hello: bytes | None = None
    terminated: bool = False

    @classmethod
    def from_first_packet(cls, packet: Packet) -> Flow:
        """Create a new flow from the first observed packet.

        The sender of the first packet is considered the initiator.

        Args:
            packet: The first packet of the flow.

        Returns:
            A new Flow instance.
        """
        key = FlowKey.from_packet(packet)
        return cls(
            key=key,
            start_time=packet.timestamp,
            last_seen=packet.timestamp,
            initiator_ip=packet.src_ip,
            initiator_port=packet.src_port,
            packets=[packet],
            initiator_packets=[packet],
            responder_packets=[],
        )

    def add_packet(self, packet: Packet) -> None:
        """Add a packet to this flow.

        The packet is added to the appropriate directional list based
        on whether it's from the initiator or responder.

        Args:
            packet: The packet to add.
        """
        self.packets.append(packet)
        self.last_seen = packet.timestamp

        if packet.src_ip == self.initiator_ip and packet.src_port == self.initiator_port:
            self.initiator_packets.append(packet)
        else:
            self.responder_packets.append(packet)

        # Check for connection termination
        if packet.is_fin or packet.is_rst:
            self.terminated = True

    @property
    def duration(self) -> float:
        """Calculate flow duration in seconds."""
        return self.last_seen - self.start_time

    @property
    def total_packets(self) -> int:
        """Total number of packets in the flow."""
        return len(self.packets)

    @property
    def total_bytes(self) -> int:
        """Total bytes transmitted in the flow."""
        return sum(p.total_len for p in self.packets)

    @property
    def initiator_bytes(self) -> int:
        """Bytes sent by the initiator."""
        return sum(p.total_len for p in self.initiator_packets)

    @property
    def responder_bytes(self) -> int:
        """Bytes sent by the responder."""
        return sum(p.total_len for p in self.responder_packets)

    @property
    def responder_ip(self) -> str:
        """IP address of the responder."""
        if self.key.ip_a == self.initiator_ip:
            return self.key.ip_b
        return self.key.ip_a

    @property
    def responder_port(self) -> int:
        """Port number of the responder."""
        if self.key.port_a == self.initiator_port and self.key.ip_a == self.initiator_ip:
            return self.key.port_b
        return self.key.port_a


class FlowTable:
    """Manages active flows with timeout-based expiration and optional LRU eviction.

    The flow table tracks all active network flows and handles:
    - Packet-to-flow assignment
    - Flow creation for new conversations
    - Timeout-based flow expiration
    - Explicit flow termination (FIN/RST)
    - LRU-based eviction when max capacity is reached

    Attributes:
        timeout: Flow inactivity timeout in seconds.
        max_flows: Maximum concurrent flows (0 = unlimited).
        eviction_strategy: Strategy for evicting flows ("lru" or "oldest").
    """

    def __init__(
        self,
        timeout: float = 60.0,
        max_flows: int = 0,
        eviction_strategy: EvictionStrategy = "lru",
        terminate_on_fin_rst: bool = True,
    ) -> None:
        """Initialize the flow table.

        Args:
            timeout: Inactivity timeout in seconds before a flow expires.
            max_flows: Maximum concurrent flows (0 = unlimited).
            eviction_strategy: Strategy for evicting flows when limit reached.
            terminate_on_fin_rst: If True, flows terminate on FIN/RST and new
                flows are created for subsequent packets. If False, flows
                continue after FIN/RST (NFStream-compatible behavior).
        """
        self.timeout = timeout
        self.max_flows = max_flows
        self.eviction_strategy = eviction_strategy
        self.terminate_on_fin_rst = terminate_on_fin_rst
        self._flows: OrderedDict[tuple[str, int, str, int, int], Flow] = OrderedDict()
        self._last_cleanup: float = 0.0
        self._evicted_count: int = 0

    def add_packet(self, packet: Packet) -> Flow | list[Flow] | None:
        """Add a packet to the appropriate flow.

        If the flow is new, it will be created. If adding the packet
        causes the flow to terminate, the completed flow is returned.
        If the max flow limit is reached, evicted flows are also returned.

        Args:
            packet: The packet to add.

        Returns:
            - None if nothing to report
            - A single Flow if it terminated normally
            - A list of Flows if eviction occurred (evicted flows + optionally terminated flow)
        """
        key = FlowKey.from_packet(packet)
        key_tuple = key.to_tuple()
        evicted_flows: list[Flow] = []

        if key_tuple in self._flows:
            flow = self._flows[key_tuple]
            flow.add_packet(packet)

            # LRU: move to end on access
            if self.eviction_strategy == "lru":
                self._flows.move_to_end(key_tuple)

            # Only terminate flow on FIN/RST if configured to do so
            if flow.terminated and self.terminate_on_fin_rst:
                del self._flows[key_tuple]
                return flow
            elif flow.terminated:
                # Reset terminated flag if we're not terminating on FIN/RST
                flow.terminated = False
        else:
            # Check if we need to evict before adding
            if self.max_flows > 0 and len(self._flows) >= self.max_flows:
                evicted_flows = self._evict_flows()

            flow = Flow.from_first_packet(packet)
            self._flows[key_tuple] = flow

        if evicted_flows:
            return evicted_flows
        return None

    def _evict_flows(self, count: int = 1) -> list[Flow]:
        """Evict flows to make room for new ones.

        Args:
            count: Number of flows to evict.

        Returns:
            List of evicted flows.
        """
        evicted: list[Flow] = []

        for _ in range(count):
            if not self._flows:
                break

            if self.eviction_strategy == "lru":
                # LRU: evict from front (least recently used)
                key_tuple, flow = self._flows.popitem(last=False)
            else:
                # Oldest: evict the flow with earliest start_time
                oldest_key = min(self._flows.keys(), key=lambda k: self._flows[k].start_time)
                flow = self._flows.pop(oldest_key)

            evicted.append(flow)
            self._evicted_count += 1

        return evicted

    def expire_flows(self, current_time: float | None = None) -> list[Flow]:
        """Expire flows that have been inactive for longer than timeout.

        Args:
            current_time: Current timestamp. Uses system time if None.

        Returns:
            List of expired flows.
        """
        if current_time is None:
            current_time = time.time()

        expired: list[Flow] = []
        keys_to_remove: list[tuple[str, int, str, int, int]] = []

        for key_tuple, flow in self._flows.items():
            if current_time - flow.last_seen > self.timeout:
                expired.append(flow)
                keys_to_remove.append(key_tuple)

        for key_tuple in keys_to_remove:
            del self._flows[key_tuple]

        return expired

    def flush_all(self) -> list[Flow]:
        """Flush all active flows regardless of timeout.

        This should be called at the end of processing to get
        any remaining incomplete flows.

        Returns:
            List of all remaining flows.
        """
        flows = list(self._flows.values())
        self._flows.clear()
        return flows

    def get_all_flows(self) -> list[Flow]:
        """Return a snapshot of all active flows without modifying state."""
        return list(self._flows.values())

    @property
    def active_flow_count(self) -> int:
        """Number of currently active flows."""
        return len(self._flows)

    @property
    def evicted_count(self) -> int:
        """Number of flows that have been evicted due to capacity limits."""
        return self._evicted_count

    def get_flow(self, key: FlowKey) -> Flow | None:
        """Get a specific flow by key.

        Args:
            key: The flow key to look up.

        Returns:
            The Flow if found, None otherwise.
        """
        return self._flows.get(key.to_tuple())
