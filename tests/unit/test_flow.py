"""Tests for Flow data structures."""

from __future__ import annotations

import pytest

from joyfuljay.core.flow import Flow, FlowKey, FlowTable
from joyfuljay.core.packet import Packet


class TestFlowKey:
    """Tests for FlowKey."""

    def test_flow_key_from_packet(self, sample_packet: Packet) -> None:
        """Test FlowKey creation from packet."""
        key = FlowKey.from_packet(sample_packet)
        assert key.protocol == 6

    def test_flow_key_bidirectional(
        self,
        sample_packet: Packet,
        sample_packet_reverse: Packet,
    ) -> None:
        """Test that forward and reverse packets produce same key."""
        key1 = FlowKey.from_packet(sample_packet)
        key2 = FlowKey.from_packet(sample_packet_reverse)
        assert key1 == key2

    def test_flow_key_to_tuple(self, sample_packet: Packet) -> None:
        """Test conversion to tuple for hashing."""
        key = FlowKey.from_packet(sample_packet)
        key_tuple = key.to_tuple()
        assert isinstance(key_tuple, tuple)
        assert len(key_tuple) == 5


class TestFlow:
    """Tests for Flow."""

    def test_flow_from_first_packet(self, sample_packet: Packet) -> None:
        """Test flow creation from first packet."""
        flow = Flow.from_first_packet(sample_packet)
        assert flow.initiator_ip == sample_packet.src_ip
        assert flow.initiator_port == sample_packet.src_port
        assert flow.start_time == sample_packet.timestamp
        assert len(flow.packets) == 1
        assert len(flow.initiator_packets) == 1
        assert len(flow.responder_packets) == 0

    def test_flow_add_packet(
        self,
        sample_packet: Packet,
        sample_packet_reverse: Packet,
    ) -> None:
        """Test adding packets to flow."""
        flow = Flow.from_first_packet(sample_packet)
        flow.add_packet(sample_packet_reverse)

        assert len(flow.packets) == 2
        assert len(flow.initiator_packets) == 1
        assert len(flow.responder_packets) == 1
        assert flow.last_seen == sample_packet_reverse.timestamp

    def test_flow_duration(self, sample_flow: Flow) -> None:
        """Test flow duration calculation."""
        duration = sample_flow.duration
        assert duration > 0
        assert duration == sample_flow.last_seen - sample_flow.start_time

    def test_flow_byte_counts(self, sample_flow: Flow) -> None:
        """Test byte count calculations."""
        assert sample_flow.total_bytes > 0
        assert sample_flow.initiator_bytes > 0
        assert sample_flow.responder_bytes > 0
        assert (
            sample_flow.total_bytes
            == sample_flow.initiator_bytes + sample_flow.responder_bytes
        )

    def test_flow_terminated_on_fin(self, sample_flow: Flow) -> None:
        """Test that flow is marked terminated after FIN."""
        assert sample_flow.terminated is True

    def test_flow_responder_ip(self, sample_flow: Flow) -> None:
        """Test responder IP extraction."""
        assert sample_flow.responder_ip == "10.0.0.1"
        assert sample_flow.responder_port == 443


class TestFlowTable:
    """Tests for FlowTable."""

    def test_flow_table_creation(self, flow_table: FlowTable) -> None:
        """Test flow table creation."""
        assert flow_table.timeout == 60.0
        assert flow_table.active_flow_count == 0

    def test_add_packet_creates_flow(
        self,
        flow_table: FlowTable,
        sample_packet: Packet,
    ) -> None:
        """Test that adding a packet creates a new flow."""
        result = flow_table.add_packet(sample_packet)
        assert result is None  # Flow not yet complete
        assert flow_table.active_flow_count == 1

    def test_add_packet_returns_completed_flow(
        self,
        flow_table: FlowTable,
        sample_packets: list[Packet],
    ) -> None:
        """Test that adding FIN packet returns completed flow."""
        for i, packet in enumerate(sample_packets):
            result = flow_table.add_packet(packet)
            if i < len(sample_packets) - 1:
                assert result is None
            else:
                # Last packet is FIN, should return flow
                assert result is not None
                assert result.terminated is True

        assert flow_table.active_flow_count == 0

    def test_expire_flows(
        self,
        flow_table: FlowTable,
        sample_packet: Packet,
    ) -> None:
        """Test flow expiration."""
        flow_table.add_packet(sample_packet)
        assert flow_table.active_flow_count == 1

        # Expire with future timestamp
        expired = flow_table.expire_flows(sample_packet.timestamp + 120)
        assert len(expired) == 1
        assert flow_table.active_flow_count == 0

    def test_flush_all(
        self,
        flow_table: FlowTable,
        sample_packets: list[Packet],
    ) -> None:
        """Test flushing all flows."""
        # Add packets but not the FIN
        for packet in sample_packets[:-1]:
            flow_table.add_packet(packet)

        assert flow_table.active_flow_count == 1

        flushed = flow_table.flush_all()
        assert len(flushed) == 1
        assert flow_table.active_flow_count == 0


class TestFlowTableEviction:
    """Tests for FlowTable eviction functionality."""

    def test_lru_eviction(self) -> None:
        """Test LRU eviction when max flows is reached."""
        table = FlowTable(timeout=60.0, max_flows=2, eviction_strategy="lru")

        # Create 3 different flows
        pkt1 = Packet(
            timestamp=1.0,
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=1111,
            dst_port=443,
            protocol=6,
            payload_len=100,
            total_len=140,
        )
        pkt2 = Packet(
            timestamp=2.0,
            src_ip="192.168.1.2",
            dst_ip="10.0.0.2",
            src_port=2222,
            dst_port=443,
            protocol=6,
            payload_len=100,
            total_len=140,
        )
        pkt3 = Packet(
            timestamp=3.0,
            src_ip="192.168.1.3",
            dst_ip="10.0.0.3",
            src_port=3333,
            dst_port=443,
            protocol=6,
            payload_len=100,
            total_len=140,
        )

        # Add first two flows
        result1 = table.add_packet(pkt1)
        result2 = table.add_packet(pkt2)
        assert result1 is None
        assert result2 is None
        assert table.active_flow_count == 2

        # Add third flow - should evict first flow (LRU)
        result3 = table.add_packet(pkt3)
        assert result3 is not None  # Evicted flow returned
        assert isinstance(result3, list)
        assert len(result3) == 1
        assert table.active_flow_count == 2
        assert table.evicted_count == 1

    def test_oldest_eviction(self) -> None:
        """Test oldest eviction strategy."""
        table = FlowTable(timeout=60.0, max_flows=2, eviction_strategy="oldest")

        # Create flows with different start times
        pkt1 = Packet(
            timestamp=10.0,  # Older
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=1111,
            dst_port=443,
            protocol=6,
            payload_len=100,
            total_len=140,
        )
        pkt2 = Packet(
            timestamp=20.0,  # Newer
            src_ip="192.168.1.2",
            dst_ip="10.0.0.2",
            src_port=2222,
            dst_port=443,
            protocol=6,
            payload_len=100,
            total_len=140,
        )
        pkt3 = Packet(
            timestamp=30.0,  # Newest
            src_ip="192.168.1.3",
            dst_ip="10.0.0.3",
            src_port=3333,
            dst_port=443,
            protocol=6,
            payload_len=100,
            total_len=140,
        )

        table.add_packet(pkt1)
        table.add_packet(pkt2)

        # Add third - should evict oldest (pkt1's flow)
        result = table.add_packet(pkt3)
        assert result is not None
        assert isinstance(result, list)
        evicted_flow = result[0]
        assert evicted_flow.start_time == 10.0  # The oldest flow

    def test_lru_updates_on_access(self) -> None:
        """Test that LRU order updates when flow is accessed."""
        table = FlowTable(timeout=60.0, max_flows=2, eviction_strategy="lru")

        pkt1 = Packet(
            timestamp=1.0,
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=1111,
            dst_port=443,
            protocol=6,
            payload_len=100,
            total_len=140,
        )
        pkt1_update = Packet(
            timestamp=2.5,
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=1111,
            dst_port=443,
            protocol=6,
            payload_len=100,
            total_len=140,
        )
        pkt2 = Packet(
            timestamp=2.0,
            src_ip="192.168.1.2",
            dst_ip="10.0.0.2",
            src_port=2222,
            dst_port=443,
            protocol=6,
            payload_len=100,
            total_len=140,
        )
        pkt3 = Packet(
            timestamp=3.0,
            src_ip="192.168.1.3",
            dst_ip="10.0.0.3",
            src_port=3333,
            dst_port=443,
            protocol=6,
            payload_len=100,
            total_len=140,
        )

        # Add first two flows
        table.add_packet(pkt1)  # Flow 1 added
        table.add_packet(pkt2)  # Flow 2 added

        # Update flow 1 (makes it recently used)
        table.add_packet(pkt1_update)

        # Add third flow - should evict flow 2 (now LRU)
        result = table.add_packet(pkt3)
        assert result is not None
        evicted_flow = result[0]
        # Flow 2 should be evicted, not flow 1
        assert evicted_flow.initiator_ip == "192.168.1.2"

    def test_no_eviction_when_unlimited(self) -> None:
        """Test that no eviction occurs when max_flows is 0."""
        table = FlowTable(timeout=60.0, max_flows=0)

        # Add many flows
        for i in range(100):
            pkt = Packet(
                timestamp=float(i),
                src_ip=f"192.168.1.{i}",
                dst_ip="10.0.0.1",
                src_port=1000 + i,
                dst_port=443,
                protocol=6,
                payload_len=100,
                total_len=140,
            )
            result = table.add_packet(pkt)
            assert result is None

        assert table.active_flow_count == 100
        assert table.evicted_count == 0
