"""Fuzz tests for protocol extractors."""

from __future__ import annotations

import pytest
from hypothesis import given, settings, strategies as st

from joyfuljay.core.flow import Flow
from joyfuljay.core.packet import Packet
from joyfuljay.extractors.dns import DNSExtractor
from joyfuljay.extractors.quic import QUICExtractor
from joyfuljay.extractors.ssh import SSHExtractor
from joyfuljay.extractors.tls import TLSExtractor


def _build_flow(payloads: list[bytes], protocol: int) -> Flow:
    first_payload = payloads[0]
    first_packet = Packet(
        timestamp=1.0,
        src_ip="192.168.0.1",
        dst_ip="192.168.0.2",
        src_port=12345,
        dst_port=443,
        protocol=protocol,
        payload_len=len(first_payload),
        total_len=len(first_payload) + 40,
        raw_payload=first_payload,
    )
    flow = Flow.from_first_packet(first_packet)

    for idx, payload in enumerate(payloads[1:], start=1):
        packet = Packet(
            timestamp=1.0 + idx * 0.01,
            src_ip="192.168.0.2" if idx % 2 else "192.168.0.1",
            dst_ip="192.168.0.1" if idx % 2 else "192.168.0.2",
            src_port=443,
            dst_port=12345,
            protocol=protocol,
            payload_len=len(payload),
            total_len=len(payload) + 40,
            raw_payload=payload,
        )
        flow.add_packet(packet)

    return flow


@pytest.mark.slow
@given(
    st.lists(st.binary(min_size=0, max_size=512), min_size=1, max_size=5),
    st.sampled_from([Packet.PROTO_TCP, Packet.PROTO_UDP]),
)
@settings(max_examples=50)
def test_protocol_extractors_fuzz(payloads: list[bytes], protocol: int) -> None:
    flow = _build_flow(payloads, protocol)
    extractors = [TLSExtractor(), SSHExtractor(), QUICExtractor(), DNSExtractor()]

    for extractor in extractors:
        features = extractor.extract(flow)
        assert isinstance(features, dict)
