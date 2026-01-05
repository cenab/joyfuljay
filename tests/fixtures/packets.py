"""Mock packet payloads for extractor testing.

This module provides realistic TLS, QUIC, SSH, DNS payloads for unit testing.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

from joyfuljay.core.flow import Flow
from joyfuljay.core.packet import Packet


# =============================================================================
# TLS Test Data
# =============================================================================

def create_tls_client_hello(
    version: int = 0x0303,
    ciphers: list[int] | None = None,
    extensions: list[tuple[int, bytes]] | None = None,
    sni: str = "example.com",
    session_id: bytes = b"",
) -> bytes:
    """Create a TLS ClientHello message.

    Args:
        version: TLS version (0x0303 = TLS 1.2)
        ciphers: List of cipher suite IDs
        extensions: List of (extension_type, extension_data) tuples
        sni: Server Name Indication hostname
        session_id: Session ID bytes

    Returns:
        Complete TLS record with ClientHello
    """
    if ciphers is None:
        ciphers = [0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b]  # TLS 1.3 + ECDHE

    # Build extensions
    ext_bytes = b""

    # SNI extension (type 0)
    if sni:
        sni_bytes = sni.encode("ascii")
        sni_entry = struct.pack("!BH", 0, len(sni_bytes)) + sni_bytes
        sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
        ext_bytes += struct.pack("!HH", 0, len(sni_list)) + sni_list

    # Supported groups extension (type 10)
    groups = [0x001d, 0x0017, 0x0018]  # x25519, secp256r1, secp384r1
    groups_data = struct.pack("!H", len(groups) * 2)
    for g in groups:
        groups_data += struct.pack("!H", g)
    ext_bytes += struct.pack("!HH", 10, len(groups_data)) + groups_data

    # EC point formats extension (type 11)
    ec_formats = bytes([0])  # uncompressed
    ec_data = struct.pack("!B", len(ec_formats)) + ec_formats
    ext_bytes += struct.pack("!HH", 11, len(ec_data)) + ec_data

    # ALPN extension (type 16)
    alpn_proto = b"h2"
    alpn_entry = struct.pack("!B", len(alpn_proto)) + alpn_proto
    alpn_list = struct.pack("!H", len(alpn_entry)) + alpn_entry
    ext_bytes += struct.pack("!HH", 16, len(alpn_list)) + alpn_list

    # Add custom extensions
    if extensions:
        for ext_type, ext_data in extensions:
            ext_bytes += struct.pack("!HH", ext_type, len(ext_data)) + ext_data

    # Build cipher suites
    cipher_bytes = struct.pack("!H", len(ciphers) * 2)
    for c in ciphers:
        cipher_bytes += struct.pack("!H", c)

    # Build ClientHello body
    random = b"\x00" * 32
    session_id_data = struct.pack("!B", len(session_id)) + session_id
    compression = b"\x01\x00"  # null compression
    extensions_len = struct.pack("!H", len(ext_bytes))

    hello_body = (
        struct.pack("!H", version) +
        random +
        session_id_data +
        cipher_bytes +
        compression +
        extensions_len +
        ext_bytes
    )

    # Handshake message header (type=1, length)
    handshake = struct.pack("!B", 1) + struct.pack("!I", len(hello_body))[1:4] + hello_body

    # TLS record header (type=22=handshake, version, length)
    record = struct.pack("!BHH", 22, 0x0301, len(handshake)) + handshake

    return record


def create_tls_server_hello(
    version: int = 0x0303,
    cipher: int = 0x1301,
    extensions: list[tuple[int, bytes]] | None = None,
) -> bytes:
    """Create a TLS ServerHello message."""
    # Build extensions
    ext_bytes = b""
    if extensions:
        for ext_type, ext_data in extensions:
            ext_bytes += struct.pack("!HH", ext_type, len(ext_data)) + ext_data

    # Build ServerHello body
    random = b"\x00" * 32
    session_id = b"\x00" * 32
    session_id_data = struct.pack("!B", len(session_id)) + session_id
    compression = b"\x00"
    extensions_len = struct.pack("!H", len(ext_bytes))

    hello_body = (
        struct.pack("!H", version) +
        random +
        session_id_data +
        struct.pack("!H", cipher) +
        compression +
        extensions_len +
        ext_bytes
    )

    # Handshake message header (type=2, length)
    handshake = struct.pack("!B", 2) + struct.pack("!I", len(hello_body))[1:4] + hello_body

    # TLS record header
    record = struct.pack("!BHH", 22, 0x0301, len(handshake)) + handshake

    return record


def create_tls_certificate(cert_lengths: list[int] | None = None) -> bytes:
    """Create a TLS Certificate message with mock certificates."""
    if cert_lengths is None:
        cert_lengths = [1024, 512]  # Two certificates

    # Build certificate entries
    certs_data = b""
    for cert_len in cert_lengths:
        cert = b"\x00" * cert_len  # Mock certificate data
        certs_data += struct.pack("!I", cert_len)[1:4] + cert

    # Total certificates length
    body = struct.pack("!I", len(certs_data))[1:4] + certs_data

    # Handshake message header (type=11, length)
    handshake = struct.pack("!B", 11) + struct.pack("!I", len(body))[1:4] + body

    # TLS record header
    record = struct.pack("!BHH", 22, 0x0301, len(handshake)) + handshake

    return record


# =============================================================================
# QUIC Test Data
# =============================================================================

def create_quic_initial_packet(
    version: int = 0x00000001,
    dcid: bytes = b"\x01\x02\x03\x04",
    scid: bytes = b"\x05\x06\x07\x08",
) -> bytes:
    """Create a QUIC Initial packet (long header).

    QUIC Long Header format:
    - 1 byte: flags (1 | form | fixed | type | reserved | packet number length)
    - 4 bytes: version
    - 1 byte: DCID length
    - N bytes: DCID
    - 1 byte: SCID length
    - N bytes: SCID
    - Variable: token length + token (for Initial)
    - Variable: length
    - Variable: packet number
    - Payload
    """
    # Initial packet type = 0b00 for Long Header Initial
    # Header form = 1 (long), fixed bit = 1
    flags = 0b11000000  # Long header, Initial type

    header = struct.pack("!B", flags)
    header += struct.pack("!I", version)
    header += struct.pack("!B", len(dcid)) + dcid
    header += struct.pack("!B", len(scid)) + scid
    header += struct.pack("!B", 0)  # Token length = 0

    # Length (varint) and packet number
    payload = b"\x00" * 100  # Mock payload
    pn = b"\x00\x01"  # Packet number
    length = len(pn) + len(payload)

    # Simple varint encoding for length < 16384
    header += struct.pack("!H", length | 0x4000)
    header += pn
    header += payload

    return header


def create_quic_short_header_packet(
    dcid: bytes = b"\x01\x02\x03\x04",
    spin_bit: bool = False,
) -> bytes:
    """Create a QUIC short header packet."""
    # Short header: 0 | spin | reserved | key phase | pn len
    flags = 0b01000000
    if spin_bit:
        flags |= 0b00100000

    header = struct.pack("!B", flags)
    header += dcid
    header += struct.pack("!B", 0)  # Packet number (1 byte)
    header += b"\x00" * 50  # Mock payload

    return header


# =============================================================================
# SSH Test Data
# =============================================================================

def create_ssh_version_exchange(
    version: str = "SSH-2.0-OpenSSH_8.9",
) -> bytes:
    """Create SSH version exchange message."""
    return (version + "\r\n").encode("ascii")


def create_ssh_kex_init(
    kex_algos: list[str] | None = None,
    host_key_algos: list[str] | None = None,
    encryption_algos: list[str] | None = None,
) -> bytes:
    """Create SSH Key Exchange Init message.

    SSH KEX_INIT format:
    - 1 byte: message type (20)
    - 16 bytes: cookie
    - name-list: kex_algorithms
    - name-list: server_host_key_algorithms
    - name-list: encryption_algorithms_client_to_server
    - name-list: encryption_algorithms_server_to_client
    - name-list: mac_algorithms_client_to_server
    - name-list: mac_algorithms_server_to_client
    - name-list: compression_algorithms_client_to_server
    - name-list: compression_algorithms_server_to_client
    - name-list: languages_client_to_server
    - name-list: languages_server_to_client
    - boolean: first_kex_packet_follows
    - uint32: reserved (0)
    """
    if kex_algos is None:
        kex_algos = ["curve25519-sha256", "ecdh-sha2-nistp256"]
    if host_key_algos is None:
        host_key_algos = ["ssh-ed25519", "rsa-sha2-512"]
    if encryption_algos is None:
        encryption_algos = ["aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"]

    def make_name_list(names: list[str]) -> bytes:
        data = ",".join(names).encode("ascii")
        return struct.pack("!I", len(data)) + data

    mac_algos = ["hmac-sha2-256-etm@openssh.com"]
    comp_algos = ["none"]

    body = b"\x00" * 16  # Cookie
    body += make_name_list(kex_algos)
    body += make_name_list(host_key_algos)
    body += make_name_list(encryption_algos)  # Client to server
    body += make_name_list(encryption_algos)  # Server to client
    body += make_name_list(mac_algos)  # Client to server
    body += make_name_list(mac_algos)  # Server to client
    body += make_name_list(comp_algos)  # Client to server
    body += make_name_list(comp_algos)  # Server to client
    body += make_name_list([])  # Languages client to server
    body += make_name_list([])  # Languages server to client
    body += struct.pack("!B", 0)  # first_kex_packet_follows
    body += struct.pack("!I", 0)  # reserved

    # SSH packet format: length (4 bytes) + padding_length (1 byte) + type (1 byte) + payload
    msg_type = 20  # SSH_MSG_KEXINIT
    padding_len = 8 - ((1 + 1 + len(body)) % 8)
    if padding_len < 4:
        padding_len += 8

    packet = struct.pack("!I", 1 + 1 + len(body) + padding_len)
    packet += struct.pack("!B", padding_len)
    packet += struct.pack("!B", msg_type)
    packet += body
    packet += b"\x00" * padding_len

    return packet


# =============================================================================
# DNS Test Data
# =============================================================================

def create_dns_query(
    domain: str = "example.com",
    query_type: int = 1,  # A record
    query_id: int = 0x1234,
) -> bytes:
    """Create a DNS query packet.

    Args:
        domain: Domain name to query
        query_type: DNS query type (1=A, 28=AAAA, etc.)
        query_id: Transaction ID

    Returns:
        DNS query packet bytes
    """
    # DNS header
    header = struct.pack("!H", query_id)  # Transaction ID
    header += struct.pack("!H", 0x0100)  # Flags: standard query
    header += struct.pack("!H", 1)  # Questions
    header += struct.pack("!H", 0)  # Answer RRs
    header += struct.pack("!H", 0)  # Authority RRs
    header += struct.pack("!H", 0)  # Additional RRs

    # Question section
    question = b""
    for label in domain.split("."):
        question += struct.pack("!B", len(label)) + label.encode("ascii")
    question += b"\x00"  # Null terminator
    question += struct.pack("!HH", query_type, 1)  # Type and class (IN)

    return header + question


def create_dns_response(
    domain: str = "example.com",
    answers: list[tuple[int, bytes]] | None = None,
    query_id: int = 0x1234,
    rcode: int = 0,
) -> bytes:
    """Create a DNS response packet.

    Args:
        domain: Domain name
        answers: List of (type, rdata) tuples
        query_id: Transaction ID
        rcode: Response code (0=NOERROR, 2=SERVFAIL, 3=NXDOMAIN)

    Returns:
        DNS response packet bytes
    """
    if answers is None:
        answers = [(1, b"\x5d\xb8\xd8\x22")]  # A record: 93.184.216.34

    # DNS header
    flags = 0x8000 | (rcode & 0x0F)  # Response flag + rcode
    header = struct.pack("!H", query_id)
    header += struct.pack("!H", flags)
    header += struct.pack("!H", 1)  # Questions
    header += struct.pack("!H", len(answers))  # Answer RRs
    header += struct.pack("!H", 0)  # Authority RRs
    header += struct.pack("!H", 0)  # Additional RRs

    # Question section
    question = b""
    for label in domain.split("."):
        question += struct.pack("!B", len(label)) + label.encode("ascii")
    question += b"\x00"
    question += struct.pack("!HH", 1, 1)  # Type A, class IN

    # Answer section
    answer_data = b""
    for rtype, rdata in answers:
        # Name pointer to question
        answer_data += struct.pack("!H", 0xC00C)
        answer_data += struct.pack("!H", rtype)  # Type
        answer_data += struct.pack("!H", 1)  # Class IN
        answer_data += struct.pack("!I", 300)  # TTL
        answer_data += struct.pack("!H", len(rdata))  # RDLENGTH
        answer_data += rdata

    return header + question + answer_data


# =============================================================================
# Flow Builders
# =============================================================================

def create_tls_flow(
    include_certificate: bool = True,
    sni: str = "example.com",
    version: int = 0x0303,
) -> Flow:
    """Create a complete TLS flow with ClientHello, ServerHello, and optionally Certificate."""
    # Client packet with ClientHello
    client_hello = create_tls_client_hello(version=version, sni=sni)
    client_packet = Packet(
        timestamp=1000.0,
        src_ip="192.168.1.100",
        dst_ip="93.184.216.34",
        src_port=54321,
        dst_port=443,
        protocol=6,
        payload_len=len(client_hello),
        total_len=len(client_hello) + 40,
        tcp_flags=0x18,  # PSH+ACK
        raw_payload=client_hello,
    )

    # Server packet with ServerHello
    server_hello = create_tls_server_hello(version=version, cipher=0x1301)
    server_packet = Packet(
        timestamp=1000.05,
        src_ip="93.184.216.34",
        dst_ip="192.168.1.100",
        src_port=443,
        dst_port=54321,
        protocol=6,
        payload_len=len(server_hello),
        total_len=len(server_hello) + 40,
        tcp_flags=0x18,
        raw_payload=server_hello,
    )

    packets = [client_packet, server_packet]

    if include_certificate:
        cert = create_tls_certificate()
        cert_packet = Packet(
            timestamp=1000.06,
            src_ip="93.184.216.34",
            dst_ip="192.168.1.100",
            src_port=443,
            dst_port=54321,
            protocol=6,
            payload_len=len(cert),
            total_len=len(cert) + 40,
            tcp_flags=0x18,
            raw_payload=cert,
        )
        packets.append(cert_packet)

    flow = Flow.from_first_packet(packets[0])
    for pkt in packets[1:]:
        flow.add_packet(pkt)

    return flow


def create_quic_flow() -> Flow:
    """Create a QUIC flow with Initial and short header packets."""
    initial = create_quic_initial_packet()
    initial_packet = Packet(
        timestamp=1000.0,
        src_ip="192.168.1.100",
        dst_ip="93.184.216.34",
        src_port=54321,
        dst_port=443,
        protocol=17,  # UDP
        payload_len=len(initial),
        total_len=len(initial) + 28,
        raw_payload=initial,
    )

    response = create_quic_initial_packet(dcid=b"\x05\x06\x07\x08", scid=b"\x01\x02\x03\x04")
    response_packet = Packet(
        timestamp=1000.05,
        src_ip="93.184.216.34",
        dst_ip="192.168.1.100",
        src_port=443,
        dst_port=54321,
        protocol=17,
        payload_len=len(response),
        total_len=len(response) + 28,
        raw_payload=response,
    )

    short = create_quic_short_header_packet(spin_bit=True)
    short_packet = Packet(
        timestamp=1000.1,
        src_ip="192.168.1.100",
        dst_ip="93.184.216.34",
        src_port=54321,
        dst_port=443,
        protocol=17,
        payload_len=len(short),
        total_len=len(short) + 28,
        raw_payload=short,
    )

    flow = Flow.from_first_packet(initial_packet)
    flow.add_packet(response_packet)
    flow.add_packet(short_packet)

    return flow


def create_ssh_flow() -> Flow:
    """Create an SSH flow with version exchange and KEX_INIT."""
    version = create_ssh_version_exchange()
    version_packet = Packet(
        timestamp=1000.0,
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        src_port=54321,
        dst_port=22,
        protocol=6,
        payload_len=len(version),
        total_len=len(version) + 40,
        tcp_flags=0x18,
        raw_payload=version,
    )

    server_version = create_ssh_version_exchange("SSH-2.0-OpenSSH_9.0")
    server_version_packet = Packet(
        timestamp=1000.01,
        src_ip="10.0.0.1",
        dst_ip="192.168.1.100",
        src_port=22,
        dst_port=54321,
        protocol=6,
        payload_len=len(server_version),
        total_len=len(server_version) + 40,
        tcp_flags=0x18,
        raw_payload=server_version,
    )

    kex_init = create_ssh_kex_init()
    kex_packet = Packet(
        timestamp=1000.02,
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        src_port=54321,
        dst_port=22,
        protocol=6,
        payload_len=len(kex_init),
        total_len=len(kex_init) + 40,
        tcp_flags=0x18,
        raw_payload=kex_init,
    )

    server_kex = create_ssh_kex_init()
    server_kex_packet = Packet(
        timestamp=1000.03,
        src_ip="10.0.0.1",
        dst_ip="192.168.1.100",
        src_port=22,
        dst_port=54321,
        protocol=6,
        payload_len=len(server_kex),
        total_len=len(server_kex) + 40,
        tcp_flags=0x18,
        raw_payload=server_kex,
    )

    flow = Flow.from_first_packet(version_packet)
    flow.add_packet(server_version_packet)
    flow.add_packet(kex_packet)
    flow.add_packet(server_kex_packet)

    return flow


def create_dns_flow(domain: str = "example.com") -> Flow:
    """Create a DNS flow with query and response."""
    query = create_dns_query(domain=domain)
    query_packet = Packet(
        timestamp=1000.0,
        src_ip="192.168.1.100",
        dst_ip="8.8.8.8",
        src_port=54321,
        dst_port=53,
        protocol=17,  # UDP
        payload_len=len(query),
        total_len=len(query) + 28,
        raw_payload=query,
    )

    response = create_dns_response(domain=domain)
    response_packet = Packet(
        timestamp=1000.01,
        src_ip="8.8.8.8",
        dst_ip="192.168.1.100",
        src_port=53,
        dst_port=54321,
        protocol=17,
        payload_len=len(response),
        total_len=len(response) + 28,
        raw_payload=response,
    )

    flow = Flow.from_first_packet(query_packet)
    flow.add_packet(response_packet)

    return flow


def create_entropy_flow(
    payload_type: str = "random",
    size: int = 256,
) -> Flow:
    """Create a flow with specific entropy characteristics.

    Args:
        payload_type: "random", "compressed", "plaintext", "zeros"
        size: Payload size in bytes
    """
    import random

    if payload_type == "random":
        payload = bytes([random.randint(0, 255) for _ in range(size)])
    elif payload_type == "compressed":
        # Simulate compressed data (high entropy but structured)
        payload = bytes([random.randint(0, 255) for _ in range(size)])
    elif payload_type == "plaintext":
        # ASCII text (low entropy)
        text = "Hello World! " * (size // 13 + 1)
        payload = text[:size].encode("ascii")
    elif payload_type == "zeros":
        payload = b"\x00" * size
    else:
        payload = b"\x00" * size

    packet = Packet(
        timestamp=1000.0,
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        src_port=54321,
        dst_port=8080,
        protocol=6,
        payload_len=size,
        total_len=size + 40,
        tcp_flags=0x18,
        raw_payload=payload,
    )

    flow = Flow.from_first_packet(packet)
    return flow


def create_padding_flow(packet_sizes: list[int] | None = None) -> Flow:
    """Create a flow with specific packet size patterns for padding detection."""
    if packet_sizes is None:
        # Tor-like: fixed 586-byte cells
        packet_sizes = [586, 586, 586, 586, 586]

    packets = []
    timestamp = 1000.0

    for i, size in enumerate(packet_sizes):
        is_forward = i % 2 == 0
        packet = Packet(
            timestamp=timestamp,
            src_ip="192.168.1.100" if is_forward else "10.0.0.1",
            dst_ip="10.0.0.1" if is_forward else "192.168.1.100",
            src_port=54321 if is_forward else 9001,
            dst_port=9001 if is_forward else 54321,
            protocol=6,
            payload_len=size,
            total_len=size + 40,
            tcp_flags=0x18,
            raw_payload=b"\x00" * min(size, 100),  # Partial payload
        )
        packets.append(packet)
        timestamp += 0.01

    flow = Flow.from_first_packet(packets[0])
    for pkt in packets[1:]:
        flow.add_packet(pkt)

    return flow


def create_fingerprint_flow(traffic_type: str = "normal") -> Flow:
    """Create flows for fingerprint detection testing.

    Args:
        traffic_type: "normal", "tor", "vpn", "doh"
    """
    if traffic_type == "tor":
        # Tor uses fixed 586-byte cells
        return create_padding_flow([586] * 10)
    elif traffic_type == "vpn":
        # VPN typically uses port 1194 (OpenVPN)
        packet = Packet(
            timestamp=1000.0,
            src_ip="192.168.1.100",
            dst_ip="vpn.server.com",
            src_port=54321,
            dst_port=1194,
            protocol=17,  # UDP
            payload_len=1400,
            total_len=1428,
            tcp_flags=None,
            raw_payload=b"\x00" * 100,
        )
        flow = Flow.from_first_packet(packet)
        return flow
    elif traffic_type == "doh":
        # DNS over HTTPS on port 443
        dns_payload = create_dns_query()
        tls_wrapped = create_tls_client_hello(sni="dns.google")
        packet = Packet(
            timestamp=1000.0,
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=443,
            protocol=6,
            payload_len=len(tls_wrapped),
            total_len=len(tls_wrapped) + 40,
            tcp_flags=0x18,
            raw_payload=tls_wrapped,
        )
        flow = Flow.from_first_packet(packet)
        return flow
    else:
        # Normal HTTPS traffic
        return create_tls_flow()


def create_connection_flows(num_flows: int = 5) -> list[Flow]:
    """Create multiple flows for connection graph testing.

    Creates flows between different IP pairs to test graph analysis.

    Args:
        num_flows: Number of flows to create.

    Returns:
        List of Flow objects.
    """
    flows = []
    timestamp = 1000.0

    # Define some IP pairs for variety
    ip_pairs = [
        ("192.168.1.100", "10.0.0.1", 54321, 80),
        ("192.168.1.100", "10.0.0.2", 54322, 443),
        ("192.168.1.101", "10.0.0.1", 54323, 80),
        ("192.168.1.101", "10.0.0.2", 54324, 443),
        ("192.168.1.100", "10.0.0.1", 54325, 8080),
    ]

    for i in range(num_flows):
        src_ip, dst_ip, src_port, dst_port = ip_pairs[i % len(ip_pairs)]

        packet = Packet(
            timestamp=timestamp + i * 0.1,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port + (i // len(ip_pairs)),
            dst_port=dst_port,
            protocol=6,
            payload_len=100 + i * 10,
            total_len=140 + i * 10,
            tcp_flags=0x18,
            raw_payload=b"\x00" * 100,
        )

        # Add more packets to make more realistic flows
        response_packet = Packet(
            timestamp=timestamp + i * 0.1 + 0.01,
            src_ip=dst_ip,
            dst_ip=src_ip,
            src_port=dst_port,
            dst_port=src_port + (i // len(ip_pairs)),
            protocol=6,
            payload_len=200 + i * 10,
            total_len=240 + i * 10,
            tcp_flags=0x18,
            raw_payload=b"\x00" * 200,
        )

        flow = Flow.from_first_packet(packet)
        flow.add_packet(response_packet)
        flows.append(flow)

    return flows
