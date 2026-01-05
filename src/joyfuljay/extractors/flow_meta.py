"""Flow metadata feature extractor."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Any

from ..utils.port_classifier import get_port_class_name, get_port_class_number
from .base import FeatureExtractor

if TYPE_CHECKING:
    from ..core.flow import Flow


class FlowMetaExtractor(FeatureExtractor):
    """Extracts basic flow metadata features.

    Features include:
    - 5-tuple identifiers (optional)
    - Duration and timing
    - Packet and byte counts (bidirectional and per-direction)
    - Directional ratios
    - Hashed flow ID (optional)
    """

    def __init__(
        self,
        include_ips: bool = True,
        include_ports: bool = True,
        anonymize_ips: bool = False,
        anonymization_salt: str = "",
        include_flow_id: bool = False,
    ) -> None:
        """Initialize the flow metadata extractor.

        Args:
            include_ips: Whether to include IP addresses in features.
            include_ports: Whether to include port numbers in features.
            anonymize_ips: Whether to hash IP addresses for privacy.
            anonymization_salt: Salt for IP hashing (for reproducibility).
            include_flow_id: Whether to include a hashed flow identifier.
        """
        self.include_ips = include_ips
        self.include_ports = include_ports
        self.anonymize_ips = anonymize_ips
        self.anonymization_salt = anonymization_salt
        self.include_flow_id = include_flow_id

    def _anonymize_ip(self, ip: str) -> str:
        """Hash an IP address for anonymization.

        Args:
            ip: The IP address to hash.

        Returns:
            Hashed IP address (hex string).
        """
        data = f"{self.anonymization_salt}{ip}".encode("utf-8")
        return hashlib.sha256(data).hexdigest()[:16]

    def _compute_flow_id(self, flow: Flow) -> str:
        """Compute a unique hashed flow identifier.

        The flow ID is a hash of the normalized 5-tuple, providing
        a unique identifier that can be used for cross-referencing
        without exposing raw IP addresses.

        Args:
            flow: The flow to identify.

        Returns:
            Hashed flow identifier (hex string).
        """
        # Create normalized 5-tuple string
        key = flow.key
        tuple_str = f"{key.ip_a}:{key.port_a}:{key.ip_b}:{key.port_b}:{key.protocol}"
        data = f"{self.anonymization_salt}{tuple_str}".encode("utf-8")
        return hashlib.sha256(data).hexdigest()[:32]

    def extract(self, flow: Flow) -> dict[str, Any]:
        """Extract flow metadata features.

        Args:
            flow: The completed flow.

        Returns:
            Dictionary of flow metadata features.
        """
        features: dict[str, Any] = {}

        # Flow ID (optional)
        if self.include_flow_id:
            features["flow_id"] = self._compute_flow_id(flow)

        # Identifier features (optional)
        if self.include_ips:
            if self.anonymize_ips:
                features["src_ip"] = self._anonymize_ip(flow.initiator_ip)
                features["dst_ip"] = self._anonymize_ip(flow.responder_ip)
            else:
                features["src_ip"] = flow.initiator_ip
                features["dst_ip"] = flow.responder_ip

        if self.include_ports:
            features["src_port"] = flow.initiator_port
            features["dst_port"] = flow.responder_port
            # Port classification - Tranalyzer compatible
            features["dst_port_class"] = get_port_class_name(flow.responder_port)
            features["dst_port_class_num"] = get_port_class_number(flow.responder_port)

        # Protocol
        features["protocol"] = flow.key.protocol

        # Timing features
        features["start_time"] = flow.start_time
        features["end_time"] = flow.last_seen
        features["duration"] = flow.duration

        # Packet counts
        features["total_packets"] = flow.total_packets
        features["packets_fwd"] = len(flow.initiator_packets)
        features["packets_bwd"] = len(flow.responder_packets)

        # Byte counts
        features["total_bytes"] = flow.total_bytes
        features["bytes_fwd"] = flow.initiator_bytes
        features["bytes_bwd"] = flow.responder_bytes

        # Payload bytes (excluding headers)
        features["payload_bytes_fwd"] = sum(
            p.payload_len for p in flow.initiator_packets
        )
        features["payload_bytes_bwd"] = sum(
            p.payload_len for p in flow.responder_packets
        )
        features["payload_bytes_total"] = (
            features["payload_bytes_fwd"] + features["payload_bytes_bwd"]
        )

        # Ratios (avoid division by zero)
        if features["packets_bwd"] > 0:
            features["packets_ratio"] = features["packets_fwd"] / features["packets_bwd"]
        else:
            features["packets_ratio"] = float(features["packets_fwd"]) if features["packets_fwd"] > 0 else 0.0

        if features["bytes_bwd"] > 0:
            features["bytes_ratio"] = features["bytes_fwd"] / features["bytes_bwd"]
        else:
            features["bytes_ratio"] = float(features["bytes_fwd"]) if features["bytes_fwd"] > 0 else 0.0

        # Packets per second
        if flow.duration > 0:
            features["packets_per_second"] = flow.total_packets / flow.duration
            features["bytes_per_second"] = flow.total_bytes / flow.duration
        else:
            features["packets_per_second"] = float(flow.total_packets)
            features["bytes_per_second"] = float(flow.total_bytes)

        # Average packet size
        if flow.total_packets > 0:
            features["avg_packet_size"] = flow.total_bytes / flow.total_packets
        else:
            features["avg_packet_size"] = 0.0

        # Tranalyzer-compatible features (#44)
        # timeFirst/timeLast aliases
        features["time_first"] = flow.start_time
        features["time_last"] = flow.last_seen

        # Flow termination status (flowStat)
        # Bit 0: Has SYN
        # Bit 1: Has SYN-ACK
        # Bit 2: Has FIN from initiator
        # Bit 3: Has FIN from responder
        # Bit 4: Has RST
        # Bit 5: Flow timed out (not established)
        # Bit 6: Proper TCP termination
        flow_stat = self._compute_flow_stat(flow)
        features["flow_stat"] = flow_stat

        # Protocol stack description
        hdr_desc, num_hdrs = self._get_protocol_stack(flow)
        features["num_hdrs"] = num_hdrs
        features["hdr_desc"] = hdr_desc

        return features

    def _compute_flow_stat(self, flow: Flow) -> int:
        """Compute flow termination status bitmap.

        Args:
            flow: The flow to analyze.

        Returns:
            Flow status bitmap.
        """
        stat = 0
        has_syn = False
        has_syn_ack = False
        has_fin_fwd = False
        has_fin_bwd = False
        has_rst = False

        for pkt in flow.packets:
            if pkt.tcp_flags is None:
                continue

            is_forward = (
                pkt.src_ip == flow.initiator_ip and pkt.src_port == flow.initiator_port
            )

            is_syn = bool(pkt.tcp_flags & 0x02)
            is_ack = bool(pkt.tcp_flags & 0x10)
            is_fin = bool(pkt.tcp_flags & 0x01)
            is_rst = bool(pkt.tcp_flags & 0x04)

            if is_syn and not is_ack:
                has_syn = True
            if is_syn and is_ack:
                has_syn_ack = True
            if is_fin:
                if is_forward:
                    has_fin_fwd = True
                else:
                    has_fin_bwd = True
            if is_rst:
                has_rst = True

        if has_syn:
            stat |= 0x01
        if has_syn_ack:
            stat |= 0x02
        if has_fin_fwd:
            stat |= 0x04
        if has_fin_bwd:
            stat |= 0x08
        if has_rst:
            stat |= 0x10

        # Check for proper termination
        if has_syn and has_syn_ack:
            if (has_fin_fwd and has_fin_bwd) or has_rst:
                stat |= 0x40  # Proper termination

        return stat

    def _get_protocol_stack(self, flow: Flow) -> tuple[str, int]:
        """Determine the protocol stack for this flow.

        Args:
            flow: The flow to analyze.

        Returns:
            Tuple of (protocol description, header count).
        """
        protocol = flow.key.protocol
        first_pkt = flow.packets[0] if flow.packets else None

        layers: list[str] = []

        # Layer 2
        if first_pkt and first_pkt.src_mac:
            layers.append("ETH")

        # Layer 3
        if first_pkt and first_pkt.ip_version == 6:
            layers.append("IP6")
        else:
            layers.append("IP")

        # Layer 4
        if protocol == 6:  # TCP
            layers.append("TCP")
        elif protocol == 17:  # UDP
            layers.append("UDP")
        elif protocol == 1:  # ICMP
            layers.append("ICMP")
        else:
            layers.append(f"PROTO{protocol}")

        return "-".join(layers), len(layers)

    @property
    def feature_names(self) -> list[str]:
        """Get feature names produced by this extractor."""
        names = []

        if self.include_flow_id:
            names.append("flow_id")

        if self.include_ips:
            names.extend(["src_ip", "dst_ip"])

        if self.include_ports:
            names.extend(["src_port", "dst_port", "dst_port_class", "dst_port_class_num"])

        names.extend([
            "protocol",
            "start_time",
            "end_time",
            "duration",
            "total_packets",
            "packets_fwd",
            "packets_bwd",
            "total_bytes",
            "bytes_fwd",
            "bytes_bwd",
            "payload_bytes_fwd",
            "payload_bytes_bwd",
            "payload_bytes_total",
            "packets_ratio",
            "bytes_ratio",
            "packets_per_second",
            "bytes_per_second",
            "avg_packet_size",
            # Tranalyzer-compatible features (#44)
            "time_first",
            "time_last",
            "flow_stat",
            "num_hdrs",
            "hdr_desc",
        ])

        return names
