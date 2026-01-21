"""TCP protocol metadata feature extractor."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .base import FeatureExtractor

if TYPE_CHECKING:
    from ..core.flow import Flow
    from ..core.packet import Packet
    from ..schema.registry import FeatureMeta

# TCP flag constants
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
TCP_ECE = 0x40
TCP_CWR = 0x80


class TCPExtractor(FeatureExtractor):
    """Extracts TCP protocol metadata features.

    Analyzes TCP-specific characteristics:
    - Flag distribution and anomalies
    - Connection state indicators
    - Handshake patterns
    - Push/urgency indicators
    """

    def extract(self, flow: Flow) -> dict[str, Any]:
        """Extract TCP metadata features from a flow.

        Args:
            flow: The completed flow.

        Returns:
            Dictionary of TCP features.
        """
        features: dict[str, Any] = {
            "tcp_is_tcp": False,
            "tcp_syn_count": 0,
            "tcp_synack_count": 0,
            "tcp_fin_count": 0,
            "tcp_rst_count": 0,
            "tcp_ack_count": 0,
            "tcp_psh_count": 0,
            "tcp_urg_count": 0,
            "tcp_ece_count": 0,
            "tcp_cwr_count": 0,
            "tcp_complete_handshake": False,
            "tcp_graceful_close": False,
            "tcp_reset_close": False,
            "tcp_syn_ratio": 0.0,
            "tcp_fin_ratio": 0.0,
            "tcp_rst_ratio": 0.0,
            "tcp_psh_ratio": 0.0,
            "tcp_data_packets": 0,
            "tcp_ack_only_packets": 0,
            "tcp_flags_anomaly": False,
            "tcp_initiator_syn": False,
            "tcp_responder_synack": False,
            # Tranalyzer-compatible features (#53)
            "tcp_fstat": 0,
            "tcp_flags_agg": 0,
            "tcp_flags_fwd": 0,
            "tcp_flags_bwd": 0,
        }

        # Only process TCP flows
        if flow.key.protocol != 6:  # Not TCP
            return features

        features["tcp_is_tcp"] = True

        # Track flag counts
        syn_count = 0
        synack_count = 0
        fin_count = 0
        rst_count = 0
        ack_count = 0
        psh_count = 0
        urg_count = 0
        ece_count = 0
        cwr_count = 0
        data_packets = 0
        ack_only_packets = 0

        # Track handshake
        initiator_syn = False
        responder_synack = False
        initiator_fin = False
        responder_fin = False

        for packet in flow.packets:
            if packet.tcp_flags is None:
                continue

            flags = packet.tcp_flags

            # Count individual flags
            if flags & TCP_SYN:
                if flags & TCP_ACK:
                    synack_count += 1
                    # Check if this is the responder's SYN-ACK
                    if self._is_responder_packet(packet, flow):
                        responder_synack = True
                else:
                    syn_count += 1
                    # Check if this is the initiator's SYN
                    if self._is_initiator_packet(packet, flow):
                        initiator_syn = True

            if flags & TCP_FIN:
                fin_count += 1
                if self._is_initiator_packet(packet, flow):
                    initiator_fin = True
                else:
                    responder_fin = True

            if flags & TCP_RST:
                rst_count += 1

            if flags & TCP_ACK:
                ack_count += 1
                # ACK-only packet (no data, no SYN/FIN/RST)
                if packet.payload_len == 0 and not (flags & (TCP_SYN | TCP_FIN | TCP_RST)):
                    ack_only_packets += 1

            if flags & TCP_PSH:
                psh_count += 1

            if flags & TCP_URG:
                urg_count += 1

            if flags & TCP_ECE:
                ece_count += 1

            if flags & TCP_CWR:
                cwr_count += 1

            # Data packet (has payload)
            if packet.payload_len > 0:
                data_packets += 1

        # Store counts
        features["tcp_syn_count"] = syn_count
        features["tcp_synack_count"] = synack_count
        features["tcp_fin_count"] = fin_count
        features["tcp_rst_count"] = rst_count
        features["tcp_ack_count"] = ack_count
        features["tcp_psh_count"] = psh_count
        features["tcp_urg_count"] = urg_count
        features["tcp_ece_count"] = ece_count
        features["tcp_cwr_count"] = cwr_count
        features["tcp_data_packets"] = data_packets
        features["tcp_ack_only_packets"] = ack_only_packets

        # Calculate ratios
        total = len(flow.packets)
        if total > 0:
            features["tcp_syn_ratio"] = (syn_count + synack_count) / total
            features["tcp_fin_ratio"] = fin_count / total
            features["tcp_rst_ratio"] = rst_count / total
            features["tcp_psh_ratio"] = psh_count / total

        # Handshake detection
        features["tcp_initiator_syn"] = initiator_syn
        features["tcp_responder_synack"] = responder_synack
        features["tcp_complete_handshake"] = initiator_syn and responder_synack

        # Connection close detection
        features["tcp_graceful_close"] = initiator_fin and responder_fin
        features["tcp_reset_close"] = rst_count > 0

        # Detect flag anomalies
        # - SYN flood: many SYNs without SYN-ACKs
        # - Xmas tree: FIN+PSH+URG set
        # - Null scan: no flags
        features["tcp_flags_anomaly"] = self._detect_anomalies(flow)

        # Tranalyzer-compatible features (#53)
        # tcpFStat: TCP flow status bitmap
        # Bit 0: SYN seen from A (initiator)
        # Bit 1: SYN-ACK seen from B (responder)
        # Bit 2: ACK seen (handshake complete)
        # Bit 3: FIN seen from A
        # Bit 4: FIN seen from B
        # Bit 5: RST seen
        # Bit 6: Data transferred
        # Bit 7: State anomaly detected
        tcp_fstat = 0
        if initiator_syn:
            tcp_fstat |= 0x01
        if responder_synack:
            tcp_fstat |= 0x02
        if ack_count > synack_count:  # ACKs beyond handshake
            tcp_fstat |= 0x04
        if initiator_fin:
            tcp_fstat |= 0x08
        if responder_fin:
            tcp_fstat |= 0x10
        if rst_count > 0:
            tcp_fstat |= 0x20
        if data_packets > 0:
            tcp_fstat |= 0x40
        if features["tcp_flags_anomaly"]:
            tcp_fstat |= 0x80
        features["tcp_fstat"] = tcp_fstat

        # tcpFlags: Aggregate flag bitmap (OR of all flags seen)
        aggregate_flags = 0
        for packet in flow.packets:
            if packet.tcp_flags is not None:
                aggregate_flags |= packet.tcp_flags
        features["tcp_flags_agg"] = aggregate_flags

        # Per-direction flag aggregates
        fwd_flags = 0
        bwd_flags = 0
        for packet in flow.packets:
            if packet.tcp_flags is not None:
                if self._is_initiator_packet(packet, flow):
                    fwd_flags |= packet.tcp_flags
                else:
                    bwd_flags |= packet.tcp_flags
        features["tcp_flags_fwd"] = fwd_flags
        features["tcp_flags_bwd"] = bwd_flags

        return features

    def _is_initiator_packet(self, packet: Packet, flow: Flow) -> bool:
        """Check if packet is from the flow initiator."""
        return (
            packet.src_ip == flow.initiator_ip
            and packet.src_port == flow.initiator_port
        )

    def _is_responder_packet(self, packet: Packet, flow: Flow) -> bool:
        """Check if packet is from the flow responder."""
        return (
            packet.src_ip == flow.responder_ip
            and packet.src_port == flow.responder_port
        )

    def _detect_anomalies(self, flow: Flow) -> bool:
        """Detect TCP flag anomalies that might indicate scanning or attacks."""
        for packet in flow.packets:
            if packet.tcp_flags is None:
                continue

            flags = packet.tcp_flags

            # Null scan: no flags set
            if flags == 0:
                return True

            # Xmas tree scan: FIN+PSH+URG
            if (flags & (TCP_FIN | TCP_PSH | TCP_URG)) == (TCP_FIN | TCP_PSH | TCP_URG):
                return True

            # FIN without ACK (unusual)
            if (flags & TCP_FIN) and not (flags & TCP_ACK) and not (flags & TCP_SYN):
                return True

            # SYN+FIN (malformed)
            if (flags & TCP_SYN) and (flags & TCP_FIN):
                return True

            # SYN+RST (malformed)
            if (flags & TCP_SYN) and (flags & TCP_RST):
                return True

        return False

    @property
    def feature_names(self) -> list[str]:
        """Get feature names produced by this extractor."""
        return [
            "tcp_is_tcp",
            "tcp_syn_count",
            "tcp_synack_count",
            "tcp_fin_count",
            "tcp_rst_count",
            "tcp_ack_count",
            "tcp_psh_count",
            "tcp_urg_count",
            "tcp_ece_count",
            "tcp_cwr_count",
            "tcp_complete_handshake",
            "tcp_graceful_close",
            "tcp_reset_close",
            "tcp_syn_ratio",
            "tcp_fin_ratio",
            "tcp_rst_ratio",
            "tcp_psh_ratio",
            "tcp_data_packets",
            "tcp_ack_only_packets",
            "tcp_flags_anomaly",
            "tcp_initiator_syn",
            "tcp_responder_synack",
            # Tranalyzer-compatible features (#53)
            "tcp_fstat",
            "tcp_flags_agg",
            "tcp_flags_fwd",
            "tcp_flags_bwd",
        ]

    @property
    def extractor_id(self) -> str:
        """Return the unique identifier for this extractor."""
        return "tcp"

    def feature_meta(self) -> dict[str, FeatureMeta]:
        """Return metadata for all features produced by this extractor.

        Returns:
            Dictionary mapping feature IDs to their FeatureMeta objects.
        """
        from ..schema.registry import FeatureMeta

        return {
            "tcp.is_tcp": FeatureMeta(
                id="tcp.is_tcp",
                dtype="bool",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="True if flow uses TCP protocol",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Whether the flow is a TCP flow",
            ),
            "tcp.syn_count": FeatureMeta(
                id="tcp.syn_count",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="bidir",
                direction_semantics="Count of SYN packets in entire flow",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Number of TCP SYN packets (without ACK)",
            ),
            "tcp.synack_count": FeatureMeta(
                id="tcp.synack_count",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="bidir",
                direction_semantics="Count of SYN-ACK packets in entire flow",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Number of TCP SYN-ACK packets",
            ),
            "tcp.fin_count": FeatureMeta(
                id="tcp.fin_count",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="bidir",
                direction_semantics="Count of FIN packets in entire flow",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Number of TCP FIN packets",
            ),
            "tcp.rst_count": FeatureMeta(
                id="tcp.rst_count",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="bidir",
                direction_semantics="Count of RST packets in entire flow",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Number of TCP RST packets",
            ),
            "tcp.ack_count": FeatureMeta(
                id="tcp.ack_count",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="bidir",
                direction_semantics="Count of ACK packets in entire flow",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Number of TCP packets with ACK flag set",
            ),
            "tcp.psh_count": FeatureMeta(
                id="tcp.psh_count",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="bidir",
                direction_semantics="Count of PSH packets in entire flow",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Number of TCP packets with PSH flag set",
            ),
            "tcp.urg_count": FeatureMeta(
                id="tcp.urg_count",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="bidir",
                direction_semantics="Count of URG packets in entire flow",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Number of TCP packets with URG flag set",
            ),
            "tcp.ece_count": FeatureMeta(
                id="tcp.ece_count",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="bidir",
                direction_semantics="Count of ECE packets in entire flow",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Number of TCP packets with ECE flag set",
            ),
            "tcp.cwr_count": FeatureMeta(
                id="tcp.cwr_count",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="bidir",
                direction_semantics="Count of CWR packets in entire flow",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Number of TCP packets with CWR flag set",
            ),
            "tcp.complete_handshake": FeatureMeta(
                id="tcp.complete_handshake",
                dtype="bool",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="True if SYN from initiator and SYN-ACK from responder observed",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Whether a complete TCP handshake was observed",
            ),
            "tcp.graceful_close": FeatureMeta(
                id="tcp.graceful_close",
                dtype="bool",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="True if FIN seen from both directions",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Whether the connection closed gracefully with FIN from both sides",
            ),
            "tcp.reset_close": FeatureMeta(
                id="tcp.reset_close",
                dtype="bool",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="True if any RST packet observed",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Whether the connection was closed with a RST",
            ),
            "tcp.syn_ratio": FeatureMeta(
                id="tcp.syn_ratio",
                dtype="float64",
                shape=[1],
                units="ratio",
                scope="flow",
                direction="bidir",
                direction_semantics="Ratio of SYN+SYN-ACK packets to total packets",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Ratio of SYN and SYN-ACK packets to total packets",
            ),
            "tcp.fin_ratio": FeatureMeta(
                id="tcp.fin_ratio",
                dtype="float64",
                shape=[1],
                units="ratio",
                scope="flow",
                direction="bidir",
                direction_semantics="Ratio of FIN packets to total packets",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Ratio of FIN packets to total packets",
            ),
            "tcp.rst_ratio": FeatureMeta(
                id="tcp.rst_ratio",
                dtype="float64",
                shape=[1],
                units="ratio",
                scope="flow",
                direction="bidir",
                direction_semantics="Ratio of RST packets to total packets",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Ratio of RST packets to total packets",
            ),
            "tcp.psh_ratio": FeatureMeta(
                id="tcp.psh_ratio",
                dtype="float64",
                shape=[1],
                units="ratio",
                scope="flow",
                direction="bidir",
                direction_semantics="Ratio of PSH packets to total packets",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Ratio of PSH packets to total packets",
            ),
            "tcp.data_packets": FeatureMeta(
                id="tcp.data_packets",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="bidir",
                direction_semantics="Count of packets with payload in entire flow",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Number of TCP packets with non-zero payload",
            ),
            "tcp.ack_only_packets": FeatureMeta(
                id="tcp.ack_only_packets",
                dtype="int64",
                shape=[1],
                units="count",
                scope="flow",
                direction="bidir",
                direction_semantics="Count of ACK-only packets in entire flow",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Number of TCP packets with only ACK flag and no payload",
            ),
            "tcp.flags_anomaly": FeatureMeta(
                id="tcp.flags_anomaly",
                dtype="bool",
                shape=[1],
                units="",
                scope="flow",
                direction="bidir",
                direction_semantics="True if anomalous flag combinations detected",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Whether anomalous TCP flag combinations were detected (null scan, xmas tree, etc.)",
            ),
            "tcp.initiator_syn": FeatureMeta(
                id="tcp.initiator_syn",
                dtype="bool",
                shape=[1],
                units="",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="True if initiator sent SYN",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Whether the flow initiator sent a SYN packet",
            ),
            "tcp.responder_synack": FeatureMeta(
                id="tcp.responder_synack",
                dtype="bool",
                shape=[1],
                units="",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="True if responder sent SYN-ACK",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Whether the flow responder sent a SYN-ACK packet",
            ),
            "tcp.fstat": FeatureMeta(
                id="tcp.fstat",
                dtype="int64",
                shape=[1],
                units="bitmap",
                scope="flow",
                direction="bidir",
                direction_semantics="Bitmap encoding TCP flow state",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Tranalyzer-compatible TCP flow status bitmap",
            ),
            "tcp.flags_agg": FeatureMeta(
                id="tcp.flags_agg",
                dtype="int64",
                shape=[1],
                units="bitmap",
                scope="flow",
                direction="bidir",
                direction_semantics="OR of all TCP flags seen in flow",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Aggregate TCP flags (OR of all flags seen in flow)",
            ),
            "tcp.flags_fwd": FeatureMeta(
                id="tcp.flags_fwd",
                dtype="int64",
                shape=[1],
                units="bitmap",
                scope="flow",
                direction="src_to_dst",
                direction_semantics="OR of all TCP flags from initiator",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Aggregate TCP flags from forward direction (initiator to responder)",
            ),
            "tcp.flags_bwd": FeatureMeta(
                id="tcp.flags_bwd",
                dtype="int64",
                shape=[1],
                units="bitmap",
                scope="flow",
                direction="dst_to_src",
                direction_semantics="OR of all TCP flags from responder",
                missing_policy="zero",
                missing_sentinel=None,
                dependencies=["tcp"],
                privacy_level="safe",
                description="Aggregate TCP flags from backward direction (responder to initiator)",
            ),
        }
