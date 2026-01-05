"""SSH protocol metadata feature extractor."""

from __future__ import annotations

import re
import struct
from typing import TYPE_CHECKING, Any

from .base import FeatureExtractor

if TYPE_CHECKING:
    from ..core.flow import Flow

# SSH message types
SSH_MSG_KEXINIT = 20
SSH_MSG_NEWKEYS = 21
SSH_MSG_KEXDH_INIT = 30
SSH_MSG_KEXDH_REPLY = 31

# SSH version string pattern
SSH_VERSION_PATTERN = re.compile(rb"SSH-(\d+\.\d+)-([^\r\n]+)")


class SSHExtractor(FeatureExtractor):
    """Extracts SSH protocol metadata features.

    Detects SSH traffic and extracts:
    - SSH version (1.x or 2.x)
    - Client and server software versions
    - Key exchange detection
    - Encryption start detection
    """

    def extract(self, flow: Flow) -> dict[str, Any]:
        """Extract SSH metadata features from a flow.

        Args:
            flow: The completed flow.

        Returns:
            Dictionary of SSH features.
        """
        features: dict[str, Any] = {
            "ssh_detected": False,
            "ssh_version": "",
            "ssh_client_software": "",
            "ssh_server_software": "",
            "ssh_client_version": "",
            "ssh_server_version": "",
            "ssh_hassh": "",
            "ssh_hassh_server": "",
            "ssh_kex_packets": 0,
            "ssh_encrypted_packets": 0,
        }

        # SSH typically runs on TCP port 22
        if flow.key.protocol != 6:  # Not TCP
            return features

        # Look for SSH version exchange
        client_banner = self._find_ssh_banner(flow.initiator_packets)
        server_banner = self._find_ssh_banner(flow.responder_packets)

        if client_banner or server_banner:
            features["ssh_detected"] = True

        if client_banner:
            version, software = self._parse_ssh_banner(client_banner)
            features["ssh_client_version"] = version
            features["ssh_client_software"] = software
            features["ssh_version"] = version

        if server_banner:
            version, software = self._parse_ssh_banner(server_banner)
            features["ssh_server_version"] = version
            features["ssh_server_software"] = software
            if not features["ssh_version"]:
                features["ssh_version"] = version

        # Look for KEXINIT messages to compute HASSH
        client_kexinit = self._find_kexinit(flow.initiator_packets)
        server_kexinit = self._find_kexinit(flow.responder_packets)

        if client_kexinit:
            features["ssh_hassh"] = self._compute_hassh(client_kexinit, is_server=False)

        if server_kexinit:
            features["ssh_hassh_server"] = self._compute_hassh(server_kexinit, is_server=True)

        # Count key exchange and encrypted packets
        features["ssh_kex_packets"] = self._count_kex_packets(flow)
        features["ssh_encrypted_packets"] = self._count_encrypted_packets(flow)

        return features

    def _find_ssh_banner(self, packets: list) -> bytes | None:
        """Find SSH version banner in packets."""
        for packet in packets:
            if packet.raw_payload:
                # SSH banner starts with "SSH-"
                if packet.raw_payload.startswith(b"SSH-"):
                    # Extract the banner line
                    end = packet.raw_payload.find(b"\r\n")
                    if end == -1:
                        end = packet.raw_payload.find(b"\n")
                    if end == -1:
                        end = min(255, len(packet.raw_payload))
                    return packet.raw_payload[:end]
        return None

    def _parse_ssh_banner(self, banner: bytes) -> tuple[str, str]:
        """Parse SSH version banner.

        Args:
            banner: Raw SSH banner bytes.

        Returns:
            Tuple of (version, software_name).
        """
        match = SSH_VERSION_PATTERN.match(banner)
        if match:
            version = match.group(1).decode("ascii", errors="ignore")
            software = match.group(2).decode("ascii", errors="ignore")
            # Clean up software string
            software = software.split()[0] if software else ""
            return version, software
        return "", ""

    def _find_kexinit(self, packets: list) -> bytes | None:
        """Find SSH_MSG_KEXINIT message in packets."""
        for packet in packets:
            if packet.raw_payload and len(packet.raw_payload) > 5:
                # Check if this looks like an SSH packet after banner
                if not packet.raw_payload.startswith(b"SSH-"):
                    # SSH binary packet format:
                    # 4 bytes: packet length
                    # 1 byte: padding length
                    # N bytes: payload (first byte is message type)
                    if len(packet.raw_payload) >= 6:
                        try:
                            pkt_len = struct.unpack("!I", packet.raw_payload[0:4])[0]
                            if 4 < pkt_len < 35000:  # Reasonable SSH packet size
                                padding_len = packet.raw_payload[4]
                                if padding_len < pkt_len:
                                    msg_type = packet.raw_payload[5]
                                    if msg_type == SSH_MSG_KEXINIT:
                                        # Return KEXINIT payload
                                        return packet.raw_payload[5:]
                        except (struct.error, IndexError):
                            pass
        return None

    def _compute_hassh(self, kexinit: bytes, is_server: bool = False) -> str:
        """Compute HASSH fingerprint from KEXINIT message.

        HASSH (client) is MD5 hash of:
        kex_algorithms;encryption_algorithms_client_to_server;
        mac_algorithms_client_to_server;compression_algorithms_client_to_server

        HASSHServer is MD5 hash of:
        kex_algorithms;encryption_algorithms_server_to_client;
        mac_algorithms_server_to_client;compression_algorithms_server_to_client

        Args:
            kexinit: Raw KEXINIT message bytes.
            is_server: If True, compute HASSHServer fingerprint.

        Returns:
            HASSH fingerprint string or empty string.
        """
        try:
            import hashlib

            # KEXINIT format after message type:
            # 16 bytes: cookie
            # name-list[0]: kex_algorithms
            # name-list[1]: server_host_key_algorithms
            # name-list[2]: encryption_algorithms_client_to_server
            # name-list[3]: encryption_algorithms_server_to_client
            # name-list[4]: mac_algorithms_client_to_server
            # name-list[5]: mac_algorithms_server_to_client
            # name-list[6]: compression_algorithms_client_to_server
            # name-list[7]: compression_algorithms_server_to_client
            # ... (more fields)

            if len(kexinit) < 18:  # 1 (type) + 16 (cookie) + 1 (min)
                return ""

            offset = 17  # Skip message type + cookie
            lists: list[str] = []

            # Read 8 name-lists (need index 7 for server compression)
            for i in range(8):
                if offset + 4 > len(kexinit):
                    break
                list_len = struct.unpack("!I", kexinit[offset : offset + 4])[0]
                offset += 4
                if offset + list_len > len(kexinit):
                    break
                name_list = kexinit[offset : offset + list_len].decode("ascii", errors="ignore")
                lists.append(name_list)
                offset += list_len

            if is_server:
                # HASSHServer: kex;enc_s2c;mac_s2c;comp_s2c
                if len(lists) >= 8:
                    hassh_string = f"{lists[0]};{lists[3]};{lists[5]};{lists[7]}"
                    return hashlib.md5(hassh_string.encode()).hexdigest()
            else:
                # HASSH: kex;enc_c2s;mac_c2s;comp_c2s
                if len(lists) >= 7:
                    hassh_string = f"{lists[0]};{lists[2]};{lists[4]};{lists[6]}"
                    return hashlib.md5(hassh_string.encode()).hexdigest()

        except (struct.error, IndexError):
            pass

        return ""

    def _count_kex_packets(self, flow: Flow) -> int:
        """Count SSH key exchange packets."""
        count = 0
        for packet in flow.packets:
            if packet.raw_payload and len(packet.raw_payload) >= 6:
                if not packet.raw_payload.startswith(b"SSH-"):
                    try:
                        pkt_len = struct.unpack("!I", packet.raw_payload[0:4])[0]
                        if 4 < pkt_len < 35000:
                            msg_type = packet.raw_payload[5]
                            # KEX messages are 20-49
                            if 20 <= msg_type <= 49:
                                count += 1
                    except (struct.error, IndexError):
                        pass
        return count

    def _count_encrypted_packets(self, flow: Flow) -> int:
        """Count packets after key exchange (likely encrypted)."""
        count = 0
        kex_complete = False

        for packet in flow.packets:
            if packet.raw_payload and len(packet.raw_payload) >= 6:
                if not packet.raw_payload.startswith(b"SSH-"):
                    try:
                        pkt_len = struct.unpack("!I", packet.raw_payload[0:4])[0]
                        if 4 < pkt_len < 35000:
                            msg_type = packet.raw_payload[5]
                            if msg_type == SSH_MSG_NEWKEYS:
                                kex_complete = True
                            elif kex_complete:
                                count += 1
                    except (struct.error, IndexError):
                        if kex_complete:
                            count += 1
        return count

    @property
    def feature_names(self) -> list[str]:
        """Get feature names produced by this extractor."""
        return [
            "ssh_detected",
            "ssh_version",
            "ssh_client_software",
            "ssh_server_software",
            "ssh_client_version",
            "ssh_server_version",
            "ssh_hassh",
            "ssh_hassh_server",
            "ssh_kex_packets",
            "ssh_encrypted_packets",
        ]
