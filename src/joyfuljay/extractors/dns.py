"""DNS protocol metadata feature extractor."""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING, Any

from .base import FeatureExtractor

if TYPE_CHECKING:
    from ..core.flow import Flow

# DNS record types
DNS_TYPE_A = 1
DNS_TYPE_AAAA = 28
DNS_TYPE_CNAME = 5
DNS_TYPE_MX = 15
DNS_TYPE_TXT = 16
DNS_TYPE_NS = 2
DNS_TYPE_SOA = 6
DNS_TYPE_PTR = 12
DNS_TYPE_SRV = 33
DNS_TYPE_HTTPS = 65

# DNS response codes
DNS_RCODE_NOERROR = 0
DNS_RCODE_FORMERR = 1
DNS_RCODE_SERVFAIL = 2
DNS_RCODE_NXDOMAIN = 3
DNS_RCODE_NOTIMP = 4
DNS_RCODE_REFUSED = 5


class DNSExtractor(FeatureExtractor):
    """Extracts DNS protocol metadata features.

    Parses DNS queries and responses to extract:
    - Query names and types
    - Response codes
    - TTL values
    - Answer counts
    """

    def extract(self, flow: Flow) -> dict[str, Any]:
        """Extract DNS metadata features from a flow.

        Args:
            flow: The completed flow.

        Returns:
            Dictionary of DNS features.
        """
        features: dict[str, Any] = {
            "dns_detected": False,
            "dns_query_name": "",
            "dns_query_type": 0,
            "dns_query_type_str": "",
            "dns_response_code": -1,
            "dns_response_code_str": "",
            "dns_answer_count": 0,
            "dns_authority_count": 0,
            "dns_additional_count": 0,
            "dns_min_ttl": 0,
            "dns_max_ttl": 0,
            "dns_is_query": False,
            "dns_is_response": False,
            "dns_truncated": False,
            "dns_recursion_desired": False,
            "dns_recursion_available": False,
        }

        # DNS typically uses UDP port 53
        if flow.key.protocol != 17:  # Not UDP
            return features

        # Check if either port is 53
        if flow.responder_port != 53 and flow.initiator_port != 53:
            return features

        # Parse DNS packets
        for packet in flow.packets:
            if packet.raw_payload and len(packet.raw_payload) >= 12:
                if self._parse_dns_packet(packet.raw_payload, features):
                    features["dns_detected"] = True
                    break  # Got what we need from first valid DNS packet

        return features

    def _parse_dns_packet(
        self,
        data: bytes,
        features: dict[str, Any],
    ) -> bool:
        """Parse a DNS packet.

        Args:
            data: Raw DNS packet data.
            features: Dictionary to update with parsed features.

        Returns:
            True if successfully parsed, False otherwise.
        """
        try:
            if len(data) < 12:
                return False

            # DNS header (12 bytes)
            # 2 bytes: Transaction ID
            # 2 bytes: Flags
            # 2 bytes: Questions count
            # 2 bytes: Answers count
            # 2 bytes: Authority count
            # 2 bytes: Additional count

            flags = struct.unpack("!H", data[2:4])[0]
            questions = struct.unpack("!H", data[4:6])[0]
            answers = struct.unpack("!H", data[6:8])[0]
            authority = struct.unpack("!H", data[8:10])[0]
            additional = struct.unpack("!H", data[10:12])[0]

            # Parse flags
            qr = (flags >> 15) & 0x1  # Query (0) or Response (1)
            opcode = (flags >> 11) & 0xF  # Operation code
            aa = (flags >> 10) & 0x1  # Authoritative Answer
            tc = (flags >> 9) & 0x1  # Truncated
            rd = (flags >> 8) & 0x1  # Recursion Desired
            ra = (flags >> 7) & 0x1  # Recursion Available
            rcode = flags & 0xF  # Response code

            features["dns_is_query"] = qr == 0
            features["dns_is_response"] = qr == 1
            features["dns_truncated"] = tc == 1
            features["dns_recursion_desired"] = rd == 1
            features["dns_recursion_available"] = ra == 1

            if qr == 1:  # Response
                features["dns_response_code"] = rcode
                features["dns_response_code_str"] = self._rcode_to_string(rcode)

            features["dns_answer_count"] = answers
            features["dns_authority_count"] = authority
            features["dns_additional_count"] = additional

            # Parse question section
            offset = 12
            if questions > 0:
                name, offset = self._parse_dns_name(data, offset)
                if name and offset + 4 <= len(data):
                    qtype = struct.unpack("!H", data[offset : offset + 2])[0]
                    features["dns_query_name"] = name
                    features["dns_query_type"] = qtype
                    features["dns_query_type_str"] = self._qtype_to_string(qtype)
                    offset += 4  # Skip type and class

            # Parse answer section to get TTLs
            if answers > 0 and qr == 1:
                min_ttl = float("inf")
                max_ttl = 0

                for _ in range(answers):
                    if offset >= len(data):
                        break

                    # Skip name (with compression support)
                    _, offset = self._parse_dns_name(data, offset)

                    if offset + 10 > len(data):
                        break

                    # Skip type (2) and class (2)
                    offset += 4

                    # TTL (4 bytes)
                    ttl = struct.unpack("!I", data[offset : offset + 4])[0]
                    min_ttl = min(min_ttl, ttl)
                    max_ttl = max(max_ttl, ttl)
                    offset += 4

                    # RDLENGTH (2 bytes)
                    rdlength = struct.unpack("!H", data[offset : offset + 2])[0]
                    offset += 2 + rdlength

                if min_ttl != float("inf"):
                    features["dns_min_ttl"] = int(min_ttl)
                    features["dns_max_ttl"] = max_ttl

            return True

        except (struct.error, IndexError):
            return False

    def _parse_dns_name(self, data: bytes, offset: int) -> tuple[str, int]:
        """Parse a DNS name with compression support.

        Args:
            data: DNS packet data.
            offset: Starting offset.

        Returns:
            Tuple of (name, new_offset).
        """
        labels = []
        original_offset = offset
        jumped = False
        max_jumps = 50  # Prevent infinite loops

        for _ in range(max_jumps):
            if offset >= len(data):
                break

            length = data[offset]

            if length == 0:
                # End of name
                if not jumped:
                    offset += 1
                break

            elif (length & 0xC0) == 0xC0:
                # Compression pointer
                if offset + 1 >= len(data):
                    break
                pointer = struct.unpack("!H", data[offset : offset + 2])[0] & 0x3FFF
                if not jumped:
                    original_offset = offset + 2
                    jumped = True
                offset = pointer

            else:
                # Regular label
                offset += 1
                if offset + length > len(data):
                    break
                label = data[offset : offset + length]
                try:
                    labels.append(label.decode("ascii"))
                except UnicodeDecodeError:
                    labels.append(label.hex())
                offset += length

        name = ".".join(labels) if labels else ""
        return name, original_offset if jumped else offset

    def _qtype_to_string(self, qtype: int) -> str:
        """Convert DNS query type to string."""
        types = {
            DNS_TYPE_A: "A",
            DNS_TYPE_AAAA: "AAAA",
            DNS_TYPE_CNAME: "CNAME",
            DNS_TYPE_MX: "MX",
            DNS_TYPE_TXT: "TXT",
            DNS_TYPE_NS: "NS",
            DNS_TYPE_SOA: "SOA",
            DNS_TYPE_PTR: "PTR",
            DNS_TYPE_SRV: "SRV",
            DNS_TYPE_HTTPS: "HTTPS",
            255: "ANY",
        }
        return types.get(qtype, f"TYPE{qtype}")

    def _rcode_to_string(self, rcode: int) -> str:
        """Convert DNS response code to string."""
        codes = {
            DNS_RCODE_NOERROR: "NOERROR",
            DNS_RCODE_FORMERR: "FORMERR",
            DNS_RCODE_SERVFAIL: "SERVFAIL",
            DNS_RCODE_NXDOMAIN: "NXDOMAIN",
            DNS_RCODE_NOTIMP: "NOTIMP",
            DNS_RCODE_REFUSED: "REFUSED",
        }
        return codes.get(rcode, f"RCODE{rcode}")

    @property
    def feature_names(self) -> list[str]:
        """Get feature names produced by this extractor."""
        return [
            "dns_detected",
            "dns_query_name",
            "dns_query_type",
            "dns_query_type_str",
            "dns_response_code",
            "dns_response_code_str",
            "dns_answer_count",
            "dns_authority_count",
            "dns_additional_count",
            "dns_min_ttl",
            "dns_max_ttl",
            "dns_is_query",
            "dns_is_response",
            "dns_truncated",
            "dns_recursion_desired",
            "dns_recursion_available",
        ]
