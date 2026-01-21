"""X.509 certificate parsing utilities.

Provides functions to parse TLS certificates and extract metadata
for feature extraction.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, cast

logger = logging.getLogger(__name__)


@dataclass
class CertificateInfo:
    """Parsed X.509 certificate information.

    Attributes:
        subject_cn: Subject Common Name.
        issuer_cn: Issuer Common Name.
        issuer_org: Issuer Organization.
        not_before: Certificate validity start date.
        not_after: Certificate validity end date.
        serial_number: Certificate serial number (hex).
        signature_algorithm: Signature algorithm name.
        public_key_algorithm: Public key algorithm name.
        public_key_bits: Public key size in bits.
        san_dns_names: Subject Alternative Name DNS entries.
        san_ip_addresses: Subject Alternative Name IP entries.
        is_self_signed: Whether the certificate is self-signed.
        is_ca: Whether this is a CA certificate.
        fingerprint_sha256: SHA-256 fingerprint of the certificate.
        days_to_expiry: Days until certificate expires (negative if expired).
        raw_length: Raw certificate length in bytes.
    """

    subject_cn: str = ""
    issuer_cn: str = ""
    issuer_org: str = ""
    not_before: datetime | None = None
    not_after: datetime | None = None
    serial_number: str = ""
    signature_algorithm: str = ""
    public_key_algorithm: str = ""
    public_key_bits: int = 0
    san_dns_names: list[str] | None = None
    san_ip_addresses: list[str] | None = None
    is_self_signed: bool = False
    is_ca: bool = False
    fingerprint_sha256: str = ""
    days_to_expiry: int = 0
    raw_length: int = 0


def parse_certificate(cert_bytes: bytes) -> CertificateInfo | None:
    """Parse an X.509 certificate from DER-encoded bytes.

    Args:
        cert_bytes: DER-encoded certificate bytes.

    Returns:
        CertificateInfo object, or None if parsing fails.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
    except ImportError:
        logger.debug("cryptography library not available for certificate parsing")
        return None

    try:
        cert = x509.load_der_x509_certificate(cert_bytes)
    except Exception as e:
        logger.debug(f"Failed to parse certificate: {e}")
        return None

    info = CertificateInfo(raw_length=len(cert_bytes))

    def _as_str(value: str | bytes) -> str:
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return value

    # Subject and Issuer
    try:
        cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        if cn_attrs:
            info.subject_cn = _as_str(cn_attrs[0].value)
    except Exception:
        pass

    try:
        cn_attrs = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        if cn_attrs:
            info.issuer_cn = _as_str(cn_attrs[0].value)
    except Exception:
        pass

    try:
        org_attrs = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
        if org_attrs:
            info.issuer_org = _as_str(org_attrs[0].value)
    except Exception:
        pass

    # Validity
    info.not_before = cert.not_valid_before_utc
    info.not_after = cert.not_valid_after_utc

    # Days to expiry
    if info.not_after:
        now = datetime.now(timezone.utc)
        delta = info.not_after - now
        info.days_to_expiry = delta.days

    # Serial number
    info.serial_number = format(cert.serial_number, "x")

    # Signature algorithm
    info.signature_algorithm = cert.signature_algorithm_oid._name

    # Public key info
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        info.public_key_algorithm = "RSA"
        info.public_key_bits = public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        info.public_key_algorithm = "EC"
        info.public_key_bits = public_key.key_size
    elif isinstance(public_key, dsa.DSAPublicKey):
        info.public_key_algorithm = "DSA"
        info.public_key_bits = public_key.key_size
    else:
        info.public_key_algorithm = "Unknown"

    # Subject Alternative Names
    try:
        san_ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        san = cast("x509.SubjectAlternativeName", san_ext.value)
        info.san_dns_names = [
            str(name) for name in san.get_values_for_type(x509.DNSName)
        ]
        info.san_ip_addresses = [
            str(ip) for ip in san.get_values_for_type(x509.IPAddress)
        ]
    except x509.ExtensionNotFound:
        info.san_dns_names = []
        info.san_ip_addresses = []

    # Self-signed check
    info.is_self_signed = cert.issuer == cert.subject

    # CA check
    try:
        basic_constraints = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )
        constraints = cast("x509.BasicConstraints", basic_constraints.value)
        info.is_ca = constraints.ca
    except x509.ExtensionNotFound:
        info.is_ca = False

    # SHA-256 fingerprint
    info.fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex()

    return info


def parse_certificate_chain(cert_bytes_list: list[bytes]) -> list[CertificateInfo]:
    """Parse a chain of X.509 certificates.

    Args:
        cert_bytes_list: List of DER-encoded certificate bytes.

    Returns:
        List of CertificateInfo objects.
    """
    chain = []
    for cert_bytes in cert_bytes_list:
        info = parse_certificate(cert_bytes)
        if info:
            chain.append(info)
    return chain


def extract_certificate_features(cert_bytes_list: list[bytes]) -> dict[str, Any]:
    """Extract ML-friendly features from a certificate chain.

    Args:
        cert_bytes_list: List of DER-encoded certificate bytes.

    Returns:
        Dictionary of certificate chain features.
    """
    features: dict[str, Any] = {
        "cert_chain_length": len(cert_bytes_list),
        "cert_leaf_cn": "",
        "cert_leaf_issuer_cn": "",
        "cert_leaf_issuer_org": "",
        "cert_leaf_self_signed": False,
        "cert_leaf_is_ca": False,
        "cert_leaf_key_algorithm": "",
        "cert_leaf_key_bits": 0,
        "cert_leaf_sig_algorithm": "",
        "cert_leaf_days_to_expiry": 0,
        "cert_leaf_san_count": 0,
        "cert_leaf_fingerprint": "",
        "cert_root_cn": "",
        "cert_root_org": "",
        "cert_chain_valid": False,
        "cert_total_bytes": sum(len(b) for b in cert_bytes_list),
    }

    if not cert_bytes_list:
        return features

    chain = parse_certificate_chain(cert_bytes_list)
    if not chain:
        return features

    # Leaf certificate (first in chain)
    leaf = chain[0]
    features["cert_leaf_cn"] = leaf.subject_cn
    features["cert_leaf_issuer_cn"] = leaf.issuer_cn
    features["cert_leaf_issuer_org"] = leaf.issuer_org
    features["cert_leaf_self_signed"] = leaf.is_self_signed
    features["cert_leaf_is_ca"] = leaf.is_ca
    features["cert_leaf_key_algorithm"] = leaf.public_key_algorithm
    features["cert_leaf_key_bits"] = leaf.public_key_bits
    features["cert_leaf_sig_algorithm"] = leaf.signature_algorithm
    features["cert_leaf_days_to_expiry"] = leaf.days_to_expiry
    features["cert_leaf_san_count"] = len(leaf.san_dns_names or []) + len(
        leaf.san_ip_addresses or []
    )
    features["cert_leaf_fingerprint"] = leaf.fingerprint_sha256

    # Root certificate (last in chain)
    if len(chain) > 1:
        root = chain[-1]
        features["cert_root_cn"] = root.subject_cn
        features["cert_root_org"] = root.issuer_org

    # Basic chain validation (issuer matches subject of next cert)
    if len(chain) >= 2:
        valid = True
        for i in range(len(chain) - 1):
            if chain[i].issuer_cn != chain[i + 1].subject_cn:
                valid = False
                break
        features["cert_chain_valid"] = valid
    elif len(chain) == 1:
        features["cert_chain_valid"] = leaf.is_self_signed

    return features


def compute_cert_fingerprint(cert_bytes: bytes, algorithm: str = "sha256") -> str:
    """Compute fingerprint of a certificate.

    Args:
        cert_bytes: DER-encoded certificate bytes.
        algorithm: Hash algorithm ("sha256", "sha1", "md5").

    Returns:
        Hex-encoded fingerprint.
    """
    if algorithm == "sha256":
        return hashlib.sha256(cert_bytes).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(cert_bytes).hexdigest()
    elif algorithm == "md5":
        return hashlib.md5(cert_bytes).hexdigest()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
