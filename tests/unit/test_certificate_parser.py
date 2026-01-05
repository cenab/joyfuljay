"""Tests for certificate parsing utilities."""

from __future__ import annotations

import hashlib

import pytest

from joyfuljay.utils.certificate_parser import (
    CertificateInfo,
    compute_cert_fingerprint,
    extract_certificate_features,
    parse_certificate,
    parse_certificate_chain,
)


class TestCertificateInfo:
    """Tests for CertificateInfo dataclass."""

    def test_default_values(self) -> None:
        """Test default values of CertificateInfo."""
        info = CertificateInfo()
        assert info.subject_cn == ""
        assert info.issuer_cn == ""
        assert info.issuer_org == ""
        assert info.not_before is None
        assert info.not_after is None
        assert info.serial_number == ""
        assert info.signature_algorithm == ""
        assert info.public_key_algorithm == ""
        assert info.public_key_bits == 0
        assert info.san_dns_names is None
        assert info.san_ip_addresses is None
        assert info.is_self_signed is False
        assert info.is_ca is False
        assert info.fingerprint_sha256 == ""
        assert info.days_to_expiry == 0
        assert info.raw_length == 0

    def test_custom_values(self) -> None:
        """Test CertificateInfo with custom values."""
        info = CertificateInfo(
            subject_cn="example.com",
            issuer_cn="CA",
            public_key_bits=2048,
            is_self_signed=True,
        )
        assert info.subject_cn == "example.com"
        assert info.issuer_cn == "CA"
        assert info.public_key_bits == 2048
        assert info.is_self_signed is True


class TestParseCertificate:
    """Tests for parse_certificate function."""

    def test_invalid_bytes_returns_none(self) -> None:
        """Test that invalid certificate bytes return None."""
        result = parse_certificate(b"not a certificate")
        assert result is None

    def test_empty_bytes_returns_none(self) -> None:
        """Test that empty bytes return None."""
        result = parse_certificate(b"")
        assert result is None

    @pytest.mark.skipif(
        not pytest.importorskip("cryptography", reason="cryptography not installed"),
        reason="cryptography not installed"
    )
    def test_parse_valid_certificate(self) -> None:
        """Test parsing a valid self-signed certificate."""
        # Generate a self-signed certificate for testing
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.x509.oid import NameOID
            from datetime import datetime, timedelta, timezone

            # Generate key
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            # Build certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            ])

            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(timezone.utc))
                .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
                .sign(key, hashes.SHA256())
            )

            cert_bytes = cert.public_bytes(
                encoding=__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.DER
            )

            # Parse it
            info = parse_certificate(cert_bytes)

            assert info is not None
            assert info.subject_cn == "test.example.com"
            assert info.issuer_cn == "test.example.com"
            assert info.public_key_algorithm == "RSA"
            assert info.public_key_bits == 2048
            assert info.is_self_signed is True
            assert info.fingerprint_sha256 != ""
            assert info.raw_length == len(cert_bytes)

        except ImportError:
            pytest.skip("cryptography not installed")


class TestParseCertificateChain:
    """Tests for parse_certificate_chain function."""

    def test_empty_chain(self) -> None:
        """Test parsing empty certificate chain."""
        result = parse_certificate_chain([])
        assert result == []

    def test_invalid_certs_skipped(self) -> None:
        """Test that invalid certificates are skipped."""
        result = parse_certificate_chain([b"invalid", b"also invalid"])
        assert result == []


class TestExtractCertificateFeatures:
    """Tests for extract_certificate_features function."""

    def test_empty_chain(self) -> None:
        """Test feature extraction from empty chain."""
        features = extract_certificate_features([])

        assert features["cert_chain_length"] == 0
        assert features["cert_leaf_cn"] == ""
        assert features["cert_leaf_self_signed"] is False
        assert features["cert_chain_valid"] is False
        assert features["cert_total_bytes"] == 0

    def test_returns_all_expected_features(self) -> None:
        """Test that all expected features are returned."""
        features = extract_certificate_features([])

        expected_keys = [
            "cert_chain_length",
            "cert_leaf_cn",
            "cert_leaf_issuer_cn",
            "cert_leaf_issuer_org",
            "cert_leaf_self_signed",
            "cert_leaf_is_ca",
            "cert_leaf_key_algorithm",
            "cert_leaf_key_bits",
            "cert_leaf_sig_algorithm",
            "cert_leaf_days_to_expiry",
            "cert_leaf_san_count",
            "cert_leaf_fingerprint",
            "cert_root_cn",
            "cert_root_org",
            "cert_chain_valid",
            "cert_total_bytes",
        ]

        for key in expected_keys:
            assert key in features, f"Missing feature: {key}"

    def test_total_bytes_calculation(self) -> None:
        """Test that total bytes is calculated correctly."""
        cert1 = b"fake cert 1"
        cert2 = b"fake cert 2 longer"

        features = extract_certificate_features([cert1, cert2])

        assert features["cert_chain_length"] == 2
        assert features["cert_total_bytes"] == len(cert1) + len(cert2)


class TestComputeCertFingerprint:
    """Tests for compute_cert_fingerprint function."""

    def test_sha256_fingerprint(self) -> None:
        """Test SHA-256 fingerprint computation."""
        data = b"test certificate data"
        result = compute_cert_fingerprint(data, "sha256")
        expected = hashlib.sha256(data).hexdigest()
        assert result == expected

    def test_sha1_fingerprint(self) -> None:
        """Test SHA-1 fingerprint computation."""
        data = b"test certificate data"
        result = compute_cert_fingerprint(data, "sha1")
        expected = hashlib.sha1(data).hexdigest()
        assert result == expected

    def test_md5_fingerprint(self) -> None:
        """Test MD5 fingerprint computation."""
        data = b"test certificate data"
        result = compute_cert_fingerprint(data, "md5")
        expected = hashlib.md5(data).hexdigest()
        assert result == expected

    def test_invalid_algorithm_raises(self) -> None:
        """Test that invalid algorithm raises ValueError."""
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            compute_cert_fingerprint(b"data", "invalid")

    def test_empty_data(self) -> None:
        """Test fingerprint of empty data."""
        result = compute_cert_fingerprint(b"", "sha256")
        expected = hashlib.sha256(b"").hexdigest()
        assert result == expected

    def test_fingerprint_deterministic(self) -> None:
        """Test that fingerprint is deterministic."""
        data = b"test data"
        result1 = compute_cert_fingerprint(data, "sha256")
        result2 = compute_cert_fingerprint(data, "sha256")
        assert result1 == result2
