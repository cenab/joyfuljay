"""Hashing utilities for fingerprint computation."""

from __future__ import annotations

import hashlib
from typing import Sequence


def compute_ja3_hash(
    tls_version: int,
    cipher_suites: Sequence[int],
    extensions: Sequence[int],
    elliptic_curves: Sequence[int],
    ec_point_formats: Sequence[int],
) -> str:
    """Compute JA3 fingerprint hash for a TLS ClientHello.

    JA3 is a method for fingerprinting TLS clients based on the
    unencrypted fields of the ClientHello message.

    The fingerprint string format is:
        TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats

    Args:
        tls_version: TLS version (e.g., 0x0303 for TLS 1.2).
        cipher_suites: List of cipher suite codes.
        extensions: List of extension type codes.
        elliptic_curves: List of elliptic curve codes (supported groups).
        ec_point_formats: List of EC point format codes.

    Returns:
        MD5 hash of the JA3 fingerprint string.
    """
    # Filter out GREASE values (0x?a?a pattern)
    cipher_suites = _filter_grease(cipher_suites)
    extensions = _filter_grease(extensions)
    elliptic_curves = _filter_grease(elliptic_curves)

    # Build the fingerprint string
    parts = [
        str(tls_version),
        "-".join(str(c) for c in cipher_suites),
        "-".join(str(e) for e in extensions),
        "-".join(str(ec) for ec in elliptic_curves),
        "-".join(str(f) for f in ec_point_formats),
    ]
    ja3_string = ",".join(parts)

    # Compute MD5 hash
    return hashlib.md5(ja3_string.encode()).hexdigest()


def compute_ja3s_hash(
    tls_version: int,
    cipher_suite: int,
    extensions: Sequence[int],
) -> str:
    """Compute JA3S fingerprint hash for a TLS ServerHello.

    JA3S is the server-side companion to JA3, fingerprinting
    the ServerHello message.

    Args:
        tls_version: TLS version from ServerHello.
        cipher_suite: Selected cipher suite.
        extensions: List of extension type codes.

    Returns:
        MD5 hash of the JA3S fingerprint string.
    """
    # Filter out GREASE values
    extensions = _filter_grease(extensions)

    # Build the fingerprint string
    parts = [
        str(tls_version),
        str(cipher_suite),
        "-".join(str(e) for e in extensions),
    ]
    ja3s_string = ",".join(parts)

    # Compute MD5 hash
    return hashlib.md5(ja3s_string.encode()).hexdigest()


def _filter_grease(values: Sequence[int]) -> list[int]:
    """Filter out GREASE values from a sequence.

    GREASE (Generate Random Extensions And Sustain Extensibility)
    values follow the pattern 0x?a?a where ? is any hex digit.

    Args:
        values: Sequence of integer values.

    Returns:
        List with GREASE values removed.
    """
    result = []
    for v in values:
        # GREASE pattern: (v & 0x0f0f) == 0x0a0a
        if (v & 0x0F0F) != 0x0A0A:
            result.append(v)
    return result


def compute_ja3_string(
    tls_version: int,
    cipher_suites: Sequence[int],
    extensions: Sequence[int],
    elliptic_curves: Sequence[int],
    ec_point_formats: Sequence[int],
) -> str:
    """Get the raw JA3 fingerprint string (before hashing).

    Useful for debugging or when you need the full fingerprint
    rather than just the hash.

    Args:
        tls_version: TLS version.
        cipher_suites: List of cipher suite codes.
        extensions: List of extension type codes.
        elliptic_curves: List of elliptic curve codes.
        ec_point_formats: List of EC point format codes.

    Returns:
        The JA3 fingerprint string.
    """
    cipher_suites = _filter_grease(cipher_suites)
    extensions = _filter_grease(extensions)
    elliptic_curves = _filter_grease(elliptic_curves)

    parts = [
        str(tls_version),
        "-".join(str(c) for c in cipher_suites),
        "-".join(str(e) for e in extensions),
        "-".join(str(ec) for ec in elliptic_curves),
        "-".join(str(f) for f in ec_point_formats),
    ]
    return ",".join(parts)
