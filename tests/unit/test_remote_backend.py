"""Tests for remote backend URL parsing and TLS handling."""

from __future__ import annotations

import ssl

from joyfuljay.capture.remote_backend import RemoteCaptureBackend


def test_remote_backend_parses_plain_url() -> None:
    backend = RemoteCaptureBackend.from_jj_url("jj://example.com:9999?token=abc")
    assert backend.ws_url == "ws://example.com:9999"
    assert backend.ssl_context is None


def test_remote_backend_parses_tls_url() -> None:
    backend = RemoteCaptureBackend.from_jj_url(
        "jj://example.com:9999?token=abc&tls=1",
        tls_verify=False,
    )
    assert backend.ws_url == "wss://example.com:9999"
    assert backend.ssl_context is not None
    assert backend.ssl_context.verify_mode == ssl.CERT_NONE
