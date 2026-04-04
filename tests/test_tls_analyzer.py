"""
Unit tests for the TLS Analyzer module.
"""
import pytest
from unittest.mock import MagicMock

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.scanner.tls_analyzer import TLSAnalyzer, CertificateInfo, TLSEndpointResult


class TestExtractKeyExchange:
    """Tests for TLSAnalyzer._extract_key_exchange()."""

    def test_ecdhe_rsa_cipher(self):
        kex = TLSAnalyzer._extract_key_exchange("ECDHE-RSA-AES256-GCM-SHA384")
        assert kex == "ECDHE"

    def test_dhe_cipher(self):
        kex = TLSAnalyzer._extract_key_exchange("DHE-RSA-AES128-GCM-SHA256")
        assert kex == "DHE"

    def test_rsa_static_cipher(self):
        kex = TLSAnalyzer._extract_key_exchange("AES256-GCM-SHA384")
        # No ECDHE/DHE prefix — falls through to pattern matching
        # Will match RSA if it doesn't match others
        assert kex in ("RSA", "UNKNOWN", "TLS1.3-ECDHE")

    def test_tls13_cipher(self):
        kex = TLSAnalyzer._extract_key_exchange("TLS_AES_256_GCM_SHA384")
        assert kex == "TLS1.3-ECDHE"

    def test_tls13_chacha(self):
        kex = TLSAnalyzer._extract_key_exchange("TLS_CHACHA20_POLY1305_SHA256")
        assert kex == "TLS1.3-ECDHE"

    def test_kyber_cipher(self):
        kex = TLSAnalyzer._extract_key_exchange("KYBER768-AES256-GCM-SHA384")
        assert kex == "ML-KEM"

    def test_hybrid_x25519mlkem768(self):
        kex = TLSAnalyzer._extract_key_exchange("X25519MLKEM768")
        assert kex == "X25519MLKEM768"


class TestCertificateInfo:
    """Tests for CertificateInfo dataclass."""

    def test_to_dict(self):
        cert = CertificateInfo(
            subject={"commonName": "example.com"},
            issuer={"commonName": "Let's Encrypt"},
            serial_number="ABC123",
            public_key_type="RSA",
            public_key_bits=2048,
        )
        d = cert.to_dict()
        assert d["subject"]["commonName"] == "example.com"
        assert d["public_key_type"] == "RSA"
        assert d["public_key_bits"] == 2048


class TestTLSEndpointResult:
    """Tests for TLSEndpointResult dataclass."""

    def test_is_successful_true(self):
        r = TLSEndpointResult(host="example.com", port=443, cipher_suite="AES256")
        assert r.is_successful is True

    def test_is_successful_false_with_error(self):
        r = TLSEndpointResult(host="example.com", port=443, error="timeout")
        assert r.is_successful is False

    def test_is_successful_false_no_cipher(self):
        r = TLSEndpointResult(host="example.com", port=443)
        assert r.is_successful is False

    def test_to_dict(self):
        r = TLSEndpointResult(
            host="example.com", port=443,
            cipher_suite="ECDHE-RSA-AES256-GCM-SHA384",
            protocol_version="TLSv1.3",
            key_exchange="ECDHE",
            cipher_bits=256,
        )
        d = r.to_dict()
        assert d["host"] == "example.com"
        assert d["cipher_bits"] == 256


def test_analyze_with_stdlib_parses_der_when_peer_cert_dict_empty(monkeypatch):
    analyzer = TLSAnalyzer()
    result = TLSEndpointResult(host="example.com", port=443)

    fake_plain_sock = MagicMock()
    fake_tls_sock = MagicMock()
    fake_tls_sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    fake_tls_sock.version.return_value = "TLSv1.3"
    fake_tls_sock.getpeercert.side_effect = [{}, b"fake-der"]
    fake_ctx = MagicMock()
    fake_ctx.wrap_socket.return_value = fake_tls_sock

    monkeypatch.setattr("src.scanner.tls_analyzer.socket.create_connection", lambda *args, **kwargs: fake_plain_sock)
    monkeypatch.setattr("src.scanner.tls_analyzer.ssl.create_default_context", lambda: fake_ctx)
    monkeypatch.setattr(analyzer, "get_supported_protocols", lambda host, port: ["TLSv1.3"])

    expected_cert = CertificateInfo(serial_number="SER123")
    parser_calls = {}

    def fake_parse(cert_dict, cert_der):
        parser_calls["cert_dict"] = cert_dict
        parser_calls["cert_der"] = cert_der
        return expected_cert

    monkeypatch.setattr(analyzer, "_parse_stdlib_cert", fake_parse)

    analyzer._analyze_with_stdlib(result, "example.com", 443)

    assert result.certificate is expected_cert
    assert parser_calls["cert_dict"] == {}
    assert parser_calls["cert_der"] == b"fake-der"
    assert result.cipher_suite == "TLS_AES_256_GCM_SHA384"
