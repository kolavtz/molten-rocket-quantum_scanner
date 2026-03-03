"""
Unit tests for the Network Discovery module.
"""
import socket
import ssl
from unittest import mock

import pytest

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.scanner.network_discovery import NetworkScanner, DiscoveredEndpoint, sanitize_target


class TestSanitizeTarget:
    """Tests for sanitize_target() — URL parsing & input validation."""

    # ── URL stripping ──

    def test_https_url(self):
        host, port = sanitize_target("https://example.com/")
        assert host == "example.com"
        assert port is None

    def test_https_url_with_path(self):
        host, port = sanitize_target("https://website.example/some/path?q=1#frag")
        assert host == "website.example"
        assert port is None

    def test_http_url(self):
        host, port = sanitize_target("http://example.org/login")
        assert host == "example.org"
        assert port is None

    def test_url_with_port(self):
        host, port = sanitize_target("https://example.com:8443/api/v2")
        assert host == "example.com"
        assert port == 8443

    def test_url_with_standard_port(self):
        host, port = sanitize_target("https://example.com:443/")
        assert host == "example.com"
        assert port == 443

    # ── Plain hostnames ──

    def test_plain_hostname(self):
        host, port = sanitize_target("google.com")
        assert host == "google.com"
        assert port is None

    def test_hostname_with_trailing_slash(self):
        host, port = sanitize_target("google.com/")
        assert host == "google.com"
        assert port is None

    def test_host_colon_port(self):
        host, port = sanitize_target("example.com:8443")
        assert host == "example.com"
        assert port == 8443

    def test_ip_address(self):
        host, port = sanitize_target("8.8.8.8")
        assert host == "8.8.8.8"
        assert port is None

    def test_cidr(self):
        host, port = sanitize_target("192.168.1.0/24")
        assert host == "192.168.1.0/24"
        assert port is None

    def test_whitespace_stripped(self):
        host, port = sanitize_target("  google.com  ")
        assert host == "google.com"

    # ── Rejection / validation ──

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="empty"):
            sanitize_target("")

    def test_dangerous_semicolon(self):
        with pytest.raises(ValueError, match="invalid characters"):
            sanitize_target("google.com; rm -rf /")

    def test_dangerous_pipe(self):
        with pytest.raises(ValueError, match="invalid characters"):
            sanitize_target("google.com | cat /etc/passwd")


class TestIsPublicFacing:
    """Tests for NetworkScanner.is_public_facing()."""

    def test_private_ipv4_class_a(self):
        assert NetworkScanner.is_public_facing("10.0.0.1") is False

    def test_private_ipv4_class_b(self):
        assert NetworkScanner.is_public_facing("172.16.0.1") is False

    def test_private_ipv4_class_c(self):
        assert NetworkScanner.is_public_facing("192.168.1.1") is False

    def test_loopback(self):
        assert NetworkScanner.is_public_facing("127.0.0.1") is False

    def test_link_local(self):
        assert NetworkScanner.is_public_facing("169.254.0.1") is False

    def test_public_ipv4(self):
        assert NetworkScanner.is_public_facing("8.8.8.8") is True

    def test_public_ipv4_cloudflare(self):
        assert NetworkScanner.is_public_facing("1.1.1.1") is True

    def test_hostname_returns_true(self):
        # Hostnames can't be parsed as IPs, so they return True
        assert NetworkScanner.is_public_facing("google.com") is True


class TestResolveTarget:
    """Tests for NetworkScanner._resolve_target()."""

    def test_single_ip(self):
        scanner = NetworkScanner()
        result = scanner._resolve_target("8.8.8.8")
        assert result == ["8.8.8.8"]

    def test_cidr_small(self):
        scanner = NetworkScanner()
        result = scanner._resolve_target("192.168.1.0/30")
        # /30 has 2 usable hosts
        assert len(result) == 2
        assert "192.168.1.1" in result
        assert "192.168.1.2" in result

    def test_cidr_too_large(self):
        scanner = NetworkScanner()
        with pytest.raises(ValueError, match="too large"):
            scanner._resolve_target("10.0.0.0/16")


class TestDiscoveredEndpoint:
    """Tests for DiscoveredEndpoint dataclass."""

    def test_str_tls(self):
        ep = DiscoveredEndpoint(host="1.2.3.4", port=443, service="HTTPS", is_tls=True)
        assert "TLS" in str(ep)
        assert "1.2.3.4:443" in str(ep)

    def test_str_no_tls(self):
        ep = DiscoveredEndpoint(host="1.2.3.4", port=80, service="HTTP", is_tls=False)
        assert "NO-TLS" in str(ep)


class TestDiscoverTargets:
    """Tests for NetworkScanner.discover_targets() with mocked sockets."""

    @mock.patch('src.scanner.network_discovery.ssl.create_default_context')
    @mock.patch('src.scanner.network_discovery.socket.socket')
    def test_successful_probe(self, mock_socket_cls, mock_ssl_ctx):
        """Verify that a successful TLS connection returns an endpoint."""
        # Setup mock socket
        mock_sock = mock.MagicMock()
        mock_socket_cls.return_value = mock_sock

        # Setup mock TLS
        mock_ctx = mock.MagicMock()
        mock_ssl_ctx.return_value = mock_ctx
        mock_tls_sock = mock.MagicMock()
        mock_tls_sock.version.return_value = "TLSv1.3"
        mock_ctx.wrap_socket.return_value = mock_tls_sock

        scanner = NetworkScanner(ports=[443], max_workers=1)
        results = scanner.discover_targets("8.8.8.8")

        assert len(results) == 1
        assert results[0].host == "8.8.8.8"
        assert results[0].port == 443
        assert results[0].is_tls is True

    @mock.patch('src.scanner.network_discovery.socket.socket')
    def test_closed_port(self, mock_socket_cls):
        """Verify that a closed port returns no endpoints."""
        mock_sock = mock.MagicMock()
        mock_sock.connect.side_effect = socket.timeout("Connection timed out")
        mock_socket_cls.return_value = mock_sock

        scanner = NetworkScanner(ports=[443], max_workers=1)
        results = scanner.discover_targets("10.0.0.1")

        assert len(results) == 0
