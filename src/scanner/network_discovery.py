"""
Network Discovery Module

Scans target hosts for TLS-enabled services on common ports using raw
sockets.  No external dependencies (nmap) required — fully portable on
Windows, Linux, and macOS.

Classes:
    NetworkScanner — discovers TLS-enabled endpoints on a target host or
                     IP range.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import ssl
import concurrent.futures
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from urllib.parse import urlparse

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from config import (
    DEFAULT_TLS_PORTS,
    EXTENDED_DISCOVERY_PORTS,
    PORT_SERVICE_MAP,
    SCAN_TIMEOUT_SECONDS,
    ALLOW_LOCAL_SCANS,
)


@dataclass
class DiscoveredEndpoint:
    """Represents a single TLS-enabled endpoint discovered during a scan."""

    host: str
    port: int
    service: str = ""
    is_tls: bool = False
    banner: str = ""
    is_public: bool = False
    error: Optional[str] = None

    def __str__(self) -> str:
        status = "TLS" if self.is_tls else "NO-TLS"
        return f"{self.host}:{self.port} [{self.service}] ({status})"


def sanitize_target(raw_input: str) -> Tuple[str, Optional[int]]:
    """Sanitize and normalize a user-supplied scan target.

    Accepts:
    * Plain hostnames:  ``google.com``
    * IP addresses:     ``8.8.8.8``
    * CIDR ranges:      ``10.0.0.0/24``
    * Full URLs:        ``https://example.com/path?q=1``
    * URLs with ports:  ``https://example.com:8443/``

    Returns
    -------
    tuple[str, int | None]
        ``(hostname_or_ip, port_override)``.
        ``port_override`` is ``None`` unless a non-standard port was
        specified in a URL.

    Raises
    ------
    ValueError
        If the input is empty, too long, or contains dangerous characters.
    """
    target = raw_input.strip()

    # ── Basic validation ──
    if not target:
        raise ValueError("Target cannot be empty.")
    if len(target) > 2048:
        raise ValueError("Target string is too long (max 2048 characters).")

    # Reject shell metacharacters and control chars
    _DANGEROUS = re.compile(r'[;&|`$(){}\[\]!<>\\\n\r\t\x00]')
    if _DANGEROUS.search(target):
        raise ValueError(
            "Target contains invalid characters. "
            "Provide a hostname, IP, CIDR, or URL."
        )

    port_override: Optional[int] = None

    # ── URL detection: anything with :// or leading http/https ──
    if '://' in target or target.lower().startswith(('http:', 'https:')):
        parsed = urlparse(target)
        hostname = parsed.hostname or parsed.path.split('/')[0]
        if parsed.port:
            port_override = parsed.port
        target = hostname

    # ── Strip trailing slashes / whitespace leftover ──
    target = target.strip('/')

    # ── Remove a trailing port (host:port without scheme) ──
    if ':' in target and '/' not in target:
        parts = target.rsplit(':', 1)
        if parts[1].isdigit():
            target = parts[0]
            port_override = int(parts[1])

    # Final hostname validation
    if not target:
        raise ValueError("Could not extract a hostname from the input.")

    # Allow only valid hostname/IP/CIDR characters
    _VALID_TARGET = re.compile(r'^[a-zA-Z0-9.:\-_/]+$')
    if not _VALID_TARGET.match(target):
        raise ValueError(
            f"Invalid target '{target}'. "
            "Only hostnames, IPs, and CIDR ranges are accepted."
        )

    return target, port_override


class NetworkScanner:
    """Discovers TLS-enabled services on a target host or IP range.

    Usage::

        scanner = NetworkScanner()
        endpoints = scanner.discover_targets("example.com")
        for ep in endpoints:
            print(ep)
    """

    def __init__(
        self,
        ports: Optional[List[int]] = None,
        timeout: float = SCAN_TIMEOUT_SECONDS,
        max_workers: int = 20,
    ) -> None:
        self.ports = ports or list(DEFAULT_TLS_PORTS)
        self.timeout = timeout
        self.max_workers = max_workers

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def discover_targets(
        self, target: str, ports: Optional[List[int]] = None
    ) -> List[DiscoveredEndpoint]:
        """Scan *target* for TLS-enabled services.

        Parameters
        ----------
        target : str
            A hostname, single IP, CIDR range, or URL.
            URLs (``https://example.com/path``) are automatically
            sanitized to extract the hostname.
        ports : list[int], optional
            Override the default port list for this scan.

        Returns
        -------
        list[DiscoveredEndpoint]
            Endpoints where a TLS handshake succeeded.
        """
        # Sanitize: strip URL scheme/path, extract host & optional port
        clean_target, port_from_url = sanitize_target(target)

        scan_ports = ports or self.ports
        # If the URL contained a non-standard port, prepend it
        if port_from_url and port_from_url not in scan_ports:
            scan_ports = [port_from_url] + list(scan_ports)

        hosts = self._resolve_target(clean_target)

        tasks: list[tuple[str, int]] = []
        for host in hosts:
            for port in scan_ports:
                tasks.append((host, port))

        results: List[DiscoveredEndpoint] = []
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_workers
        ) as pool:
            futures = {
                pool.submit(self._probe_endpoint, h, p): (h, p)
                for h, p in tasks
            }
            for future in concurrent.futures.as_completed(futures):
                ep = future.result()
                if ep is not None and ep.is_tls:
                    results.append(ep)

        # Sort by host then port for consistent output
        results.sort(key=lambda e: (e.host, e.port))
        return results

    def discover_services(
        self,
        target: str,
        ports: Optional[List[int]] = None,
    ) -> List[DiscoveredEndpoint]:
        """Broad service discovery across common ports.

        Unlike ``discover_targets`` which only returns TLS endpoints,
        this method returns **every open port** it finds, indicating
        whether TLS is available on each.

        Parameters
        ----------
        target : str
            Hostname, IP, CIDR, or URL.
        ports : list[int], optional
            Ports to scan. Defaults to ``EXTENDED_DISCOVERY_PORTS``.
        """
        clean_target, port_from_url = sanitize_target(target)

        scan_ports = ports or list(EXTENDED_DISCOVERY_PORTS)
        if port_from_url and port_from_url not in scan_ports:
            scan_ports = [port_from_url] + list(scan_ports)

        hosts = self._resolve_target(clean_target)

        tasks: list[tuple[str, int]] = []
        for host in hosts:
            for port in scan_ports:
                tasks.append((host, port))

        results: List[DiscoveredEndpoint] = []
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_workers
        ) as pool:
            futures = {
                pool.submit(self._probe_endpoint, h, p): (h, p)
                for h, p in tasks
            }
            for future in concurrent.futures.as_completed(futures):
                ep = future.result()
                if ep is not None:   # includes both TLS and non-TLS open ports
                    results.append(ep)

        results.sort(key=lambda e: (e.host, e.port))
        return results

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _resolve_target(self, target: str) -> List[str]:
        """Expand *target* into a list of IP address strings.

        Supports:
        * Hostname (resolved via DNS)
        * Single IPv4/IPv6 address
        * CIDR notation (e.g. ``10.0.0.0/28``)
        """
        allow_local = ALLOW_LOCAL_SCANS

        def check_ssrf(ip_obj):
            if not allow_local and (ip_obj.is_private or ip_obj.is_loopback):
                raise ValueError(
                    f"Target {ip_obj} is a private/local address. "
                    "Scanning internal networks is disabled for security reasons."
                )

        # Try CIDR first
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            network = None

        if network is not None:
            # Limit to /24 at most to avoid accidental huge scans
            if network.num_addresses > 256:
                raise ValueError(
                    f"CIDR range too large ({network.num_addresses} hosts). "
                    "Maximum supported is /24 (256 hosts)."
                )
            check_ssrf(network.network_address)
            return [str(ip) for ip in network.hosts()]

        # Try single IP
        try:
            addr = ipaddress.ip_address(target)
            check_ssrf(addr)
            return [str(addr)]
        except ValueError:
            pass

        # Treat as hostname — resolve to IP(s)
        try:
            infos = socket.getaddrinfo(
                target, None, socket.AF_UNSPEC, socket.SOCK_STREAM
            )
            ips = []
            for info in infos:
                ip_str = info[4][0]
                addr = ipaddress.ip_address(ip_str)
                check_ssrf(addr)
                ips.append(ip_str)
            ips = list(set(ips))
            return ips if ips else [target]
        except socket.gaierror:
            return [target]

    def _probe_endpoint(
        self, host: str, port: int
    ) -> Optional[DiscoveredEndpoint]:
        """Attempt a TLS connection to *host*:*port*.

        Returns a `DiscoveredEndpoint` if the port is open and TLS
        handshake succeeds, otherwise ``None``.
        """
        service = PORT_SERVICE_MAP.get(port, f"TLS-{port}")
        ep = DiscoveredEndpoint(
            host=host,
            port=port,
            service=service,
            is_public=self.is_public_facing(host),
        )

        # Step 1: TCP connect
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((host, port))
        except (socket.timeout, socket.error, OSError):
            sock.close()
            return None  # port closed or unreachable

        # Step 2: TLS handshake
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # we just want to probe, not verify
        try:
            tls_sock = ctx.wrap_socket(sock, server_hostname=host)
            ep.is_tls = True
            ep.banner = tls_sock.version() or ""
            tls_sock.close()
        except ssl.SSLError as exc:
            # Port is open but does NOT speak TLS
            ep.is_tls = False
            ep.banner = "open (no TLS)"
            ep.error = str(exc)
            sock.close()
            return ep   # still report as open service
        except (socket.timeout, socket.error, OSError) as exc:
            ep.error = str(exc)
            sock.close()
            return None

        return ep

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def is_public_facing(ip: str) -> bool:
        """Return ``True`` if *ip* is **not** in a private/reserved range.

        Checks against RFC 1918 private ranges, link-local, loopback,
        and other reserved blocks.
        """
        try:
            addr = ipaddress.ip_address(ip)
            return not (
                addr.is_private
                or addr.is_loopback
                or addr.is_link_local
                or addr.is_reserved
                or addr.is_multicast
            )
        except ValueError:
            # If it's a hostname (not IP), assume public for now
            return True
