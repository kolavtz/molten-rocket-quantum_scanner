"""
SubdomainScanner Module

Unlimited, 100% free, API-key-free nested subdomain discovery engine using:
1. Asynchronous Direct DNS Resolution (aiodns / dnspython / asyncio getaddrinfo fallback)
2. Direct SSL Certificate Subject Alternative Name (SAN) Extraction via TLS/443
3. Recursive Subdomain Depth Expansion (e.g., app.dev.ns1.example.com)
"""

import asyncio
import logging
import socket
import ssl
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# Default comprehensive subdomain wordlist
DEFAULT_SUBDOMAIN_WORDLIST = [
    "ns1", "ns2", "ns3", "dev", "app", "api", "admin", "mail", "stage",
    "test", "internal", "auth", "portal", "v1", "v2", "v3", "db", "shop",
    "vpn", "gateway", "status", "dashboard", "cdn", "assets", "cloud",
    "secure", "login", "sso", "identity", "git", "ci", "jenkins", "k8s",
    "staging", "qa", "demo", "prod", "monitor", "logs", "metrics", "proxy"
]


class SubdomainScanner:
    """
    Unlimited free nested subdomain discovery scanner.
    Queries open public DNS resolvers directly and extracts SAN fields from SSL certs.
    """

    def __init__(
        self,
        target_domain: str,
        max_depth: int = 2,
        wordlist: Optional[List[str]] = None,
        timeout: float = 2.5
    ):
        self.target_domain = target_domain.strip().lower().lstrip(".")
        self.max_depth = max(1, min(max_depth, 4))
        self.wordlist = [w.strip().lower() for w in (wordlist or DEFAULT_SUBDOMAIN_WORDLIST) if w.strip()]
        self.timeout = timeout
        self.discovered_domains: Set[str] = set()
        self.results: List[Dict[str, str]] = []
        self.resolver = None
        self._has_aiodns = False

    async def init_resolver(self):
        """Initialize async DNS resolver using public DNS servers (1.1.1.1, 8.8.8.8, 9.9.9.9)."""
        try:
            import aiodns
            loop = asyncio.get_event_loop()
            self.resolver = aiodns.DNSResolver(loop=loop)
            self.resolver.nameservers = ['1.1.1.1', '8.8.8.8', '9.9.9.9']
            self._has_aiodns = True
        except ImportError:
            self._has_aiodns = False
            logger.debug("aiodns package not available; using asyncio getaddrinfo fallback for DNS resolution.")

    async def resolve_domain(self, domain: str) -> Tuple[bool, Optional[str]]:
        """
        Directly resolves A records via async DNS.
        Returns tuple: (is_resolved, resolved_ip)
        """
        domain = domain.strip().lower()
        if self._has_aiodns and self.resolver is not None:
            try:
                res = await asyncio.wait_for(self.resolver.query(domain, 'A'), timeout=self.timeout)
                if res and len(res) > 0:
                    ip = getattr(res[0], 'host', None) or str(res[0])
                    return True, str(ip)
            except Exception:
                pass

        # Fallback to standard library asyncio getaddrinfo
        loop = asyncio.get_event_loop()
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM),
                timeout=self.timeout
            )
            if infos and len(infos) > 0:
                ip = infos[0][4][0]
                return True, str(ip)
        except Exception:
            return False, None

        return False, None

    def extract_ssl_sans(self, domain: str) -> Set[str]:
        """
        Connects directly via TCP/443 and reads the SSL certificate's SAN fields.
        Finds nested domains like 'app.dev.ns1.example.com' listed on certificates without API keys.
        """
        extracted = set()
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert(binary_form=False) or {}
                    
                    # Extract SANs
                    alt_names = cert.get('subjectAltName', ())
                    for type_name, value in alt_names:
                        if type_name == 'DNS':
                            cleaned = str(value).replace('*.', '').strip().lower()
                            if cleaned.endswith(self.target_domain) and cleaned != self.target_domain:
                                extracted.add(cleaned)

                    # Extract Subject CN
                    subject = cert.get('subject', ())
                    for rdn in subject:
                        for key, value in rdn:
                            if key == 'commonName':
                                cleaned = str(value).replace('*.', '').strip().lower()
                                if cleaned.endswith(self.target_domain) and cleaned != self.target_domain:
                                    extracted.add(cleaned)
        except Exception:
            pass  # Non-HTTPS host or port 443 closed

        return extracted

    async def scan_node(self, current_domain: str, current_depth: int):
        """Recursively scans parent domain for subdomains up to max_depth."""
        if current_depth > self.max_depth:
            return

        candidates = [f"{word}.{current_domain}" for word in self.wordlist]
        tasks = [
            self._check_and_recurse(candidate, current_depth)
            for candidate in candidates
            if candidate not in self.discovered_domains
        ]

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_and_recurse(self, fqdn: str, current_depth: int):
        resolved, ip = await self.resolve_domain(fqdn)
        if resolved and fqdn not in self.discovered_domains:
            self.discovered_domains.add(fqdn)
            self.results.append({
                "subdomain": fqdn,
                "ip": ip or "",
                "source": "DNS",
                "depth": current_depth
            })

            # Extract nested domains from SSL Certificate
            ssl_found = await asyncio.to_thread(self.extract_ssl_sans, fqdn)
            for san in ssl_found:
                if san not in self.discovered_domains:
                    self.discovered_domains.add(san)
                    san_resolved, san_ip = await self.resolve_domain(san)
                    self.results.append({
                        "subdomain": san,
                        "ip": san_ip or "",
                        "source": "SSL_SAN",
                        "depth": current_depth
                    })
                    if san_resolved and current_depth + 1 <= self.max_depth:
                        await self.scan_node(san, current_depth + 1)

            # Recurse under newly found domain
            if current_depth + 1 <= self.max_depth:
                await self.scan_node(fqdn, current_depth + 1)

    async def run(self) -> List[Dict[str, str]]:
        """Run complete async subdomain scan."""
        await self.init_resolver()

        # Step 0: Check root target's SSL certificate for initial SANs
        root_ssl_sans = await asyncio.to_thread(self.extract_ssl_sans, self.target_domain)
        for san in root_ssl_sans:
            if san not in self.discovered_domains:
                self.discovered_domains.add(san)
                resolved, ip = await self.resolve_domain(san)
                self.results.append({
                    "subdomain": san,
                    "ip": ip or "",
                    "source": "SSL_SAN",
                    "depth": 1
                })

        # Step 1: Recursive scan node
        await self.scan_node(self.target_domain, current_depth=1)
        return self.results


def discover_nested_subdomains_sync(
    target_domain: str,
    max_depth: int = 2,
    wordlist: Optional[List[str]] = None
) -> List[Dict[str, str]]:
    """Synchronous entry point for running SubdomainScanner."""
    scanner = SubdomainScanner(target_domain=target_domain, max_depth=max_depth, wordlist=wordlist)
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import nest_asyncio
            nest_asyncio.apply()
            return loop.run_until_complete(scanner.run())
        else:
            return loop.run_until_complete(scanner.run())
    except Exception:
        return asyncio.run(scanner.run())
