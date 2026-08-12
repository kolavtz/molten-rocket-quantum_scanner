"""
SubdomainScanner Module — 3-Tier Enterprise Discovery Engine

100% Free, Aggressive & Unrestricted Subdomain Harvesting:
- Tier 1: Passive Certificate Transparency Logging (crt.sh via httpx/requests) for historical & current SAN records.
- Tier 2: Dynamic Permutation & Alteration Search based on harvested base keywords.
- Tier 3: High-speed Async DNS Resolution via aiodns & dnspython sidecar to classify Active (IP resolved) vs Unresolved OSINT (NXDOMAIN).
"""

import asyncio
import logging
import re
import socket
import ssl
from typing import Dict, List, Optional, Set, Tuple

import dns.resolver  # dnspython sidecar
import httpx
import requests

logger = logging.getLogger(__name__)

# Default base keywords for dynamic permutations
DEFAULT_BASE_KEYWORDS = [
    "ns1", "ns2", "ns3", "dev", "app", "api", "admin", "mail", "stage",
    "test", "internal", "auth", "portal", "v1", "v2", "v3", "db", "shop",
    "vpn", "gateway", "status", "dashboard", "cdn", "assets", "cloud",
    "secure", "login", "sso", "identity", "git", "ci", "jenkins", "k8s",
    "staging", "qa", "demo", "prod", "monitor", "logs", "metrics", "proxy",
    "vkyc", "mbs", "digi", "agent", "payment", "cards", "apply", "support", "cms"
]


def fetch_ct_subdomains(domain: str, timeout: float = 12.0) -> Set[str]:
    """Retrieves current and historical subdomains passively from Certificate Transparency logs for free."""
    domain = domain.strip().lower().lstrip(".")
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    discovered: Set[str] = set()

    # Try httpx first
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name_value = entry.get("name_value", "") or ""
                    for name in name_value.split("\n"):
                        cleaned = name.replace("*.", "").strip().lower()
                        if cleaned.endswith(domain) and cleaned != domain:
                            discovered.add(cleaned)
    except Exception as exc:
        logger.debug("httpx crt.sh query failed, trying requests fallback: %s", exc)
        try:
            r = requests.get(url, timeout=timeout)
            if r.status_code == 200:
                data = r.json()
                for entry in data:
                    name_value = entry.get("name_value", "") or ""
                    for name in name_value.split("\n"):
                        cleaned = name.replace("*.", "").strip().lower()
                        if cleaned.endswith(domain) and cleaned != domain:
                            discovered.add(cleaned)
        except Exception as fallback_exc:
            logger.warning("CRT.sh lookup failed for %s: %s", domain, fallback_exc)

    return discovered


def generate_dynamic_permutations(harvested_domains: Set[str], target_domain: str, base_keywords: Optional[List[str]] = None) -> Set[str]:
    """Dynamically generates targeted alterations (e.g. pnb-vkyc, digi-vkyc) from harvested CT words."""
    domain = target_domain.strip().lower().lstrip(".")
    keywords: Set[str] = set(base_keywords or DEFAULT_BASE_KEYWORDS)

    # Extract single-word tokens from harvested CT subdomains
    for sub in harvested_domains:
        prefix = sub[: -len(domain)].rstrip(".")
        tokens = re.split(r"[.\-_]", prefix)
        for t in tokens:
            t_clean = t.strip().lower()
            if t_clean and len(t_clean) >= 2 and t_clean not in {"www", "com", "in", "org", "net"}:
                keywords.add(t_clean)

    permutations: Set[str] = set()
    key_list = list(keywords)[:30]  # Cap top 30 base terms for fast execution

    for kw in key_list:
        # standard sub
        permutations.add(f"{kw}.{domain}")
        # common alterations
        permutations.add(f"{kw}-app.{domain}")
        permutations.add(f"{kw}-api.{domain}")
        permutations.add(f"{kw}-vkyc.{domain}")
        permutations.add(f"{kw}-agent.{domain}")
        permutations.add(f"digi-{kw}.{domain}")
        permutations.add(f"mbs-{kw}.{domain}")

    return permutations


class SubdomainScanner:
    """
    3-Tier Aggressive & Free Subdomain Scanner.
    Combines passive CT logs (historical), dynamic permutations, and async DNS resolution.
    """

    def __init__(
        self,
        target_domain: str,
        max_depth: int = 2,
        wordlist: Optional[List[str]] = None,
        timeout: float = 3.0
    ):
        self.target_domain = target_domain.strip().lower().lstrip(".")
        self.max_depth = max(1, min(max_depth, 4))
        self.wordlist = [w.strip().lower() for w in (wordlist or DEFAULT_BASE_KEYWORDS) if w.strip()]
        self.timeout = timeout
        self.discovered_domains: Set[str] = set()
        self.resolved_records: List[Dict[str, str]] = []
        self.unresolved_records: List[Dict[str, str]] = []
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

    async def resolve_domain(self, domain: str) -> Tuple[bool, Optional[str]]:
        """
        Resolves domain using aiodns, dnspython sidecar, or getaddrinfo fallback.
        """
        domain = domain.strip().lower()

        # 1. Try aiodns
        if self._has_aiodns and self.resolver is not None:
            try:
                res = await asyncio.wait_for(self.resolver.query(domain, 'A'), timeout=self.timeout)
                if res and len(res) > 0:
                    ip = getattr(res[0], 'host', None) or str(res[0])
                    return True, str(ip)
            except Exception:
                pass

        # 2. Try dnspython sidecar in thread pool
        def _dnspython_resolve(target_d: str) -> Tuple[bool, Optional[str]]:
            try:
                r = dns.resolver.Resolver()
                r.nameservers = ['1.1.1.1', '8.8.8.8']
                r.lifetime = 2.5
                answers = r.resolve(target_d, 'A')
                for rdata in answers:
                    return True, str(rdata.address)
            except Exception:
                return False, None
            return False, None

        try:
            dns_ok, dns_ip = await asyncio.to_thread(_dnspython_resolve, domain)
            if dns_ok:
                return True, dns_ip
        except Exception:
            pass

        # 3. Fallback to standard library asyncio getaddrinfo
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
        """Extract SAN fields directly from TCP/443 SSL certificate."""
        extracted: Set[str] = set()
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert(binary_form=False) or {}
                    alt_names = cert.get('subjectAltName', ())
                    for type_name, value in alt_names:
                        if type_name == 'DNS':
                            cleaned = str(value).replace('*.', '').strip().lower()
                            if cleaned.endswith(self.target_domain) and cleaned != self.target_domain:
                                extracted.add(cleaned)

                    subject = cert.get('subject', ())
                    for rdn in subject:
                        for key, value in rdn:
                            if key == 'commonName':
                                cleaned = str(value).replace('*.', '').strip().lower()
                                if cleaned.endswith(self.target_domain) and cleaned != self.target_domain:
                                    extracted.add(cleaned)
        except Exception:
            pass

        return extracted

    async def run(self) -> List[Dict[str, str]]:
        """Run complete 3-tier subdomain discovery pipeline."""
        await self.init_resolver()

        candidates: Set[str] = set()

        # Tier 1: Passive Certificate Transparency Logging (crt.sh historical & live records)
        ct_subdomains = await asyncio.to_thread(fetch_ct_subdomains, self.target_domain, 12.0)
        candidates.update(ct_subdomains)

        # Tier 2: Dynamic Permutations & Wordlist expansion
        permutations = generate_dynamic_permutations(ct_subdomains, self.target_domain, self.wordlist)
        candidates.update(permutations)

        # Tier 0: Direct SSL SAN Check on root target
        root_sans = await asyncio.to_thread(self.extract_ssl_sans, self.target_domain)
        candidates.update(root_sans)

        # Tier 3: Parallel Async DNS Resolution
        async def _process_candidate(candidate_fqdn: str):
            if candidate_fqdn in self.discovered_domains:
                return
            self.discovered_domains.add(candidate_fqdn)

            resolved, ip = await self.resolve_domain(candidate_fqdn)
            if resolved:
                rec = {
                    "subdomain": candidate_fqdn,
                    "ip": ip or "",
                    "source": "ACTIVE_DNS",
                    "status": "resolved"
                }
                self.resolved_records.append(rec)
            else:
                rec = {
                    "subdomain": candidate_fqdn,
                    "ip": "",
                    "source": "HISTORICAL_CT_OSINT",
                    "status": "unresolved"
                }
                self.unresolved_records.append(rec)

        tasks = [_process_candidate(c) for c in candidates if c and c.endswith(self.target_domain) and c != self.target_domain]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        return self.resolved_records + self.unresolved_records


def discover_nested_subdomains_sync(
    target_domain: str,
    max_depth: int = 2,
    wordlist: Optional[List[str]] = None
) -> List[Dict[str, str]]:
    """Synchronous entry point for running 3-tier SubdomainScanner."""
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
