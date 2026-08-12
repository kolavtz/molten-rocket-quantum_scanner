import asyncio
import json
import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple
import aiodns
import dns.resolver


def dns_fallback_enumeration(domain: str) -> List[Dict[str, str]]:
    """
    Fallback subdomain discovery using dnspython when subfinder is unavailable,
    times out, or returns no candidate subdomains.
    """
    common_prefixes = [
        "www", "mail", "api", "dev", "stage", "staging", "app", "admin", "portal",
        "ns1", "ns2", "ns3", "vpn", "shop", "blog", "m", "mobile", "test", "cloud",
        "auth", "db", "status", "cpanel", "webmail", "autodiscover", "remote", "smtp",
        "secure", "store", "assets", "cdn", "static", "img", "media", "gateway",
        "dashboard", "login", "sso", "internal"
    ]
    
    discovered = set()
    results = []

    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 3.0

    # 1. Query MX, NS, CNAME for subdomains matching base domain
    for rtype in ['MX', 'NS', 'CNAME']:
        try:
            answers = resolver.resolve(domain, rtype)
            for rdata in answers:
                target_str = str(getattr(rdata, 'target', getattr(rdata, 'exchange', ''))).rstrip('.').lower()
                if target_str.endswith(f".{domain}") and target_str != domain:
                    discovered.add(target_str)
        except Exception:
            pass

    # 2. Probe common subdomains directly
    for prefix in common_prefixes:
        sub = f"{prefix}.{domain}"
        if sub in discovered:
            continue
        try:
            answers = resolver.resolve(sub, 'A')
            if answers:
                discovered.add(sub)
        except Exception:
            try:
                answers = resolver.resolve(sub, 'CNAME')
                if answers:
                    discovered.add(sub)
            except Exception:
                pass

    for sub in discovered:
        results.append({
            "host": sub,
            "source": "dns_fallback"
        })

    return results


class SubfinderScanner:
    def __init__(self, custom_binary_path: str = None):
        """
        Locates subfinder binary dynamically based on environment.
        Checks: Custom Path -> Project Root -> System PATH
        """
        self.binary_path = self._resolve_binary_path(custom_binary_path)

    def _resolve_binary_path(self, custom_path: str = None) -> str:
        if custom_path and os.path.exists(custom_path):
            return str(Path(custom_path).resolve())

        # Project root directory (3 levels up from src/scanner/)
        project_root = Path(__file__).parent.parent.parent.resolve()

        # Check for subfinder.exe or subfinder in project root
        is_win = platform.system().lower() == "windows"
        exe_name = "subfinder.exe" if is_win else "subfinder"
        local_bin = project_root / exe_name

        if local_bin.exists():
            return str(local_bin)

        # Check system PATH
        system_path = shutil.which("subfinder") or shutil.which("subfinder.exe")
        if system_path:
            return system_path

        return None

    def run_passive_enumeration(self, domain: str, timeout: int = 60) -> List[Dict[str, str]]:
        """
        Executes subfinder using subprocess with JSON output.
        Falls back to python DNS enumeration if subfinder fails or is unavailable.
        """
        if not self.binary_path:
            print(f"[!] Subfinder binary not found. Falling back to Python DNS enumeration for {domain}")
            return dns_fallback_enumeration(domain)

        cmd = [
            self.binary_path,
            "-d", domain,
            "-json",
            "-silent"
        ]

        results = []
        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=timeout
            )

            for line in process.stdout.strip().splitlines():
                if line:
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        except subprocess.TimeoutExpired:
            print(f"[!] Subfinder scan timed out for {domain}. Falling back to Python DNS enumeration.")
            results = dns_fallback_enumeration(domain)
        except (subprocess.CalledProcessError, Exception) as e:
            print(f"[!] Subfinder error: {e}. Falling back to Python DNS enumeration.")
            results = dns_fallback_enumeration(domain)

        if not results:
            results = dns_fallback_enumeration(domain)

        return results

    async def verify_active_subdomains(self, candidate_hosts: List[str]) -> Tuple[Dict[str, str], List[str]]:
        """
        Runs high-speed DNS resolution on candidates using aiodns.
        """
        if not candidate_hosts:
            return {}, []

        loop = asyncio.get_event_loop()
        resolver = aiodns.DNSResolver(loop=loop)
        resolver.nameservers = ['1.1.1.1', '8.8.8.8', '9.9.9.9']

        resolved_hosts: Dict[str, str] = {}
        unresolved_hosts: List[str] = []

        semaphore = asyncio.Semaphore(100)  # Limit concurrent sockets

        async def verify(subdomain: str):
            async with semaphore:
                try:
                    res = await resolver.query(subdomain, 'A')
                    resolved_hosts[subdomain] = res[0].host
                except aiodns.error.DNSError:
                    unresolved_hosts.append(subdomain)

        unique_hosts = list(set(candidate_hosts))
        tasks = [verify(host) for host in unique_hosts]
        await asyncio.gather(*tasks)

        return resolved_hosts, unresolved_hosts


def execute_subdomain_scan(domain: str) -> Dict:
    """Wrapper function to execute passive scan + active DNS verification."""
    scanner = SubfinderScanner()
    
    # 1. Passive Discovery via Subfinder / DNS Fallback
    raw_subfinder_data = scanner.run_passive_enumeration(domain)
    discovered_hosts = [item.get("host") for item in raw_subfinder_data if item.get("host")]

    # 2. Active DNS Verification via aiodns
    resolved, unresolved = asyncio.run(scanner.verify_active_subdomains(discovered_hosts))

    return {
        "target": domain,
        "total_passive_found": len(discovered_hosts),
        "total_live_found": len(resolved),
        "total_unresolved_found": len(unresolved),
        "live_subdomains": resolved,
        "unresolved_subdomains": unresolved,
        "sources": raw_subfinder_data
    }


def discover_nested_subdomains_sync(target_domain: str, max_depth: int = 2) -> List[Dict[str, str]]:
    """
    Synchronous wrapper for nested subdomain discovery matching service expectations.
    """
    results = execute_subdomain_scan(target_domain)
    
    discovered_list = []
    if isinstance(results, dict):
        live = results.get("live_subdomains", {})
        if isinstance(live, dict):
            for sub, ip in live.items():
                discovered_list.append({"subdomain": sub, "ip": ip})
        elif isinstance(live, list):
            for item in live:
                if isinstance(item, str):
                    discovered_list.append({"subdomain": item, "ip": None})
                elif isinstance(item, dict):
                    discovered_list.append(item)
                    
        unresolved = results.get("unresolved_subdomains", [])
        if isinstance(unresolved, dict):
            for sub, ip in unresolved.items():
                discovered_list.append({"subdomain": sub, "ip": ip})
        elif isinstance(unresolved, list):
            for item in unresolved:
                if isinstance(item, str):
                    discovered_list.append({"subdomain": item, "ip": None})
                elif isinstance(item, dict):
                    discovered_list.append(item)
    elif isinstance(results, list):
        for item in results:
            if isinstance(item, str):
                discovered_list.append({"subdomain": item, "ip": None})
            elif isinstance(item, dict):
                discovered_list.append(item)
                
    return discovered_list
