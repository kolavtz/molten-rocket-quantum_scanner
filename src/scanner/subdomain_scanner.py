import asyncio
import json
import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple
import aiodns


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

        raise FileNotFoundError(
            f"Could not locate '{exe_name}' in project root ({project_root}) or system PATH."
        )

    def run_passive_enumeration(self, domain: str, timeout: int = 120) -> List[Dict[str, str]]:
        """
        Executes subfinder using subprocess with JSON output.
        """
        cmd = [
            self.binary_path,
            "-d", domain,
            "-json",
            "-silent"
        ]

        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=timeout
            )

            results = []
            for line in process.stdout.strip().splitlines():
                if line:
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            return results

        except subprocess.TimeoutExpired:
            print(f"[!] Subfinder scan timed out for {domain}")
            return []
        except subprocess.CalledProcessError as e:
            print(f"[!] Subfinder error: {e.stderr}")
            return []

    async def verify_active_subdomains(self, candidate_hosts: List[str]) -> Tuple[Dict[str, str], List[str]]:
        """
        Runs high-speed DNS resolution on candidates using aiodns.
        """
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
    
    # 1. Passive Discovery via Subfinder
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
