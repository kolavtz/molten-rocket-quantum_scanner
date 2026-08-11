"""
RDAP / WHOIS Enrichment Service
- Domains: python-whois (reliable, covers all TLDs)
- IPs: RDAP via rdap.arin.net (ASN, netname, org)
Both use in-memory TTL cache (1h).
"""
import time
import logging

logger = logging.getLogger(__name__)

_DOMAIN_CACHE: dict = {}
_IP_CACHE: dict = {}
_TTL = 3600

_PRIVATE_TLDS = {"example","local","test","internal","invalid","localhost","lan","home","corp"}


def _is_public_domain(domain: str) -> bool:
    tld = str(domain or "").lower().rstrip(".").rsplit(".", 1)[-1]
    return tld not in _PRIVATE_TLDS and len(tld) >= 2


def enrich_domain(domain: str) -> dict:
    """Returns {registrar, org} using python-whois."""
    domain = str(domain or "").strip().lower()
    if not domain or not _is_public_domain(domain):
        return {}
    now = time.time()
    cached = _DOMAIN_CACHE.get(domain)
    if cached and now - cached.get("cached_at", 0) < _TTL:
        return cached
    result = {"registrar": "", "org": "", "cached_at": now}
    try:
        import whois  # lazy import; only available if python-whois installed
        w = whois.whois(domain)
        reg = w.registrar or ""
        if isinstance(reg, list):
            reg = reg[0] if reg else ""
        result["registrar"] = str(reg).strip()
        org = w.org or ""
        if isinstance(org, list):
            org = org[0] if org else ""
        result["org"] = str(org).strip()
    except Exception as exc:
        logger.debug("WHOIS domain lookup failed %s: %s", domain, exc)
    _DOMAIN_CACHE[domain] = result
    return result


def enrich_ip(ip: str) -> dict:
    """Returns {netname, asn, org} using RDAP (ARIN)."""
    ip = str(ip or "").strip()
    if not ip:
        return {}
    now = time.time()
    cached = _IP_CACHE.get(ip)
    if cached and now - cached.get("cached_at", 0) < _TTL:
        return cached
    result = {"netname": "", "asn": "", "org": "", "cached_at": now}
    try:
        import requests as _req
        headers = {"Accept": "application/json", "User-Agent": "QuantumShield/1.0"}
        r = _req.get(f"https://rdap.arin.net/registry/ip/{ip}", headers=headers, timeout=5)
        if r.ok:
            data = r.json()
            result["netname"] = str(data.get("name") or "")
            result["asn"] = str(data.get("handle") or "")
            for entity in data.get("entities", []):
                vc = entity.get("vcardArray", [])
                if isinstance(vc, list) and len(vc) >= 2:
                    for prop in vc[1]:
                        if isinstance(prop, list) and len(prop) >= 4 and prop[0] == "fn":
                            fn = str(prop[3] or "").strip()
                            if fn:
                                result["org"] = fn
                                break
                if result["org"]:
                    break
    except Exception as exc:
        logger.debug("RDAP IP lookup failed %s: %s", ip, exc)
    _IP_CACHE[ip] = result
    return result

