"""
Subdomain Discovery Service
Manages the identification, tracking, and promotion of subdomains discovered during scans.
"""
import logging
from datetime import datetime, timezone
from sqlalchemy import and_, func
import json
import ipaddress
import os
import re

try:
    import dns
    import dns.exception  # type: ignore
    import dns.resolver  # type: ignore
except Exception:
    dns = None  # type: ignore

from src.db import db_session
from src.models import Asset, Subdomain, Certificate, Scan

logger = logging.getLogger(__name__)

DEFAULT_COMMON_SUBDOMAIN_LABELS = (
    "www",
    "api",
    "mail",
    "smtp",
    "imap",
    "pop",
    "ns1",
    "ns2",
    "m",
    "app",
    "portal",
    "admin",
    "auth",
    "cdn",
    "static",
    "blog",
    "dev",
    "stage",
    "beta",
    "test",
)


def _normalize_domain_candidate(value) -> str:
    candidate = str(value or "").strip().lower().rstrip(".")
    if candidate.startswith("*."):
        candidate = candidate[2:]
    if not candidate or "." not in candidate:
        return ""
    try:
        ipaddress.ip_address(candidate)
        return ""
    except Exception:
        return candidate


def _extract_domain_from_dns_value(record_type: str, record_value) -> str:
    value = str(record_value or "").strip()
    rtype = str(record_type or "").strip().upper()
    if not value:
        return ""
    if rtype == "MX":
        parts = value.split()
        value = parts[-1] if parts else value
    return _normalize_domain_candidate(value)


def _is_valid_subdomain_candidate(candidate: str, parent_domain: str) -> bool:
    normalized_candidate = _normalize_domain_candidate(candidate)
    normalized_parent = _normalize_domain_candidate(parent_domain)
    if not normalized_candidate or not normalized_parent:
        return False
    return normalized_candidate.endswith(f".{normalized_parent}") and normalized_candidate != normalized_parent


def _collect_dns_candidates_via_dnspython(domain: str) -> set[str]:
    """Collect related domain candidates using dnspython record enumeration.

    This intentionally treats "no answer" as normal and keeps queries best-effort.
    """
    root = _normalize_domain_candidate(domain)
    if not root:
        return set()

    if dns is None:
        # dnspython is optional at runtime in some environments.
        return set()

    resolver = dns.resolver.Resolver()
    resolver.timeout = 1.0
    resolver.lifetime = 2.0

    nameserver_override = str(os.getenv("QSS_DNS_NAMESERVERS", "") or "").strip()
    if nameserver_override:
        servers = [s.strip() for s in nameserver_override.split(",") if s.strip()]
        if servers:
            resolver.nameservers = servers

    record_types = (
        "A",
        "AAAA",
        "MX",
        "NS",
        "TXT",
        "CNAME",
        "SOA",
        "SRV",
        "CAA",
        "PTR",
        "DNSKEY",
        "DS",
    )

    discovered: set[str] = set()

    for record_type in record_types:
        try:
            answers = resolver.resolve(root, record_type, lifetime=2.0)
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            break
        except (dns.resolver.NoNameservers, dns.exception.Timeout):
            continue
        except dns.exception.DNSException:
            continue

        for ans in answers:
            text_val = str(ans).strip()
            normalized = _extract_domain_from_dns_value(record_type, text_val)
            if normalized:
                discovered.add(normalized)

            if record_type == "TXT":
                for match in re.finditer(r"(?:include:|redirect=)?([A-Za-z0-9*._-]+\.[A-Za-z]{2,})", text_val):
                    txt_domain = _normalize_domain_candidate(match.group(1))
                    if txt_domain:
                        discovered.add(txt_domain)

            # Record-specific host extraction for richer subdomain coverage.
            special_value = ""
            if record_type == "MX":
                special_value = str(getattr(ans, "exchange", "") or "")
            elif record_type == "NS":
                special_value = str(getattr(ans, "target", "") or "")
            elif record_type == "CNAME":
                special_value = str(getattr(ans, "target", "") or "")
            elif record_type == "SOA":
                special_value = str(getattr(ans, "mname", "") or "")
            elif record_type == "SRV":
                special_value = str(getattr(ans, "target", "") or "")
            elif record_type == "PTR":
                special_value = str(getattr(ans, "target", "") or "")

            if special_value:
                special_normalized = _normalize_domain_candidate(special_value)
                if special_normalized:
                    discovered.add(special_normalized)

    return discovered


def _collect_common_subdomains_via_dns(parent_domain: str) -> set[str]:
    """Attempt discovery of concrete subdomains by resolving common labels.

    This is intentionally conservative and bounded to avoid expensive brute-force scans.
    """
    root = _normalize_domain_candidate(parent_domain)
    if not root or dns is None:
        return set()

    labels_override = str(os.getenv("QSS_SUBDOMAIN_WORDLIST", "") or "").strip()
    labels = (
        tuple(x.strip().lower() for x in labels_override.split(",") if x.strip())
        if labels_override
        else DEFAULT_COMMON_SUBDOMAIN_LABELS
    )
    labels = tuple(dict.fromkeys(labels))[:50]

    resolver = dns.resolver.Resolver()
    resolver.timeout = 1.0
    resolver.lifetime = 2.0

    nameserver_override = str(os.getenv("QSS_DNS_NAMESERVERS", "") or "").strip()
    if nameserver_override:
        servers = [s.strip() for s in nameserver_override.split(",") if s.strip()]
        if servers:
            resolver.nameservers = servers

    discovered: set[str] = set()
    for label in labels:
        fqdn = _normalize_domain_candidate(f"{label}.{root}")
        if not fqdn:
            continue
        for record_type in ("A", "AAAA", "CNAME"):
            try:
                answers = resolver.resolve(fqdn, record_type, lifetime=2.0)
                if answers:
                    discovered.add(fqdn)
                    break
            except dns.resolver.NoAnswer:
                continue
            except dns.resolver.NXDOMAIN:
                break
            except (dns.resolver.NoNameservers, dns.exception.Timeout):
                continue
            except dns.exception.DNSException:
                continue

    return discovered

class SubdomainService:
    @staticmethod
    def get_subdomains_for_asset(parent_asset_id: int, include_inventoried: bool = False):
        """Fetch discovered subdomains for a specific parent asset."""
        query = db_session.query(Subdomain).filter(
            Subdomain.parent_asset_id == parent_asset_id,
            Subdomain.is_deleted == False
        )
        if not include_inventoried:
            query = query.filter(Subdomain.is_inventoried == False)
        
        return query.order_by(Subdomain.subdomain.asc()).all()

    @staticmethod
    def sync_from_certificate(asset_id: int, scan_id: int):
        """
        Extract subdomains from the certificate associated with a scan 
        and populate the subdomains table.
        """
        try:
            asset = db_session.query(Asset).filter(Asset.id == asset_id).first()
            if not asset:
                return 0

            parent_domain = _normalize_domain_candidate(asset.target)
            if not parent_domain:
                return 0

            # Mitigate legacy wildcard rows so UI shows concrete domains only.
            wildcard_rows = db_session.query(Subdomain).filter(
                Subdomain.parent_asset_id == asset_id,
                Subdomain.is_deleted == False,
                Subdomain.subdomain.like("*.%"),
            ).all()
            for row in wildcard_rows:
                row.is_deleted = True

            # 0. Active DNS enumeration using dnspython for discovery enrichment
            candidates = _collect_dns_candidates_via_dnspython(parent_domain)
            # 0b. Resolve a bounded common-label wordlist for concrete subdomains
            candidates.update(_collect_common_subdomains_via_dns(parent_domain))

            # Get the certificate captured in this scan
            cert = db_session.query(Certificate).filter(
                Certificate.asset_id == asset_id,
                Certificate.scan_id == scan_id
            ).first()

            # 1. Subject CN
            if cert and cert.subject_cn:
                normalized_cn = _normalize_domain_candidate(cert.subject_cn)
                if normalized_cn:
                    candidates.add(normalized_cn)
            
            # 2. SAN Domains
            if cert and cert.san_domains:
                for d in cert.san_domains.split(','):
                    normalized_san = _normalize_domain_candidate(d)
                    if normalized_san:
                        candidates.add(normalized_san)

            # 3. DNS-derived hostnames from scan.report_json
            scan_row = db_session.query(Scan).filter(Scan.id == scan_id).first()
            if scan_row is not None:
                parsed_report = None
                raw_report = getattr(scan_row, "report_json", None)
                if isinstance(raw_report, dict):
                    parsed_report = raw_report
                elif isinstance(raw_report, str):
                    text_payload = raw_report.strip()
                    if text_payload:
                        try:
                            parsed_report = json.loads(text_payload)
                        except Exception:
                            parsed_report = None

                if isinstance(parsed_report, dict):
                    for record in (parsed_report.get("dns_records") or []):
                        hostname = _normalize_domain_candidate(record.get("hostname"))
                        if hostname:
                            candidates.add(hostname)
                        domain_from_value = _extract_domain_from_dns_value(
                            str(record.get("record_type") or ""),
                            record.get("record_value"),
                        )
                        if domain_from_value:
                            candidates.add(domain_from_value)

            count = 0
            for domain in candidates:
                # Only real subdomains (not wildcard roots like *.domain.com -> domain.com)
                if _is_valid_subdomain_candidate(domain, parent_domain):
                    # Check if already exists in subdomains
                    existing = db_session.query(Subdomain).filter(
                        Subdomain.parent_asset_id == asset_id,
                        Subdomain.subdomain == domain
                    ).first()

                    if not existing:
                        new_sub = Subdomain(
                            parent_asset_id=asset_id,
                            subdomain=domain,
                            record_type='DNS',
                            is_inventoried=False,
                            discovered_at=datetime.now(timezone.utc).replace(tzinfo=None)
                        )
                        db_session.add(new_sub)
                        count += 1
            
            if count > 0:
                db_session.commit()
                logger.info("Discovered %d new subdomains for asset %s", count, asset_id)
            
            return count

        except Exception as e:
            db_session.rollback()
            logger.exception("Failed to sync subdomains from certificate for asset %s", asset_id)
            return 0

    @staticmethod
    def promote_to_inventory(subdomain_id: int, owner: str = "System"):
        """
        Promote a discovered subdomain to a full Asset.
        """
        try:
            sub = db_session.query(Subdomain).filter(Subdomain.id == subdomain_id).first()
            if not sub or sub.is_inventoried:
                return None

            # Check if an asset with this target already exists
            existing_asset = db_session.query(Asset).filter(
                func.lower(Asset.target) == sub.subdomain.lower()
            ).first()

            if existing_asset:
                # Mark all matching subdomain rows as inventoried when target exists.
                matching_rows = db_session.query(Subdomain).filter(
                    func.lower(Subdomain.subdomain) == sub.subdomain.lower(),
                    Subdomain.is_deleted == False,
                ).all()
                for row in matching_rows:
                    row.is_inventoried = True
                db_session.commit()
                return existing_asset

            # Create new asset
            new_asset = Asset(
                target=sub.subdomain,
                asset_type='Subdomain',
                owner=owner,
                risk_level='Medium', # Default
                created_at=datetime.now(timezone.utc).replace(tzinfo=None)
            )
            db_session.add(new_asset)
            db_session.flush() # Get ID

            # Mark all matching subdomain rows as inventoried for this promoted host.
            matching_rows = db_session.query(Subdomain).filter(
                func.lower(Subdomain.subdomain) == sub.subdomain.lower(),
                Subdomain.is_deleted == False,
            ).all()
            for row in matching_rows:
                row.is_inventoried = True
            db_session.commit()
            
            logger.info("Promoted subdomain %s to asset inventory (ID: %s)", sub.subdomain, new_asset.id)
            return new_asset

        except Exception as e:
            db_session.rollback()
            logger.exception("Failed to promote subdomain %s", subdomain_id)
            return None
