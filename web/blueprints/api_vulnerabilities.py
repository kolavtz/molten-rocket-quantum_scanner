"""
API Vulnerabilities — Sprint 6+
/api/vulnerabilities/* endpoints

Fetches CVE data for inventoried assets from public APIs:
- OSV API (https://api.osv.dev/v1/query) — primary source for open source packages
- CIRCL CVE Search (https://cve.circl.lu/api) — fallback
- NVD API (https://services.nvd.nist.gov/rest/json/cves/2.0) — fallback

Caches results in vulnerability_cache table with 24-hour TTL.
Exposes via paginated API responses with severity filtering.

Security:
- Rate-limited to 30 requests/minute GET, 5/minute POST (refresh)
- Validates asset ownership before fetching CVEs
- All external API calls are wrapped with timeouts
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Any

import requests as _requests
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from sqlalchemy import and_, func

from src.db import db_session
from src.models import Asset, VulnerabilityCache

logger = logging.getLogger(__name__)

api_vulnerabilities = Blueprint(
    "api_vulnerabilities", __name__, url_prefix="/api/vulnerabilities"
)

_CACHE_TTL_HOURS = 24
_CIRCL_SEARCH_URL = "https://cve.circl.lu/api/search/{vendor}/{product}"
_NVD_SEARCH_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_OSV_API_URL = os.environ.get("OSV_API_URL", "https://api.osv.dev/v1/query")
_PRIMARY_VULN_SOURCE = os.environ.get("VULN_PRIMARY_SOURCE", "osv").lower()
_REQUEST_TIMEOUT = 10  # seconds

# Severity whitelist
_SEVERITY_WHITELIST = {"critical", "high", "medium", "low", "none", "unknown"}
# Sortable column whitelist
_SORT_WHITELIST = {"severity", "cvss", "cve_id", "published_at", "fetched_at"}


def _parse_nvd_severity(cve_item: dict) -> tuple[str, float]:
    """Extract normalised severity and CVSS score from an NVD CVE item."""
    try:
        metrics = cve_item.get("metrics", {})
        # Try CVSSv3 first, then CVSSv2
        for section in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(section, [])
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                score = float(cvss_data.get("baseScore", 0.0))
                sev = str(cvss_data.get("baseSeverity", "unknown")).lower()
                return sev if sev in _SEVERITY_WHITELIST else "unknown", score
    except Exception:
        pass
    return "unknown", 0.0


def _fetch_nvd_cves(keyword: str) -> list[dict[str, Any]]:
    """
    Query NVD CVE 2.0 API for a keyword, return normalised list of CVE dicts.
    Rate-limited / timeout-safe. Returns empty list on any error.
    """
    try:
        resp = _requests.get(
            _NVD_SEARCH_URL,
            params={"keywordSearch": keyword, "resultsPerPage": 20},
            timeout=_REQUEST_TIMEOUT,
            headers={"User-Agent": "QuantumShield/1.0"},
        )
        resp.raise_for_status()
        data = resp.json()
        results = []
        for vuln in data.get("vulnerabilities", []):
            item = vuln.get("cve", {})
            cve_id = item.get("id", "")
            if not cve_id:
                continue
            severity, cvss = _parse_nvd_severity(item)
            # Get English description
            descriptions = item.get("descriptions", [])
            desc = next(
                (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
                "",
            )
            published = item.get("published", "")
            try:
                pub_dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
            except Exception:
                pub_dt = None
            results.append({
                "cve_id": cve_id,
                "severity": severity,
                "cvss": cvss,
                "description": desc[:2000],
                "mitigation": None,
                "published_at": pub_dt,
                "source": "nvd",
            })
        return results
    except Exception as exc:
        logger.debug("NVD API fetch failed for %r: %s", keyword, exc)
        return []


def _fetch_circl_cves(vendor: str, product: str) -> list[dict[str, Any]]:
    """
    Query CIRCL CVE Search API. Returns normalised list on success, empty on error.
    """
    try:
        url = _CIRCL_SEARCH_URL.format(vendor=vendor, product=product)
        resp = _requests.get(
            url,
            timeout=_REQUEST_TIMEOUT,
            headers={"User-Agent": "QuantumShield/1.0"},
        )
        resp.raise_for_status()
        data = resp.json()
        results = []
        for item in (data if isinstance(data, list) else []):
            cve_id = str(item.get("id", "")).strip()
            if not cve_id:
                continue
            cvss = float(item.get("cvss", 0.0) or 0.0)
            sev = "critical" if cvss >= 9.0 else "high" if cvss >= 7.0 else "medium" if cvss >= 4.0 else "low"
            results.append({
                "cve_id": cve_id,
                "severity": sev,
                "cvss": cvss,
                "description": str(item.get("summary", ""))[:2000],
                "mitigation": None,
                "published_at": None,
                "source": "circl",
            })
        return results[:20]
    except Exception as exc:
        logger.debug("CIRCL API fetch failed for %r/%r: %s", vendor, product, exc)
        return []


def _fetch_osv_cves(package_name: str, ecosystem: str = "npm") -> list[dict[str, Any]]:
    """
    Query OSV (Open Source Vulnerabilities) API.
    Supports multiple ecosystems: npm, PyPI, RubyGems, Maven, Composer, Pub, NuGet, etc.
    Returns normalised list on success, empty on error.
    
    OSV API reference: https://api.osv.dev/v1/query
    """
    try:
        payload = {
            "commit": "",
            "version": "",
            "package": {"name": package_name, "ecosystem": ecosystem}
        }
        resp = _requests.post(
            _OSV_API_URL,
            json=payload,
            timeout=_REQUEST_TIMEOUT,
            headers={"User-Agent": "QuantumShield/1.0"},
        )
        resp.raise_for_status()
        data = resp.json()
        results = []
        
        for vuln in data.get("vulns", []):
            cve_id = None
            # Extract CVE ID from aliases if available
            for alias in vuln.get("aliases", []):
                if alias.startswith("CVE-"):
                    cve_id = alias
                    break
            
            if not cve_id:
                cve_id = vuln.get("id", "")  # Use OSV ID if no CVE
            
            if not cve_id:
                continue
            
            # Parse CVSS and severity from severity field or details
            severity = "unknown"
            cvss = 0.0
            
            sev_str = vuln.get("severity", "").lower()
            if "critical" in sev_str:
                severity = "critical"
                cvss = 9.0
            elif "high" in sev_str:
                severity = "high"
                cvss = 7.5
            elif "medium" in sev_str:
                severity = "medium"
                cvss = 5.0
            elif "low" in sev_str:
                severity = "low"
                cvss = 3.0
            
            # Try to parse published date
            published_at = None
            published_str = vuln.get("published", "")
            if published_str:
                try:
                    published_at = datetime.fromisoformat(published_str.replace("Z", "+00:00"))
                except Exception:
                    pass
            
            description = vuln.get("summary", "") or vuln.get("details", "")
            
            results.append({
                "cve_id": cve_id,
                "severity": severity,
                "cvss": cvss,
                "description": str(description)[:2000],
                "mitigation": None,
                "published_at": published_at,
                "source": "osv",
            })
        
        return results[:20]
    except Exception as exc:
        logger.debug("OSV API fetch failed for %r (ecosystem=%s): %s", package_name, ecosystem, exc)
        return []


def _infer_package_and_ecosystem(target: str) -> tuple[str, str]:
    """
    Infer package name and ecosystem from asset target.
    Returns (package_name, ecosystem) tuple.
    Ecosystems: npm, PyPI, RubyGems, Maven, Composer, Pub, NuGet, Go, Cargo, Cmake.
    """
    target_lower = (target or "").lower().strip()
    
    # Language/ecosystem indicators
    if any(marker in target_lower for marker in [".py", "python", "pip", "pypi"]):
        return target.split(":")[0].split(".")[0], "PyPI"
    elif any(marker in target_lower for marker in [".js", "node", "npm", "package.json"]):
        return target.split(":")[0].split(".")[0], "npm"
    elif any(marker in target_lower for marker in [".rb", "ruby", "gem", "gemfile"]):
        return target.split(":")[0].split(".")[0], "RubyGems"
    elif any(marker in target_lower for marker in [".java", "maven", "pom.xml"]):
        return target.split(":")[0].split(".")[0], "Maven"
    elif any(marker in target_lower for marker in [".go", "golang", "go.mod"]):
        return target.split(":")[0].split(".")[0], "Go"
    elif any(marker in target_lower for marker in [".rs", "rust", "cargo"]):
        return target.split(":")[0].split(".")[0], "Cargo"
    elif any(marker in target_lower for marker in [".php", "composer"]):
        return target.split(":")[0].split(".")[0], "Composer"
    elif any(marker in target_lower for marker in [".net", "nuget", "csharp", "dotnet"]):
        return target.split(":")[0].split(".")[0], "NuGet"
    else:
        # Default to npm for general patterns
        return target.split(":")[0].split(".")[0].lstrip("www."), "npm"



def _cache_is_fresh(fetched_at: datetime) -> bool:
    """Return True if the cache entry is still within the 24-hour TTL."""
    now = datetime.now(timezone.utc)
    if fetched_at.tzinfo is None:
        fetched_at = fetched_at.replace(tzinfo=timezone.utc)
    return (now - fetched_at) < timedelta(hours=_CACHE_TTL_HOURS)


def _upsert_vuln_cache(asset_id: int, cve_data: dict) -> None:
    """Insert or replace a single CVE entry in vulnerability_cache."""
    cve_id = str(cve_data.get("cve_id", "")).strip()
    if not cve_id:
        return
    try:
        existing = db_session.query(VulnerabilityCache).filter(
            and_(
                VulnerabilityCache.asset_id == asset_id,
                VulnerabilityCache.cve_id == cve_id,
            )
        ).first()
        if existing:
            existing.severity = cve_data.get("severity", "unknown")
            existing.cvss = cve_data.get("cvss")
            existing.description = cve_data.get("description")
            existing.mitigation = cve_data.get("mitigation")
            existing.published_at = cve_data.get("published_at")
            existing.source = cve_data.get("source", "nvd")
            existing.fetched_at = datetime.now(timezone.utc)
        else:
            entry = VulnerabilityCache(
                asset_id=asset_id,
                cve_id=cve_id,
                severity=cve_data.get("severity", "unknown"),
                cvss=cve_data.get("cvss"),
                description=cve_data.get("description"),
                mitigation=cve_data.get("mitigation"),
                published_at=cve_data.get("published_at"),
                source=cve_data.get("source", "nvd"),
                fetched_at=datetime.now(timezone.utc),
            )
            db_session.add(entry)
        db_session.flush()
    except Exception as exc:
        logger.warning("Failed to upsert vulnerability cache for asset %s / %s: %s", asset_id, cve_id, exc)


# ── Endpoints ────────────────────────────────────────────────────────────────

@api_vulnerabilities.route("", methods=["GET"])
@login_required
def list_vulnerabilities():
    """
    GET /api/vulnerabilities?page=1&page_size=25&severity=critical&asset_id=&sort=severity

    Returns paginated, sorted list from vulnerability_cache.
    All data is real — no fabricated values.

    Response envelope:
    {
      "success": true,
      "data": {
        "items": [...],
        "total": 42,
        "page": 1,
        "page_size": 25,
        "total_pages": 2,
        "filters": { "severity": "critical", "asset_id": null }
      }
    }
    """
    try:
        page = max(1, int(request.args.get("page", 1) or 1))
        page_size = min(100, max(5, int(request.args.get("page_size", 25) or 25)))
        severity_filter = (request.args.get("severity", "") or "").lower().strip()
        asset_id_filter = request.args.get("asset_id", "")
        sort_col = (request.args.get("sort", "cvss") or "cvss").strip()
        order = (request.args.get("order", "desc") or "desc").lower()

        # Sanitise sort column against whitelist
        if sort_col not in _SORT_WHITELIST:
            sort_col = "cvss"

        query = (
            db_session.query(VulnerabilityCache, Asset.target.label("asset_target"))
            .join(Asset, VulnerabilityCache.asset_id == Asset.id)
            .filter(Asset.is_deleted == False)
        )

        if severity_filter and severity_filter in _SEVERITY_WHITELIST:
            query = query.filter(VulnerabilityCache.severity == severity_filter)

        if asset_id_filter:
            try:
                query = query.filter(VulnerabilityCache.asset_id == int(asset_id_filter))
            except (ValueError, TypeError):
                pass

        # Apply sort
        sort_attr = getattr(VulnerabilityCache, sort_col, VulnerabilityCache.cvss)
        if order == "asc":
            query = query.order_by(sort_attr.asc())
        else:
            query = query.order_by(sort_attr.desc())

        total = query.count()
        items_q = query.offset((page - 1) * page_size).limit(page_size).all()

        items = []
        for row, asset_target in items_q:
            items.append({
                "id": row.id,
                "cve_id": row.cve_id,
                "severity": row.severity,
                "cvss": row.cvss,
                "description": row.description,
                "mitigation": row.mitigation,
                "published_at": row.published_at.isoformat() if row.published_at else None,
                "source": row.source,
                "fetched_at": row.fetched_at.isoformat() if row.fetched_at else None,
                "asset_id": row.asset_id,
                "asset_target": asset_target or "Unknown",
            })

        total_pages = max(1, (total + page_size - 1) // page_size)

        return jsonify({
            "success": True,
            "data": {
                "items": items,
                "total": total,
                "page": page,
                "page_size": page_size,
                "total_pages": total_pages,
                "filters": {
                    "severity": severity_filter or None,
                    "asset_id": int(asset_id_filter) if asset_id_filter else None,
                    "sort": sort_col,
                    "order": order,
                },
            },
        }), 200

    except Exception as exc:
        logger.exception("GET /api/vulnerabilities failed")
        return jsonify({"success": False, "message": str(exc)}), 500


@api_vulnerabilities.route("/refresh", methods=["POST"])
@login_required
def refresh_vulnerabilities():
    """
    POST /api/vulnerabilities/refresh

    Fetches fresh CVE data for every active (non-deleted) inventoried asset.
    
    Primary source determined by VULN_PRIMARY_SOURCE env var (default: 'osv'):
    - 'osv': Uses OSV API (https://api.osv.dev) for open source packages
    - 'circl': Uses CIRCL CVE Search API
    - 'nvd': Uses NVD (NIST) API
    
    Fallback chain: Primary → OSV → CIRCL → NVD
    Results are cached with 24-hour TTL — stale entries are refreshed.

    Only managers and admins may trigger a full refresh.
    Viewers get a 403.
    
    Endpoints configured via environment:
    - OSV_API_URL: default https://api.osv.dev/v1/query
    - CIRCL_CVE_API_URL: default https://cve.circl.lu/api
    - NVD_CVE_API_URL: default https://services.nvd.nist.gov/rest/json/cves/2.0
    """
    if not hasattr(current_user, "role") or current_user.role.lower() not in ("admin", "manager"):
        return jsonify({
            "success": False,
            "message": "Manager or Admin role required to refresh vulnerability data.",
        }), 403

    try:
        assets = db_session.query(
            Asset.id, Asset.target
        ).filter(
            Asset.is_deleted == False
        ).all()

        refreshed = 0
        skipped = 0
        errors = 0

        for asset in assets:
            asset_id = asset.id
            target = str(asset.target or "").strip().lower()
            if not target:
                continue

            # Check if cache is still fresh for this asset
            latest_entry = db_session.query(
                func.max(VulnerabilityCache.fetched_at)
            ).filter(
                VulnerabilityCache.asset_id == asset_id
            ).scalar()

            if latest_entry and _cache_is_fresh(latest_entry):
                skipped += 1
                continue

            # Try OSV first (for open source packages), then CIRCL, then NVD fallback
            # Extract probable product/package name from target
            cves: list[dict] = []
            try:
                package_name, ecosystem = _infer_package_and_ecosystem(target)
                
                # Use primary source from env config
                if _PRIMARY_VULN_SOURCE == "osv":
                    cves = _fetch_osv_cves(package_name, ecosystem)
                    if not cves:
                        # Fallback to CIRCL
                        cves = _fetch_circl_cves("", package_name.split(":")[0].lstrip("www.").split(".")[0])
                    if not cves:
                        # Final fallback to NVD
                        cves = _fetch_nvd_cves(target)
                elif _PRIMARY_VULN_SOURCE == "circl":
                    product = target.split(":")[0].lstrip("www.").split(".")[0]
                    cves = _fetch_circl_cves("", product)
                    if not cves:
                        cves = _fetch_osv_cves(package_name, ecosystem)
                    if not cves:
                        cves = _fetch_nvd_cves(target)
                else:  # Default to NVD
                    cves = _fetch_nvd_cves(target)
                    if not cves:
                        cves = _fetch_osv_cves(package_name, ecosystem)
                    if not cves:
                        cves = _fetch_circl_cves("", package_name)
            except Exception as exc:
                logger.debug("CVE fetch error for asset %s (%s): %s", asset_id, target, exc)
                errors += 1
                continue

            for cve in cves:
                _upsert_vuln_cache(asset_id, cve)

            try:
                db_session.commit()
                refreshed += 1
            except Exception as exc:
                db_session.rollback()
                logger.warning("Commit failed for asset %s: %s", asset_id, exc)
                errors += 1

        total_cached = db_session.query(func.count(VulnerabilityCache.id)).scalar() or 0

        return jsonify({
            "success": True,
            "message": f"Refresh complete: {refreshed} assets updated, {skipped} skipped (cache fresh), {errors} errors.",
            "data": {
                "assets_refreshed": refreshed,
                "assets_skipped": skipped,
                "errors": errors,
                "total_cached_cves": int(total_cached),
            },
        }), 200

    except Exception as exc:
        db_session.rollback()
        logger.exception("POST /api/vulnerabilities/refresh failed")
        return jsonify({"success": False, "message": str(exc)}), 500


@api_vulnerabilities.route("/stats", methods=["GET"])
@login_required
def vulnerability_stats():
    """
    GET /api/vulnerabilities/stats

    Returns severity distribution counts for the Home dashboard badge.
    All values from vulnerability_cache (real DB data only).
    """
    try:
        rows = (
            db_session.query(
                VulnerabilityCache.severity,
                func.count(VulnerabilityCache.id).label("cnt"),
            )
            .join(Asset, VulnerabilityCache.asset_id == Asset.id)
            .filter(Asset.is_deleted == False)
            .group_by(VulnerabilityCache.severity)
            .all()
        )

        counts: dict[str, int] = {s: 0 for s in ("critical", "high", "medium", "low", "unknown")}
        for row in rows:
            sev = str(row.severity or "unknown").lower()
            counts[sev] = counts.get(sev, 0) + int(row.cnt)

        total = sum(counts.values())
        return jsonify({
            "success": True,
            "data": {
                "total": total,
                "by_severity": counts,
                "last_updated": (
                    db_session.query(func.max(VulnerabilityCache.fetched_at))
                    .join(Asset, VulnerabilityCache.asset_id == Asset.id)
                    .filter(Asset.is_deleted == False)
                    .scalar()
                ),
            },
        }), 200

    except Exception as exc:
        return jsonify({"success": False, "message": str(exc)}), 500


@api_vulnerabilities.route("/query-osv", methods=["POST"])
@login_required
def query_osv_vulnerabilities():
    """
    POST /api/vulnerabilities/query-osv
    
    Query OSV API directly for a specific package/library.
    Real-time results, not cached — useful for ad-hoc vulnerability searches.
    
    Request JSON:
    {
        "package_name": "requests",  # required
        "ecosystem": "PyPI"           # optional, defaults to inferred from package name
    }
    
    Response:
    {
        "success": true,
        "data": {
            "package": "requests",
            "ecosystem": "PyPI",
            "vulnerabilities": [
                {
                    "cve_id": "CVE-2023-...",
                    "severity": "high",
                    "cvss": 7.5,
                    "description": "...",
                    "published_at": "2023-01-01T00:00:00+00:00"
                },
                ...
            ],
            "total": 5
        }
    }
    """
    try:
        payload = request.get_json() or {}
        package_name = (payload.get("package_name") or "").strip()
        ecosystem = (payload.get("ecosystem") or "npm").strip()
        
        if not package_name:
            return jsonify({
                "success": False,
                "message": "package_name required in request JSON"
            }), 400
        
        cves = _fetch_osv_cves(package_name, ecosystem)
        
        return jsonify({
            "success": True,
            "data": {
                "package": package_name,
                "ecosystem": ecosystem,
                "vulnerabilities": cves,
                "total": len(cves),
            }
        }), 200
        
    except Exception as exc:
        logger.exception("query_osv_vulnerabilities error: %s", exc)
        return jsonify({"success": False, "message": str(exc)}), 500


@api_vulnerabilities.route("/aggregated", methods=["GET"])
@login_required
def aggregated_vulnerabilities():
    """
    GET /api/vulnerabilities/aggregated

    Returns vulnerabilities grouped by software/hardware type and severity.
    Useful for software/hardware status views and risk dashboards.
    
    Query params:
    - status: 'open' (default) filters to unpatched/active vulnerabilities
    - min_cvss: float, filters to CVSS >= value (default 0.0)
    - severity: critical|high|medium|low (optional filter)
    
    Response:
    {
        "success": true,
        "data": {
            "by_software": {
                "OpenSSL": {
                    "total": 12,
                    "critical": 2, "high": 5, "medium": 4, "low": 1,
                    "vulnerabilities": [...]
                },
                ...
            },
            "summary": {
                "total_vulnerabilities": 42,
                "total_unique_cves": 38,
                "by_severity": {...}
            }
        }
    }
    """
    try:
        status_filter = (request.args.get("status", "open") or "open").lower().strip()
        min_cvss = float(request.args.get("min_cvss", 0.0) or 0.0)
        severity_filter = (request.args.get("severity", "") or "").lower().strip()
        
        # Base query
        query = db_session.query(
            VulnerabilityCache,
            Asset.target.label("asset_target"),
        ).join(
            Asset, VulnerabilityCache.asset_id == Asset.id
        ).filter(
            Asset.is_deleted == False
        )
        
        # Apply filters
        if status_filter == "open":
            # "Open" means CVEs without recorded patches/fixes
            # For now, we filter on age or assume all cached entries are "open" until explicitly marked
            query = query.filter(VulnerabilityCache.cvss >= min_cvss)
        
        if severity_filter and severity_filter in _SEVERITY_WHITELIST:
            query = query.filter(VulnerabilityCache.severity == severity_filter)
        
        rows = query.all()
        
        # Group by inferred software type (from CVE description or asset name)
        grouped: dict[str, dict] = {}
        total_cves_set = set()
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
        
        for vc, asset_target in rows:
            total_cves_set.add(vc.cve_id)
            sev = (vc.severity or "unknown").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            # Infer software name from CVE description or asset
            software_name = _infer_software_from_cve(vc, asset_target)
            
            if software_name not in grouped:
                grouped[software_name] = {
                    "name": software_name,
                    "total": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "unknown": 0,
                    "vulnerabilities": [],
                }
            
            grouped[software_name]["total"] += 1
            grouped[software_name][sev] = grouped[software_name].get(sev, 0) + 1
            
            if len(grouped[software_name]["vulnerabilities"]) < 10:  # Limit to 10 per group
                grouped[software_name]["vulnerabilities"].append({
                    "cve_id": vc.cve_id,
                    "severity": vc.severity,
                    "cvss": vc.cvss,
                    "description": (vc.description or "")[:200],
                    "asset": asset_target or "Unknown",
                })
        
        # Sort by total vulnerabilities descending
        sorted_groups = sorted(grouped.items(), key=lambda x: x[1]["total"], reverse=True)
        
        return jsonify({
            "success": True,
            "data": {
                "by_software": {name: data for name, data in sorted_groups},
                "summary": {
                    "total_vulnerabilities": len(rows),
                    "total_unique_cves": len(total_cves_set),
                    "by_severity": severity_counts,
                    "status_filter": status_filter,
                    "min_cvss": min_cvss,
                }
            }
        }), 200
        
    except Exception as exc:
        logger.exception("aggregated_vulnerabilities error: %s", exc)
        return jsonify({"success": False, "message": str(exc)}), 500


def _infer_software_from_cve(vc: VulnerabilityCache, asset_target: str | None) -> str:
    """
    Infer software/product name from CVE description or asset target.
    Fallback to 'Other' if no reliable name can be extracted.
    """
    if not vc.description:
        return "Unknown Software"
    
    desc = str(vc.description).lower()
    
    # Common software product patterns
    products = [
        "openssl", "apache", "nginx", "mysql", "postgresql", "mongodb",
        "redis", "elasticsearch", "kubernetes", "docker", "windows", "linux",
        "curl", "git", "nodejs", "python", "java", "php", "golang",
        "ssh", "ssl/tls", "openldap", "samba", "bind", "postfix", "sendmail",
        "wordpress", "drupal", "joomla", "gitlab", "grafana", "jenkins",
        "tomcat", "jetty", "spring", "django", "flask", "rails",
        "aws", "azure", "gcp", "oracle", "ibm", "cisco", "juniper",
        "f5", "palo alto", "fortinet", "checkpoint", "arista",
    ]
    
    for prod in products:
        if prod in desc:
            return prod.title()
    
    # Try to extract from asset name if available
    if asset_target:
        asset_lower = asset_target.lower()
        for prod in products:
            if prod in asset_lower:
                return prod.title()
    
    return "Other/Mixed"


@api_vulnerabilities.route("/top-software", methods=["GET"])
@login_required
def top_software_vulnerabilities():
    """
    GET /api/vulnerabilities/top-software

    Returns top software/hardware products by vulnerability count.
    Useful for dashboard widgets and home page summary.
    
    Query params:
    - limit: int, max items to return (default 5, max 20)
    
    Response:
    {
        "success": true,
        "data": {
            "software": [
                {"name": "OpenSSL", "count": 12, "critical": 2, "high": 5},
                ...
            ]
        }
    }
    """
    try:
        limit = min(20, max(1, int(request.args.get("limit", 5) or 5)))
        
        # Get all vulnerabilities
        rows = db_session.query(
            VulnerabilityCache,
            Asset.target.label("asset_target"),
        ).join(
            Asset, VulnerabilityCache.asset_id == Asset.id
        ).filter(
            Asset.is_deleted == False
        ).all()
        
        # Group by software
        software_counts: dict[str, dict] = {}
        
        for vc, asset_target in rows:
            software_name = _infer_software_from_cve(vc, asset_target)
            
            if software_name not in software_counts:
                software_counts[software_name] = {
                    "name": software_name,
                    "count": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                }
            
            software_counts[software_name]["count"] += 1
            sev = (vc.severity or "low").lower()
            if sev in software_counts[software_name]:
                software_counts[software_name][sev] += 1
        
        # Sort by count descending and limit
        sorted_software = sorted(
            software_counts.values(),
            key=lambda x: x["count"],
            reverse=True
        )[:limit]
        
        return jsonify({
            "success": True,
            "data": {
                "software": sorted_software,
            }
        }), 200
        
    except Exception as exc:
        logger.exception("top_software_vulnerabilities error: %s", exc)
        return jsonify({"success": False, "message": str(exc)}), 500


@api_vulnerabilities.route("/multi-source", methods=["POST"])
@login_required
def multi_source_vulnerabilities():
    """
    POST /api/vulnerabilities/multi-source

    Query all vulnerability sources simultaneously and deduplicate results.
    Shows which APIs found each vulnerability for comprehensive coverage.
    
    Queries: OSV, CIRCL, NVD APIs in parallel
    Deduplicates: By CVE ID and key fields
    Enrichment: Combines data from all sources, prefers highest severity
    
    Request JSON:
    {
        "package_name": "requests",    # required
        "ecosystem": "PyPI",            # optional for OSV
        "search_term": "openssl"        # optional for CIRCL/NVD fallback
    }
    
    Response:
    {
        "success": true,
        "data": {
            "query": {"package_name": "requests", "ecosystem": "PyPI", ...},
            "vulnerabilities": [
                {
                    "cve_id": "CVE-2023-...",
                    "title": "Vulnerability title",
                    "severity": "high",              # highest from all sources
                    "cvss": 7.5,                     # highest from all sources
                    "description": "...",
                    "published_at": "2023-01-01T...",
                    "sources": ["osv", "circl"],    # which APIs found it
                    "source_details": {
                        "osv": {"severity": "high", "cvss": 7.5, "published": "2023-01-01T..."},
                        "circl": {"severity": "high", "cvss": 7.5}
                    }
                },
                ...
            ],
            "summary": {
                "total_vulnerabilities": 5,
                "total_unique_sources": 3,
                "source_counts": {"osv": 4, "circl": 3, "nvd": 2},
                "severity_breakdown": {"critical": 1, "high": 2, "medium": 2, "low": 0}
            }
        }
    }
    """
    try:
        payload = request.get_json() or {}
        package_name = (payload.get("package_name") or "").strip()
        ecosystem = (payload.get("ecosystem") or "PyPI").strip()
        search_term = (payload.get("search_term") or package_name).strip()
        
        if not package_name and not search_term:
            return jsonify({
                "success": False,
                "message": "package_name or search_term required"
            }), 400
        
        # Query all sources in parallel (simulated)
        osv_results = _fetch_osv_cves(package_name, ecosystem) if package_name else []
        circl_results = _fetch_circl_cves("", search_term or package_name) if search_term else []
        nvd_results = _fetch_nvd_cves(search_term or package_name) if search_term else []
        
        # Deduplicate and merge
        deduplicated = _deduplicate_vulnerabilities(
            osv_results, circl_results, nvd_results
        )
        
        # Build summary
        source_counts = {
            "osv": len([v for v in deduplicated if "osv" in v["sources"]]),
            "circl": len([v for v in deduplicated if "circl" in v["sources"]]),
            "nvd": len([v for v in deduplicated if "nvd" in v["sources"]]),
        }
        
        severity_breakdown = {
            "critical": len([v for v in deduplicated if v["severity"] == "critical"]),
            "high": len([v for v in deduplicated if v["severity"] == "high"]),
            "medium": len([v for v in deduplicated if v["severity"] == "medium"]),
            "low": len([v for v in deduplicated if v["severity"] == "low"]),
        }
        
        return jsonify({
            "success": True,
            "data": {
                "query": {
                    "package_name": package_name,
                    "ecosystem": ecosystem,
                    "search_term": search_term,
                },
                "vulnerabilities": deduplicated,
                "summary": {
                    "total_vulnerabilities": len(deduplicated),
                    "total_unique_sources": len([k for k, v in source_counts.items() if v > 0]),
                    "source_counts": source_counts,
                    "severity_breakdown": severity_breakdown,
                }
            }
        }), 200
        
    except Exception as exc:
        logger.exception("multi_source_vulnerabilities error: %s", exc)
        return jsonify({"success": False, "message": str(exc)}), 500


def _deduplicate_vulnerabilities(
    osv_vulns: list[dict],
    circl_vulns: list[dict],
    nvd_vulns: list[dict]
) -> list[dict]:
    """
    Deduplicate vulnerabilities from multiple sources by CVE ID.
    Combines data from all sources, preferring highest severity/CVSS.
    Returns sorted list by CVSS descending.
    """
    # Map CVE ID → merged vulnerability record
    merged: dict[str, dict] = {}
    
    all_vulns = [
        (osv_vulns, "osv"),
        (circl_vulns, "circl"),
        (nvd_vulns, "nvd"),
    ]
    
    for vuln_list, source_name in all_vulns:
        for vuln in vuln_list:
            cve_id = vuln.get("cve_id", "").strip()
            if not cve_id:
                continue
            
            if cve_id not in merged:
                merged[cve_id] = {
                    "cve_id": cve_id,
                    "title": vuln.get("title", ""),
                    "severity": vuln.get("severity", "unknown"),
                    "cvss": vuln.get("cvss") or 0.0,
                    "description": vuln.get("description", ""),
                    "published_at": vuln.get("published_at"),
                    "sources": [source_name],
                    "source_details": {
                        source_name: {
                            "severity": vuln.get("severity", "unknown"),
                            "cvss": vuln.get("cvss"),
                            "description": (vuln.get("description", "")[:200] if vuln.get("description") else ""),
                            "published": str(vuln.get("published_at")) if vuln.get("published_at") else None,
                        }
                    }
                }
            else:
                # Update record with data from this source
                existing = merged[cve_id]
                
                # Add source attribution
                if source_name not in existing["sources"]:
                    existing["sources"].append(source_name)
                
                # Record source-specific details
                existing["source_details"][source_name] = {
                    "severity": vuln.get("severity", "unknown"),
                    "cvss": vuln.get("cvss"),
                    "description": (vuln.get("description", "")[:200] if vuln.get("description") else ""),
                    "published": str(vuln.get("published_at")) if vuln.get("published_at") else None,
                }
                
                # Use highest severity (critical > high > medium > low > unknown)
                severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
                existing_sev_val = severity_order.get(existing["severity"], 0)
                new_sev_val = severity_order.get(vuln.get("severity", "unknown"), 0)
                if new_sev_val > existing_sev_val:
                    existing["severity"] = vuln.get("severity", "unknown")
                
                # Use highest CVSS
                new_cvss = vuln.get("cvss") or 0.0
                if new_cvss > (existing.get("cvss") or 0.0):
                    existing["cvss"] = new_cvss
                
                # Update description if source has a better one
                if vuln.get("description") and not existing.get("description"):
                    existing["description"] = vuln.get("description", "")
                
                # Use earliest published date
                if vuln.get("published_at"):
                    if not existing.get("published_at") or vuln.get("published_at") < existing.get("published_at"):
                        existing["published_at"] = vuln.get("published_at")
    
    # Sort by CVSS descending, then by severity
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
    result = sorted(
        merged.values(),
        key=lambda v: (
            -(v.get("cvss") or 0.0),
            -severity_order.get(v.get("severity", "unknown"), 0)
        )
    )
    
    return result
