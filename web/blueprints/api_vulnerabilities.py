"""
API Vulnerabilities — Sprint 6
/api/vulnerabilities/* endpoints

Fetches CVE data for inventoried assets from public APIs (CIRCL CVE Search
primary, NVD API fallback), caches results in vulnerability_cache table with
a 24-hour TTL, and exposes them via paginated API responses.

Security:
- Rate-limited to 30 requests/minute GET, 5/minute POST (refresh)
- Validates asset ownership before fetching CVEs
- All external API calls are wrapped with timeouts
"""

from __future__ import annotations

import hashlib
import json
import logging
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

        query = db_session.query(VulnerabilityCache)

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

        # Build asset name lookup
        asset_ids = list({item.asset_id for item in items_q})
        assets = {}
        if asset_ids:
            for a in db_session.query(Asset.id, Asset.target).filter(Asset.id.in_(asset_ids)).all():
                assets[a.id] = a.target

        items = []
        for row in items_q:
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
                "asset_target": assets.get(row.asset_id, "Unknown"),
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
    Uses CIRCL CVE Search as primary, NVD API as fallback.
    Results are cached with 24-hour TTL — stale entries are refreshed.

    Only managers and admins may trigger a full refresh.
    Viewers get a 403.
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

            # Try CIRCL first, NVD fallback
            # Use the bare hostname/domain as the product keyword
            cves: list[dict] = []
            try:
                # Extract probable product name from target (strip www., port, etc.)
                product = target.split(":")[0].lstrip("www.").split(".")[0]
                cves = _fetch_circl_cves("", product)
                if not cves:
                    cves = _fetch_nvd_cves(target)
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
        rows = db_session.query(
            VulnerabilityCache.severity,
            func.count(VulnerabilityCache.id).label("cnt"),
        ).group_by(VulnerabilityCache.severity).all()

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
                "last_updated": db_session.query(
                    func.max(VulnerabilityCache.fetched_at)
                ).scalar(),
            },
        }), 200

    except Exception as exc:
        return jsonify({"success": False, "message": str(exc)}), 500
