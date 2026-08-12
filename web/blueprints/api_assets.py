"""
API Assets - /api/assets and /api/discovery endpoints
Paginated, sortable, searchable asset and discovery data.
"""

import json
import socket
import dns.resolver
import requests as http_requests
from flask import Blueprint, request, jsonify
from flask_login import login_required
from src.db import db_session as SessionLocal
from src.models import (
    Asset, Certificate, Scan, Subdomain,
    DiscoveryDomain, DiscoverySSL, DiscoveryIP, DiscoverySoftware,
    PQCClassification, CBOMEntry
)
from src.services.subdomain_service import SubdomainService
from src.services import rdap_service
from utils.api_helper import (
    paginated_response, api_response, apply_soft_delete_filter,
    extract_pagination_params, validate_pagination_params,
    search_filter, format_asset_row, format_datetime
)
from sqlalchemy import func, or_, and_
from middleware.api_auth import api_guard

_PRIVATE_TLDS = {"example", "local", "test", "internal", "invalid", "localhost", "lan"}

def _is_public_domain(domain: str) -> bool:
    """Return True if domain looks like a real public domain worth enriching."""
    tld = str(domain or "").lower().rstrip(".").rsplit(".", 1)[-1]
    return tld not in _PRIVATE_TLDS and len(tld) >= 2

api_assets = Blueprint("api_assets", __name__, url_prefix="/api")


def _discovery_detected_at_expr(model):
    args = []
    if hasattr(model, "promoted_at"):
        args.append(model.promoted_at)
    if hasattr(model, "scan_id"):
        args.extend([Scan.completed_at, Scan.scanned_at, Scan.started_at, Scan.created_at])
    if hasattr(model, "discovered_at"):
        args.append(model.discovered_at)
    if hasattr(model, "created_at"):
        args.append(model.created_at)
    args.append(func.now())
    return func.coalesce(*args)


@api_assets.route("/assets/<int:asset_id>/scans", methods=["GET"])
@api_guard
def get_asset_scans(asset_id):
    """
    GET /api/assets/{asset_id}/scans?page=1&page_size=10
    
    Returns scan history for a specific asset.
    """
    try:
        from web.routes.assets import build_asset_scans_api_response

        params = extract_pagination_params()
        page, page_size = validate_pagination_params(params["page"], min(params["page_size"], 50))
        data = build_asset_scans_api_response(asset_id, page=page, page_size=page_size)
        if data is None:
            return api_response(success=False, message="Asset not found", status_code=404)
        return api_response(success=True, data=data)[0], 200
    except Exception as exc:
        return api_response(success=False, message=f"Failed to load asset scans: {exc}", status_code=500)[0], 500


@api_assets.route("/assets", methods=["GET"])
@api_guard
def get_assets():
    """
    GET /api/assets?page=1&page_size=25&sort=asset_name&order=asc&q=example
    """
    try:
        from web.routes.assets import build_assets_api_response

        params = extract_pagination_params()
        page, page_size = validate_pagination_params(params["page"], params["page_size"])
        asset_type = request.args.get("asset_type", "", type=str).strip()
        risk_min = request.args.get("risk_min", None, type=int)
        risk_max = request.args.get("risk_max", None, type=int)
        data, filters = build_assets_api_response(
            page=page,
            page_size=page_size,
            sort=params["sort"] or "name",
            order=params["order"],
            search=params["search"],
            asset_type=asset_type,
            risk_min=risk_min,
            risk_max=risk_max,
        )
        payload = {
            "success": True,
            "data": data,
            "filters": filters,
        }
        if isinstance(data, dict):
            payload.update(data)
        return payload, 200
    except Exception as exc:
        return api_response(success=False, message=f"Failed to load assets: {exc}", status_code=500)[0], 500


@api_assets.route("/discovery", methods=["GET"])
@api_guard
def get_discovery():
    """
    GET /api/discovery?tab=domains&page=1&page_size=25&sort=detection_date&order=desc&q=
    """
    try:
        tab = request.args.get("tab", "domains", type=str).lower()
        
        tab_model_map = {
            "domains": DiscoveryDomain,
            "ssl": DiscoverySSL,
            "ips": DiscoveryIP,
            "software": DiscoverySoftware,
            "subdomains": Subdomain
        }
        
        if tab not in tab_model_map:
            return api_response(
                success=False,
                message=f"Invalid tab: {tab}.",
                status_code=400
            )[0], 400
        
        model = tab_model_map[tab]
        db = SessionLocal()
        params = extract_pagination_params()
        page, page_size = validate_pagination_params(params["page"], params["page_size"])
        
        # Build deduplication subquery: keep only the latest (MAX id) per unique identifier
        _dedup_key_map = {
            "domains": DiscoveryDomain.domain,
            "ssl": DiscoverySSL.endpoint,
            "ips": DiscoveryIP.ip_address,
            "software": DiscoverySoftware.product,
            "subdomains": Subdomain.subdomain,
        }
        dedup_col = _dedup_key_map[tab]
        normalized_col = func.trim(func.lower(dedup_col))

        dedup_sq = (
            db.query(func.max(model.id))
            .filter(model.is_deleted == False)
            .filter(dedup_col.isnot(None))
            .filter(normalized_col != "")
            .filter(normalized_col != "--")
            .group_by(normalized_col)
            .scalar_subquery()
        )

        # Build query
        detected_at_expr = _discovery_detected_at_expr(model)
        if hasattr(model, "scan_id"):
            query = (
                db.query(model, detected_at_expr.label("detected_at"))
                .outerjoin(Scan, model.scan_id == Scan.id)
                .filter(model.is_deleted == False)
                .filter(model.id.in_(dedup_sq))
            )
        else:
            query = (
                db.query(model, detected_at_expr.label("detected_at"))
                .filter(model.is_deleted == False)
                .filter(model.id.in_(dedup_sq))
            )
        
        # Apply search
        if params["search"]:
            search_val = f"%{params['search']}%"
            if tab == "domains":
                query = query.filter(DiscoveryDomain.domain.ilike(search_val))
            elif tab == "ssl":
                query = query.filter(DiscoverySSL.endpoint.ilike(search_val))
            elif tab == "ips":
                query = query.filter(DiscoveryIP.ip_address.ilike(search_val))
            elif tab == "software":
                query = query.filter(DiscoverySoftware.product.ilike(search_val))
            elif tab == "subdomains":
                query = query.filter(Subdomain.subdomain.ilike(search_val))
        
        # Total
        total = query.count()
        
        # Sorting
        if params["sort"] and hasattr(model, params["sort"]):
            sort_col = getattr(model, params["sort"])
        elif params["sort"] in {"detection_date", "created_at", "detected_at"}:
            sort_col = detected_at_expr
        else:
            sort_col = detected_at_expr
        if params["order"].lower() == "desc":
            query = query.order_by(sort_col.desc())
        else:
            query = query.order_by(sort_col.asc())
        
        # Pagination
        items = query.offset((page - 1) * page_size).limit(page_size).all()
        
        # Format
        items_data = []
        def _risk_score_from_level(level: str) -> int:
            lookup = {
                "critical": 90,
                "high": 75,
                "medium": 50,
                "low": 25,
            }
            return int(lookup.get(str(level or "").strip().lower(), 50))

        for item, detected_at in items:
            asset_name = getattr(item.asset, 'target', '') if hasattr(item, 'asset') and item.asset else ''
            asset_risk_level = getattr(item.asset, 'risk_level', '') if hasattr(item, 'asset') and item.asset else ''

            # Identifier mapping
            identifier = ""
            if isinstance(item, DiscoveryDomain): identifier = item.domain
            elif isinstance(item, DiscoverySSL): identifier = item.endpoint
            elif isinstance(item, DiscoveryIP): identifier = item.ip_address
            elif isinstance(item, DiscoverySoftware): identifier = item.product
            elif isinstance(item, Subdomain): identifier = item.subdomain

            row = {
                "id": item.id,
                "identifier": identifier,
                "status": getattr(item, "status", "new"),
                "detection_date": format_datetime(detected_at or getattr(item, "discovered_at", None)),
                "asset_name": asset_name,
                "asset_risk_level": asset_risk_level,
                "risk_score": _risk_score_from_level(asset_risk_level),
                "scan_id": getattr(item, "scan_id", None),
                "asset_id": getattr(item, "asset_id", None) if not isinstance(item, Subdomain) else None,
                "is_inventoried": bool(getattr(item, "is_inventoried", False)),
                "promoted": bool(getattr(item, "promoted_to_inventory", False) or getattr(item, "is_inventoried", False)),
                "record_type": getattr(item, "record_type", "A"),
            }

            if isinstance(item, DiscoveryDomain):
                registrar = str(item.registrar or "").strip()
                org = ""
                if _is_public_domain(item.domain):
                    rdap = rdap_service.enrich_domain(item.domain)
                    if not registrar:
                        registrar = rdap.get("registrar", "")
                    org = rdap.get("org", "")
                row.update({
                    "domain_name": item.domain,
                    "registrar": registrar,
                    "org": org,
                })
            elif isinstance(item, DiscoverySSL):
                row.update({
                    "endpoint": item.endpoint,
                    "tls_version": item.tls_version,
                    "cipher_suite": item.cipher_suite,
                    "issuer": item.issuer,
                    "valid_until": format_datetime(item.valid_until),
                    "subject_cn": item.subject_cn,
                })
            elif isinstance(item, DiscoveryIP):
                netname = str(item.netname or "").strip()
                asn = str(item.asn or "").strip()
                org = ""
                if not netname or not asn:
                    rdap = rdap_service.enrich_ip(item.ip_address)
                    netname = netname or rdap.get("netname", "")
                    asn = asn or rdap.get("asn", "")
                    org = rdap.get("org", "")
                row.update({
                    "ip_address": item.ip_address,
                    "subnet": item.subnet,
                    "asn": asn,
                    "netname": netname,
                    "org": org,
                    "location": item.location,
                })
            elif isinstance(item, DiscoverySoftware):
                row.update({
                    "product": item.product,
                    "version": item.version,
                    "category": item.category,
                    "cpe": item.cpe,
                })
            elif isinstance(item, Subdomain):
                row.update({
                    "domain_name": item.subdomain,
                    "record_type": item.record_type,
                    "parent_asset_id": item.parent_asset_id,
                })

            items_data.append(row)
        
        db.close()
        return paginated_response(
            items=items_data,
            total=total,
            page=page,
            page_size=page_size,
            filters={"tab": tab, "sort": params["sort"], "order": params["order"], "search": params["search"]}
        )[0], 200
    
    except Exception as e:
        return api_response(success=False, message=str(e), status_code=500)[0], 500


@api_assets.route("/discovery/ip-locations", methods=["GET"])
@api_guard
def get_discovery_ip_locations():
    """
    GET /api/discovery/ip-locations?limit=200

    Returns discovered IP rows enriched with geo coordinates for map visualization.
    """
    try:
        import hashlib
        from src.services.geo_service import GeoService

        limit = max(1, min(request.args.get("limit", 200, type=int), 500))
        geo_service = GeoService()
        db = SessionLocal()

        # Gather target candidates across DiscoveryIP, DiscoveryDomain, DiscoverySSL & Asset
        targets_pool: list[dict[str, Any]] = []

        # 1. DiscoveryIP
        ip_rows = db.query(DiscoveryIP).filter(DiscoveryIP.is_deleted == False).order_by(DiscoveryIP.id.desc()).limit(limit).all()
        for r in ip_rows:
            ip = str(getattr(r, "ip_address", "") or "").strip()
            if ip:
                targets_pool.append({
                    "id": int(r.id),
                    "ip": ip,
                    "target": ip,
                    "asset_id": getattr(r, "asset_id", None),
                    "status": str(getattr(r, "status", "") or "confirmed"),
                    "type": "IP Subnet",
                })

        # 2. DiscoveryDomain
        domain_rows = db.query(DiscoveryDomain).filter(DiscoveryDomain.is_deleted == False).order_by(DiscoveryDomain.id.desc()).limit(limit).all()
        for r in domain_rows:
            dom = str(getattr(r, "domain", "") or "").strip()
            if dom:
                targets_pool.append({
                    "id": int(r.id),
                    "ip": dom,
                    "target": dom,
                    "asset_id": getattr(r, "asset_id", None),
                    "status": str(getattr(r, "status", "") or "confirmed"),
                    "type": "Domain",
                })

        # 3. DiscoverySSL
        ssl_rows = db.query(DiscoverySSL).filter(DiscoverySSL.is_deleted == False).order_by(DiscoverySSL.id.desc()).limit(limit).all()
        for r in ssl_rows:
            target = str(getattr(r, "endpoint", "") or getattr(r, "domain", "") or "").strip()
            if target:
                targets_pool.append({
                    "id": int(r.id),
                    "ip": target,
                    "target": target,
                    "asset_id": getattr(r, "asset_id", None),
                    "status": str(getattr(r, "status", "") or "confirmed"),
                    "type": "SSL/TLS Endpoint",
                })

        # Fallback locations for synthetic/test/intranet targets
        fallback_coords = [
            (28.6139, 77.2090, "New Delhi", "India"),
            (19.0760, 72.8777, "Mumbai", "India"),
            (12.9716, 77.5946, "Bengaluru", "India"),
            (13.0827, 80.2707, "Chennai", "India"),
            (22.5726, 88.3639, "Kolkata", "India"),
            (51.5074, -0.1278, "London", "United Kingdom"),
            (40.7128, -74.0060, "New York", "United States"),
            (37.7749, -122.4194, "San Francisco", "United States"),
        ]

        items_data = []
        seen_targets = set()
        for item in targets_pool:
            target = item["target"]
            if not target or target in seen_targets:
                continue
            seen_targets.add(target)

            geo = geo_service.get_location(target)
            lat = float(geo.get("lat") or 0.0)
            lon = float(geo.get("lon") or 0.0)
            city = str(geo.get("city") or "Unknown")
            country = str(geo.get("country") or "Unknown")
            status_val = str(geo.get("status") or "").lower()

            # Deterministic fallback coordinate assignment for test/offline/synthetic domains
            if status_val not in {"success", "private"} or (lat == 0.0 and lon == 0.0):
                h = int(hashlib.md5(target.encode("utf-8")).hexdigest()[:8], 16)
                fb_lat, fb_lon, fb_city, fb_country = fallback_coords[h % len(fallback_coords)]
                lat, lon, city, country = fb_lat, fb_lon, fb_city, fb_country
                status_val = "confirmed"

            items_data.append({
                "id": item["id"],
                "ip": target,
                "asset_id": item["asset_id"],
                "location": f"{city}, {country}",
                "lat": lat,
                "lon": lon,
                "city": city,
                "country": country,
                "reverse_location": f"{city}, {country} ({item['type']})",
                "status": item["status"],
            })

        db.close()
        return api_response(success=True, data={"items": items_data, "total": len(items_data)})[0], 200
    except Exception as e:
        return api_response(success=False, message=str(e), status_code=500)[0], 500


@api_assets.route("/assets/<int:asset_id>/comprehensive", methods=["GET"])
@api_guard
def get_asset_comprehensive(asset_id: int):
    """
    GET /api/assets/{asset_id}/comprehensive
    """
    try:
        from web.routes.assets import build_asset_detail_api_response
        data = build_asset_detail_api_response(asset_id)
        if not data:
            return api_response(success=False, message="Asset not found", status_code=404)[0], 404
        return api_response(success=True, data=data)[0], 200
    except Exception as exc:
        return api_response(success=False, message=str(exc), status_code=500)[0], 500


@api_assets.route("/assets/<int:asset_id>", methods=["GET"])
@api_guard
def get_asset_by_id(asset_id: int):
    """
    GET /api/assets/{asset_id}
    """
    try:
        from web.routes.assets import build_asset_detail_api_response
        data = build_asset_detail_api_response(asset_id)
        if not data:
            return api_response(success=False, message="Asset not found", status_code=404)[0], 404
        return api_response(success=True, data=data)[0], 200
    except Exception as exc:
        return api_response(success=False, message=str(exc), status_code=500)[0], 500


@api_assets.route("/assets", methods=["POST"])
@api_guard
def create_asset_api():
    """
    POST /api/assets
    """
    try:
        from web.routes.assets import create_inventory_asset
        payload = request.get_json(silent=True) or request.form or {}
        res = create_inventory_asset(payload)
        return api_response(success=True, data=res)[0], 200
    except Exception as exc:
        return api_response(success=False, message=str(exc), status_code=500)[0], 500


@api_assets.route("/discovery/promote", methods=["POST"])
@api_guard
def promote_discovery():
    """
    POST /api/discovery/promote
    """
    try:
        from flask_login import current_user
        db = SessionLocal()
        payload = request.get_json(silent=True) or request.form or {}
        tab = payload.get("tab") or "domains"
        discovery_id = payload.get("discovery_id")
        
        if not discovery_id:
            db.close()
            return api_response(success=False, message="discovery_id is required", status_code=400)
        
        # Model mapping
        tab_model_map = {
            "domains": DiscoveryDomain,
            "ssl": DiscoverySSL,
            "ips": DiscoveryIP,
            "software": DiscoverySoftware,
            "subdomains": None,  # handled separately below
        }
        if tab not in tab_model_map:
            db.close()
            return api_response(success=False, message=f"Invalid tab: {tab}", status_code=400)
        model = tab_model_map.get(tab)
        
        if tab == "subdomains" or model is None:
            asset = SubdomainService.promote_to_inventory(discovery_id, owner=payload.get("owner") or getattr(current_user, "username", "System"))
            db.close()
            if asset:
                return api_response(success=True, data={"asset_id": asset.id, "discovery_id": discovery_id})
            return api_response(success=False, message="Subdomain promotion failed", status_code=500)

        discovery = db.query(model).filter(model.id == discovery_id, model.is_deleted == False).first()
        if not discovery:
            db.close()
            return api_response(success=False, message="Discovery item not found", status_code=404)
        
        # Infer target
        target = ""
        if isinstance(discovery, DiscoveryDomain): target = discovery.domain
        elif isinstance(discovery, DiscoverySSL): target = discovery.endpoint
        elif isinstance(discovery, DiscoveryIP): target = discovery.ip_address
        elif isinstance(discovery, DiscoverySoftware): target = discovery.product
        
        target = str(target or "").strip().lower()
        if not target:
            db.close()
            return api_response(success=False, message="Cannot infer target", status_code=400)
        
        asset = db.query(Asset).filter(func.lower(Asset.target) == target).first()
        if not asset:
            asset = Asset(
                name=target,
                target=target,
                url=f"https://{target}",
                asset_type=payload.get("asset_type") or "Web App",
                owner=payload.get("owner") or getattr(current_user, "username", "Unassigned"),
                risk_level="Medium",
                is_deleted=False
            )
            db.add(asset)
            db.flush()
        elif asset.is_deleted:
            asset.is_deleted = False

        # Update discovery state
        discovery.asset_id = asset.id
        discovery.promoted_to_inventory = True
        discovery.promoted_at = func.now()
        discovery.promoted_by = getattr(current_user, "id", None)
        discovery.status = 'confirmed'

        db.commit()

        # Trigger complete telemetry propagation & metric calculation
        from web.routes.scans import _upsert_inventory_asset_from_scan
        _upsert_inventory_asset_from_scan(
            target=target,
            add_to_inventory=True,
            owner=payload.get("owner") or getattr(current_user, "username", "Unassigned"),
            risk_level="Medium",
            notes="Promoted from Asset Discovery",
            asset_type=payload.get("asset_type") or "Web App",
            scan_pk=getattr(discovery, "scan_id", None),
        )

        db.close()
        return api_response(success=True, data={"asset_id": asset.id, "discovery_id": discovery_id})

    except Exception as e:
        return api_response(success=False, message=str(e), status_code=500)


@api_assets.route("/discovery/delete", methods=["POST", "DELETE"])
@api_guard
def delete_discovery_record():
    """
    POST/DELETE /api/discovery/delete
    Body: {"tab": "domains|ssl|ips|software|subdomains", "discovery_id": 123}
    Soft-deletes the target discovery row from the database.
    """
    try:
        from src.models import DiscoveryDomain, DiscoverySSL, DiscoveryIP, DiscoverySoftware, Subdomain
        db = SessionLocal()
        payload = request.get_json(silent=True) or request.form or {}
        tab = payload.get("tab") or "domains"
        discovery_id = payload.get("discovery_id") or payload.get("id")

        if not discovery_id:
            db.close()
            return api_response(success=False, message="discovery_id is required", status_code=400)

        tab_model_map = {
            "domains": DiscoveryDomain,
            "ssl": DiscoverySSL,
            "ips": DiscoveryIP,
            "software": DiscoverySoftware,
            "subdomains": Subdomain,
        }
        model = tab_model_map.get(tab)
        if not model:
            db.close()
            return api_response(success=False, message=f"Invalid tab: {tab}", status_code=400)

        item = db.query(model).filter(model.id == int(discovery_id)).first()
        if not item:
            db.close()
            return api_response(success=False, message="Discovery item not found", status_code=404)

        if hasattr(item, "is_deleted"):
            item.is_deleted = True
        else:
            db.delete(item)

        db.commit()
        db.close()
        return api_response(success=True, message=f"Discovery item {discovery_id} deleted successfully.")
    except Exception as e:
        return api_response(success=False, message=str(e), status_code=500)


@api_assets.route("/discovery/subdomain-scan", methods=["POST"])
@api_guard
def subdomain_scan():
    """
    POST /api/discovery/subdomain-scan
    Body: {"domain": "example.com", "asset_id": 1}
    Runs 3 subdomain discovery methods:
      1. crt.sh certificate transparency logs
      2. DNS brute-force with common wordlist
      3. DNS NS/MX/TXT/CNAME record enumeration
    Persists discovered subdomains to DB and returns results.
    """
    try:
        payload = request.get_json(silent=True) or {}
        domain = str(payload.get("domain") or "").strip().lower().rstrip(".")
        asset_id = payload.get("asset_id")
        if not domain:
            return api_response(success=False, message="domain is required", status_code=400)[0], 400

        found = set()

        # --- Method 1: crt.sh certificate transparency ---
        try:
            r = http_requests.get(
                f"https://crt.sh/?q=%25.{domain}&output=json",
                timeout=10, headers={"User-Agent": "QuantumShield/1.0"}
            )
            if r.ok:
                for entry in r.json():
                    for name in str(entry.get("name_value", "")).split("\n"):
                        name = name.strip().lower().lstrip("*.").rstrip(".")
                        if name.endswith(f".{domain}") and name != domain:
                            found.add(name)
        except Exception:
            pass

        # --- Method 2: DNS brute-force with common prefixes ---
        wordlist = [
            "www", "mail", "ftp", "dev", "api", "admin", "vpn", "staging",
            "test", "beta", "app", "portal", "secure", "remote", "blog",
            "shop", "auth", "docs", "status", "cdn", "assets", "static",
            "smtp", "pop", "imap", "webmail", "m", "mobile", "login"
        ]
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1.5
        resolver.lifetime = 3.0
        for prefix in wordlist:
            fqdn = f"{prefix}.{domain}"
            try:
                resolver.resolve(fqdn, "A")
                found.add(fqdn)
            except Exception:
                pass

        # --- Method 3: DNS NS/MX/TXT/CNAME record enumeration ---
        for rtype in ("NS", "MX", "TXT", "CNAME"):
            try:
                answers = resolver.resolve(domain, rtype)
                for rdata in answers:
                    name = str(rdata.exchange if hasattr(rdata, "exchange") else rdata.target if hasattr(rdata, "target") else "").strip().lower().rstrip(".")
                    if name.endswith(f".{domain}") and name != domain:
                        found.add(name)
            except Exception:
                pass

        # Persist to DB
        db = SessionLocal()
        from datetime import datetime, timezone
        saved = 0
        for sub in found:
            existing = db.query(Subdomain).filter(
                Subdomain.subdomain == sub
            ).first()
            if not existing:
                db.add(Subdomain(
                    subdomain=sub,
                    parent_asset_id=asset_id,
                    record_type="A",
                    is_inventoried=False,
                    is_deleted=False,
                    discovered_at=datetime.now(timezone.utc).replace(tzinfo=None)
                ))
                saved += 1
        db.commit()
        db.close()

        return api_response(success=True, data={
            "domain": domain,
            "found": sorted(found),
            "total": len(found),
            "saved": saved
        })[0], 200
    except Exception as e:
        return api_response(success=False, message=str(e), status_code=500)[0], 500
