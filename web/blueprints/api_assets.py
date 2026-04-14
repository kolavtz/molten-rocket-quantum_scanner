"""
API Assets - /api/assets and /api/discovery endpoints
Paginated, sortable, searchable asset and discovery data.
"""

import json
import ipaddress
from urllib.parse import urlparse
from flask import Blueprint, request, jsonify
from flask_login import login_required
from src.db import db_session as SessionLocal
from src.models import (
    Asset, Certificate, Scan, Subdomain,
    DiscoveryDomain, DiscoverySSL, DiscoveryIP, DiscoverySoftware
)
from src.services.subdomain_service import SubdomainService
from utils.api_helper import (
    paginated_response, api_response, apply_soft_delete_filter,
    extract_pagination_params, validate_pagination_params,
    search_filter, format_asset_row, format_datetime
)
from sqlalchemy import func, or_, and_
from middleware.api_auth import api_guard

api_assets = Blueprint("api_assets", __name__, url_prefix="/api")

_INVALID_DISCOVERY_TARGETS = {"", "-", "--", "n/a", "na", "unknown", "0.0.0.0", "::"}


def _normalize_cluster_seed(value: str) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    if "://" in raw:
        parsed = urlparse(raw)
        raw = (parsed.hostname or parsed.netloc or parsed.path or raw).strip().lower()
    return raw


_MULTI_LABEL_PUBLIC_SUFFIXES = {
    "co.uk",
    "org.uk",
    "gov.uk",
    "ac.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.in",
    "com.br",
    "com.sg",
    "co.jp",
    "co.kr",
}


def _registrable_domain(host: str) -> str:
    labels = [label for label in str(host or "").strip(".").split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    suffix2 = ".".join(labels[-2:]).lower()
    if suffix2 in _MULTI_LABEL_PUBLIC_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _derive_cluster_label(value: str) -> str:
    seed = _normalize_cluster_seed(value)
    if not seed:
        return "unclustered"

    try:
        ip_obj = ipaddress.ip_address(seed)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            parts = seed.split(".")
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        if isinstance(ip_obj, ipaddress.IPv6Address):
            return f"{seed[:19]}::/64"
        return seed
    except ValueError:
        pass

    host = seed.split(":", 1)[0]
    reg_domain = _registrable_domain(host)
    return reg_domain or host


def _discovery_detected_at_expr(model):
    return func.coalesce(
        getattr(model, "promoted_at", None),
        Scan.completed_at,
        Scan.scanned_at,
        Scan.started_at,
        Scan.created_at,
    )


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
        
        db = SessionLocal()
        params = extract_pagination_params()
        page, page_size = validate_pagination_params(params["page"], params["page_size"])

        # Subdomains live in a dedicated table with different shape (no scan_id / asset_id columns).
        if tab == "subdomains":
            sub_query = (
                db.query(Subdomain, Asset.target.label("parent_target"))
                .outerjoin(Asset, Subdomain.parent_asset_id == Asset.id)
                .filter(Subdomain.is_deleted == False)
                .filter(~Subdomain.subdomain.like("*.%"))
            )

            if params["search"]:
                search_val = f"%{params['search']}%"
                sub_query = sub_query.filter(
                    or_(
                        Subdomain.subdomain.ilike(search_val),
                        Asset.target.ilike(search_val),
                        Asset.owner.ilike(search_val),
                    )
                )

            total = sub_query.count()
            sort_field = (params.get("sort") or "detection_date").lower()
            if sort_field in {"domain_name", "name", "identifier", "subdomain"}:
                sort_col = Subdomain.subdomain
            elif sort_field in {"record_type", "type"}:
                sort_col = Subdomain.record_type
            elif sort_field in {"parent_asset", "asset_name"}:
                sort_col = Asset.target
            else:
                sort_col = Subdomain.discovered_at

            if params["order"].lower() == "desc":
                sub_query = sub_query.order_by(sort_col.desc(), Subdomain.id.desc())
            else:
                sub_query = sub_query.order_by(sort_col.asc(), Subdomain.id.asc())

            rows = sub_query.offset((page - 1) * page_size).limit(page_size).all()
            items_data = []
            for item, parent_target in rows:
                identifier = str(getattr(item, "subdomain", "") or "")
                cluster_seed = str(identifier or parent_target or "").strip()
                cluster_label = _derive_cluster_label(cluster_seed)
                row = {
                    "id": int(getattr(item, "id", 0) or 0),
                    "identifier": identifier,
                    "status": "confirmed" if bool(getattr(item, "is_inventoried", False)) else "new",
                    "detection_date": format_datetime(getattr(item, "discovered_at", None)),
                    "asset_name": str(parent_target or ""),
                    "asset_risk_level": "",
                    "risk_score": 50,
                    "scan_id": None,
                    "asset_id": int(getattr(item, "parent_asset_id", 0) or 0),
                    "promoted": bool(getattr(item, "is_inventoried", False)),
                    "cluster_key": cluster_label,
                    "cluster_label": cluster_label,
                    "cluster_seed": cluster_seed,
                    "domain_name": identifier,
                    "record_type": str(getattr(item, "record_type", "") or ""),
                    "parent_asset_id": int(getattr(item, "parent_asset_id", 0) or 0),
                }
                items_data.append(row)

            db.close()
            return paginated_response(
                items=items_data,
                total=total,
                page=page,
                page_size=page_size,
                filters={"tab": tab, "sort": params["sort"], "order": params["order"], "search": params["search"]}
            )[0], 200

        model = tab_model_map[tab]
        
        # Build query
        detected_at_expr = _discovery_detected_at_expr(model)
        query = (
            db.query(model, detected_at_expr.label("detected_at"), Scan.target.label("scan_target"))
            .outerjoin(Scan, model.scan_id == Scan.id)
            .filter(model.is_deleted == False)
        )
        if tab == "ips":
            query = query.filter(func.trim(func.coalesce(DiscoveryIP.ip_address, "")) != "")
            query = query.filter(~func.lower(func.trim(func.coalesce(DiscoveryIP.ip_address, ""))).in_(tuple(_INVALID_DISCOVERY_TARGETS - {""})))
        
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

        for item, detected_at, scan_target in items:
            asset_name = getattr(item.asset, 'target', '') if hasattr(item, 'asset') and item.asset else ''
            asset_risk_level = getattr(item.asset, 'risk_level', '') if hasattr(item, 'asset') and item.asset else ''
            
            # Identifier mapping
            identifier = ""
            if isinstance(item, DiscoveryDomain): identifier = item.domain
            elif isinstance(item, DiscoverySSL): identifier = item.endpoint
            elif isinstance(item, DiscoveryIP): identifier = item.ip_address
            elif isinstance(item, DiscoverySoftware): identifier = item.product
            elif isinstance(item, Subdomain): identifier = item.subdomain

            cluster_seed = str(identifier or scan_target or asset_name or "").strip()
            cluster_label = _derive_cluster_label(cluster_seed)

            row = {
                "id": item.id,
                "identifier": identifier,
                "status": getattr(item, "status", "new"),
                "detection_date": format_datetime(detected_at or getattr(item, "discovered_at", None)),
                "asset_name": asset_name,
                "asset_risk_level": asset_risk_level,
                "risk_score": _risk_score_from_level(asset_risk_level),
                "scan_id": getattr(item, "scan_id", None),
                "asset_id": getattr(item, "asset_id", None),
                "promoted": getattr(item, "promoted_to_inventory", False) or getattr(item, "is_inventoried", False),
                "cluster_key": cluster_label,
                "cluster_label": cluster_label,
                "cluster_seed": cluster_seed,
            }

            if isinstance(item, DiscoveryDomain):
                row.update({
                    "domain_name": item.domain,
                    "registrar": item.registrar,
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
                row.update({
                    "ip_address": item.ip_address,
                    "subnet": item.subnet,
                    "asn": item.asn,
                    "netname": item.netname,
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
        from src.services.geo_service import GeoService

        limit = max(1, min(request.args.get("limit", 200, type=int), 500))
        geo_service = GeoService()
        db = SessionLocal()

        detected_at_expr = _discovery_detected_at_expr(DiscoveryIP)
        rows = (
            db.query(DiscoveryIP, detected_at_expr.label("detected_at"))
            .outerjoin(Scan, DiscoveryIP.scan_id == Scan.id)
            .filter(DiscoveryIP.is_deleted == False)
            .filter(func.trim(func.coalesce(DiscoveryIP.ip_address, "")) != "")
            .filter(~func.lower(func.trim(func.coalesce(DiscoveryIP.ip_address, ""))).in_(tuple(_INVALID_DISCOVERY_TARGETS - {""})))
            .order_by(detected_at_expr.desc(), DiscoveryIP.id.desc())
            .limit(limit)
            .all()
        )

        items_data = []
        seen_ips = set()
        for row, detected_at in rows:
            ip = str(getattr(row, "ip_address", "") or "").strip()
            if not ip or ip in seen_ips:
                continue
            seen_ips.add(ip)

            geo = geo_service.get_location(ip)
            geo_status = str(geo.get("status") or "").lower()

            # Fallback: use persisted scan.report_json asset_locations when live geo lookup fails.
            if geo_status not in {"success", "private"} and getattr(row, "scan_id", None):
                scan_row = db.query(Scan).filter(Scan.id == row.scan_id).first()
                if scan_row is not None:
                    raw_report = getattr(scan_row, "report_json", None)
                    parsed_report = None
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
                        for pt in (parsed_report.get("asset_locations") or []):
                            if str(pt.get("ip") or "").strip() != ip:
                                continue
                            geo = {
                                "status": "success",
                                "lat": float(pt.get("lat") or 0.0),
                                "lon": float(pt.get("lon") or 0.0),
                                "city": str(pt.get("city") or "Unknown"),
                                "country": str(pt.get("country") or "Unknown"),
                                "reverse_location": str(pt.get("reverse_location") or ""),
                            }
                            geo_status = "success"
                            break

            if geo_status not in {"success", "private"}:
                continue

            lat = float(geo.get("lat") or 0.0)
            lon = float(geo.get("lon") or 0.0)
            if not lat and not lon:
                continue

            items_data.append({
                "id": int(row.id),
                "ip": ip,
                "asset_id": row.asset_id,
                "asset_name": getattr(getattr(row, "asset", None), "target", "") if getattr(row, "asset", None) else "",
                "location": str(getattr(row, "location", "") or ""),
                "lat": lat,
                "lon": lon,
                "city": geo.get("city") or "Unknown",
                "country": geo.get("country") or "Unknown",
                "reverse_location": str(geo.get("reverse_location") or ""),
                "status": str(getattr(row, "status", "") or "new"),
                "detection_date": format_datetime(detected_at),
            })

        db.close()
        return api_response(success=True, data={"items": items_data, "total": len(items_data)})[0], 200
    except Exception as e:
        return api_response(success=False, message=str(e), status_code=500)[0], 500


@api_assets.route("/assets/<int:asset_id>/comprehensive", methods=["GET"])
@api_guard
def get_asset_comprehensive_detail(asset_id):
    """
    GET /api/assets/<asset_id>/comprehensive
    Returns a unified DTO for the Intelligence modal.
    """
    try:
        from web.routes.assets import build_comprehensive_asset_dto
        data = build_comprehensive_asset_dto(asset_id)
        if data is None:
            return api_response(success=False, message="Asset not found", status_code=404)[0], 404
        return api_response(success=True, data=data)[0], 200
    except Exception as exc:
        return api_response(success=False, message=f"Failed to load comprehensive details: {exc}", status_code=500)[0], 500


@api_assets.route("/assets/<int:asset_id>", methods=["GET"])
@api_guard
def get_asset_detail(asset_id):
    """
    GET /api/assets/<asset_id>
    """
    try:
        from web.routes.assets import build_asset_detail_api_response
        asset_data = build_asset_detail_api_response(asset_id)
        if asset_data is None:
            return api_response(success=False, message="Asset not found", status_code=404)[0], 404
        return api_response(success=True, data=asset_data)[0], 200
    except Exception as exc:
        return api_response(success=False, message=f"Failed to load asset detail: {exc}", status_code=500)[0], 500


@api_assets.route("/assets", methods=["POST"])
@api_guard
def create_asset():
    """
    POST /api/assets
    """
    try:
        from web.routes.assets import create_or_scan_asset_api
        payload = request.get_json(silent=True) or request.form.to_dict(flat=False)
        response, status_code = create_or_scan_asset_api(payload)
        return response, status_code
    except Exception as exc:
        return api_response(success=False, message=f"Failed to create/scan asset: {exc}", status_code=500)[0], 500


@api_assets.route("/discovery/promote", methods=["POST"])
@api_guard
def promote_discovery_to_asset():
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
        
        if tab == "subdomains":
            asset = SubdomainService.promote_to_inventory(discovery_id, owner=payload.get("owner") or getattr(current_user, "username", "System"))
            db.close()
            if asset:
                return api_response(success=True, data={"asset_id": asset.id, "discovery_id": discovery_id})
            return api_response(success=False, message="Subdomain promotion failed", status_code=500)

        # Model mapping
        tab_model_map = {
            "domains": DiscoveryDomain,
            "ssl": DiscoverySSL,
            "ips": DiscoveryIP,
            "software": DiscoverySoftware
        }
        model = tab_model_map.get(tab)
        if not model:
            db.close()
            return api_response(success=False, message=f"Invalid tab: {tab}", status_code=400)

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
        if target in _INVALID_DISCOVERY_TARGETS:
            discovery.status = "false_positive"
            discovery.is_deleted = True
            discovery.deleted_at = func.now()
            db.commit()
            db.close()
            return api_response(success=False, message="Invalid placeholder discovery record was removed.", status_code=400)
        
        asset = db.query(Asset).filter(Asset.target == target).first()
        if not asset:
            asset = Asset(
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
        discovery.promoted_by = current_user.id
        discovery.status = 'confirmed'
        
        db.commit()
        db.close()
        return api_response(success=True, data={
            "asset_id": asset.id,
            "discovery_id": discovery_id,
            "cluster_key": _derive_cluster_label(str(getattr(discovery, "scan", None).target if getattr(discovery, "scan", None) else target)),
        })
    except Exception as e:
        return api_response(success=False, message=str(e), status_code=500)
