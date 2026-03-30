"""
API Assets - /api/assets and /api/discovery endpoints
Paginated, sortable, searchable asset and discovery data.
"""

import json
from flask import Blueprint, request, jsonify
from flask_login import login_required
from src.db import db_session as SessionLocal
from src.models import (
    Asset, Certificate, Scan,
    DiscoveryDomain, DiscoverySSL, DiscoveryIP, DiscoverySoftware
)
from utils.api_helper import (
    paginated_response, api_response, apply_soft_delete_filter,
    extract_pagination_params, validate_pagination_params,
    search_filter, format_asset_row, format_datetime
)
from sqlalchemy import func, or_, and_

api_assets = Blueprint("api_assets", __name__, url_prefix="/api")


def _discovery_detected_at_expr(model):
    return func.coalesce(
        getattr(model, "promoted_at", None),
        Scan.completed_at,
        Scan.scanned_at,
        Scan.started_at,
        Scan.created_at,
    )


@api_assets.route("/assets/<int:asset_id>/scans", methods=["GET"])
@login_required
def get_asset_scans(asset_id):
    """
    GET /api/assets/{asset_id}/scans?page=1&page_size=10
    
    Returns scan history for a specific asset.
    """
    from web.routes.assets import build_asset_scans_api_response

    params = extract_pagination_params()
    page, page_size = validate_pagination_params(params["page"], min(params["page_size"], 50))
    data = build_asset_scans_api_response(asset_id, page=page, page_size=page_size)
    if data is None:
        return api_response(success=False, message="Asset not found", status_code=404)
    return api_response(success=True, data=data)[0], 200


@api_assets.route("/assets", methods=["GET"])
@login_required
def get_assets():
    """
    GET /api/assets?page=1&page_size=25&sort=asset_name&order=asc&q=example
    """
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


@api_assets.route("/discovery", methods=["GET"])
@login_required
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
            "software": DiscoverySoftware
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
        
        # Build query
        detected_at_expr = _discovery_detected_at_expr(model)
        query = (
            db.query(model, detected_at_expr.label("detected_at"))
            .outerjoin(Scan, model.scan_id == Scan.id)
            .filter(model.is_deleted == False)
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

            row = {
                "id": item.id,
                "identifier": identifier,
                "status": item.status,
                "detection_date": format_datetime(detected_at),
                "asset_name": asset_name,
                "asset_risk_level": asset_risk_level,
                "risk_score": _risk_score_from_level(asset_risk_level),
                "scan_id": item.scan_id,
                "asset_id": item.asset_id,
                "promoted": getattr(item, "promoted_to_inventory", False)
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
@login_required
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
            if str(geo.get("status") or "").lower() not in {"success", "private"}:
                continue

            items_data.append({
                "id": int(row.id),
                "ip": ip,
                "asset_id": row.asset_id,
                "asset_name": getattr(getattr(row, "asset", None), "target", "") if getattr(row, "asset", None) else "",
                "location": str(getattr(row, "location", "") or ""),
                "lat": float(geo.get("lat") or 0.0),
                "lon": float(geo.get("lon") or 0.0),
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
@login_required
def get_asset_comprehensive_detail(asset_id):
    """
    GET /api/assets/<asset_id>/comprehensive
    Returns a unified DTO for the Intelligence modal.
    """
    from web.routes.assets import build_comprehensive_asset_dto
    data = build_comprehensive_asset_dto(asset_id)
    if data is None:
        return api_response(success=False, message="Asset not found", status_code=404)[0], 404
    return api_response(success=True, data=data)[0], 200


@api_assets.route("/assets/<int:asset_id>", methods=["GET"])
@login_required
def get_asset_detail(asset_id):
    """
    GET /api/assets/<asset_id>
    """
    from web.routes.assets import build_asset_detail_api_response
    asset_data = build_asset_detail_api_response(asset_id)
    if asset_data is None:
        return api_response(success=False, message="Asset not found", status_code=404)[0], 404
    return api_response(success=True, data=asset_data)[0], 200


@api_assets.route("/assets", methods=["POST"])
@login_required
def create_asset():
    """
    POST /api/assets
    """
    from web.routes.assets import create_or_scan_asset_api
    payload = request.get_json(silent=True) or request.form.to_dict(flat=False)
    response, status_code = create_or_scan_asset_api(payload)
    return response, status_code


@api_assets.route("/discovery/promote", methods=["POST"])
@login_required
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
        return api_response(success=True, data={"asset_id": asset.id, "discovery_id": discovery_id})
    except Exception as e:
        return api_response(success=False, message=str(e), status_code=500)
