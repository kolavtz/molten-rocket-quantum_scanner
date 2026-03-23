"""
API Assets - /api/assets and /api/discovery endpoints
Paginated, sortable, searchable asset and discovery data.
"""

import json
from flask import Blueprint, request, jsonify
from flask_login import login_required
from src.db import db_session as SessionLocal
from src.models import Asset, Certificate, DiscoveryItem
from utils.api_helper import (
    paginated_response, api_response, apply_soft_delete_filter,
    extract_pagination_params, validate_pagination_params,
    search_filter, format_asset_row, format_datetime
)
from sqlalchemy import func, or_, and_

api_assets = Blueprint("api_assets", __name__, url_prefix="/api")


@api_assets.route("/assets/<int:asset_id>/scans", methods=["GET"])
@login_required
def get_asset_scans(asset_id):
    """
    GET /api/assets/{asset_id}/scans?page=1&page_size=10
    
    Returns scan history for a specific asset.
    
    Query Parameters:
        page (int): Page number, default 1
        page_size (int): Records per page, default 10, max 50
    
    Response:
    {
        "success": true,
        "data": {
            "asset_id": 1,
            "asset_name": "example.com",
            "items": [
                {
                    "scan_id": "abc123",
                    "status": "completed",
                    "started_at": "2026-03-22T10:30:00Z",
                    "completed_at": "2026-03-22T10:35:00Z",
                    "quantum_safe": true,
                    "pqc_score": 85.5,
                    "total_certificates": 3
                }
            ],
            "total": 5,
            "page": 1,
            "page_size": 10,
            "total_pages": 1
        }
    }
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
    
    Returns paginated, sortable, searchable list of assets.
    
    Query Parameters:
        page (int): Page number, default 1
        page_size (int): Records per page, default 25, max 100
        sort (str): Sort field (asset_name, risk_level, created_at, updated_at)
        order (str): asc or desc
        q (str): Search query (searches asset_name and url)
    
    Response:
    {
        "success": true,
        "data": {
            "items": [
                {
                    "id": 1,
                    "asset_name": "example.com",
                    "url": "https://example.com",
                    "type": "domain",
                    "owner": "John Doe",
                    "risk_level": "Medium",
                    "last_scan": "2026-03-22 07:18:12",
                    "created_at": "2026-03-20 10:00:00",
                    "updated_at": "2026-03-22 07:18:12"
                }
            ],
            "total": 150,
            "page": 1,
            "page_size": 25,
            "total_pages": 6
        },
        "filters": {
            "sort": "asset_name",
            "order": "asc",
            "search": "example"
        }
    }
    """
    from web.routes.assets import build_assets_api_response

    params = extract_pagination_params()
    page, page_size = validate_pagination_params(params["page"], params["page_size"])
    data, filters = build_assets_api_response(
        page=page,
        page_size=page_size,
        sort=params["sort"] or "name",
        order=params["order"],
        search=params["search"],
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
    
    Returns discovery items filtered by type (tab).
    
    Query Parameters:
        tab (str): Type filter: domains, ssl, ips, software (required)
        page (int): Page number
        page_size (int): Records per page
        sort (str): Sort field
        order (str): asc or desc
        q (str): Search query
    
    Response: Paginated discovery items with asset info
    """
    try:
        tab = request.args.get("tab", "domains", type=str).lower()
        
        # Map tab names to types
        tab_type_map = {
            "domains": "domain",
            "ssl": "ssl",
            "ips": "ip",
            "software": "software"
        }
        
        if tab not in tab_type_map:
            return api_response(
                success=False,
                message=f"Invalid tab: {tab}. Must be one of: domains, ssl, ips, software",
                status_code=400
            )[0], 400
        
        discovery_type = tab_type_map[tab]
        db = SessionLocal()
        params = extract_pagination_params()
        page, page_size = validate_pagination_params(params["page"], params["page_size"])
        
        # Build query
        query = db.query(DiscoveryItem).filter(
            DiscoveryItem.is_deleted == False,
            DiscoveryItem.type == discovery_type
        )
        
        # Get total
        total = query.count()
        
        # Apply sorting
        if params["order"].lower() == "desc":
            query = query.order_by(DiscoveryItem.detection_date.desc())
        else:
            query = query.order_by(DiscoveryItem.detection_date.asc())
        
        # Apply pagination
        offset = (page - 1) * page_size
        items = query.offset(offset).limit(page_size).all()
        
        # Format items
        items_data = []
        for item in items:
            asset_name = ""
            if item.asset:
                asset_name = item.asset.target
            
            items_data.append({
                "id": item.id,
                "type": item.type,
                "status": item.status,
                "detection_date": format_datetime(item.detection_date),
                "asset_name": asset_name,
                "scan_id": item.scan_id,
                "asset_id": item.asset_id
            })
        
        db.close()
        
        return paginated_response(
            items=items_data,
            total=total,
            page=page,
            page_size=page_size,
            filters={
                "tab": tab,
                "sort": params["sort"],
                "order": params["order"],
                "search": params["search"]
            }
        )[0], 200
    
    except Exception as e:
        return api_response(success=False, message=str(e), status_code=500)[0], 500


@api_assets.route("/assets/<int:asset_id>", methods=["GET"])
@login_required
def get_asset_detail(asset_id):
    """
    GET /api/assets/<asset_id>
    Returns detailed information about a specific asset.
    """
    from web.routes.assets import build_asset_detail_api_response

    asset_data = build_asset_detail_api_response(asset_id)
    if asset_data is None:
        return api_response(
            success=False,
            message="Asset not found",
            status_code=404
        )[0], 404
    return api_response(success=True, data=asset_data)[0], 200


@api_assets.route("/assets", methods=["POST"])
@login_required
def create_asset():
    """
    POST /api/assets
    Create a new asset or restore a soft-deleted one.
    
    Body:
    {
        "target": "example.com" (required),
        "type": "Web App",
        "owner": "Infra Team",
        "risk_level": "Medium"
    }
    
    Response: 201 or 400 on validation error
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
    Promote a discovery item to inventory asset.
    
    Body:
    {
        "discovery_id": 123 (required),
        "asset_type": "Web App" (optional, from item),
        "owner": "Infra Team" (optional)
    }
    
    Response: 200 or 400/404 on error
    """
    try:
        from flask_login import current_user
        
        db = SessionLocal()
        
        payload =  request.get_json(silent=True) or request.form or {}
        discovery_id = payload.get("discovery_id", type=int)
        
        if not discovery_id:
            db.close()
            return api_response(success=False, message="discovery_id is required", status_code=400)
        
        # Get discovery item
        discovery = db.query(DiscoveryItem).filter(
            DiscoveryItem.id == discovery_id,
            DiscoveryItem.is_deleted == False
        ).first()
        
        if not discovery:
            db.close()
            return api_response(success=False, message="Discovery item not found", status_code=404)
        
        # Get or create asset
        target = str(discovery.domain_name or discovery.ip or discovery.common_name or "").strip().lower()
        if not target:
            db.close()
            return api_response(success=False, message="Cannot infer target from discovery", status_code=400)
        
        asset = db.query(Asset).filter(Asset.target == target).first()
        if not asset:
            asset = Asset(
                target=target,
                url=f"https://{target}",
                asset_type=payload.get("asset_type") or "Web App",
                owner=payload.get("owner") or getattr(current_user, "username", "Unassigned") or "Unassigned",
                risk_level="Medium",
                is_deleted=False
            )
            db.add(asset)
            db.flush()
        elif asset.is_deleted:
            asset.is_deleted = False
            asset.deleted_at = None
        
        # Link discovery to asset
        discovery.asset_id = asset.id
        
        db.commit()
        db.close()
        
        return api_response(
            success=True,
            data={"asset_id": asset.id, "discovery_id": discovery_id}
        )
    
    except Exception as e:
        return api_response(success=False, message=str(e), status_code=500)
