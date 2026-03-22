"""
API Assets - /api/assets and /api/discovery endpoints
Paginated, sortable, searchable asset and discovery data.
"""

from flask import Blueprint, request, jsonify
from flask_login import login_required
from src.db import SessionLocal
from src.models import Asset, Certificate, DiscoveryItem
from utils.api_helper import (
    paginated_response, api_response, apply_soft_delete_filter,
    extract_pagination_params, validate_pagination_params,
    search_filter, format_asset_row, format_datetime
)
from sqlalchemy import func, or_, and_

api_assets = Blueprint("api_assets", __name__, url_prefix="/api")


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
    try:
        db = SessionLocal()
        params = extract_pagination_params()
        page, page_size = validate_pagination_params(params["page"], params["page_size"])
        
        # Build base query
        query = db.query(Asset).filter(Asset.is_deleted == False)
        
        # Apply search filter
        if params["search"]:
            search_cond = or_(
                Asset.target.ilike(f"%{params['search']}%"),
                Asset.url.ilike(f"%{params['search']}%")
            )
            query = query.filter(search_cond)
        
        # Get total before pagination
        total = query.count()
        
        # Apply sorting
        allowed_sorts = {
            "asset_name": Asset.target,
            "risk_level": Asset.risk_level,
            "created_at": Asset.created_at,
            "updated_at": Asset.updated_at,
            "owner": Asset.owner,
            "type": Asset.asset_type
        }
        
        sort_field = params["sort"] or "created_at"
        if sort_field in allowed_sorts:
            sort_col = allowed_sorts[sort_field]
            if params["order"].lower() == "desc":
                query = query.order_by(sort_col.desc())
            else:
                query = query.order_by(sort_col.asc())
        
        # Apply pagination
        offset = (page - 1) * page_size
        items = query.offset(offset).limit(page_size).all()
        
        # Format response
        items_data = [format_asset_row(asset) for asset in items]
        
        db.close()
        
        return paginated_response(
            items=items_data,
            total=total,
            page=page,
            page_size=page_size,
            filters={
                "sort": params["sort"] or "created_at",
                "order": params["order"],
                "search": params["search"]
            }
        )[0], 200
    
    except Exception as e:
        return api_response(success=False, message=str(e), status_code=500)[0], 500


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
    try:
        db = SessionLocal()
        
        asset = db.query(Asset).filter(
            Asset.id == asset_id,
            Asset.is_deleted == False
        ).first()
        
        if not asset:
            return api_response(
                success=False,
                message="Asset not found",
                status_code=404
            )[0], 404
        
        # Get certificates for this asset
        certs = db.query(Certificate).filter(
            Certificate.asset_id == asset_id,
            Certificate.is_deleted == False
        ).all()
        
        asset_data = format_asset_row(asset)
        asset_data["certificates_count"] = len(certs)
        asset_data["discovery_count"] = db.query(func.count(DiscoveryItem.id)).filter(
            DiscoveryItem.asset_id == asset_id,
            DiscoveryItem.is_deleted == False
        ).scalar() or 0
        
        db.close()
        
        return api_response(
            success=True,
            data=asset_data
        )[0], 200
    
    except Exception as e:
        return api_response(success=False, message=str(e), status_code=500)[0], 500


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
    try:
        from flask_login import current_user
        import re
        from urllib.parse import urlparse
        import ipaddress
        
        db = SessionLocal()
        
        # Parse request
        payload = request.get_json(silent=True) or request.form or {}
        target = str(payload.get("target") or "").strip()
        asset_type = str(payload.get("type") or payload.get("asset_type") or "Web App").strip()[:100]
        owner = str(payload.get("owner") or getattr(current_user, "username", "Unassigned") or "Unassigned").strip()[:100]
        risk_level = str(payload.get("risk_level") or "Medium").strip()[:20]
        
        # Validate target
        if not target or len(target) > 255:
            db.close()
            return api_response(success=False, message="target is required and must be <= 255 chars", status_code=400)[0], 400
        
        # Normalize target (remove protocol, port)
        if target.startswith(("http://", "https://", "ftp://")):
            try:
                parsed = urlparse(target)
                target = parsed.netloc or parsed.path
            except:
                pass
        
        if ":" in target:
            target = target.split(":")[0]
        
        target = target.strip().lower()
        
        # Try to parse as IP or validate as hostname
        valid = False
        try:
            ipaddress.ip_address(target)
            valid = True
        except ValueError:
            if re.match(r"^[a-z0-9][a-z0-9.-]*[a-z0-9]$|^[a-z0-9]$", target, re.I):
                valid = True
        
        if not valid:
            db.close()
            return api_response(success=False, message="target must be valid hostname or IP", status_code=400)[0], 400
        
        # Check if asset exists
        asset = db.query(Asset).filter(
            Asset.target == target
        ).first()
        
        if asset:
            # Restore if soft-deleted
            created = False
            if asset.is_deleted:
                asset.is_deleted = False
                asset.deleted_at = None
                asset.deleted_by_user_id = None
            else:
                created = False  # Already exists
        else:
            # Create new asset
            asset = Asset(
                target=target,
                url=f"https://{target}",
                asset_type=asset_type,
                owner=owner,
                risk_level=risk_level,
                is_deleted=False
            )
            db.add(asset)
            created = True
        
        db.commit()
        asset_id = asset.id
        db.close()
        
        return api_response(
            success=True,
            data={
                "id": asset_id,
                "target": target,
                "created": created,
                "restored": asset and asset.is_deleted == False and not created
            },
            status_code=201 if created else 200
        )[0], (201 if created else 200)
    
    except Exception as e:
        return api_response(success=False, message=str(e), status_code=500)[0], 500


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
            return api_response(success=False, message="discovery_id is required", status_code=400)[0], 400
        
        # Get discovery item
        discovery = db.query(DiscoveryItem).filter(
            DiscoveryItem.id == discovery_id,
            DiscoveryItem.is_deleted == False
        ).first()
        
        if not discovery:
            db.close()
            return api_response(success=False, message="Discovery item not found", status_code=404)[0], 404
        
        # Get or create asset
        target = str(discovery.domain_name or discovery.ip or discovery.common_name or "").strip().lower()
        if not target:
            db.close()
            return api_response(success=False, message="Cannot infer target from discovery", status_code=400)[0], 400
        
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
        )[0], 200
    
    except Exception as e:
        return api_response(success=False, message=str(e), status_code=500)[0], 500
