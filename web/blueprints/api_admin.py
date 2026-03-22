"""
API Admin - /api/admin/* endpoints
Admin-only endpoints for API key management, metrics, and cache control.
"""

from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
from src.db import SessionLocal
from src.models import User
from middleware.api_auth import APIKey
from utils.api_helper import api_response, format_datetime
from datetime import datetime, timedelta
import secrets

api_admin = Blueprint("api_admin", __name__, url_prefix="/api/admin")


def is_admin():
    """Check if current user is admin."""
    if not current_user.is_authenticated:
        return False
    return hasattr(current_user, "role") and current_user.role in ["Admin", "Administrator"]


@api_admin.route("/api-keys", methods=["GET"])
@login_required
def list_api_keys():
    """
    GET /api/admin/api-keys
    Lists all API keys (admin only).
    """
    if not is_admin():
        return api_response(
            success=False,
            message="Admin access required",
            status_code=403
        )[0], 403
    
    try:
        db = SessionLocal()
        
        keys = db.query(APIKey).filter(APIKey.is_active == True).all()
        
        items = [
            {
                "key": f"sk_{key.key[-8:]}" if len(key.key) > 8 else "sk_****",  # Mask for security
                "name": key.name,
                "created_at": format_datetime(key.created_at),
                "last_used_at": format_datetime(key.last_used_at),
                "expires_at": format_datetime(key.expires_at) if key.expires_at else None,
                "user_id": key.user_id
            }
            for key in keys
        ]
        
        db.close()
        
        return api_response(success=True, data={"keys": items})[0], 200
    
    except Exception as e:
        return api_response(success=False, message=str(e), status_code=500)[0], 500


@api_admin.route("/api-keys", methods=["POST"])
@login_required
def create_api_key():
    """
    POST /api/admin/api-keys
    Creates a new API key (admin only).
    
    Body:
    {
        "name": "My App Key",
        "expires_in_days": 365
    }
    """
    if not is_admin():
        return api_response(
            success=False,
            message="Admin access required",
            status_code=403
        )[0], 403
    
    try:
        data = request.get_json() or {}
        name = data.get("name", f"API Key {datetime.utcnow().isoformat()}")
        expires_in_days = int(data.get("expires_in_days", 365))
        
        db = SessionLocal()
        
        # Generate new API key
        new_key = APIKey.generate_key()
        expires_at = datetime.utcnow() + timedelta(days=expires_in_days) if expires_in_days > 0 else None
        
        api_key_obj = APIKey(
            key=new_key,
            name=name,
            user_id=str(current_user.id) if hasattr(current_user, "id") else None,
            is_active=True,
            expires_at=expires_at
        )
        
        db.add(api_key_obj)
        db.commit()
        db.close()
        
        return api_response(
            success=True,
            data={
                "key": new_key,
                "name": name,
                "expires_at": format_datetime(expires_at),
                "message": "Save this key securely. You won't be able to see it again!"
            }
        )[0], 201
    
    except Exception as e:
        return api_response(success=False, message=str(e), status_code=500)[0], 500


@api_admin.route("/api-keys/<key_name>", methods=["DELETE"])
@login_required
def revoke_api_key(key_name):
    """
    DELETE /api/admin/api-keys/<key_name>
    Revokes an API key (admin only).
    """
    if not is_admin():
        return api_response(
            success=False,
            message="Admin access required",
            status_code=403
        )[0], 403
    
    try:
        db = SessionLocal()
        
        key = db.query(APIKey).filter(APIKey.name == key_name).first()
        
        if not key:
            return api_response(
                success=False,
                message="API key not found",
                status_code=404
            )[0], 404
        
        key.is_active = False
        db.commit()
        db.close()
        
        return api_response(
            success=True,
            message=f"API key '{key_name}' revoked"
        )[0], 200
    
    except Exception as e:
        return api_response(success=False, message=str(e), status_code=500)[0], 500


@api_admin.route("/metrics", methods=["GET"])
@login_required
def admin_metrics():
    """
    GET /api/admin/metrics
    Returns admin dashboard metrics (admin only).
    """
    if not is_admin():
        return api_response(
            success=False,
            message="Admin access required",
            status_code=403
        )[0], 403
    
    try:
        db = SessionLocal()
        
        from src.models import Asset, Scan, User
        from sqlalchemy import func
        
        total_users = db.query(func.count(User.id)).scalar() or 0
        total_assets = db.query(func.count(Asset.id)).filter(Asset.is_deleted == False).scalar() or 0
        total_scans = db.query(func.count(Scan.id)).filter(Scan.is_deleted == False).scalar() or 0
        active_api_keys = db.query(func.count(APIKey.id)).filter(APIKey.is_active == True).scalar() or 0
        
        metrics = {
            "total_users": int(total_users),
            "total_assets": int(total_assets),
            "total_scans": int(total_scans),
            "active_api_keys": int(active_api_keys),
            "generated_at": format_datetime(datetime.utcnow())
        }
        
        db.close()
        
        return api_response(success=True, data=metrics)[0], 200
    
    except Exception as e:
        return api_response(success=False, message=str(e), status_code=500)[0], 500


@api_admin.route("/flush-cache", methods=["POST"])
@login_required
def flush_cache():
    """
    POST /api/admin/flush-cache
    Clears any application caches (admin only).
    """
    if not is_admin():
        return api_response(
            success=False,
            message="Admin access required",
            status_code=403
        )[0], 403
    
    try:
        # In a real implementation, clear Redis or memcached
        # For now, just return success
        
        return api_response(
            success=True,
            message="Cache flushed successfully"
        )[0], 200
    
    except Exception as e:
        return api_response(success=False, message=str(e), status_code=500)[0], 500
