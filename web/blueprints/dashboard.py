from flask import Blueprint, render_template, jsonify, request, redirect, url_for, flash
from flask_login import login_required, current_user
from src.services.asset_service import AssetService
from src.services.geo_service import GeoService

dashboard_bp = Blueprint('quantumshield_dashboard', __name__, url_prefix='/dashboard')

asset_service = AssetService()
geo_service = GeoService()

@dashboard_bp.route('/assets')
@login_required
def dashboard_home():
    """Renders primary Quantumshield Dashboard with charts and maps."""
    assets = asset_service.load_combined_assets()
    summary = asset_service.get_dashboard_summary(assets)
    return render_template(
        'home.html', 
        assets=assets, 
        summary=summary,
        enterprise_metrics=summary
    )

@dashboard_bp.route('/geojson')
@login_required
def dashboard_geojson():
    """Returns GeoJSON Cluster Feed for Leaflet Map mapping mapping coordinate overlays."""
    assets = asset_service.load_combined_assets()
    features = []
    
    for asset in assets:
        target = asset.get("asset_name")
        loc = geo_service.get_location(target)
        if loc.get("status") in ("success", "Private"):
            features.append({
                "type": "Feature",
                "geometry": {
                    "type": "Point",
                    "coordinates": [loc["lon"], loc["lat"]]  # [Lon, Lat] for GeoJSON spec
                },
                "properties": {
                    "title": target,
                    "type": asset.get("type", "Unknown"),
                    "risk": asset.get("risk", "Medium"),
                    "location": f"{loc.get('city')}, {loc.get('country')}"
                }
            })
            
    return jsonify({
        "type": "FeatureCollection",
        "features": features
    })

@dashboard_bp.route('/assets', methods=['POST'])
@login_required
def add_asset():
    """CRUD: Add/Insert Asset details into persistent storage natively."""
    from src.db import db_session
    from src.models import Asset
    from flask import jsonify
    import re
    from urllib.parse import urlparse
    from sqlalchemy import func
    
    # Input validation & sanitization
    target = (request.form.get("target") or "").strip()
    a_type = request.form.get("type", "Web App").strip()
    owner = (request.form.get("owner") or "Unassigned").strip()[:100]  # Limit length
    risk = request.form.get("risk_level", "Medium").strip()
    
    # Validate target (hostname or domain)
    if not target or len(target) > 255:
        flash("Invalid target. Must be between 1-255 characters.", "error")
        return redirect(request.referrer or url_for('quantumshield_dashboard.dashboard_home'))
    
    # Sanitize URL: remove protocol if user provided full URL
    hostname = target
    if target.startswith(('http://', 'https://', 'ftp://')):
        try:
            parsed = urlparse(target)
            hostname = parsed.netloc or parsed.path
            # Remove port if present
            if ':' in hostname:
                hostname = hostname.split(':')[0]
        except:
            hostname = target
    
    hostname = hostname.strip().lower()

    # Basic hostname/domain validation (alphanumeric, dots, hyphens)
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$', hostname):
        flash("Invalid target format. Use valid domain, hostname, or URL.", "error")
        return redirect(request.referrer or url_for('quantumshield_dashboard.dashboard_home'))
    
    # Validate type and risk from allowed values
    allowed_types = ["Web App", "API", "VPN/Gateway", "Server"]
    allowed_risks = ["Low", "Medium", "High", "Critical"]
    
    if a_type not in allowed_types:
        a_type = "Web App"
    if risk not in allowed_risks:
        risk = "Medium"

    try:
        existing = db_session.query(Asset).filter(func.lower(Asset.name) == hostname).first()
        if not existing:
            # Build clean URL (always HTTPS)
            clean_url = f"https://{hostname}"
            
            new_asset = Asset(
                name=hostname,
                url=clean_url,
                asset_type=a_type,
                owner=owner,
                risk_level=risk
            )
            db_session.add(new_asset)
            db_session.commit()
            flash(f"Asset {hostname} added successfully.", "success")
        else:
            # If previously soft-deleted, reactivate instead of inserting duplicate.
            if getattr(existing, "is_deleted", False):
                existing.is_deleted = False
                existing.name = hostname
                existing.url = existing.url or f"https://{hostname}"
                existing.asset_type = a_type
                existing.owner = owner
                existing.risk_level = risk
                db_session.commit()
                flash(f"Asset {hostname} restored from recycle bin.", "success")
            else:
                flash(f"Asset {hostname} already exists.", "warning")
    except Exception as e:
        db_session.rollback()
        print(f"[!] Error adding asset: {e}")
        flash("Error adding asset. Please try again.", "error")
            
    return redirect(request.referrer or url_for('quantumshield_dashboard.dashboard_home'))

@dashboard_bp.route('/assets/<asset_id>/delete', methods=['POST'])
@login_required
def delete_asset(asset_id):
    """CRUD: Soft delete Asset from persistent storage."""
    from src.db import db_session
    from src.models import Asset
    asset = db_session.query(Asset).filter_by(id=asset_id, is_deleted=False).first()
    if asset:
        asset.is_deleted = True
        db_session.commit()
        flash(f"Asset deleted.", "success")
    else:
        flash(f"Asset not found.", "error")
    return redirect(request.referrer or url_for('asset_inventory_page'))


# ══════════════════════════════════════════════════════════════
# INVENTORY BULK SCANNING ENDPOINTS
# ══════════════════════════════════════════════════════════════

@dashboard_bp.route('/inventory/scan', methods=['POST'])
@login_required
def scan_all_inventory():
    """
    Manually trigger comprehensive scan of all assets in inventory.
    Captures: TLS/Certs, DNS, CBOM, PQC Posture, KPIs, and all details.
    """
    from src.services.inventory_scan_service import InventoryScanService
    
    try:
        scan_service = InventoryScanService()
        background = request.form.get('background', 'true').lower() == 'true'
        
        result = scan_service.scan_all_assets(background=background)
        
        if background:
            flash("Inventory scan started in background. Check status to monitor progress.", "info")
        else:
            if result.get("status") == "complete":
                summary = result.get("summary", {})
                flash(
                    f"Inventory scan complete: {summary.get('successful')} ✓ / {summary.get('failed')} ✗",
                    "success"
                )
            else:
                flash("Inventory scan failed. Check logs for details.", "error")
    except Exception as e:
        flash(f"Error starting inventory scan: {str(e)}", "error")
    
    return redirect(request.referrer or url_for('quantumshield_dashboard.dashboard_home'))


@dashboard_bp.route('/inventory/scan-status', methods=['GET'])
@login_required
def inventory_scan_status():
    """Get current status of inventory scan operation."""
    from src.services.inventory_scan_service import InventoryScanService
    
    try:
        scan_service = InventoryScanService()
        status = scan_service.get_scan_status()
        
        return jsonify({
            "status": "success",
            "data": status
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@dashboard_bp.route('/inventory/asset/<int:asset_id>/scan', methods=['POST'])
@login_required
def scan_single_asset(asset_id):
    """
    Manually trigger comprehensive scan of a single asset.
    Captures all details: certificates, DNS, CBOM, PQC, KPIs.
    """
    from src.services.inventory_scan_service import InventoryScanService
    from src.db import db_session
    from src.models import Asset
    
    try:
        asset = db_session.query(Asset).filter_by(id=asset_id, is_deleted=False).first()
        if not asset:
            flash("Asset not found.", "error")
            return redirect(request.referrer or url_for('quantumshield_dashboard.dashboard_home'))
        
        scan_service = InventoryScanService()
        result = scan_service.scan_asset(asset)
        
        db_session.commit()
        
        if result.get("status") == "complete":
            flash(f"Asset {asset.name} scanned successfully.", "success")
        else:
            errors = " | ".join(result.get("errors", ["Unknown error"]))
            flash(f"Asset scan completed with errors: {errors}", "warning")
    except Exception as e:
        flash(f"Error scanning asset: {str(e)}", "error")
    
    return redirect(request.referrer or url_for('quantumshield_dashboard.dashboard_home'))


@dashboard_bp.route('/inventory/asset/<int:asset_id>/history', methods=['GET'])
@login_required
def asset_scan_history(asset_id):
    """Get scan history for a specific asset."""
    from src.services.inventory_scan_service import InventoryScanService
    
    try:
        scan_service = InventoryScanService()
        history = scan_service.get_asset_scan_history(asset_id)
        
        return jsonify({
            "status": "success",
            "data": history
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@dashboard_bp.route('/inventory/schedule', methods=['GET', 'POST'])
@login_required
def manage_inventory_schedule():
    """
    Manage inventory scan schedule settings.
    GET: Returns current schedule configuration
    POST: Updates schedule configuration (enable/disable, interval)
    """
    from flask import jsonify
    import os
    
    try:
        if request.method == 'POST':
            # Update schedule settings
            enabled = request.form.get('enabled', 'false').lower() == 'true'
            interval_hours = int(request.form.get('interval_hours', 24))
            
            # Validate interval
            if interval_hours < 1 or interval_hours > 168:  # 1 hour to 1 week
                return jsonify({
                    "status": "error",
                    "message": "Interval must be between 1 and 168 hours"
                }), 400
            
            # Read current config
            from config import BASE_DIR
            config_path = os.path.join(BASE_DIR, 'config.py')
            
            # Store settings (could use database or environment)
            os.environ['INVENTORY_SCAN_ENABLED'] = str(enabled)
            os.environ['INVENTORY_SCAN_INTERVAL_HOURS'] = str(interval_hours)
            
            flash("Schedule updated successfully.", "success")
            
            return jsonify({
                "status": "success",
                "message": "Schedule updated",
                "settings": {
                    "enabled": enabled,
                    "interval_hours": interval_hours
                }
            })
        
        else:  # GET
            # Return current schedule settings
            from config import AUTOMATED_SCAN_ENABLED, AUTOMATED_SCAN_INTERVAL_HOURS
            
            return jsonify({
                "status": "success",
                "data": {
                    "enabled": AUTOMATED_SCAN_ENABLED,
                    "interval_hours": AUTOMATED_SCAN_INTERVAL_HOURS
                }
            })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

