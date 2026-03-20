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
    target = request.form.get("target")
    a_type = request.form.get("type", "Web App")
    owner  = request.form.get("owner", "Unassigned")
    risk   = request.form.get("risk_level", "Medium")

    if target:
        existing = db_session.query(Asset).filter_by(name=target, is_deleted=False).first()
        if not existing:
            new_asset = Asset(
                name=target,
                url=f"https://{target}",
                asset_type=a_type,
                owner=owner,
                risk_level=risk
            )
            db_session.add(new_asset)
            db_session.commit()
            flash(f"Asset {target} added successfully.", "success")
        else:
            flash(f"Asset {target} already exists.", "warning")
            
    return redirect(request.referrer or url_for('asset_inventory_page'))

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
