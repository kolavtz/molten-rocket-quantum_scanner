from flask import Blueprint, render_template, jsonify, request, redirect, url_for
from flask_login import login_required, current_user
from src.services.asset_service import AssetService
from src.services.geo_service import GeoService
from src import database as db

dashboard_bp = Blueprint('quantumshield_dashboard', __name__, url_prefix='/dashboard')

asset_service = AssetService()
geo_service = GeoService()

@dashboard_bp.route('/assets')
@login_required
def dashboard_home():
    """Renders primary Quantumshield Dashboard with charts and maps."""
    assets = asset_service.load_combined_assets()
    summary = asset_service.get_dashboard_summary(assets)
    
    # Render specification template
    return render_template(
        'home.html', 
        assets=assets, 
        summary=summary,
        enterprise_metrics=summary # fallback for backward-compatible lookups if any
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
    """CRUD: Add/Insert Asset details into persistent storage."""
    target = request.form.get("target")
    a_type = request.form.get("type", "Web App")
    owner  = request.form.get("owner", "Unassigned")
    risk   = request.form.get("risk_level", "Medium")
    notes  = request.form.get("notes", "")

    if target:
        db.save_asset({
            "target": target,
            "type": a_type,
            "owner": owner,
            "risk_level": risk,
            "notes": notes
        })
    return redirect(url_for('quantumshield_dashboard.dashboard_home'))
