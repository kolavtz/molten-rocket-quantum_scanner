import logging
import typing
from datetime import datetime
from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify, current_app
from flask_login import login_required, current_user
from src.services.asset_service import AssetService
from src.services.geo_service import GeoService
from src.services.dashboard_data_service import DashboardDataService
from src.services.certificate_telemetry_service import CertificateTelemetryService

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint('quantumshield_dashboard', __name__, url_prefix='/dashboard')

asset_service = AssetService()
geo_service = GeoService()

_dashboard_data_cache = {
    "data": None,
    "updated_at": 0,
}
_dashboard_data_ttl = 30


def get_dashboard_data_cached():
    """Fetches real-time dashboard scan aggregates directly."""
    return DashboardDataService.get_all_scans_aggregated()


def _inventory_scan_service():
    """Create scan service bound to app-configured pipeline callable."""
    from src.services.inventory_scan_service import InventoryScanService

    scan_runner = current_app.config.get("RUN_SCAN_PIPELINE_FUNC")
    return InventoryScanService(scan_runner=scan_runner)

@dashboard_bp.route('/assets')
@login_required
def dashboard_home():
    """Renders primary Quantumshield Dashboard with charts and maps using unified data service."""
    try:
        # Canonical route payload: combine best of both approaches
        # 1) Aggregate KPIs (fast DB-level query path)
        # 2) Asset roster rows (inventory ORM path)
        data = get_dashboard_data_cached()
        assets = asset_service.load_combined_assets()
        summary = asset_service.get_dashboard_summary(assets)

        # Keep aggregate metadata available without breaking template expectations.
        summary["total_scans"] = typing.cast(dict, data).get("total_scans", 0)
        summary["aggregated_kpis"] = typing.cast(dict, data).get("aggregated_kpis", {})
        summary["distributions"] = typing.cast(dict, data).get("distributions", {})

        return render_template(
            'home.html',
            assets=assets,
            summary=summary,
            enterprise_metrics=summary,
        )
    except Exception as e:
        current_app.logger.error(f"Error loading dashboard data: {e}")
        # Fallback to asset service for backward compatibility
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
    
    wants_json = request.is_json or (request.accept_mimetypes.best == "application/json")
    payload = request.get_json(silent=True) if request.is_json else request.form

    # Input validation & sanitization
    target = (payload.get("target") or "").strip()
    a_type = str(payload.get("type") or payload.get("asset_type") or "Web App").strip()
    owner = str(payload.get("owner") or "Unassigned").strip()[:100]  # Limit length
    risk = str(payload.get("risk_level") or "Medium").strip()
    
    # Validate target (hostname or domain)
    if not target or len(target) > 255:
        if wants_json:
            return jsonify({"status": "error", "message": "Invalid target. Must be between 1-255 characters."}), 400
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
        if wants_json:
            return jsonify({"status": "error", "message": "Invalid target format. Use valid domain, hostname, or URL."}), 400
        flash("Invalid target format. Use valid domain, hostname, or URL.", "error")
        return redirect(request.referrer or url_for('quantumshield_dashboard.dashboard_home'))
    
    # Validate type and risk from allowed values
    allowed_types = ["Web App", "API", "VPN/Gateway", "Server", "Load Balancer", "Other"]
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
            try:
                from web.app import invalidate_dashboard_cache

                invalidate_dashboard_cache()
            except Exception:
                pass
            if wants_json:
                return jsonify({
                    "status": "success",
                    "message": f"Asset {hostname} added successfully.",
                    "data": {"target": hostname, "created": True, "restored": False},
                }), 200
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
                try:
                    from web.app import invalidate_dashboard_cache

                    invalidate_dashboard_cache()
                except Exception:
                    pass
                if wants_json:
                    return jsonify({
                        "status": "success",
                        "message": f"Asset {hostname} restored from recycle bin.",
                        "data": {"target": hostname, "created": False, "restored": True},
                    }), 200
                flash(f"Asset {hostname} restored from recycle bin.", "success")
            else:
                if wants_json:
                    return jsonify({
                        "status": "success",
                        "message": f"Asset {hostname} already exists.",
                        "data": {"target": hostname, "created": False, "restored": False, "exists": True},
                    }), 200
                flash(f"Asset {hostname} already exists.", "warning")
    except Exception as e:
        db_session.rollback()
        current_app.logger.error(f"[!] Error adding asset: {e}")
        if wants_json:
            return jsonify({"status": "error", "message": "Error adding asset. Please try again."}), 500
        flash("Error adding asset. Please try again.", "error")
            
    return redirect(request.referrer or url_for('quantumshield_dashboard.dashboard_home'))

@dashboard_bp.route('/assets/<asset_id>/delete', methods=['POST'])
@login_required
def delete_asset(asset_id):
    """Compatibility route delegating to canonical inventory delete/cascade flow.

    Authorization policy remains Admin/Manager only via `web.routes.assets.asset_delete`.
    """
    from web.routes.assets import asset_delete as inventory_asset_delete

    return inventory_asset_delete(int(asset_id))


@dashboard_bp.route('/api/assets', methods=['POST'])
@login_required
def add_asset_api():
    """JSON API wrapper for dashboard asset creation/restoration."""
    return add_asset()


@dashboard_bp.route('/api/assets/<asset_id>/delete', methods=['POST'])
@login_required
def delete_asset_api(asset_id):
    """JSON API wrapper for dashboard asset deletion."""
    return delete_asset(asset_id)


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
    wants_json = "application/json" in (request.headers.get("Accept", "") or "")

    try:
        scan_service = _inventory_scan_service()
        background = request.form.get('background', 'true').lower() == 'true'
        
        result = scan_service.scan_all_assets(background=background)

        if wants_json:
            code = 200 if result.get("status") in {"started", "complete", "in_progress"} else 500
            return jsonify(result), code
        
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
        if wants_json:
            return jsonify({"status": "error", "message": str(e)}), 500
        flash(f"Error starting inventory scan: {str(e)}", "error")
    
    return redirect(request.referrer or url_for('quantumshield_dashboard.dashboard_home'))


@dashboard_bp.route('/inventory/scan-status', methods=['GET'])
@login_required
def inventory_scan_status():
    """Get current status of inventory scan operation."""

    try:
        scan_service = _inventory_scan_service()
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
    from src.db import db_session
    from src.models import Asset
    
    try:
        asset = db_session.query(Asset).filter_by(id=asset_id, is_deleted=False).first()
        if not asset:
            flash("Asset not found.", "error")
            return redirect(request.referrer or url_for('quantumshield_dashboard.dashboard_home'))
        
        scan_service = _inventory_scan_service()
        result = scan_service.scan_asset(asset)
        
        db_session.commit()
        try:
            from web.app import invalidate_dashboard_cache

            invalidate_dashboard_cache()
        except Exception:
            pass
        
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

    try:
        scan_service = _inventory_scan_service()
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


# ════════════════════════════════════════════════════════════════════
# CERTIFICATE TELEMETRY ENDPOINTS
# ════════════════════════════════════════════════════════════════════

@dashboard_bp.route('/api/certificates/telemetry', methods=['GET'])
@login_required
def get_certificates_telemetry():
    """
    Complete SSL/TLS certificate telemetry API endpoint.
    
    Returns all certificate metrics in a single response:
    - KPIs (expiring, expired counts)
    - Timeline distribution (4-bucket expiry timeline)
    - Inventory (full certificate list with status)
    - Distributions (key length, cipher suite, TLS version, CA)
    - Weak cryptography metrics (weak keys, weak TLS, expired, self-signed)
    - Issues count (CBOM metric)
    
    Used by: Asset inventory dashboard, CBOM dashboard, PQC dashboard
    
    Query Parameters:
    - limit: Int, max results for inventory (default: 100)
    - include_weak: Bool, include weak crypto metrics (default: true)
    
    Response Structure:
    {
        "status": "ok",
        "timestamp": "2025-03-21T...",
        "data": {
            "kpis": {
                "total_certificates": int,
                "expiring_certificates": int,
                "expired_certificates": int,
            },
            "expiry_timeline": {"0-30": int, "30-60": int, ...},
            "tls_version_distribution": {"TLS 1.3": int, ...},
            "key_length_distribution": {"2048": int, ...},
            "certificate_inventory": [...],
            "certificate_authority_distribution": [...],
            "cipher_suite_distribution": [...],
            "weak_cryptography": {
                "weak_keys": int,
                "weak_tls": int,
                "expired": int,
                "self_signed": int
            },
            "cert_issues_count": int
        }
    }
    """
    try:
        limit = request.args.get('limit', 100, type=int)
        include_weak = request.args.get('include_weak', True, type=lambda x: x.lower() == 'true')
        
        # Create service instance
        cert_service = CertificateTelemetryService()
        
        # Fetch complete telemetry
        telemetry = cert_service.get_complete_certificate_telemetry()
        
        # Optionally include weak crypto metrics
        if not include_weak:
            telemetry.pop("weak_cryptography", None)
        
        # Limit inventory results if specified
        if limit and 'certificate_inventory' in telemetry:
            telemetry['certificate_inventory'] = telemetry['certificate_inventory'][:limit]
        
        return jsonify({
            "status": "ok",
            "timestamp": datetime.now().isoformat(),
            "data": telemetry,
        }), 200
    
    except Exception as e:
        current_app.logger.error(f"Error fetching certificate telemetry: {e}")
        return jsonify({
            "status": "error",
            "message": str(e),
            "timestamp": datetime.now().isoformat(),
        }), 500


@dashboard_bp.route('/api/certificates/inventory', methods=['GET'])
@login_required
def get_certificate_inventory():
    """
    Get detailed certificate inventory with optional filtering.
    
    Query Parameters:
    - limit: Int, max results (default: 100)
    - status: Str, filter by status (Expired|Expiring|Valid|Critical)
    - issuer: Str, filter by issuer/CA name
    
    Response: List of certificate dicts with full details
    """
    try:
        limit = request.args.get('limit', 100, type=int)
        status_filter = request.args.get('status', '').strip()
        issuer_filter = request.args.get('issuer', '').strip()
        
        cert_service = CertificateTelemetryService()
        inventory = cert_service.get_certificate_inventory(limit=limit)
        
        # Apply filters if specified
        if status_filter:
            inventory = [c for c in inventory if c.get('status') == status_filter]
        
        if issuer_filter:
            inventory = [c for c in inventory if issuer_filter.lower() in c.get('issuer', '').lower()]
        
        return jsonify({
            "status": "ok",
            "count": len(inventory),
            "timestamp": datetime.now().isoformat(),
            "data": inventory,
        }), 200
    
    except Exception as e:
        current_app.logger.error(f"Error fetching certificate inventory: {e}")
        return jsonify({
            "status": "error",
            "message": str(e),
            "timestamp": datetime.now().isoformat(),
        }), 500


@dashboard_bp.route('/api/certificates/weak', methods=['GET'])
@login_required
def get_weak_cryptography():
    """
    Get weak cryptography metrics for security dashboard.
    
    Returns breakdown of cryptographic issues:
    - weak_keys: RSA keys < 2048-bit
    - weak_tls: TLS versions 1.0/1.1/SSL
    - expired: Certificates past valid_until date
    - self_signed: Issuer == Subject (self-signed certs)
    
    Used by: Security posture dashboard, compliance reports
    """
    try:
        cert_service = CertificateTelemetryService()
        metrics = cert_service.get_weak_cryptography_metrics()
        
        return jsonify({
            "status": "ok",
            "timestamp": datetime.now().isoformat(),
            "data": metrics,
        }), 200
    
    except Exception as e:
        current_app.logger.error(f"Error fetching weak crypto metrics: {e}")
        return jsonify({
            "status": "error",
            "message": str(e),
            "timestamp": datetime.now().isoformat(),
        }), 500


@dashboard_bp.route('/api/certificates/distribution/tls', methods=['GET'])
@login_required
def get_tls_distribution():
    """Get TLS version distribution across all certificates."""
    try:
        cert_service = CertificateTelemetryService()
        distribution = cert_service.get_tls_version_distribution()
        
        return jsonify({
            "status": "ok",
            "timestamp": datetime.now().isoformat(),
            "data": distribution,
        }), 200
    except Exception as e:
        current_app.logger.error(f"Error fetching TLS distribution: {e}")
        return jsonify({
            "status": "error",
            "message": str(e),
        }), 500


@dashboard_bp.route('/api/certificates/distribution/keys', methods=['GET'])
@login_required
def get_key_distribution():
    """Get RSA key length distribution across all certificates."""
    try:
        cert_service = CertificateTelemetryService()
        distribution = cert_service.get_key_length_distribution()
        
        return jsonify({
            "status": "ok",
            "timestamp": datetime.now().isoformat(),
            "data": distribution,
        }), 200
    except Exception as e:
        current_app.logger.error(f"Error fetching key distribution: {e}")
        return jsonify({
            "status": "error",
            "message": str(e),
        }), 500


@dashboard_bp.route('/api/certificates/distribution/ca', methods=['GET'])
@login_required
def get_ca_distribution():
    """Get Certificate Authority distribution (portfolio analysis)."""
    try:
        limit = request.args.get('limit', 10, type=int)
        cert_service = CertificateTelemetryService()
        distribution = cert_service.get_certificate_authority_distribution(limit=limit)
        
        return jsonify({
            "status": "ok",
            "timestamp": datetime.now().isoformat(),
            "data": distribution,
        }), 200
    except Exception as e:
        current_app.logger.error(f"Error fetching CA distribution: {e}")
        return jsonify({
            "status": "error",
            "message": str(e),
        }), 500


@dashboard_bp.route('/api/cbom/metrics', methods=['GET'])
@login_required
def get_cbom_metrics():
    """CBOM metrics API endpoint with real MySQL data."""
    try:
        from src.services.cbom_service import CbomService
        asset_id = request.args.get('asset_id', type=int)
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')

        cbom_data = CbomService.get_cbom_dashboard_data(asset_id=asset_id, start_date=start_date, end_date=end_date, limit=200)

        return jsonify({
            'status': 'ok',
            'timestamp': datetime.now().isoformat(),
            'data': {
                'kpis': cbom_data.get('kpis', {}),
                'key_length_distribution': cbom_data.get('key_length_distribution', {}),
                'cipher_usage': cbom_data.get('cipher_usage', {}),
                'top_cas': cbom_data.get('top_cas', {}),
                'protocols': cbom_data.get('protocols', {}),
                'weakness_heatmap': cbom_data.get('weakness_heatmap', []),
                'meta': cbom_data.get('meta', {}),
            }
        }), 200
    except Exception as e:
        current_app.logger.error(f'Error fetching CBOM metrics: {e}')
        return jsonify({'status': 'error', 'message': str(e)}), 500


@dashboard_bp.route('/api/pqc/metrics', methods=['GET'])
@login_required
def get_pqc_metrics():
    """PQC posture metrics API endpoint with asset-based aggregation."""
    try:
        from src.services.pqc_service import PQCService
        from datetime import datetime as _dt
        asset_id = request.args.get('asset_id', type=int)
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')

        parsed_start = None
        parsed_end = None
        if start_date:
            try:
                parsed_start = _dt.fromisoformat(start_date)
            except Exception:
                parsed_start = None
        if end_date:
            try:
                parsed_end = _dt.fromisoformat(end_date)
            except Exception:
                parsed_end = None

        pqc_data = PQCService.get_pqc_dashboard_data(asset_id=asset_id, start_date=parsed_start, end_date=parsed_end, limit=200)

        return jsonify({
            'status': 'ok',
            'timestamp': datetime.now().isoformat(),
            'data': {
                'kpis': pqc_data.get('kpis', {}),
                'grade_counts': pqc_data.get('grade_counts', {}),
                'status_distribution': pqc_data.get('status_distribution', {}),
                'risk_heatmap': pqc_data.get('risk_heatmap', []),
                'recommendations': pqc_data.get('recommendations', []),
                'meta': pqc_data.get('meta', {}),
            }
        }), 200
    except Exception as e:
        current_app.logger.error(f'Error fetching PQC metrics: {e}')
        return jsonify({'status': 'error', 'message': str(e)}), 500


@dashboard_bp.route('/api/pqc/inventory', methods=['GET'])
@login_required
def get_pqc_inventory():
    """PQC inventory endpoint for asset-based PQC classifications."""
    try:
        from src.services.pqc_service import PQCService
        asset_id = request.args.get('asset_id', type=int)
        limit = request.args.get('limit', 100, type=int)
        offset = request.args.get('offset', 0, type=int)

        rows, total_count = PQCService.get_pqc_inventory(asset_id=asset_id, limit=limit, offset=offset)

        return jsonify({
            'status': 'ok',
            'timestamp': datetime.now().isoformat(),
            'count': len(rows),
            'total_count': total_count,
            'data': rows,
        }), 200
    except Exception as e:
        current_app.logger.error(f'Error fetching PQC inventory: {e}')
        return jsonify({'status': 'error', 'message': str(e)}), 500


@dashboard_bp.route('/api/pqc/heatmap', methods=['GET'])
@login_required
def get_pqc_heatmap():
    """PQC risk heatmap as JSON."""
    try:
        from src.services.pqc_service import PQCService
        from datetime import datetime as _dt
        asset_id = request.args.get('asset_id', type=int)
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')

        parsed_start = None
        parsed_end = None
        if start_date:
            try:
                parsed_start = _dt.fromisoformat(start_date)
            except Exception:
                parsed_start = None
        if end_date:
            try:
                parsed_end = _dt.fromisoformat(end_date)
            except Exception:
                parsed_end = None

        pqc_data = PQCService.get_pqc_dashboard_data(asset_id=asset_id, start_date=parsed_start, end_date=parsed_end, limit=200)

        return jsonify({
            'status': 'ok',
            'timestamp': datetime.now().isoformat(),
            'data': pqc_data.get('risk_heatmap', []),
        }), 200
    except Exception as e:
        current_app.logger.error(f'Error fetching PQC heatmap: {e}')
        return jsonify({'status': 'error', 'message': str(e)}), 500


@dashboard_bp.route('/api/cbom/inventory', methods=['GET'])
@login_required
def get_cbom_inventory():
    """CBOM inventory endpoint for application/certificate rows."""
    try:
        from src.services.cbom_service import CbomService
        asset_id = request.args.get('asset_id', type=int)
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        limit = request.args.get('limit', 100, type=int)

        cbom_data = CbomService.get_cbom_dashboard_data(asset_id=asset_id, start_date=start_date, end_date=end_date, limit=limit)
        rows = cbom_data.get('applications', [])

        return jsonify({
            'status': 'ok',
            'timestamp': datetime.now().isoformat(),
            'count': len(rows),
            'data': rows,
        }), 200
    except Exception as e:
        current_app.logger.error(f'Error fetching CBOM inventory: {e}')
        return jsonify({'status': 'error', 'message': str(e)}), 500


@dashboard_bp.route('/api/cbom/heatmap', methods=['GET'])
@login_required
def get_cbom_heatmap():
    """CBOM weakness heatmap as JSON."""
    try:
        from src.services.cbom_service import CbomService
        asset_id = request.args.get('asset_id', type=int)
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')

        cbom_data = CbomService.get_cbom_dashboard_data(asset_id=asset_id, start_date=start_date, end_date=end_date, limit=200)

        return jsonify({
            'status': 'ok',
            'timestamp': datetime.now().isoformat(),
            'data': cbom_data.get('weakness_heatmap', []),
        }), 200
    except Exception as e:
        current_app.logger.error(f'Error fetching CBOM heatmap: {e}')
        return jsonify({'status': 'error', 'message': str(e)}), 500


@dashboard_bp.route('/api/cyber/metrics', methods=['GET'])
@login_required
def get_cyber_metrics():
    """Cyber rating metrics endpoint with asset-joined, orphan-safe aggregation."""
    try:
        from src.services.cyber_reporting_service import CyberReportingService

        asset_id = request.args.get('asset_id', type=int)
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        limit = request.args.get('limit', 200, type=int)

        cyber_data = CyberReportingService.get_cyber_rating_data(
            asset_id=asset_id,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
        )

        return jsonify({
            'status': 'ok',
            'timestamp': datetime.now().isoformat(),
            'data': {
                'kpis': cyber_data.get('kpis', {}),
                'grade_counts': cyber_data.get('grade_counts', {}),
                'status_distribution': cyber_data.get('status_distribution', {}),
                'risk_heatmap': cyber_data.get('risk_heatmap', []),
                'recommendations': cyber_data.get('recommendations', []),
                'meta': cyber_data.get('meta', {}),
            }
        }), 200
    except Exception as e:
        current_app.logger.error(f'Error fetching cyber metrics: {e}')
        return jsonify({'status': 'error', 'message': str(e)}), 500


@dashboard_bp.route('/api/cyber/inventory', methods=['GET'])
@login_required
def get_cyber_inventory():
    """Cyber telemetry table endpoint (asset-level rows)."""
    try:
        from src.services.cyber_reporting_service import CyberReportingService

        asset_id = request.args.get('asset_id', type=int)
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        limit = request.args.get('limit', 100, type=int)

        cyber_data = CyberReportingService.get_cyber_rating_data(
            asset_id=asset_id,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
        )
        rows = cyber_data.get('applications', [])

        return jsonify({
            'status': 'ok',
            'timestamp': datetime.now().isoformat(),
            'count': len(rows),
            'data': rows,
        }), 200
    except Exception as e:
        current_app.logger.error(f'Error fetching cyber inventory: {e}')
        return jsonify({'status': 'error', 'message': str(e)}), 500


@dashboard_bp.route('/api/cyber/heatmap', methods=['GET'])
@login_required
def get_cyber_heatmap():
    """Cyber risk heatmap endpoint."""
    try:
        from src.services.cyber_reporting_service import CyberReportingService

        asset_id = request.args.get('asset_id', type=int)
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')

        cyber_data = CyberReportingService.get_cyber_rating_data(
            asset_id=asset_id,
            start_date=start_date,
            end_date=end_date,
            limit=200,
        )

        return jsonify({
            'status': 'ok',
            'timestamp': datetime.now().isoformat(),
            'data': cyber_data.get('risk_heatmap', []),
        }), 200
    except Exception as e:
        current_app.logger.error(f'Error fetching cyber heatmap: {e}')
        return jsonify({'status': 'error', 'message': str(e)}), 500


@dashboard_bp.route('/api/reporting/summary', methods=['GET'])
@login_required
def get_reporting_summary():
    """Reporting dashboard summary endpoint with active-asset consistency."""
    try:
        from src.services.cyber_reporting_service import CyberReportingService

        summary = CyberReportingService.get_reporting_summary()
        cleanup_sql = CyberReportingService.get_orphan_cleanup_sql_examples()

        return jsonify({
            'status': 'ok',
            'timestamp': datetime.now().isoformat(),
            'data': {
                'summary': summary,
                'orphan_cleanup_sql_examples': cleanup_sql,
            },
        }), 200
    except Exception as e:
        current_app.logger.error(f'Error fetching reporting summary: {e}')
        return jsonify({'status': 'error', 'message': str(e)}), 500


