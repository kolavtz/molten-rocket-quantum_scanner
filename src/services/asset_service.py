"""
AssetService configuration layer for QuantumShield.
Loads and calculates live dashboard telemetry scoring aggregates.
"""

from datetime import datetime, timezone
from collections import Counter
from typing import Dict, List
import json

import logging
from sqlalchemy import text, func, desc

from src.models import Asset, Scan, Certificate, CBOMEntry, PQCClassification, DiscoveryItem
from src.db import db_session
from urllib.parse import urlparse
import ipaddress
from src.services.certificate_telemetry_service import CertificateTelemetryService
from src.services.ip_location_service import IPLocationService

logger = logging.getLogger(__name__)

class AssetService:
    def __init__(self):
         self.ip_locator = IPLocationService()

    def _as_list(self, value):
        if value is None:
            return []
        if isinstance(value, list):
            return value
        if isinstance(value, tuple):
            return list(value)
        if isinstance(value, set):
            return list(value)
        return [value]

    def _coerce_datetime(self, value):
        if value is None:
            return None
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            raw = value.strip()
            if not raw:
                return None
            try:
                return datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                return None
        return None

    def _format_scan_time(self, value) -> str:
        dt = self._coerce_datetime(value)
        if dt is not None:
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        if isinstance(value, str) and value.strip():
            return value.strip()
        return "Pending"

    def _normalize_target(self, raw_target: str) -> str:
        target = str(raw_target or "").strip()
        if not target:
            return ""

        if "://" in target:
            try:
                parsed = urlparse(target)
                target = parsed.hostname or parsed.netloc or parsed.path or target
            except Exception:
                pass

        target = target.strip().lower()
        if not target:
            return ""

        try:
            ipaddress.ip_address(target)
            return target
        except ValueError:
            pass

        if ":" in target and target.count(":") == 1:
            host, maybe_port = target.rsplit(":", 1)
            if maybe_port.isdigit():
                target = host

        return target

    def _safe_json_dict(self, value) -> dict:
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            raw = value.strip()
            if not raw:
                return {}
            try:
                parsed = json.loads(raw)
                return parsed if isinstance(parsed, dict) else {}
            except Exception:
                return {}
        return {}

    def load_combined_assets(self) -> list:
        """Hydrate inventory rows from MySQL tables only (assets/scans/certificates)."""

        assets_out = []
        asset_query = db_session.query(Asset)
        if hasattr(asset_query, "filter"):
            asset_query = asset_query.filter(Asset.is_deleted == False, Asset.deleted_at.is_(None))
        elif hasattr(asset_query, "filter_by"):
            asset_query = asset_query.filter_by(is_deleted=False)
        if hasattr(asset_query, "order_by"):
            asset_query = asset_query.order_by(Asset.target.asc())
        db_assets = self._as_list(asset_query.all()) if hasattr(asset_query, "all") else []

        latest_scan_by_target: Dict[str, Scan] = {}
        scan_query = db_session.query(Scan)
        if hasattr(scan_query, "filter"):
            scan_query = scan_query.filter(Scan.is_deleted == False, Scan.deleted_at.is_(None), Scan.status == "complete")
        elif hasattr(scan_query, "filter_by"):
            scan_query = scan_query.filter_by(status="complete")
        scans = self._as_list(scan_query.all()) if hasattr(scan_query, "all") else []
        for scan in scans:
            key = self._normalize_target(getattr(scan, "target", "") or "")
            if not key:
                continue
            previous = latest_scan_by_target.get(key)
            if previous is None:
                latest_scan_by_target[key] = scan
                continue
            prev_ts = (
                getattr(previous, "completed_at", None)
                or getattr(previous, "scanned_at", None)
                or getattr(previous, "started_at", None)
            )
            cur_ts = (
                getattr(scan, "completed_at", None)
                or getattr(scan, "scanned_at", None)
                or getattr(scan, "started_at", None)
            )
            prev_dt = self._coerce_datetime(prev_ts) or datetime.min
            cur_dt = self._coerce_datetime(cur_ts) or datetime.min
            if cur_dt >= prev_dt:
                latest_scan_by_target[key] = scan

        asset_ids = [int(a.id) for a in db_assets if getattr(a, "id", None) is not None]
        latest_cert_by_asset: Dict[int, Certificate] = {}
        certs = []
        if asset_ids:
            try:
                cert_query = db_session.query(Certificate)
                if hasattr(cert_query, "filter"):
                    cert_query = cert_query.filter(Certificate.is_deleted == False, Certificate.deleted_at.is_(None), Certificate.asset_id.in_(asset_ids))
                    certs = self._as_list(cert_query.all()) if hasattr(cert_query, "all") else []
                else:
                    certs = []
            except Exception:
                # Legacy deployments may not yet include new certificate columns.
                # Keep inventory functional and degrade gracefully without cert joins.
                certs = []
        for cert in certs:
            asset_id = int(getattr(cert, "asset_id", 0) or 0)
            if asset_id <= 0:
                continue
            prev = latest_cert_by_asset.get(asset_id)
            if prev is None:
                latest_cert_by_asset[asset_id] = cert
                continue
            prev_ts = getattr(prev, "valid_until", None) or datetime.min
            cur_ts = getattr(cert, "valid_until", None) or datetime.min
            if cur_ts >= prev_ts:
                latest_cert_by_asset[asset_id] = cert

        now_naive_utc = datetime.now(timezone.utc).replace(tzinfo=None)

        for meta in db_assets:
            target_key = self._normalize_target(meta.name or meta.target or "")
            latest_scan = latest_scan_by_target.get(target_key)
            latest_cert = latest_cert_by_asset.get(int(getattr(meta, "id", 0) or 0))

            risk_score = 0.0
            risk_level = str(getattr(meta, "risk_level", "") or "").strip()
            cert_days = None
            key_length = 0
            cert_status = "Not Scanned"
            tls_version = "Unknown"
            cipher_suite = "Unknown"
            ca_name = "Unknown"

            if latest_scan:
                risk_score = float(getattr(latest_scan, "overall_pqc_score", 0) or 0)
                if not risk_level:
                    risk_level = self._score_to_risk(risk_score)

            if latest_cert:
                key_length = int(getattr(latest_cert, "key_length", 0) or 0)
                tls_version = str(getattr(latest_cert, "tls_version", "") or "Unknown")
                cipher_suite = str(getattr(latest_cert, "cipher_suite", "") or "Unknown")
                ca_name = str(getattr(latest_cert, "ca", "") or getattr(latest_cert, "issuer", "") or "Unknown")
                valid_until = getattr(latest_cert, "valid_until", None)
                if valid_until:
                    cert_days = int((valid_until - now_naive_utc).days)
                    if cert_days < 0:
                        cert_status = "Expired"
                    elif cert_days <= 30:
                        cert_status = "Expiring"
                    else:
                        cert_status = "Valid"
                else:
                    cert_status = "Unknown"

            last_scan_ts = None
            last_scan_id = None
            scan_status = "Never"
            scan_kind = "N/A"
            scanned_by = "N/A"
            latest_scan_report = {}
            if latest_scan is not None:
                last_scan_ts = (
                    getattr(latest_scan, "completed_at", None)
                    or getattr(latest_scan, "scanned_at", None)
                    or getattr(latest_scan, "started_at", None)
                )
                last_scan_id = getattr(latest_scan, "scan_id", None) or getattr(latest_scan, "id", None)
                scan_status = str(getattr(latest_scan, "status", "") or "Unknown").title()
                latest_scan_report = self._safe_json_dict(getattr(latest_scan, "report_json", None))
                # Add overall_pqc_score to latest_scan_report if missing for consistent UI rendering
                if "overall_pqc_score" not in latest_scan_report and getattr(latest_scan, "overall_pqc_score", None) is not None:
                    latest_scan_report["overall_pqc_score"] = float(latest_scan.overall_pqc_score)
                scan_kind = str(latest_scan_report.get("scan_kind") or "N/A")
                scanned_by = str(latest_scan_report.get("scanned_by") or "N/A")

            # Ensure we use exactly 'asset_name' for key matching in UI and API
            asset_display_name = str(meta.name or meta.target or "").strip()

            assets_out.append({
                "id": meta.id,
                "name": asset_display_name,
                "asset_name": asset_display_name,
                "url": meta.url or (f"https://{asset_display_name}" if not asset_display_name.startswith("http") else asset_display_name),
                "ipv4": str(getattr(meta, "ipv4", "") or ""),
                "ipv6": str(getattr(meta, "ipv6", "") or ""),
                "asset_type": str(meta.asset_type or "Web App"),
                "type": str(meta.asset_type or "Web App"),
                "asset_class": str(getattr(latest_scan, "asset_class", "") or "Inventory"),
                "is_deleted": bool(getattr(meta, "is_deleted", False)),
                "risk_level": risk_level or "Medium",
                "risk": risk_level or "Medium",
                "risk_score": risk_score,
                "cert_status": cert_status,
                "cert_days": cert_days,
                "key_length": key_length,
                "tls_version": tls_version,
                "cipher_suite": cipher_suite,
                "ca": ca_name,
                "last_scan_id": last_scan_id,
                "last_scan": self._format_scan_time(last_scan_ts),
                "scan_status": scan_status,
                "scan_kind": scan_kind,
                "scanned_by": scanned_by,
                "owner": str(meta.owner or "Unassigned"),
                "notes": str(getattr(meta, "notes", "") or ""),
                "overview": {
                    "last_scan_report": latest_scan_report,
                    "certificate_id": getattr(latest_cert, "id", None) if latest_cert else None
                },
            })

        return assets_out

    def get_inventory_view_model(self, testing_mode: bool = False) -> dict:
        """Build full asset inventory page view-model from MySQL tables only."""

        if testing_mode:
            return {
                "empty": True,
                "kpis": {
                    "total_assets": 0,
                    "public_web_apps": 0,
                    "apis": 0,
                    "servers": 0,
                    "expiring_certificates": 0,
                    "expired_certificates": 0,
                    "weak_crypto_issues": 0,
                    "high_risk_assets": 0,
                },
                "asset_type_distribution": {
                    "Web Applications": 0,
                    "APIs": 0,
                    "Servers": 0,
                    "Load Balancers": 0,
                    "Other": 0,
                },
                "asset_risk_distribution": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
                "risk_heatmap": [],
                "certificate_expiry_timeline": {"0-30": 0, "30-60": 0, "60-90": 0, ">90": 0},
                "ip_version_breakdown": {"IPv4": 0, "IPv6": 0},
                "assets": [],
                "nameserver_records": [],
                "crypto_overview": [],
                "asset_locations": [],
                "certificate_inventory": [],
                "weak_cryptography": {"weak_keys": 0, "weak_tls": 0, "expired": 0, "self_signed": 0},
                "cert_issues_count": 0,
            }

        assets = self.load_combined_assets()
        assets = [row for row in assets if not row.get("is_deleted")]
        type_dist = Counter(a.get("type", "Other") for a in assets)
        risk_dist = Counter(a.get("risk", "Medium") for a in assets)
        cert_bucket = Counter({"0-30": 0, "30-60": 0, "60-90": 0, ">90": 0})

        # Initialize CertificateTelemetryService for enhanced metrics
        try:
            cert_service = CertificateTelemetryService()
            weak_crypto_metrics = cert_service.get_weak_cryptography_metrics()
            cert_issues_count = cert_service.get_certificate_issues_count()
            expired_certs = cert_service.get_expired_certificates_count()
        except Exception:
            # Fallback if service fails
            weak_crypto_metrics = {"weak_keys": 0, "weak_tls": 0, "expired": 0, "self_signed": 0}
            cert_issues_count = 0
            expired_certs = 0

        for row in assets:
            days = row.get("cert_days")
            if not isinstance(days, (int, float)):
                continue
            if days <= 30:
                cert_bucket["0-30"] += 1
            elif days <= 60:
                cert_bucket["30-60"] += 1
            elif days <= 90:
                cert_bucket["60-90"] += 1
            else:
                cert_bucket[">90"] += 1

        ipv4_count = sum(1 for a in assets if str(a.get("ipv4") or "").strip())
        ipv6_count = sum(1 for a in assets if str(a.get("ipv6") or "").strip())
        total_ip_assets = max(1, ipv4_count + ipv6_count)

        owners = sorted({str(a.get("owner") or "Unassigned") for a in assets}) or ["Unassigned"]
        heatmap = []
        for owner in owners:
            owner_rows = [a for a in assets if str(a.get("owner") or "Unassigned") == owner]
            for band in ("Critical", "High", "Medium", "Low"):
                value = sum(1 for a in owner_rows if str(a.get("risk") or "") == band)
                heatmap.append({"x": owner, "y": band, "value": value})

        certificate_inventory = []
        crypto_overview = []
        for a in assets:
            cert_status = str(a.get("cert_status") or "")
            if cert_status and cert_status != "Not Scanned":
                certificate_inventory.append(
                    {
                        "asset": a.get("asset_name"),
                        "issuer": a.get("ca") or "Unknown",
                        "key_length": int(a.get("key_length") or 0),
                        "tls_version": a.get("tls_version") or "Unknown",
                        "days_remaining": a.get("cert_days"),
                        "status": cert_status,
                    }
                )

            if int(a.get("key_length") or 0) > 0:
                crypto_overview.append(
                    {
                        "asset": a.get("asset_name"),
                        "key_length": int(a.get("key_length") or 0),
                        "cipher_suite": a.get("cipher_suite") or "Unknown",
                        "tls_version": a.get("tls_version") or "Unknown",
                        "ca": a.get("ca") or "Unknown",
                        "last_scan": str(a.get("last_scan") or "")[:10],
                    }
                )

        # DNS records are sourced from relational tables only and tied to active assets/scans.
        nameserver_records = []
        try:
            dns_rows = db_session.execute(
                text(
                    """
                    SELECT d.hostname, d.record_type, d.record_value, d.ttl
                    FROM asset_dns_records d
                    INNER JOIN scans s ON s.scan_id = d.scan_id
                    INNER JOIN assets a ON LOWER(a.target) = LOWER(s.target)
                    WHERE COALESCE(a.is_deleted, 0) = 0
                      AND COALESCE(s.is_deleted, 0) = 0
                    ORDER BY COALESCE(d.resolved_at, s.scanned_at, s.started_at) DESC, d.id DESC
                    LIMIT 500
                    """
                )
            ).mappings().all()
            for row in dns_rows:
                record_type = str(row.get("record_type") or "A").upper()
                value = str(row.get("record_value") or "")
                nameserver_records.append(
                    {
                        "hostname": str(row.get("hostname") or ""),
                        "type": record_type,
                        "ip": value if record_type in {"A", "MX", "NS", "PTR", "CNAME"} else "",
                        "ipv6": value if record_type == "AAAA" else "",
                        "ttl": int(row.get("ttl") or 300),
                    }
                )
        except Exception:
            nameserver_records = []

        return {
            "empty": len(assets) == 0,
            "kpis": {
                "total_assets": len(assets),
                "public_web_apps": sum(1 for a in assets if a.get("type") == "Web App"),
                "apis": sum(1 for a in assets if a.get("type") == "API"),
                "servers": sum(1 for a in assets if a.get("type") == "Server"),
                "expiring_certificates": sum(1 for a in assets if a.get("cert_status") == "Expiring"),
                "expired_certificates": expired_certs,
                "weak_crypto_issues": weak_crypto_metrics.get("weak_keys", 0) + weak_crypto_metrics.get("weak_tls", 0),
                "high_risk_assets": sum(1 for a in assets if a.get("risk") in {"Critical", "High"}),
            },
            "asset_type_distribution": {
                "Web Applications": type_dist.get("Web App", 0),
                "APIs": type_dist.get("API", 0),
                "Servers": type_dist.get("Server", 0),
                "Load Balancers": type_dist.get("Load Balancer", 0),
                "Other": type_dist.get("Other", 0),
            },
            "asset_risk_distribution": {
                "Critical": risk_dist.get("Critical", 0),
                "High": risk_dist.get("High", 0),
                "Medium": risk_dist.get("Medium", 0),
                "Low": risk_dist.get("Low", 0),
            },
            "risk_heatmap": heatmap,
            "certificate_expiry_timeline": dict(cert_bucket),
            "ip_version_breakdown": {
                "IPv4": round((ipv4_count * 100) / total_ip_assets),
                "IPv6": round((ipv6_count * 100) / total_ip_assets),
            },
            "assets": assets,
            "nameserver_records": nameserver_records,
            "crypto_overview": crypto_overview,
            "asset_locations": [],
            "certificate_inventory": certificate_inventory,
            "weak_cryptography": weak_crypto_metrics,
            "cert_issues_count": cert_issues_count,
        }

    def get_dashboard_summary(self, assets: list) -> dict:
        """Compute top-level statistics dynamically."""
        total = len(assets)
        scanned_assets = sum(
            1
            for a in assets
            if str(a.get("last_scan") or "").strip() not in {"", "Pending", "Never"}
        )
        api_count = sum(1 for a in assets if a["type"] == "API")
        vpn_count = sum(1 for a in assets if a["type"] == "VPN/Gateway")
        server_count = sum(1 for a in assets if a["type"] == "Server")
        
        expiring = sum(1 for a in assets if a["cert_status"] == "Expiring")
        
        # Risk Distribution formula
        dist = Counter(a["risk"] for a in assets)
        total_weight = (dist["Critical"] * 1.0) + (dist["High"] * 0.7) + (dist["Medium"] * 0.4) + (dist["Low"] * 0.1)
        risk_percent = min(100, int((total_weight / max(total, 1)) * 100))

        # Type Distribution array for charts
        web_app_count = total - (api_count + vpn_count + server_count)
        type_array = [api_count, vpn_count, server_count, max(0, web_app_count)]

        # 3. Certificate Expiry Timeline Bucketization
        ssl_expiry = {"0-30": 0, "30-60": 0, "60-90": 0, ">90": 0}
        for a in assets:
            days = a.get("cert_days")
            if isinstance(days, (int, float)):
                if days <= 30: ssl_expiry["0-30"] += 1
                elif days <= 60: ssl_expiry["30-60"] += 1
                elif days <= 90: ssl_expiry["60-90"] += 1
                else: ssl_expiry[">90"] += 1

        # 4. IP Version Breakdown (Heuristic based on target if not pure hostname)
        ipv4_cnt = 0
        ipv6_cnt = 0
        for a in assets:
            t = str(a.get("asset_name", ""))
            if ":" in t: ipv6_cnt += 1
            elif t.replace(".", "").isdigit(): ipv4_cnt += 1  # basic IP check
            else: ipv4_cnt += 1 # fallback WebApp generally runs on IPv4 stacks.

        return {
            "total_assets": total,
            "scanned_assets": scanned_assets,
            "api_count": api_count,
            "vpn_count": vpn_count,
            "server_count": server_count,
            "expiring_certs": expiring,
            "overall_risk_score": risk_percent,
            "risk_distribution": dict(dist),
            "type_distribution": type_array,
            "ssl_expiry": [ssl_expiry["0-30"], ssl_expiry["30-60"], ssl_expiry["60-90"], ssl_expiry[">90"]],
            "ip_breakdown": [ipv4_cnt, ipv6_cnt]
        }


    def _score_to_risk(self, score: float) -> str:
        if score >= 80: return "Low"
        if score >= 50: return "Medium"
        if score >= 25: return "High"
        return "Critical"

    def _guess_type(self, target: str, discovered: list) -> str:
        target_l = str(target).lower()
        if "api" in target_l: return "API"
        if "vpn" in target_l or "gateway" in target_l: return "VPN/Gateway"
        if discovered: return "Server"
        return "Web App"

    def get_comprehensive_asset_detail(self, asset_id: int) -> dict:
        """
        Consolidates ALL telemetry for a single asset into a unified DTO.
        Used by the frontend modal popup.
        """
        try:
            query = db_session.query(Asset).filter(Asset.id == asset_id)
            asset = query.first()
            if not asset: return {"success": False, "message": "Asset not found"}

            # 1. Basic Discovery Status
            discovery = db_session.query(DiscoveryItem).filter(DiscoveryItem.asset_id == asset_id).order_by(DiscoveryItem.discovery_date.desc()).all()
            
            # 2. Network & Geo
            latest_scan = db_session.query(Scan).filter(Scan.asset_id == asset_id, Scan.status == "complete").order_by(Scan.scan_date.desc()).first()
            dns_records = []
            geo_info = {"lat": None, "lon": None, "city": "Unknown", "country": "Unknown"}
            
            if latest_scan:
                # Raw query for associated DNS items
                dns_rows = db_session.execute(
                    text("SELECT record_type, hostname, record_value FROM discovery_items WHERE asset_id = :aid AND record_type IN ('A', 'AAAA', 'CNAME', 'TXT', 'MX')"),
                    {"aid": asset_id}
                ).fetchall()
                dns_records = [{"type": r[0], "name": r[1], "value": r[2]} for r in dns_rows]
                
                # Fetch real Geo data using IPLocationService
                ip_to_check = asset.ip_address
                if not ip_to_check and asset.target_url:
                    # In a real app, you'd resolve DNS here if not in DB
                    pass
                
                geo_info = self.ip_locator.get_location(ip_to_check or "")

            # 3. Security posture
            cert = db_session.query(Certificate).filter(Certificate.asset_id == asset_id).first()
            cbom = db_session.query(CBOMEntry).filter(CBOMEntry.asset_id == asset_id).all()
            pqc_flaws = db_session.query(PQCClassification).filter(PQCClassification.asset_id == asset_id).all()

            # 4. KPI Scoring
            total_algos = len(cbom)
            safe_algos = sum(1 for e in cbom if e.quantum_safe)
            pqc_score = (safe_algos / total_algos * 100) if total_algos > 0 else 0
            
            # 5. Graph Data (Nodes/Edges)
            nodes = [{"id": asset_id, "label": asset.target_url or asset.ip_address, "group": "asset"}]
            edges = []
            
            if asset.ip_address:
                nodes.append({"id": f"ip_{asset_id}", "label": asset.ip_address, "group": "ip"})
                edges.append({"from": asset_id, "to": f"ip_{asset_id}", "label": "resolves"})

            # DTO Construction
            asset_data = {
                "id": asset.id,
                "target": asset.target_url or asset.ip_address,
                "ipv4": asset.ip_address,
                "ipv6": None,
                "type": self._guess_type(asset.target_url or "", discovery),
                "risk_level": self._score_to_risk(pqc_score),
                "owner": None,
                "network": {
                    "dns": dns_records,
                    "geo": geo_info,
                    "discovery": [{"date": d.discovery_date.isoformat(), "type": d.record_type, "status": d.status} for d in discovery],
                    "graph": {"nodes": nodes, "edges": edges}
                },
                "security": {
                    "certificate": {
                        "issuer": cert.issuer_cn if cert else None,
                        "valid_from": cert.valid_from.isoformat() if cert else None,
                        "valid_until": cert.expiry_date.isoformat() if cert else None,
                        "expiry_days": (cert.expiry_date - datetime.utcnow().date()).days if cert else -1,
                        "is_expired": (cert.expiry_date < datetime.utcnow().date()) if cert else False,
                        "tls_version": cert.tls_version if cert else "TLS/1.2",
                        "key_algorithm": cert.signature_algo if cert else "RSA",
                        "key_length": 2048
                    } if cert else None,
                    "cbom": [{
                        "algorithm": c.algorithm,
                        "category": c.category,
                        "key_length": c.key_length,
                        "nist_status": "Deprecated" if not c.quantum_safe else "Standard",
                        "quantum_safe": c.quantum_safe
                    } for c in cbom],
                    "pqc": {
                        "score": pqc_score,
                        "status": "Safe" if pqc_score > 80 else "Unsafe",
                        "classifications": [{
                            "algorithm": f.algorithm_name,
                            "status": f.classification_status,
                            "score": f.risk_weight,
                            "nist_category": f.nist_security_level
                        } for f in pqc_flaws]
                    }
                }
            }

            return {"success": True, "data": asset_data}

        except Exception as e:
            logger.error(f"Error aggregating comprehensive asset detail for ID {asset_id}: {str(e)}")
            return {"success": False, "message": str(e)}
