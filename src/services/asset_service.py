"""
AssetService configuration layer for QuantumShield.
Loads and calculates live dashboard telemetry scoring aggregates.
"""

from datetime import datetime, timezone, timedelta
from collections import Counter
from typing import Dict, List, Any, Optional
import json

import logging
from sqlalchemy import text, func, desc, and_

from src.models import (
    Asset, Scan, Certificate, CBOMEntry, PQCClassification,
    DiscoveryDomain, DiscoverySSL, DiscoveryIP, DiscoverySoftware
)
from src import db
from urllib.parse import urlparse
import ipaddress
from src.services.certificate_telemetry_service import CertificateTelemetryService
from src.services.ip_location_service import IPLocationService

logger = logging.getLogger(__name__)


class _DBSessionProxy:
    def __getattr__(self, name):
        return getattr(db.db_session, name)


db_session = _DBSessionProxy()

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

        def _query_results(query, *, filter_kwargs=None, order_by=None):
            if filter_kwargs and hasattr(query, "filter_by"):
                try:
                    query = query.filter_by(**filter_kwargs)
                except Exception:
                    pass
            if order_by is not None and hasattr(query, "order_by"):
                try:
                    query = query.order_by(order_by)
                except Exception:
                    pass
            try:
                results = query.all()
            except Exception:
                results = []
            return self._as_list(results)

        assets_out = []
        db_assets = _query_results(
            db_session.query(Asset),
            filter_kwargs={"is_deleted": False, "deleted_at": None},
            order_by=Asset.target.asc(),
        )

        latest_scan_by_target: Dict[str, Scan] = {}
        scans = _query_results(
            db_session.query(Scan),
            filter_kwargs={"is_deleted": False, "deleted_at": None, "status": "complete"},
        )
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
            cert_query = db_session.query(Certificate)
            if hasattr(cert_query, "filter_by"):
                try:
                    cert_query = cert_query.filter_by(is_deleted=False, deleted_at=None)
                except Exception:
                    pass
            if hasattr(cert_query, "filter"):
                try:
                    cert_query = cert_query.filter(Certificate.asset_id.in_(asset_ids))
                except Exception:
                    pass
            certs = _query_results(cert_query)
            if not hasattr(cert_query, "filter"):
                asset_id_set = {int(asset_id) for asset_id in asset_ids}
                certs = [cert for cert in certs if int(getattr(cert, "asset_id", 0) or 0) in asset_id_set]
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
            latest_scan_report_raw = self._safe_json_dict(getattr(latest_scan, "report_json", None)) if latest_scan else {}
            latest_scan_report = dict(latest_scan_report_raw)

            risk_score = 0.0
            risk_level = str(getattr(meta, "risk_level", "") or "").strip()
            cert_days = None
            cert_valid_until = None
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
                    cert_valid_until = valid_until.strftime("%Y-%m-%d")
                    cert_days = int((valid_until - now_naive_utc).days)
                    if cert_days < 0:
                        cert_status = "Expired"
                    elif cert_days <= 30:
                        cert_status = "Expiring"
                    else:
                        cert_status = "Valid"
                else:
                    scan_tls_results = latest_scan_report.get("tls_results") if isinstance(latest_scan_report.get("tls_results"), list) else []
                    first_tls = scan_tls_results[0] if scan_tls_results else {}
                    if isinstance(first_tls, dict):
                        tls_valid_to = str(first_tls.get("valid_to") or "").strip()
                        tls_cert_status = str(first_tls.get("cert_status") or "").strip().title()
                        if tls_valid_to:
                            cert_valid_until = tls_valid_to[:10]
                        if tls_cert_status in {"Valid", "Expiring", "Expired"}:
                            cert_status = tls_cert_status
                        else:
                            cert_status = "Expired" if bool(getattr(latest_cert, "is_expired", False)) else "Valid"
                    else:
                        cert_status = "Expired" if bool(getattr(latest_cert, "is_expired", False)) else "Valid"

            certificate_details = {}
            scan_tls_results = latest_scan_report.get("tls_results") if isinstance(latest_scan_report.get("tls_results"), list) else []
            for tls_row in scan_tls_results:
                if not isinstance(tls_row, dict):
                    continue
                details = tls_row.get("certificate_details")
                if isinstance(details, dict) and details:
                    certificate_details = details
                    break

            overview = {}
            if latest_scan_report_raw:
                overview["last_scan_report"] = latest_scan_report_raw
            if latest_cert is not None and getattr(latest_cert, "id", None) is not None:
                overview["certificate_id"] = getattr(latest_cert, "id", None)

            last_scan_ts = None
            last_scan_id = None
            scan_status = "Never"
            scan_kind = "N/A"
            scanned_by = "N/A"
            if latest_scan is not None:
                last_scan_ts = (
                    getattr(latest_scan, "completed_at", None)
                    or getattr(latest_scan, "scanned_at", None)
                    or getattr(latest_scan, "started_at", None)
                )
                last_scan_id = getattr(latest_scan, "scan_id", None) or getattr(latest_scan, "id", None)
                scan_status = str(getattr(latest_scan, "status", "") or "Unknown").title()
                if "overall_pqc_score" not in latest_scan_report and getattr(latest_scan, "overall_pqc_score", None) is not None:
                    latest_scan_report["overall_pqc_score"] = float(latest_scan.overall_pqc_score)
                scan_kind = str(latest_scan_report.get("scan_kind") or "N/A")
                scanned_by = str(latest_scan_report.get("scanned_by") or "N/A")

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
                "cert_valid_until": cert_valid_until,
                "certificate_details": certificate_details,
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
                "overview": overview,
            })

        return assets_out

    def get_dashboard_summary(self, assets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculates dashboard summary metrics and distributions from current inventory."""
        total = len(assets)
        
        # Identity counts
        web_apps = sum(1 for a in assets if a.get("type") == "Web App")
        apis = sum(1 for a in assets if a.get("type") == "API")
        servers = sum(1 for a in assets if a.get("type") == "Server")
        
        # Risk distribution
        risks = [a.get("risk", "Medium") for a in assets]
        risk_counts = Counter(risks)
        high_risk_count = risk_counts.get("Critical", 0) + risk_counts.get("High", 0)
        
        # Expiring certs (< 30 days)
        expiring_30 = sum(1 for a in assets if a.get("cert_status") == "Expiring" or (isinstance(a.get("cert_days"), int) and 0 <= a.get("cert_days") <= 30))
        
        # Scan count
        total_scans = db_session.query(Scan).filter(Scan.is_deleted == False).count()
        
        # Weak Ciphers (from Certificate service or global search)
        try:
            cert_service = CertificateTelemetryService()
            weak_crypto = cert_service.get_weak_cryptography_metrics()
            weak_ciphers_count = weak_crypto.get("weak_tls", 0) + weak_crypto.get("weak_keys", 0)
        except Exception:
            weak_ciphers_count = 0

        # PQC readiness
        pqc_scores = [a.get("risk_score", 0) for a in assets if a.get("risk_score") is not None]
        avg_pqc = sum(pqc_scores) / len(pqc_scores) if pqc_scores else 0

        # Type distribution (ordered for Chart.js)
        type_dist = [
            apis,
            sum(1 for a in assets if "VPN" in str(a.get("type", "")).upper()),
            servers,
            web_apps
        ]

        return {
            "total_assets": total,
            "public_web_apps": web_apps,
            "web_apps_count": web_apps,
            "apis": apis,
            "apis_count": apis,
            "servers": servers,
            "expiring_certs_30": expiring_30,
            "expiring_certs_count": expiring_30,
            "high_risk_assets": high_risk_count,
            "high_risk_count": high_risk_count,
            "total_scans": total_scans,
            "total_scans_platform": total_scans,
            "weak_ciphers_count": weak_ciphers_count,
            "critical_vulns_count": weak_ciphers_count,
            "recent_discoveries_count": len(self.get_recent_discoveries(days=7)) if hasattr(self, 'get_recent_discoveries') else 0,
            "overall_pqc_readiness": round(avg_pqc, 1),
            "risk_distribution": {
                "Critical": risk_counts.get("Critical", 0),
                "High": risk_counts.get("High", 0),
                "Medium": risk_counts.get("Medium", 0),
                "Low": risk_counts.get("Low", 0)
            },
            "type_distribution": type_dist,
            "vulnerable_software": self.get_top_vulnerable_software(5)
        }

    def get_recent_discoveries(self, days: int = 7) -> List[Dict[str, Any]]:
        """Fetch items discovered or added to inventory in the last 7 days."""
        threshold = datetime.utcnow() - timedelta(days=days)
        
        recent_items = []
        
        # 1. New Assets (Inventoried)
        new_assets = db_session.query(Asset).filter(
            and_(
                Asset.created_at >= threshold,
                Asset.is_deleted == False
            )
        ).all()
        
        for asset in new_assets:
            recent_items.append({
                "name": asset.name or asset.target,
                "type": asset.asset_type,
                "date": asset.created_at.strftime("%Y-%m-%d"),
                "risk": asset.risk_level or "Medium",
                "source": "Inventory"
            })
            
        # 2. Discovery Items (Not yet promoted)
        # We'll peak into DiscoveryDomain and DiscoverySoftware as they are most representative
        detected_at_expr = self._discovery_detected_at_expr(DiscoveryDomain)
        new_domains = (
            db_session.query(DiscoveryDomain, detected_at_expr.label("detected_at"))
            .outerjoin(Scan, DiscoveryDomain.scan_id == Scan.id)
            .filter(
                and_(
                    DiscoveryDomain.is_deleted == False,
                    DiscoveryDomain.promoted_to_inventory == False,
                    detected_at_expr >= threshold,
                )
            )
            .all()
        )
        
        for d, detected_at in new_domains:
            detected_value = self._coerce_datetime(detected_at)
            recent_items.append({
                "name": d.domain,
                "type": "Domain",
                "date": detected_value.strftime("%Y-%m-%d") if detected_value else "Unknown",
                "risk": "New",
                "source": "Discovery",
                "_sort_at": detected_value or datetime.min,
            })

        for item in recent_items:
            if "_sort_at" not in item:
                item["_sort_at"] = self._coerce_datetime(item.get("date")) or datetime.min

        sorted_items = sorted(recent_items, key=lambda x: x["_sort_at"], reverse=True)[:10]
        for item in sorted_items:
            item.pop("_sort_at", None)
        return sorted_items

    def get_top_vulnerable_software(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Get top vulnerable software from discovery or CBOM."""
        # Query DiscoverySoftware for products with many occurrences or specific categories
        software = db_session.query(
            DiscoverySoftware.product,
            func.count(DiscoverySoftware.id).label('count')
        ).group_by(DiscoverySoftware.product).order_by(desc('count')).limit(limit).all()
        
        return [{"product": s[0], "count": s[1]} for s in software]

    def get_inventory_view_model(self, testing_mode: bool = False) -> dict:
        """Build full asset inventory page view-model from MySQL tables only."""
        if testing_mode:
            return {
                "empty": True,
                "kpis": {
                    "total_assets": 0, "public_web_apps": 0, "apis": 0,
                    "servers": 0, "expiring_certificates": 0, "expired_certificates": 0,
                    "weak_crypto_issues": 0, "high_risk_assets": 0,
                },
                "assets": [],
                "nameserver_records": [],
                "crypto_overview": [],
                "certificate_inventory": [],
            }

        assets = self.load_combined_assets()
        assets = [row for row in assets if not row.get("is_deleted")]
        type_dist = Counter(a.get("type", "Other") for a in assets)
        risk_dist = Counter(a.get("risk", "Medium") for a in assets)
        cert_bucket = Counter({"0-30": 0, "30-60": 0, "60-90": 0, ">90": 0})

        try:
            cert_service = CertificateTelemetryService()
            weak_crypto_metrics = cert_service.get_weak_cryptography_metrics()
            cert_issues_count = cert_service.get_certificate_issues_count()
            expired_certs = cert_service.get_expired_certificates_count()
        except Exception:
            weak_crypto_metrics = {"weak_keys": 0, "weak_tls": 0, "expired": 0, "self_signed": 0}
            cert_issues_count = 0
            expired_certs = 0

        for row in assets:
            days = row.get("cert_days")
            if not isinstance(days, (int, float)): continue
            if days <= 30: cert_bucket["0-30"] += 1
            elif days <= 60: cert_bucket["30-60"] += 1
            elif days <= 90: cert_bucket["60-90"] += 1
            else: cert_bucket[">90"] += 1

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
                certificate_inventory.append({
                    "asset": a.get("asset_name"),
                    "issuer": a.get("ca") or "Unknown",
                    "key_length": int(a.get("key_length") or 0),
                    "tls_version": a.get("tls_version") or "Unknown",
                    "days_remaining": a.get("cert_days"),
                    "status": cert_status,
                })

            if int(a.get("key_length") or 0) > 0:
                crypto_overview.append({
                    "asset": a.get("asset_name"),
                    "key_length": int(a.get("key_length") or 0),
                    "cipher_suite": a.get("cipher_suite") or "Unknown",
                    "tls_version": a.get("tls_version") or "Unknown",
                    "ca": a.get("ca") or "Unknown",
                    "last_scan": str(a.get("last_scan") or "")[:10],
                })

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
            "asset_risk_distribution": risk_dist,
            "risk_heatmap": heatmap,
            "certificate_expiry_timeline": dict(cert_bucket),
            "ip_version_breakdown": {
                "IPv4": round((ipv4_count * 100) / total_ip_assets),
                "IPv6": round((ipv6_count * 100) / total_ip_assets),
            },
            "assets": assets,
            "crypto_overview": crypto_overview,
            "certificate_inventory": certificate_inventory,
            "weak_cryptography": weak_crypto_metrics,
            "cert_issues_count": cert_issues_count,
        }


    def _score_to_risk(self, score: float) -> str:
        if score >= 80: return "Low"
        if score >= 50: return "Medium"
        if score >= 25: return "High"
        return "Critical"

    def _discovery_detected_at_expr(self, model):
        return func.coalesce(
            getattr(model, "promoted_at", None),
            Scan.completed_at,
            Scan.scanned_at,
            Scan.started_at,
            Scan.created_at,
        )

    def _discovery_detected_at_value(self, item):
        promoted_at = getattr(item, "promoted_at", None)
        if promoted_at is not None:
            return promoted_at

        scan = getattr(item, "scan", None)
        if scan is None:
            return None

        return (
            getattr(scan, "completed_at", None)
            or getattr(scan, "scanned_at", None)
            or getattr(scan, "started_at", None)
            or getattr(scan, "created_at", None)
        )

    def get_comprehensive_asset_detail(self, asset_id: int) -> dict:
        """
        Consolidates ALL telemetry for a single asset into a unified DTO.
        """
        try:
            asset = db_session.query(Asset).filter(Asset.id == asset_id).first()
            if not asset: return {"success": False, "message": "Asset not found"}

            # Get Discovery Info from split tables
            discovery_domains = db_session.query(DiscoveryDomain).filter(DiscoveryDomain.asset_id == asset_id).all()
            discovery_ssl = db_session.query(DiscoverySSL).filter(DiscoverySSL.asset_id == asset_id).all()
            discovery_ips = db_session.query(DiscoveryIP).filter(DiscoveryIP.asset_id == asset_id).all()
            discovery_software = db_session.query(DiscoverySoftware).filter(DiscoverySoftware.asset_id == asset_id).all()

            discovery_events = []
            for d in discovery_domains:
                detected_at = self._discovery_detected_at_value(d)
                discovery_events.append({"date": detected_at.isoformat() if detected_at else None, "type": "Domain", "status": d.status})
            for d in discovery_ssl:
                detected_at = self._discovery_detected_at_value(d)
                discovery_events.append({"date": detected_at.isoformat() if detected_at else None, "type": "SSL", "status": d.status})
            for d in discovery_ips:
                detected_at = self._discovery_detected_at_value(d)
                discovery_events.append({"date": detected_at.isoformat() if detected_at else None, "type": "IP", "status": d.status})
            for d in discovery_software:
                detected_at = self._discovery_detected_at_value(d)
                discovery_events.append({"date": detected_at.isoformat() if detected_at else None, "type": "Software", "status": d.status})
            
            latest_scan = db_session.query(Scan).filter(Scan.asset_id == asset_id, Scan.status == "complete").order_by(Scan.completed_at.desc()).first()
            geo_info = self.ip_locator.get_location(asset.ipv4 or asset.target)

            cert = db_session.query(Certificate).filter(Certificate.asset_id == asset_id).first()
            cbom = db_session.query(CBOMEntry).filter(CBOMEntry.asset_id == asset_id).all()
            pqc_flaws = db_session.query(PQCClassification).filter(PQCClassification.asset_id == asset_id).all()

            total_algos = len(cbom)
            safe_algos = sum(1 for e in cbom if getattr(e, "quantum_safe", False))
            pqc_score = (safe_algos / total_algos * 100) if total_algos > 0 else 0
            
            nodes = [{"id": asset_id, "label": asset.target, "group": "asset"}]
            edges = []
            if asset.ipv4:
                nodes.append({"id": f"ip_{asset_id}", "label": asset.ipv4, "group": "ip"})
                edges.append({"from": asset_id, "to": f"ip_{asset_id}", "label": "resolves"})

            asset_data = {
                "id": asset.id,
                "target": asset.target,
                "ipv4": asset.ipv4,
                "ipv6": getattr(asset, "ipv6", None),
                "type": asset.asset_type,
                "risk_level": asset.risk_level or self._score_to_risk(pqc_score),
                "owner": asset.owner,
                "network": {
                    "geo": geo_info,
                    "discovery": discovery_events,
                    "graph": {"nodes": nodes, "edges": edges}
                },
                "security": {
                    "certificate": {
                        "issuer": cert.issuer if cert else None,
                        "valid_from": cert.valid_from.isoformat() if cert and cert.valid_from else None,
                        "valid_until": cert.valid_until.isoformat() if cert and cert.valid_until else None,
                        "expiry_days": getattr(cert, "expiry_days", -1),
                        "tls_version": getattr(cert, "tls_version", "TLS/1.2"),
                        "key_algorithm": getattr(cert, "key_algorithm", "RSA"),
                        "key_length": getattr(cert, "key_length", 2048)
                    } if cert else None,
                    "cbom": [{
                        "algorithm": c.algorithm_name or c.element_name,
                        "category": c.asset_type or "Unknown",
                        "key_length": getattr(c, "key_size", 0),
                        "quantum_safe": getattr(c, "quantum_safe_flag", False)
                    } for c in cbom],
                    "pqc": {
                        "score": pqc_score,
                        "status": "Safe" if pqc_score > 80 else "Unsafe",
                        "classifications": [] # Simplified for refactor
                    }
                }
            }

            return {"success": True, "data": asset_data}

        except Exception as e:
            logger.error(f"Error aggregating comprehensive asset detail for ID {asset_id}: {str(e)}")
            return {"success": False, "message": str(e)}
