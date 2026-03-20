"""
AssetService configuration layer for QuantumShield.
Loads and calculates live dashboard telemetry scoring aggregates.
"""

import os
import json
from datetime import datetime, timezone
from collections import Counter
import ipaddress

from src import database as db

class AssetService:
    def __init__(self):
         pass

    def load_combined_assets(self) -> list:
        """Hydrate list of assets from native SQL store ensuring metrics map exclusively to inventory assets."""
        from src.db import db_session
        from src.models import Asset, Scan
        
        assets_out = []
        db_assets = db_session.query(Asset).filter_by(is_deleted=False).all()
        
        for meta in db_assets:
            # Fetch latest complete scan for this asset
            latest_scan = db_session.query(Scan).filter_by(target=meta.name, status="complete").order_by(Scan.started_at.desc()).first()
            
            if latest_scan:
                overview = getattr(latest_scan, "overview", None) or {}
                # Handle possible nulls natively from scan models if stored there, else fallback to JSON blob overview
                # Because we migrated to ORM, many metrics are native columns.
                risk_score = float(latest_scan.overall_pqc_score or overview.get("average_compliance_score") or 0)
                risk_level = self._score_to_risk(risk_score)
                
                # Fetch First Certificate safely if mapped, else default
                cert_days = None
                key_length = 0
                cert_status = "Unknown"
                certs = getattr(latest_scan, "certificates", None) or []
                if certs:
                    first_cert = certs[0]
                    key_length = first_cert.key_length or 0
                    if first_cert.valid_until:
                        delta = (first_cert.valid_until - datetime.now(timezone.utc).replace(tzinfo=None)).days
                        cert_days = delta
                        cert_status = "Expired" if delta < 0 else ("Expiring" if delta <= 30 else "Valid")
                
                assets_out.append({
                    "id": meta.id,  # Useful for UI deletions/edits internally
                    "asset_name": meta.name,
                    "url": meta.url or (f"https://{meta.name}" if not str(meta.name).startswith("http") else meta.name),
                    "ipv4": "", # Placeholder mapped historically from discovered services
                    "ipv6": "",
                    "type": meta.asset_type or "Web App",
                    "asset_class": "Automated",
                    "risk": meta.risk_level or risk_level,
                    "risk_score": risk_score,
                    "cert_status": cert_status,
                    "cert_days": cert_days,
                    "key_length": key_length,
                    "last_scan": latest_scan.completed_at.strftime('%Y-%m-%d %H:%M:%S') if latest_scan.completed_at else "",
                    "owner": meta.owner or "Unassigned",
                    "notes": getattr(meta, "notes", "") or "",
                    "overview": overview
                })
            else:
                # No scans yet for this inventory item
                assets_out.append({
                    "id": meta.id,
                    "asset_name": meta.name,
                    "url": meta.url or (f"https://{meta.name}" if not str(meta.name).startswith("http") else meta.name),
                    "type": meta.asset_type or "Web App",
                    "asset_class": "Manual",
                    "risk": meta.risk_level or "Medium",
                    "risk_score": 50.0,
                    "cert_status": "Scanning...",
                    "cert_days": None,
                    "key_length": 0,
                    "last_scan": "Pending",
                    "owner": meta.owner or "Unassigned",
                    "notes": getattr(meta, "notes", "") or "",
                    "overview": {}
                })
                
        return assets_out

    def get_dashboard_summary(self, assets: list) -> dict:
        """Compute top-level statistics dynamically."""
        total = len(assets)
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
