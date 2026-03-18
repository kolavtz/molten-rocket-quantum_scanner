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
        """Hydrate list of assets from scans with normalized schemas."""
        assets = []
        meta_assets = {a["target"]: a for a in db.list_assets()}
        visited_targets = set()
        
        for scan in db.list_scans(limit=100):
            if scan.get("status") != "complete":
                continue
                
            target = scan.get("target")
            visited_targets.add(target)
            meta = meta_assets.get(target, {})
            
            overview = scan.get("overview") or {}
            tls_results = scan.get("tls_results") or []
            discovered = scan.get("discovered_services") or []
            
            first = tls_results[0] if tls_results else {}
            cert_days = first.get("cert_days_remaining")
            
            cert_status = "Unknown"
            if isinstance(cert_days, (int, float)):
                cert_status = "Expired" if cert_days < 0 else ("Expiring" if cert_days <= 30 else "Valid")

            risk_score = float(overview.get("average_compliance_score") or 0)
            risk_level = self._score_to_risk(risk_score)
            
            asset_row = {
                "asset_name": target,
                "url": target if str(target).startswith("http") else f"https://{target}",
                "type": meta.get("type") or self._guess_type(target, discovered),
                "asset_class": scan.get("asset_class", "Other"),
                "risk": meta.get("risk_level") or risk_level,
                "risk_score": risk_score,
                "cert_status": cert_status,
                "key_length": first.get("key_length") or first.get("key_size") or 0,
                "last_scan": scan.get("generated_at") or scan.get("scanned_at") or "",
                "owner": meta.get("owner") or "Unassigned",
                "notes": meta.get("notes") or "",
                "overview": overview
            }
            assets.append(asset_row)

        for target, meta in meta_assets.items():
            if target not in visited_targets:
                assets.append({
                    "asset_name": target,
                    "url": target if str(target).startswith("http") else f"https://{target}",
                    "type": meta.get("type") or "Web App",
                    "asset_class": "Manual",
                    "risk": meta.get("risk_level") or "Medium",
                    "risk_score": 50.0,
                    "cert_status": "Scanning...",
                    "key_length": 0,
                    "last_scan": "Pending",
                    "owner": meta.get("owner") or "Unassigned",
                    "notes": meta.get("notes") or "",
                    "overview": {}
                })
        return assets

    def get_dashboard_summary(self, assets: list) -> dict:
        """Compute top-level statistics dynamically."""
        total = len(assets)
        api_count = sum(1 for a in assets if a["type"] == "API")
        vpn_count = sum(1 for a in assets if a["type"] == "VPN/Gateway")
        server_count = sum(1 for a in assets if a["type"] == "Server")
        
        expiring = sum(1 for a in assets if a["cert_status"] == "Expiring")
        
        # Risk Distribution formula
        dist = Counter(a["risk"] for a in assets)
        # Weighted aggregate: Critical=1.0, High=0.7, Medium=0.4, Low=0.1
        # Max score is 100% assuming 0 critical, or inverted
        total_weight = (dist["Critical"] * 1.0) + (dist["High"] * 0.7) + (dist["Medium"] * 0.4) + (dist["Low"] * 0.1)
        risk_percent = min(100, int((total_weight / max(total, 1)) * 100))

        # Type Distribution array for charts: [API, VPN, Server, Web App]
        web_app_count = total - (api_count + vpn_count + server_count)
        type_array = [api_count, vpn_count, server_count, max(0, web_app_count)]

        return {
            "total_assets": total,
            "api_count": api_count,
            "vpn_count": vpn_count,
            "server_count": server_count,
            "expiring_certs": expiring,
            "overall_risk_score": risk_percent,
            "risk_distribution": dict(dist),
            "type_distribution": type_array
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
