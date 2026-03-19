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
            if target not in meta_assets:
                continue

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
            
            ipv4, ipv6 = "", ""
            for svc in discovered:
                cand = str(svc.get("host", "")).strip()
                if cand:
                    try:
                        parsed = ipaddress.ip_address(cand)
                        if parsed.version == 4 and not ipv4: ipv4 = cand
                        if parsed.version == 6 and not ipv6: ipv6 = cand
                    except ValueError: pass

            asset_row = {
                "asset_name": target,
                "url": target if str(target).startswith("http") else f"https://{target}",
                "ipv4": ipv4,
                "ipv6": ipv6,
                "type": meta.get("type") or self._guess_type(target, discovered),
                "asset_class": scan.get("asset_class", "Other"),
                "risk": meta.get("risk_level") or risk_level,
                "risk_score": risk_score,
                "cert_status": cert_status,
                "cert_days": cert_days,  # Added for charting
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
                    "cert_days": None,
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
