"""
GeoService layer for cluster mappings in QuantumShield.
Resolves IPs to physical locations for landing grid plots.
"""

import urllib.request
import urllib.parse
import json
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class GeoService:
    def __init__(self):
        self._geo_cache: Dict[str, Dict[str, Any]] = {}

    def geolocate_ip(self, ip_addr: str) -> Dict[str, Any]:
        """Resolve individual IP to coordinates & metadata from pluggable API lookup."""
        if not ip_addr:
            return {}
        if ip_addr in self._geo_cache:
            return self._geo_cache[ip_addr]

        result: Dict[str, Any] = {}
        try:
            # Using ipapi.co (pluggable setup node)
            url = f"https://ipapi.co/{urllib.parse.quote(ip_addr)}/json/"
            req = urllib.request.Request(url, headers={"User-Agent": "QuantumShield/1.0"})
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            
            lat = payload.get("latitude")
            lon = payload.get("longitude")
            
            if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
                result = {
                    "ip": ip_addr,
                    "lat": float(lat),
                    "lon": float(lon),
                    "city": str(payload.get("city") or ""),
                    "region": str(payload.get("region") or ""),
                    "country": str(payload.get("country_name") or payload.get("country") or ""),
                    "asn": str(payload.get("asn") or "")
                }
        except Exception as e:
            logger.warning(f"Geolocation failed for {ip_addr}: {e}")
            result = {}

        self._geo_cache[ip_addr] = result
        return result

    def get_geo_clusters(self, ip_list: List[str]) -> List[Dict[str, Any]]:
        """Groups addresses by coordinates to form clustered map plotted responses."""
        clusters: Dict[tuple, Dict[str, Any]] = {}
        
        for ip in ip_list:
            geo = self.geolocate_ip(ip)
            if not geo or "lat" not in geo:
                continue
            
            key = (geo["lat"], geo["lon"])
            if key not in clusters:
                clusters[key] = {
                    "lat": geo["lat"],
                    "lon": geo["lon"],
                    "city": geo.get("city"),
                    "country": geo.get("country"),
                    "service_count": 0,
                    "ip_count": 0,
                    "ips": []
                }
            clusters[key]["ip_count"] += 1
            clusters[key]["ips"].append(ip)

        return list(clusters.values())
