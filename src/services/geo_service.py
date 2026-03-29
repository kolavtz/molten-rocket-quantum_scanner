"""
Geolocation Service for QuantumShield.
Resolves IP addresses to coordinates (Lat / Lon) using live providers layout node securely.
"""

import urllib.request
import json
import socket
import ipaddress
import logging
from urllib.parse import urlencode

logger = logging.getLogger(__name__)

class GeoService:
    def __init__(self, provider_url: str = "http://ip-api.com/json/"):
        self.provider_url = provider_url
        self._reverse_cache: dict[str, str] = {}

    def _reverse_geocode(self, lat: float, lon: float) -> str:
        """Resolve coordinates to a human-readable OpenStreetMap location label."""
        cache_key = f"{round(float(lat), 4)}:{round(float(lon), 4)}"
        cached = self._reverse_cache.get(cache_key)
        if cached is not None:
            return cached

        try:
            query = urlencode(
                {
                    "format": "jsonv2",
                    "lat": f"{float(lat):.6f}",
                    "lon": f"{float(lon):.6f}",
                    "zoom": "10",
                    "addressdetails": "1",
                }
            )
            url = f"https://nominatim.openstreetmap.org/reverse?{query}"
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "QuantumShield/1.0 (asset-discovery-map)",
                    "Accept": "application/json",
                },
            )
            with urllib.request.urlopen(req, timeout=4) as response:
                if response.status != 200:
                    self._reverse_cache[cache_key] = ""
                    return ""
                payload = json.loads(response.read().decode("utf-8"))

            label = str(payload.get("display_name") or "").strip()
            self._reverse_cache[cache_key] = label
            return label
        except Exception as exc:
            if logger:
                logger.debug("OSM reverse geocode failed for %s: %s", cache_key, exc)
            self._reverse_cache[cache_key] = ""
            return ""

    def get_location(self, target: str) -> dict:
        """Resolve target hostname/IP to City, Country, Lat, Lon securely.

        Returns:
            dict: {lat: float, lon: float, city: str, country: str, asn: str, status: str}
        """
        try:
            # 1. Resolve hostname to IP if needed
            ip = target
            if not self._is_valid_ip(target):
                ip = socket.gethostbyname(target)
            
            # 2. Check for private IPs (no geo lookup)
            if self._is_private_ip(ip):
                return {
                    "ip": ip,
                    "status": "Private",
                    "lat": 28.6139,  # Default to New Delhi or target aggregate
                    "lon": 77.2090, 
                    "city": "Intranet",
                    "country": "Private Network",
                    "asn": "N/A",
                    "reverse_location": "Intranet / Private Network",
                }

            # 3. Live REST fetch
            url = f"{self.provider_url}{ip}"
            with urllib.request.urlopen(url, timeout=5) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode('utf-8'))
                    if data.get("status") == "success":
                        lat = float(data.get("lat", 0.0) or 0.0)
                        lon = float(data.get("lon", 0.0) or 0.0)
                        reverse_location = self._reverse_geocode(lat, lon) if lat and lon else ""
                        return {
                            "ip": ip,
                            "status": "success",
                            "lat": lat,
                            "lon": lon,
                            "city": data.get("city", "Unknown"),
                            "country": data.get("country", "Unknown"),
                            "asn": data.get("as", "Unknown"),
                            "reverse_location": reverse_location,
                        }
        except Exception as e:
            # Downgrade DNS resolution errors to debug to prevent log flooding for internal/test domains
            if isinstance(e, socket.gaierror) or "11001" in str(e):
                if logger: logger.debug(f"Geolocation DNS lookup failed for {target}: {e}")
            else:
                if logger: logger.error(f"Geolocation lookup failed for {target}: {e}")
        
        return {
            "ip": target,
            "status": "fail",
            "lat": 0.0,
            "lon": 0.0,
            "reverse_location": "",
        }

    def _is_valid_ip(self, ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _is_private_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_loopback
        except ValueError:
            return False
