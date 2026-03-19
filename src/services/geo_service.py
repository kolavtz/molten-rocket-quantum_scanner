"""
Geolocation Service for QuantumShield.
Resolves IP addresses to coordinates (Lat / Lon) using live providers layout node securely.
"""

import urllib.request
import json
import socket
import ipaddress
import logging

logger = logging.getLogger(__name__)

class GeoService:
    def __init__(self, provider_url: str = "http://ip-api.com/json/"):
        self.provider_url = provider_url

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
                    "asn": "N/A"
                }

            # 3. Live REST fetch
            url = f"{self.provider_url}{ip}"
            with urllib.request.urlopen(url, timeout=5) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode('utf-8'))
                    if data.get("status") == "success":
                        return {
                            "ip": ip,
                            "status": "success",
                            "lat": data.get("lat", 0.0),
                            "lon": data.get("lon", 0.0),
                            "city": data.get("city", "Unknown"),
                            "country": data.get("country", "Unknown"),
                            "asn": data.get("as", "Unknown")
                        }
        except Exception as e:
            if logger: logger.error(f"Geolocation lookup failed for {target}: {e}")
        
        return {"ip": target, "status": "fail", "lat": 0.0, "lon": 0.0}

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
