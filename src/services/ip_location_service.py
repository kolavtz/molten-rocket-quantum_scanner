import requests
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class IPLocationService:
    """
    Service to fetch geographic location for an IP address.
    Uses ip-api.com (free for non-commercial use).
    """
    
    BASE_URL = "http://ip-api.com/json"
    
    def __init__(self):
        self._cache = {}

    def get_location(self, ip: str) -> Dict[str, Any]:
        """
        Fetches location data for a given IP.
        Returns a dictionary with lat, lon, city, country, isp, etc.
        """
        if not ip or ip in ['127.0.0.1', 'localhost', '::1']:
            return self._local_fallback()

        if ip in self._cache:
            return self._cache[ip]

        try:
            # Note: The free API is HTTP only. Use HTTPS if you have a pro key.
            response = requests.get(f"{self.BASE_URL}/{ip}", timeout=5)
            response.raise_for_status()
            data = response.json()
            
            if data.get('status') == 'fail':
                logger.warning(f"IP Location lookup failed for {ip}: {data.get('message')}")
                return self._error_fallback(ip, data.get('message'))
            
            result = {
                "ip": ip,
                "lat": data.get('lat'),
                "lon": data.get('lon'),
                "city": data.get('city'),
                "region": data.get('regionName'),
                "country": data.get('country'),
                "isp": data.get('isp'),
                "org": data.get('org'),
                "zip": data.get('zip'),
                "timezone": data.get('timezone'),
                "success": True
            }
            
            self._cache[ip] = result
            return result
            
        except Exception as e:
            logger.error(f"Error fetching IP location for {ip}: {str(e)}")
            return self._error_fallback(ip, str(e))

    def _local_fallback(self) -> Dict[str, Any]:
        return {
            "ip": "127.0.0.1",
            "lat": 0.0,
            "lon": 0.0,
            "city": "Localhost",
            "region": "Internal",
            "country": "Local",
            "success": True
        }

    def _error_fallback(self, ip: str, message: str) -> Dict[str, Any]:
        return {
            "ip": ip,
            "success": False,
            "error": message
        }
