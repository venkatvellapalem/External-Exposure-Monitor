import json
import urllib.request
import urllib.error

class InternetDBClient:
    """Client for Shodan's free InternetDB API."""
    
    BASE_URL = "https://internetdb.shodan.io"

    def get_ip_info(self, ip: str) -> dict:
        """Fetches open ports and vulnerabilities for a given IP."""
        url = f"{self.BASE_URL}/{ip}"
        
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'EASM-Collector/1.0'})
            # ponytail: Use stdlib urllib. No API key needed for InternetDB. Upgrade path: Use full Shodan API if you need specific queries.
            with urllib.request.urlopen(req, timeout=10) as response:
                return json.loads(response.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"ip": ip, "error": "No data in InternetDB."}
            return {"ip": ip, "error": f"HTTP {e.code}"}
        except Exception as e:
            return {"ip": ip, "error": str(e)}
