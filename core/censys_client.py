import json
import os
import urllib.request
import ssl
from core.logger import get_logger
from core.models import ExposureEvent

logger = get_logger()

class CensysClient:
    """Queries Censys Platform API v3 (hosts lookup) using a Personal Access Token (PAT)."""
    
    def __init__(self):
        self.api_token = os.getenv("CENSYS_API_TOKEN", "")
        
    def get_ip_info(self, ip: str) -> dict:
        """Fetches host details from Censys Platform API v3."""
        if (not self.api_token or 
                "placeholder" in self.api_token or 
                "here" in self.api_token or 
                "token" in self.api_token):
            logger.info("[-] Censys API token missing or placeholder. Skipping Censys passive scan.")
            return {}
            
        url = f"https://api.platform.censys.io/v3/global/asset/host/{ip}"
        
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {self.api_token}",
                "Accept": "application/vnd.censys.api.v3.host.v1+json",
                # Browser User-Agent is REQUIRED to bypass Cloudflare signature blocks
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }
        )
        
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with urllib.request.urlopen(req, context=ctx, timeout=5) as response:
                if response.status == 200:
                    return json.loads(response.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                logger.info(f"[-] Censys returned 404 for {ip} (no passive record).")
            elif e.code == 403:
                logger.error(f"[!] Censys API Forbidden (403) for {ip}. Check token permissions or rate limits.")
            else:
                logger.error(f"[!] Censys API HTTP Error {e.code} for {ip}: {e.reason}")
        except Exception as e:
            logger.error(f"[!] Censys API query error for {ip}: {e}")
            
        return {}

    def get_exposures(self, ip: str) -> list:
        """Normalizes Censys Platform v3 host lookup results into standardized ExposureEvent instances."""
        events = []
        data = self.get_ip_info(ip)
        
        if not data or "result" not in data:
            return events
            
        result = data["result"]
        resource = result.get("resource", {})
        ip_addr = resource.get("ip", ip)
        services = resource.get("services", [])
        
        for s in services:
            # Filter for TCP services since our active verifier runs on TCP
            if s.get("transport_protocol", "").upper() != "TCP":
                continue
                
            port = s.get("port")
            if not port:
                continue
                
            service_name = s.get("service_name", s.get("protocol", ""))
            
            cpes = []
            for soft in s.get("software", []):
                vendor = soft.get("vendor", "")
                product = soft.get("product", "")
                version = soft.get("version", "")
                if vendor or product:
                    cpes.append(f"cpe:/{vendor}:{product}:{version}")
                    
            events.append(
                ExposureEvent(
                    ip=ip_addr,
                    port=port,
                    hostnames=[],
                    cpes=cpes,
                    vulns=[],
                    tags=[service_name] if service_name else [],
                    source="censys"
                )
            )
            
        logger.info(f"[-] Censys passive scan found {len(events)} TCP exposures for {ip}")
        return events
