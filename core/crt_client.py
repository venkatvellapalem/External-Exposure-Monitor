import json
import urllib.request
import urllib.error
import socket
from core.logger import get_logger

logger = get_logger()

class CrtClient:
    """Client for Certificate Transparency logs via crt.sh to find subdomains."""
    
    BASE_URL = "https://crt.sh"

    def get_subdomains(self, domain: str) -> set:
        """Fetches unique subdomains for a domain using crt.sh with retries."""
        url = f"{self.BASE_URL}/?q=%25.{domain}&output=json"
        subdomains = set()
        
        logger.info(f"Querying crt.sh for domain: {domain}")
        req = urllib.request.Request(url, headers={'User-Agent': 'EASM-Collector/1.0'})
        
        import time
        max_retries = 3
        for attempt in range(max_retries):
            try:
                # ponytail: crt.sh is a free service and frequently times out or returns 404/502 under load.
                # Upgrade path: Use a commercial CT log API or local subfinder database for production.
                with urllib.request.urlopen(req, timeout=15) as response:
                    data = json.loads(response.read().decode('utf-8'))
                    for entry in data:
                        names = []
                        if "common_name" in entry and entry["common_name"]:
                            names.append(entry["common_name"])
                        if "name_value" in entry and entry["name_value"]:
                            names.extend(entry["name_value"].split("\n"))
                            
                        for name in names:
                            name = name.strip().lower()
                            if name and not name.startswith("*.") and domain in name:
                                subdomains.add(name)
                    break # Success
            except urllib.error.HTTPError as e:
                logger.warning(f"crt.sh returned HTTP {e.code} (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    time.sleep(2)
            except Exception as e:
                logger.warning(f"crt.sh error: {e} (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    time.sleep(2)
        else:
            logger.error(f"Failed to fetch subdomains from crt.sh after {max_retries} attempts.")
            
        logger.info(f"Found {len(subdomains)} unique subdomains for {domain}")
        return subdomains

    def resolve_subdomains_to_ips(self, subdomains: set) -> set:
        """Resolves subdomains to IP addresses.
        
        ponytail: using socket.gethostbyname. Ceiling: Only returns first IPv4 address.
        """
        ips = set()
        for sub in subdomains:
            try:
                ip = socket.gethostbyname(sub)
                ips.add(ip)
                logger.info(f"Resolved {sub} -> {ip}")
            except socket.gaierror:
                # Subdomain doesn't resolve (dead/internal cert)
                pass
            except Exception as e:
                logger.error(f"Error resolving {sub}: {e}")
        return ips
