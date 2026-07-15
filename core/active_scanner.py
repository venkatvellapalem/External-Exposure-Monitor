import socket
import urllib.request
import urllib.error
import ssl
from core.logger import get_logger

logger = get_logger()

class ActiveScanner:
    """Performs active verification of open ports and audits for leaked configuration files."""

    def is_port_open(self, ip: str, port: int, timeout: int = 3) -> bool:
        """Verifies if a port is actually open using a direct TCP connection."""
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                logger.info(f"[+] Verified port {port} is OPEN on {ip}")
                return True
        except Exception:
            logger.info(f"[-] Port {port} is CLOSED on {ip}")
            return False

    def audit_sensitive_files(self, ip: str, port: int, timeout: int = 3) -> list:
        """Checks for highly sensitive leaked files on HTTP/HTTPS ports."""
        # Detect protocol
        protocol = "https" if port in {443, 8443, 2083, 2087} else "http"
        base_url = f"{protocol}://{ip}:{port}"
        discovered_leaks = []
        
        # Files to check and their expected signatures (to verify it's not a dummy 200 OK page)
        checks = {
            "/.git/HEAD": "ref: refs/heads/",
            "/.env": "DB_",
            "/backup.zip": None # Binary check, we verify if status is 200 (hard to verify signature, but useful context)
        }
        
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        for path, signature in checks.items():
            url = f"{base_url}{path}"
            req = urllib.request.Request(url, headers={'User-Agent': 'EASM-Active-Audit/1.0'})
            try:
                with urllib.request.urlopen(req, context=ctx, timeout=timeout) as response:
                    if response.status == 200:
                        # Fetch first 1KB of content to verify signature
                        content = response.read(1024).decode('utf-8', errors='ignore')
                        if signature is None or signature in content:
                            logger.warn(f"[!!!] CRITICAL DATA LEAK DETECTED: {url}")
                            discovered_leaks.append(path)
            except Exception:
                # Page doesn't exist, throws 404/connection errors
                pass
                
        return discovered_leaks
