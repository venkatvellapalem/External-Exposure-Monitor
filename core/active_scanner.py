import os
import socket
import urllib.request
import urllib.error
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.logger import get_logger

logger = get_logger()

class ActiveScanner:
    """Performs active verification of open ports and audits for leaked configuration files."""

    def __init__(self):
        # Load configurable scan timeout from environment, default to 2.5s to prevent false negatives
        self.timeout = float(os.getenv("SCAN_TIMEOUT", 2.5))
        logger.info(f"[-] ActiveScanner initialized with timeout={self.timeout}s")

    def is_port_open(self, ip: str, port: int, timeout: float = None) -> bool:
        """Verifies if a port is actually open using a direct TCP connection."""
        t = timeout if timeout is not None else self.timeout
        try:
            with socket.create_connection((ip, port), timeout=t):
                logger.info(f"[+] Verified port {port} is OPEN on {ip}")
                return True
        except Exception:
            return False

    def scan_ports_parallel(self, ip: str, ports: list, timeout: float = None) -> list:
        """Scans a list of ports in parallel using a ThreadPoolExecutor to eliminate latency."""
        t = timeout if timeout is not None else self.timeout
        open_ports = []
        with ThreadPoolExecutor(max_workers=len(ports)) as executor:
            future_to_port = {executor.submit(self.is_port_open, ip, port, t): port for port in ports}
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                if future.result():
                    open_ports.append(port)
        return open_ports

    def audit_sensitive_files(self, ip: str, port: int, domain: str = "", timeout: float = None) -> list:
        """Checks for highly sensitive leaked files on HTTP/HTTPS ports.
        
        Uses the parent domain (if available) to ensure Host headers route correctly 
        on shared hosting (virtual host servers).
        """
        t = timeout if timeout is not None else self.timeout
        protocol = "https" if port in {443, 8443, 2083, 2087} else "http"
        
        # Use domain name if available to solve shared hosting (IIS/Apache/Nginx Virtual Hosts) routing
        target_host = domain if domain else ip
        base_url = f"{protocol}://{target_host}:{port}"
        discovered_leaks = []
        
        checks = {
            "/.git/HEAD": "ref: refs/heads/",
            "/.env": "DB_",
            "/backup.zip": None
        }
        
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        for path, signature in checks.items():
            url = f"{base_url}{path}"
            req = urllib.request.Request(url, headers={'User-Agent': 'EASM-Active-Audit/1.0'})
            try:
                with urllib.request.urlopen(req, context=ctx, timeout=t) as response:
                    if response.status == 200:
                        content = response.read(1024).decode('utf-8', errors='ignore')
                        if signature is None or signature in content:
                            logger.warn(f"[!!!] CRITICAL DATA LEAK DETECTED: {url}")
                            discovered_leaks.append(path)
            except Exception:
                pass
                
        return discovered_leaks
