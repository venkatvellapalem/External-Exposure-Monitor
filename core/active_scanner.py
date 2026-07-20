import os
import socket
import urllib.request
import urllib.error
import ssl
import shutil
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.logger import get_logger

logger = get_logger()

class ActiveScanner:
    """Performs active verification of open ports and audits for leaked configuration files."""

    def __init__(self):
        # Load configurable scan timeout from environment, default to 2.5s to prevent false negatives
        self.timeout = float(os.getenv("SCAN_TIMEOUT", 2.5))
        logger.info(f"[-] ActiveScanner initialized with timeout={self.timeout}s")

    def is_rustscan_available(self) -> bool:
        """Returns True if rustscan binary is installed in the system PATH."""
        return shutil.which("rustscan") is not None

    def run_rustscan(self, ip: str) -> list:
        """Runs RustScan to scan all 65,535 ports in parallel.
        
        Parses output in grepable format: e.g. '1.1.1.1 -> [53, 80, 443]'
        """
        if not self.is_rustscan_available():
            return []
            
        logger.warn(f"[-] RustScan detected! Initiating high-speed 65,535 port scan on {ip}...")
        cmd = ["rustscan", "-a", ip, "-t", "2000", "--ulimit", "5000", "-g"]
        
        try:
            # Execute RustScan with a 20 second safety timeout
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            if result.returncode == 0:
                output = result.stdout.strip()
                # Extract ports from e.g. "44.238.29.244 -> [80, 443]"
                match = re.search(r"->\s*\[(.*?)\]", output)
                if match:
                    ports_str = match.group(1)
                    if ports_str.strip():
                        ports = [int(p.strip()) for p in ports_str.split(",") if p.strip().isdigit()]
                        logger.info(f"[+] RustScan discovered {len(ports)} open TCP ports on {ip}: {ports}")
                        return ports
                logger.info(f"[-] RustScan completed. No open ports found on {ip}.")
            else:
                logger.error(f"[!] RustScan process failed (exit {result.returncode}): {result.stderr}")
        except subprocess.TimeoutExpired:
            logger.error(f"[!] RustScan execution timed out for {ip}")
        except Exception as e:
            logger.error(f"[!] Failed to run RustScan wrapper: {e}")
            
        return []

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
        
        # Use domain name only if it is a valid FQDN (no spaces), otherwise fall back to IP
        target_host = domain.strip() if domain and " " not in domain.strip() else ip
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
