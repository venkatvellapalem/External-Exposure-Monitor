import ipaddress
from core.splunk_client import SplunkClient
from core.logger import get_logger
from core.shodan_client import InternetDBClient
from core.normalizer import normalize_internetdb_response
from core.risk_engine import calculate_risk
from core.baseline import BaselineEngine
from core.config_loader import ConfigLoader
from core.crt_client import CrtClient
from core.active_scanner import ActiveScanner

logger = get_logger()

def get_target_ips():
    """Yields unique individual IPs from the configured assets, resolving domains and CIDRs."""
    config = ConfigLoader().load()
    crt = CrtClient()
    scanned_ips = set()
    
    for asset in config.get("assets", []):
        val = asset.get("value")
        a_type = asset.get("type")
        
        if a_type == "cidr":
            for ip in ipaddress.ip_network(val, strict=False):
                ip_str = str(ip)
                if ip_str not in scanned_ips:
                    scanned_ips.add(ip_str)
                    yield ip_str
        elif a_type == "domain":
            subs = crt.get_subdomains(val)
            resolved_ips = crt.resolve_subdomains_to_ips(subs)
            for ip_str in resolved_ips:
                if ip_str not in scanned_ips:
                    scanned_ips.add(ip_str)
                    yield ip_str
        else:
            if val not in scanned_ips:
                scanned_ips.add(val)
                yield val

def main():
    logger.info("=== EASM Collector started ===")
    
    try:
        splunk = SplunkClient()
    except Exception as e:
        logger.error(f"Failed to initialize SplunkClient: {e}")
        return

    baseline = BaselineEngine()
    shodan = InternetDBClient()
    active = ActiveScanner()
    
    new_exposures = 0
    total_targets = 0

    for ip in get_target_ips():
        total_targets += 1
        logger.info(f"Scanning {ip}...")
        info = shodan.get_ip_info(ip)
        events = normalize_internetdb_response(info)
        
        for event in events:
            # 1. Active Verification: Check if port is genuinely open
            if not active.is_port_open(event.ip, event.port):
                logger.info(f"Skipping closed exposure: {event.ip}:{event.port}")
                continue

            # 2. Baseline Check: Only alert on new exposures
            if baseline.is_new_exposure(event):
                new_exposures += 1
                event_dict = event.to_dict()
                
                # 3. Default Risk Calculation
                risk = calculate_risk(event)
                
                # 4. Active Leak Auditing for Web Ports
                web_ports = {80, 443, 8080, 8443, 2082, 2083, 2087, 8880}
                leaks = []
                if event.port in web_ports:
                    leaks = active.audit_sensitive_files(event.ip, event.port)
                    if leaks:
                        risk = "Critical"
                        event_dict["leaks"] = leaks
                        logger.warn(f"[!] Escalating risk for {event.ip}:{event.port} to Critical due to leaks: {leaks}")
                
                event_dict["risk"] = risk
                logger.info(f"NEW Exposure Detected: {event_dict['ip']}:{event_dict['port']} ({event_dict['risk']})")
                
                # Dispatch to Splunk
                result = splunk.send_event(event_dict)
                if not result.get("success"):
                    logger.error(f"Failed to send to Splunk: {result.get('error')}")

    logger.info(f"Scan complete. {total_targets} targets scanned. {new_exposures} new exposures verified and sent to Splunk.")
    logger.info("=== EASM Collector finished ===")

if __name__ == "__main__":
    main()