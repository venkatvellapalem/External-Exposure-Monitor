import ipaddress
import socket
import os
from dotenv import load_dotenv
load_dotenv()

from core.splunk_client import SplunkClient
from core.logger import get_logger
from core.shodan_client import InternetDBClient
from core.normalizer import normalize_internetdb_response
from core.risk_engine import calculate_risk
from core.baseline import BaselineEngine
from core.config_loader import ConfigLoader
from core.crt_client import CrtClient
from core.active_scanner import ActiveScanner
from core.models import ExposureEvent

logger = get_logger()

def resolve_to_ip(value: str) -> str:
    """Helper to resolve domain strings to IP address if needed."""
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        try:
            ip = socket.gethostbyname(value)
            logger.info(f"[-] Resolved {value} -> {ip}")
            return ip
        except Exception as e:
            logger.error(f"[!] Failed to resolve {value}: {e}")
            return None

def get_target_ips():
    """Yields unique individual tuples of (ip, domain/hostname) from the configured assets."""
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
                    yield ip_str, ""
        elif a_type == "domain":
            # 1. Always resolve and scan the root domain itself first
            root_ip = resolve_to_ip(val)
            if root_ip and root_ip not in scanned_ips:
                scanned_ips.add(root_ip)
                yield root_ip, val

            # 2. Additionally check subdomains in CT logs
            subs = crt.get_subdomains(val)
            for sub in subs:
                sub_ip = resolve_to_ip(sub)
                if sub_ip and sub_ip not in scanned_ips:
                    scanned_ips.add(sub_ip)
                    yield sub_ip, sub
        else:
            resolved_ip = resolve_to_ip(val)
            if resolved_ip and resolved_ip not in scanned_ips:
                scanned_ips.add(resolved_ip)
                domain_val = val if resolved_ip != val else ""
                yield resolved_ip, domain_val

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
    resolved_exposures_count = 0
    
    # State tracking sets for this run
    scanned_ips_this_run = set()
    active_exposures_this_run = set()

    for ip, domain in get_target_ips():
        scanned_ips_this_run.add(ip)
        logger.info(f"Scanning {ip} (Asset Domain: {domain if domain else 'None'})...")
        
        info = shodan.get_ip_info(ip)
        events = normalize_internetdb_response(info)
        
        # Fallback: If Shodan has no data, actively verify common industry ports in parallel
        if not events:
            logger.info(f"[-] No Shodan data for {ip}. Running parallel fallback port scan...")
            fallback_ports = [80, 443, 8080, 8443, 21, 22, 23]
            open_ports = active.scan_ports_parallel(ip, fallback_ports)
            for port in open_ports:
                events.append(
                    ExposureEvent(
                        ip=ip,
                        port=port,
                        hostnames=[],
                        cpes=[],
                        vulns=[],
                        tags=[],
                        source="active_fallback"
                    )
                )
        
        # Process exposures
        for event in events:
            event.domain = domain
            
            # Check active status (skip if Shodan-reported port is actually closed)
            if event.source == "internetdb" and not active.is_port_open(event.ip, event.port):
                logger.info(f"Skipping closed exposure: {event.ip}:{event.port}")
                continue

            # Record this exposure as active during this run
            exposure_id = f"{event.ip}:{event.port}"
            active_exposures_this_run.add(exposure_id)

            # Check state changes in baseline
            last_status = baseline.get_status(event.ip, event.port)
            if last_status != "open":
                # Newly opened or re-opened!
                new_exposures += 1
                event.status = "open"
                baseline.update_status(event.ip, event.port, "open")
                
                event_dict = event.to_dict()
                risk = calculate_risk(event)
                
                web_ports = {80, 443, 8080, 8443, 2082, 2083, 2087, 8880}
                leaks = []
                if event.port in web_ports:
                    leaks = active.audit_sensitive_files(event.ip, event.port, domain=event.domain)
                    if leaks:
                        risk = "Critical"
                        event_dict["leaks"] = leaks
                        logger.warn(f"[!] Escalating risk for {event.ip}:{event.port} to Critical due to leaks: {leaks}")
                
                event_dict["risk"] = risk
                logger.info(f"NEW/RE-OPENED Exposure Detected: {exposure_id} ({risk})")
                
                result = splunk.send_event(event_dict)
                if not result.get("success"):
                    logger.error(f"Failed to send to Splunk: {result.get('error')}")

    # 4. Active Reconciliation: Detect resolved (closed) exposures on scanned IPs
    currently_open_in_baseline = baseline.get_currently_open()
    for exp_id in currently_open_in_baseline:
        ip, port_str = exp_id.split(":")
        port = int(port_str)
        
        # We only declare an exposure closed if we actively scanned the parent IP,
        # but the specific port was no longer found open.
        if ip in scanned_ips_this_run and exp_id not in active_exposures_this_run:
            resolved_exposures_count += 1
            baseline.update_status(ip, port, "closed")
            
            # Send status='closed' event to Splunk
            resolved_event = ExposureEvent(
                ip=ip,
                port=port,
                hostnames=[],
                cpes=[],
                vulns=[],
                tags=[],
                source="active_reconciliation",
                status="closed"
            )
            event_dict = resolved_event.to_dict()
            event_dict["risk"] = "Resolved"
            
            logger.warn(f"[-] Exposure RESOLVED/CLOSED: {exp_id}")
            
            result = splunk.send_event(event_dict)
            if not result.get("success"):
                logger.error(f"Failed to send to Splunk HEC: {result.get('error')}")

    logger.info(f"Scan complete. {len(scanned_ips_this_run)} targets scanned.")
    logger.info(f"Result: {new_exposures} new exposures, {resolved_exposures_count} resolved exposures.")
    logger.info("=== EASM Collector finished ===")

if __name__ == "__main__":
    main()