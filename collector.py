import ipaddress
from core.splunk_client import SplunkClient
from core.logger import get_logger
from core.shodan_client import InternetDBClient
from core.normalizer import normalize_internetdb_response
from core.risk_engine import calculate_risk
from core.baseline import BaselineEngine
from core.config_loader import ConfigLoader

logger = get_logger()

def get_target_ips():
    """Yields individual IPs from the configured assets."""
    config = ConfigLoader().load()
    for asset in config.get("assets", []):
        val = asset.get("value")
        if asset.get("type") == "cidr":
            for ip in ipaddress.ip_network(val, strict=False):
                yield str(ip)
        else:
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
    
    new_exposures = 0
    total_targets = 0

    for ip in get_target_ips():
        total_targets += 1
        logger.info(f"Scanning {ip}...")
        info = shodan.get_ip_info(ip)
        events = normalize_internetdb_response(info)
        
        for event in events:
            if baseline.is_new_exposure(event):
                new_exposures += 1
                event_dict = event.to_dict()
                event_dict["risk"] = calculate_risk(event)
                logger.info(f"NEW Exposure Detected: {event_dict['ip']}:{event_dict['port']} ({event_dict['risk']})")
                
                # Dispatch to Splunk
                result = splunk.send_event(event_dict)
                if not result.get("success"):
                    logger.error(f"Failed to send to Splunk: {result.get('error')}")

    logger.info(f"Scan complete. {total_targets} targets scanned. {new_exposures} new exposures sent to Splunk.")
    logger.info("=== EASM Collector finished ===")

if __name__ == "__main__":
    main()