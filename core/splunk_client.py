import os
import json
import time
import urllib.request
import urllib.error
import ssl
from dotenv import load_dotenv

load_dotenv()

class SplunkClient:
    """Client for interacting with Splunk HTTP Event Collector (HEC)."""
    
    def __init__(self):
        self.url = os.getenv("SPLUNK_URL")
        self.token = os.getenv("SPLUNK_HEC_TOKEN")

        if not self.url:
            raise ValueError("SPLUNK_URL is not configured.")
        if not self.token:
            raise ValueError("SPLUNK_HEC_TOKEN is not configured.")

    def send_event(self, event: dict, max_retries: int = 3) -> dict:
        """Sends a single event to Splunk HEC with automatic retries."""
        
        headers = {
            "Authorization": f"Splunk {self.token}",
            "Content-Type": "application/json"
        }
        
        # Proper HEC wrapper
        payload_dict = {
            "sourcetype": "_json",
            "source": "easm_collector",
            "event": event
        }
        payload = json.dumps(payload_dict).encode('utf-8')
        
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        last_error = None
        for attempt in range(1, max_retries + 1):
            try:
                req = urllib.request.Request(self.url, data=payload, headers=headers, method='POST')
                with urllib.request.urlopen(req, context=ctx, timeout=15) as response:
                    return {
                        "success": True,
                        "status_code": response.status,
                        "message": "Event sent successfully.",
                        "data": json.loads(response.read().decode('utf-8')),
                        "error": None
                    }
            except urllib.error.HTTPError as e:
                # HTTP rejection (401, 403, 400) won't succeed on retry
                return {
                    "success": False,
                    "status_code": e.code,
                    "message": "HTTP request failed.",
                    "data": None,
                    "error": str(e)
                }
            except (urllib.error.URLError, Exception) as e:
                last_error = str(e.reason) if hasattr(e, 'reason') else str(e)
                if attempt < max_retries:
                    time.sleep(1)
                    continue

        return {
            "success": False,
            "status_code": None,
            "message": f"Failed to reach Splunk HEC after {max_retries} attempts.",
            "data": None,
            "error": last_error
        }