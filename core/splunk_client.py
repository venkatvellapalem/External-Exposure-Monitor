import os
import json
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

    def send_event(self, event: dict) -> dict:
        """Sends a single event to Splunk HEC."""
        
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
        req = urllib.request.Request(self.url, data=payload, headers=headers, method='POST')
        
        # ponytail: ignoring SSL validation by default for local self-signed certs. Upgrade path: add SPLUNK_CA_CERT to env and pass cafile to create_default_context.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
                return {
                    "success": True,
                    "status_code": response.status,
                    "message": "Event sent successfully.",
                    "data": json.loads(response.read().decode('utf-8')),
                    "error": None
                }
        except urllib.error.HTTPError as e:
            return {
                "success": False,
                "status_code": e.code,
                "message": "HTTP request failed.",
                "data": None,
                "error": str(e)
            }
        except urllib.error.URLError as e:
            return {
                "success": False,
                "status_code": None,
                "message": "Failed to reach Splunk HEC.",
                "data": None,
                "error": str(e.reason)
            }
        except Exception as e:
            return {
                "success": False,
                "status_code": None,
                "message": "Unexpected error.",
                "data": None,
                "error": str(e)
            }