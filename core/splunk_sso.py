import os
import ssl
import json
import urllib.request
import urllib.parse
import xml.etree.ElementTree as ET
from core.logger import get_logger

logger = get_logger()

class SplunkSSOManager:
    """Manages Single Sign-On (SSO) ticket generation with Splunk REST API on Port 8089."""

    def __init__(self):
        self.host = os.getenv("SPLUNK_HOST", "13.205.90.142")
        self.rest_port = os.getenv("SPLUNK_REST_PORT", "8089")
        self.web_port = os.getenv("SPLUNK_WEB_PORT", "8000")
        self.admin_user = os.getenv("SPLUNK_ADMIN_USER", "admin")
        self.admin_pass = os.getenv("SPLUNK_ADMIN_PASS", "Splunk@2026Secure!")

    def get_splunk_session_key(self, easm_role: str = "root_admin") -> str:
        """Obtains a Splunk Web session key via REST API on Port 8089."""
        url = f"https://{self.host}:{self.rest_port}/services/auth/login"
        payload = urllib.parse.urlencode({
            "username": self.admin_user,
            "password": self.admin_pass
        }).encode('utf-8')

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url, data=payload, method='POST')
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=8) as response:
                xml_response = response.read().decode('utf-8')
                root = ET.fromstring(xml_response)
                session_key = root.findtext("sessionKey")
                if session_key:
                    logger.info(f"[+] Obtained Splunk Web SSO session ticket for role '{easm_role}'")
                    return session_key
        except Exception as e:
            logger.error(f"[!] Failed to obtain Splunk Web SSO ticket: {e}")

        return None

    def get_sso_redirect_url(self, easm_role: str = "root_admin") -> str:
        """Constructs direct Splunk Web Dashboard Studio SSO URL with session ticket."""
        session_key = self.get_splunk_session_key(easm_role)
        base_url = f"http://{self.host}:{self.web_port}/en-GB/app/search/external_attack_surface_monitor"
        if session_key:
            return f"{base_url}?s={urllib.parse.quote(session_key)}"
        return base_url
