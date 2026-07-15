from typing import List
from core.models import ExposureEvent

def normalize_internetdb_response(raw_data: dict) -> List[ExposureEvent]:
    """Converts a raw InternetDB response into a list of ExposureEvents (one per port)."""
    if "error" in raw_data or not raw_data.get("ports"):
        return []

    ip = raw_data.get("ip", "")
    hostnames = raw_data.get("hostnames", [])
    cpes = raw_data.get("cpes", [])
    vulns = raw_data.get("vulns", [])
    tags = raw_data.get("tags", [])

    return [
        ExposureEvent(
            ip=ip,
            port=port,
            hostnames=hostnames,
            cpes=cpes,
            vulns=vulns,
            tags=tags
        )
        for port in raw_data.get("ports", [])
    ]
