from core.models import ExposureEvent

def calculate_risk(event: ExposureEvent) -> str:
    """Returns a risk severity for the exposed port."""
    if event.port in {3389, 23}: return "Critical"  # RDP, Telnet
    if event.port in {445, 21}: return "High"       # SMB, FTP
    if event.port in {80, 443, 8080, 8443}: return "Medium"
    return "Low"
