from core.models import ExposureEvent

def calculate_risk(event: ExposureEvent) -> str:
    """Returns a risk severity for the exposed port.
    
    - Standard Web Ports (80, 443): Low (Green/Safe)
    - Admin/Alternate Web & Infra (8080, 8443, 2082, 2083, 2087, 8880): Medium (Yellow)
    - Sensitive Infra (445 SMB, 21 FTP, 22 SSH): High (Orange)
    - Critical Remote Management (3389 RDP, 23 Telnet): Critical (Red)
    """
    if event.port in {3389, 23}:
        return "Critical"
    if event.port in {445, 21, 22}:
        return "High"
    if event.port in {8080, 8443, 2082, 2083, 2087, 8880}:
        return "Medium"
    if event.port in {80, 443}:
        return "Low"
    return "Low"
