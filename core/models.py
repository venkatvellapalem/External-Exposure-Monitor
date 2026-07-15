from dataclasses import dataclass, asdict
from typing import List

@dataclass
class ExposureEvent:
    """Represents a single exposed port/service on an asset."""
    ip: str
    port: int
    hostnames: List[str]
    cpes: List[str]
    vulns: List[str]
    tags: List[str]
    source: str = "internetdb"
    domain: str = ""
    status: str = "open" # "open" or "closed" to represent lifecycle changes
    
    def to_dict(self) -> dict:
        return asdict(self)
