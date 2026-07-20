from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional


@dataclass
class Target:
    """A single entry from assets.yaml -- something we're allowed to check."""
    type: str           
    value: str
    organization: str = ""


@dataclass
class Finding:
 
    ip: str
    collector_source: str                                  
    port: Optional[int] = None
    status: str = "found"                         
    message: str = ""                              
    product: str = ""
    version: str = ""
    hostnames: list[str] = field(default_factory=list)
    vulns: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    severity: str = "Unscored"                       
    scanned_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return asdict(self)
