from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
import uuid


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class NormalizedEvent:
    timestamp: datetime
    source_ip: Optional[str]
    dest_ip: Optional[str]
    source_port: Optional[int]
    dest_port: Optional[int]
    protocol: Optional[str]
    action: str
    username: Optional[str]
    log_source: str
    raw_log: str
    severity: Severity = Severity.INFO
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tags: list[str] = field(default_factory=list)
