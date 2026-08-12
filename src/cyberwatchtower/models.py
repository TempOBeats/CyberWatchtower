from dataclasses import dataclass, field
from enum import Enum
from typing import List

class Severity(str, Enum):
    INFO= "INFO"
    LOW= "LOW"
    MEDIUM= "MEDIUM"
    HIGH= "HIGH"
    CRITICAL= "CRITICAL"

@dataclass
class Finding:
    title: str
    description: str
    severity: Severity
    recommendation: str
    evidence: List[str] = field(default_factory=list)
    confidence: int = 0
    technique_id: str | None = None
