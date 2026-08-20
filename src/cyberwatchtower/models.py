from dataclasses import dataclass, field
from enum import Enum
from typing import List

class Severity(str, Enum):
    INFO= "INFO"
    LOW= "LOW"
    MEDIUM= "MEDIUM"
    HIGH= "HIGH"
    CRITICAL= "CRITICAL"


class FindingKind(str, Enum):
    RISK = "RISK"
    COVERAGE_GAP = "COVERAGE_GAP"
    OBSERVATION = "OBSERVATION"


class AssessmentState(str, Enum):
    CONFIRMED = "CONFIRMED"
    POTENTIAL = "POTENTIAL"
    INCOMPLETE = "INCOMPLETE"
    INFORMATIONAL = "INFORMATIONAL"


@dataclass
class Finding:
    title: str
    description: str
    severity: Severity
    recommendation: str
    evidence: List[str] = field(default_factory=list)
    confidence: int = 0
    technique_id: str | None = None
    finding_id: str | None = None
    source: str = "unknown"
    kind: FindingKind = FindingKind.RISK
    assessment_state: AssessmentState = AssessmentState.POTENTIAL
    network_context: dict[str, object] | None = None
    presentation_group_id: str | None = None
