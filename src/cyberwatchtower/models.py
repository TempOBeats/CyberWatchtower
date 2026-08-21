from dataclasses import dataclass, field
from enum import Enum
from typing import List


MAX_RUNTIME_INSTANCE_COUNT = 65_536

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

    runtime_instance_count: int = 1

    def __post_init__(self) -> None:
        count = self.runtime_instance_count
        if (
            isinstance(count, bool)
            or not isinstance(count, int)
            or not 1 <= count <= MAX_RUNTIME_INSTANCE_COUNT
        ):
            raise ValueError("runtime_instance_count is outside the supported bound.")

    def __setattr__(self, name: str, value: object) -> None:
        if name == "runtime_instance_count" and name in self.__dict__:
            raise AttributeError("runtime_instance_count is immutable.")
        super().__setattr__(name, value)
