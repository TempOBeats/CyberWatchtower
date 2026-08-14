from dataclasses import dataclass
from enum import Enum


class EpistemicRole(str, Enum):
    OBSERVED_FACT = "OBSERVED_FACT"
    DETERMINISTIC_DERIVATION = "DETERMINISTIC_DERIVATION"
    EXTERNAL_KNOWLEDGE = "EXTERNAL_KNOWLEDGE"
    USER_ASSERTION = "USER_ASSERTION"
    USER_DECISION = "USER_DECISION"
    MODEL_INTERPRETATION = "MODEL_INTERPRETATION"


class EvidenceSource(str, Enum):
    CURRENT_SCAN = "CURRENT_SCAN"
    HISTORICAL_SCAN = "HISTORICAL_SCAN"
    DETERMINISTIC_FINDING = "DETERMINISTIC_FINDING"
    DETERMINISTIC_ADVISOR = "DETERMINISTIC_ADVISOR"
    EXTERNAL_KNOWLEDGE = "EXTERNAL_KNOWLEDGE"
    USER_INPUT = "USER_INPUT"
    MODEL_OUTPUT = "MODEL_OUTPUT"


@dataclass(frozen=True)
class EvidenceRef:
    evidence_id: str
    source: EvidenceSource
    source_id: str
    epistemic_role: EpistemicRole
    label: str = ""


@dataclass(frozen=True)
class Claim:
    claim_id: str
    text: str
    epistemic_role: EpistemicRole
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class ResponseSection:
    section_id: str
    title: str
    claims: tuple[Claim, ...]


@dataclass(frozen=True)
class GroundedResponse:
    intent: str
    sections: tuple[ResponseSection, ...]
    evidence: tuple[EvidenceRef, ...]
    finding_ids: tuple[str, ...] = ()
    action_ids: tuple[str, ...] = ()
    notice: str | None = None
