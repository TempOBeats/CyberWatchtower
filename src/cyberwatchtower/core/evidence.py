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
    MEMORY_HISTORY = "MEMORY_HISTORY"
    MEMORY_DECISION = "MEMORY_DECISION"
    MEMORY_AUDIT = "MEMORY_AUDIT"


SOURCE_ROLE_COMPATIBILITY: dict[EvidenceSource, frozenset[EpistemicRole]] = {
    EvidenceSource.CURRENT_SCAN: frozenset({EpistemicRole.OBSERVED_FACT}),
    EvidenceSource.HISTORICAL_SCAN: frozenset({EpistemicRole.OBSERVED_FACT}),
    EvidenceSource.DETERMINISTIC_FINDING: frozenset({EpistemicRole.OBSERVED_FACT}),
    EvidenceSource.DETERMINISTIC_ADVISOR: frozenset({
        EpistemicRole.DETERMINISTIC_DERIVATION,
    }),
    EvidenceSource.EXTERNAL_KNOWLEDGE: frozenset({EpistemicRole.EXTERNAL_KNOWLEDGE}),
    EvidenceSource.USER_INPUT: frozenset({
        EpistemicRole.USER_ASSERTION,
        EpistemicRole.USER_DECISION,
    }),
    EvidenceSource.MODEL_OUTPUT: frozenset({EpistemicRole.MODEL_INTERPRETATION}),
    EvidenceSource.MEMORY_HISTORY: frozenset({
        EpistemicRole.OBSERVED_FACT,
        EpistemicRole.DETERMINISTIC_DERIVATION,
    }),
    EvidenceSource.MEMORY_DECISION: frozenset({EpistemicRole.USER_DECISION}),
    EvidenceSource.MEMORY_AUDIT: frozenset({
        EpistemicRole.DETERMINISTIC_DERIVATION,
        EpistemicRole.USER_DECISION,
    }),
}


@dataclass(frozen=True)
class EvidenceRef:
    evidence_id: str
    source: EvidenceSource
    source_id: str
    epistemic_role: EpistemicRole
    label: str = ""


def make_evidence_ref(
    evidence_id: str,
    source: EvidenceSource,
    source_id: str,
    epistemic_role: EpistemicRole,
    label: str = "",
) -> EvidenceRef:
    """Construct evidence only when its provenance can support its role."""

    if epistemic_role not in SOURCE_ROLE_COMPATIBILITY[source]:
        raise ValueError(
            f"{source.value} cannot be labeled {epistemic_role.value}."
        )
    return EvidenceRef(evidence_id, source, source_id, epistemic_role, label)


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
