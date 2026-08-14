from enum import Enum

from cyberwatchtower.core.evidence import EpistemicRole


class MemoryProvenance(str, Enum):
    DETERMINISTIC_OBSERVATION = "DETERMINISTIC_OBSERVATION"
    DERIVED_HISTORY = "DERIVED_HISTORY"
    USER_ASSERTION = "USER_ASSERTION"
    USER_DECISION = "USER_DECISION"
    RETRIEVED_KNOWLEDGE = "RETRIEVED_KNOWLEDGE"
    MODEL_INTERPRETATION = "MODEL_INTERPRETATION"


_EPISTEMIC_ROLE_BY_PROVENANCE = {
    MemoryProvenance.DETERMINISTIC_OBSERVATION: EpistemicRole.OBSERVED_FACT,
    MemoryProvenance.DERIVED_HISTORY: EpistemicRole.DETERMINISTIC_DERIVATION,
    MemoryProvenance.USER_ASSERTION: EpistemicRole.USER_ASSERTION,
    MemoryProvenance.USER_DECISION: EpistemicRole.USER_DECISION,
    MemoryProvenance.RETRIEVED_KNOWLEDGE: EpistemicRole.EXTERNAL_KNOWLEDGE,
    MemoryProvenance.MODEL_INTERPRETATION: EpistemicRole.MODEL_INTERPRETATION,
}


def provenance_epistemic_role(provenance: MemoryProvenance) -> EpistemicRole:
    """Map the closed storage-origin contract to the grounding contract."""

    return _EPISTEMIC_ROLE_BY_PROVENANCE[MemoryProvenance(provenance)]
