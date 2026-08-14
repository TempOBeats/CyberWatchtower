import unittest

from cyberwatchtower.core.evidence import (
    Claim,
    EpistemicRole,
    EvidenceRef,
    EvidenceSource,
    GroundedResponse,
    ResponseSection,
)
from cyberwatchtower.core.grounding import validate_grounding


def _response(claim_role, evidence_role):
    return GroundedResponse(
        intent="TEST",
        sections=(
            ResponseSection(
                section_id="test",
                title="Test",
                claims=(Claim("claim", "A claim", claim_role, ("evidence",)),),
            ),
        ),
        evidence=(
            EvidenceRef(
                "evidence",
                EvidenceSource.MODEL_OUTPUT,
                "model:1",
                evidence_role,
            ),
        ),
    )


class GroundingTests(unittest.TestCase):
    def test_observed_fact_accepts_observed_evidence(self):
        result = validate_grounding(
            _response(EpistemicRole.OBSERVED_FACT, EpistemicRole.OBSERVED_FACT)
        )
        self.assertTrue(result.valid)

    def test_model_interpretation_cannot_support_observed_fact(self):
        result = validate_grounding(
            _response(
                EpistemicRole.OBSERVED_FACT,
                EpistemicRole.MODEL_INTERPRETATION,
            )
        )
        self.assertFalse(result.valid)

    def test_model_interpretation_cannot_support_deterministic_derivation(self):
        result = validate_grounding(
            _response(
                EpistemicRole.DETERMINISTIC_DERIVATION,
                EpistemicRole.MODEL_INTERPRETATION,
            )
        )
        self.assertFalse(result.valid)

    def test_unknown_evidence_is_rejected(self):
        response = GroundedResponse(
            intent="TEST",
            sections=(ResponseSection("test", "Test", (Claim(
                "claim", "A claim", EpistemicRole.OBSERVED_FACT, ("missing",)
            ),)),),
            evidence=(),
        )
        self.assertFalse(validate_grounding(response).valid)


if __name__ == "__main__":
    unittest.main()
