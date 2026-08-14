import unittest

from cyberwatchtower.core.evidence import (
    Claim,
    EpistemicRole,
    EvidenceRef,
    EvidenceSource,
    GroundedResponse,
    ResponseSection,
    make_evidence_ref,
)
from cyberwatchtower.core.grounding import validate_grounding


def _response(claim_role, evidence_role, source=EvidenceSource.MODEL_OUTPUT):
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
                source,
                "model:1",
                evidence_role,
            ),
        ),
    )


class GroundingTests(unittest.TestCase):
    def test_observed_fact_accepts_observed_evidence(self):
        result = validate_grounding(
            _response(
                EpistemicRole.OBSERVED_FACT,
                EpistemicRole.OBSERVED_FACT,
                EvidenceSource.CURRENT_SCAN,
            )
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

    def test_model_output_cannot_forge_observed_role(self):
        result = validate_grounding(
            _response(EpistemicRole.OBSERVED_FACT, EpistemicRole.OBSERVED_FACT)
        )
        self.assertFalse(result.valid)
        with self.assertRaises(ValueError):
            make_evidence_ref(
                "forged", EvidenceSource.MODEL_OUTPUT, "model:1",
                EpistemicRole.OBSERVED_FACT,
            )

    def test_disallowed_mixed_evidence_cannot_piggyback(self):
        response = GroundedResponse(
            "TEST",
            (ResponseSection("test", "Test", (Claim(
                "claim", "Derived claim", EpistemicRole.DETERMINISTIC_DERIVATION,
                ("fact", "interpretation"),
            ),)),),
            (
                EvidenceRef("fact", EvidenceSource.CURRENT_SCAN, "scan:1",
                            EpistemicRole.OBSERVED_FACT),
                EvidenceRef("interpretation", EvidenceSource.MODEL_OUTPUT, "model:1",
                            EpistemicRole.MODEL_INTERPRETATION),
            ),
        )
        self.assertFalse(validate_grounding(response).valid)


if __name__ == "__main__":
    unittest.main()
