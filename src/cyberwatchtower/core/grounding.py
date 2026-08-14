from dataclasses import dataclass

from .evidence import EpistemicRole, GroundedResponse


@dataclass(frozen=True)
class GroundingIssue:
    claim_id: str
    message: str


@dataclass(frozen=True)
class GroundingResult:
    valid: bool
    issues: tuple[GroundingIssue, ...]


_PERMITTED_SUPPORT = {
    EpistemicRole.OBSERVED_FACT: {EpistemicRole.OBSERVED_FACT},
    EpistemicRole.DETERMINISTIC_DERIVATION: {
        EpistemicRole.OBSERVED_FACT,
        EpistemicRole.DETERMINISTIC_DERIVATION,
    },
    EpistemicRole.EXTERNAL_KNOWLEDGE: {EpistemicRole.EXTERNAL_KNOWLEDGE},
    EpistemicRole.USER_ASSERTION: {EpistemicRole.USER_ASSERTION},
    EpistemicRole.USER_DECISION: {EpistemicRole.USER_DECISION},
    EpistemicRole.MODEL_INTERPRETATION: set(EpistemicRole),
}


def validate_grounding(response: GroundedResponse) -> GroundingResult:
    """Validate claim support without treating model interpretation as fact."""

    evidence = {item.evidence_id: item for item in response.evidence}
    issues = []
    for section in response.sections:
        for claim in section.claims:
            if not claim.evidence_ids:
                issues.append(GroundingIssue(claim.claim_id, "Claim has no evidence."))
                continue
            missing = [item for item in claim.evidence_ids if item not in evidence]
            if missing:
                issues.append(
                    GroundingIssue(claim.claim_id, "Claim references unknown evidence.")
                )
                continue
            allowed = _PERMITTED_SUPPORT[claim.epistemic_role]
            roles = {evidence[item].epistemic_role for item in claim.evidence_ids}
            if not roles.intersection(allowed):
                issues.append(
                    GroundingIssue(
                        claim.claim_id,
                        f"{claim.epistemic_role.value} lacks qualifying evidence.",
                    )
                )
    return GroundingResult(valid=not issues, issues=tuple(issues))


def require_grounded(response: GroundedResponse) -> GroundedResponse:
    result = validate_grounding(response)
    if not result.valid:
        details = "; ".join(issue.message for issue in result.issues)
        raise ValueError(f"Response failed grounding validation: {details}")
    return response
