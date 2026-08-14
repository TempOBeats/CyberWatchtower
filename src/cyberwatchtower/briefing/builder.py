from collections.abc import Mapping
from dataclasses import dataclass

from cyberwatchtower.advisor.context import build_advisor_context
from cyberwatchtower.advisor.models import AdvisoryReport, AdvisorContext
from cyberwatchtower.advisor.service import generate_advisory
from cyberwatchtower.core.evidence import (
    Claim,
    EpistemicRole,
    EvidenceRef,
    EvidenceSource,
    GroundedResponse,
    ResponseSection,
)
from cyberwatchtower.core.grounding import require_grounded


@dataclass(frozen=True)
class SecurityBriefing:
    response: GroundedResponse
    advisor_context: AdvisorContext
    advisory: AdvisoryReport


def _claim(claim_id: str, text: str, evidence_id: str) -> Claim:
    return Claim(
        claim_id,
        text,
        EpistemicRole.DETERMINISTIC_DERIVATION,
        (evidence_id,),
    )


def build_security_briefing(
    current_report: Mapping,
    comparison: Mapping | None,
    intelligence: Mapping | None,
) -> SecurityBriefing:
    """Build one channel-neutral briefing from the trusted deterministic Advisor."""

    context = build_advisor_context(current_report, comparison, intelligence)
    advisory = generate_advisory(context)
    evidence = [
        EvidenceRef(
            "advisor:posture",
            EvidenceSource.DETERMINISTIC_ADVISOR,
            "posture_summary",
            EpistemicRole.DETERMINISTIC_DERIVATION,
            "Deterministic score and assessment summary",
        ),
        EvidenceRef(
            "advisor:changes",
            EvidenceSource.DETERMINISTIC_ADVISOR,
            "changes_summary",
            EpistemicRole.DETERMINISTIC_DERIVATION,
            "Deterministic report comparison",
        ),
        EvidenceRef(
            "advisor:recurring",
            EvidenceSource.DETERMINISTIC_ADVISOR,
            "recurring_summary",
            EpistemicRole.DETERMINISTIC_DERIVATION,
            "Deterministic historical analysis",
        ),
    ]
    findings_by_id = {finding.finding_id: finding for finding in context.findings}
    priority_claims = []
    for finding_id in advisory.important_finding_ids:
        finding = findings_by_id[finding_id]
        evidence_id = f"finding:{finding_id}"
        evidence.append(EvidenceRef(
            evidence_id,
            EvidenceSource.DETERMINISTIC_FINDING,
            finding_id,
            EpistemicRole.DETERMINISTIC_DERIVATION,
            finding.title,
        ))
        uncertainty = (
            " (legacy metadata normalized conservatively; not confirmed)"
            if finding.metadata_inferred else ""
        )
        priority_claims.append(_claim(
            f"priority:{finding_id}",
            f"[{finding.severity}/{finding.assessment_state.value}] {finding.title}{uncertainty}",
            evidence_id,
        ))

    action_claims = []
    for action in advisory.actions[:3]:
        evidence_id = f"action:{action.action_id}"
        evidence.append(EvidenceRef(
            evidence_id,
            EvidenceSource.DETERMINISTIC_ADVISOR,
            action.action_id,
            EpistemicRole.DETERMINISTIC_DERIVATION,
            "Deterministic Advisor action",
        ))
        action_claims.append(_claim(
            f"next:{action.action_id}",
            f"{action.action} Why it matters: {action.rationale}",
            evidence_id,
        ))

    if not action_claims:
        action_claims.append(_claim(
            "next:monitor",
            advisory.next_steps[0],
            "advisor:posture",
        ))

    coverage_claims = tuple(
        _claim(f"coverage:{index}", warning, "advisor:posture")
        for index, warning in enumerate(advisory.coverage_warnings, start=1)
    )
    sections = [
        ResponseSection("posture", "Current posture", (
            _claim("posture:summary", advisory.posture_summary, "advisor:posture"),
        )),
        ResponseSection("changes", "Changes since previous assessment", (
            _claim("changes:summary", advisory.changes_summary, "advisor:changes"),
        )),
        ResponseSection("priorities", "Highest priorities", tuple(priority_claims)),
        ResponseSection("recurring", "Recurring concerns", (
            _claim("recurring:summary", advisory.recurring_summary, "advisor:recurring"),
        )),
    ]
    if context.resolved_findings:
        resolved_text = "; ".join(item.title for item in context.resolved_findings)
        sections.append(ResponseSection("resolved", "Resolved issues", (
            _claim("resolved:summary", resolved_text, "advisor:changes"),
        )))
    if coverage_claims:
        sections.append(ResponseSection("coverage", "Coverage limitations", coverage_claims))
    sections.append(ResponseSection("next", "What should I do next?", tuple(action_claims)))

    response = require_grounded(GroundedResponse(
        intent="SECURITY_BRIEFING",
        sections=tuple(sections),
        evidence=tuple(evidence),
        finding_ids=advisory.important_finding_ids,
        action_ids=tuple(action.action_id for action in advisory.actions[:3]),
    ))
    return SecurityBriefing(response, context, advisory)
