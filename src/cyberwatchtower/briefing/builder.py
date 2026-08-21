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
    make_evidence_ref,
)
from cyberwatchtower.core.grounding import require_grounded
from cyberwatchtower.memory.context import MemoryContext
from cyberwatchtower.score_explanation import render_score_explanation


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
    memory_context: MemoryContext | None = None,
) -> SecurityBriefing:
    """Build one channel-neutral briefing from the trusted deterministic Advisor."""

    context = build_advisor_context(current_report, comparison, intelligence)
    advisory = generate_advisory(context)
    evidence = [
        make_evidence_ref(
            "advisor:posture",
            EvidenceSource.DETERMINISTIC_ADVISOR,
            "posture_summary",
            EpistemicRole.DETERMINISTIC_DERIVATION,
            "Deterministic score and assessment summary",
        ),
        make_evidence_ref(
            "advisor:changes",
            EvidenceSource.DETERMINISTIC_ADVISOR,
            "changes_summary",
            EpistemicRole.DETERMINISTIC_DERIVATION,
            "Deterministic report comparison",
        ),
        make_evidence_ref(
            "advisor:recurring",
            EvidenceSource.DETERMINISTIC_ADVISOR,
            "recurring_summary",
            EpistemicRole.DETERMINISTIC_DERIVATION,
            "Deterministic historical analysis",
        ),
    ]
    if context.score_explanation is not None:
        evidence.append(make_evidence_ref(
            "advisor:score",
            EvidenceSource.DETERMINISTIC_ADVISOR,
            "score_explanation",
            EpistemicRole.DETERMINISTIC_DERIVATION,
            "Canonical deterministic score breakdown",
        ))
    findings_by_id = {finding.finding_id: finding for finding in context.findings}
    priority_claims = []
    for group in advisory.finding_groups[:5]:
        finding = findings_by_id[group.finding_ids[0]]
        evidence_ids = []
        for finding_id in group.finding_ids:
            member = findings_by_id[finding_id]
            evidence_id = f"finding:{finding_id}"
            evidence.append(make_evidence_ref(
                evidence_id,
                EvidenceSource.DETERMINISTIC_FINDING,
                finding_id,
                EpistemicRole.OBSERVED_FACT,
                member.title,
            ))
            evidence_ids.append(evidence_id)
            if member.reachability_state:
                reachability_id = f"reachability:{finding_id}"
                evidence.append(make_evidence_ref(
                    reachability_id,
                    EvidenceSource.DETERMINISTIC_INTERPRETATION,
                    finding_id,
                    EpistemicRole.DETERMINISTIC_DERIVATION,
                    member.reachability_state,
                ))
                evidence_ids.append(reachability_id)
        uncertainty = (
            " (legacy metadata normalized conservatively; not confirmed)"
            if finding.metadata_inferred else ""
        )
        related = (
            f" ({len(group.finding_ids)} related listeners)"
            if len(group.finding_ids) > 1 else ""
        )
        priority_claims.append(Claim(
            f"priority:{group.group_id}",
            f"[{finding.severity}/{finding.assessment_state.value}] "
            f"{finding.title}{related}{uncertainty}",
            EpistemicRole.DETERMINISTIC_DERIVATION,
            tuple(evidence_ids),
        ))

    action_claims = []
    for action in advisory.actions[:3]:
        evidence_id = f"action:{action.action_id}"
        evidence.append(make_evidence_ref(
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
    if context.score_explanation is not None:
        score_claims = tuple(
            _claim(f"score:{index}", line, "advisor:score")
            for index, line in enumerate(render_score_explanation(
                context.score_explanation, context.assessment_assurance
            ), start=1)
        )
        sections.insert(1, ResponseSection(
            "score", "Score explanation", score_claims
        ))
    if context.resolved_findings:
        resolved_text = "; ".join(item.title for item in context.resolved_findings)
        sections.append(ResponseSection("resolved", "Resolved issues", (
            _claim("resolved:summary", resolved_text, "advisor:changes"),
        )))
    if coverage_claims:
        sections.append(ResponseSection("coverage", "Coverage limitations", coverage_claims))
    sections.append(ResponseSection("next", "What should I do next?", tuple(action_claims)))

    if memory_context and memory_context.findings:
        evidence.extend(memory_context.evidence)
        history_claims = []
        decision_claims = []
        for item in memory_context.findings:
            history_text = f"{item.finding_id} has appeared in {item.occurrence_count} scan(s)."
            if item.reopened_count:
                history_text += (
                    f" It was previously resolved and has reappeared "
                    f"{item.reopened_count} time(s)."
                )
            history_claims.append(_claim(
                f"memory:history:{item.finding_id}", history_text,
                f"memory:lifecycle:{item.finding_id}",
            ))
            if item.exception_expires_at:
                decision_claims.append(Claim(
                    f"memory:exception-claim:{item.finding_id}",
                    f"An active presentation exception exists for {item.finding_id} until {item.exception_expires_at}; the finding remains authoritative.",
                    EpistemicRole.USER_DECISION,
                    (f"memory:exception:{item.exception_id}",),
                ))
            if item.approved_baseline_id:
                decision_claims.append(Claim(
                    f"memory:baseline-claim:{item.finding_id}",
                    f"{item.finding_id} matches an approved baseline entry; this does not suppress the finding.",
                    EpistemicRole.USER_DECISION,
                    (f"memory:baseline:{item.approved_baseline_id}",),
                ))
            if item.previous_investigation_id:
                decision_claims.append(Claim(
                    f"memory:investigation-claim:{item.finding_id}",
                    f"{item.finding_id} was examined in investigation {item.previous_investigation_id}; completion does not establish remediation.",
                    EpistemicRole.USER_DECISION,
                    (f"memory:investigation:{item.previous_investigation_id}",),
                ))
        sections.insert(-1, ResponseSection(
            "memory-history", "Persistent history", tuple(history_claims)
        ))
        if decision_claims:
            sections.insert(-1, ResponseSection(
                "memory-context", "Approved context", tuple(decision_claims)
            ))
        if memory_context.actions:
            sections.insert(-1, ResponseSection(
                "memory-actions", "Previous action responses", tuple(
                    Claim(
                        f"memory:action-claim:{item.action_id}",
                        f"Action {item.action_id} was recorded as {item.response_type}; only a deterministic scan can establish remediation.",
                        EpistemicRole.USER_DECISION,
                        (f"memory:action-response:{item.response_id}",),
                    ) for item in memory_context.actions
                ),
            ))

    response = require_grounded(GroundedResponse(
        intent="SECURITY_BRIEFING",
        sections=tuple(sections),
        evidence=tuple(evidence),
        finding_ids=advisory.important_finding_ids,
        action_ids=tuple(action.action_id for action in advisory.actions[:3]),
        notice=memory_context.limitation if memory_context else None,
    ))
    return SecurityBriefing(response, context, advisory)
