import hashlib

from cyberwatchtower.models import AssessmentState, FindingKind

from .models import (
    AdvisoryAction,
    AdvisoryFinding,
    AdvisoryFindingGroup,
    AdvisoryReport,
    AdvisorContext,
)


SEVERITY_PRIORITY = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
    "UNKNOWN": 0,
}

STATE_PRIORITY = {
    AssessmentState.CONFIRMED: 4,
    AssessmentState.POTENTIAL: 3,
    AssessmentState.INCOMPLETE: 2,
    AssessmentState.INFORMATIONAL: 1,
}


def finding_priority_key(finding: AdvisoryFinding) -> tuple:
    return (
        SEVERITY_PRIORITY.get(finding.severity, 0),
        STATE_PRIORITY[finding.assessment_state],
        int(finding.is_new),
        int(finding.is_recurring),
        int(finding.exposure == "all interfaces"),
        finding.confidence,
        finding.finding_id,
    )


def _posture_summary(context: AdvisorContext) -> str:
    confirmed = sum(
        finding.assessment_state == AssessmentState.CONFIRMED
        and finding.kind == FindingKind.RISK
        for finding in context.findings
    )
    potential = sum(
        finding.assessment_state == AssessmentState.POTENTIAL
        and finding.kind == FindingKind.RISK
        for finding in context.findings
    )
    incomplete = sum(
        finding.assessment_state == AssessmentState.INCOMPLETE
        for finding in context.findings
    )
    return (
        f"CyberWatchtower scored this system {context.score}/100 with a "
        f"{context.risk_level} risk level. Assessment assurance is "
        f"{context.assessment_assurance}. The current assessment contains "
        f"{confirmed} confirmed risk(s), {potential} potential risk(s), and "
        f"{incomplete} incomplete assessment(s)."
    )


def _finding_rationale(finding: AdvisoryFinding) -> str:
    if finding.assessment_state == AssessmentState.INCOMPLETE:
        rationale = (
            "This matters because the assessment could not verify this security "
            "area, so the reported posture may be incomplete."
        )
    elif finding.assessment_state == AssessmentState.CONFIRMED:
        rationale = (
            f"This matters because CyberWatchtower confirmed the {finding.title} "
            "condition from deterministic scan evidence."
        )
    else:
        rationale = (
            f"This matters because {finding.title} may affect the system's "
            "security posture and should be verified."
        )

    if finding.metadata_inferred:
        rationale += (
            " Its potential-risk classification was inferred conservatively from "
            "a legacy report and is not a confirmed finding."
        )

    service_name = finding.application_name
    if service_name and finding.process:
        rationale += (
            f" Process Intelligence attributed the {service_name} application "
            f"to the {finding.process} process."
        )
    elif finding.process and finding.port:
        rationale += f" The listener is owned by {finding.process} on port {finding.port}."

    if finding.is_new:
        rationale += " This finding is new since the previous scan."
    if finding.is_recurring:
        rationale += f" It has appeared in {finding.occurrences} scans."
    if finding.runtime_instance_count > 1:
        rationale += (
            " Multiple runtime instances were observed: "
            f"{finding.runtime_instance_count}. This does not increase risk by itself."
        )
    return rationale


def _group_key(finding: AdvisoryFinding) -> tuple[str, ...]:
    if finding.presentation_group_id:
        return ("presentation", finding.presentation_group_id)
    return ("finding", finding.finding_id)


def _group_id(key: tuple[str, ...]) -> str:
    return "presentation:" + hashlib.sha256("\0".join(key).encode()).hexdigest()


def _groups(findings: list[AdvisoryFinding]) -> tuple[tuple[AdvisoryFinding, ...], ...]:
    grouped: dict[tuple[str, ...], list[AdvisoryFinding]] = {}
    for finding in findings:
        grouped.setdefault(_group_key(finding), []).append(finding)
    groups = tuple(
        tuple(sorted(items, key=lambda item: item.finding_id))
        for items in grouped.values()
    )
    return tuple(sorted(
        groups,
        key=lambda items: finding_priority_key(max(items, key=finding_priority_key)),
        reverse=True,
    ))


def _presentation_groups(
    findings: list[AdvisoryFinding],
) -> tuple[AdvisoryFindingGroup, ...]:
    result = []
    for items in _groups(findings):
        representative = max(items, key=finding_priority_key)
        result.append(AdvisoryFindingGroup(
            _group_id(_group_key(representative)),
            tuple(item.finding_id for item in items),
            representative.title,
            representative.severity,
            representative.assessment_state,
        ))
    return tuple(sorted(
        result,
        key=lambda group: (
            SEVERITY_PRIORITY.get(group.severity, 0),
            STATE_PRIORITY[group.assessment_state],
            group.group_id,
        ),
        reverse=True,
    ))


def _build_actions(findings: tuple[AdvisoryFinding, ...]) -> tuple[AdvisoryAction, ...]:
    actionable = [
        finding
        for finding in findings
        if finding.kind != FindingKind.OBSERVATION
    ]
    actionable.sort(key=finding_priority_key, reverse=True)
    actions = []

    for priority, items in enumerate(_groups(actionable), start=1):
        finding = max(items, key=finding_priority_key)
        action_text = finding.recommendation.strip() or (
            f"Review the deterministic finding: {finding.title}."
        )
        finding_ids = tuple(item.finding_id for item in items)
        action_id = (
            f"action:{finding.finding_id}"
            if len(items) == 1
            else "action-group:" + hashlib.sha256(
                "\0".join(finding_ids).encode()
            ).hexdigest()
        )
        rationale = _finding_rationale(finding)
        if len(items) > 1:
            rationale += f" This action covers {len(items)} related listener findings."
        actions.append(
            AdvisoryAction(
                action_id=action_id,
                priority=priority,
                finding_ids=finding_ids,
                action=action_text,
                rationale=rationale,
                assessment_state=finding.assessment_state,
                is_new=any(item.is_new for item in items),
                is_recurring=any(item.is_recurring for item in items),
            )
        )

    return tuple(actions)


def _changes_summary(context: AdvisorContext) -> str:
    if context.previous_score is None:
        return "No previous same-host scan is available for comparison."

    if context.trend == "SCORING_VERSION_CHANGED":
        transition = ""
        if context.previous_scoring_version and context.current_scoring_version:
            transition = (
                f" from v{context.previous_scoring_version} to "
                f"v{context.current_scoring_version}"
            )
        summary = (
            f"The scoring methodology changed{transition} between assessments, "
            "so the numeric "
            "score difference is not classified as an improvement or regression."
        )
    else:
        summary = (
        f"The score changed by {context.score_change:+d} points since the previous "
        f"scan, so the short-term trend is {context.trend}."
        )
    if context.new_findings:
        new_titles = "; ".join(
            finding.title for finding in context.new_findings[:3]
        )
        summary += f" New: {new_titles}."
    if context.resolved_findings:
        resolved_titles = "; ".join(
            finding.title for finding in context.resolved_findings[:3]
        )
        summary += f" Resolved: {resolved_titles}."
    if context.uncertain_findings:
        uncertain_titles = "; ".join(
            finding.title for finding in context.uncertain_findings[:3]
        )
        summary += (
            " Disappearance uncertain because coverage was incomplete: "
            f"{uncertain_titles}."
        )
    return summary


def _recurring_summary(context: AdvisorContext) -> str:
    recurring = [finding for finding in context.findings if finding.is_recurring]
    if not recurring:
        return "No current finding has recurred across multiple scans."

    recurring.sort(key=finding_priority_key, reverse=True)
    descriptions = []
    for items in _groups(recurring)[:3]:
        representative = max(items, key=finding_priority_key)
        suffix = (
            f"; {len(items)} related listeners" if len(items) > 1 else ""
        )
        descriptions.append(
            f"{representative.title} ({max(item.occurrences for item in items)} scans{suffix})"
        )
    return "Recurring problems: " + "; ".join(descriptions) + "."


def build_deterministic_advisory(context: AdvisorContext) -> AdvisoryReport:
    """Create a complete advisory using deterministic source records only."""

    actions = _build_actions(context.findings)
    important = sorted(
        (
            finding
            for finding in context.findings
            if finding.kind != FindingKind.OBSERVATION
        ),
        key=finding_priority_key,
        reverse=True,
    )
    presentation_groups = _presentation_groups(important)
    finding_warnings = tuple(
        finding.title
        for finding in context.findings
        if finding.assessment_state == AssessmentState.INCOMPLETE
    )
    coverage_warnings = tuple(dict.fromkeys((
        *context.coverage_limitations,
        *finding_warnings,
    )))
    next_steps = tuple(action.action for action in actions[:3])

    if not next_steps:
        next_steps = (
            "Continue regular scans and review informational observations for change.",
        )

    return AdvisoryReport(
        mode="deterministic",
        posture_summary=_posture_summary(context),
        important_finding_ids=tuple(
            finding.finding_id for finding in important[:5]
        ),
        actions=actions,
        changes_summary=_changes_summary(context),
        recurring_summary=_recurring_summary(context),
        next_steps=next_steps,
        coverage_warnings=coverage_warnings,
        finding_groups=presentation_groups,
    )
