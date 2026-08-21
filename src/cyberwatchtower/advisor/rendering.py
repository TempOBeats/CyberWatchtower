from .models import AdvisoryReport, AdvisorContext
from cyberwatchtower.score_explanation import render_score_explanation


def render_advisory(advisory: AdvisoryReport, context: AdvisorContext) -> str:
    """Render trusted advisory records without provider-authored prose."""

    findings_by_id = {finding.finding_id: finding for finding in context.findings}
    lines = [
        "AI ADVISOR",
        "==========",
        "",
        "CURRENT SECURITY POSTURE",
        advisory.posture_summary,
    ]
    if context.score_explanation is not None:
        lines.extend((
            "",
            "SCORE EXPLANATION",
            *render_score_explanation(
                context.score_explanation, context.assessment_assurance
            ),
        ))
    lines.extend([
        "",
        "MOST IMPORTANT FINDINGS",
    ])

    if advisory.finding_groups:
        for group in advisory.finding_groups[:5]:
            finding = findings_by_id[group.finding_ids[0]]
            related = (
                f" ({len(group.finding_ids)} related listeners)"
                if len(group.finding_ids) > 1 else ""
            )
            lines.append(
                f"- [{finding.severity}/{finding.assessment_state.value}] "
                f"{finding.title}{related}"
            )
    else:
        lines.append("- No current risk or coverage-gap findings to prioritize.")

    lines.extend(["", "IMPROVEMENTS AND REGRESSIONS", advisory.changes_summary])
    lines.extend(["", "RECURRING PROBLEMS", advisory.recurring_summary])
    lines.extend(["", "PRIORITIZED REMEDIATION"])

    if advisory.actions:
        for action in advisory.actions:
            lines.extend(
                [
                    f"{action.priority}. {action.action}",
                    f"   Why it matters: {action.rationale}",
                ]
            )
    else:
        lines.append("- No current remediation action was derived from the findings.")

    lines.extend(["", "WHAT SHOULD I DO NEXT?"])
    for step_number, step in enumerate(advisory.next_steps, start=1):
        lines.append(f"{step_number}. {step}")

    if advisory.coverage_warnings:
        lines.extend(["", "ASSESSMENT LIMITATIONS"])
        for warning in advisory.coverage_warnings:
            lines.append(f"- {warning}")

    if advisory.provider_warning:
        lines.extend(["", f"Advisor notice: {advisory.provider_warning}"])

    return "\n".join(lines)
