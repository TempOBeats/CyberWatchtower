from dataclasses import dataclass
from enum import Enum

from .models import AdvisoryReport, AdvisorContext


class QuestionIntent(str, Enum):
    WHY_DANGEROUS = "WHY_DANGEROUS"
    WHAT_CHANGED = "WHAT_CHANGED"
    FIX_FIRST = "FIX_FIRST"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class QuestionAnswer:
    intent: QuestionIntent
    answer: str
    finding_ids: tuple[str, ...] = ()
    action_ids: tuple[str, ...] = ()


def classify_question(question: str) -> QuestionIntent:
    normalized = " ".join(question.casefold().split())

    if "what changed" in normalized or "since the previous" in normalized:
        return QuestionIntent.WHAT_CHANGED
    if (
        "fix first" in normalized
        or "do first" in normalized
        or "should i fix" in normalized
    ):
        return QuestionIntent.FIX_FIRST
    if "why" in normalized and (
        "dangerous" in normalized
        or "matter" in normalized
        or "risk" in normalized
    ):
        return QuestionIntent.WHY_DANGEROUS
    return QuestionIntent.UNKNOWN


def _why_dangerous(
    context: AdvisorContext,
    advisory: AdvisoryReport,
    finding_id: str | None,
) -> QuestionAnswer:
    target_id = finding_id
    if target_id is None and advisory.important_finding_ids:
        target_id = advisory.important_finding_ids[0]

    findings_by_id = {finding.finding_id: finding for finding in context.findings}
    finding = findings_by_id.get(target_id)
    if finding is None:
        return QuestionAnswer(
            intent=QuestionIntent.WHY_DANGEROUS,
            answer=(
                "Select a current finding so CyberWatchtower can explain it from "
                "the available scan evidence."
            ),
        )

    action = next(
        (
            action
            for action in advisory.actions
            if finding.finding_id in action.finding_ids
        ),
        None,
    )
    if action is not None:
        answer = action.rationale
        action_ids = (action.action_id,)
    else:
        answer = finding.description or (
            "CyberWatchtower has no additional deterministic explanation for "
            "this informational observation."
        )
        action_ids = ()

    return QuestionAnswer(
        intent=QuestionIntent.WHY_DANGEROUS,
        answer=answer,
        finding_ids=(finding.finding_id,),
        action_ids=action_ids,
    )


def _what_changed(
    context: AdvisorContext,
    advisory: AdvisoryReport,
) -> QuestionAnswer:
    return QuestionAnswer(
        intent=QuestionIntent.WHAT_CHANGED,
        answer=advisory.changes_summary,
        finding_ids=tuple(
            finding.finding_id
            for finding in (*context.new_findings, *context.resolved_findings)
        ),
    )


def _fix_first(advisory: AdvisoryReport) -> QuestionAnswer:
    if not advisory.actions:
        return QuestionAnswer(
            intent=QuestionIntent.FIX_FIRST,
            answer=(
                "No current remediation action was derived from the deterministic "
                "findings. Continue regular scanning."
            ),
        )

    action = advisory.actions[0]
    return QuestionAnswer(
        intent=QuestionIntent.FIX_FIRST,
        answer=f"First, {action.action} {action.rationale}",
        finding_ids=action.finding_ids,
        action_ids=(action.action_id,),
    )


def answer_question(
    question: str,
    context: AdvisorContext,
    advisory: AdvisoryReport,
    finding_id: str | None = None,
) -> QuestionAnswer:
    """Answer supported questions from trusted deterministic records only."""

    intent = classify_question(question)
    if intent == QuestionIntent.WHY_DANGEROUS:
        return _why_dangerous(context, advisory, finding_id)
    if intent == QuestionIntent.WHAT_CHANGED:
        return _what_changed(context, advisory)
    if intent == QuestionIntent.FIX_FIRST:
        return _fix_first(advisory)
    return QuestionAnswer(
        intent=QuestionIntent.UNKNOWN,
        answer=(
            "CyberWatchtower cannot answer that question from the supported "
            "deterministic advisory data."
        ),
    )
