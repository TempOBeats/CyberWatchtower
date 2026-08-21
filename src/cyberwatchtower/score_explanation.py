"""Read-only presentation projection for canonical stored score breakdowns."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .scoring_contracts import ScoringCategory, ScoringVersion
from .scoring_report import (
    ScoringReportValidationError,
    validate_serialized_security_score,
)


_CATEGORY_LABELS = {
    ScoringCategory.NETWORK_EXPOSURE.value: "Network exposure",
    ScoringCategory.FIREWALL_POSTURE.value: "Firewall posture",
    ScoringCategory.OTHER_DETERMINISTIC_RISK.value: "Other deterministic risk",
}


@dataclass(frozen=True)
class ScoreContributorExplanation:
    group_id: str
    category: str
    finding_ids: tuple[str, ...]
    severity: str
    assessment_state: str
    base_penalty: int
    raw_penalty: int
    applied_penalty: int
    basis_code: str


@dataclass(frozen=True)
class ScoreCategoryExplanation:
    category: str
    label: str
    applied_penalty: int
    saturated: bool
    contributor_group_ids: tuple[str, ...]
    finding_ids: tuple[str, ...]


@dataclass(frozen=True)
class ScoreGuardrailExplanation:
    highest_confirmed_severity: str | None
    category_applied_penalty_total: int
    additional_guardrail_penalty: int
    effective_penalty_total: int
    effective_score_ceiling: int | None
    applied: bool


@dataclass(frozen=True)
class ScoreExplanation:
    scoring_version: str
    final_score: int
    risk_level: str
    total_effective_penalty: int | None
    categories: tuple[ScoreCategoryExplanation, ...]
    contributors: tuple[ScoreContributorExplanation, ...]
    guardrail: ScoreGuardrailExplanation | None

    @property
    def has_breakdown(self) -> bool:
        return self.scoring_version == ScoringVersion.V2.value


def build_score_explanation(
    score: object,
    *,
    report_finding_ids: set[str],
    schema_version: str | None = None,
) -> ScoreExplanation | None:
    """Validate and project stored score data without recalculating penalties."""

    if not isinstance(score, Mapping):
        return None
    version = score.get("scoring_version", ScoringVersion.V1.value)
    validation_schema = schema_version or (
        "1.4" if "scoring_version" in score else "1.3"
    )
    try:
        normalized = validate_serialized_security_score(
            score, validation_schema, report_finding_ids
        )
    except (ScoringReportValidationError, TypeError, ValueError):
        return None

    if version != ScoringVersion.V2.value:
        return ScoreExplanation(
            scoring_version=ScoringVersion.V1.value,
            final_score=int(normalized["score"]),
            risk_level=str(normalized["risk_level"]),
            total_effective_penalty=None,
            categories=(),
            contributors=(),
            guardrail=None,
        )

    breakdown = normalized["breakdown"]
    raw_contributors = tuple(breakdown["contributors"])
    contributors = tuple(
        ScoreContributorExplanation(
            group_id=str(item["group_id"]),
            category=str(item["category"]),
            finding_ids=tuple(item["finding_ids"]),
            severity=str(item["severity"]),
            assessment_state=str(item["assessment_state"]),
            base_penalty=int(item["base_penalty"]),
            raw_penalty=int(item["raw_penalty"]),
            applied_penalty=int(item["applied_penalty"]),
            basis_code=str(item["basis_code"]),
        )
        for item in raw_contributors
    )
    categories = tuple(
        ScoreCategoryExplanation(
            category=str(item["category"]),
            label=_CATEGORY_LABELS[str(item["category"])],
            applied_penalty=int(item["applied_penalty"]),
            saturated=bool(item["saturated"]),
            contributor_group_ids=tuple(
                contributor.group_id for contributor in contributors
                if contributor.category == item["category"]
            ),
            finding_ids=tuple(
                finding_id
                for contributor in contributors
                if contributor.category == item["category"]
                for finding_id in contributor.finding_ids
            ),
        )
        for item in breakdown["categories"]
    )
    raw_guardrail = breakdown["guardrail"]
    guardrail = ScoreGuardrailExplanation(
        highest_confirmed_severity=raw_guardrail["highest_confirmed_severity"],
        category_applied_penalty_total=int(
            raw_guardrail["category_applied_penalty_total"]
        ),
        additional_guardrail_penalty=int(
            raw_guardrail["additional_guardrail_penalty"]
        ),
        effective_penalty_total=int(raw_guardrail["effective_penalty_total"]),
        effective_score_ceiling=raw_guardrail["effective_score_ceiling"],
        applied=bool(raw_guardrail["applied"]),
    )
    return ScoreExplanation(
        scoring_version=ScoringVersion.V2.value,
        final_score=int(normalized["score"]),
        risk_level=str(normalized["risk_level"]),
        total_effective_penalty=int(breakdown["total_effective_penalty"]),
        categories=categories,
        contributors=contributors,
        guardrail=guardrail,
    )


def render_score_explanation(
    explanation: ScoreExplanation,
    assessment_assurance: str,
    *,
    detailed: bool = False,
) -> tuple[str, ...]:
    """Render only values already present in the validated score projection."""

    lines = (
        f"Security Score: {explanation.final_score}/100 — {explanation.risk_level}",
        f"Scoring Method: v{explanation.scoring_version}",
        f"Assessment Assurance: {assessment_assurance}",
    )
    if not explanation.has_breakdown:
        return (*lines, "Detailed score contributors are unavailable for Scoring v1.")

    lines = (*lines, f"Effective deduction: {explanation.total_effective_penalty}")
    lines = (*lines, "Score contributors:")
    for category in explanation.categories:
        lines = (*lines, f"- {category.label}: {category.applied_penalty} points")
        if category.saturated:
            lines = (*lines, "  - category saturated")
        lines = (*lines, (
            f"  - {len(category.finding_ids)} atomic finding(s) represented by "
            f"{len(category.contributor_group_ids)} semantic scoring group(s)"
        ))
    if detailed:
        lines = (*lines, "Detailed scoring groups:")
        for contributor in explanation.contributors:
            member_ids = ", ".join(contributor.finding_ids)
            lines = (*lines, (
                f"- Scoring group {contributor.group_id}: base "
                f"{contributor.base_penalty}; raw {contributor.raw_penalty}; "
                f"applied {contributor.applied_penalty}; "
                f"{contributor.severity}/{contributor.assessment_state}; "
                f"basis {contributor.basis_code}; findings {member_ids}"
            ))
    guardrail = explanation.guardrail
    if guardrail is not None:
        highest = guardrail.highest_confirmed_severity or "NONE"
        lines = (*lines, f"Highest confirmed severity: {highest}")
        if guardrail.applied:
            lines = (*lines, (
                "Confirmed-risk guardrail adjustment: "
                f"{guardrail.additional_guardrail_penalty}"
            ))
            if detailed:
                lines = (*lines, (
                    "Guardrail detail: category penalties "
                    f"{guardrail.category_applied_penalty_total}; effective "
                    f"deduction {guardrail.effective_penalty_total}; score ceiling "
                    f"{guardrail.effective_score_ceiling}"
                ))
    return lines
