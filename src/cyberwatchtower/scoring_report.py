"""Closed JSON-facing contracts for versioned deterministic score records."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import unicodedata

from .models import AssessmentState, Severity
from .scoring_contracts import (
    MAX_SCORING_FINDING_ID_LENGTH,
    MAX_SCORING_TEXT_LENGTH,
    ScoringBasisCode,
    ScoringCategory,
    ScoringResult,
    ScoringVersion,
)


MAX_SCORING_CONTRIBUTORS = 4_096
MAX_SCORING_GROUP_MEMBERS = 4_096
MAX_ATOMIC_PENALTIES = 4_096
_SCORE_KEYS = frozenset({
    "scoring_version", "score", "risk_level", "counts", "breakdown",
})
_BREAKDOWN_KEYS = frozenset({
    "total_effective_penalty", "categories", "contributors", "guardrail",
})
_CATEGORY_KEYS = frozenset({
    "category", "raw_penalty", "applied_penalty", "saturated",
})
_CONTRIBUTOR_KEYS = frozenset({
    "group_id", "category", "finding_ids", "severity", "assessment_state",
    "atomic_penalties", "base_penalty", "raw_penalty", "applied_penalty",
    "basis_code",
})
_GUARDRAIL_KEYS = frozenset({
    "highest_confirmed_severity", "category_applied_penalty_total",
    "effective_penalty_total", "additional_guardrail_penalty",
    "effective_score_ceiling", "applied",
})


class ScoringReportValidationError(ValueError):
    def __init__(self, code: str, message: str, field: str | None = None):
        super().__init__(message)
        self.code = code
        self.field = field


def _mapping(value: object, field: str) -> Mapping:
    if not isinstance(value, Mapping):
        raise ScoringReportValidationError(
            "INVALID_SCORING_TYPE", f"{field} must be an object.", field
        )
    return value


def _exact_keys(value: Mapping, expected: frozenset[str], field: str) -> None:
    if set(value) != expected:
        raise ScoringReportValidationError(
            "INVALID_SCORING_FIELDS",
            f"{field} contains missing or unsupported fields.",
            field,
        )


def _integer(
    value: object,
    field: str,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ScoringReportValidationError(
            "INVALID_SCORING_INTEGER", f"{field} must be an integer.", field
        )
    if value < minimum or (maximum is not None and value > maximum):
        raise ScoringReportValidationError(
            "SCORING_VALUE_OUT_OF_RANGE", f"{field} is out of range.", field
        )
    return value


def _text(value: object, field: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise ScoringReportValidationError(
            "INVALID_SCORING_TEXT", f"{field} must be text.", field
        )
    text = value.strip()
    if (
        not text
        or len(text) > maximum
        or any(unicodedata.category(char) in {"Cc", "Cf"} for char in text)
    ):
        raise ScoringReportValidationError(
            "INVALID_SCORING_TEXT", f"{field} must be bounded safe text.", field
        )
    return text


def scoring_version_from_score(score: object) -> ScoringVersion:
    score_data = _mapping(score, "security_score")
    raw_version = score_data.get("scoring_version", ScoringVersion.V1.value)
    try:
        return ScoringVersion(raw_version)
    except (TypeError, ValueError) as exc:
        raise ScoringReportValidationError(
            "INVALID_SCORING_VERSION",
            "security_score.scoring_version is not supported.",
            "security_score.scoring_version",
        ) from exc


def scoring_version_from_report(report: Mapping) -> ScoringVersion:
    return scoring_version_from_score(report.get("security_score"))


def _guardrail_mapping(result: ScoringResult) -> dict[str, object]:
    category_total = sum(
        item.applied_penalty for item in result.breakdown.categories
    )
    additional = result.breakdown.total_penalty - category_total
    return {
        "highest_confirmed_severity": (
            result.breakdown.highest_confirmed_severity.value
            if result.breakdown.highest_confirmed_severity is not None
            else None
        ),
        "category_applied_penalty_total": category_total,
        "effective_penalty_total": result.breakdown.total_penalty,
        "additional_guardrail_penalty": additional,
        "effective_score_ceiling": result.score if additional else None,
        "applied": bool(additional),
    }


def serialize_scoring_result(
    result: ScoringResult,
    report_finding_ids: set[str],
) -> dict[str, object]:
    """Serialize an immutable v2 result without host or evidence material."""

    if not isinstance(result, ScoringResult):
        raise TypeError("result must be a ScoringResult.")
    contributor_ids = {
        finding_id
        for group in result.breakdown.contributors
        for finding_id in group.finding_ids
    }
    if not contributor_ids.issubset(report_finding_ids):
        raise ScoringReportValidationError(
            "UNKNOWN_SCORING_FINDING",
            "A scoring contributor references a finding absent from the report.",
            "security_score.breakdown.contributors",
        )
    score = {
        "scoring_version": ScoringVersion.V2.value,
        "score": result.score,
        "risk_level": result.risk_level,
        "counts": dict(result.counts),
        "breakdown": {
            "total_effective_penalty": result.breakdown.total_penalty,
            "categories": [
                {
                    "category": item.category.value,
                    "raw_penalty": item.raw_penalty,
                    "applied_penalty": item.applied_penalty,
                    "saturated": item.saturated,
                }
                for item in result.breakdown.categories
            ],
            "contributors": [
                {
                    "group_id": group.group_id,
                    "category": group.category.value,
                    "finding_ids": list(group.finding_ids),
                    "severity": group.severity.value,
                    "assessment_state": group.assessment_state.value,
                    "atomic_penalties": list(group.atomic_penalties),
                    "base_penalty": group.base_penalty,
                    "raw_penalty": group.raw_penalty,
                    "applied_penalty": group.applied_penalty,
                    "basis_code": group.basis_code.value,
                }
                for group in result.breakdown.contributors
            ],
            "guardrail": _guardrail_mapping(result),
        },
    }
    validate_serialized_security_score(score, "1.4", report_finding_ids)
    return score


def serialize_security_score(
    score: object,
    report_finding_ids: set[str],
) -> dict[str, object]:
    """Serialize current v1 mappings or an explicitly supplied v2 result."""

    if isinstance(score, ScoringResult):
        return serialize_scoring_result(score, report_finding_ids)
    score_data = dict(_mapping(score, "security_score"))
    score_data.setdefault("scoring_version", ScoringVersion.V1.value)
    validate_serialized_security_score(score_data, "1.4", report_finding_ids)
    return score_data


def _sequence(value: object, field: str, maximum: int) -> Sequence:
    if (
        not isinstance(value, (list, tuple))
        or isinstance(value, (str, bytes))
        or len(value) > maximum
    ):
        raise ScoringReportValidationError(
            "INVALID_SCORING_SEQUENCE", f"{field} must be a bounded list.", field
        )
    return value


def _validate_categories(raw: object) -> tuple[dict[str, object], ...]:
    categories = _sequence(raw, "security_score.breakdown.categories", 3)
    if len(categories) != len(ScoringCategory):
        raise ScoringReportValidationError(
            "INVALID_SCORING_CATEGORIES",
            "Every scoring category must be represented exactly once.",
            "security_score.breakdown.categories",
        )
    normalized = []
    seen = set()
    for index, raw_category in enumerate(categories):
        field = f"security_score.breakdown.categories[{index}]"
        category = _mapping(raw_category, field)
        _exact_keys(category, _CATEGORY_KEYS, field)
        try:
            category_name = ScoringCategory(category.get("category"))
        except (TypeError, ValueError) as exc:
            raise ScoringReportValidationError(
                "INVALID_SCORING_CATEGORY", "Unknown scoring category.", field
            ) from exc
        if category_name in seen:
            raise ScoringReportValidationError(
                "DUPLICATE_SCORING_CATEGORY", "Duplicate scoring category.", field
            )
        seen.add(category_name)
        raw_penalty = _integer(category.get("raw_penalty"), f"{field}.raw_penalty")
        applied = _integer(
            category.get("applied_penalty"), f"{field}.applied_penalty"
        )
        if applied > raw_penalty or not isinstance(category.get("saturated"), bool):
            raise ScoringReportValidationError(
                "INVALID_SCORING_CATEGORY", "Invalid category penalty state.", field
            )
        normalized.append({
            "category": category_name.value,
            "raw_penalty": raw_penalty,
            "applied_penalty": applied,
            "saturated": category["saturated"],
        })
    if tuple(item["category"] for item in normalized) != tuple(
        item.value for item in ScoringCategory
    ):
        raise ScoringReportValidationError(
            "INVALID_SCORING_CATEGORY_ORDER",
            "Scoring categories must use the closed deterministic order.",
            "security_score.breakdown.categories",
        )
    return tuple(normalized)


def _expected_basis(category: ScoringCategory, state: AssessmentState) -> ScoringBasisCode:
    expected = {
        (ScoringCategory.NETWORK_EXPOSURE, AssessmentState.POTENTIAL):
            ScoringBasisCode.POTENTIAL_LISTENER_EXPOSURE,
        (ScoringCategory.NETWORK_EXPOSURE, AssessmentState.CONFIRMED):
            ScoringBasisCode.CONFIRMED_LISTENER_EXPOSURE,
        (ScoringCategory.FIREWALL_POSTURE, AssessmentState.POTENTIAL):
            ScoringBasisCode.POTENTIAL_FIREWALL_POLICY_RISK,
        (ScoringCategory.FIREWALL_POSTURE, AssessmentState.CONFIRMED):
            ScoringBasisCode.CONFIRMED_FIREWALL_POLICY_RISK,
        (ScoringCategory.OTHER_DETERMINISTIC_RISK, AssessmentState.POTENTIAL):
            ScoringBasisCode.POTENTIAL_DETERMINISTIC_RISK,
        (ScoringCategory.OTHER_DETERMINISTIC_RISK, AssessmentState.CONFIRMED):
            ScoringBasisCode.CONFIRMED_DETERMINISTIC_RISK,
    }
    return expected[(category, state)]


def _validate_contributors(
    raw: object,
    report_finding_ids: set[str],
) -> tuple[dict[str, object], ...]:
    contributors = _sequence(
        raw, "security_score.breakdown.contributors", MAX_SCORING_CONTRIBUTORS
    )
    normalized = []
    group_ids = set()
    globally_referenced = set()
    for index, raw_contributor in enumerate(contributors):
        field = f"security_score.breakdown.contributors[{index}]"
        contributor = _mapping(raw_contributor, field)
        _exact_keys(contributor, _CONTRIBUTOR_KEYS, field)
        group_id = _text(
            contributor.get("group_id"), f"{field}.group_id",
            MAX_SCORING_TEXT_LENGTH,
        )
        if group_id in group_ids:
            raise ScoringReportValidationError(
                "DUPLICATE_SCORING_GROUP", "Duplicate scoring group ID.", field
            )
        group_ids.add(group_id)
        try:
            category = ScoringCategory(contributor.get("category"))
            severity = Severity(contributor.get("severity"))
            state = AssessmentState(contributor.get("assessment_state"))
            basis = ScoringBasisCode(contributor.get("basis_code"))
        except (TypeError, ValueError) as exc:
            raise ScoringReportValidationError(
                "INVALID_SCORING_CONTRIBUTOR",
                "Contributor contains an unknown closed value.", field,
            ) from exc
        if state not in {AssessmentState.CONFIRMED, AssessmentState.POTENTIAL}:
            raise ScoringReportValidationError(
                "INVALID_SCORING_STATE", "Contributor state is not scoreable.", field
            )
        if basis != _expected_basis(category, state):
            raise ScoringReportValidationError(
                "INVALID_SCORING_BASIS", "Contributor basis is incompatible.", field
            )
        raw_ids = _sequence(
            contributor.get("finding_ids"), f"{field}.finding_ids",
            MAX_SCORING_GROUP_MEMBERS,
        )
        finding_ids = tuple(
            _text(item, f"{field}.finding_ids", MAX_SCORING_FINDING_ID_LENGTH)
            for item in raw_ids
        )
        if (
            not finding_ids
            or len(set(finding_ids)) != len(finding_ids)
            or tuple(sorted(finding_ids)) != finding_ids
            or globally_referenced.intersection(finding_ids)
            or not set(finding_ids).issubset(report_finding_ids)
        ):
            raise ScoringReportValidationError(
                "INVALID_SCORING_FINDING_REFERENCE",
                "Contributor finding references are invalid or duplicated.", field,
            )
        globally_referenced.update(finding_ids)
        atomic_values = _sequence(
            contributor.get("atomic_penalties"), f"{field}.atomic_penalties",
            MAX_ATOMIC_PENALTIES,
        )
        atomic = tuple(
            _integer(item, f"{field}.atomic_penalties") for item in atomic_values
        )
        if not atomic:
            raise ScoringReportValidationError(
                "INVALID_ATOMIC_PENALTIES", "Atomic penalties cannot be empty.", field
            )
        base = _integer(contributor.get("base_penalty"), f"{field}.base_penalty")
        raw_penalty = _integer(contributor.get("raw_penalty"), f"{field}.raw_penalty")
        applied = _integer(
            contributor.get("applied_penalty"), f"{field}.applied_penalty"
        )
        if base != max(atomic) or applied > raw_penalty:
            raise ScoringReportValidationError(
                "INVALID_SCORING_PENALTY", "Contributor penalties are inconsistent.", field
            )
        normalized.append({
            "group_id": group_id,
            "category": category.value,
            "finding_ids": finding_ids,
            "severity": severity.value,
            "assessment_state": state.value,
            "atomic_penalties": atomic,
            "base_penalty": base,
            "raw_penalty": raw_penalty,
            "applied_penalty": applied,
            "basis_code": basis.value,
        })
    if tuple(item["group_id"] for item in normalized) != tuple(sorted(group_ids)):
        raise ScoringReportValidationError(
            "INVALID_SCORING_GROUP_ORDER",
            "Scoring groups must use deterministic group-ID ordering.",
            "security_score.breakdown.contributors",
        )
    return tuple(normalized)


def _validate_guardrail(
    raw: object,
    score: int,
    categories: tuple[dict[str, object], ...],
    contributors: tuple[dict[str, object], ...],
    total_effective_penalty: int,
) -> dict[str, object]:
    field = "security_score.breakdown.guardrail"
    guardrail = _mapping(raw, field)
    _exact_keys(guardrail, _GUARDRAIL_KEYS, field)
    highest_raw = guardrail.get("highest_confirmed_severity")
    if highest_raw is None:
        highest = None
    else:
        try:
            highest = Severity(highest_raw)
        except (TypeError, ValueError) as exc:
            raise ScoringReportValidationError(
                "INVALID_SCORING_GUARDRAIL", "Unknown guardrail severity.", field
            ) from exc
    severity_order = {
        Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
        Severity.HIGH: 3, Severity.CRITICAL: 4,
    }
    expected_highest = max(
        (
            Severity(item["severity"])
            for item in contributors
            if item["assessment_state"] == AssessmentState.CONFIRMED.value
        ),
        key=lambda item: severity_order[item],
        default=None,
    )
    category_total = sum(int(item["applied_penalty"]) for item in categories)
    recorded_category_total = _integer(
        guardrail.get("category_applied_penalty_total"),
        f"{field}.category_applied_penalty_total",
    )
    recorded_effective = _integer(
        guardrail.get("effective_penalty_total"),
        f"{field}.effective_penalty_total", maximum=100,
    )
    additional = _integer(
        guardrail.get("additional_guardrail_penalty"),
        f"{field}.additional_guardrail_penalty", maximum=100,
    )
    applied = guardrail.get("applied")
    ceiling = guardrail.get("effective_score_ceiling")
    if ceiling is not None:
        ceiling = _integer(ceiling, f"{field}.effective_score_ceiling", maximum=100)
    if (
        highest != expected_highest
        or recorded_category_total != category_total
        or recorded_effective != total_effective_penalty
        or additional != total_effective_penalty - category_total
        or not isinstance(applied, bool)
        or applied != bool(additional)
        or ceiling != (score if additional else None)
    ):
        raise ScoringReportValidationError(
            "INVALID_SCORING_GUARDRAIL",
            "Guardrail metadata does not explain the effective score deduction.",
            field,
        )
    return {
        "highest_confirmed_severity": highest.value if highest else None,
        "category_applied_penalty_total": category_total,
        "effective_penalty_total": recorded_effective,
        "additional_guardrail_penalty": additional,
        "effective_score_ceiling": ceiling,
        "applied": applied,
    }


def validate_serialized_security_score(
    raw_score: object,
    schema_version: str,
    report_finding_ids: set[str],
) -> dict[str, object]:
    """Validate and normalize a stored score without recalculating its value."""

    score_data = _mapping(raw_score, "security_score")
    version = scoring_version_from_score(score_data)
    if schema_version == "1.4" and "scoring_version" not in score_data:
        raise ScoringReportValidationError(
            "MISSING_SCORING_VERSION",
            "Schema 1.4 requires an explicit scoring version.",
            "security_score.scoring_version",
        )
    if schema_version != "1.4" and version != ScoringVersion.V1:
        raise ScoringReportValidationError(
            "SCORING_VERSION_SCHEMA_MISMATCH",
            "Scoring v2 requires the schema 1.4 scoring contract.",
            "security_score.scoring_version",
        )
    expected_keys = (
        _SCORE_KEYS if version == ScoringVersion.V2
        else _SCORE_KEYS - {"breakdown"}
    )
    if schema_version == "1.4" or version == ScoringVersion.V2:
        _exact_keys(score_data, expected_keys, "security_score")
    score = _integer(score_data.get("score"), "security_score.score", maximum=100)
    risk_value = score_data.get("risk_level")
    if risk_value is None and schema_version == "1.0":
        risk_value = "UNKNOWN"
    risk_level = _text(
        risk_value, "security_score.risk_level", 32
    )
    counts_data = _mapping(score_data.get("counts", {}), "security_score.counts")
    allowed_severities = tuple(item.value for item in Severity)
    if schema_version == "1.4" and set(counts_data) - set(allowed_severities):
        raise ScoringReportValidationError(
            "INVALID_SCORING_COUNTS", "Unknown severity count.",
            "security_score.counts",
        )
    counts = {
        severity: _integer(
            counts_data.get(severity, 0), f"security_score.counts.{severity}"
        )
        for severity in allowed_severities
    }
    normalized: dict[str, object] = {
        "scoring_version": version.value,
        "score": score,
        "risk_level": risk_level,
        "counts": counts,
    }
    if version == ScoringVersion.V1:
        return normalized
    if risk_level not in {"LOW", "MODERATE", "HIGH", "CRITICAL"}:
        raise ScoringReportValidationError(
            "INVALID_SCORING_RISK_LEVEL",
            "Scoring v2 risk_level is outside the closed contract.",
            "security_score.risk_level",
        )

    breakdown = _mapping(score_data.get("breakdown"), "security_score.breakdown")
    _exact_keys(breakdown, _BREAKDOWN_KEYS, "security_score.breakdown")
    total = _integer(
        breakdown.get("total_effective_penalty"),
        "security_score.breakdown.total_effective_penalty", maximum=100,
    )
    if score + total != 100:
        raise ScoringReportValidationError(
            "INVALID_EFFECTIVE_PENALTY",
            "Stored score and effective penalty must total 100.",
            "security_score.breakdown.total_effective_penalty",
        )
    categories = _validate_categories(breakdown.get("categories"))
    contributors = _validate_contributors(
        breakdown.get("contributors"), report_finding_ids
    )
    for category in categories:
        matching = tuple(
            item for item in contributors if item["category"] == category["category"]
        )
        if (
            sum(int(item["raw_penalty"]) for item in matching)
            != category["raw_penalty"]
            or sum(int(item["applied_penalty"]) for item in matching)
            != category["applied_penalty"]
        ):
            raise ScoringReportValidationError(
                "INVALID_SCORING_CATEGORY_TOTAL",
                "Category totals do not match contributor penalties.",
                "security_score.breakdown.categories",
            )
    guardrail = _validate_guardrail(
        breakdown.get("guardrail"), score, categories, contributors, total
    )
    normalized["breakdown"] = {
        "total_effective_penalty": total,
        "categories": categories,
        "contributors": contributors,
        "guardrail": guardrail,
    }
    return normalized
