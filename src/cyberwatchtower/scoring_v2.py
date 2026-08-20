"""Deterministic Scoring v2 engine, isolated from the production v1 path."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import replace
from types import MappingProxyType
from typing import Iterable

from .models import AssessmentState, FindingKind, Severity
from .scoring_contracts import (
    NetworkScoringIdentity,
    ScoringBasisCode,
    ScoringBreakdown,
    ScoringCategory,
    ScoringCategoryBreakdown,
    ScoringFinding,
    ScoringResult,
    ScoringRiskGroup,
    ScoringVersion,
)


V1_CONFIRMED_WEIGHTS = MappingProxyType({
    Severity.CRITICAL: 30,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 5,
    Severity.INFO: 0,
})

V2_POTENTIAL_WEIGHTS = MappingProxyType({
    Severity.CRITICAL: 12,
    Severity.HIGH: 8,
    Severity.MEDIUM: 4,
    Severity.LOW: 2,
    Severity.INFO: 0,
})

CATEGORY_POTENTIAL_CAPS = MappingProxyType({
    ScoringCategory.NETWORK_EXPOSURE: 18,
    ScoringCategory.FIREWALL_POSTURE: 12,
    ScoringCategory.OTHER_DETERMINISTIC_RISK: 25,
})

CATEGORY_TOTAL_CAPS = MappingProxyType({
    ScoringCategory.NETWORK_EXPOSURE: 40,
    ScoringCategory.FIREWALL_POSTURE: 40,
    ScoringCategory.OTHER_DETERMINISTIC_RISK: 70,
})

CONFIRMED_SCORE_CEILINGS = MappingProxyType({
    Severity.CRITICAL: 49,
    Severity.HIGH: 74,
    Severity.MEDIUM: 89,
    Severity.LOW: 94,
})

# Thresholds are deliberately part of the v2 contract even though they match v1.
V2_RISK_THRESHOLDS = (
    (90, "LOW"),
    (75, "MODERATE"),
    (50, "HIGH"),
    (0, "CRITICAL"),
)

_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
_COUNT_ORDER = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

_DIMINISHING_NUMERATORS = (8, 4, 2)
_FIXED_POINT_DENOMINATOR = 8
_SUBSEQUENT_NUMERATOR = 1
_FAMILY_CAP_NUMERATOR = 14


def _risk_level(score: int) -> str:
    for threshold, level in V2_RISK_THRESHOLDS:
        if score >= threshold:
            return level
    raise AssertionError("The closed risk thresholds did not cover the score.")


def _eligible(finding: ScoringFinding) -> bool:
    return bool(
        finding.kind == FindingKind.RISK
        and finding.assessment_state in {
            AssessmentState.CONFIRMED,
            AssessmentState.POTENTIAL,
        }
        and finding.severity != Severity.INFO
    )


def _atomic_penalty(finding: ScoringFinding) -> int:
    if not _eligible(finding):
        return 0
    if finding.assessment_state == AssessmentState.CONFIRMED:
        return V1_CONFIRMED_WEIGHTS[finding.severity]
    return V2_POTENTIAL_WEIGHTS[finding.severity]


def _basis(finding: ScoringFinding) -> ScoringBasisCode:
    potential = finding.assessment_state == AssessmentState.POTENTIAL
    if finding.category == ScoringCategory.NETWORK_EXPOSURE:
        return (
            ScoringBasisCode.POTENTIAL_LISTENER_EXPOSURE
            if potential
            else ScoringBasisCode.CONFIRMED_LISTENER_EXPOSURE
        )
    if finding.category == ScoringCategory.FIREWALL_POSTURE:
        return (
            ScoringBasisCode.POTENTIAL_FIREWALL_POLICY_RISK
            if potential
            else ScoringBasisCode.CONFIRMED_FIREWALL_POLICY_RISK
        )
    return (
        ScoringBasisCode.POTENTIAL_DETERMINISTIC_RISK
        if potential
        else ScoringBasisCode.CONFIRMED_DETERMINISTIC_RISK
    )


def _normalized_subject(identity: NetworkScoringIdentity) -> str:
    if identity.application_identity:
        return "application:" + identity.application_identity.casefold()
    if identity.process_basename:
        return "process:" + identity.process_basename.casefold()
    return f"unknown:{identity.protocol}:{identity.port}"


def _network_family_key(finding: ScoringFinding) -> tuple[str, ...]:
    identity = finding.network_identity
    if identity is None:
        raise AssertionError("Validated network scoring input lost its identity.")
    return (
        finding.category.value,
        finding.source.casefold(),
        _normalized_subject(identity),
        identity.protocol,
        identity.bind_exposure.value,
        identity.reachability_state.value,
        finding.severity.value,
        finding.assessment_state.value,
    )


def _semantic_endpoint_key(finding: ScoringFinding) -> tuple[str, ...]:
    identity = finding.network_identity
    if identity is None:
        raise AssertionError("Validated network scoring input lost its identity.")
    return (*_network_family_key(finding), str(identity.port))


def _stable_group_id(components: tuple[str, ...]) -> str:
    digest = hashlib.sha256("\0".join(components).encode("utf-8")).hexdigest()
    return "score-group:" + digest


def _weighted_penalty(base: int, index: int) -> int:
    """Apply frozen floor rounding to fixed eighth-point multipliers."""

    numerator = (
        _DIMINISHING_NUMERATORS[index]
        if index < len(_DIMINISHING_NUMERATORS)
        else _SUBSEQUENT_NUMERATOR
    )
    return base * numerator // _FIXED_POINT_DENOMINATOR


def _network_groups(findings: tuple[ScoringFinding, ...]) -> list[ScoringRiskGroup]:
    families: dict[tuple[str, ...], list[ScoringFinding]] = defaultdict(list)
    for finding in findings:
        families[_network_family_key(finding)].append(finding)

    result = []
    for family_key in sorted(families):
        members = families[family_key]
        endpoints: dict[tuple[str, ...], list[ScoringFinding]] = defaultdict(list)
        for finding in members:
            endpoints[_semantic_endpoint_key(finding)].append(finding)
        endpoint_penalties = sorted(
            (_atomic_penalty(items[0]) for items in endpoints.values()),
            reverse=True,
        )
        atomic_penalties = tuple(sorted(
            (_atomic_penalty(item) for item in members), reverse=True
        ))
        base = max(endpoint_penalties, default=0)
        raw = sum(
            _weighted_penalty(penalty, index)
            for index, penalty in enumerate(endpoint_penalties)
        )
        family_cap = base * _FAMILY_CAP_NUMERATOR // _FIXED_POINT_DENOMINATOR
        applied = min(raw, family_cap)
        representative = members[0]
        result.append(ScoringRiskGroup(
            group_id=_stable_group_id(family_key),
            category=ScoringCategory.NETWORK_EXPOSURE,
            finding_ids=tuple(sorted(item.finding_id for item in members)),
            severity=representative.severity,
            assessment_state=representative.assessment_state,
            atomic_penalties=atomic_penalties,
            base_penalty=base,
            raw_penalty=raw,
            applied_penalty=applied,
            basis_code=_basis(representative),
        ))
    return result


def _atomic_groups(findings: tuple[ScoringFinding, ...]) -> list[ScoringRiskGroup]:
    result = []
    for finding in sorted(findings, key=lambda item: item.finding_id):
        penalty = _atomic_penalty(finding)
        result.append(ScoringRiskGroup(
            group_id=_stable_group_id((
                finding.category.value,
                finding.source.casefold(),
                finding.finding_id,
            )),
            category=finding.category,
            finding_ids=(finding.finding_id,),
            severity=finding.severity,
            assessment_state=finding.assessment_state,
            atomic_penalties=(penalty,),
            base_penalty=penalty,
            raw_penalty=penalty,
            applied_penalty=penalty,
            basis_code=_basis(finding),
        ))
    return result


def _allocation_key(group: ScoringRiskGroup) -> tuple[int, int, int, str]:
    return (
        int(group.assessment_state == AssessmentState.CONFIRMED),
        _SEVERITY_ORDER[group.severity],
        group.raw_penalty,
        group.group_id,
    )


def _cap_groups(
    groups: tuple[ScoringRiskGroup, ...],
    category: ScoringCategory,
) -> tuple[tuple[ScoringRiskGroup, ...], ScoringCategoryBreakdown]:
    raw = sum(group.raw_penalty for group in groups)
    potential_remaining = CATEGORY_POTENTIAL_CAPS[category]
    category_remaining = CATEGORY_TOTAL_CAPS[category]
    applied_by_id = {}

    for group in sorted(groups, key=_allocation_key, reverse=True):
        available = group.applied_penalty
        if group.assessment_state == AssessmentState.POTENTIAL:
            available = min(available, potential_remaining)
            potential_remaining -= available
        applied = min(available, category_remaining)
        category_remaining -= applied
        applied_by_id[group.group_id] = applied

    capped = tuple(sorted(
        (
            replace(group, applied_penalty=applied_by_id[group.group_id])
            for group in groups
        ),
        key=lambda item: item.group_id,
    ))
    applied_total = sum(group.applied_penalty for group in capped)
    return capped, ScoringCategoryBreakdown(
        category=category,
        raw_penalty=raw,
        applied_penalty=applied_total,
        saturated=applied_total < raw,
    )


def calculate_security_score_v2(
    findings: Iterable[ScoringFinding],
) -> ScoringResult:
    """Calculate an isolated deterministic v2 score from immutable snapshots."""

    snapshots = tuple(findings)
    if any(not isinstance(item, ScoringFinding) for item in snapshots):
        raise TypeError("Scoring v2 accepts only ScoringFinding values.")
    finding_ids = tuple(item.finding_id for item in snapshots)
    if len(set(finding_ids)) != len(finding_ids):
        raise ValueError("Scoring input finding IDs must be unique.")

    eligible = tuple(item for item in snapshots if _eligible(item))
    network = tuple(
        item for item in eligible
        if item.category == ScoringCategory.NETWORK_EXPOSURE
    )
    other = tuple(
        item for item in eligible
        if item.category != ScoringCategory.NETWORK_EXPOSURE
    )
    groups = tuple(_network_groups(network) + _atomic_groups(other))

    contributors = []
    categories = []
    for category in ScoringCategory:
        category_groups = tuple(
            group for group in groups if group.category == category
        )
        capped, breakdown = _cap_groups(category_groups, category)
        contributors.extend(capped)
        categories.append(breakdown)

    category_penalty = sum(item.applied_penalty for item in categories)
    score = max(0, min(100, 100 - category_penalty))
    confirmed_groups = tuple(
        group for group in contributors
        if group.assessment_state == AssessmentState.CONFIRMED
    )
    highest_confirmed = max(
        (group.severity for group in confirmed_groups),
        key=lambda severity: _SEVERITY_ORDER[severity],
        default=None,
    )
    if highest_confirmed in CONFIRMED_SCORE_CEILINGS:
        score = min(score, CONFIRMED_SCORE_CEILINGS[highest_confirmed])
    confirmed_critical_count = sum(
        group.severity == Severity.CRITICAL for group in confirmed_groups
    )
    if confirmed_critical_count >= 2:
        score = min(score, 20)

    # The total records the effective deduction after semantic guardrails.
    total_penalty = 100 - score

    counts = tuple(
        (severity.value, sum(item.severity == severity for item in snapshots))
        for severity in _COUNT_ORDER
    )
    breakdown = ScoringBreakdown(
        scoring_version=ScoringVersion.V2,
        total_penalty=total_penalty,
        categories=tuple(categories),
        contributors=tuple(sorted(contributors, key=lambda item: item.group_id)),
        highest_confirmed_severity=highest_confirmed,
    )
    return ScoringResult(score, _risk_level(score), counts, breakdown)
