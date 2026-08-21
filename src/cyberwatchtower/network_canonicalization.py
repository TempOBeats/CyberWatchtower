"""Fail-closed canonicalization of transient network finding instances."""

from __future__ import annotations

from dataclasses import dataclass, replace

from .models import Finding, MAX_RUNTIME_INSTANCE_COUNT
from .scoring_contracts import NetworkScoringIdentity
from .scoring_projection import canonical_finding_id


@dataclass(frozen=True, slots=True)
class NetworkFindingCandidate:
    finding: Finding
    scoring_identity: NetworkScoringIdentity
    runtime_pid: int | None

    def __post_init__(self) -> None:
        if not isinstance(self.finding, Finding):
            raise TypeError("network candidate requires a Finding.")
        if not isinstance(self.scoring_identity, NetworkScoringIdentity):
            raise TypeError("network candidate requires a scoring identity.")
        if self.runtime_pid is not None and (
            isinstance(self.runtime_pid, bool)
            or not isinstance(self.runtime_pid, int)
            or self.runtime_pid < 0
        ):
            raise ValueError("network candidate PID is invalid.")


def _durable_evidence(finding: Finding) -> tuple[str, ...]:
    return tuple(
        item for item in finding.evidence
        if not (
            isinstance(item, str)
            and item.partition(":")[0].strip().casefold() == "pid"
        )
    )


def _durable_semantics(candidate: NetworkFindingCandidate) -> tuple[object, ...]:
    finding = candidate.finding
    return (
        canonical_finding_id(finding),
        finding.source,
        finding.severity,
        finding.kind,
        finding.assessment_state,
        finding.title,
        finding.description,
        finding.technique_id,
        finding.recommendation,
        finding.confidence,
        _durable_evidence(finding),
        finding.network_context,
        finding.presentation_group_id,
        candidate.scoring_identity,
    )


def canonicalize_network_findings(
    candidates: tuple[NetworkFindingCandidate, ...],
) -> tuple[tuple[Finding, NetworkScoringIdentity], ...]:
    """Aggregate PID-distinct instances only when durable semantics are equal."""

    grouped: dict[str, list[NetworkFindingCandidate]] = {}
    order: list[str] = []
    for candidate in candidates:
        if not isinstance(candidate, NetworkFindingCandidate):
            raise TypeError("network canonicalization requires typed candidates.")
        finding_id = canonical_finding_id(candidate.finding)
        if finding_id not in grouped:
            grouped[finding_id] = []
            order.append(finding_id)
        grouped[finding_id].append(candidate)

    canonical = []
    for finding_id in order:
        members = grouped[finding_id]
        first = members[0]
        expected = _durable_semantics(first)
        if any(_durable_semantics(member) != expected for member in members[1:]):
            raise ValueError(
                "A stable network finding ID maps to conflicting durable semantics."
            )
        pids = tuple(member.runtime_pid for member in members)
        if len(members) > 1 and (
            any(pid is None for pid in pids) or len(set(pids)) != len(pids)
        ):
            raise ValueError(
                "Duplicate network findings are not distinct attributable instances."
            )
        count = sum(member.finding.runtime_instance_count for member in members)
        if count > MAX_RUNTIME_INSTANCE_COUNT:
            raise ValueError("Network finding multiplicity exceeds the supported bound.")
        finding = first.finding
        if count > 1:
            finding = replace(
                finding,
                evidence=list(_durable_evidence(finding)),
                runtime_instance_count=count,
            )
        canonical.append((finding, first.scoring_identity))
    return tuple(canonical)
