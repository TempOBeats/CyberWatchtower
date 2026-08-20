"""Immutable contracts for deterministic, versioned security scoring."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from .models import AssessmentState, FindingKind, Severity
from .platform.models import BindExposure
from .reachability import RemoteReachabilityState


MAX_SCORING_TEXT_LENGTH = 256
MAX_SCORING_FINDING_ID_LENGTH = 512
_SAFE_TEXT = re.compile(r"^[^\x00-\x1f\x7f-\x9f]+$")


class ScoringVersion(str, Enum):
    V1 = "1"
    V2 = "2"


class ScoringCategory(str, Enum):
    NETWORK_EXPOSURE = "NETWORK_EXPOSURE"
    FIREWALL_POSTURE = "FIREWALL_POSTURE"
    OTHER_DETERMINISTIC_RISK = "OTHER_DETERMINISTIC_RISK"


class ScoringBasisCode(str, Enum):
    POTENTIAL_LISTENER_EXPOSURE = "POTENTIAL_LISTENER_EXPOSURE"
    CONFIRMED_LISTENER_EXPOSURE = "CONFIRMED_LISTENER_EXPOSURE"
    POTENTIAL_FIREWALL_POLICY_RISK = "POTENTIAL_FIREWALL_POLICY_RISK"
    CONFIRMED_FIREWALL_POLICY_RISK = "CONFIRMED_FIREWALL_POLICY_RISK"
    POTENTIAL_DETERMINISTIC_RISK = "POTENTIAL_DETERMINISTIC_RISK"
    CONFIRMED_DETERMINISTIC_RISK = "CONFIRMED_DETERMINISTIC_RISK"


def _bounded_text(
    value: str,
    field: str,
    maximum: int = MAX_SCORING_TEXT_LENGTH,
) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string.")
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > maximum
        or _SAFE_TEXT.fullmatch(normalized) is None
    ):
        raise ValueError(f"{field} must be bounded non-control text.")
    return normalized


@dataclass(frozen=True, slots=True)
class NetworkScoringIdentity:
    """Structured network identity used only for scoring projection."""

    protocol: str
    port: int
    bind_exposure: BindExposure
    reachability_state: RemoteReachabilityState
    application_identity: str | None = None
    process_basename: str | None = None

    def __post_init__(self) -> None:
        protocol = _bounded_text(self.protocol, "protocol").casefold()
        if protocol not in {"tcp", "udp"}:
            raise ValueError("protocol must be tcp or udp.")
        if isinstance(self.port, bool) or not isinstance(self.port, int):
            raise TypeError("port must be an integer.")
        if not 0 <= self.port <= 65535:
            raise ValueError("port must be between 0 and 65535.")
        if not isinstance(self.bind_exposure, BindExposure):
            raise TypeError("bind_exposure must be a BindExposure.")
        if not isinstance(self.reachability_state, RemoteReachabilityState):
            raise TypeError(
                "reachability_state must be a RemoteReachabilityState."
            )
        application = (
            _bounded_text(self.application_identity, "application_identity")
            if self.application_identity is not None
            else None
        )
        process = (
            _bounded_text(self.process_basename, "process_basename")
            if self.process_basename is not None
            else None
        )
        object.__setattr__(self, "protocol", protocol)
        object.__setattr__(self, "application_identity", application)
        object.__setattr__(self, "process_basename", process)


@dataclass(frozen=True, slots=True)
class ScoringFinding:
    """Immutable authoritative-field snapshot supplied to Scoring v2."""

    finding_id: str
    severity: Severity
    kind: FindingKind
    assessment_state: AssessmentState
    source: str
    category: ScoringCategory
    network_identity: NetworkScoringIdentity | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "finding_id",
            _bounded_text(
                self.finding_id, "finding_id", MAX_SCORING_FINDING_ID_LENGTH
            ),
        )
        object.__setattr__(self, "source", _bounded_text(self.source, "source"))
        if not isinstance(self.severity, Severity):
            raise TypeError("severity must be a Severity.")
        if not isinstance(self.kind, FindingKind):
            raise TypeError("kind must be a FindingKind.")
        if not isinstance(self.assessment_state, AssessmentState):
            raise TypeError("assessment_state must be an AssessmentState.")
        if not isinstance(self.category, ScoringCategory):
            raise TypeError("category must be a ScoringCategory.")
        if (
            self.category == ScoringCategory.NETWORK_EXPOSURE
            and self.network_identity is None
        ):
            raise ValueError("Network scoring findings require network_identity.")
        if (
            self.category != ScoringCategory.NETWORK_EXPOSURE
            and self.network_identity is not None
        ):
            raise ValueError(
                "Only network exposure findings may have network_identity."
            )


@dataclass(frozen=True, slots=True)
class ScoringRiskGroup:
    group_id: str
    category: ScoringCategory
    finding_ids: tuple[str, ...]
    severity: Severity
    assessment_state: AssessmentState
    atomic_penalties: tuple[int, ...]
    base_penalty: int
    raw_penalty: int
    applied_penalty: int
    basis_code: ScoringBasisCode

    def __post_init__(self) -> None:
        _bounded_text(self.group_id, "group_id")
        if not isinstance(self.category, ScoringCategory):
            raise TypeError("category must be a ScoringCategory.")
        if not isinstance(self.severity, Severity):
            raise TypeError("severity must be a Severity.")
        if not isinstance(self.assessment_state, AssessmentState):
            raise TypeError("assessment_state must be an AssessmentState.")
        if not isinstance(self.basis_code, ScoringBasisCode):
            raise TypeError("basis_code must be a ScoringBasisCode.")
        if not self.finding_ids or len(set(self.finding_ids)) != len(self.finding_ids):
            raise ValueError("finding_ids must be non-empty and unique.")
        if tuple(sorted(self.finding_ids)) != self.finding_ids:
            raise ValueError("finding_ids must use deterministic sorted ordering.")
        for finding_id in self.finding_ids:
            _bounded_text(
                finding_id, "finding_id", MAX_SCORING_FINDING_ID_LENGTH
            )
        if not self.atomic_penalties:
            raise ValueError("atomic_penalties must be non-empty.")
        for value in (
            *self.atomic_penalties,
            self.base_penalty,
            self.raw_penalty,
            self.applied_penalty,
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("penalties must be non-negative integers.")
        if self.applied_penalty > self.raw_penalty:
            raise ValueError("applied_penalty cannot exceed raw_penalty.")
        if self.base_penalty != max(self.atomic_penalties):
            raise ValueError("base_penalty must equal the highest atomic penalty.")


@dataclass(frozen=True, slots=True)
class ScoringCategoryBreakdown:
    category: ScoringCategory
    raw_penalty: int
    applied_penalty: int
    saturated: bool

    def __post_init__(self) -> None:
        if not isinstance(self.category, ScoringCategory):
            raise TypeError("category must be a ScoringCategory.")
        for value in (self.raw_penalty, self.applied_penalty):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("category penalties must be non-negative integers.")
        if self.applied_penalty > self.raw_penalty:
            raise ValueError("applied_penalty cannot exceed raw_penalty.")
        if not isinstance(self.saturated, bool):
            raise TypeError("saturated must be a boolean.")


@dataclass(frozen=True, slots=True)
class ScoringBreakdown:
    scoring_version: ScoringVersion
    total_penalty: int
    categories: tuple[ScoringCategoryBreakdown, ...]
    contributors: tuple[ScoringRiskGroup, ...]
    highest_confirmed_severity: Severity | None

    def __post_init__(self) -> None:
        if not isinstance(self.scoring_version, ScoringVersion):
            raise TypeError("scoring_version must be a ScoringVersion.")
        if (
            isinstance(self.total_penalty, bool)
            or not isinstance(self.total_penalty, int)
            or self.total_penalty < 0
        ):
            raise ValueError("total_penalty must be a non-negative integer.")
        if tuple(item.category for item in self.categories) != tuple(ScoringCategory):
            raise ValueError("categories must use the complete closed enum ordering.")
        if tuple(sorted(
            item.group_id for item in self.contributors
        )) != tuple(item.group_id for item in self.contributors):
            raise ValueError("contributors must use deterministic group ordering.")
        if (
            self.highest_confirmed_severity is not None
            and not isinstance(self.highest_confirmed_severity, Severity)
        ):
            raise TypeError("highest_confirmed_severity must be a Severity or None.")


@dataclass(frozen=True, slots=True)
class ScoringResult:
    score: int
    risk_level: str
    counts: tuple[tuple[str, int], ...]
    breakdown: ScoringBreakdown

    def __post_init__(self) -> None:
        if isinstance(self.score, bool) or not isinstance(self.score, int):
            raise TypeError("score must be an integer.")
        if not 0 <= self.score <= 100:
            raise ValueError("score must be between 0 and 100.")
        if self.risk_level not in {"LOW", "MODERATE", "HIGH", "CRITICAL"}:
            raise ValueError("risk_level is not part of the closed v2 contract.")
        expected_order = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        if tuple(name for name, _ in self.counts) != expected_order:
            raise ValueError("counts must use the frozen severity ordering.")
        if any(
            isinstance(count, bool) or not isinstance(count, int) or count < 0
            for _, count in self.counts
        ):
            raise ValueError("counts must be non-negative integers.")
        if self.breakdown.scoring_version != ScoringVersion.V2:
            raise ValueError("ScoringResult requires a v2 breakdown.")
