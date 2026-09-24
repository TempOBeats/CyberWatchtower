"""Immutable, purpose-specific contracts for the application-service boundary."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import re
import unicodedata

from cyberwatchtower.core.evidence import EpistemicRole
from cyberwatchtower.firewall_policy import (
    EvaluatedPolicyDisposition,
    FirewallDefaultPolicyContext,
    FirewallRuleApplicability,
    ListenerPolicyBasis,
)
from cyberwatchtower.models import AssessmentState, FindingKind, Severity
from cyberwatchtower.platform.models import BindExposure
from cyberwatchtower.reachability import (
    ReachabilityEvidenceBasis,
    RemoteReachabilityState,
)
from cyberwatchtower.report_contracts import (
    AssessmentAssurance,
    CoverageState,
    ScanDomain,
)
from cyberwatchtower.scoring_contracts import (
    ScoringBasisCode,
    ScoringCategory,
    ScoringVersion,
)


_OPERATION_ID = re.compile(r"^assessment:[0-9a-f]{32}$")
_MAX_TEXT = 4096


def _text(value: object, field: str, maximum: int = _MAX_TEXT) -> None:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"{field} must be bounded non-empty text.")
    if any(
        unicodedata.category(character) in {"Cc", "Cf"}
        for character in value
    ):
        raise ValueError(f"{field} contains prohibited control characters.")


def _optional_text(value: object, field: str, maximum: int = _MAX_TEXT) -> None:
    if value is not None:
        _text(value, field, maximum)


def _typed_tuple(value: object, expected: type, field: str) -> None:
    if not isinstance(value, tuple) or not all(
        isinstance(item, expected) for item in value
    ):
        raise TypeError(f"{field} must be an immutable typed tuple.")


class SupportedPlatform(str, Enum):
    LINUX = "LINUX"
    WINDOWS = "WINDOWS"


class ApplicationEvidenceCategory(str, Enum):
    ADDRESS = "ADDRESS"
    EXPOSURE = "EXPOSURE"
    FORWARD_POLICY = "FORWARD_POLICY"
    FIREWALL_ENABLED = "FIREWALL_ENABLED"
    DEFAULT_INBOUND_ACTION = "DEFAULT_INBOUND_ACTION"
    BLOCK_ALL_INBOUND = "BLOCK_ALL_INBOUND"
    INPUT_POLICY = "INPUT_POLICY"
    OUTPUT_POLICY = "OUTPUT_POLICY"
    PORT = "PORT"
    PROCESS = "PROCESS"
    PROFILE = "PROFILE"
    PROTOCOL = "PROTOCOL"
    SERVICE = "SERVICE"
    SERVICE_APPLICATION = "SERVICE_APPLICATION"


class EvidenceProjectionState(str, Enum):
    COMPLETE = "COMPLETE"
    REDACTED = "REDACTED"


class ProjectionNoticeCode(str, Enum):
    EVIDENCE_REDACTED = "EVIDENCE_REDACTED"


class SecurityRiskLevel(str, Enum):
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True, slots=True)
class CurrentSystemAssessmentRequest:
    """Request the single supported read-only assessment of the local system."""


@dataclass(frozen=True, slots=True)
class SystemSummary:
    system_id: str | None
    hostname: str | None
    username: str | None
    operating_system: str
    os_version: str | None
    architecture: str | None
    processor: str | None

    def __post_init__(self) -> None:
        _text(self.operating_system, "operating_system")
        for name in (
            "system_id", "hostname", "username", "os_version",
            "architecture", "processor",
        ):
            _optional_text(getattr(self, name), name)


@dataclass(frozen=True, slots=True)
class FirewallTechnologySummary:
    detected_technologies: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.detected_technologies, tuple):
            raise TypeError("detected technologies must be an immutable tuple.")
        if len(set(self.detected_technologies)) != len(self.detected_technologies):
            raise ValueError("detected technologies must be unique.")
        for value in self.detected_technologies:
            _text(value, "detected technology", 128)


@dataclass(frozen=True, slots=True)
class ApplicationEvidence:
    category: ApplicationEvidenceCategory
    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.category, ApplicationEvidenceCategory):
            raise TypeError("evidence category must use the closed enum.")
        _text(self.value, "evidence value", 512)


@dataclass(frozen=True, slots=True)
class ProjectionNotice:
    code: ProjectionNoticeCode
    subject_id: str
    omitted_count: int

    def __post_init__(self) -> None:
        if not isinstance(self.code, ProjectionNoticeCode):
            raise TypeError("projection notice code must use the closed enum.")
        _text(self.subject_id, "projection notice subject", 512)
        if (
            isinstance(self.omitted_count, bool)
            or not isinstance(self.omitted_count, int)
            or self.omitted_count < 1
        ):
            raise ValueError("projection notice omitted count must be positive.")


@dataclass(frozen=True, slots=True)
class DomainCoverage:
    domain: ScanDomain
    state: CoverageState

    def __post_init__(self) -> None:
        if not isinstance(self.domain, ScanDomain):
            raise TypeError("coverage domain must use the closed enum.")
        if not isinstance(self.state, CoverageState):
            raise TypeError("coverage state must use the closed enum.")


@dataclass(frozen=True, slots=True)
class AssessmentAssuranceSummary:
    level: AssessmentAssurance
    limitations: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.level, AssessmentAssurance):
            raise TypeError("assurance level must use the closed enum.")
        if not isinstance(self.limitations, tuple):
            raise TypeError("assurance limitations must be an immutable tuple.")
        for limitation in self.limitations:
            _text(limitation, "assurance limitation", 512)


@dataclass(frozen=True, slots=True)
class FirewallApplicabilitySummary:
    applicability: FirewallRuleApplicability
    default_policy_context: FirewallDefaultPolicyContext
    evidence_basis: tuple[ListenerPolicyBasis, ...]
    matching_rule_digests: tuple[str, ...]
    collection_coverage: CoverageState
    applicability_coverage: CoverageState
    evaluated_policy_disposition: EvaluatedPolicyDisposition

    def __post_init__(self) -> None:
        if not isinstance(self.applicability, FirewallRuleApplicability):
            raise TypeError("firewall applicability must use the closed enum.")
        if not isinstance(self.default_policy_context, FirewallDefaultPolicyContext):
            raise TypeError("default policy context must use the closed enum.")
        _typed_tuple(self.evidence_basis, ListenerPolicyBasis, "policy evidence")
        if not isinstance(self.matching_rule_digests, tuple):
            raise TypeError("matching rule digests must be an immutable tuple.")
        for digest in self.matching_rule_digests:
            _text(digest, "matching rule digest", 64)
            if len(digest) != 64:
                raise ValueError("matching rule digest must be SHA-256.")
            try:
                int(digest, 16)
            except ValueError as exc:
                raise ValueError("matching rule digest must be hexadecimal.") from exc
        if not isinstance(self.collection_coverage, CoverageState):
            raise TypeError("rule collection coverage must use the closed enum.")
        if not isinstance(self.applicability_coverage, CoverageState):
            raise TypeError("rule applicability coverage must use the closed enum.")
        if not isinstance(
            self.evaluated_policy_disposition, EvaluatedPolicyDisposition
        ):
            raise TypeError("evaluated policy disposition must use the closed enum.")


@dataclass(frozen=True, slots=True)
class NetworkExposureContext:
    bind_exposure: BindExposure
    bind_epistemic_role: EpistemicRole
    reachability_state: RemoteReachabilityState
    reachability_epistemic_role: EpistemicRole
    evidence_basis: tuple[ReachabilityEvidenceBasis, ...]
    firewall_policy: FirewallApplicabilitySummary | None

    def __post_init__(self) -> None:
        if not isinstance(self.bind_exposure, BindExposure):
            raise TypeError("bind exposure must use the closed enum.")
        if self.bind_epistemic_role != EpistemicRole.OBSERVED_FACT:
            raise ValueError("bind exposure must remain an observed fact.")
        if not isinstance(self.reachability_state, RemoteReachabilityState):
            raise TypeError("reachability state must use the closed enum.")
        if self.reachability_epistemic_role != EpistemicRole.DETERMINISTIC_DERIVATION:
            raise ValueError("reachability must remain a deterministic derivation.")
        _typed_tuple(
            self.evidence_basis, ReachabilityEvidenceBasis,
            "reachability evidence",
        )
        if self.firewall_policy is not None and not isinstance(
            self.firewall_policy, FirewallApplicabilitySummary
        ):
            raise TypeError("firewall policy must use the immutable summary.")


@dataclass(frozen=True, slots=True)
class SeverityCount:
    severity: Severity
    count: int

    def __post_init__(self) -> None:
        if not isinstance(self.severity, Severity):
            raise TypeError("severity count must use the closed enum.")
        if isinstance(self.count, bool) or not isinstance(self.count, int) or self.count < 0:
            raise ValueError("severity count must be a non-negative integer.")


@dataclass(frozen=True, slots=True)
class ScoreCategoryBreakdown:
    category: ScoringCategory
    raw_penalty: int
    applied_penalty: int
    saturated: bool

    def __post_init__(self) -> None:
        if not isinstance(self.category, ScoringCategory):
            raise TypeError("score category must use the closed enum.")
        for value in (self.raw_penalty, self.applied_penalty):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("score penalties must be non-negative integers.")
        if self.applied_penalty > self.raw_penalty:
            raise ValueError("applied penalty cannot exceed raw penalty.")
        if not isinstance(self.saturated, bool):
            raise TypeError("saturated must be boolean.")


@dataclass(frozen=True, slots=True)
class ScoreContributor:
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
        _text(self.group_id, "score group id", 256)
        if not isinstance(self.category, ScoringCategory):
            raise TypeError("score contributor category must use the closed enum.")
        if not isinstance(self.finding_ids, tuple) or not self.finding_ids:
            raise TypeError("score finding IDs must be a non-empty tuple.")
        for finding_id in self.finding_ids:
            _text(finding_id, "score finding id", 512)
        if not isinstance(self.severity, Severity):
            raise TypeError("score severity must use the closed enum.")
        if not isinstance(self.assessment_state, AssessmentState):
            raise TypeError("score assessment state must use the closed enum.")
        if not isinstance(self.atomic_penalties, tuple) or not self.atomic_penalties:
            raise TypeError("atomic penalties must be a non-empty tuple.")
        for value in (
            *self.atomic_penalties, self.base_penalty, self.raw_penalty,
            self.applied_penalty,
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("score penalties must be non-negative integers.")
        if not isinstance(self.basis_code, ScoringBasisCode):
            raise TypeError("score basis must use the closed enum.")


@dataclass(frozen=True, slots=True)
class ScoreGuardrail:
    highest_confirmed_severity: Severity | None
    category_applied_penalty_total: int
    effective_penalty_total: int
    additional_guardrail_penalty: int
    effective_score_ceiling: int | None
    applied: bool

    def __post_init__(self) -> None:
        if self.highest_confirmed_severity is not None and not isinstance(
            self.highest_confirmed_severity, Severity
        ):
            raise TypeError("guardrail severity must use the closed enum.")
        for value in (
            self.category_applied_penalty_total,
            self.effective_penalty_total,
            self.additional_guardrail_penalty,
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("guardrail penalties must be non-negative integers.")
        if self.effective_score_ceiling is not None and (
            isinstance(self.effective_score_ceiling, bool)
            or not isinstance(self.effective_score_ceiling, int)
            or not 0 <= self.effective_score_ceiling <= 100
        ):
            raise ValueError("guardrail score ceiling is invalid.")
        if not isinstance(self.applied, bool):
            raise TypeError("guardrail applied flag must be boolean.")


@dataclass(frozen=True, slots=True)
class SecurityScoreBreakdown:
    total_effective_penalty: int
    categories: tuple[ScoreCategoryBreakdown, ...]
    contributors: tuple[ScoreContributor, ...]
    guardrail: ScoreGuardrail

    def __post_init__(self) -> None:
        if (
            isinstance(self.total_effective_penalty, bool)
            or not isinstance(self.total_effective_penalty, int)
            or not 0 <= self.total_effective_penalty <= 100
        ):
            raise ValueError("effective penalty must be between 0 and 100.")
        _typed_tuple(self.categories, ScoreCategoryBreakdown, "score categories")
        _typed_tuple(self.contributors, ScoreContributor, "score contributors")
        if not isinstance(self.guardrail, ScoreGuardrail):
            raise TypeError("score guardrail must use the immutable contract.")


@dataclass(frozen=True, slots=True)
class SecurityScore:
    scoring_version: ScoringVersion
    score: int
    risk_level: SecurityRiskLevel
    counts: tuple[SeverityCount, ...]
    breakdown: SecurityScoreBreakdown

    def __post_init__(self) -> None:
        if self.scoring_version != ScoringVersion.V2:
            raise ValueError("the application contract requires Scoring v2.")
        if isinstance(self.score, bool) or not isinstance(self.score, int) or not 0 <= self.score <= 100:
            raise ValueError("security score must be between 0 and 100.")
        if not isinstance(self.risk_level, SecurityRiskLevel):
            raise TypeError("risk level must use the closed enum.")
        _typed_tuple(self.counts, SeverityCount, "severity counts")
        if not isinstance(self.breakdown, SecurityScoreBreakdown):
            raise TypeError("score breakdown must use the immutable contract.")


@dataclass(frozen=True, slots=True)
class ApplicationFinding:
    finding_id: str
    title: str
    description: str
    severity: Severity
    recommendation: str
    evidence: tuple[ApplicationEvidence, ...]
    evidence_projection_state: EvidenceProjectionState
    omitted_evidence_count: int
    confidence: int
    technique_id: str | None
    source: str
    kind: FindingKind
    assessment_state: AssessmentState
    network_context: NetworkExposureContext | None
    presentation_group_id: str | None
    runtime_instance_count: int

    def __post_init__(self) -> None:
        _text(self.finding_id, "finding id", 512)
        _text(self.title, "finding title")
        _text(self.description, "finding description")
        _text(self.recommendation, "finding recommendation")
        _text(self.source, "finding source", 256)
        _optional_text(self.technique_id, "technique id", 256)
        _optional_text(self.presentation_group_id, "presentation group id", 512)
        if not isinstance(self.severity, Severity):
            raise TypeError("finding severity must use the closed enum.")
        if not isinstance(self.kind, FindingKind):
            raise TypeError("finding kind must use the closed enum.")
        if not isinstance(self.assessment_state, AssessmentState):
            raise TypeError("assessment state must use the closed enum.")
        _typed_tuple(self.evidence, ApplicationEvidence, "finding evidence")
        if not isinstance(self.evidence_projection_state, EvidenceProjectionState):
            raise TypeError("evidence projection state must use the closed enum.")
        if (
            isinstance(self.omitted_evidence_count, bool)
            or not isinstance(self.omitted_evidence_count, int)
            or self.omitted_evidence_count < 0
        ):
            raise ValueError("omitted evidence count must be non-negative.")
        if (
            self.evidence_projection_state == EvidenceProjectionState.COMPLETE
            and self.omitted_evidence_count != 0
        ) or (
            self.evidence_projection_state == EvidenceProjectionState.REDACTED
            and self.omitted_evidence_count == 0
        ):
            raise ValueError("evidence state and omitted count are inconsistent.")
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, int) or not 0 <= self.confidence <= 100:
            raise ValueError("finding confidence must be between 0 and 100.")
        if self.network_context is not None and not isinstance(
            self.network_context, NetworkExposureContext
        ):
            raise TypeError("network context must use the immutable contract.")
        if (
            isinstance(self.runtime_instance_count, bool)
            or not isinstance(self.runtime_instance_count, int)
            or not 1 <= self.runtime_instance_count <= 65_536
        ):
            raise ValueError("runtime multiplicity is outside the supported bound.")


@dataclass(frozen=True, slots=True)
class CurrentSystemAssessmentResult:
    operation_id: str
    completed_at: datetime
    platform: SupportedPlatform
    system: SystemSummary
    firewall: FirewallTechnologySummary
    findings: tuple[ApplicationFinding, ...]
    score: SecurityScore
    coverage: tuple[DomainCoverage, ...]
    assurance: AssessmentAssuranceSummary
    projection_notices: tuple[ProjectionNotice, ...]

    def __post_init__(self) -> None:
        if _OPERATION_ID.fullmatch(self.operation_id) is None:
            raise ValueError("operation id has an invalid format.")
        if not isinstance(self.completed_at, datetime) or (
            self.completed_at.tzinfo is None or self.completed_at.utcoffset() is None
        ):
            raise ValueError("completion time must be timezone-aware.")
        if not isinstance(self.platform, SupportedPlatform):
            raise TypeError("platform must use the closed enum.")
        if not isinstance(self.system, SystemSummary):
            raise TypeError("system must use the immutable summary.")
        if not isinstance(self.firewall, FirewallTechnologySummary):
            raise TypeError("firewall must use the immutable summary.")
        _typed_tuple(self.findings, ApplicationFinding, "findings")
        _typed_tuple(self.coverage, DomainCoverage, "coverage")
        _typed_tuple(self.projection_notices, ProjectionNotice, "projection notices")
        if len({finding.finding_id for finding in self.findings}) != len(self.findings):
            raise ValueError("finding identities must be unique.")
        if not isinstance(self.score, SecurityScore):
            raise TypeError("score must use the immutable contract.")
        if not isinstance(self.assurance, AssessmentAssuranceSummary):
            raise TypeError("assurance must use the immutable summary.")
