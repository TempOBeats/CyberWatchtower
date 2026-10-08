"""Immutable, purpose-specific contracts for the application-service boundary."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
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


_ASSESSMENT_OPERATION_ID = re.compile(r"^assessment:[0-9a-f]{32}$")
_REPORT_OPERATION_ID = re.compile(r"^reportop:[0-9a-f]{32}$")
_HISTORY_OPERATION_ID = re.compile(r"^historyop:[0-9a-f]{32}$")
_ASSISTANT_OPERATION_ID = re.compile(r"^assistantop:[0-9a-f]{32}$")
_PROPOSAL_ID = re.compile(r"^proposal:[0-9a-f]{32}$")
_REPORT_ID = re.compile(r"^report:[0-9a-f]{64}$")
_CAPABILITY_ID = re.compile(
    r"^cyberwatchtower\.application\.[a-z][a-z0-9_]{0,95}$"
)
_CAPABILITY_VERSION = re.compile(r"^[1-9][0-9]{0,19}$")
_STABLE_PRESENTATION_ID = re.compile(r"^[a-z][a-z0-9_.:-]{0,127}$")
_EFFECT_ID = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
_PARAMETER_KEY = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SHA256_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_INTEGER_PARAMETER = re.compile(r"^(?:0|-[1-9][0-9]*|[1-9][0-9]*)$")
_UTC_TIMESTAMP_PARAMETER = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$"
)
_URL_TARGET = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
_WINDOWS_ROOT = re.compile(r"^[A-Za-z]:[\\/]")
_PEM_PRIVATE_KEY_HEADER = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----",
    re.IGNORECASE,
)
_F_SENSITIVE_MARKERS = (
    "api-key",
    "api_key",
    "apikey",
    "authorization:",
    "bearer ",
    "command line",
    "credential",
    "cookie:",
    "environment=",
    "password",
    "raw argv",
    "stderr",
    "token=",
    "token:",
)
_F_COMMAND_MARKERS = (
    "-----begin private key-----",
    "-----begin rsa private key-----",
    "-----begin ec private key-----",
    "$(",
    "`",
    "sh -c",
    "bash -c",
    "cmd.exe",
    "powershell",
)
SYSTEM_ID_MAX = 4096
FINDING_ID_MAX = 512
RECURRING_DEFAULT_LIMIT = 50
RECURRING_MAX_LIMIT = 200
TIMELINE_DEFAULT_LIMIT = 100
TIMELINE_MAX_LIMIT = 500
SCORE_HISTORY_DEFAULT_LIMIT = 100
SCORE_HISTORY_MAX_LIMIT = 500
SCORE_HISTORY_MAX_RANGE_DAYS = 366
MEMORY_HEALTH_MAX_DIAGNOSTICS = 32
_MAX_TEXT = SYSTEM_ID_MAX


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


def _non_negative_integer(value: object, field: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer.")


def _aware_datetime(value: object, field: str) -> None:
    if not isinstance(value, datetime) or (
        value.tzinfo is None or value.utcoffset() is None
    ):
        raise ValueError(f"{field} must be timezone-aware.")


def _system_id(value: object, field: str = "system_id") -> None:
    _text(value, field)
    if value != value.strip():
        raise ValueError(f"{field} cannot contain surrounding whitespace.")


def _is_assessment_operation_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and _ASSESSMENT_OPERATION_ID.fullmatch(value) is not None
    )


def _is_report_operation_id(value: object) -> bool:
    return isinstance(value, str) and _REPORT_OPERATION_ID.fullmatch(value) is not None


def _is_history_operation_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and _HISTORY_OPERATION_ID.fullmatch(value) is not None
    )


def _is_application_operation_id(value: object) -> bool:
    return (
        _is_assessment_operation_id(value)
        or _is_report_operation_id(value)
        or _is_history_operation_id(value)
    )


def _history_operation(value: object) -> None:
    if not _is_history_operation_id(value):
        raise ValueError("history operation id has an invalid format.")


def _report_identity(value: object, field: str = "report_id") -> None:
    if not isinstance(value, ReportId):
        raise TypeError(f"{field} must use the immutable report identity.")


def _boolean(value: object, field: str) -> None:
    if not isinstance(value, bool):
        raise TypeError(f"{field} must be boolean.")


def _bounded_limit(value: object, field: str, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field} must be an integer.")
    if not 1 <= value <= maximum:
        raise ValueError(f"{field} is outside the supported bound.")


def _score(value: object, field: str) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= 100
    ):
        raise ValueError(f"{field} must be between 0 and 100.")


def _scoring_version(value: object, field: str) -> None:
    if not isinstance(value, ScoringVersion):
        raise TypeError(f"{field} must use the closed scoring-version enum.")


def _bounded_result(
    values: object,
    expected: type,
    returned_count: object,
    has_more: object,
    field: str,
) -> None:
    _typed_tuple(values, expected, field)
    _non_negative_integer(returned_count, "returned_count")
    if returned_count != len(values):
        raise ValueError("returned_count must equal the returned tuple length.")
    _boolean(has_more, "has_more")


def _f_text(value: object, field: str, maximum: int) -> None:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"{field} must be bounded non-empty text.")
    if not value.strip():
        raise ValueError(f"{field} cannot be blank.")
    if not unicodedata.is_normalized("NFC", value):
        raise ValueError(f"{field} must use Unicode NFC.")
    if any(unicodedata.category(character) in {"Cc", "Cf"} for character in value):
        raise ValueError(f"{field} contains prohibited control characters.")


def _f_system_id(value: object, field: str = "system_id") -> None:
    _system_id(value, field)
    if not unicodedata.is_normalized("NFC", value):
        raise ValueError(f"{field} must use Unicode NFC.")


def _closed(value: object, expected: type, field: str) -> None:
    if not isinstance(value, expected):
        raise TypeError(f"{field} must use the closed {expected.__name__} enum.")


def _f_tuple(
    value: object,
    expected: type,
    field: str,
    *,
    minimum: int = 0,
    maximum: int,
) -> None:
    _typed_tuple(value, expected, field)
    if not minimum <= len(value) <= maximum:
        raise ValueError(f"{field} is outside the supported bound.")


def _utc_datetime(value: object, field: str) -> None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is not timezone.utc
        or value.utcoffset() != timedelta(0)
    ):
        raise ValueError(f"{field} must use canonical UTC.")


def _reject_unsafe_text(
    value: str,
    field: str,
    *,
    reject_url: bool = False,
) -> None:
    folded = value.casefold()
    if any(marker in folded for marker in _F_SENSITIVE_MARKERS):
        raise ValueError(f"{field} contains prohibited sensitive content.")
    if any(marker in folded for marker in _F_COMMAND_MARKERS):
        raise ValueError(f"{field} contains prohibited command or secret content.")
    if _PEM_PRIVATE_KEY_HEADER.search(value) is not None:
        raise ValueError(f"{field} contains prohibited command or secret content.")
    if (
        value.startswith(("/", "./", "../", "~", "\\\\"))
        or "/../" in value
        or "\\..\\" in value
        or folded.startswith("file:")
        or _WINDOWS_ROOT.match(value) is not None
    ):
        raise ValueError(f"{field} contains a prohibited path.")
    if reject_url and _URL_TARGET.match(value) is not None:
        raise ValueError(f"{field} contains a prohibited URL.")


def _assistant_operation(value: object) -> None:
    if not isinstance(value, str) or _ASSISTANT_OPERATION_ID.fullmatch(value) is None:
        raise ValueError("assistant operation id has an invalid format.")


def _capability_id(value: object) -> None:
    if not isinstance(value, str) or _CAPABILITY_ID.fullmatch(value) is None:
        raise ValueError("capability_id has an invalid format.")


def _capability_version(value: object) -> None:
    if not isinstance(value, str) or _CAPABILITY_VERSION.fullmatch(value) is None:
        raise ValueError("capability_version has an invalid format.")


def _digest(value: object, field: str) -> None:
    if not isinstance(value, str) or _SHA256_DIGEST.fullmatch(value) is None:
        raise ValueError(f"{field} must be a lowercase SHA-256 digest.")


def _presentation_id(value: object, field: str) -> None:
    if not isinstance(value, str) or _STABLE_PRESENTATION_ID.fullmatch(value) is None:
        raise ValueError(f"{field} has an invalid format.")


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


class ReportCatalogCompleteness(str, Enum):
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"


class ReportCompatibilityState(str, Enum):
    CURRENT = "CURRENT"
    LEGACY_NORMALIZED = "LEGACY_NORMALIZED"


class SavedReportField(str, Enum):
    ASSESSMENT_DOMAINS = "ASSESSMENT_DOMAINS"
    COVERAGE = "COVERAGE"
    ASSURANCE = "ASSURANCE"
    FINDING_METADATA = "FINDING_METADATA"
    RUNTIME_MULTIPLICITY = "RUNTIME_MULTIPLICITY"
    SCORING_VERSION = "SCORING_VERSION"
    RISK_LEVEL = "RISK_LEVEL"
    SEVERITY_COUNTS = "SEVERITY_COUNTS"
    SCORING_BREAKDOWN = "SCORING_BREAKDOWN"


class ScoreTrendState(str, Enum):
    IMPROVED = "IMPROVED"
    DECLINED = "DECLINED"
    UNCHANGED = "UNCHANGED"
    INCOMPARABLE = "INCOMPARABLE"


class FindingLifecycleState(str, Enum):
    ACTIVE = "ACTIVE"
    RESOLVED = "RESOLVED"
    RESOLUTION_UNCERTAIN = "RESOLUTION_UNCERTAIN"


class LifecycleEventType(str, Enum):
    FIRST_SEEN = "FIRST_SEEN"
    SEEN = "SEEN"
    RESOLVED = "RESOLVED"
    REOPENED = "REOPENED"
    SEVERITY_CHANGED = "SEVERITY_CHANGED"
    ASSESSMENT_STATE_CHANGED = "ASSESSMENT_STATE_CHANGED"
    KIND_CHANGED = "KIND_CHANGED"


LIFECYCLE_EVENT_PRECEDENCE = (
    LifecycleEventType.FIRST_SEEN,
    LifecycleEventType.SEEN,
    LifecycleEventType.REOPENED,
    LifecycleEventType.SEVERITY_CHANGED,
    LifecycleEventType.ASSESSMENT_STATE_CHANGED,
    LifecycleEventType.KIND_CHANGED,
    LifecycleEventType.RESOLVED,
)
_LIFECYCLE_EVENT_ORDER = {
    event_type: index
    for index, event_type in enumerate(LIFECYCLE_EVENT_PRECEDENCE, start=1)
}


class MemoryIngestionStatus(str, Enum):
    INGESTED = "INGESTED"
    ALREADY_PRESENT = "ALREADY_PRESENT"


class MemoryHealthState(str, Enum):
    DISABLED = "DISABLED"
    UNINITIALIZED = "UNINITIALIZED"
    AVAILABLE = "AVAILABLE"
    DEGRADED = "DEGRADED"
    MIGRATION_REQUIRED = "MIGRATION_REQUIRED"
    INCOMPATIBLE = "INCOMPATIBLE"
    CORRUPT = "CORRUPT"
    UNAVAILABLE = "UNAVAILABLE"


class MemoryIntegrityState(str, Enum):
    NOT_CHECKED = "NOT_CHECKED"
    PASS = "PASS"
    WARNING = "WARNING"
    FAIL = "FAIL"
    UNAVAILABLE = "UNAVAILABLE"


class MemoryDiagnosticSeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class MemoryDiagnosticCategory(str, Enum):
    CONFIGURATION = "CONFIGURATION"
    STORAGE = "STORAGE"
    SCHEMA = "SCHEMA"
    INTEGRITY = "INTEGRITY"


class MemoryDiagnosticCode(str, Enum):
    DISABLED = "DISABLED"
    UNINITIALIZED = "UNINITIALIZED"
    AVAILABLE = "AVAILABLE"
    DEGRADED = "DEGRADED"
    MIGRATION_REQUIRED = "MIGRATION_REQUIRED"
    INCOMPATIBLE_SCHEMA = "INCOMPATIBLE_SCHEMA"
    CORRUPT = "CORRUPT"
    UNAVAILABLE = "UNAVAILABLE"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    LOCKED = "LOCKED"
    INTEGRITY_WARNING = "INTEGRITY_WARNING"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class EffectClass(str, Enum):
    PURE = "PURE"
    LOCAL_READ = "LOCAL_READ"
    LOCAL_DERIVED_STATE_CHANGE = "LOCAL_DERIVED_STATE_CHANGE"
    LOCAL_AUTHORITATIVE_STATE_CHANGE = "LOCAL_AUTHORITATIVE_STATE_CHANGE"
    SYSTEM_OBSERVATION = "SYSTEM_OBSERVATION"
    SYSTEM_STATE_CHANGE = "SYSTEM_STATE_CHANGE"
    EXTERNAL_IO = "EXTERNAL_IO"
    PROHIBITED = "PROHIBITED"


class PermissionClass(str, Enum):
    READ_ONLY = "READ_ONLY"
    USER_APPROVAL_REQUIRED = "USER_APPROVAL_REQUIRED"
    PROHIBITED = "PROHIBITED"


class PrivacyClass(str, Enum):
    PUBLIC_METADATA = "PUBLIC_METADATA"
    LOCAL_SECURITY_DATA = "LOCAL_SECURITY_DATA"
    SENSITIVE_LOCAL_DATA = "SENSITIVE_LOCAL_DATA"
    SECRET = "SECRET"


class CapabilityAvailability(str, Enum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    PROHIBITED = "PROHIBITED"


class CapabilityParameterKind(str, Enum):
    TEXT = "TEXT"
    INTEGER = "INTEGER"
    BOOLEAN = "BOOLEAN"
    UTC_TIMESTAMP = "UTC_TIMESTAMP"


class CapabilityTargetKind(str, Enum):
    APPLICATION = "APPLICATION"
    SYSTEM = "SYSTEM"
    REPORT = "REPORT"
    FINDING = "FINDING"


class ReusePolicy(str, Enum):
    ONE_TIME = "ONE_TIME"


class EpistemicState(str, Enum):
    OBSERVED = "OBSERVED"
    STRONGLY_SUPPORTED = "STRONGLY_SUPPORTED"
    POSSIBLE = "POSSIBLE"
    UNKNOWN = "UNKNOWN"


class AssistantSectionId(str, Enum):
    POSTURE = "posture"
    CHANGES = "changes"
    PRIORITIES = "priorities"
    EXPLANATION = "explanation"
    COVERAGE = "coverage"
    NEXT_STEPS = "next_steps"


class AssistantEvidenceSourceKind(str, Enum):
    CANONICAL_REPORT = "CANONICAL_REPORT"
    REPORT_FINDING = "REPORT_FINDING"
    REPORT_COMPARISON = "REPORT_COMPARISON"
    DETERMINISTIC_ADVISOR = "DETERMINISTIC_ADVISOR"


class AssistantEvidenceRole(str, Enum):
    OBSERVED_FACT = "OBSERVED_FACT"
    DETERMINISTIC_DERIVATION = "DETERMINISTIC_DERIVATION"


class AssistantIntent(str, Enum):
    SUMMARY = "SUMMARY"
    WHY_FINDING = "WHY_FINDING"
    WHAT_CHANGED = "WHAT_CHANGED"
    WHAT_TO_FIX_FIRST = "WHAT_TO_FIX_FIRST"
    COVERAGE = "COVERAGE"


class AssistantQuestionStatus(str, Enum):
    ANSWERED = "ANSWERED"
    UNSUPPORTED = "UNSUPPORTED"
    AMBIGUOUS = "AMBIGUOUS"
    MISSING_CONTEXT = "MISSING_CONTEXT"


@dataclass(frozen=True, slots=True)
class CurrentSystemAssessmentRequest:
    """Request the single supported read-only assessment of the local system."""


@dataclass(frozen=True, slots=True)
class ReportId:
    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or _REPORT_ID.fullmatch(self.value) is None:
            raise ValueError("report ID has an invalid format.")


@dataclass(frozen=True, slots=True)
class ListSavedReportsRequest:
    system_id: str

    def __post_init__(self) -> None:
        _system_id(self.system_id)


@dataclass(frozen=True, slots=True)
class GetSavedReportRequest:
    report_id: ReportId
    expected_system_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.report_id, ReportId):
            raise TypeError("report_id must use the immutable report identity.")
        _system_id(self.expected_system_id, "expected_system_id")


@dataclass(frozen=True, slots=True)
class GetLatestSavedReportRequest:
    system_id: str

    def __post_init__(self) -> None:
        _system_id(self.system_id)


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
        if (
            isinstance(self.score, bool)
            or not isinstance(self.score, int)
            or not 0 <= self.score <= 100
        ):
            raise ValueError("security score must be between 0 and 100.")
        if not isinstance(self.risk_level, SecurityRiskLevel):
            raise TypeError("risk level must use the closed enum.")
        _typed_tuple(self.counts, SeverityCount, "severity counts")
        if not isinstance(self.breakdown, SecurityScoreBreakdown):
            raise TypeError("score breakdown must use the immutable contract.")


@dataclass(frozen=True, slots=True)
class SavedReportCompatibility:
    state: ReportCompatibilityState
    defaulted_fields: tuple[SavedReportField, ...]
    unavailable_fields: tuple[SavedReportField, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.state, ReportCompatibilityState):
            raise TypeError("report compatibility state must use the closed enum.")
        _typed_tuple(
            self.defaulted_fields, SavedReportField, "defaulted report fields"
        )
        _typed_tuple(
            self.unavailable_fields, SavedReportField, "unavailable report fields"
        )


@dataclass(frozen=True, slots=True)
class SavedReportCatalogDiagnostics:
    malformed_count: int
    unsupported_count: int
    oversized_count: int
    permission_denied_count: int
    io_error_count: int
    symlink_count: int
    nonregular_count: int
    disappeared_count: int
    unresolved_system_count: int
    duplicate_count: int

    def __post_init__(self) -> None:
        for field in self.__dataclass_fields__:
            _non_negative_integer(getattr(self, field), field)


@dataclass(frozen=True, slots=True)
class SavedReportSummary:
    report_id: ReportId
    generated_at: datetime
    schema_version: str
    system_id: str
    scoring_version: ScoringVersion
    score: int
    risk_level: str
    finding_count: int
    coverage: tuple[DomainCoverage, ...]
    assurance: AssessmentAssuranceSummary | None
    compatibility: SavedReportCompatibility

    def __post_init__(self) -> None:
        if not isinstance(self.report_id, ReportId):
            raise TypeError("report summary requires an immutable report identity.")
        _aware_datetime(self.generated_at, "generated_at")
        _text(self.schema_version, "schema_version", 32)
        _system_id(self.system_id)
        if not isinstance(self.scoring_version, ScoringVersion):
            raise TypeError("scoring version must use the closed enum.")
        if (
            isinstance(self.score, bool)
            or not isinstance(self.score, int)
            or not 0 <= self.score <= 100
        ):
            raise ValueError("saved report score must be between 0 and 100.")
        _text(self.risk_level, "risk_level", 32)
        _non_negative_integer(self.finding_count, "finding_count")
        _typed_tuple(self.coverage, DomainCoverage, "saved report coverage")
        if self.assurance is not None and not isinstance(
            self.assurance, AssessmentAssuranceSummary
        ):
            raise TypeError("assurance must use the immutable summary.")
        if not isinstance(self.compatibility, SavedReportCompatibility):
            raise TypeError("compatibility must use the immutable report contract.")


@dataclass(frozen=True, slots=True)
class SavedReportCatalog:
    operation_id: str
    reports: tuple[SavedReportSummary, ...]
    completeness: ReportCatalogCompleteness
    omitted_count: int
    diagnostics: SavedReportCatalogDiagnostics

    def __post_init__(self) -> None:
        if not _is_report_operation_id(self.operation_id):
            raise ValueError("report operation id has an invalid format.")
        _typed_tuple(self.reports, SavedReportSummary, "saved reports")
        if not isinstance(self.completeness, ReportCatalogCompleteness):
            raise TypeError("catalog completeness must use the closed enum.")
        _non_negative_integer(self.omitted_count, "omitted_count")
        if not isinstance(self.diagnostics, SavedReportCatalogDiagnostics):
            raise TypeError("catalog diagnostics must use the immutable contract.")


@dataclass(frozen=True, slots=True)
class SavedReportSystemSummary:
    system_id: str
    hostname: str

    def __post_init__(self) -> None:
        _system_id(self.system_id)
        _text(self.hostname, "hostname")


@dataclass(frozen=True, slots=True)
class SavedReportScore:
    scoring_version: ScoringVersion
    score: int
    risk_level: str
    counts: tuple[SeverityCount, ...]
    breakdown: SecurityScoreBreakdown | None

    def __post_init__(self) -> None:
        if not isinstance(self.scoring_version, ScoringVersion):
            raise TypeError("scoring version must use the closed enum.")
        if (
            isinstance(self.score, bool)
            or not isinstance(self.score, int)
            or not 0 <= self.score <= 100
        ):
            raise ValueError("saved report score must be between 0 and 100.")
        _text(self.risk_level, "risk_level", 32)
        _typed_tuple(self.counts, SeverityCount, "saved severity counts")
        if self.breakdown is not None and not isinstance(
            self.breakdown, SecurityScoreBreakdown
        ):
            raise TypeError("score breakdown must use the immutable contract.")
        if self.scoring_version == ScoringVersion.V1 and self.breakdown is not None:
            raise ValueError("Scoring v1 cannot carry a v2 breakdown.")
        if self.scoring_version == ScoringVersion.V2 and self.breakdown is None:
            raise ValueError("Scoring v2 requires its authoritative breakdown.")


@dataclass(frozen=True, slots=True)
class SavedReportFinding:
    finding_id: str
    title: str
    description: str | None
    severity: Severity
    recommendation: str | None
    evidence: tuple[ApplicationEvidence, ...]
    evidence_projection_state: EvidenceProjectionState
    omitted_evidence_count: int
    confidence: int
    technique_id: str | None
    source: str
    kind: FindingKind
    assessment_state: AssessmentState
    metadata_inferred: bool
    network_context: NetworkExposureContext | None
    runtime_instance_count: int

    def __post_init__(self) -> None:
        _text(self.finding_id, "finding id", 512)
        _text(self.title, "finding title")
        _optional_text(self.description, "finding description")
        _optional_text(self.recommendation, "finding recommendation")
        _optional_text(self.technique_id, "technique id", 256)
        _text(self.source, "finding source", 256)
        if not isinstance(self.severity, Severity):
            raise TypeError("finding severity must use the closed enum.")
        if not isinstance(self.kind, FindingKind):
            raise TypeError("finding kind must use the closed enum.")
        if not isinstance(self.assessment_state, AssessmentState):
            raise TypeError("assessment state must use the closed enum.")
        _typed_tuple(self.evidence, ApplicationEvidence, "finding evidence")
        if not isinstance(self.evidence_projection_state, EvidenceProjectionState):
            raise TypeError("evidence projection state must use the closed enum.")
        _non_negative_integer(self.omitted_evidence_count, "omitted_evidence_count")
        if (
            self.evidence_projection_state == EvidenceProjectionState.COMPLETE
            and self.omitted_evidence_count != 0
        ) or (
            self.evidence_projection_state == EvidenceProjectionState.REDACTED
            and self.omitted_evidence_count == 0
        ):
            raise ValueError("evidence state and omitted count are inconsistent.")
        if (
            isinstance(self.confidence, bool)
            or not isinstance(self.confidence, int)
            or not 0 <= self.confidence <= 100
        ):
            raise ValueError("finding confidence must be between 0 and 100.")
        if not isinstance(self.metadata_inferred, bool):
            raise TypeError("metadata_inferred must be boolean.")
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
class SavedReportDetail:
    operation_id: str
    report_id: ReportId
    generated_at: datetime
    schema_version: str
    system: SavedReportSystemSummary
    findings: tuple[SavedReportFinding, ...]
    score: SavedReportScore
    coverage: tuple[DomainCoverage, ...]
    assurance: AssessmentAssuranceSummary | None
    compatibility: SavedReportCompatibility
    projection_notices: tuple[ProjectionNotice, ...]

    def __post_init__(self) -> None:
        if not _is_report_operation_id(self.operation_id):
            raise ValueError("report operation id has an invalid format.")
        if not isinstance(self.report_id, ReportId):
            raise TypeError("report detail requires an immutable report identity.")
        _aware_datetime(self.generated_at, "generated_at")
        _text(self.schema_version, "schema_version", 32)
        if not isinstance(self.system, SavedReportSystemSummary):
            raise TypeError("system must use the immutable saved-report summary.")
        _typed_tuple(self.findings, SavedReportFinding, "saved report findings")
        if not isinstance(self.score, SavedReportScore):
            raise TypeError("score must use the immutable saved-report contract.")
        _typed_tuple(self.coverage, DomainCoverage, "saved report coverage")
        if self.assurance is not None and not isinstance(
            self.assurance, AssessmentAssuranceSummary
        ):
            raise TypeError("assurance must use the immutable summary.")
        if not isinstance(self.compatibility, SavedReportCompatibility):
            raise TypeError("compatibility must use the immutable report contract.")
        _typed_tuple(
            self.projection_notices, ProjectionNotice, "projection notices"
        )


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
        if not _is_assessment_operation_id(self.operation_id):
            raise ValueError("operation id has an invalid format.")
        _aware_datetime(self.completed_at, "completion time")
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


@dataclass(frozen=True, slots=True)
class SavedCurrentSystemAssessmentResult:
    assessment: CurrentSystemAssessmentResult
    report: SavedReportSummary

    def __post_init__(self) -> None:
        if not isinstance(self.assessment, CurrentSystemAssessmentResult):
            raise TypeError("assessment must use the immutable assessment result.")
        if not isinstance(self.report, SavedReportSummary):
            raise TypeError("report must use the immutable saved-report summary.")


@dataclass(frozen=True, slots=True)
class CompareSavedReportsRequest:
    system_id: str
    previous_report_id: ReportId
    current_report_id: ReportId

    def __post_init__(self) -> None:
        _system_id(self.system_id)
        _report_identity(self.previous_report_id, "previous_report_id")
        _report_identity(self.current_report_id, "current_report_id")
        if self.previous_report_id == self.current_report_id:
            raise ValueError("previous and current report IDs must differ.")


@dataclass(frozen=True, slots=True)
class SavedReportReference:
    report_id: ReportId
    generated_at: datetime

    def __post_init__(self) -> None:
        _report_identity(self.report_id)
        _aware_datetime(self.generated_at, "generated_at")


@dataclass(frozen=True, slots=True)
class ComparisonFindingSummary:
    finding_id: str
    title: str
    severity: Severity
    source: str
    kind: FindingKind
    assessment_state: AssessmentState

    def __post_init__(self) -> None:
        _text(self.finding_id, "finding_id", FINDING_ID_MAX)
        if self.finding_id != self.finding_id.strip():
            raise ValueError("finding_id cannot contain surrounding whitespace.")
        _text(self.title, "title")
        _text(self.source, "source", 256)
        if not isinstance(self.severity, Severity):
            raise TypeError("severity must use the closed enum.")
        if not isinstance(self.kind, FindingKind):
            raise TypeError("kind must use the closed enum.")
        if not isinstance(self.assessment_state, AssessmentState):
            raise TypeError("assessment_state must use the closed enum.")


def _comparison_findings(
    value: object,
    field: str,
) -> tuple[ComparisonFindingSummary, ...]:
    _typed_tuple(value, ComparisonFindingSummary, field)
    if tuple(sorted(value, key=lambda item: item.finding_id)) != value:
        raise ValueError(f"{field} must be ordered by finding identity.")
    if len({item.finding_id for item in value}) != len(value):
        raise ValueError(f"{field} cannot contain duplicate finding identities.")
    return value


@dataclass(frozen=True, slots=True)
class SavedReportComparisonResult:
    operation_id: str
    system_id: str
    previous_report: SavedReportReference
    current_report: SavedReportReference
    previous_score: int
    current_score: int
    previous_risk: str
    current_risk: str
    previous_scoring_version: ScoringVersion
    current_scoring_version: ScoringVersion
    score_trend: ScoreTrendState
    score_change: int | None
    added_findings: tuple[ComparisonFindingSummary, ...]
    resolved_findings: tuple[ComparisonFindingSummary, ...]
    uncertain_disappearances: tuple[ComparisonFindingSummary, ...]

    def __post_init__(self) -> None:
        _history_operation(self.operation_id)
        _system_id(self.system_id)
        if not isinstance(self.previous_report, SavedReportReference):
            raise TypeError("previous_report must use the immutable reference.")
        if not isinstance(self.current_report, SavedReportReference):
            raise TypeError("current_report must use the immutable reference.")
        previous_key = (
            self.previous_report.generated_at,
            self.previous_report.report_id.value,
        )
        current_key = (
            self.current_report.generated_at,
            self.current_report.report_id.value,
        )
        if previous_key >= current_key:
            raise ValueError("comparison report chronology is invalid.")
        _score(self.previous_score, "previous_score")
        _score(self.current_score, "current_score")
        _text(self.previous_risk, "previous_risk", 32)
        _text(self.current_risk, "current_risk", 32)
        _scoring_version(
            self.previous_scoring_version, "previous_scoring_version"
        )
        _scoring_version(
            self.current_scoring_version, "current_scoring_version"
        )
        if not isinstance(self.score_trend, ScoreTrendState):
            raise TypeError("score_trend must use the closed enum.")
        compatible = (
            self.previous_scoring_version == self.current_scoring_version
        )
        if not compatible:
            if (
                self.score_trend != ScoreTrendState.INCOMPARABLE
                or self.score_change is not None
            ):
                raise ValueError("incompatible scoring versions cannot be trended.")
        else:
            expected_change = self.current_score - self.previous_score
            expected_trend = (
                ScoreTrendState.IMPROVED
                if expected_change > 0
                else ScoreTrendState.DECLINED
                if expected_change < 0
                else ScoreTrendState.UNCHANGED
            )
            if (
                isinstance(self.score_change, bool)
                or not isinstance(self.score_change, int)
                or self.score_change != expected_change
                or self.score_trend != expected_trend
            ):
                raise ValueError("score trend does not match compatible scores.")
        categories = (
            _comparison_findings(self.added_findings, "added_findings"),
            _comparison_findings(self.resolved_findings, "resolved_findings"),
            _comparison_findings(
                self.uncertain_disappearances,
                "uncertain_disappearances",
            ),
        )
        identities = [
            finding.finding_id
            for category in categories
            for finding in category
        ]
        if len(set(identities)) != len(identities):
            raise ValueError("comparison categories must be identity-disjoint.")


@dataclass(frozen=True, slots=True)
class IngestSavedReportIntoMemoryRequest:
    system_id: str
    report_id: ReportId

    def __post_init__(self) -> None:
        _system_id(self.system_id)
        _report_identity(self.report_id)


@dataclass(frozen=True, slots=True)
class SavedReportMemoryIngestionResult:
    operation_id: str
    status: MemoryIngestionStatus
    report_id: ReportId
    system_id: str
    schema_version: str

    def __post_init__(self) -> None:
        _history_operation(self.operation_id)
        if not isinstance(self.status, MemoryIngestionStatus):
            raise TypeError("status must use the closed ingestion enum.")
        _report_identity(self.report_id)
        _system_id(self.system_id)
        _text(self.schema_version, "schema_version", 32)


@dataclass(frozen=True, slots=True)
class ListRecurringFindingsRequest:
    system_id: str
    limit: int = RECURRING_DEFAULT_LIMIT
    active_only: bool = False

    def __post_init__(self) -> None:
        _system_id(self.system_id)
        _bounded_limit(self.limit, "limit", RECURRING_MAX_LIMIT)
        _boolean(self.active_only, "active_only")


@dataclass(frozen=True, slots=True)
class MemoryFindingSummary:
    finding_id: str
    title: str
    severity: Severity
    source: str
    kind: FindingKind
    assessment_state: AssessmentState
    occurrence_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    lifecycle_state: FindingLifecycleState
    reopen_count: int

    def __post_init__(self) -> None:
        _text(self.finding_id, "finding_id", FINDING_ID_MAX)
        if self.finding_id != self.finding_id.strip():
            raise ValueError("finding_id cannot contain surrounding whitespace.")
        _text(self.title, "title")
        _text(self.source, "source", 256)
        if not isinstance(self.severity, Severity):
            raise TypeError("severity must use the closed enum.")
        if not isinstance(self.kind, FindingKind):
            raise TypeError("kind must use the closed enum.")
        if not isinstance(self.assessment_state, AssessmentState):
            raise TypeError("assessment_state must use the closed enum.")
        if (
            isinstance(self.occurrence_count, bool)
            or not isinstance(self.occurrence_count, int)
            or self.occurrence_count < 1
        ):
            raise ValueError("occurrence_count must be a positive integer.")
        _aware_datetime(self.first_seen_at, "first_seen_at")
        _aware_datetime(self.last_seen_at, "last_seen_at")
        if self.first_seen_at > self.last_seen_at:
            raise ValueError("first_seen_at cannot follow last_seen_at.")
        if not isinstance(self.lifecycle_state, FindingLifecycleState):
            raise TypeError("lifecycle_state must use the closed enum.")
        _non_negative_integer(self.reopen_count, "reopen_count")


def _recurring_ordered(value: tuple[MemoryFindingSummary, ...]) -> None:
    for left, right in zip(value, value[1:]):
        if left.occurrence_count < right.occurrence_count:
            raise ValueError("recurring findings are not deterministically ordered.")
        if (
            left.occurrence_count == right.occurrence_count
            and left.last_seen_at < right.last_seen_at
        ):
            raise ValueError("recurring findings are not deterministically ordered.")
        if (
            left.occurrence_count == right.occurrence_count
            and left.last_seen_at == right.last_seen_at
            and left.finding_id > right.finding_id
        ):
            raise ValueError("recurring findings are not deterministically ordered.")


@dataclass(frozen=True, slots=True)
class RecurringFindingsResult:
    operation_id: str
    system_id: str
    findings: tuple[MemoryFindingSummary, ...]
    returned_count: int
    has_more: bool

    def __post_init__(self) -> None:
        _history_operation(self.operation_id)
        _system_id(self.system_id)
        _bounded_result(
            self.findings,
            MemoryFindingSummary,
            self.returned_count,
            self.has_more,
            "findings",
        )
        if len(self.findings) > RECURRING_MAX_LIMIT:
            raise ValueError("recurring findings exceed the supported bound.")
        if any(item.occurrence_count < 2 for item in self.findings):
            raise ValueError("recurring findings require repeated occurrences.")
        _recurring_ordered(self.findings)


@dataclass(frozen=True, slots=True)
class GetFindingTimelineRequest:
    system_id: str
    finding_id: str
    limit: int = TIMELINE_DEFAULT_LIMIT

    def __post_init__(self) -> None:
        _system_id(self.system_id)
        _text(self.finding_id, "finding_id", FINDING_ID_MAX)
        if self.finding_id != self.finding_id.strip():
            raise ValueError("finding_id cannot contain surrounding whitespace.")
        _bounded_limit(self.limit, "limit", TIMELINE_MAX_LIMIT)


@dataclass(frozen=True, slots=True)
class FindingLifecycleEvent:
    event_type: LifecycleEventType
    occurred_at: datetime
    report_id: ReportId
    previous_value: str | None
    current_value: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.event_type, LifecycleEventType):
            raise TypeError("event_type must use the closed lifecycle enum.")
        _aware_datetime(self.occurred_at, "occurred_at")
        _report_identity(self.report_id)
        _optional_text(self.previous_value, "previous_value", 512)
        _optional_text(self.current_value, "current_value", 512)


def _timeline_ordered(value: tuple[FindingLifecycleEvent, ...]) -> None:
    keys = tuple(
        (
            event.occurred_at,
            event.report_id.value,
            -_LIFECYCLE_EVENT_ORDER[event.event_type],
        )
        for event in value
    )
    if any(left < right for left, right in zip(keys, keys[1:])):
        raise ValueError("lifecycle events are not deterministically ordered.")


@dataclass(frozen=True, slots=True)
class FindingTimelineResult:
    operation_id: str
    system_id: str
    finding_id: str
    summary: MemoryFindingSummary
    events: tuple[FindingLifecycleEvent, ...]
    returned_count: int
    has_more: bool

    def __post_init__(self) -> None:
        _history_operation(self.operation_id)
        _system_id(self.system_id)
        _text(self.finding_id, "finding_id", FINDING_ID_MAX)
        if self.finding_id != self.finding_id.strip():
            raise ValueError("finding_id cannot contain surrounding whitespace.")
        if not isinstance(self.summary, MemoryFindingSummary):
            raise TypeError("summary must use the immutable finding contract.")
        if self.summary.finding_id != self.finding_id:
            raise ValueError("timeline summary identity must match finding_id.")
        _bounded_result(
            self.events,
            FindingLifecycleEvent,
            self.returned_count,
            self.has_more,
            "events",
        )
        if len(self.events) > TIMELINE_MAX_LIMIT:
            raise ValueError("timeline events exceed the supported bound.")
        _timeline_ordered(self.events)


@dataclass(frozen=True, slots=True)
class GetScoreHistoryRequest:
    system_id: str
    start_at: datetime
    end_at: datetime
    limit: int = SCORE_HISTORY_DEFAULT_LIMIT
    scoring_version: str | None = None

    def __post_init__(self) -> None:
        _system_id(self.system_id)
        _aware_datetime(self.start_at, "start_at")
        _aware_datetime(self.end_at, "end_at")
        if self.start_at > self.end_at:
            raise ValueError("start_at cannot follow end_at.")
        if self.end_at - self.start_at > timedelta(
            days=SCORE_HISTORY_MAX_RANGE_DAYS
        ):
            raise ValueError("score-history range exceeds 366 days.")
        _bounded_limit(self.limit, "limit", SCORE_HISTORY_MAX_LIMIT)
        if self.scoring_version is not None and (
            type(self.scoring_version) is not str
            or self.scoring_version not in ("1", "2")
        ):
            raise ValueError("scoring_version must be '1', '2', or omitted.")


@dataclass(frozen=True, slots=True)
class ScoreHistoryPoint:
    report_id: ReportId
    observed_at: datetime
    score: int
    risk_level: str
    scoring_version: ScoringVersion

    def __post_init__(self) -> None:
        _report_identity(self.report_id)
        _aware_datetime(self.observed_at, "observed_at")
        _score(self.score, "score")
        _text(self.risk_level, "risk_level", 32)
        _scoring_version(self.scoring_version, "scoring_version")


@dataclass(frozen=True, slots=True)
class ScoreHistorySeries:
    scoring_version: ScoringVersion
    points: tuple[ScoreHistoryPoint, ...]
    returned_count: int
    has_more: bool

    def __post_init__(self) -> None:
        _scoring_version(self.scoring_version, "scoring_version")
        _bounded_result(
            self.points,
            ScoreHistoryPoint,
            self.returned_count,
            self.has_more,
            "points",
        )
        if len(self.points) > SCORE_HISTORY_MAX_LIMIT:
            raise ValueError("score-history points exceed the supported bound.")
        if any(point.scoring_version != self.scoring_version for point in self.points):
            raise ValueError("score series cannot mix scoring versions.")
        keys = tuple(
            (point.observed_at, point.report_id.value) for point in self.points
        )
        if any(left > right for left, right in zip(keys, keys[1:])):
            raise ValueError("score points are not chronologically ordered.")


@dataclass(frozen=True, slots=True)
class ScoreHistoryResult:
    operation_id: str
    system_id: str
    series: tuple[ScoreHistorySeries, ...]

    def __post_init__(self) -> None:
        _history_operation(self.operation_id)
        _system_id(self.system_id)
        _typed_tuple(self.series, ScoreHistorySeries, "series")
        versions = tuple(item.scoring_version for item in self.series)
        if len(set(versions)) != len(versions):
            raise ValueError("score history cannot duplicate a scoring version.")
        if versions != tuple(sorted(versions, key=lambda item: item.value)):
            raise ValueError("score-history series must use deterministic ordering.")


@dataclass(frozen=True, slots=True)
class GetMemoryHealthRequest:
    """Request a read-only, privacy-safe Memory health projection."""


@dataclass(frozen=True, slots=True)
class MemoryHealthDiagnostic:
    severity: MemoryDiagnosticSeverity
    category: MemoryDiagnosticCategory
    code: MemoryDiagnosticCode
    safe_summary: str
    count: int

    def __post_init__(self) -> None:
        if not isinstance(self.severity, MemoryDiagnosticSeverity):
            raise TypeError("severity must use the closed diagnostic enum.")
        if not isinstance(self.category, MemoryDiagnosticCategory):
            raise TypeError("category must use the closed diagnostic enum.")
        if not isinstance(self.code, MemoryDiagnosticCode):
            raise TypeError("code must use the closed diagnostic enum.")
        _text(self.safe_summary, "safe_summary", 512)
        _non_negative_integer(self.count, "count")


@dataclass(frozen=True, slots=True)
class MemoryHealthResult:
    operation_id: str
    health_state: MemoryHealthState
    current_schema_version: int | None
    expected_schema_version: int
    integrity_state: MemoryIntegrityState
    diagnostics: tuple[MemoryHealthDiagnostic, ...]

    def __post_init__(self) -> None:
        _history_operation(self.operation_id)
        if not isinstance(self.health_state, MemoryHealthState):
            raise TypeError("health_state must use the closed health enum.")
        if self.current_schema_version is not None:
            _non_negative_integer(
                self.current_schema_version,
                "current_schema_version",
            )
        if self.expected_schema_version != 8:
            raise ValueError("expected_schema_version must remain Memory schema 8.")
        if not isinstance(self.integrity_state, MemoryIntegrityState):
            raise TypeError("integrity_state must use the closed integrity enum.")
        _typed_tuple(
            self.diagnostics,
            MemoryHealthDiagnostic,
            "diagnostics",
        )
        if len(self.diagnostics) > MEMORY_HEALTH_MAX_DIAGNOSTICS:
            raise ValueError("Memory health diagnostics exceed the supported bound.")


@dataclass(frozen=True, slots=True)
class CapabilityExpectedEffect:
    effect_id: str
    effect_class: EffectClass
    summary: str

    def __post_init__(self) -> None:
        if not isinstance(self.effect_id, str) or _EFFECT_ID.fullmatch(self.effect_id) is None:
            raise ValueError("effect_id has an invalid format.")
        _closed(self.effect_class, EffectClass, "effect_class")
        _f_text(self.summary, "summary", 512)


@dataclass(frozen=True, slots=True)
class CapabilityParameterSpec:
    key: str
    kind: CapabilityParameterKind
    required: bool
    privacy_class: PrivacyClass

    def __post_init__(self) -> None:
        if not isinstance(self.key, str) or _PARAMETER_KEY.fullmatch(self.key) is None:
            raise ValueError("parameter key has an invalid format.")
        _closed(self.kind, CapabilityParameterKind, "kind")
        _boolean(self.required, "required")
        _closed(self.privacy_class, PrivacyClass, "privacy_class")


@dataclass(frozen=True, slots=True)
class CapabilityTarget:
    kind: CapabilityTargetKind
    system_id: str
    report_ids: tuple[ReportId, ...]
    finding_id: str | None

    def __post_init__(self) -> None:
        _closed(self.kind, CapabilityTargetKind, "kind")
        _f_system_id(self.system_id)
        _reject_unsafe_text(self.system_id, "system_id", reject_url=True)
        _f_tuple(self.report_ids, ReportId, "report_ids", maximum=2)
        if len(set(self.report_ids)) != len(self.report_ids):
            raise ValueError("report_ids cannot contain duplicates.")
        if self.finding_id is not None:
            _f_text(self.finding_id, "finding_id", FINDING_ID_MAX)
            if self.finding_id != self.finding_id.strip():
                raise ValueError("finding_id cannot contain surrounding whitespace.")
            _reject_unsafe_text(self.finding_id, "finding_id", reject_url=True)
        if self.kind in (CapabilityTargetKind.APPLICATION, CapabilityTargetKind.SYSTEM):
            if self.report_ids or self.finding_id is not None:
                raise ValueError("application and system targets cannot bind reports or findings.")
        elif self.kind == CapabilityTargetKind.REPORT:
            if len(self.report_ids) not in (1, 2) or self.finding_id is not None:
                raise ValueError("report targets require one or two reports and no finding.")
        elif self.kind == CapabilityTargetKind.FINDING:
            if self.finding_id is None or len(self.report_ids) > 1:
                raise ValueError("finding targets require a finding and at most one report.")


def _expected_effects(value: object) -> None:
    _f_tuple(
        value,
        CapabilityExpectedEffect,
        "expected_effects",
        minimum=1,
        maximum=16,
    )
    effect_ids = tuple(item.effect_id for item in value)
    if effect_ids != tuple(sorted(effect_ids)):
        raise ValueError("expected_effects must be ordered by effect_id.")
    if len(set(effect_ids)) != len(effect_ids):
        raise ValueError("expected_effects cannot duplicate effect_id.")
    semantics = tuple((item.effect_class, item.summary) for item in value)
    if len(set(semantics)) != len(semantics):
        raise ValueError("expected_effects cannot duplicate effect semantics.")


def _parameter_specs(value: object) -> None:
    _f_tuple(
        value,
        CapabilityParameterSpec,
        "parameters",
        maximum=32,
    )
    keys = tuple(item.key for item in value)
    if keys != tuple(sorted(keys)):
        raise ValueError("parameter specs must be ordered by key.")
    if len(set(keys)) != len(keys):
        raise ValueError("parameter specs cannot duplicate keys.")


@dataclass(frozen=True, slots=True)
class CapabilityMetadata:
    capability_id: str
    capability_version: str
    title: str
    summary: str
    effect_class: EffectClass
    permission_class: PermissionClass
    privacy_class: PrivacyClass
    availability: CapabilityAvailability
    expected_effects: tuple[CapabilityExpectedEffect, ...]
    target_kinds: tuple[CapabilityTargetKind, ...]
    parameters: tuple[CapabilityParameterSpec, ...]

    def __post_init__(self) -> None:
        _capability_id(self.capability_id)
        _capability_version(self.capability_version)
        _f_text(self.title, "title", 128)
        _f_text(self.summary, "summary", 1024)
        _closed(self.effect_class, EffectClass, "effect_class")
        _closed(self.permission_class, PermissionClass, "permission_class")
        _closed(self.privacy_class, PrivacyClass, "privacy_class")
        _closed(self.availability, CapabilityAvailability, "availability")
        _expected_effects(self.expected_effects)
        _f_tuple(
            self.target_kinds,
            CapabilityTargetKind,
            "target_kinds",
            minimum=1,
            maximum=4,
        )
        if len(set(self.target_kinds)) != len(self.target_kinds):
            raise ValueError("target_kinds cannot contain duplicates.")
        target_order = {kind: index for index, kind in enumerate(CapabilityTargetKind)}
        if tuple(sorted(self.target_kinds, key=target_order.__getitem__)) != self.target_kinds:
            raise ValueError("target_kinds must follow enum declaration order.")
        _parameter_specs(self.parameters)
        if self.availability == CapabilityAvailability.AVAILABLE and any(
            parameter.privacy_class == PrivacyClass.SECRET
            for parameter in self.parameters
        ):
            raise ValueError("available capabilities cannot accept secret parameters.")


@dataclass(frozen=True, slots=True)
class ProposalParameter:
    key: str
    kind: CapabilityParameterKind
    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.key, str) or _PARAMETER_KEY.fullmatch(self.key) is None:
            raise ValueError("parameter key has an invalid format.")
        _reject_unsafe_text(self.key, "key")
        _closed(self.kind, CapabilityParameterKind, "kind")
        _f_text(self.value, "value", 1024)
        _reject_unsafe_text(self.value, "value")
        if self.kind == CapabilityParameterKind.TEXT:
            if self.value != self.value.strip():
                raise ValueError("text parameter values cannot have surrounding whitespace.")
        elif self.kind == CapabilityParameterKind.INTEGER:
            if _INTEGER_PARAMETER.fullmatch(self.value) is None:
                raise ValueError("integer parameter value is not canonical.")
            parsed = int(self.value)
            if not -(2**63) <= parsed <= 2**63 - 1:
                raise ValueError("integer parameter value is outside signed 64-bit range.")
        elif self.kind == CapabilityParameterKind.BOOLEAN:
            if self.value not in ("true", "false"):
                raise ValueError("boolean parameter value is not canonical.")
        elif self.kind == CapabilityParameterKind.UTC_TIMESTAMP:
            if _UTC_TIMESTAMP_PARAMETER.fullmatch(self.value) is None:
                raise ValueError("timestamp parameter value is not canonical.")
            try:
                datetime.strptime(self.value, "%Y-%m-%dT%H:%M:%S.%fZ")
            except ValueError:
                raise ValueError("timestamp parameter value is invalid.") from None


def _proposal_parameters(value: object) -> None:
    _f_tuple(value, ProposalParameter, "parameters", maximum=32)
    keys = tuple(item.key for item in value)
    if keys != tuple(sorted(keys)):
        raise ValueError("proposal parameters must be ordered by key.")
    if len(set(keys)) != len(keys):
        raise ValueError("proposal parameters cannot duplicate keys.")


@dataclass(frozen=True, slots=True)
class AssistantEvidenceReference:
    evidence_id: str
    source_kind: AssistantEvidenceSourceKind
    source_id: str
    evidence_role: AssistantEvidenceRole
    report_ids: tuple[ReportId, ...]

    def __post_init__(self) -> None:
        _presentation_id(self.evidence_id, "evidence_id")
        _closed(self.source_kind, AssistantEvidenceSourceKind, "source_kind")
        _f_text(self.source_id, "source_id", 512)
        _reject_unsafe_text(self.source_id, "source_id")
        _closed(self.evidence_role, AssistantEvidenceRole, "evidence_role")
        _f_tuple(self.report_ids, ReportId, "report_ids", minimum=1, maximum=2)
        if len(set(self.report_ids)) != len(self.report_ids):
            raise ValueError("evidence report_ids cannot contain duplicates.")
        observed_sources = {
            AssistantEvidenceSourceKind.CANONICAL_REPORT,
            AssistantEvidenceSourceKind.REPORT_FINDING,
        }
        expected_role = (
            AssistantEvidenceRole.OBSERVED_FACT
            if self.source_kind in observed_sources
            else AssistantEvidenceRole.DETERMINISTIC_DERIVATION
        )
        if self.evidence_role != expected_role:
            raise ValueError("evidence source and role are incompatible.")
        if self.source_kind == AssistantEvidenceSourceKind.CANONICAL_REPORT:
            if len(self.report_ids) != 1 or self.source_id != self.report_ids[0].value:
                raise ValueError("canonical-report evidence binding is invalid.")
        elif self.source_kind == AssistantEvidenceSourceKind.REPORT_FINDING:
            if len(self.report_ids) != 1:
                raise ValueError("finding evidence must bind exactly one report.")
        elif self.source_kind == AssistantEvidenceSourceKind.REPORT_COMPARISON:
            if len(self.report_ids) != 2:
                raise ValueError("comparison evidence must bind exactly two reports.")


@dataclass(frozen=True, slots=True)
class AssistantClaim:
    claim_id: str
    text: str
    epistemic_state: EpistemicState
    evidence_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        _presentation_id(self.claim_id, "claim_id")
        _f_text(self.text, "text", 2048)
        _reject_unsafe_text(self.text, "text")
        _closed(self.epistemic_state, EpistemicState, "epistemic_state")
        if not isinstance(self.evidence_refs, tuple) or not all(
            isinstance(item, str) for item in self.evidence_refs
        ):
            raise TypeError("evidence_refs must be an immutable text tuple.")
        if not 1 <= len(self.evidence_refs) <= 16:
            raise ValueError("evidence_refs is outside the supported bound.")
        for evidence_id in self.evidence_refs:
            _presentation_id(evidence_id, "evidence_ref")
        if len(set(self.evidence_refs)) != len(self.evidence_refs):
            raise ValueError("evidence_refs cannot contain duplicates.")


@dataclass(frozen=True, slots=True)
class AssistantSection:
    section_id: AssistantSectionId
    title: str
    claims: tuple[AssistantClaim, ...]
    omitted_item_count: int

    def __post_init__(self) -> None:
        _closed(self.section_id, AssistantSectionId, "section_id")
        _f_text(self.title, "title", 128)
        _reject_unsafe_text(self.title, "title")
        _f_tuple(self.claims, AssistantClaim, "claims", maximum=64)
        if not self.claims and self.section_id != AssistantSectionId.PRIORITIES:
            raise ValueError("only the priorities section may be empty.")
        if (
            isinstance(self.omitted_item_count, bool)
            or not isinstance(self.omitted_item_count, int)
            or not 0 <= self.omitted_item_count <= 65536
        ):
            raise ValueError("omitted_item_count is outside the supported bound.")


def _evidence_order(item: AssistantEvidenceReference) -> tuple[object, ...]:
    return (
        item.source_kind.value,
        item.source_id,
        item.evidence_role.value,
        tuple(report_id.value for report_id in item.report_ids),
        item.evidence_id,
    )


@dataclass(frozen=True, slots=True)
class AssistantGroundedResponse:
    sections: tuple[AssistantSection, ...]
    evidence: tuple[AssistantEvidenceReference, ...]

    def __post_init__(self) -> None:
        _f_tuple(self.sections, AssistantSection, "sections", minimum=1, maximum=16)
        section_ids = tuple(section.section_id for section in self.sections)
        if len(set(section_ids)) != len(section_ids):
            raise ValueError("response sections cannot duplicate identifiers.")
        precedence = {section: index for index, section in enumerate(AssistantSectionId)}
        if tuple(sorted(section_ids, key=precedence.__getitem__)) != section_ids:
            raise ValueError("response sections must follow canonical precedence.")
        claims = tuple(claim for section in self.sections for claim in section.claims)
        if len(claims) > 64:
            raise ValueError("response contains too many claims.")
        if sum(len(claim.text) for claim in claims) > 65536:
            raise ValueError("response claim text exceeds the aggregate bound.")
        claim_ids = tuple(claim.claim_id for claim in claims)
        if len(set(claim_ids)) != len(claim_ids):
            raise ValueError("response claims cannot duplicate identifiers.")
        _f_tuple(
            self.evidence,
            AssistantEvidenceReference,
            "evidence",
            minimum=1,
            maximum=128,
        )
        evidence_ids = tuple(item.evidence_id for item in self.evidence)
        if len(set(evidence_ids)) != len(evidence_ids):
            raise ValueError("response evidence cannot duplicate identifiers.")
        semantic_keys = tuple(
            (item.source_kind, item.source_id, item.evidence_role, item.report_ids)
            for item in self.evidence
        )
        if len(set(semantic_keys)) != len(semantic_keys):
            raise ValueError("response evidence cannot duplicate semantic identity.")
        if tuple(sorted(self.evidence, key=_evidence_order)) != self.evidence:
            raise ValueError("response evidence must use canonical ordering.")
        evidence_by_id = {item.evidence_id: item for item in self.evidence}
        evidence_position = {
            item.evidence_id: index for index, item in enumerate(self.evidence)
        }
        referenced: set[str] = set()
        for claim in claims:
            if any(item not in evidence_by_id for item in claim.evidence_refs):
                raise ValueError("claim references missing evidence.")
            positions = tuple(evidence_position[item] for item in claim.evidence_refs)
            if positions != tuple(sorted(positions)):
                raise ValueError("claim evidence references must follow response order.")
            referenced.update(claim.evidence_refs)
            roles = tuple(evidence_by_id[item].evidence_role for item in claim.evidence_refs)
            if claim.epistemic_state == EpistemicState.OBSERVED and any(
                role != AssistantEvidenceRole.OBSERVED_FACT for role in roles
            ):
                raise ValueError("observed claims require observed-fact evidence only.")
            if claim.epistemic_state == EpistemicState.STRONGLY_SUPPORTED and (
                AssistantEvidenceRole.OBSERVED_FACT not in roles
            ):
                raise ValueError("strongly supported claims require observed evidence.")
        if referenced != set(evidence_ids):
            raise ValueError("every evidence item must support at least one claim.")


def _report_selection(
    system_id: object,
    current_report_id: object,
    previous_report_id: object,
) -> None:
    _f_system_id(system_id)
    _report_identity(current_report_id, "current_report_id")
    if previous_report_id is not None:
        _report_identity(previous_report_id, "previous_report_id")
        if previous_report_id == current_report_id:
            raise ValueError("previous and current report IDs must differ.")


@dataclass(frozen=True, slots=True)
class SecurityBriefingRequest:
    system_id: str
    current_report_id: ReportId
    previous_report_id: ReportId | None

    def __post_init__(self) -> None:
        _report_selection(
            self.system_id,
            self.current_report_id,
            self.previous_report_id,
        )


@dataclass(frozen=True, slots=True)
class AssistantQuestionRequest:
    system_id: str
    current_report_id: ReportId
    previous_report_id: ReportId | None
    question: str

    def __post_init__(self) -> None:
        _report_selection(
            self.system_id,
            self.current_report_id,
            self.previous_report_id,
        )
        _f_text(self.question, "question", 4096)


def _result_report_context(
    system_id: object,
    current_report: object,
    previous_report: object,
) -> None:
    _f_system_id(system_id)
    if not isinstance(current_report, SavedReportReference):
        raise TypeError("current_report must use the immutable report reference.")
    _utc_datetime(current_report.generated_at, "current_report.generated_at")
    if previous_report is not None:
        if not isinstance(previous_report, SavedReportReference):
            raise TypeError("previous_report must use the immutable report reference.")
        _utc_datetime(previous_report.generated_at, "previous_report.generated_at")
        previous_key = (previous_report.generated_at, previous_report.report_id.value)
        current_key = (current_report.generated_at, current_report.report_id.value)
        if previous_key >= current_key:
            raise ValueError("report result chronology is invalid.")


@dataclass(frozen=True, slots=True)
class SecurityBriefingResult:
    operation_id: str
    system_id: str
    current_report: SavedReportReference
    previous_report: SavedReportReference | None
    response: AssistantGroundedResponse

    def __post_init__(self) -> None:
        _assistant_operation(self.operation_id)
        _result_report_context(self.system_id, self.current_report, self.previous_report)
        if not isinstance(self.response, AssistantGroundedResponse):
            raise TypeError("response must use the immutable grounded response.")


@dataclass(frozen=True, slots=True)
class AssistantQuestionResult:
    operation_id: str
    system_id: str
    current_report: SavedReportReference
    previous_report: SavedReportReference | None
    status: AssistantQuestionStatus
    intent: AssistantIntent | None
    response: AssistantGroundedResponse | None

    def __post_init__(self) -> None:
        _assistant_operation(self.operation_id)
        _result_report_context(self.system_id, self.current_report, self.previous_report)
        _closed(self.status, AssistantQuestionStatus, "status")
        if self.intent is not None:
            _closed(self.intent, AssistantIntent, "intent")
        if self.response is not None and not isinstance(
            self.response, AssistantGroundedResponse
        ):
            raise TypeError("response must use the immutable grounded response.")
        if self.status == AssistantQuestionStatus.ANSWERED:
            if self.intent is None or self.response is None:
                raise ValueError("answered results require intent and response.")
        elif self.status == AssistantQuestionStatus.MISSING_CONTEXT:
            if self.intent != AssistantIntent.WHAT_CHANGED or self.response is not None:
                raise ValueError("missing-context results require only WHAT_CHANGED intent.")
        elif self.intent is not None or self.response is not None:
            raise ValueError("unsupported and ambiguous results carry no intent or response.")


@dataclass(frozen=True, slots=True)
class ListCapabilitiesRequest:
    """Request the static application capability metadata."""


@dataclass(frozen=True, slots=True)
class CapabilityCatalogResult:
    operation_id: str
    capabilities: tuple[CapabilityMetadata, ...]
    returned_count: int

    def __post_init__(self) -> None:
        _assistant_operation(self.operation_id)
        _f_tuple(self.capabilities, CapabilityMetadata, "capabilities", maximum=64)
        if (
            isinstance(self.returned_count, bool)
            or not isinstance(self.returned_count, int)
            or not 0 <= self.returned_count <= 64
            or self.returned_count != len(self.capabilities)
        ):
            raise ValueError("returned_count must equal the bounded catalog length.")
        identities = tuple(
            (item.capability_id, item.capability_version)
            for item in self.capabilities
        )
        if len(set(identities)) != len(identities):
            raise ValueError("capability catalog cannot contain duplicate identities.")
        expected = tuple(
            sorted(
                self.capabilities,
                key=lambda item: (item.capability_id, int(item.capability_version)),
            )
        )
        if expected != self.capabilities:
            raise ValueError("capability catalog must use canonical ordering.")


@dataclass(frozen=True, slots=True)
class ProposeCapabilityRequest:
    system_id: str
    capability_id: str
    capability_version: str
    target: CapabilityTarget
    parameters: tuple[ProposalParameter, ...]

    def __post_init__(self) -> None:
        _f_system_id(self.system_id)
        _capability_id(self.capability_id)
        _capability_version(self.capability_version)
        if not isinstance(self.target, CapabilityTarget):
            raise TypeError("target must use the immutable capability target.")
        if self.system_id != self.target.system_id:
            raise ValueError("request and target system_id must match exactly.")
        _proposal_parameters(self.parameters)


@dataclass(frozen=True, slots=True)
class CapabilityProposal:
    proposal_id: str
    system_id: str
    capability_id: str
    capability_version: str
    target: CapabilityTarget
    target_digest: str
    parameters: tuple[ProposalParameter, ...]
    parameter_digest: str
    effect_class: EffectClass
    permission_class: PermissionClass
    privacy_class: PrivacyClass
    expected_effects: tuple[CapabilityExpectedEffect, ...]
    issued_at: datetime
    expires_at: datetime
    reuse_policy: ReusePolicy

    def __post_init__(self) -> None:
        if not isinstance(self.proposal_id, str) or _PROPOSAL_ID.fullmatch(self.proposal_id) is None:
            raise ValueError("proposal_id has an invalid format.")
        _f_system_id(self.system_id)
        _capability_id(self.capability_id)
        _capability_version(self.capability_version)
        if not isinstance(self.target, CapabilityTarget):
            raise TypeError("target must use the immutable capability target.")
        if self.system_id != self.target.system_id:
            raise ValueError("proposal and target system_id must match exactly.")
        _digest(self.target_digest, "target_digest")
        _proposal_parameters(self.parameters)
        _digest(self.parameter_digest, "parameter_digest")
        _closed(self.effect_class, EffectClass, "effect_class")
        _closed(self.permission_class, PermissionClass, "permission_class")
        _closed(self.privacy_class, PrivacyClass, "privacy_class")
        _expected_effects(self.expected_effects)
        _utc_datetime(self.issued_at, "issued_at")
        _utc_datetime(self.expires_at, "expires_at")
        if self.expires_at != self.issued_at + timedelta(minutes=10):
            raise ValueError("proposal expiry must be exactly ten minutes.")
        _closed(self.reuse_policy, ReusePolicy, "reuse_policy")
        if self.reuse_policy != ReusePolicy.ONE_TIME:
            raise ValueError("proposal reuse policy must be ONE_TIME.")


@dataclass(frozen=True, slots=True)
class ProposeCapabilityResult:
    operation_id: str
    proposal: CapabilityProposal

    def __post_init__(self) -> None:
        _assistant_operation(self.operation_id)
        if not isinstance(self.proposal, CapabilityProposal):
            raise TypeError("proposal must use the immutable proposal contract.")
