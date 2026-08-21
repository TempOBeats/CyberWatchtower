from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from cyberwatchtower.report_contracts import (
    LegacyIdentityResolution,
    LegacyLinkPolicy,
)


class IngestionStatus(str, Enum):
    INGESTED = "INGESTED"
    DUPLICATE = "DUPLICATE"
    INVALID = "INVALID"
    UNSUPPORTED_SCHEMA = "UNSUPPORTED_SCHEMA"
    IDENTITY_UNRESOLVED = "IDENTITY_UNRESOLVED"
    IDENTITY_CONFLICT = "IDENTITY_CONFLICT"
    FAILED = "FAILED"


class DiagnosticSeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


@dataclass(frozen=True)
class IngestionDiagnostic:
    code: str
    message: str
    severity: DiagnosticSeverity
    field: str | None = None


@dataclass(frozen=True)
class ReportIngestionRequest:
    path: Path
    expected_system_id: str | None = None
    legacy_link_policy: LegacyLinkPolicy = LegacyLinkPolicy.REQUIRE_NATIVE_SYSTEM_ID


@dataclass(frozen=True)
class ReportIngestionResult:
    status: IngestionStatus
    report_id: str | None
    system_id: str | None
    content_digest: str | None
    schema_version: str | None
    identity_resolution: LegacyIdentityResolution | None
    diagnostics: tuple[IngestionDiagnostic, ...] = ()


@dataclass(frozen=True)
class NormalizedScore:
    scoring_version: str
    score: int
    risk_level: str
    counts: tuple[tuple[str, int], ...]


@dataclass(frozen=True)
class NormalizedFinding:
    finding_id: str
    title: str
    description: str
    severity: str
    recommendation: str
    confidence: int
    technique_id: str | None
    source: str
    kind: str
    assessment_state: str
    metadata_inferred: bool
    evidence: tuple[str, ...]
    runtime_instance_count: int = 1


@dataclass(frozen=True)
class NormalizedReport:
    schema_version: str
    generated_at: str
    native_system_id: str | None
    hostname: str
    coverage: tuple[tuple[str, str], ...]
    score: NormalizedScore
    findings: tuple[NormalizedFinding, ...]
