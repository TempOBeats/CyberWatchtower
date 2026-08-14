"""Typed, non-sensitive operational integrity contracts."""

from dataclasses import dataclass
from enum import Enum


class DiagnosticSeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class DiagnosticCategory(str, Enum):
    SQLITE = "SQLITE"
    MIGRATION = "MIGRATION"
    SCHEMA = "SCHEMA"
    REPORT = "REPORT"
    LIFECYCLE = "LIFECYCLE"
    RELATIONSHIP = "RELATIONSHIP"
    DECISION = "DECISION"


class ReportVerificationStatus(str, Enum):
    VERIFIED = "VERIFIED"
    SOURCE_MISSING = "SOURCE_MISSING"
    SOURCE_INACCESSIBLE = "SOURCE_INACCESSIBLE"
    DIGEST_MISMATCH = "DIGEST_MISMATCH"
    INVALID_SOURCE = "INVALID_SOURCE"
    REPORT_NOT_FOUND = "REPORT_NOT_FOUND"


@dataclass(frozen=True)
class IntegrityDiagnostic:
    severity: DiagnosticSeverity
    category: DiagnosticCategory
    code: str
    summary: str
    count: int = 1


@dataclass(frozen=True)
class IntegrityReport:
    health: str
    schema_version: int | None
    diagnostics: tuple[IntegrityDiagnostic, ...]


@dataclass(frozen=True)
class ReportVerification:
    report_id: str
    status: ReportVerificationStatus


@dataclass(frozen=True)
class MemoryStatus:
    health: str
    schema_version: int
    latest_report_at: str | None
    safe_counts: tuple[tuple[str, int], ...]
    active_exception_count: int
    pending_exception_count: int
    expired_exception_count: int
    retention_eligible_count: int
    diagnostic_counts: tuple[tuple[str, int], ...]
