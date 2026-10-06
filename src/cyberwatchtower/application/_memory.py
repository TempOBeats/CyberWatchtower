"""Private storage-neutral seams for future WS1-E Memory operations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
from typing import Protocol

from cyberwatchtower.memory.errors import (
    MemoryCorrupt,
    MemoryIncompatibleVersion,
    MemoryIntegrityError,
    MemoryLifecycleError,
    MemoryLocked,
    MemoryMigrationFailed,
    MemoryQueryError,
    MemoryUnavailable,
)
from cyberwatchtower.memory.ingestion import MAX_REPORT_BYTES
from cyberwatchtower.memory.ingestion_models import NormalizedReport
from cyberwatchtower.memory.ingestion_models import IngestionStatus
from cyberwatchtower.memory.service import SQLiteSecurityMemory

from ._privacy import _required_text_is_sensitive

from .contracts import (
    AssessmentState,
    FindingKind,
    FindingLifecycleState,
    LifecycleEventType,
    MemoryDiagnosticCategory,
    MemoryDiagnosticCode,
    MemoryDiagnosticSeverity,
    MemoryHealthState,
    MemoryFindingSummary,
    MemoryIngestionStatus,
    MemoryIntegrityState,
    FindingLifecycleEvent,
    FindingTimelineResult,
    GetFindingTimelineRequest,
    GetMemoryHealthRequest,
    GetScoreHistoryRequest,
    ListRecurringFindingsRequest,
    MemoryHealthDiagnostic,
    MemoryHealthResult,
    RecurringFindingsResult,
    ReportId,
    IngestSavedReportIntoMemoryRequest,
    ScoreHistoryPoint,
    ScoreHistoryResult,
    ScoreHistorySeries,
    ScoringVersion,
    Severity,
    _aware_datetime,
    _system_id,
    _text,
)
from .errors import ApplicationComponent, ApplicationErrorCode


_CANONICAL_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MEMORY_DATABASE_ENVIRONMENT = "CYBERWATCHTOWER_MEMORY_DB"
_MEMORY_SCHEMA_VERSION = 8


class _MemoryOperationFailure(Exception):
    """Carry a closed classification without retaining storage details."""

    def __init__(
        self,
        code: ApplicationErrorCode,
        *,
        retryable: bool = False,
        component: ApplicationComponent = ApplicationComponent.STORAGE,
    ) -> None:
        self.code = code
        self.component = component
        self.retryable = retryable
        super().__init__(code.value)


def _memory_failure(error: BaseException) -> _MemoryOperationFailure:
    if isinstance(error, MemoryIncompatibleVersion):
        return _MemoryOperationFailure(ApplicationErrorCode.COMPATIBILITY_FAILURE)
    if isinstance(
        error,
        (MemoryMigrationFailed, MemoryCorrupt, MemoryIntegrityError, MemoryLifecycleError),
    ):
        return _MemoryOperationFailure(ApplicationErrorCode.INTEGRITY_FAILURE)
    if isinstance(error, MemoryLocked):
        return _MemoryOperationFailure(
            ApplicationErrorCode.STORAGE_FAILURE,
            retryable=True,
        )
    if isinstance(error, PermissionError):
        return _MemoryOperationFailure(ApplicationErrorCode.PERMISSION_DENIED)
    if isinstance(error, MemoryQueryError):
        return _MemoryOperationFailure(ApplicationErrorCode.STORAGE_FAILURE)
    if isinstance(error, (MemoryUnavailable, OSError)):
        return _MemoryOperationFailure(ApplicationErrorCode.STORAGE_FAILURE)
    return _MemoryOperationFailure(ApplicationErrorCode.INTERNAL_FAILURE)


def _valid_ingest_saved_report_request(value: object) -> bool:
    if type(value) is not IngestSavedReportIntoMemoryRequest:
        return False
    try:
        _system_id(value.system_id)
        if type(value.report_id) is not ReportId:
            return False
        ReportId(value.report_id.value)
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def _valid_request(value: object, expected: type) -> bool:
    if type(value) is not expected:
        return False
    try:
        expected(**{
            field: getattr(value, field)
            for field in expected.__dataclass_fields__
        })
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def _valid_list_recurring_findings_request(value: object) -> bool:
    return _valid_request(value, ListRecurringFindingsRequest)


def _valid_get_finding_timeline_request(value: object) -> bool:
    return _valid_request(value, GetFindingTimelineRequest)


def _valid_get_score_history_request(value: object) -> bool:
    return _valid_request(value, GetScoreHistoryRequest)


def _valid_get_memory_health_request(value: object) -> bool:
    return _valid_request(value, GetMemoryHealthRequest)


@dataclass(frozen=True, slots=True)
class _TrustedReportMaterial:
    """Pathless, repository-approved report material for private ingestion."""

    report_id: ReportId
    canonical_digest: str
    canonical_bytes: bytes
    normalized_report: NormalizedReport
    system_id: str
    schema_version: str
    generated_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.report_id, ReportId):
            raise TypeError("trusted material requires the canonical ReportId.")
        if (
            not isinstance(self.canonical_digest, str)
            or _CANONICAL_DIGEST.fullmatch(self.canonical_digest) is None
        ):
            raise ValueError("canonical_digest must be lowercase SHA-256.")
        if not isinstance(self.canonical_bytes, bytes):
            raise TypeError("canonical_bytes must be immutable bytes.")
        if len(self.canonical_bytes) > MAX_REPORT_BYTES:
            raise ValueError("canonical_bytes exceed the trusted report bound.")
        if hashlib.sha256(self.canonical_bytes).hexdigest() != self.canonical_digest:
            raise ValueError("canonical bytes do not match canonical_digest.")
        if self.report_id.value != f"report:{self.canonical_digest}":
            raise ValueError("ReportId and canonical_digest are inconsistent.")
        if not isinstance(self.normalized_report, NormalizedReport):
            raise TypeError("normalized_report must use the compatibility authority.")
        _system_id(self.system_id)
        _text(self.schema_version, "schema_version", 32)
        _aware_datetime(self.generated_at, "generated_at")
        if self.normalized_report.native_system_id != self.system_id:
            raise ValueError("normalized report system identity is inconsistent.")
        if self.normalized_report.schema_version != self.schema_version:
            raise ValueError("normalized report schema version is inconsistent.")
        try:
            normalized_generated_at = datetime.fromisoformat(
                self.normalized_report.generated_at.replace("Z", "+00:00")
            )
        except (AttributeError, ValueError) as exc:
            raise ValueError("normalized report chronology is inconsistent.") from exc
        if (
            normalized_generated_at.tzinfo is None
            or normalized_generated_at.utcoffset() is None
            or normalized_generated_at.astimezone(timezone.utc)
            != self.generated_at.astimezone(timezone.utc)
        ):
            raise ValueError("normalized report chronology is inconsistent.")


@dataclass(frozen=True, slots=True)
class _MemoryIngestionRecord:
    status: MemoryIngestionStatus
    schema_version: str


@dataclass(frozen=True, slots=True)
class _MemoryFindingRecord:
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


@dataclass(frozen=True, slots=True)
class _MemoryRecurringPage:
    findings: tuple[_MemoryFindingRecord, ...]
    has_more: bool


@dataclass(frozen=True, slots=True)
class _MemoryLifecycleEventRecord:
    event_type: LifecycleEventType
    occurred_at: datetime
    canonical_digest: str
    previous_value: str | None
    current_value: str | None


@dataclass(frozen=True, slots=True)
class _MemoryTimelineRecord:
    summary: _MemoryFindingRecord
    events: tuple[_MemoryLifecycleEventRecord, ...]
    has_more: bool


@dataclass(frozen=True, slots=True)
class _MemoryScorePointRecord:
    canonical_digest: str
    observed_at: datetime
    score: int
    risk_level: str
    scoring_version: ScoringVersion


@dataclass(frozen=True, slots=True)
class _MemoryScoreSeriesRecord:
    scoring_version: ScoringVersion
    points: tuple[_MemoryScorePointRecord, ...]
    has_more: bool


@dataclass(frozen=True, slots=True)
class _MemoryHealthDiagnosticRecord:
    severity: MemoryDiagnosticSeverity
    category: MemoryDiagnosticCategory
    code: MemoryDiagnosticCode
    safe_summary: str
    count: int


@dataclass(frozen=True, slots=True)
class _MemoryHealthRecord:
    health_state: MemoryHealthState
    current_schema_version: int | None
    integrity_state: MemoryIntegrityState
    diagnostics: tuple[_MemoryHealthDiagnosticRecord, ...]


def _stored_datetime(value: object) -> datetime:
    if not isinstance(value, str):
        raise _MemoryOperationFailure(ApplicationErrorCode.INTEGRITY_FAILURE)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise _MemoryOperationFailure(
            ApplicationErrorCode.INTEGRITY_FAILURE
        ) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise _MemoryOperationFailure(ApplicationErrorCode.INTEGRITY_FAILURE)
    return parsed.astimezone(timezone.utc)


def _public_report_id(digest: object) -> ReportId:
    if not isinstance(digest, str) or _CANONICAL_DIGEST.fullmatch(digest) is None:
        raise _MemoryOperationFailure(ApplicationErrorCode.INTEGRITY_FAILURE)
    try:
        return ReportId(f"report:{digest}")
    except (TypeError, ValueError):
        raise _MemoryOperationFailure(
            ApplicationErrorCode.INTEGRITY_FAILURE
        ) from None


def _finding_record(value: object) -> _MemoryFindingRecord:
    try:
        finding_id = value.finding_id
        title = value.latest_title
        source = value.latest_source
        if _required_text_is_sensitive((finding_id, title, source)):
            raise _MemoryOperationFailure(
                ApplicationErrorCode.PRIVACY_POLICY_BLOCKED,
                component=ApplicationComponent.PRIVACY,
            )
        return _MemoryFindingRecord(
            finding_id=finding_id,
            title=title,
            severity=Severity(value.latest_severity),
            source=source,
            kind=FindingKind(value.latest_kind),
            assessment_state=AssessmentState(value.latest_assessment_state),
            occurrence_count=value.occurrence_count,
            first_seen_at=_stored_datetime(value.first_seen_at),
            last_seen_at=_stored_datetime(value.last_seen_at),
            lifecycle_state=FindingLifecycleState(value.lifecycle_state),
            reopen_count=value.reopened_count,
        )
    except _MemoryOperationFailure:
        raise
    except (AttributeError, TypeError, ValueError):
        raise _MemoryOperationFailure(
            ApplicationErrorCode.INTEGRITY_FAILURE
        ) from None


def _public_finding(value: _MemoryFindingRecord) -> MemoryFindingSummary:
    try:
        if _required_text_is_sensitive(
            (value.finding_id, value.title, value.source)
        ):
            raise _MemoryOperationFailure(
                ApplicationErrorCode.PRIVACY_POLICY_BLOCKED,
                component=ApplicationComponent.PRIVACY,
            )
        return MemoryFindingSummary(
            finding_id=value.finding_id,
            title=value.title,
            severity=value.severity,
            source=value.source,
            kind=value.kind,
            assessment_state=value.assessment_state,
            occurrence_count=value.occurrence_count,
            first_seen_at=value.first_seen_at,
            last_seen_at=value.last_seen_at,
            lifecycle_state=value.lifecycle_state,
            reopen_count=value.reopen_count,
        )
    except _MemoryOperationFailure:
        raise
    except (TypeError, ValueError):
        raise _MemoryOperationFailure(
            ApplicationErrorCode.INTEGRITY_FAILURE
        ) from None


def _health_record(
    health_state: MemoryHealthState,
    integrity_state: MemoryIntegrityState,
    code: MemoryDiagnosticCode,
    *,
    current_schema_version: int | None,
    category: MemoryDiagnosticCategory,
    severity: MemoryDiagnosticSeverity,
    summary: str,
    count: int = 1,
) -> _MemoryHealthRecord:
    return _MemoryHealthRecord(
        health_state,
        current_schema_version,
        integrity_state,
        (_MemoryHealthDiagnosticRecord(
            severity,
            category,
            code,
            summary,
            count,
        ),),
    )


def _disabled_health() -> _MemoryHealthRecord:
    return _health_record(
        MemoryHealthState.DISABLED,
        MemoryIntegrityState.NOT_CHECKED,
        MemoryDiagnosticCode.DISABLED,
        current_schema_version=None,
        category=MemoryDiagnosticCategory.CONFIGURATION,
        severity=MemoryDiagnosticSeverity.INFO,
        summary="Persistent Security Memory is disabled.",
    )


class _MemoryPort(Protocol):
    """One-operation-owned, storage-neutral Memory boundary."""

    def ingest_trusted_report(
        self,
        material: _TrustedReportMaterial,
    ) -> _MemoryIngestionRecord:
        ...

    def recurring_findings(
        self,
        *,
        system_id: str,
        limit: int,
        active_only: bool,
    ) -> _MemoryRecurringPage:
        ...

    def finding_timeline(
        self,
        *,
        system_id: str,
        finding_id: str,
        limit: int,
    ) -> _MemoryTimelineRecord | None:
        ...

    def score_history(
        self,
        *,
        system_id: str,
        start_at: datetime,
        end_at: datetime,
        limit: int,
        scoring_version: str | None,
    ) -> tuple[_MemoryScoreSeriesRecord, ...]:
        ...

    def health(self) -> _MemoryHealthRecord:
        ...

    def close(self) -> None:
        ...


class _MemoryFactory(Protocol):
    """Select read-only or writable ownership without exposing a DB path."""

    def open_read_only(self) -> _MemoryPort | None:
        ...

    def open_writable(self) -> _MemoryPort | None:
        ...

    def inspect_health(self) -> _MemoryHealthRecord:
        ...


class _SQLiteMemoryPort:
    """Private adapter that owns one writable Memory handle per operation."""

    __slots__ = ("_memory", "_closed")

    def __init__(self, memory: SQLiteSecurityMemory) -> None:
        self._memory = memory
        self._closed = False

    def ingest_trusted_report(
        self,
        material: _TrustedReportMaterial,
    ) -> _MemoryIngestionRecord:
        if self._closed or type(material) is not _TrustedReportMaterial:
            raise _MemoryOperationFailure(ApplicationErrorCode.INTEGRITY_FAILURE)
        if len(material.canonical_bytes) > MAX_REPORT_BYTES:
            raise _MemoryOperationFailure(ApplicationErrorCode.INTEGRITY_FAILURE)
        try:
            result = self._memory._ingest_trusted_report(
                public_report_id=material.report_id.value,
                canonical_digest=material.canonical_digest,
                canonical_bytes=material.canonical_bytes,
                normalized_report=material.normalized_report,
                expected_system_id=material.system_id,
                generated_at=material.generated_at,
            )
        except Exception as error:
            failure = _memory_failure(error)
            raise failure from None
        if result.status == IngestionStatus.INGESTED:
            status = MemoryIngestionStatus.INGESTED
        elif result.status == IngestionStatus.DUPLICATE:
            status = MemoryIngestionStatus.ALREADY_PRESENT
        else:
            raise _MemoryOperationFailure(ApplicationErrorCode.INTEGRITY_FAILURE)
        if (
            result.system_id != material.system_id
            or result.content_digest != material.canonical_digest
            or result.schema_version != material.schema_version
        ):
            raise _MemoryOperationFailure(ApplicationErrorCode.INTEGRITY_FAILURE)
        return _MemoryIngestionRecord(status, result.schema_version)

    def recurring_findings(
        self,
        *,
        system_id: str,
        limit: int,
        active_only: bool,
    ) -> _MemoryRecurringPage:
        if self._closed:
            raise _MemoryOperationFailure(ApplicationErrorCode.INTEGRITY_FAILURE)
        try:
            page = self._memory._recurring_findings_page(
                system_id=system_id,
                limit=limit,
                active_only=active_only,
            )
            return _MemoryRecurringPage(
                tuple(_finding_record(item) for item in page.findings),
                page.has_more,
            )
        except _MemoryOperationFailure:
            raise
        except (AttributeError, TypeError, ValueError):
            raise _MemoryOperationFailure(
                ApplicationErrorCode.INTEGRITY_FAILURE
            ) from None
        except Exception as error:
            raise _memory_failure(error) from None

    def finding_timeline(
        self,
        *,
        system_id: str,
        finding_id: str,
        limit: int,
    ) -> _MemoryTimelineRecord | None:
        if self._closed:
            raise _MemoryOperationFailure(ApplicationErrorCode.INTEGRITY_FAILURE)
        try:
            timeline = self._memory._finding_timeline_page(
                system_id=system_id,
                finding_id=finding_id,
                limit=limit,
            )
            if timeline is None:
                return None
            events = tuple(_MemoryLifecycleEventRecord(
                LifecycleEventType(event.event_type),
                _stored_datetime(event.occurred_at),
                _public_report_id(event.content_digest).value.removeprefix("report:"),
                event.previous_value,
                event.current_value,
            ) for event in timeline.events)
            return _MemoryTimelineRecord(
                _finding_record(timeline.summary),
                events,
                timeline.has_more,
            )
        except _MemoryOperationFailure:
            raise
        except (AttributeError, TypeError, ValueError):
            raise _MemoryOperationFailure(
                ApplicationErrorCode.INTEGRITY_FAILURE
            ) from None
        except Exception as error:
            raise _memory_failure(error) from None

    def score_history(
        self,
        *,
        system_id: str,
        start_at: datetime,
        end_at: datetime,
        limit: int,
        scoring_version: str | None,
    ) -> tuple[_MemoryScoreSeriesRecord, ...]:
        if self._closed:
            raise _MemoryOperationFailure(ApplicationErrorCode.INTEGRITY_FAILURE)
        try:
            series = self._memory._score_history_series(
                system_id=system_id,
                start_at=start_at,
                end_at=end_at,
                limit=limit,
                scoring_version=scoring_version,
            )
            return tuple(_MemoryScoreSeriesRecord(
                ScoringVersion(item.scoring_version),
                tuple(_MemoryScorePointRecord(
                    _public_report_id(point.content_digest).value.removeprefix("report:"),
                    _stored_datetime(point.observed_at),
                    point.score,
                    point.risk_level,
                    ScoringVersion(point.scoring_version),
                ) for point in item.points),
                item.has_more,
            ) for item in series)
        except _MemoryOperationFailure:
            raise
        except (AttributeError, TypeError, ValueError):
            raise _MemoryOperationFailure(
                ApplicationErrorCode.INTEGRITY_FAILURE
            ) from None
        except Exception as error:
            raise _memory_failure(error) from None

    def health(self) -> _MemoryHealthRecord:
        if self._closed:
            raise _MemoryOperationFailure(ApplicationErrorCode.INTEGRITY_FAILURE)
        try:
            report = self._memory._health_snapshot()
        except Exception as error:
            raise _memory_failure(error) from None
        if report.health == "UNAVAILABLE" or report.schema_version is None:
            return _health_record(
                MemoryHealthState.UNAVAILABLE,
                MemoryIntegrityState.UNAVAILABLE,
                MemoryDiagnosticCode.UNAVAILABLE,
                current_schema_version=report.schema_version,
                category=MemoryDiagnosticCategory.STORAGE,
                severity=MemoryDiagnosticSeverity.ERROR,
                summary="Persistent Security Memory could not be inspected safely.",
            )
        errors = sum(
            item.count for item in report.diagnostics
            if item.severity.value == "ERROR"
        )
        warnings = sum(
            item.count for item in report.diagnostics
            if item.severity.value == "WARNING"
        )
        budget_exhausted = SQLiteSecurityMemory._health_budget_exhausted(report)
        if errors:
            return _health_record(
                MemoryHealthState.CORRUPT,
                MemoryIntegrityState.FAIL,
                MemoryDiagnosticCode.INTEGRITY_FAILURE,
                current_schema_version=report.schema_version,
                category=MemoryDiagnosticCategory.INTEGRITY,
                severity=MemoryDiagnosticSeverity.ERROR,
                summary="Persistent Security Memory integrity checks failed.",
                count=errors,
            )
        if budget_exhausted:
            return _health_record(
                MemoryHealthState.DEGRADED,
                MemoryIntegrityState.WARNING,
                MemoryDiagnosticCode.INTEGRITY_WARNING,
                current_schema_version=report.schema_version,
                category=MemoryDiagnosticCategory.INTEGRITY,
                severity=MemoryDiagnosticSeverity.WARNING,
                summary=(
                    "Persistent Security Memory bounded integrity inspection "
                    "was incomplete."
                ),
                count=warnings,
            )
        if warnings:
            return _health_record(
                MemoryHealthState.DEGRADED,
                MemoryIntegrityState.WARNING,
                MemoryDiagnosticCode.INTEGRITY_WARNING,
                current_schema_version=report.schema_version,
                category=MemoryDiagnosticCategory.INTEGRITY,
                severity=MemoryDiagnosticSeverity.WARNING,
                summary="Persistent Security Memory has integrity warnings.",
                count=warnings,
            )
        return _health_record(
            MemoryHealthState.AVAILABLE,
            MemoryIntegrityState.PASS,
            MemoryDiagnosticCode.AVAILABLE,
            current_schema_version=report.schema_version,
            category=MemoryDiagnosticCategory.INTEGRITY,
            severity=MemoryDiagnosticSeverity.INFO,
            summary="Persistent Security Memory is available.",
        )

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            try:
                self._memory.close()
            except Exception as error:
                failure = _memory_failure(error)
                raise failure from None


class _ConfiguredMemoryFactory:
    """One-facade private configuration; the path never crosses the boundary."""

    __slots__ = ("_database_path",)

    def __init__(self, database_path: Path) -> None:
        self._database_path = database_path

    def _database_is_absent(self) -> bool:
        try:
            os.stat(self._database_path, follow_symlinks=False)
        except FileNotFoundError:
            return True
        except Exception as error:
            raise _memory_failure(error) from None
        return False

    def open_read_only(self) -> _MemoryPort | None:
        if self._database_is_absent():
            return None
        database = None
        try:
            memory = SQLiteSecurityMemory._open_readonly_unvalidated(
                self._database_path
            )
            database = memory
            if memory._schema_version() != memory._expected_schema_version():
                raise MemoryIncompatibleVersion(
                    "Persistent Security Memory has an incompatible schema."
                )
            memory._validate_current_schema()
            database = None
            return _SQLiteMemoryPort(memory)
        except Exception as error:
            if database is not None:
                database.close()
            raise _memory_failure(error) from None

    def open_writable(self) -> _MemoryPort:
        try:
            return _SQLiteMemoryPort(SQLiteSecurityMemory.open(self._database_path))
        except Exception as error:
            failure = _memory_failure(error)
            raise failure from None

    def inspect_health(self) -> _MemoryHealthRecord:
        database = None
        port = None
        try:
            if self._database_is_absent():
                return _health_record(
                    MemoryHealthState.UNINITIALIZED,
                    MemoryIntegrityState.NOT_CHECKED,
                    MemoryDiagnosticCode.UNINITIALIZED,
                    current_schema_version=None,
                    category=MemoryDiagnosticCategory.STORAGE,
                    severity=MemoryDiagnosticSeverity.INFO,
                    summary="Persistent Security Memory has not been initialized.",
                )
            memory = SQLiteSecurityMemory._open_readonly_unvalidated(
                self._database_path
            )
            database = memory
            version = memory._schema_version()
            expected = memory._expected_schema_version()
            if 1 <= version < expected:
                return _health_record(
                    MemoryHealthState.MIGRATION_REQUIRED,
                    MemoryIntegrityState.NOT_CHECKED,
                    MemoryDiagnosticCode.MIGRATION_REQUIRED,
                    current_schema_version=version,
                    category=MemoryDiagnosticCategory.SCHEMA,
                    severity=MemoryDiagnosticSeverity.WARNING,
                    summary="Persistent Security Memory requires a forward migration.",
                )
            if version > expected:
                return _health_record(
                    MemoryHealthState.INCOMPATIBLE,
                    MemoryIntegrityState.NOT_CHECKED,
                    MemoryDiagnosticCode.INCOMPATIBLE_SCHEMA,
                    current_schema_version=version,
                    category=MemoryDiagnosticCategory.SCHEMA,
                    severity=MemoryDiagnosticSeverity.ERROR,
                    summary="Persistent Security Memory uses an incompatible schema.",
                )
            if version != expected:
                return _health_record(
                    MemoryHealthState.CORRUPT,
                    MemoryIntegrityState.FAIL,
                    MemoryDiagnosticCode.CORRUPT,
                    current_schema_version=version,
                    category=MemoryDiagnosticCategory.SCHEMA,
                    severity=MemoryDiagnosticSeverity.ERROR,
                    summary="Persistent Security Memory schema integrity is invalid.",
                )
            database = None
            port = _SQLiteMemoryPort(memory)
            result = port.health()
            port.close()
            port = None
            return result
        except _MemoryOperationFailure as failure:
            if failure.code == ApplicationErrorCode.COMPATIBILITY_FAILURE:
                state = MemoryHealthState.INCOMPATIBLE
                integrity = MemoryIntegrityState.NOT_CHECKED
                code = MemoryDiagnosticCode.INCOMPATIBLE_SCHEMA
                category = MemoryDiagnosticCategory.SCHEMA
            elif failure.code == ApplicationErrorCode.INTEGRITY_FAILURE:
                state = MemoryHealthState.CORRUPT
                integrity = MemoryIntegrityState.FAIL
                code = MemoryDiagnosticCode.CORRUPT
                category = MemoryDiagnosticCategory.INTEGRITY
            elif failure.code in {
                ApplicationErrorCode.PERMISSION_DENIED,
                ApplicationErrorCode.STORAGE_FAILURE,
            }:
                state = MemoryHealthState.UNAVAILABLE
                integrity = MemoryIntegrityState.UNAVAILABLE
                code = (
                    MemoryDiagnosticCode.PERMISSION_DENIED
                    if failure.code == ApplicationErrorCode.PERMISSION_DENIED
                    else MemoryDiagnosticCode.UNAVAILABLE
                )
                category = MemoryDiagnosticCategory.STORAGE
            else:
                raise
            return _health_record(
                state,
                integrity,
                code,
                current_schema_version=None,
                category=category,
                severity=MemoryDiagnosticSeverity.ERROR,
                summary="Persistent Security Memory could not be inspected safely.",
            )
        except Exception as error:
            failure = _memory_failure(error)
            if failure.code == ApplicationErrorCode.INTERNAL_FAILURE:
                raise failure from None
            return _health_record(
                MemoryHealthState.UNAVAILABLE,
                MemoryIntegrityState.UNAVAILABLE,
                MemoryDiagnosticCode.UNAVAILABLE,
                current_schema_version=None,
                category=MemoryDiagnosticCategory.STORAGE,
                severity=MemoryDiagnosticSeverity.ERROR,
                summary="Persistent Security Memory could not be inspected safely.",
            )
        finally:
            if port is not None:
                try:
                    port.close()
                except Exception:
                    pass
            if database is not None:
                try:
                    database.close()
                except Exception:
                    pass


def _default_memory_factory() -> _MemoryFactory | None:
    """Resolve transitional private configuration only when a Memory operation runs."""

    configured = os.environ.get(_MEMORY_DATABASE_ENVIRONMENT)
    if configured is None or configured == "":
        return None
    return _ConfiguredMemoryFactory(Path(configured))


def _open_writable(factory: _MemoryFactory) -> _MemoryPort:
    try:
        port = factory.open_writable()
    except _MemoryOperationFailure:
        raise
    except Exception as error:
        failure = _memory_failure(error)
        raise failure from None
    if port is None:
        raise _MemoryOperationFailure(ApplicationErrorCode.COMPONENT_UNAVAILABLE)
    return port


def _open_read_only(factory: _MemoryFactory) -> _MemoryPort:
    try:
        port = factory.open_read_only()
    except _MemoryOperationFailure:
        raise
    except Exception as error:
        raise _memory_failure(error) from None
    if port is None:
        raise _MemoryOperationFailure(ApplicationErrorCode.COMPONENT_UNAVAILABLE)
    return port


def _ingest_material(
    port: _MemoryPort,
    material: _TrustedReportMaterial,
) -> _MemoryIngestionRecord:
    try:
        return port.ingest_trusted_report(material)
    except _MemoryOperationFailure:
        raise
    except Exception as error:
        failure = _memory_failure(error)
        raise failure from None


def _project_recurring_result(
    operation_id: str,
    system_id: str,
    page: _MemoryRecurringPage,
) -> RecurringFindingsResult:
    try:
        findings = tuple(_public_finding(item) for item in page.findings)
        return RecurringFindingsResult(
            operation_id,
            system_id,
            findings,
            len(findings),
            page.has_more,
        )
    except _MemoryOperationFailure:
        raise
    except (TypeError, ValueError):
        raise _MemoryOperationFailure(
            ApplicationErrorCode.INTEGRITY_FAILURE
        ) from None


def _project_timeline_result(
    operation_id: str,
    system_id: str,
    finding_id: str,
    timeline: _MemoryTimelineRecord,
) -> FindingTimelineResult:
    try:
        events = tuple(FindingLifecycleEvent(
            event.event_type,
            event.occurred_at,
            _public_report_id(event.canonical_digest),
            event.previous_value,
            event.current_value,
        ) for event in timeline.events)
        return FindingTimelineResult(
            operation_id,
            system_id,
            finding_id,
            _public_finding(timeline.summary),
            events,
            len(events),
            timeline.has_more,
        )
    except _MemoryOperationFailure:
        raise
    except (TypeError, ValueError):
        raise _MemoryOperationFailure(
            ApplicationErrorCode.INTEGRITY_FAILURE
        ) from None


def _project_score_result(
    operation_id: str,
    system_id: str,
    series: tuple[_MemoryScoreSeriesRecord, ...],
) -> ScoreHistoryResult:
    try:
        projected = tuple(ScoreHistorySeries(
            item.scoring_version,
            tuple(ScoreHistoryPoint(
                _public_report_id(point.canonical_digest),
                point.observed_at,
                point.score,
                point.risk_level,
                point.scoring_version,
            ) for point in item.points),
            len(item.points),
            item.has_more,
        ) for item in series)
        return ScoreHistoryResult(operation_id, system_id, projected)
    except _MemoryOperationFailure:
        raise
    except (TypeError, ValueError):
        raise _MemoryOperationFailure(
            ApplicationErrorCode.INTEGRITY_FAILURE
        ) from None


def _project_health_result(
    operation_id: str,
    health: _MemoryHealthRecord,
) -> MemoryHealthResult:
    diagnostics = tuple(MemoryHealthDiagnostic(
        item.severity,
        item.category,
        item.code,
        item.safe_summary,
        item.count,
    ) for item in health.diagnostics)
    return MemoryHealthResult(
        operation_id,
        health.health_state,
        health.current_schema_version,
        _MEMORY_SCHEMA_VERSION,
        health.integrity_state,
        diagnostics,
    )
