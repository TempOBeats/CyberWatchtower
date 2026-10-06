"""Narrow application boundary for optional Persistent Security Memory."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Protocol, runtime_checkable

from .database import (
    MemoryDatabase,
    _open_memory_database_readonly_unvalidated,
    open_memory_database,
    open_memory_database_readonly,
    validate_memory_database,
)
from .models import CURRENT_MEMORY_SCHEMA_VERSION
from .decision_models import BaselineType, Scope
from .decisions import (
    action_response_history,
    active_exceptions,
    current_approved_baseline,
    decisions_for_scope,
)
from .history_models import (
    FindingHistoryQuery,
    RecurringFindingsQuery,
    ScoreTrendQuery,
    SystemHistoryQuery,
)
from .ingestion import _ingest_trusted_report, ingest_report
from .ingestion_models import ReportIngestionRequest, ReportIngestionResult
from .investigations import (
    active_conversation_references,
    create_conversation_reference,
    latest_completed_for_finding,
    latest_completed_for_scope,
)
from .queries import (
    _guard,
    _finding_timeline_page,
    _read_snapshot,
    _recurring_findings_page,
    _score_history_series,
    finding_timeline,
    latest_report_summary,
    recurring_findings,
    score_trend,
    score_trends_by_version,
)


@runtime_checkable
class SecurityMemory(Protocol):
    """Typed operations available to application consumers; never arbitrary SQL."""

    def ingest_report(self, request: ReportIngestionRequest) -> ReportIngestionResult: ...
    def latest_report(self, query: SystemHistoryQuery): ...
    def recurring_findings(self, query: RecurringFindingsQuery): ...
    def finding_timeline(self, query: FindingHistoryQuery): ...
    def score_trend(self, query: ScoreTrendQuery): ...
    def score_trends_by_version(self, query: ScoreTrendQuery): ...
    def active_exceptions(self, *, system_id: str, at: datetime): ...
    def current_baseline(self, *, system_id: str, baseline_type: BaselineType): ...
    def decisions_for_scope(self, *, system_id: str, scope: Scope): ...
    def action_history(self, *, system_id: str, action_id: str): ...
    def previous_investigation_for_finding(self, *, system_id: str, finding_id: str): ...
    def previous_investigation_for_scope(self, *, system_id: str, scope: Scope): ...
    def active_references(self, *, system_id: str, session_id: str, at: datetime): ...
    def remember_reference(self, *, system_id: str, session_id: str,
                           reference_type, target_id: str, reference_state,
                           created_at: datetime, expires_at: datetime): ...
    def close(self) -> None: ...
    def integrity_report(self, *, at: datetime | None = None): ...
    def operational_status(self, *, system_id: str, at: datetime | None = None): ...
    def verify_report(self, *, system_id: str, report_id: str): ...
    def plan_retention(self, *, system_id: str, at: datetime, policy=None): ...
    def authorize_retention(self, *, plan, decision_id: str,
                            at: datetime, expires_at: datetime): ...
    def execute_retention(self, *, plan, authorization_id: str, at: datetime): ...


class SQLiteSecurityMemory:
    """SQLite implementation. The database handle is intentionally private."""

    def __init__(self, database: MemoryDatabase) -> None:
        self.__database = database

    @classmethod
    def open(cls, path: str | Path) -> "SQLiteSecurityMemory":
        return cls(open_memory_database(Path(path)))

    @classmethod
    def open_readonly(cls, path: str | Path) -> "SQLiteSecurityMemory":
        return cls(open_memory_database_readonly(Path(path)))

    @classmethod
    def _open_readonly_unvalidated(cls, path: str | Path) -> "SQLiteSecurityMemory":
        return cls(_open_memory_database_readonly_unvalidated(Path(path)))

    @classmethod
    def _expected_schema_version(cls) -> int:
        return CURRENT_MEMORY_SCHEMA_VERSION

    def _schema_version(self) -> int:
        return self.__database.info.schema_version

    def _validate_current_schema(self) -> None:
        validate_memory_database(self.__database.connection)

    def close(self) -> None:
        self.__database.close()

    def ingest_report(self, request):
        return ingest_report(self.__database, request)

    def _ingest_trusted_report(
        self,
        *,
        public_report_id,
        canonical_digest,
        canonical_bytes,
        normalized_report,
        expected_system_id,
        generated_at,
    ):
        return _ingest_trusted_report(
            self.__database,
            public_report_id=public_report_id,
            canonical_digest=canonical_digest,
            canonical_bytes=canonical_bytes,
            normalized_report=normalized_report,
            expected_system_id=expected_system_id,
            generated_at=generated_at,
        )

    def _recurring_findings_page(self, *, system_id, limit, active_only):
        return _recurring_findings_page(
            self.__database,
            system_id=system_id,
            limit=limit,
            active_only=active_only,
        )

    def _finding_timeline_page(self, *, system_id, finding_id, limit):
        return _finding_timeline_page(
            self.__database,
            system_id=system_id,
            finding_id=finding_id,
            limit=limit,
        )

    def _score_history_series(
        self,
        *,
        system_id,
        start_at,
        end_at,
        limit,
        scoring_version,
    ):
        return _score_history_series(
            self.__database,
            system_id=system_id,
            start_at=start_at,
            end_at=end_at,
            limit=limit,
            scoring_version=scoring_version,
        )

    def _health_snapshot(self):
        from .integrity import _bounded_application_health

        return _guard(lambda: _read_snapshot(
            self.__database,
            lambda: _bounded_application_health(self.__database),
        ))

    @staticmethod
    def _health_budget_exhausted(report) -> bool:
        from .integrity import _APPLICATION_HEALTH_BUDGET_CODE

        return any(
            diagnostic.code == _APPLICATION_HEALTH_BUDGET_CODE
            for diagnostic in report.diagnostics
        )

    def latest_report(self, query):
        return latest_report_summary(self.__database, query)

    def recurring_findings(self, query):
        return recurring_findings(self.__database, query)

    def finding_timeline(self, query):
        return finding_timeline(self.__database, query)

    def score_trend(self, query):
        return score_trend(self.__database, query)

    def score_trends_by_version(self, query):
        return score_trends_by_version(self.__database, query)

    def active_exceptions(self, *, system_id, at):
        return active_exceptions(self.__database, system_id=system_id, at=at)

    def current_baseline(self, *, system_id, baseline_type):
        return current_approved_baseline(
            self.__database, system_id=system_id, baseline_type=baseline_type
        )

    def decisions_for_scope(self, *, system_id, scope):
        return decisions_for_scope(self.__database, system_id=system_id, scope=scope)

    def action_history(self, *, system_id, action_id):
        return action_response_history(self.__database, system_id=system_id, action_id=action_id)

    def previous_investigation_for_finding(self, *, system_id, finding_id):
        return latest_completed_for_finding(
            self.__database, system_id=system_id, finding_id=finding_id
        )

    def previous_investigation_for_scope(self, *, system_id, scope):
        return latest_completed_for_scope(self.__database, system_id=system_id, scope=scope)

    def active_references(self, *, system_id, session_id, at):
        return active_conversation_references(
            self.__database, system_id=system_id, session_id=session_id, at=at
        )

    def remember_reference(self, *, system_id, session_id, reference_type,
                           target_id, reference_state, created_at, expires_at):
        return create_conversation_reference(
            self.__database, system_id=system_id, session_id=session_id,
            reference_type=reference_type, target_id=target_id,
            reference_state=reference_state, created_at=created_at,
            expires_at=expires_at,
        )

    def integrity_report(self, *, at=None):
        from .integrity import check_integrity
        return check_integrity(self.__database, at=at)

    def operational_status(self, *, system_id, at=None):
        from .integrity import memory_status
        return memory_status(self.__database, system_id=system_id, at=at)

    def verify_report(self, *, system_id, report_id):
        from .integrity import verify_canonical_report
        return verify_canonical_report(
            self.__database, system_id=system_id, report_id=report_id
        )

    def plan_retention(self, *, system_id, at, policy=None):
        from .retention import plan_retention
        return plan_retention(
            self.__database, system_id=system_id, at=at, policy=policy
        )

    def authorize_retention(self, *, plan, decision_id, at, expires_at):
        from .retention import authorize_retention_plan
        return authorize_retention_plan(
            self.__database, plan=plan, decision_id=decision_id,
            at=at, expires_at=expires_at,
        )

    def execute_retention(self, *, plan, authorization_id, at):
        from .retention import execute_retention_plan
        return execute_retention_plan(
            self.__database, plan=plan, authorization_id=authorization_id, at=at
        )
