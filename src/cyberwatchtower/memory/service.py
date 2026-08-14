"""Narrow application boundary for optional Persistent Security Memory."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Protocol, runtime_checkable

from .database import MemoryDatabase, open_memory_database
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
from .ingestion import ingest_report
from .ingestion_models import ReportIngestionRequest, ReportIngestionResult
from .investigations import (
    active_conversation_references,
    create_conversation_reference,
    latest_completed_for_finding,
    latest_completed_for_scope,
)
from .queries import finding_timeline, latest_report_summary, recurring_findings, score_trend


@runtime_checkable
class SecurityMemory(Protocol):
    """Typed operations available to application consumers; never arbitrary SQL."""

    def ingest_report(self, request: ReportIngestionRequest) -> ReportIngestionResult: ...
    def latest_report(self, query: SystemHistoryQuery): ...
    def recurring_findings(self, query: RecurringFindingsQuery): ...
    def finding_timeline(self, query: FindingHistoryQuery): ...
    def score_trend(self, query: ScoreTrendQuery): ...
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


class SQLiteSecurityMemory:
    """SQLite implementation. The database handle is intentionally private."""

    def __init__(self, database: MemoryDatabase) -> None:
        self.__database = database

    @classmethod
    def open(cls, path: str | Path) -> "SQLiteSecurityMemory":
        return cls(open_memory_database(Path(path)))

    def close(self) -> None:
        self.__database.close()

    def ingest_report(self, request):
        return ingest_report(self.__database, request)

    def latest_report(self, query):
        return latest_report_summary(self.__database, query)

    def recurring_findings(self, query):
        return recurring_findings(self.__database, query)

    def finding_timeline(self, query):
        return finding_timeline(self.__database, query)

    def score_trend(self, query):
        return score_trend(self.__database, query)

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
