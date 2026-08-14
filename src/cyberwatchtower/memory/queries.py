"""Host-isolated, parameterized, read-only Persistent Security Memory queries."""

import json
import sqlite3
from datetime import timezone

from .database import MemoryDatabase
from .errors import MemoryCorrupt, MemoryLocked, MemoryQueryError
from .history_models import (
    FindingHistoryQuery, FindingLifecycleSummary, FindingOccurrence, FindingTimeline,
    LatestReportSummary, LifecycleEvent, RecurringFindingsQuery, ScorePoint,
    ScoreTrendQuery, SystemHistoryQuery,
)


def _summary(row):
    return FindingLifecycleSummary(
        row["finding_id"], row["first_seen_at"], row["last_seen_at"],
        row["occurrence_count"], bool(row["active"]), row["lifecycle_state"],
        bool(row["recurring"]), row["reopened_count"], row["last_resolved_at"],
        row["latest_title"], row["latest_severity"], row["latest_kind"],
        row["latest_assessment_state"], row["latest_source"],
        bool(row["metadata_inferred"]),
    )


def _guard(operation):
    try:
        return operation()
    except sqlite3.OperationalError as exc:
        if "locked" in str(exc).casefold():
            raise MemoryLocked("Persistent Security Memory is locked.") from exc
        raise MemoryQueryError("Persistent Security Memory query failed.") from exc
    except sqlite3.DatabaseError as exc:
        raise MemoryCorrupt("Persistent Security Memory query encountered corruption.") from exc
    except json.JSONDecodeError as exc:
        raise MemoryCorrupt("Persistent Security Memory contains invalid stored JSON.") from exc


def recurring_findings(database: MemoryDatabase, query: RecurringFindingsQuery):
    def run():
        rows = database.connection.execute(
            """SELECT * FROM findings WHERE system_id = ? AND occurrence_count >= 2
               AND (? = 0 OR active = 1)
               ORDER BY occurrence_count DESC, last_seen_at DESC, finding_id""",
            (query.system_id, int(query.active_only)),
        ).fetchall()
        return tuple(_summary(row) for row in rows)
    return _guard(run)


def finding_timeline(database: MemoryDatabase, query: FindingHistoryQuery):
    def run():
        row = database.connection.execute(
            "SELECT * FROM findings WHERE system_id = ? AND finding_id = ?",
            (query.system_id, query.finding_id),
        ).fetchone()
        if row is None:
            return None
        occurrences = database.connection.execute(
            """SELECT o.* FROM finding_occurrences o
               WHERE o.system_id=? AND o.stable_finding_id=?
               ORDER BY o.observed_at, o.report_id, o.occurrence_id""",
            (query.system_id, query.finding_id),
        ).fetchall()
        events = database.connection.execute(
            """SELECT e.* FROM finding_lifecycle_events e JOIN findings f
               ON f.finding_pk=e.finding_pk AND f.system_id=e.system_id
               WHERE e.system_id=? AND f.finding_id=?
               ORDER BY e.occurred_at, e.report_id,
               CASE e.event_type WHEN 'FIRST_SEEN' THEN 1 WHEN 'SEEN' THEN 2
               WHEN 'REOPENED' THEN 3 WHEN 'SEVERITY_CHANGED' THEN 4
               WHEN 'ASSESSMENT_STATE_CHANGED' THEN 5 WHEN 'KIND_CHANGED' THEN 6
               WHEN 'RESOLVED' THEN 7 ELSE 8 END, e.event_id""",
            (query.system_id, query.finding_id),
        ).fetchall()
        return FindingTimeline(
            _summary(row),
            tuple(FindingOccurrence(
                item["occurrence_id"], item["report_id"], item["observed_at"],
                item["title"], item["severity"], item["kind"],
                item["assessment_state"], item["source"],
                bool(item["metadata_inferred"]),
            ) for item in occurrences),
            tuple(LifecycleEvent(
                item["event_id"], item["report_id"], item["event_type"],
                item["occurred_at"], item["previous_value"], item["current_value"],
            ) for item in events),
        )
    return _guard(run)


def score_trend(database: MemoryDatabase, query: ScoreTrendQuery):
    start = query.start_at.astimezone(timezone.utc).isoformat()
    end = query.end_at.astimezone(timezone.utc).isoformat()
    def run():
        rows = database.connection.execute(
            """SELECT report_id, observed_at, score, risk_level FROM score_history
               WHERE system_id=? AND observed_at>=? AND observed_at<=?
               ORDER BY observed_at, report_id""",
            (query.system_id, start, end),
        ).fetchall()
        return tuple(ScorePoint(row["report_id"], row["observed_at"], row["score"], row["risk_level"]) for row in rows)
    return _guard(run)


def latest_report_summary(database: MemoryDatabase, query: SystemHistoryQuery):
    def run():
        row = database.connection.execute(
            """SELECT r.report_id, r.generated_at, r.report_schema_version,
               r.coverage_json, s.score, s.risk_level,
               (SELECT COUNT(*) FROM finding_occurrences o
                WHERE o.system_id=r.system_id AND o.report_id=r.report_id) finding_count
               FROM reports r JOIN score_history s
               ON s.report_id=r.report_id AND s.system_id=r.system_id
               WHERE r.system_id=? ORDER BY r.generated_at DESC, r.report_id DESC LIMIT 1""",
            (query.system_id,),
        ).fetchone()
        if row is None:
            return None
        coverage = json.loads(row["coverage_json"])
        return LatestReportSummary(
            row["report_id"], row["generated_at"], row["report_schema_version"],
            row["score"], row["risk_level"], row["finding_count"],
            tuple(sorted(coverage.items())),
        )
    return _guard(run)
