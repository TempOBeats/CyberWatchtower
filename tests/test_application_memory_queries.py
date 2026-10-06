import json
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import cyberwatchtower.application as application
from cyberwatchtower.application import _history as history_boundary
from cyberwatchtower.application import _memory as memory_boundary
from cyberwatchtower.memory import open_memory_database, open_memory_database_readonly
from cyberwatchtower.memory import integrity as memory_integrity
from cyberwatchtower.memory.database import _open_memory_database_readonly_unvalidated
from cyberwatchtower.memory.errors import MemoryLocked
from cyberwatchtower.memory.history_models import FindingHistoryQuery
from cyberwatchtower.memory.ingestion import ingest_report
from cyberwatchtower.memory.ingestion_models import IngestionStatus, ReportIngestionRequest
from cyberwatchtower.memory.integrity_models import (
    DiagnosticCategory,
    DiagnosticSeverity,
    IntegrityDiagnostic,
    IntegrityReport,
    ReportVerificationStatus,
)
from cyberwatchtower.memory.migrations import discover_migrations
from cyberwatchtower.memory.queries import _finding_timeline_page, finding_timeline


SYSTEM_ID = "system:queries"
OTHER_SYSTEM_ID = "system:other"
START = datetime(2026, 8, 1, tzinfo=timezone.utc)


def _finding(finding_id, title=None):
    return {
        "finding_id": finding_id,
        "title": title or finding_id,
        "description": "A deterministic condition.",
        "severity": "LOW",
        "recommendation": "Review it.",
        "evidence": ["Port: 8080"],
        "confidence": 90,
        "technique_id": None,
        "source": "network",
        "kind": "RISK",
        "assessment_state": "CONFIRMED",
    }


def _report(system_id, day, score, findings=()):
    return {
        "schema_version": "1.1",
        "generated_at": f"2026-08-{day:02d}T00:00:00+00:00",
        "system": {"system_id": system_id, "hostname": "display-only"},
        "coverage": {"network_socket_inspection": "COMPLETE"},
        "security_score": {
            "score": score,
            "risk_level": "LOW" if score >= 80 else "MODERATE",
            "counts": {"LOW": len(findings)},
        },
        "findings": list(findings),
    }


def _ingest(database, root, name, report):
    path = root / name
    path.write_text(json.dumps(report), encoding="utf-8")
    result = ingest_report(database, ReportIngestionRequest(path))
    if result.status != IngestionStatus.INGESTED:
        raise AssertionError(result)
    return result, path


def _create_database_at_version(path, version):
    connection = sqlite3.connect(path)
    connection.execute(
        """CREATE TABLE schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            checksum TEXT NOT NULL,
            applied_at TEXT NOT NULL,
            application_version TEXT NOT NULL
        )"""
    )
    for migration in discover_migrations()[:version]:
        connection.executescript(migration.sql)
        connection.execute(
            """INSERT INTO schema_migrations
               (version,name,checksum,applied_at,application_version)
               VALUES (?,?,?,'then','memory-v0.2')""",
            (migration.version, migration.name, migration.checksum),
        )
        connection.execute(f"PRAGMA user_version={migration.version}")
    connection.commit()
    connection.close()


class _TrackingConnection:
    """Delegate to SQLite while recording progress-budget lifecycle."""

    def __init__(self, connection):
        self._connection = connection
        self.progress_calls = []
        self.callback_calls = 0
        self.statements = []

    def execute(self, statement, parameters=()):
        self.statements.append(statement)
        return self._connection.execute(statement, parameters)

    def set_progress_handler(self, callback, interval):
        self.progress_calls.append((callback, interval))
        if callback is None:
            return self._connection.set_progress_handler(None, interval)

        def tracked_callback():
            self.callback_calls += 1
            return callback()

        return self._connection.set_progress_handler(tracked_callback, interval)

    def __getattr__(self, name):
        return getattr(self._connection, name)


class _FakePort:
    def __init__(self, *, recurring=None, timeline=None, score=None, error=None):
        self.recurring = recurring
        self.timeline = timeline
        self.score = score
        self.error = error
        self.close_calls = 0
        self.calls = []

    def recurring_findings(self, **values):
        self.calls.append(("recurring", values))
        if self.error:
            raise self.error
        return self.recurring

    def finding_timeline(self, **values):
        self.calls.append(("timeline", values))
        if self.error:
            raise self.error
        return self.timeline

    def score_history(self, **values):
        self.calls.append(("score", values))
        if self.error:
            raise self.error
        return self.score

    def close(self):
        self.close_calls += 1


class _FakeFactory:
    def __init__(self, port=None, health=None, error=None):
        self.port = port
        self.health = health
        self.error = error
        self.read_opens = 0
        self.health_calls = 0

    def open_read_only(self):
        self.read_opens += 1
        if self.error:
            raise self.error
        return self.port

    def inspect_health(self):
        self.health_calls += 1
        if self.error:
            raise self.error
        return self.health


def _application_with(factory):
    facade = application.CyberWatchtowerApplication()
    facade._memory_factory = factory
    facade._memory_factory_resolved = True
    return facade


class ApplicationMemoryQueryBoundaryTests(unittest.TestCase):
    def test_each_operation_generates_history_id_before_invalid_validation(self):
        facade = application.CyberWatchtowerApplication()
        methods = (
            facade.list_recurring_findings,
            facade.get_finding_timeline,
            facade.get_score_history,
            facade.get_memory_health,
        )
        for method in methods:
            with self.subTest(method=method.__name__), patch.object(
                history_boundary,
                "_history_operation_id",
                return_value="historyop:" + "a" * 32,
            ) as operation_id, patch.object(
                memory_boundary, "_default_memory_factory"
            ) as factory, self.assertRaises(
                application.CyberWatchtowerApplicationError
            ) as caught:
                method(object())
            operation_id.assert_called_once_with()
            factory.assert_not_called()
            self.assertEqual(
                caught.exception.failure.code,
                application.ApplicationErrorCode.INVALID_REQUEST,
            )

    def test_fake_recurring_projection_is_bounded_private_and_closed(self):
        finding = memory_boundary._MemoryFindingRecord(
            "finding:one",
            "Safe finding",
            application.Severity.LOW,
            "network",
            application.FindingKind.RISK,
            application.AssessmentState.CONFIRMED,
            2,
            START,
            START + timedelta(days=1),
            application.FindingLifecycleState.ACTIVE,
            0,
        )
        port = _FakePort(
            recurring=memory_boundary._MemoryRecurringPage((finding,), False)
        )
        result = _application_with(_FakeFactory(port)).list_recurring_findings(
            application.ListRecurringFindingsRequest(SYSTEM_ID, 1, True)
        )
        self.assertEqual((result.returned_count, result.has_more), (1, False))
        self.assertEqual(port.calls[0][1]["limit"], 1)
        self.assertEqual(port.close_calls, 1)
        rendered = repr(result).casefold()
        for prohibited in ("evidence", "report_id", "path", "row_id"):
            self.assertNotIn(prohibited, rendered)

    def test_timeline_absence_and_query_failures_close_and_detach(self):
        port = _FakePort(timeline=None)
        facade = _application_with(_FakeFactory(port))
        with self.assertRaises(application.CyberWatchtowerApplicationError) as caught:
            facade.get_finding_timeline(
                application.GetFindingTimelineRequest(SYSTEM_ID, "finding:missing")
            )
        self.assertEqual(caught.exception.failure.code, application.ApplicationErrorCode.NOT_FOUND)
        self.assertEqual(port.close_calls, 1)

        raw = _FakePort(error=sqlite3.OperationalError("/private/memory.db is locked"))
        with self.assertRaises(application.CyberWatchtowerApplicationError) as caught:
            _application_with(_FakeFactory(raw)).get_score_history(
                application.GetScoreHistoryRequest(
                    SYSTEM_ID, START, START + timedelta(days=1)
                )
            )
        self.assertEqual(caught.exception.failure.code, application.ApplicationErrorCode.INTERNAL_FAILURE)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn("private", repr(caught.exception.failure).casefold())
        self.assertEqual(raw.close_calls, 1)

    def test_shared_privacy_seam_blocks_sensitive_finding_text(self):
        record = memory_boundary._MemoryFindingRecord(
            "finding:secret",
            "Password material",
            application.Severity.LOW,
            "network",
            application.FindingKind.RISK,
            application.AssessmentState.CONFIRMED,
            2,
            START,
            START,
            application.FindingLifecycleState.ACTIVE,
            0,
        )
        port = _FakePort(
            recurring=memory_boundary._MemoryRecurringPage((record,), False)
        )
        with self.assertRaises(application.CyberWatchtowerApplicationError) as caught:
            _application_with(_FakeFactory(port)).list_recurring_findings(
                application.ListRecurringFindingsRequest(SYSTEM_ID)
            )
        self.assertEqual(
            caught.exception.failure.code,
            application.ApplicationErrorCode.PRIVACY_POLICY_BLOCKED,
        )
        self.assertEqual(port.close_calls, 1)

    def test_no_configuration_is_disabled_for_health_and_unavailable_for_queries(self):
        with patch.object(memory_boundary.os.environ, "get", return_value=None):
            health = application.CyberWatchtowerApplication().get_memory_health(
                application.GetMemoryHealthRequest()
            )
        self.assertEqual(health.health_state, application.MemoryHealthState.DISABLED)
        self.assertEqual(health.integrity_state, application.MemoryIntegrityState.NOT_CHECKED)

        for method, request in (
            ("list_recurring_findings", application.ListRecurringFindingsRequest(SYSTEM_ID)),
            ("get_finding_timeline", application.GetFindingTimelineRequest(SYSTEM_ID, "finding:x")),
            ("get_score_history", application.GetScoreHistoryRequest(SYSTEM_ID, START, START)),
        ):
            with self.subTest(method=method), patch.object(
                memory_boundary.os.environ, "get", return_value=None
            ), self.assertRaises(application.CyberWatchtowerApplicationError) as caught:
                getattr(application.CyberWatchtowerApplication(), method)(request)
            self.assertEqual(
                caught.exception.failure.code,
                application.ApplicationErrorCode.COMPONENT_UNAVAILABLE,
            )


class RealApplicationMemoryQueryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.path = self.root / "memory.db"
        alpha = _finding("finding:alpha", "Alpha")
        beta = _finding("finding:beta", "Beta")
        with open_memory_database(self.path) as database:
            self.results = []
            for day, score, findings in (
                (1, 80, (alpha, beta)),
                (2, 90, (alpha, beta)),
                (3, 70, (alpha,)),
                (4, 60, (alpha,)),
            ):
                result, _path = _ingest(
                    database,
                    self.root,
                    f"report-{day}.json",
                    _report(SYSTEM_ID, day, score, findings),
                )
                self.results.append(result)
            _ingest(
                database,
                self.root,
                "other.json",
                _report(OTHER_SYSTEM_ID, 1, 99, (alpha,)),
            )
            database.connection.execute(
                "UPDATE score_history SET scoring_version='2' WHERE observed_at IN (?,?)",
                (
                    "2026-08-02T00:00:00+00:00",
                    "2026-08-04T00:00:00+00:00",
                ),
            )
            database.connection.commit()
        self.facade = application.CyberWatchtowerApplication()
        self.environment = patch.dict(
            memory_boundary.os.environ,
            {"CYBERWATCHTOWER_MEMORY_DB": str(self.path)},
            clear=False,
        )
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        self.temporary.cleanup()

    def test_recurring_is_exact_system_scoped_ordered_bounded_and_active_filtered(self):
        all_items = self.facade.list_recurring_findings(
            application.ListRecurringFindingsRequest(SYSTEM_ID)
        )
        self.assertEqual(
            [(item.finding_id, item.occurrence_count, item.lifecycle_state) for item in all_items.findings],
            [
                ("finding:alpha", 4, application.FindingLifecycleState.ACTIVE),
                ("finding:beta", 2, application.FindingLifecycleState.RESOLVED),
            ],
        )
        active = self.facade.list_recurring_findings(
            application.ListRecurringFindingsRequest(SYSTEM_ID, active_only=True)
        )
        self.assertEqual([item.finding_id for item in active.findings], ["finding:alpha"])
        page = self.facade.list_recurring_findings(
            application.ListRecurringFindingsRequest(SYSTEM_ID, limit=1)
        )
        self.assertEqual((page.returned_count, page.has_more), (1, True))
        other = self.facade.list_recurring_findings(
            application.ListRecurringFindingsRequest(OTHER_SYSTEM_ID)
        )
        self.assertEqual(other.findings, ())

    def test_timeline_is_newest_first_bounded_and_uses_public_report_ids(self):
        result = self.facade.get_finding_timeline(
            application.GetFindingTimelineRequest(SYSTEM_ID, "finding:beta", 2)
        )
        self.assertEqual((result.returned_count, result.has_more), (2, True))
        self.assertEqual(
            [event.event_type for event in result.events],
            [application.LifecycleEventType.RESOLVED, application.LifecycleEventType.SEEN],
        )
        self.assertGreater(result.events[0].occurred_at, result.events[1].occurred_at)
        self.assertTrue(all(event.report_id.value.startswith("report:") for event in result.events))
        rendered = repr(result)
        self.assertNotIn("event:", rendered)
        self.assertNotIn("occurrence:", rendered)

    def test_timeline_missing_and_cross_system_are_not_found(self):
        for system_id in (SYSTEM_ID, OTHER_SYSTEM_ID):
            with self.subTest(system_id=system_id), self.assertRaises(
                application.CyberWatchtowerApplicationError
            ) as caught:
                self.facade.get_finding_timeline(
                    application.GetFindingTimelineRequest(system_id, "finding:missing")
                )
            self.assertEqual(caught.exception.failure.code, application.ApplicationErrorCode.NOT_FOUND)

    def test_timeline_equal_time_uses_report_id_and_fixed_event_precedence(self):
        occurred_at = "2026-08-10T00:00:00+00:00"
        with open_memory_database(self.path) as database:
            latest = database.connection.execute(
                """SELECT e.finding_pk,e.report_id FROM finding_lifecycle_events e
                   JOIN reports r ON r.report_id=e.report_id
                   WHERE e.system_id=? AND e.event_type='SEEN'
                   ORDER BY r.generated_at DESC LIMIT 1""",
                (SYSTEM_ID,),
            ).fetchone()
            database.connection.execute(
                "UPDATE finding_lifecycle_events SET occurred_at=? WHERE system_id=?",
                (occurred_at, SYSTEM_ID),
            )
            database.connection.execute(
                """INSERT INTO finding_lifecycle_events
                   (event_id,finding_pk,system_id,report_id,event_type,occurred_at,
                    previous_value,current_value,provenance)
                   VALUES ('event:ordering',?,?,?,'KIND_CHANGED',?,'RISK','INFO',
                           'DERIVED_HISTORY')""",
                (latest["finding_pk"], SYSTEM_ID, latest["report_id"], occurred_at),
            )
            rows = database.connection.execute(
                """SELECT e.event_type,r.content_digest FROM finding_lifecycle_events e
                   JOIN findings f ON f.finding_pk=e.finding_pk
                   JOIN reports r ON r.report_id=e.report_id
                   WHERE e.system_id=? AND f.finding_id='finding:alpha'""",
                (SYSTEM_ID,),
            ).fetchall()
            database.connection.commit()
        precedence = {
            event.value: index
            for index, event in enumerate(application.LIFECYCLE_EVENT_PRECEDENCE, start=1)
        }
        expected = sorted(
            ((row["event_type"], "report:" + row["content_digest"]) for row in rows),
            key=lambda item: (item[1], -precedence[item[0]]),
            reverse=True,
        )
        result = self.facade.get_finding_timeline(
            application.GetFindingTimelineRequest(SYSTEM_ID, "finding:alpha")
        )
        actual = [(item.event_type.value, item.report_id.value) for item in result.events]
        self.assertEqual(actual, expected)

    def test_score_series_are_separate_bounded_recent_and_chronological(self):
        result = self.facade.get_score_history(
            application.GetScoreHistoryRequest(
                SYSTEM_ID,
                START,
                START + timedelta(days=10),
                limit=1,
            )
        )
        self.assertEqual(
            [series.scoring_version for series in result.series],
            [application.ScoringVersion.V1, application.ScoringVersion.V2],
        )
        self.assertEqual([series.has_more for series in result.series], [True, True])
        self.assertEqual([series.points[0].score for series in result.series], [70, 60])
        self.assertTrue(all(series.returned_count == 1 for series in result.series))
        self.assertTrue(all(point.report_id.value.startswith("report:") for series in result.series for point in series.points))

        v2 = self.facade.get_score_history(
            application.GetScoreHistoryRequest(
                SYSTEM_ID,
                START,
                START + timedelta(days=10),
                scoring_version="2",
            )
        )
        self.assertEqual(len(v2.series), 1)
        self.assertEqual(v2.series[0].scoring_version, application.ScoringVersion.V2)
        self.assertEqual([point.score for point in v2.series[0].points], [90, 60])
        self.assertLess(v2.series[0].points[0].observed_at, v2.series[0].points[1].observed_at)

    def test_score_equal_time_tie_break_is_public_report_id_ascending(self):
        with open_memory_database(self.path) as database:
            database.connection.execute(
                "UPDATE score_history SET observed_at='2026-08-10T00:00:00+00:00' WHERE system_id=?",
                (SYSTEM_ID,),
            )
            database.connection.commit()
        result = self.facade.get_score_history(
            application.GetScoreHistoryRequest(
                SYSTEM_ID,
                START,
                START + timedelta(days=20),
            )
        )
        for series in result.series:
            identities = [point.report_id.value for point in series.points]
            self.assertEqual(identities, sorted(identities))

    def test_queries_are_read_only_and_do_not_create_sidecars(self):
        before = (self.path.stat().st_size, self.path.stat().st_mtime_ns)
        before_names = {path.name for path in self.root.iterdir()}
        self.facade.list_recurring_findings(application.ListRecurringFindingsRequest(SYSTEM_ID))
        self.facade.get_finding_timeline(
            application.GetFindingTimelineRequest(SYSTEM_ID, "finding:alpha")
        )
        self.facade.get_score_history(
            application.GetScoreHistoryRequest(SYSTEM_ID, START, START + timedelta(days=10))
        )
        self.facade.get_memory_health(application.GetMemoryHealthRequest())
        self.assertEqual((self.path.stat().st_size, self.path.stat().st_mtime_ns), before)
        self.assertEqual({path.name for path in self.root.iterdir()}, before_names)

    def test_storage_queries_use_limit_plus_one(self):
        statements = []
        with open_memory_database_readonly(self.path) as database:
            database.connection.set_trace_callback(statements.append)
            from cyberwatchtower.memory.queries import (
                _recurring_findings_page,
                _score_history_series,
            )
            _recurring_findings_page(
                database, system_id=SYSTEM_ID, limit=1, active_only=False
            )
            _finding_timeline_page(
                database, system_id=SYSTEM_ID, finding_id="finding:alpha", limit=1
            )
            _score_history_series(
                database,
                system_id=SYSTEM_ID,
                start_at=START,
                end_at=START + timedelta(days=10),
                limit=1,
                scoring_version=None,
            )
        limited = [statement for statement in statements if "LIMIT 2" in statement.upper()]
        self.assertGreaterEqual(len(limited), 4)

    def test_malformed_digest_fails_timeline_and_score_integrity(self):
        with open_memory_database(self.path) as database:
            database.connection.execute(
                "UPDATE reports SET content_digest='bad-' || report_id WHERE system_id=?",
                (SYSTEM_ID,),
            )
            database.connection.commit()
        for method, request in (
            (
                self.facade.get_finding_timeline,
                application.GetFindingTimelineRequest(SYSTEM_ID, "finding:alpha"),
            ),
            (
                self.facade.get_score_history,
                application.GetScoreHistoryRequest(SYSTEM_ID, START, START + timedelta(days=10)),
            ),
        ):
            with self.subTest(method=method.__name__), self.assertRaises(
                application.CyberWatchtowerApplicationError
            ) as caught:
                method(request)
            self.assertEqual(caught.exception.failure.code, application.ApplicationErrorCode.INTEGRITY_FAILURE)

    def test_current_database_health_and_pathless_source_are_available(self):
        with open_memory_database(self.path) as database:
            database.connection.execute(
                "UPDATE reports SET source_path=NULL,source_filename=NULL WHERE system_id=?",
                (SYSTEM_ID,),
            )
            database.connection.commit()
        result = self.facade.get_memory_health(application.GetMemoryHealthRequest())
        self.assertEqual(result.health_state, application.MemoryHealthState.AVAILABLE)
        self.assertEqual(result.integrity_state, application.MemoryIntegrityState.PASS)
        self.assertLessEqual(len(result.diagnostics), 32)
        self.assertNotIn(str(self.path), repr(result))

    def test_missing_legacy_source_is_a_safe_warning(self):
        (self.root / "report-1.json").unlink()
        result = self.facade.get_memory_health(application.GetMemoryHealthRequest())
        self.assertEqual(result.health_state, application.MemoryHealthState.DEGRADED)
        self.assertEqual(result.integrity_state, application.MemoryIntegrityState.WARNING)
        self.assertNotIn(str(self.root), repr(result))


class BoundedApplicationHealthRepairTests(unittest.TestCase):
    def _healthy_database(self, path):
        with open_memory_database(path):
            pass

    def test_real_sqlite_budget_exhaustion_is_degraded_private_and_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "memory.db"
            self._healthy_database(path)
            before_bytes = path.read_bytes()
            before_names = {item.name for item in root.iterdir()}

            with patch.dict(
                memory_boundary.os.environ,
                {"CYBERWATCHTOWER_MEMORY_DB": str(path)},
            ), patch.object(
                memory_integrity,
                "_APPLICATION_HEALTH_PROGRESS_INTERVAL",
                1,
            ), patch.object(
                memory_integrity,
                "_APPLICATION_HEALTH_MAX_VM_STEPS",
                1,
            ):
                result = application.CyberWatchtowerApplication().get_memory_health(
                    application.GetMemoryHealthRequest()
                )

            self.assertEqual(result.health_state, application.MemoryHealthState.DEGRADED)
            self.assertEqual(result.integrity_state, application.MemoryIntegrityState.WARNING)
            self.assertEqual(
                result.diagnostics[0].code,
                application.MemoryDiagnosticCode.INTEGRITY_WARNING,
            )
            self.assertIn("incomplete", result.diagnostics[0].safe_summary.casefold())
            rendered = repr(result).casefold()
            for prohibited in (str(path).casefold(), "select ", "pragma ", "interrupted"):
                self.assertNotIn(prohibited, rendered)
            self.assertEqual(path.read_bytes(), before_bytes)
            self.assertEqual({item.name for item in root.iterdir()}, before_names)

    def test_budget_is_single_cumulative_handler_and_removed_after_exhaustion(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.db"
            self._healthy_database(path)
            database = _open_memory_database_readonly_unvalidated(path)
            tracking = _TrackingConnection(database.connection)
            database.connection = tracking
            try:
                with patch.object(
                    memory_integrity,
                    "_APPLICATION_HEALTH_PROGRESS_INTERVAL",
                    1,
                ), patch.object(
                    memory_integrity,
                    "_APPLICATION_HEALTH_MAX_VM_STEPS",
                    32,
                ):
                    report = memory_integrity._bounded_application_health(database)

                self.assertIn(
                    memory_integrity._APPLICATION_HEALTH_BUDGET_CODE,
                    {item.code for item in report.diagnostics},
                )
                self.assertEqual(tracking.callback_calls, 32)
                self.assertGreaterEqual(len(tracking.statements), 2)
                self.assertEqual(len(tracking.progress_calls), 2)
                self.assertIsNotNone(tracking.progress_calls[0][0])
                self.assertEqual(tracking.progress_calls[0][1], 1)
                self.assertEqual(tracking.progress_calls[1], (None, 0))
                self.assertEqual(tracking.execute("SELECT 1").fetchone()[0], 1)
            finally:
                database.close()

    def test_progress_handler_is_removed_after_success_and_unexpected_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.db"
            self._healthy_database(path)
            database = _open_memory_database_readonly_unvalidated(path)
            tracking = _TrackingConnection(database.connection)
            database.connection = tracking
            try:
                report = memory_integrity._bounded_application_health(database)
                self.assertEqual(report.health, "HEALTHY")
                self.assertEqual(tracking.progress_calls[-1], (None, 0))
                self.assertEqual(tracking.execute("SELECT 1").fetchone()[0], 1)

                with patch.object(
                    memory_integrity,
                    "validate_memory_database",
                    side_effect=RuntimeError("private failure"),
                ), self.assertRaises(RuntimeError):
                    memory_integrity._bounded_application_health(database)
                self.assertEqual(tracking.progress_calls[-1], (None, 0))
                self.assertEqual(tracking.execute("SELECT 1").fetchone()[0], 1)
            finally:
                database.close()

    def test_full_integrity_remains_deep_when_application_budget_is_tiny(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.db"
            with open_memory_database(path) as database, patch.object(
                memory_integrity,
                "_APPLICATION_HEALTH_PROGRESS_INTERVAL",
                1,
            ), patch.object(
                memory_integrity,
                "_APPLICATION_HEALTH_MAX_VM_STEPS",
                1,
            ):
                report = memory_integrity.check_integrity(database)

            self.assertEqual(report.health, "HEALTHY")
            self.assertNotIn(
                memory_integrity._APPLICATION_HEALTH_BUDGET_CODE,
                {item.code for item in report.diagnostics},
            )

    def test_positive_corruption_precedes_budget_incomplete_warning(self):
        class FakeMemory:
            def _health_snapshot(self):
                return IntegrityReport(
                    "DEGRADED",
                    8,
                    (
                        IntegrityDiagnostic(
                            DiagnosticSeverity.ERROR,
                            DiagnosticCategory.RELATIONSHIP,
                            "FOREIGN_KEY_VIOLATION",
                            "Foreign-key integrity violations exist.",
                        ),
                        IntegrityDiagnostic(
                            DiagnosticSeverity.WARNING,
                            DiagnosticCategory.SQLITE,
                            memory_integrity._APPLICATION_HEALTH_BUDGET_CODE,
                            "Bounded application health inspection did not complete.",
                        ),
                    ),
                )

            def close(self):
                pass

        result = memory_boundary._SQLiteMemoryPort(FakeMemory()).health()
        self.assertEqual(result.health_state, application.MemoryHealthState.CORRUPT)
        self.assertEqual(result.integrity_state, application.MemoryIntegrityState.FAIL)


class BoundedLegacySourceHealthRepairTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.database_path = self.root / "memory.db"
        self.source_path = self.root / "legacy-report.json"
        self.source_path.write_text(
            json.dumps(_report(SYSTEM_ID, 1, 80, (_finding("finding:legacy"),))),
            encoding="utf-8",
        )
        with open_memory_database(self.database_path) as database:
            result = ingest_report(
                database,
                ReportIngestionRequest(self.source_path),
            )
        self.report_id = result.report_id

    def tearDown(self):
        self.temporary.cleanup()

    def _health(self):
        with patch.dict(
            memory_boundary.os.environ,
            {"CYBERWATCHTOWER_MEMORY_DB": str(self.database_path)},
        ):
            return application.CyberWatchtowerApplication().get_memory_health(
                application.GetMemoryHealthRequest()
            )

    def _bounded_verification(self):
        with open_memory_database_readonly(self.database_path) as database:
            return memory_integrity._verify_canonical_report_bounded(
                database,
                system_id=SYSTEM_ID,
                report_id=self.report_id,
            )

    def test_oversized_source_is_bounded_not_parsed_private_and_read_only(self):
        byte_limit = 128
        self.source_path.write_bytes(
            b'{"oversized":"' + (b"x" * (byte_limit * 2)) + b'"}'
        )
        database_before = self.database_path.read_bytes()
        source_before = self.source_path.read_bytes()
        names_before = {item.name for item in self.root.iterdir()}
        requested_reads = []
        real_read = os.read

        def tracked_read(descriptor, count):
            requested_reads.append(count)
            return real_read(descriptor, count)

        with patch.object(
            memory_integrity,
            "MAX_REPORT_BYTES",
            byte_limit,
        ), patch.object(
            memory_integrity.os,
            "read",
            side_effect=tracked_read,
        ), patch.object(
            memory_integrity.json,
            "loads",
            side_effect=AssertionError("oversized source must not be parsed"),
        ):
            result = self._health()

        self.assertEqual(result.health_state, application.MemoryHealthState.DEGRADED)
        self.assertEqual(result.integrity_state, application.MemoryIntegrityState.WARNING)
        self.assertLessEqual(sum(requested_reads), byte_limit + 1)
        self.assertEqual(self.database_path.read_bytes(), database_before)
        self.assertEqual(self.source_path.read_bytes(), source_before)
        self.assertEqual({item.name for item in self.root.iterdir()}, names_before)
        rendered = repr(result).casefold()
        for prohibited in (str(self.root).casefold(), "oversized", "select ", "errno"):
            self.assertNotIn(prohibited, rendered)

    def test_source_growth_during_read_cannot_exceed_the_actual_byte_bound(self):
        original_size = self.source_path.stat().st_size
        byte_limit = original_size + 32
        requested_reads = []
        real_read = os.read
        grew = []

        def growing_read(descriptor, count):
            requested_reads.append(count)
            if not grew:
                grew.append(True)
                with self.source_path.open("ab") as source:
                    source.write(b"x" * (byte_limit + 1))
            return real_read(descriptor, count)

        with patch.object(
            memory_integrity,
            "MAX_REPORT_BYTES",
            byte_limit,
        ), patch.object(
            memory_integrity.os,
            "read",
            side_effect=growing_read,
        ), patch.object(
            memory_integrity.json,
            "loads",
            side_effect=AssertionError("grown oversized source must not be parsed"),
        ):
            result = self._health()

        self.assertTrue(grew)
        self.assertEqual(result.health_state, application.MemoryHealthState.DEGRADED)
        self.assertEqual(result.integrity_state, application.MemoryIntegrityState.WARNING)
        self.assertLessEqual(sum(requested_reads), byte_limit + 1)

    @unittest.skipUnless(
        hasattr(os, "symlink") and hasattr(os, "O_NOFOLLOW"),
        "no-follow symlink checks require platform support",
    )
    def test_symlink_is_not_followed_while_full_verifier_keeps_legacy_semantics(self):
        target = self.root / "legacy-target.json"
        expected = self.source_path.read_bytes()
        self.source_path.replace(target)
        self.source_path.symlink_to(target)

        result = self._health()
        self.assertEqual(result.health_state, application.MemoryHealthState.DEGRADED)
        self.assertEqual(result.integrity_state, application.MemoryIntegrityState.WARNING)
        self.assertEqual(target.read_bytes(), expected)

        with open_memory_database_readonly(self.database_path) as database:
            full = memory_integrity.verify_canonical_report(
                database,
                system_id=SYSTEM_ID,
                report_id=self.report_id,
            )
        self.assertEqual(full.status, ReportVerificationStatus.VERIFIED)

    @unittest.skipUnless(
        hasattr(os, "mkfifo") and hasattr(os, "O_NOFOLLOW"),
        "nonregular FIFO checks require platform support",
    )
    def test_fifo_is_rejected_without_opening_or_blocking(self):
        self.source_path.unlink()
        os.mkfifo(self.source_path)
        real_open = os.open
        source_opened = []

        def guarded_open(path, flags, *args, **kwargs):
            if Path(path) == self.source_path:
                source_opened.append(True)
                raise AssertionError("nonregular source must not be opened")
            return real_open(path, flags, *args, **kwargs)

        with patch.object(memory_integrity.os, "open", side_effect=guarded_open):
            result = self._health()
        self.assertFalse(source_opened)
        self.assertEqual(result.health_state, application.MemoryHealthState.DEGRADED)
        self.assertEqual(result.integrity_state, application.MemoryIntegrityState.WARNING)

    @unittest.skipUnless(
        hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_NONBLOCK"),
        "race-safe source open checks require platform support",
    )
    def test_source_open_is_nofollow_nonblocking_and_fstat_precedes_read(self):
        real_open = os.open
        real_fstat = os.fstat
        real_read = os.read
        source_descriptors = set()
        source_flags = []
        source_events = []

        def tracked_open(path, flags, *args, **kwargs):
            descriptor = real_open(path, flags, *args, **kwargs)
            if Path(path) == self.source_path:
                source_descriptors.add(descriptor)
                source_flags.append(flags)
                source_events.append("open")
            return descriptor

        def tracked_fstat(descriptor):
            if descriptor in source_descriptors:
                source_events.append("fstat")
            return real_fstat(descriptor)

        def tracked_read(descriptor, count):
            if descriptor in source_descriptors:
                source_events.append("read")
            return real_read(descriptor, count)

        with patch.object(
            memory_integrity.os,
            "open",
            side_effect=tracked_open,
        ), patch.object(
            memory_integrity.os,
            "fstat",
            side_effect=tracked_fstat,
        ), patch.object(
            memory_integrity.os,
            "read",
            side_effect=tracked_read,
        ):
            verification = self._bounded_verification()

        self.assertEqual(verification.status, ReportVerificationStatus.VERIFIED)
        self.assertEqual(len(source_flags), 1)
        self.assertTrue(source_flags[0] & os.O_NOFOLLOW)
        self.assertTrue(source_flags[0] & os.O_NONBLOCK)
        self.assertLess(source_events.index("fstat"), source_events.index("read"))

    @unittest.skipUnless(
        hasattr(os, "mkfifo")
        and hasattr(os, "O_NOFOLLOW")
        and hasattr(os, "O_NONBLOCK"),
        "regular-to-FIFO race checks require platform support",
    )
    def test_regular_to_fifo_race_is_nonblocking_and_rejected_before_read(self):
        real_open = os.open
        replaced = []
        source_flags = []

        def replacing_open(path, flags, *args, **kwargs):
            if Path(path) == self.source_path and not replaced:
                source_flags.append(flags)
                if not flags & os.O_NONBLOCK:
                    raise AssertionError("raced FIFO open must be nonblocking")
                self.source_path.unlink()
                os.mkfifo(self.source_path)
                replaced.append(True)
            return real_open(path, flags, *args, **kwargs)

        with patch.object(
            memory_integrity.os,
            "open",
            side_effect=replacing_open,
        ), patch.object(
            memory_integrity.os,
            "read",
            side_effect=AssertionError("raced FIFO must not be read"),
        ):
            result = self._health()

        self.assertTrue(replaced)
        self.assertEqual(len(source_flags), 1)
        self.assertTrue(source_flags[0] & os.O_NOFOLLOW)
        self.assertTrue(source_flags[0] & os.O_NONBLOCK)
        self.assertEqual(result.health_state, application.MemoryHealthState.DEGRADED)
        self.assertEqual(result.integrity_state, application.MemoryIntegrityState.WARNING)
        rendered = repr(result).casefold()
        self.assertNotIn(str(self.root).casefold(), rendered)
        self.assertNotIn("fifo", rendered)

    @unittest.skipUnless(
        hasattr(os, "symlink") and hasattr(os, "O_NOFOLLOW"),
        "regular-to-symlink race checks require platform support",
    )
    def test_regular_to_symlink_race_is_not_followed(self):
        target = self.root / "replacement-target.json"
        target.write_bytes(self.source_path.read_bytes())
        real_open = os.open
        replaced = []

        def replacing_open(path, flags, *args, **kwargs):
            if Path(path) == self.source_path and not replaced:
                self.source_path.unlink()
                self.source_path.symlink_to(target)
                replaced.append(True)
            return real_open(path, flags, *args, **kwargs)

        with patch.object(memory_integrity.os, "open", side_effect=replacing_open):
            verification = self._bounded_verification()

        self.assertTrue(replaced)
        self.assertEqual(
            verification.status,
            ReportVerificationStatus.INVALID_SOURCE,
        )
        self.assertEqual(target.read_bytes(), self.source_path.resolve().read_bytes())

    @unittest.skipUnless(
        hasattr(os, "O_NOFOLLOW"),
        "descriptor-bound replacement checks require platform support",
    )
    def test_replacement_between_lstat_and_open_fails_verification(self):
        replacement = self.root / "replacement.json"
        replacement.write_text(
            json.dumps(_report(SYSTEM_ID, 2, 20, (_finding("finding:replacement"),))),
            encoding="utf-8",
        )
        real_open = os.open
        replaced = []

        def replacing_open(path, flags, *args, **kwargs):
            if Path(path) == self.source_path and not replaced:
                replaced.append(True)
                os.replace(replacement, self.source_path)
            return real_open(path, flags, *args, **kwargs)

        with patch.object(memory_integrity.os, "open", side_effect=replacing_open):
            verification = self._bounded_verification()
        self.assertTrue(replaced)
        self.assertEqual(
            verification.status,
            ReportVerificationStatus.INVALID_SOURCE,
        )

    def test_invalid_utf8_invalid_json_and_digest_mismatch_are_truthful(self):
        cases = (
            (b"\xff", application.MemoryHealthState.DEGRADED),
            (b"{not-json", application.MemoryHealthState.DEGRADED),
            (
                json.dumps(_report(SYSTEM_ID, 2, 20)).encode("utf-8"),
                application.MemoryHealthState.CORRUPT,
            ),
        )
        for source, expected in cases:
            with self.subTest(expected=expected):
                self.source_path.write_bytes(source)
                result = self._health()
                self.assertEqual(result.health_state, expected)
                rendered = repr(result).casefold()
                for prohibited in (str(self.root).casefold(), "not-json", "unicode", "jsondecode"):
                    self.assertNotIn(prohibited, rendered)

    def test_valid_and_pathless_sources_remain_healthy(self):
        valid = self._health()
        self.assertEqual(valid.health_state, application.MemoryHealthState.AVAILABLE)
        self.assertEqual(valid.integrity_state, application.MemoryIntegrityState.PASS)

        with open_memory_database(self.database_path) as database:
            database.connection.execute(
                "UPDATE reports SET source_path=NULL,source_filename=NULL WHERE report_id=?",
                (self.report_id,),
            )
            database.connection.commit()
        with patch.object(
            memory_integrity,
            "_bounded_source_bytes",
            side_effect=AssertionError("pathless source must not touch the filesystem"),
        ):
            pathless = self._health()
        self.assertEqual(pathless.health_state, application.MemoryHealthState.AVAILABLE)
        self.assertEqual(pathless.integrity_state, application.MemoryIntegrityState.PASS)

    def test_source_descriptor_closes_on_success_and_unexpected_parse_failure(self):
        real_close = os.close
        close_calls = []

        def tracked_close(descriptor):
            close_calls.append(descriptor)
            return real_close(descriptor)

        with patch.object(memory_integrity.os, "close", side_effect=tracked_close):
            verification = self._bounded_verification()
        self.assertEqual(verification.status, ReportVerificationStatus.VERIFIED)
        self.assertEqual(len(close_calls), 1)

        close_calls.clear()
        with patch.object(
            memory_integrity.json,
            "loads",
            side_effect=RuntimeError("private parser failure"),
        ), patch.object(
            memory_integrity.os,
            "close",
            side_effect=tracked_close,
        ), self.assertRaises(RuntimeError):
            self._bounded_verification()
        self.assertEqual(len(close_calls), 1)


class MemoryReadOnlyStateTests(unittest.TestCase):
    def test_missing_configured_database_never_creates_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "missing", "memory.db")
            for method, request in (
                ("list_recurring_findings", application.ListRecurringFindingsRequest(SYSTEM_ID)),
                ("get_finding_timeline", application.GetFindingTimelineRequest(SYSTEM_ID, "finding:x")),
                ("get_score_history", application.GetScoreHistoryRequest(SYSTEM_ID, START, START)),
            ):
                with self.subTest(method=method), patch.dict(
                    memory_boundary.os.environ,
                    {"CYBERWATCHTOWER_MEMORY_DB": str(path)},
                    clear=False,
                ), self.assertRaises(application.CyberWatchtowerApplicationError) as caught:
                    getattr(application.CyberWatchtowerApplication(), method)(request)
                self.assertEqual(caught.exception.failure.code, application.ApplicationErrorCode.COMPONENT_UNAVAILABLE)
                self.assertFalse(path.parent.exists())
            with patch.dict(
                memory_boundary.os.environ,
                {"CYBERWATCHTOWER_MEMORY_DB": str(path)},
                clear=False,
            ):
                health = application.CyberWatchtowerApplication().get_memory_health(
                    application.GetMemoryHealthRequest()
                )
            self.assertEqual(health.health_state, application.MemoryHealthState.UNINITIALIZED)
            self.assertFalse(path.parent.exists())

    def test_old_newer_and_checksum_states_are_read_only_and_truthful(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old = root / "old.db"
            _create_database_at_version(old, 7)
            with patch.dict(memory_boundary.os.environ, {"CYBERWATCHTOWER_MEMORY_DB": str(old)}):
                facade = application.CyberWatchtowerApplication()
                health = facade.get_memory_health(application.GetMemoryHealthRequest())
                with self.assertRaises(application.CyberWatchtowerApplicationError) as caught:
                    facade.list_recurring_findings(application.ListRecurringFindingsRequest(SYSTEM_ID))
            self.assertEqual(health.health_state, application.MemoryHealthState.MIGRATION_REQUIRED)
            self.assertEqual(caught.exception.failure.code, application.ApplicationErrorCode.COMPATIBILITY_FAILURE)
            connection = sqlite3.connect(old)
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 7)
            connection.close()

            newer = root / "newer.db"
            connection = sqlite3.connect(newer)
            connection.execute("PRAGMA user_version=99")
            connection.close()
            with patch.dict(memory_boundary.os.environ, {"CYBERWATCHTOWER_MEMORY_DB": str(newer)}):
                health = application.CyberWatchtowerApplication().get_memory_health(
                    application.GetMemoryHealthRequest()
                )
            self.assertEqual(health.health_state, application.MemoryHealthState.INCOMPATIBLE)

            corrupt = root / "corrupt.db"
            with open_memory_database(corrupt) as database:
                database.connection.execute(
                    "UPDATE schema_migrations SET checksum='tampered' WHERE version=8"
                )
                database.connection.commit()
            with patch.dict(memory_boundary.os.environ, {"CYBERWATCHTOWER_MEMORY_DB": str(corrupt)}):
                health = application.CyberWatchtowerApplication().get_memory_health(
                    application.GetMemoryHealthRequest()
                )
            self.assertEqual(health.health_state, application.MemoryHealthState.CORRUPT)
            self.assertEqual(health.integrity_state, application.MemoryIntegrityState.FAIL)

    def test_lock_and_permission_are_safe_without_retry_or_exception_leakage(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "memory.db")
            path.touch()
            with patch.dict(
                memory_boundary.os.environ,
                {"CYBERWATCHTOWER_MEMORY_DB": str(path)},
            ), patch.object(
                memory_boundary.SQLiteSecurityMemory,
                "_open_readonly_unvalidated",
                side_effect=MemoryLocked("locked /private/memory.db"),
            ) as opened, self.assertRaises(
                application.CyberWatchtowerApplicationError
            ) as caught:
                application.CyberWatchtowerApplication().list_recurring_findings(
                    application.ListRecurringFindingsRequest(SYSTEM_ID)
                )
            self.assertEqual(opened.call_count, 1)
            self.assertEqual(caught.exception.failure.code, application.ApplicationErrorCode.STORAGE_FAILURE)
            self.assertTrue(caught.exception.failure.retryable)
            self.assertIsNone(caught.exception.__cause__)
            self.assertIsNone(caught.exception.__context__)
            self.assertNotIn("private", repr(caught.exception.failure).casefold())

            with patch.dict(
                memory_boundary.os.environ,
                {"CYBERWATCHTOWER_MEMORY_DB": str(path)},
            ), patch.object(
                memory_boundary.SQLiteSecurityMemory,
                "_open_readonly_unvalidated",
                side_effect=PermissionError("/private/memory.db"),
            ):
                health = application.CyberWatchtowerApplication().get_memory_health(
                    application.GetMemoryHealthRequest()
                )
            self.assertEqual(health.health_state, application.MemoryHealthState.UNAVAILABLE)
            self.assertEqual(health.integrity_state, application.MemoryIntegrityState.UNAVAILABLE)
            self.assertNotIn("private", repr(health).casefold())

            with patch.dict(
                memory_boundary.os.environ,
                {"CYBERWATCHTOWER_MEMORY_DB": str(path)},
            ), patch.object(
                memory_boundary.os,
                "stat",
                side_effect=PermissionError("/private/memory.db"),
            ), self.assertRaises(
                application.CyberWatchtowerApplicationError
            ) as caught:
                application.CyberWatchtowerApplication().list_recurring_findings(
                    application.ListRecurringFindingsRequest(SYSTEM_ID)
                )
            self.assertEqual(
                caught.exception.failure.code,
                application.ApplicationErrorCode.PERMISSION_DENIED,
            )
            self.assertIsNone(caught.exception.__context__)

            with patch.dict(
                memory_boundary.os.environ,
                {"CYBERWATCHTOWER_MEMORY_DB": str(path)},
            ), patch.object(
                memory_boundary.os,
                "stat",
                side_effect=PermissionError("/private/memory.db"),
            ):
                health = application.CyberWatchtowerApplication().get_memory_health(
                    application.GetMemoryHealthRequest()
                )
            self.assertEqual(health.health_state, application.MemoryHealthState.UNAVAILABLE)
            self.assertNotIn("private", repr(health).casefold())

    def test_health_closes_the_single_opened_handle_on_success_and_failure(self):
        class FakeMemory:
            def __init__(self, error=None):
                self.error = error
                self.close_calls = 0

            @classmethod
            def _expected_schema_version(cls):
                return 8

            def _schema_version(self):
                return 8

            def _health_snapshot(self):
                if self.error:
                    raise self.error
                return type("Report", (), {
                    "health": "HEALTHY",
                    "schema_version": 8,
                    "diagnostics": (),
                })()

            def close(self):
                self.close_calls += 1

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "memory.db")
            path.touch()
            for error, expected in (
                (None, application.MemoryHealthState.AVAILABLE),
                (MemoryLocked("locked"), application.MemoryHealthState.UNAVAILABLE),
            ):
                memory = FakeMemory(error)
                with self.subTest(error=error), patch.object(
                    memory_boundary.SQLiteSecurityMemory,
                    "_open_readonly_unvalidated",
                    return_value=memory,
                ):
                    result = memory_boundary._ConfiguredMemoryFactory(path).inspect_health()
                self.assertEqual(result.health_state, expected)
                self.assertEqual(memory.close_calls, 1)

    def test_real_snapshot_prevents_mixed_timeline_during_concurrent_ingestion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "memory.db"
            with open_memory_database(path) as writer:
                writer.connection.execute("PRAGMA journal_mode=WAL")
                _ingest(writer, root, "first.json", _report(
                    SYSTEM_ID, 1, 80, (_finding("finding:alpha"),)
                ))
            reader = open_memory_database_readonly(path)
            writer = open_memory_database(path)
            invoked = []

            def concurrent_write(statement):
                if "FROM finding_lifecycle_events" in statement and not invoked:
                    invoked.append(True)
                    _ingest(writer, root, "second.json", _report(
                        SYSTEM_ID, 2, 90, (_finding("finding:alpha"),)
                    ))

            reader.connection.set_trace_callback(concurrent_write)
            try:
                snapshot = _finding_timeline_page(
                    reader,
                    system_id=SYSTEM_ID,
                    finding_id="finding:alpha",
                    limit=100,
                )
            finally:
                reader.close()
                writer.close()
            with open_memory_database_readonly(path) as current:
                after = finding_timeline(
                    current,
                    FindingHistoryQuery(SYSTEM_ID, "finding:alpha"),
                )
            self.assertTrue(invoked)
            self.assertEqual(snapshot.summary.occurrence_count, 1)
            self.assertEqual(len(snapshot.events), 1)
            self.assertEqual(after.summary.occurrence_count, 2)
            self.assertEqual(len(after.events), 2)


if __name__ == "__main__":
    unittest.main()
