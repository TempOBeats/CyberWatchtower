import hashlib
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cyberwatchtower.memory import open_memory_database
from cyberwatchtower.memory.decision_models import (
    ActionResponseType, ApplicationScope, BaselineEntry, BaselineState, BaselineType,
    DecisionStatus, DecisionType, ExceptionStatus, FindingScope, FirewallStateScope,
    ListenerScope, ServiceScope,
)
from cyberwatchtower.memory.decisions import (
    action_response_history, active_exceptions, approve_baseline, baseline_history,
    create_decision, create_draft_baseline, create_exception,
    create_next_baseline_version, current_approved_baseline, decisions_for_scope,
    exceptions_for_scope, record_action_response, record_recommendation_shown,
    revoke_decision, revoke_exception, supersede_decision, supersede_exception,
)
from cyberwatchtower.memory.errors import MemoryDecisionError, MemoryMigrationFailed
from cyberwatchtower.memory.ingestion import ingest_report
from cyberwatchtower.memory.ingestion_models import IngestionStatus, ReportIngestionRequest
from cyberwatchtower.memory.migrations import discover_migrations
from cyberwatchtower.memory.models import CURRENT_MEMORY_SCHEMA_VERSION


UTC = timezone.utc
T0 = datetime(2026, 8, 1, tzinfo=UTC)


def report(system_id, hostname="shared"):
    return {
        "schema_version": "1.1", "generated_at": T0.isoformat(),
        "system": {"system_id": system_id, "hostname": hostname},
        "coverage": {"firewall_technology": "COMPLETE", "iptables_input_policy": "UNKNOWN",
                     "network_socket_inspection": "COMPLETE"},
        "security_score": {"score": 90, "risk_level": "LOW", "counts": {"LOW": 1}},
        "findings": [{
            "finding_id": "finding:service", "title": "Exposed service",
            "description": "A listener is exposed.", "severity": "LOW",
            "recommendation": "Restrict the listener.", "evidence": ["Port: 8080"],
            "confidence": 90, "technique_id": None, "source": "network",
            "kind": "RISK", "assessment_state": "CONFIRMED",
        }],
    }


class DecisionMemorySupport:
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.database = open_memory_database(Path(self.temporary.name, "memory.db"))
        self.add_system("system-a")

    def tearDown(self):
        self.database.close()
        self.temporary.cleanup()

    def add_system(self, system_id):
        path = Path(self.temporary.name, f"{system_id}.json")
        path.write_text(json.dumps(report(system_id)), encoding="utf-8")
        result = ingest_report(self.database, ReportIngestionRequest(path))
        self.assertEqual(result.status, IngestionStatus.INGESTED)


class DecisionTests(DecisionMemorySupport, unittest.TestCase):
    def test_creation_supersession_revocation_and_history_are_auditable(self):
        scope = FindingScope("finding:service")
        first = create_decision(
            self.database, system_id="system-a", decision_type=DecisionType.REVIEWED,
            scope=scope, actor="analyst", rationale="Reviewed locally.", effective_at=T0)
        second = supersede_decision(
            self.database, system_id="system-a", decision_id=first.decision_id,
            decision_type=DecisionType.ACCEPTED_RISK, scope=scope, actor="owner",
            rationale="Presentation context only.", effective_at=T0 + timedelta(hours=1))
        revoked = revoke_decision(
            self.database, system_id="system-a", decision_id=second.decision_id)
        history = decisions_for_scope(self.database, system_id="system-a", scope=scope)
        self.assertEqual([item.status for item in history],
                         [DecisionStatus.SUPERSEDED, DecisionStatus.REVOKED])
        self.assertEqual(second.supersedes_id, first.decision_id)
        self.assertEqual(revoked.provenance.value, "USER_DECISION")
        self.assertTrue(all(item.presentation_only for item in history))
        with self.assertRaises(sqlite3.IntegrityError):
            self.database.connection.execute(
                "UPDATE user_decisions SET rationale='rewritten' WHERE decision_id=?",
                (first.decision_id,))
        self.database.connection.rollback()
        with self.assertRaises(sqlite3.IntegrityError):
            self.database.connection.execute(
                "DELETE FROM user_decisions WHERE decision_id=?", (first.decision_id,))
        self.database.connection.rollback()

    def test_cross_system_supersession_is_rejected(self):
        self.add_system("system-b")
        first = create_decision(
            self.database, system_id="system-a", decision_type=DecisionType.REVIEWED,
            scope=FindingScope("finding:service"), actor="analyst", effective_at=T0)
        with self.assertRaises(MemoryDecisionError):
            supersede_decision(
                self.database, system_id="system-b", decision_id=first.decision_id,
                decision_type=DecisionType.REVIEWED, scope=FindingScope("finding:service"),
                actor="analyst", effective_at=T0)
        self.assertEqual(decisions_for_scope(
            self.database, system_id="system-a", scope=FindingScope("finding:service"))[0].status,
            DecisionStatus.ACTIVE)

    def test_all_typed_scopes_are_exact_and_free_form_scope_is_rejected(self):
        scopes = (
            FindingScope("finding:service"),
            ListenerScope("TCP", "0.0.0.0", "ALL_INTERFACES", 8080, "/usr/bin/app"),
            ServiceScope("HTTP", "tcp", 8080), ApplicationScope("/usr/bin/app"),
            FirewallStateScope("iptables", "DROP"),
        )
        for index, scope in enumerate(scopes):
            create_decision(
                self.database, system_id="system-a", decision_type=DecisionType.REVIEWED,
                scope=scope, actor="analyst", effective_at=T0 + timedelta(minutes=index))
            self.assertEqual(len(decisions_for_scope(
                self.database, system_id="system-a", scope=scope)), 1)
        self.assertEqual(decisions_for_scope(
            self.database, system_id="system-a",
            scope=ListenerScope("tcp", "127.0.0.1", "all_interfaces", 8080, "/usr/bin/app")), ())
        with self.assertRaises(MemoryDecisionError):
            create_decision(
                self.database, system_id="system-a", decision_type=DecisionType.REVIEWED,
                scope="title contains exposed", actor="analyst", effective_at=T0)  # type: ignore

    def test_unsafe_actor_rationale_and_scope_values_are_rejected(self):
        invalid = ("token=secret", "bad\x00value", "x" * 1025, "$ rm -rf /tmp/example")
        for value in invalid:
            with self.assertRaises(MemoryDecisionError):
                create_decision(
                    self.database, system_id="system-a", decision_type=DecisionType.REVIEWED,
                    scope=FindingScope("finding:service"), actor="analyst",
                    rationale=value, effective_at=T0)
        with self.assertRaises(MemoryDecisionError):
            ApplicationScope("raw argv: python secret.py")
        with self.assertRaises(MemoryDecisionError):
            create_decision(
                self.database, system_id="system-a", decision_type=DecisionType.REVIEWED,
                scope=FindingScope("finding:service"), actor="token=secret",
                effective_at=T0)


class ExceptionTests(DecisionMemorySupport, unittest.TestCase):
    def test_expiration_is_mandatory_and_query_time_enforced_fail_closed(self):
        scope = FindingScope("finding:service")
        with self.assertRaises((TypeError, MemoryDecisionError)):
            create_exception(self.database, system_id="system-a", scope=scope,
                             approver="owner", starts_at=T0)  # type: ignore
        exception = create_exception(
            self.database, system_id="system-a", scope=scope, approver="owner",
            starts_at=T0, expires_at=T0 + timedelta(days=1))
        self.assertEqual(len(active_exceptions(
            self.database, system_id="system-a", at=T0 + timedelta(hours=1))), 1)
        self.assertEqual(active_exceptions(
            self.database, system_id="system-a", at=T0 + timedelta(days=1)), ())
        historical = exceptions_for_scope(
            self.database, system_id="system-a", scope=scope,
            at=T0 + timedelta(days=2))
        self.assertEqual(historical[0].status, ExceptionStatus.EXPIRED)
        stored = self.database.connection.execute(
            "SELECT status FROM exceptions WHERE exception_id=?", (exception.exception_id,)).fetchone()[0]
        self.assertEqual(stored, "ACTIVE")

    def test_revoked_and_superseded_exceptions_are_inactive(self):
        scope = FindingScope("finding:service")
        first = create_exception(
            self.database, system_id="system-a", scope=scope, approver="owner",
            starts_at=T0, expires_at=T0 + timedelta(days=2))
        second = supersede_exception(
            self.database, system_id="system-a", exception_id=first.exception_id,
            scope=scope, approver="owner", starts_at=T0,
            expires_at=T0 + timedelta(days=3))
        revoke_exception(self.database, system_id="system-a", exception_id=second.exception_id)
        self.assertEqual(active_exceptions(
            self.database, system_id="system-a", at=T0 + timedelta(hours=1)), ())
        history = exceptions_for_scope(self.database, system_id="system-a", scope=scope)
        self.assertEqual([item.status for item in history],
                         [ExceptionStatus.SUPERSEDED, ExceptionStatus.REVOKED])

    def test_cross_system_and_exact_scope_isolation(self):
        self.add_system("system-b")
        scope = ListenerScope("tcp", "0.0.0.0", "all", 8080, "/usr/bin/app")
        create_exception(self.database, system_id="system-a", scope=scope, approver="owner",
                         starts_at=T0, expires_at=T0 + timedelta(days=1))
        self.assertEqual(active_exceptions(
            self.database, system_id="system-b", at=T0 + timedelta(hours=1)), ())
        other = ListenerScope("tcp", "0.0.0.0", "all", 8081, "/usr/bin/app")
        self.assertEqual(exceptions_for_scope(
            self.database, system_id="system-a", scope=other), ())


class BaselineTests(DecisionMemorySupport, unittest.TestCase):
    def test_draft_approval_next_version_and_history(self):
        draft = create_draft_baseline(
            self.database, system_id="system-a", baseline_type=BaselineType.EXPECTED_SERVICES,
            entries=(BaselineEntry("service:ssh", "tcp/22"),), rationale="Initial baseline.")
        self.assertEqual((draft.version, draft.state), (1, BaselineState.DRAFT))
        approved = approve_baseline(
            self.database, system_id="system-a", baseline_id=draft.baseline_id,
            approver="owner", approved_at=T0)
        self.assertEqual(current_approved_baseline(
            self.database, system_id="system-a",
            baseline_type=BaselineType.EXPECTED_SERVICES).baseline_id, approved.baseline_id)
        next_draft = create_next_baseline_version(
            self.database, system_id="system-a", baseline_type=BaselineType.EXPECTED_SERVICES,
            entries=(BaselineEntry("service:https", "tcp/443"),))
        self.assertEqual((next_draft.version, next_draft.previous_baseline_id),
                         (2, approved.baseline_id))
        approve_baseline(self.database, system_id="system-a", baseline_id=next_draft.baseline_id,
                         approver="owner", approved_at=T0 + timedelta(days=1))
        history = baseline_history(
            self.database, system_id="system-a", baseline_type=BaselineType.EXPECTED_SERVICES)
        self.assertEqual([item.version for item in history], [1, 2])
        self.assertEqual([item.state for item in history],
                         [BaselineState.SUPERSEDED, BaselineState.APPROVED])

    def test_approved_baseline_and_entries_are_immutable(self):
        draft = create_draft_baseline(
            self.database, system_id="system-a", baseline_type=BaselineType.SYSTEM_POSTURE,
            entries=(BaselineEntry("posture", "restricted"),))
        approve_baseline(self.database, system_id="system-a", baseline_id=draft.baseline_id,
                         approver="owner", approved_at=T0)
        with self.assertRaises(MemoryDecisionError):
            approve_baseline(self.database, system_id="system-a", baseline_id=draft.baseline_id,
                             approver="other", approved_at=T0 + timedelta(days=1))
        with self.assertRaises(sqlite3.IntegrityError):
            self.database.connection.execute(
                "UPDATE baseline_entries SET entry_value='changed' WHERE baseline_id=?",
                (draft.baseline_id,))
        self.database.connection.rollback()

    def test_baseline_isolation(self):
        self.add_system("system-b")
        draft = create_draft_baseline(
            self.database, system_id="system-a", baseline_type=BaselineType.APPROVED_LISTENERS,
            entries=(BaselineEntry("listener", "tcp/8080"),))
        approve_baseline(self.database, system_id="system-a", baseline_id=draft.baseline_id,
                         approver="owner", approved_at=T0)
        self.assertIsNone(current_approved_baseline(
            self.database, system_id="system-b", baseline_type=BaselineType.APPROVED_LISTENERS))


class RecommendationAndAuthorityTests(DecisionMemorySupport, unittest.TestCase):
    def _authoritative_snapshot(self):
        tables = ("score_history", "finding_occurrences", "findings", "finding_lifecycle_events")
        return {table: tuple(tuple(row) for row in self.database.connection.execute(
            f"SELECT * FROM {table} ORDER BY 1")) for table in tables}

    def test_all_action_responses_persist_without_claiming_remediation(self):
        recommendation = record_recommendation_shown(
            self.database, system_id="system-a", finding_id="finding:service",
            action_id="action:restrict", trusted_text_hash=hashlib.sha256(b"trusted").hexdigest(),
            shown_at=T0)
        for index, response in enumerate(ActionResponseType):
            record_action_response(
                self.database, system_id="system-a",
                recommendation_event_id=recommendation.recommendation_event_id,
                action_id="action:restrict", response_type=response, actor="owner",
                recorded_at=T0 + timedelta(minutes=index),
                defer_until=T0 + timedelta(days=1) if response == ActionResponseType.DEFERRED else None)
        history = action_response_history(
            self.database, system_id="system-a", action_id="action:restrict")
        self.assertEqual([item.response_type for item in history], list(ActionResponseType))
        lifecycle = self.database.connection.execute(
            "SELECT lifecycle_state FROM findings WHERE system_id='system-a'").fetchone()[0]
        self.assertEqual(lifecycle, "ACTIVE")

    def test_all_context_records_leave_authoritative_state_byte_for_byte_unchanged(self):
        before = self._authoritative_snapshot()
        scope = FindingScope("finding:service")
        create_decision(self.database, system_id="system-a", decision_type=DecisionType.REVIEWED,
                        scope=scope, actor="owner", effective_at=T0)
        create_exception(self.database, system_id="system-a", scope=scope, approver="owner",
                         starts_at=T0, expires_at=T0 + timedelta(days=1))
        draft = create_draft_baseline(
            self.database, system_id="system-a", baseline_type=BaselineType.SYSTEM_POSTURE,
            entries=(BaselineEntry("posture", "restricted"),))
        approve_baseline(self.database, system_id="system-a", baseline_id=draft.baseline_id,
                         approver="owner", approved_at=T0)
        recommendation = record_recommendation_shown(
            self.database, system_id="system-a", action_id="action:review",
            trusted_text_hash=hashlib.sha256(b"review").hexdigest(), shown_at=T0)
        record_action_response(
            self.database, system_id="system-a",
            recommendation_event_id=recommendation.recommendation_event_id,
            action_id="action:review", response_type=ActionResponseType.COMPLETED,
            actor="owner", recorded_at=T0)
        self.assertEqual(before, self._authoritative_snapshot())


class DecisionMigrationTests(unittest.TestCase):
    def test_schema_two_and_three_migrate_forward_without_rewriting_history(self):
        migrations = discover_migrations()
        for starting_version in (2, 3):
            with self.subTest(starting_version=starting_version), tempfile.TemporaryDirectory() as directory:
                path = Path(directory, "memory.db")
                connection = sqlite3.connect(path)
                connection.row_factory = sqlite3.Row
                for migration in migrations[:starting_version]:
                    connection.executescript(migration.sql)
                connection.execute(
                    """CREATE TABLE schema_migrations (
                        version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL,
                        applied_at TEXT NOT NULL, application_version TEXT NOT NULL)""")
                for migration in migrations[:starting_version]:
                    connection.execute("INSERT INTO schema_migrations VALUES (?, ?, ?, 'then', 'memory-v0.2')",
                                       (migration.version, migration.name, migration.checksum))
                connection.execute("INSERT INTO systems VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                   ("preserved", "host", "then", "then", 1, "STABLE",
                                    "DETERMINISTIC_OBSERVATION", "then", "then"))
                connection.execute(f"PRAGMA user_version={starting_version}")
                connection.commit()
                connection.close()
                with open_memory_database(path) as database:
                    version = database.connection.execute("PRAGMA user_version").fetchone()[0]
                    retained = database.connection.execute("SELECT system_id FROM systems").fetchone()[0]
                self.assertEqual((version, retained), (CURRENT_MEMORY_SCHEMA_VERSION, "preserved"))

    def test_milestone_four_migration_failure_rolls_back_without_reset(self):
        migrations = discover_migrations()
        with tempfile.TemporaryDirectory() as directory:
            migration_dir = Path(directory, "migrations")
            migration_dir.mkdir()
            for migration in migrations[:3]:
                Path(migration_dir, f"{migration.version:04d}_{migration.name}.sql").write_text(
                    migration.sql, encoding="utf-8")
            Path(migration_dir, "0004_broken.sql").write_text(
                "CREATE TABLE partial_m4(value TEXT);\nTHIS IS NOT SQL;\n", encoding="utf-8")
            Path(migration_dir, "0005_placeholder.sql").write_text(
                "CREATE TABLE never_reached_m5(value TEXT);\n", encoding="utf-8")
            path = Path(directory, "memory.db")
            with self.assertRaises(MemoryMigrationFailed):
                open_memory_database(path, migration_directory=migration_dir)
            connection = sqlite3.connect(path)
            tables = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            connection.close()
        self.assertEqual(version, 3)
        self.assertNotIn("partial_m4", tables)
