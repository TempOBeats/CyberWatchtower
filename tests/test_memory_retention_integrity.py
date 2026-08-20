import copy
import io
import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cyberwatchtower.cli import main
from cyberwatchtower.capabilities.registry import PermissionClass
from cyberwatchtower.core.orchestrator import IntelligenceOrchestrator
from cyberwatchtower.memory import open_memory_database, open_memory_database_readonly
from cyberwatchtower.memory.decision_models import (
    BaselineEntry, BaselineType, DecisionType, FindingScope,
)
from cyberwatchtower.memory.decisions import (
    approve_baseline, create_decision, create_draft_baseline, create_exception,
    revoke_decision,
)
from cyberwatchtower.memory.errors import (
    MemoryCorrupt, MemoryIncompatibleVersion, MemoryRetentionApprovalError,
    MemoryRetentionError, MemoryUnavailable,
)
from cyberwatchtower.memory.ingestion import ingest_report
from cyberwatchtower.memory.ingestion_models import IngestionStatus, ReportIngestionRequest
from cyberwatchtower.memory.integrity import (
    check_integrity, diagnose_memory_path, memory_status, verify_canonical_report,
)
from cyberwatchtower.memory.integrity_models import ReportVerificationStatus
from cyberwatchtower.memory.investigation_models import InvestigationDisposition, ReferenceState, ReferenceType
from cyberwatchtower.memory.investigations import (
    attach_related_finding, attach_subject_finding, complete_investigation,
    create_conversation_reference, create_investigation, record_capability_proposal,
)
from cyberwatchtower.memory.models import CURRENT_MEMORY_SCHEMA_VERSION
from cyberwatchtower.memory.migrations import discover_migrations
from cyberwatchtower.memory.retention import (
    authorize_retention_plan, execute_retention_plan, plan_retention,
)
from cyberwatchtower.memory.retention_models import RetentionOutcome, RetentionPolicy
from cyberwatchtower.memory.service import SQLiteSecurityMemory


UTC = timezone.utc
T0 = datetime(2023, 1, 1, tzinfo=UTC)
NOW = datetime(2026, 1, 15, tzinfo=UTC)


def report(system_id="system-a", generated=T0):
    return {
        "schema_version": "1.1", "generated_at": generated.isoformat(),
        "system": {"system_id": system_id, "hostname": "host"},
        "coverage": {"network_socket_inspection": "COMPLETE"},
        "security_score": {"score": 80, "risk_level": "MEDIUM", "counts": {"HIGH": 1}},
        "findings": [{"finding_id": "finding:service", "title": "Exposed service",
            "description": "A listener is exposed.", "severity": "HIGH",
            "recommendation": "Restrict it.", "evidence": ["Port: 8080"],
            "confidence": 95, "technique_id": None, "source": "network",
            "kind": "RISK", "assessment_state": "CONFIRMED"}],
    }


class RetentionSupport:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / "private" / "memory.db"
        self.database = open_memory_database(self.path)
        self.report_path = self.root / "report.json"
        self.report_path.write_text(json.dumps(report()), encoding="utf-8")
        result = ingest_report(self.database, ReportIngestionRequest(self.report_path))
        self.assertEqual(result.status, IngestionStatus.INGESTED)
        self.report_id = result.report_id
        self.decision = create_decision(
            self.database, system_id="system-a", decision_type=DecisionType.REVIEWED,
            scope=FindingScope("finding:service"), actor="operator", effective_at=T0,
        )

    def tearDown(self):
        self.database.close()
        self.temp.cleanup()

    def authoritative(self):
        tables = ("reports", "score_history", "findings", "finding_occurrences",
                  "finding_lifecycle_events")
        return {table: tuple(tuple(row) for row in self.database.connection.execute(
            f"SELECT * FROM {table} ORDER BY 1")) for table in tables}

    def retention_targets(self):
        tables = (
            "exceptions", "recommendations_shown", "action_responses",
            "conversation_references", "capability_executions",
            "capability_execution_events", "investigations",
            "investigation_status_events", "investigation_findings",
            "investigation_scopes", "investigation_evidence",
            "investigation_questions", "investigation_recommendations",
        )
        return {table: tuple(tuple(row) for row in self.database.connection.execute(
            f"SELECT * FROM {table} ORDER BY 1")) for table in tables}

    def authorize(self, plan, at=NOW):
        return authorize_retention_plan(
            self.database, plan=plan, decision_id=self.decision.decision_id,
            at=at, expires_at=at + timedelta(minutes=30),
        )


class RetentionContractTests(RetentionSupport, unittest.TestCase):
    def seed_eligible(self):
        create_exception(
            self.database, system_id="system-a", scope=FindingScope("finding:service"),
            approver="operator", starts_at=T0, expires_at=T0 + timedelta(days=1),
        )
        investigation = create_investigation(
            self.database, system_id="system-a", title="Review service",
            actor="operator", opened_at=T0,
        )
        attach_subject_finding(
            self.database, system_id="system-a",
            investigation_id=investigation.investigation_id,
            finding_id="finding:service", attached_at=T0 + timedelta(hours=1),
        )
        attach_related_finding(
            self.database, system_id="system-a",
            investigation_id=investigation.investigation_id,
            finding_id="finding:service", attached_at=T0 + timedelta(hours=2),
        )
        complete_investigation(
            self.database, system_id="system-a", investigation_id=investigation.investigation_id,
            closed_at=T0 + timedelta(days=1),
            disposition=InvestigationDisposition.NO_ACTION,
        )
        create_conversation_reference(
            self.database, system_id="system-a", session_id="session:old",
            reference_type=ReferenceType.FINDING, target_id="finding:service",
            reference_state=ReferenceState.FOCUSED, created_at=T0,
            expires_at=T0 + timedelta(days=1),
        )

    def test_dry_run_is_deterministic_bounded_and_read_only(self):
        self.seed_eligible()
        before = {table: self.database.connection.execute(
            f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in (
                "exceptions", "investigations", "conversation_references",
                "retention_authorizations", "retention_executions")}
        first = plan_retention(self.database, system_id="system-a", at=NOW)
        second = plan_retention(self.database, system_id="system-a", at=NOW)
        after = {table: self.database.connection.execute(
            f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in before}
        self.assertEqual(first, second)
        self.assertEqual(before, after)
        self.assertTrue(first.items)
        self.assertLessEqual(len(first.items), RetentionPolicy().maximum_items)
        self.assertTrue(all(item.system_id == "system-a" for item in first.items))
        self.assertFalse(any("operator" in repr(item) for item in first.items))

    def test_exact_authorization_and_transactional_deletion_preserve_authority(self):
        self.seed_eligible()
        before = self.authoritative()
        plan = plan_retention(self.database, system_id="system-a", at=NOW)
        authorization = self.authorize(plan)
        result = execute_retention_plan(
            self.database, plan=plan, authorization_id=authorization.authorization_id,
            at=NOW + timedelta(minutes=1),
        )
        self.assertEqual(result.outcome, RetentionOutcome.SUCCEEDED)
        self.assertEqual(before, self.authoritative())
        self.assertEqual(self.database.connection.execute(
            "SELECT COUNT(*) FROM retention_executions").fetchone()[0], 1)
        self.assertEqual(self.database.connection.execute(
            "SELECT lifecycle_state FROM findings WHERE system_id='system-a'").fetchone()[0], "ACTIVE")

    def test_modified_stale_expired_and_wrong_system_approval_fail_closed(self):
        self.seed_eligible()
        plan = plan_retention(self.database, system_id="system-a", at=NOW)
        modified = replace(plan, policy_version="tampered")
        with self.assertRaises(MemoryRetentionApprovalError):
            self.authorize(modified)
        with self.assertRaises(MemoryRetentionApprovalError):
            self.authorize(plan, at=NOW + timedelta(hours=2))
        other_path = self.root / "other.json"
        other_path.write_text(json.dumps(report("system-b")), encoding="utf-8")
        ingest_report(self.database, ReportIngestionRequest(other_path))
        other_plan = plan_retention(self.database, system_id="system-b", at=NOW)
        with self.assertRaises(MemoryRetentionApprovalError):
            authorize_retention_plan(
                self.database, plan=other_plan, decision_id=self.decision.decision_id,
                at=NOW, expires_at=NOW + timedelta(minutes=5),
            )
        auth = self.authorize(plan)
        with self.assertRaises(MemoryRetentionApprovalError):
            execute_retention_plan(
                self.database, plan=plan, authorization_id=auth.authorization_id,
                at=NOW + timedelta(hours=1),
            )

    def test_revoked_linked_decision_invalidates_existing_authorization(self):
        self.seed_eligible()
        plan = plan_retention(self.database, system_id="system-a", at=NOW)
        auth = self.authorize(plan)
        revoke_decision(
            self.database, system_id="system-a", decision_id=self.decision.decision_id
        )
        with self.assertRaises(MemoryRetentionApprovalError):
            execute_retention_plan(
                self.database, plan=plan, authorization_id=auth.authorization_id,
                at=NOW + timedelta(minutes=1),
            )

    def test_missing_dependency_blocks_parent_and_failed_transaction_rolls_back(self):
        self.database.connection.execute("""INSERT INTO recommendations_shown VALUES
            ('recommendation:old','system-a','finding:service','action:old',?,?,'DERIVED_HISTORY')""",
            ("a" * 64, T0.isoformat()))
        self.database.connection.execute("""INSERT INTO action_responses VALUES
            ('response:recent','system-a','recommendation:old','action:old','ACKNOWLEDGED',
             'operator',NULL,?,NULL,'USER_DECISION')""", ((NOW - timedelta(days=1)).isoformat(),))
        self.database.connection.commit()
        plan = plan_retention(self.database, system_id="system-a", at=NOW)
        recommendation = next(item for item in plan.items if item.record_id == "recommendation:old")
        self.assertIsNotNone(recommendation.blocker)

        create_conversation_reference(
            self.database, system_id="system-a", session_id="session:old",
            reference_type=ReferenceType.FINDING, target_id="finding:service",
            reference_state=ReferenceState.FOCUSED, created_at=T0,
            expires_at=T0 + timedelta(days=1),
        )
        plan = plan_retention(self.database, system_id="system-a", at=NOW)
        auth = self.authorize(plan)
        target = next(item for item in plan.selected_items
                      if item.record_type.value == "CONVERSATION_REFERENCE")
        self.database.connection.execute(
            "DELETE FROM conversation_references WHERE reference_id=?", (target.record_id,))
        self.database.connection.commit()
        before = self.authoritative()
        retention_before = self.retention_targets()
        with self.assertRaises(MemoryRetentionError):
            execute_retention_plan(self.database, plan=plan,
                                   authorization_id=auth.authorization_id,
                                   at=NOW + timedelta(minutes=1))
        self.assertEqual(before, self.authoritative())
        self.assertEqual(retention_before, self.retention_targets())
        audit = self.database.connection.execute(
            "SELECT outcome,failure_code FROM retention_executions").fetchone()
        self.assertEqual(tuple(audit), ("FAILED", "TRANSACTION_FAILED"))

    def test_retention_audit_is_append_only(self):
        self.seed_eligible()
        plan = plan_retention(self.database, system_id="system-a", at=NOW)
        auth = self.authorize(plan)
        execute_retention_plan(self.database, plan=plan,
            authorization_id=auth.authorization_id, at=NOW + timedelta(minutes=1))
        with self.assertRaises(sqlite3.IntegrityError):
            self.database.connection.execute("DELETE FROM retention_executions")
        self.database.connection.rollback()

    def test_locked_retention_execution_is_typed_and_non_destructive(self):
        self.seed_eligible()
        plan = plan_retention(self.database, system_id="system-a", at=NOW)
        auth = self.authorize(plan)
        before = self.authoritative()
        lock = sqlite3.connect(self.path)
        lock.execute("BEGIN EXCLUSIVE")
        try:
            with self.assertRaises(MemoryRetentionError):
                execute_retention_plan(
                    self.database, plan=plan,
                    authorization_id=auth.authorization_id,
                    at=NOW + timedelta(minutes=1),
                )
        finally:
            lock.rollback()
            lock.close()
        self.assertEqual(before, self.authoritative())

    def test_active_exception_and_deterministic_history_are_never_eligible(self):
        active_exception = create_exception(
            self.database, system_id="system-a", scope=FindingScope("finding:service"),
            approver="operator", starts_at=NOW - timedelta(days=1),
            expires_at=NOW + timedelta(days=1),
        )
        draft = create_draft_baseline(
            self.database, system_id="system-a",
            baseline_type=BaselineType.APPROVED_LISTENERS,
            entries=(BaselineEntry("listener", "tcp/8080"),),
        )
        baseline = approve_baseline(
            self.database, system_id="system-a", baseline_id=draft.baseline_id,
            approver="operator", approved_at=NOW,
        )
        plan = plan_retention(self.database, system_id="system-a", at=NOW)
        types = {item.record_type.value for item in plan.items}
        ids = {item.record_id for item in plan.items}
        self.assertFalse(types.intersection({"REPORT", "SCORE", "FINDING", "OCCURRENCE", "LIFECYCLE"}))
        self.assertFalse(any(item.record_type.value == "EXPIRED_EXCEPTION" for item in plan.items))
        self.assertNotIn(active_exception.exception_id, ids)
        self.assertNotIn(baseline.baseline_id, ids)

    def test_old_denied_capability_audit_is_eligible_without_execution_output(self):
        proposal = record_capability_proposal(
            self.database, system_id="system-a", capability_id="inspect_service",
            permission_class=PermissionClass.PROHIBITED, requested_at=T0,
            parameter_summary={"protocol": "tcp", "port": 8080},
        )
        plan = plan_retention(self.database, system_id="system-a", at=NOW)
        self.assertTrue(any(item.record_id == proposal.execution_id
                            and item.record_type.value == "CAPABILITY_EXECUTION"
                            for item in plan.selected_items))


class IntegrityAndOperationsTests(RetentionSupport, unittest.TestCase):
    def test_integrity_is_read_only_and_status_is_sanitized(self):
        before = self.authoritative()
        report = check_integrity(self.database, at=NOW)
        status = memory_status(self.database, system_id="system-a", at=NOW)
        self.assertEqual(report.health, "HEALTHY")
        self.assertEqual(before, self.authoritative())
        rendered = repr(status)
        for forbidden in (str(self.path), str(self.report_path), "operator", "Port: 8080", "token="):
            self.assertNotIn(forbidden, rendered)

    def test_integrity_detects_migration_checksum_mismatch_without_repair(self):
        self.database.connection.execute(
            "UPDATE schema_migrations SET checksum='tampered' WHERE version=1")
        self.database.connection.commit()
        result = check_integrity(self.database, at=NOW)
        self.assertIn("MIGRATION_CHECKSUM_MISMATCH",
                      {item.code for item in result.diagnostics})
        retained = self.database.connection.execute(
            "SELECT checksum FROM schema_migrations WHERE version=1").fetchone()[0]
        self.assertEqual(retained, "tampered")

    def test_foreign_key_lifecycle_baseline_exception_and_migration_diagnostics(self):
        self.database.connection.execute("PRAGMA foreign_keys=OFF")
        self.database.connection.execute("""INSERT INTO system_aliases VALUES
            ('orphan','missing','HOSTNAME','host',?,NULL,'DERIVED_HISTORY')""", (T0.isoformat(),))
        self.database.connection.execute("PRAGMA user_version=5")
        self.database.connection.execute("""INSERT INTO retention_authorizations VALUES
            ('authorization:orphan','plan','b', 'system-a','missing-decision',?,?,1,
             'USER_DECISION')""", (T0.isoformat(), NOW.isoformat()))
        self.database.connection.commit()
        self.database.connection.execute("PRAGMA foreign_keys=ON")
        result = check_integrity(self.database, at=NOW)
        codes = {item.code for item in result.diagnostics}
        self.assertIn("FOREIGN_KEY_VIOLATION", codes)
        self.assertIn("MIGRATION_VERSION_MISMATCH", codes)
        self.assertIn("INVALID_RETENTION_AUTHORIZATION", codes)

    def test_canonical_report_verified_missing_invalid_inaccessible_and_mismatch(self):
        verified = verify_canonical_report(
            self.database, system_id="system-a", report_id=self.report_id)
        self.assertEqual(verified.status, ReportVerificationStatus.VERIFIED)
        with patch.object(Path, "open", side_effect=PermissionError):
            self.assertEqual(verify_canonical_report(
                self.database, system_id="system-a", report_id=self.report_id).status,
                ReportVerificationStatus.SOURCE_INACCESSIBLE)
        original = self.report_path.read_text(encoding="utf-8")
        changed = report(); changed["security_score"]["score"] = 50
        self.report_path.write_text(json.dumps(changed), encoding="utf-8")
        source_before = self.report_path.read_bytes()
        digest_before = self.database.connection.execute(
            "SELECT content_digest FROM reports WHERE report_id=?", (self.report_id,)
        ).fetchone()[0]
        self.assertEqual(verify_canonical_report(
            self.database, system_id="system-a", report_id=self.report_id).status,
            ReportVerificationStatus.DIGEST_MISMATCH)
        self.assertEqual(self.report_path.read_bytes(), source_before)
        self.assertEqual(self.database.connection.execute(
            "SELECT content_digest FROM reports WHERE report_id=?", (self.report_id,)
        ).fetchone()[0], digest_before)
        self.report_path.write_text("not-json", encoding="utf-8")
        self.assertEqual(verify_canonical_report(
            self.database, system_id="system-a", report_id=self.report_id).status,
            ReportVerificationStatus.INVALID_SOURCE)
        self.report_path.unlink()
        self.assertEqual(verify_canonical_report(
            self.database, system_id="system-a", report_id=self.report_id).status,
            ReportVerificationStatus.SOURCE_MISSING)
        self.assertEqual(verify_canonical_report(
            self.database, system_id="system-a", report_id="missing").status,
            ReportVerificationStatus.REPORT_NOT_FOUND)
        self.assertNotEqual(original, "")

    @unittest.skipUnless(os.name == "posix", "POSIX permissions required")
    def test_symlinks_rejected_and_database_companions_private(self):
        self.database.close()
        target = self.root / "target.db"
        target.write_bytes(b"")
        link = self.root / "link.db"
        link.symlink_to(target)
        with self.assertRaises(MemoryUnavailable):
            open_memory_database(link)
        shared = self.root / "shared"; shared.mkdir(mode=0o755)
        shared.chmod(0o755)
        with self.assertRaises(MemoryUnavailable):
            open_memory_database(shared / "memory.db")
        self.assertEqual(shared.stat().st_mode & 0o777, 0o755)
        with open_memory_database(self.path) as database:
            database.connection.execute("PRAGMA journal_mode=WAL")
            database.connection.execute("CREATE TABLE IF NOT EXISTS wal_probe(value TEXT)")
            database.connection.commit()
            for suffix in ("", "-wal", "-shm"):
                candidate = Path(f"{self.path}{suffix}")
                if candidate.exists():
                    self.assertEqual(candidate.stat().st_mode & 0o777, 0o600)
        self.database = open_memory_database(self.path)

    def test_readonly_open_and_corrupt_path_diagnostics_do_not_repair(self):
        with open_memory_database_readonly(self.path) as readonly:
            self.assertEqual(readonly.info.schema_version, CURRENT_MEMORY_SCHEMA_VERSION)
            with self.assertRaises(sqlite3.OperationalError):
                readonly.connection.execute("CREATE TABLE forbidden(value TEXT)")
        corrupt = self.root / "corrupt.db"
        original = b"secret-canary-not-sqlite"
        corrupt.write_bytes(original)
        diagnostic = diagnose_memory_path(corrupt)
        self.assertEqual(diagnostic.health, "UNAVAILABLE")
        self.assertEqual(corrupt.read_bytes(), original)
        self.assertNotIn("secret-canary", repr(diagnostic))

    def test_cli_status_check_and_disabled_mode_are_read_only_and_private(self):
        secret = "token=memory-status-canary"
        self.database.connection.execute(
            "UPDATE systems SET display_hostname=? WHERE system_id='system-a'", (secret,))
        self.database.connection.commit()
        self.database.close()
        output = io.StringIO()
        with redirect_stdout(output):
            main(["memory", "status", "--system-id", "system-a", "--memory-db", str(self.path)])
            main(["memory", "check", "--memory-db", str(self.path)])
        text = output.getvalue()
        self.assertIn("CYBERWATCHTOWER MEMORY", text)
        self.assertIn("Health:", text)
        self.assertNotIn(str(self.path), text)
        self.assertNotIn(str(self.report_path), text)
        self.assertNotIn(secret, text)
        disabled = io.StringIO()
        with patch.dict(os.environ, {}, clear=True), redirect_stdout(disabled):
            main(["memory", "check"])
        self.assertIn("Memory is disabled", disabled.getvalue())
        self.database = open_memory_database(self.path)


class MemoryV02AcceptanceTests(RetentionSupport, unittest.TestCase):
    def test_complete_v02_flow_preserves_deterministic_authority(self):
        before = self.authoritative()
        create_exception(
            self.database, system_id="system-a", scope=FindingScope("finding:service"),
            approver="operator", starts_at=T0, expires_at=T0 + timedelta(days=1),
        )
        investigation = create_investigation(
            self.database, system_id="system-a", title="Review service",
            actor="operator", opened_at=T0)
        complete_investigation(
            self.database, system_id="system-a", investigation_id=investigation.investigation_id,
            closed_at=T0 + timedelta(days=1), disposition=InvestigationDisposition.NO_ACTION)
        service = SQLiteSecurityMemory(self.database)
        result = IntelligenceOrchestrator(memory=service).handle(
            "Give me my security briefing", reports=(report(),))
        self.assertEqual(result.briefing.advisor_context.score, 80)
        self.assertTrue(any(section.section_id == "memory-history"
                            for section in result.response.sections))
        plan = plan_retention(self.database, system_id="system-a", at=NOW)
        self.assertTrue(plan.selected_items)
        self.assertEqual(check_integrity(self.database, at=NOW).health, "HEALTHY")
        self.assertEqual(before, self.authoritative())
        disabled = IntelligenceOrchestrator().handle(
            "Give me my security briefing", reports=(report(),))
        self.assertEqual(disabled.briefing.advisor_context.score, 80)


class RetentionMigrationTests(unittest.TestCase):
    def test_schema_versions_one_through_five_migrate_forward(self):
        migrations = discover_migrations()
        for old_version in range(1, 6):
            with self.subTest(old_version=old_version), tempfile.TemporaryDirectory() as directory:
                path = Path(directory, "memory.db")
                connection = sqlite3.connect(path)
                connection.execute("""CREATE TABLE schema_migrations (
                    version INTEGER PRIMARY KEY,name TEXT NOT NULL,checksum TEXT NOT NULL,
                    applied_at TEXT NOT NULL,application_version TEXT NOT NULL)""")
                for migration in migrations[:old_version]:
                    connection.executescript(migration.sql)
                    connection.execute("INSERT INTO schema_migrations VALUES (?,?,?,?,?)", (
                        migration.version, migration.name, migration.checksum,
                        T0.isoformat(), "memory-v0.2"))
                connection.execute(f"PRAGMA user_version={old_version}")
                connection.commit(); connection.close()
                with open_memory_database(path) as database:
                    self.assertEqual(database.info.schema_version, CURRENT_MEMORY_SCHEMA_VERSION)
                    self.assertEqual(database.info.migration_count, CURRENT_MEMORY_SCHEMA_VERSION)

    def test_migration_six_failure_rolls_back_to_version_five(self):
        migrations = discover_migrations()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory, "migrations"); root.mkdir()
            for migration in migrations[:5]:
                Path(root, f"{migration.version:04d}_{migration.name}.sql").write_text(
                    migration.sql, encoding="utf-8")
            Path(root, "0006_broken.sql").write_text(
                "CREATE TABLE partial_m6(value TEXT);\nNOT SQL;\n", encoding="utf-8")
            Path(root, "0007_placeholder.sql").write_text(
                "CREATE TABLE never_reached_m7(value TEXT);\n", encoding="utf-8")
            Path(root, "0008_placeholder.sql").write_text(
                "CREATE TABLE never_reached_m8(value TEXT);\n", encoding="utf-8")
            path = Path(directory, "memory.db")
            from cyberwatchtower.memory.errors import MemoryMigrationFailed
            with self.assertRaises(MemoryMigrationFailed):
                open_memory_database(path, migration_directory=root)
            connection = sqlite3.connect(path)
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            tables = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            connection.close()
        self.assertEqual(version, 5)
        self.assertNotIn("partial_m6", tables)


if __name__ == "__main__":
    unittest.main()
