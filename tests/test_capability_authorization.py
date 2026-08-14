import tempfile
import unittest
import sqlite3
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cyberwatchtower.capabilities.registry import (
    ApprovalRequired, CapabilityContext, CapabilityRequest, build_read_only_registry,
)
from cyberwatchtower.memory.authorization_models import CapabilityAuthorizationRequest
from cyberwatchtower.memory.authorizations import (
    create_capability_authorization, validate_capability_authorization,
)
from cyberwatchtower.memory.database import open_memory_database
from cyberwatchtower.memory.decision_models import (
    DecisionType, FindingScope,
)
from cyberwatchtower.memory.decisions import (
    create_decision, revoke_decision, supersede_decision,
)
from cyberwatchtower.memory.errors import MemoryAuthorizationError
from cyberwatchtower.memory.errors import MemoryMigrationFailed
from cyberwatchtower.memory.migrations import discover_migrations


T0 = datetime(2026, 8, 13, 12, tzinfo=timezone.utc)


class CapabilityAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = open_memory_database(Path(self.directory.name, "memory.db"))
        self.database.connection.execute(
            "INSERT INTO systems VALUES (?,?,?,?,?,?,?,?,?)",
            ("system-a", "host", T0.isoformat(), T0.isoformat(), 1, "STABLE",
             "DETERMINISTIC_OBSERVATION", T0.isoformat(), T0.isoformat()),
        )
        self.database.connection.execute(
            "INSERT INTO systems VALUES (?,?,?,?,?,?,?,?,?)",
            ("system-b", "host", T0.isoformat(), T0.isoformat(), 1, "STABLE",
             "DETERMINISTIC_OBSERVATION", T0.isoformat(), T0.isoformat()),
        )
        self.database.connection.commit()
        self.scope = FindingScope("finding:exposed")
        self.decision = create_decision(
            self.database, system_id="system-a", decision_type=DecisionType.REVIEWED,
            scope=self.scope, actor="owner", effective_at=T0,
            expires_at=T0 + timedelta(hours=2),
        )
        self.parameters = {"finding_id": "finding:exposed", "application": "/usr/bin/wsdd"}
        self.envelope = create_capability_authorization(
            self.database, system_id="system-a", capability_id="inspect_process",
            target_scope=self.scope, parameters=self.parameters,
            proposal_id="proposal:one", decision_id=self.decision.decision_id,
            issued_at=T0 + timedelta(minutes=1),
            expires_at=T0 + timedelta(hours=1),
        )

    def tearDown(self):
        self.database.close()
        self.directory.cleanup()

    def request(self, **changes):
        values = {
            "authorization_id": self.envelope.authorization_id,
            "system_id": "system-a",
            "capability_id": "inspect_process",
            "target_scope": self.scope,
            "parameters": self.parameters,
            "proposal_id": "proposal:one",
            "execution_at": T0 + timedelta(minutes=30),
        }
        values.update(changes)
        return CapabilityAuthorizationRequest(**values)

    def test_exact_match_validates_but_cannot_execute_capability(self):
        validated = validate_capability_authorization(self.database, self.request())
        self.assertEqual(validated.authorization_id, self.envelope.authorization_id)
        with self.assertRaises(ApprovalRequired):
            build_read_only_registry().execute(
                CapabilityRequest("inspect_process", dict(self.parameters)),
                CapabilityContext(),
            )

    def test_changed_binding_fields_fail_closed(self):
        cases = (
            {"parameters": {"finding_id": "finding:other", "application": "/usr/bin/wsdd"}},
            {"target_scope": FindingScope("finding:other")},
            {"system_id": "system-b"},
            {"capability_id": "scan_host", "parameters": {"system_id": "system-a"}},
            {"proposal_id": "proposal:other"},
        )
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(MemoryAuthorizationError):
                validate_capability_authorization(self.database, self.request(**changes))

    def test_expired_revoked_and_superseded_decisions_fail_at_execution_time(self):
        with self.assertRaises(MemoryAuthorizationError):
            validate_capability_authorization(
                self.database,
                self.request(execution_at=T0 + timedelta(hours=1, seconds=1)),
            )
        revoke_decision(
            self.database, system_id="system-a", decision_id=self.decision.decision_id
        )
        with self.assertRaises(MemoryAuthorizationError):
            validate_capability_authorization(self.database, self.request())

        second = create_decision(
            self.database, system_id="system-a", decision_type=DecisionType.REVIEWED,
            scope=self.scope, actor="owner", effective_at=T0,
            expires_at=T0 + timedelta(hours=2),
        )
        second_envelope = create_capability_authorization(
            self.database, system_id="system-a", capability_id="inspect_process",
            target_scope=self.scope, parameters=self.parameters,
            proposal_id="proposal:two", decision_id=second.decision_id,
            issued_at=T0 + timedelta(minutes=1), expires_at=T0 + timedelta(hours=1),
        )
        supersede_decision(
            self.database, system_id="system-a", decision_id=second.decision_id,
            decision_type=DecisionType.REVIEWED, scope=self.scope, actor="owner",
            effective_at=T0 + timedelta(minutes=2),
            expires_at=T0 + timedelta(hours=2),
        )
        with self.assertRaises(MemoryAuthorizationError):
            validate_capability_authorization(
                self.database,
                replace(self.request(), authorization_id=second_envelope.authorization_id,
                        proposal_id="proposal:two"),
            )

    def test_fabricated_or_model_supplied_authorization_cannot_validate(self):
        with self.assertRaises(MemoryAuthorizationError):
            validate_capability_authorization(
                self.database,
                self.request(authorization_id="model:fabricated-approval"),
            )


class CapabilityAuthorizationMigrationTests(unittest.TestCase):
    def test_schema_six_migrates_forward_and_seven_rolls_back_on_failure(self):
        migrations = discover_migrations()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "schema-six.db")
            connection = sqlite3.connect(path)
            connection.execute("""CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,name TEXT NOT NULL,checksum TEXT NOT NULL,
                applied_at TEXT NOT NULL,application_version TEXT NOT NULL)""")
            for migration in migrations[:6]:
                connection.executescript(migration.sql)
                connection.execute("INSERT INTO schema_migrations VALUES (?,?,?,?,?)", (
                    migration.version, migration.name, migration.checksum,
                    T0.isoformat(), "memory-v0.2"))
            connection.execute("PRAGMA user_version=6")
            connection.commit(); connection.close()
            with open_memory_database(path) as database:
                self.assertEqual(database.info.schema_version, 7)
                self.assertIsNotNone(database.connection.execute(
                    "SELECT name FROM sqlite_master WHERE name='idx_reports_content_digest'"
                ).fetchone())

        with tempfile.TemporaryDirectory() as directory:
            migration_dir = Path(directory, "migrations"); migration_dir.mkdir()
            for migration in migrations[:6]:
                Path(migration_dir, f"{migration.version:04d}_{migration.name}.sql").write_text(
                    migration.sql, encoding="utf-8")
            Path(migration_dir, "0007_broken.sql").write_text(
                "CREATE TABLE partial_v7(value TEXT);\nNOT SQL;\n", encoding="utf-8")
            path = Path(directory, "rollback.db")
            with self.assertRaises(MemoryMigrationFailed):
                open_memory_database(path, migration_directory=migration_dir)
            connection = sqlite3.connect(path)
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            tables = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            connection.close()
        self.assertEqual(version, 6)
        self.assertNotIn("partial_v7", tables)
