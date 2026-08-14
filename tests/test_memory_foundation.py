import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cyberwatchtower.core.evidence import EpistemicRole
from cyberwatchtower.memory.database import REQUIRED_INDEXES, REQUIRED_TABLES, open_memory_database
from cyberwatchtower.memory.errors import (
    MemoryCorrupt,
    MemoryIncompatibleVersion,
    MemoryMigrationChecksumMismatch,
    MemoryMigrationFailed,
)
from cyberwatchtower.memory.models import CURRENT_MEMORY_SCHEMA_VERSION
from cyberwatchtower.memory.migrations import discover_migrations
from cyberwatchtower.memory.provenance import MemoryProvenance, provenance_epistemic_role


class ProvenanceTests(unittest.TestCase):
    def test_every_closed_provenance_maps_explicitly_to_epistemic_role(self):
        expected = {
            MemoryProvenance.DETERMINISTIC_OBSERVATION: EpistemicRole.OBSERVED_FACT,
            MemoryProvenance.DERIVED_HISTORY: EpistemicRole.DETERMINISTIC_DERIVATION,
            MemoryProvenance.USER_ASSERTION: EpistemicRole.USER_ASSERTION,
            MemoryProvenance.USER_DECISION: EpistemicRole.USER_DECISION,
            MemoryProvenance.RETRIEVED_KNOWLEDGE: EpistemicRole.EXTERNAL_KNOWLEDGE,
            MemoryProvenance.MODEL_INTERPRETATION: EpistemicRole.MODEL_INTERPRETATION,
        }
        self.assertEqual(set(expected), set(MemoryProvenance))
        for provenance, role in expected.items():
            self.assertEqual(provenance_epistemic_role(provenance), role)


class MemoryDatabaseTests(unittest.TestCase):
    def test_existing_schema_one_database_migrates_forward_without_reset(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "memory.sqlite3")
            first_migration = discover_migrations()[0]
            connection = sqlite3.connect(path)
            connection.executescript(first_migration.sql)
            connection.execute(
                """CREATE TABLE schema_migrations (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    checksum TEXT NOT NULL,
                    applied_at TEXT NOT NULL,
                    application_version TEXT NOT NULL
                )"""
            )
            connection.execute(
                "INSERT INTO schema_migrations VALUES (1, ?, ?, 'then', 'memory-v0.2')",
                (first_migration.name, first_migration.checksum),
            )
            connection.execute("INSERT INTO systems VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (
                "cwt-preserved", "host", "then", "then", 1, "STABLE",
                "DETERMINISTIC_OBSERVATION", "then", "then",
            ))
            connection.execute("PRAGMA user_version = 1")
            connection.commit()
            connection.close()

            with open_memory_database(path) as database:
                version = database.connection.execute("PRAGMA user_version").fetchone()[0]
                system = database.connection.execute(
                    "SELECT system_id FROM systems"
                ).fetchone()[0]
                columns = {
                    row[1] for row in database.connection.execute("PRAGMA table_info(reports)")
                }
        self.assertEqual(version, CURRENT_MEMORY_SCHEMA_VERSION)
        self.assertEqual(system, "cwt-preserved")
        self.assertIn("coverage_json", columns)

    def test_fresh_database_migrates_and_reopen_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "private", "memory.sqlite3")
            with open_memory_database(path) as first:
                first_count = first.info.migration_count
            with open_memory_database(path) as second:
                second_count = second.info.migration_count
                version = second.connection.execute("PRAGMA user_version").fetchone()[0]
        self.assertEqual(first_count, CURRENT_MEMORY_SCHEMA_VERSION)
        self.assertEqual(second_count, CURRENT_MEMORY_SCHEMA_VERSION)
        self.assertEqual(version, CURRENT_MEMORY_SCHEMA_VERSION)

    def test_checksum_mismatch_is_detected_without_reset(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "memory.sqlite3")
            with open_memory_database(path) as database:
                database.connection.execute(
                    "UPDATE schema_migrations SET checksum = ? WHERE version = 1",
                    ("tampered",),
                )
                database.connection.commit()
            with self.assertRaises(MemoryMigrationChecksumMismatch):
                open_memory_database(path)
            connection = sqlite3.connect(path)
            checksum = connection.execute(
                "SELECT checksum FROM schema_migrations WHERE version = 1"
            ).fetchone()[0]
            connection.close()
        self.assertEqual(checksum, "tampered")

    def test_newer_database_is_rejected_without_destructive_reset(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "memory.sqlite3")
            connection = sqlite3.connect(path)
            connection.execute("CREATE TABLE sentinel (value TEXT)")
            connection.execute("INSERT INTO sentinel VALUES ('preserved')")
            connection.execute("PRAGMA user_version = 99")
            connection.commit()
            connection.close()
            with self.assertRaises(MemoryIncompatibleVersion):
                open_memory_database(path)
            connection = sqlite3.connect(path)
            value = connection.execute("SELECT value FROM sentinel").fetchone()[0]
            connection.close()
        self.assertEqual(value, "preserved")

    def test_inconsistent_migration_version_is_rejected_without_reset(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "memory.sqlite3")
            with open_memory_database(path):
                pass
            connection = sqlite3.connect(path)
            connection.execute("PRAGMA user_version = 0")
            connection.commit()
            connection.close()
            with self.assertRaises(MemoryIncompatibleVersion):
                open_memory_database(path)
            connection = sqlite3.connect(path)
            migration_count = connection.execute(
                "SELECT COUNT(*) FROM schema_migrations"
            ).fetchone()[0]
            connection.close()
        self.assertEqual(migration_count, CURRENT_MEMORY_SCHEMA_VERSION)

    def test_corrupt_database_is_classified_and_not_recreated(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "memory.sqlite3")
            original = b"not a sqlite database"
            path.write_bytes(original)
            with self.assertRaises(MemoryCorrupt):
                open_memory_database(path)
            retained = path.read_bytes()
        self.assertEqual(retained, original)

    def test_failed_migration_rolls_back_all_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            migration_dir = Path(directory, "migrations")
            migration_dir.mkdir()
            Path(migration_dir, "0001_broken.sql").write_text(
                "CREATE TABLE partial (value TEXT);\nTHIS IS NOT SQL;\n",
                encoding="utf-8",
            )
            Path(migration_dir, "0002_placeholder.sql").write_text(
                "CREATE TABLE never_reached (value TEXT);\n",
                encoding="utf-8",
            )
            path = Path(directory, "memory.sqlite3")
            with self.assertRaises(MemoryMigrationFailed):
                open_memory_database(path, migration_directory=migration_dir)
            connection = sqlite3.connect(path)
            tables = {
                row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            connection.close()
        self.assertNotIn("partial", tables)
        self.assertNotIn("schema_migrations", tables)
        self.assertEqual(version, 0)

    def test_foreign_keys_constraints_and_expected_indexes_are_present(self):
        with tempfile.TemporaryDirectory() as directory:
            with open_memory_database(Path(directory, "memory.sqlite3")) as database:
                connection = database.connection
                objects = {
                    row["name"]: row["type"]
                    for row in connection.execute(
                        "SELECT name, type FROM sqlite_master WHERE type IN ('table', 'index')"
                    )
                }
                self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
                self.assertEqual(connection.execute("PRAGMA busy_timeout").fetchone()[0], 2000)
                if hasattr(connection, "enable_load_extension"):
                    with self.assertRaises(sqlite3.OperationalError):
                        connection.execute("SELECT load_extension('not-allowed')")
                self.assertTrue(REQUIRED_TABLES.issubset(objects))
                self.assertTrue(REQUIRED_INDEXES.issubset(objects))
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        """INSERT INTO reports
                           (report_id, system_id, generated_at, ingested_at,
                            report_schema_version, content_digest, source_path,
                            source_filename, provenance, legacy_identity_state,
                            ingestion_status)
                           VALUES ('report', 'missing-system', 'now', 'now', '1.1',
                                   'digest', NULL, NULL, 'DETERMINISTIC_OBSERVATION',
                                   'NATIVE_SYSTEM_ID', 'COMPLETE')"""
                    )

    @unittest.skipUnless(os.name == "posix", "POSIX permission bits required")
    def test_database_directory_and_file_are_private(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "memory", "memory.sqlite3")
            with open_memory_database(path):
                directory_mode = path.parent.stat().st_mode & 0o777
                file_mode = path.stat().st_mode & 0o777
        self.assertEqual(directory_mode, 0o700)
        self.assertEqual(file_mode, 0o600)


class MemoryIsolationTests(unittest.TestCase):
    def test_memory_package_does_not_import_or_invoke_scanner_collectors(self):
        memory_root = Path(__file__).parents[1] / "src" / "cyberwatchtower" / "memory"
        source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in memory_root.rglob("*.py")
        )
        prohibited = (
            "cyberwatchtower.scanner",
            "run_scan(",
            "inspect_listening_services(",
            "inspect_iptables(",
            "collect_system_information(",
            "subprocess",
        )
        for value in prohibited:
            self.assertNotIn(value, source)


if __name__ == "__main__":
    unittest.main()
