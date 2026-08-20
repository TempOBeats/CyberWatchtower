import json
import shutil
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from cyberwatchtower.memory.database import open_memory_database
from cyberwatchtower.memory.errors import MemoryMigrationFailed, MemoryQueryError
from cyberwatchtower.memory.history_models import ScoreTrendQuery
from cyberwatchtower.memory.ingestion import ingest_report
from cyberwatchtower.memory.ingestion_models import IngestionStatus, ReportIngestionRequest
from cyberwatchtower.memory.integrity import check_integrity
from cyberwatchtower.memory.migrations import discover_migrations
from cyberwatchtower.memory.models import CURRENT_MEMORY_SCHEMA_VERSION
from cyberwatchtower.memory.queries import score_trend, score_trends_by_version
from cyberwatchtower.models import AssessmentState, Finding, FindingKind, Severity
from cyberwatchtower.reporting import save_json_report
from cyberwatchtower.scoring_contracts import ScoringCategory, ScoringFinding
from cyberwatchtower.scoring_v2 import calculate_security_score_v2


def _create_database_at_version(path: Path, version: int) -> None:
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
    migrations = discover_migrations()
    for migration in migrations[:version]:
        connection.executescript(migration.sql)
        connection.execute(
            """INSERT INTO schema_migrations
               (version, name, checksum, applied_at, application_version)
               VALUES (?, ?, ?, 'then', 'memory-v0.2')""",
            (migration.version, migration.name, migration.checksum),
        )
        connection.execute(f"PRAGMA user_version={migration.version}")
    connection.commit()
    connection.close()


def _report(system_id: str, timestamp: str, score: int, *, version: str = "1") -> dict:
    risk = "LOW" if score >= 90 else "MODERATE"
    if version == "1":
        return {
            "schema_version": "1.4",
            "generated_at": timestamp,
            "system": {"system_id": system_id, "hostname": "test-host"},
            "assessment_domains": ["network_socket_inspection"],
            "coverage": {"network_socket_inspection": "COMPLETE"},
            "security_score": {
                "scoring_version": "1", "score": score, "risk_level": risk,
                "counts": {},
            },
            "findings": [],
        }
    finding = Finding(
        "Deterministic risk", "A deterministic condition.", Severity.MEDIUM,
        "Review the condition.", finding_id="finding:v2", source="deterministic",
        kind=FindingKind.RISK, assessment_state=AssessmentState.CONFIRMED,
    )
    scoring = calculate_security_score_v2((ScoringFinding(
        "finding:v2", Severity.MEDIUM, FindingKind.RISK,
        AssessmentState.CONFIRMED, "deterministic",
        ScoringCategory.OTHER_DETERMINISTIC_RISK,
    ),))
    return {
        "system": {"system_id": system_id, "hostname": "test-host"},
        "assessment_domains": ["network_socket_inspection"],
        "coverage": {"network_socket_inspection": "COMPLETE"},
        "findings": [finding],
        "score": scoring,
        "generated_at": timestamp,
    }


class MemoryScoringVersionMigrationTests(unittest.TestCase):
    def test_fresh_database_has_closed_default_v1_scoring_version(self):
        with tempfile.TemporaryDirectory() as directory:
            with open_memory_database(Path(directory, "memory.db")) as database:
                columns = {row["name"]: row for row in database.connection.execute(
                    "PRAGMA table_info(score_history)"
                )}
                version = database.connection.execute("PRAGMA user_version").fetchone()[0]
        column = columns["scoring_version"]
        self.assertEqual(version, CURRENT_MEMORY_SCHEMA_VERSION)
        self.assertEqual((column["type"], column["notnull"], column["dflt_value"]),
                         ("TEXT", 1, "'1'"))

    def test_schema_seven_rows_migrate_additively_without_recomputation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "memory.db")
            _create_database_at_version(path, 7)
            connection = sqlite3.connect(path)
            connection.execute(
                "INSERT INTO systems VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("cwt-system", "host", "then", "then", 1, "STABLE",
                 "DETERMINISTIC_OBSERVATION", "then", "then"),
            )
            connection.execute(
                """INSERT INTO reports
                   (report_id,system_id,generated_at,ingested_at,report_schema_version,
                    content_digest,source_path,source_filename,provenance,
                    legacy_identity_state,ingestion_status,coverage_json)
                   VALUES ('report:one','cwt-system','2026-01-01','then','1.3',
                    'digest',NULL,NULL,'DETERMINISTIC_OBSERVATION','NATIVE_SYSTEM_ID',
                    'COMPLETE','{}')"""
            )
            original = ("report:one", "cwt-system", 17, "LOW", 1, 2, 3, 4, 5,
                        "2026-01-01", "DETERMINISTIC_OBSERVATION")
            connection.execute(
                "INSERT INTO score_history VALUES (?,?,?,?,?,?,?,?,?,?,?)", original
            )
            connection.commit()
            before = connection.execute("SELECT * FROM score_history").fetchone()
            connection.close()
            with open_memory_database(path) as database:
                after = database.connection.execute(
                    "SELECT * FROM score_history"
                ).fetchone()
            self.assertEqual(tuple(after[:-1]), tuple(before))
            self.assertEqual(after[-1], "1")

    def test_every_supported_earlier_schema_migrates_forward(self):
        for version in range(1, CURRENT_MEMORY_SCHEMA_VERSION):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as directory:
                path = Path(directory, "memory.db")
                _create_database_at_version(path, version)
                with open_memory_database(path) as database:
                    current = database.connection.execute("PRAGMA user_version").fetchone()[0]
                    columns = {row["name"] for row in database.connection.execute(
                        "PRAGMA table_info(score_history)"
                    )}
                self.assertEqual(current, CURRENT_MEMORY_SCHEMA_VERSION)
                self.assertIn("scoring_version", columns)

    def test_failed_eighth_migration_rolls_back_column_and_version(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "memory.db")
            _create_database_at_version(path, 7)
            migration_dir = Path(directory, "migrations")
            migration_dir.mkdir()
            for source in Path("src/cyberwatchtower/memory/schema").glob("*.sql"):
                if source.name.startswith("0008_"):
                    continue
                shutil.copyfile(source, migration_dir / source.name)
            (migration_dir / "0008_broken.sql").write_text(
                "ALTER TABLE score_history ADD COLUMN scoring_version TEXT NOT NULL DEFAULT '1';\n"
                "THIS IS NOT SQL;\n", encoding="utf-8",
            )
            with self.assertRaises(MemoryMigrationFailed):
                open_memory_database(path, migration_directory=migration_dir)
            connection = sqlite3.connect(path)
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            columns = {row[1] for row in connection.execute("PRAGMA table_info(score_history)")}
            migration = connection.execute(
                "SELECT COUNT(*) FROM schema_migrations WHERE version=8"
            ).fetchone()[0]
            connection.close()
        self.assertEqual((version, migration), (7, 0))
        self.assertNotIn("scoring_version", columns)


class MemoryScoringVersionIngestionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.database = open_memory_database(Path(self.temporary.name, "memory.db"))
        self.number = 0

    def tearDown(self):
        self.database.close()
        self.temporary.cleanup()

    def _ingest(self, value: dict) -> IngestionStatus:
        self.number += 1
        path = Path(self.temporary.name, f"report-{self.number}.json")
        if "score" in value:
            value = dict(value)
            generated_at = value.pop("generated_at")
            path = save_json_report(value, Path(self.temporary.name, f"saved-{self.number}"))
            serialized = json.loads(path.read_text(encoding="utf-8"))
            serialized["generated_at"] = generated_at
            path.write_text(json.dumps(serialized), encoding="utf-8")
        else:
            path.write_text(json.dumps(value), encoding="utf-8")
        return ingest_report(self.database, ReportIngestionRequest(path)).status

    def test_explicit_v1_and_v2_coexist_and_queries_segment_them(self):
        self.assertEqual(self._ingest(_report(
            "cwt-system", "2026-08-01T00:00:00+00:00", 91,
        )), IngestionStatus.INGESTED)
        self.assertEqual(self._ingest(_report(
            "cwt-system", "2026-08-02T00:00:00+00:00", 89, version="2",
        )), IngestionStatus.INGESTED)
        query = ScoreTrendQuery(
            "cwt-system", datetime(2026, 8, 1, tzinfo=timezone.utc),
            datetime(2026, 8, 3, tzinfo=timezone.utc),
        )
        points = score_trend(self.database, query)
        series = score_trends_by_version(self.database, query)
        self.assertEqual([(item.score, item.scoring_version) for item in points],
                         [(91, "1"), (89, "2")])
        self.assertEqual([(item.scoring_version, item.average_score) for item in series],
                         [("1", 91.0), ("2", 89.0)])
        self.assertEqual(score_trend(self.database, ScoreTrendQuery(
            query.system_id, query.start_at, query.end_at, "2"
        )), (points[1],))

    def test_same_version_summary_is_exact_and_never_recomputes_scores(self):
        for day, score in ((1, 80), (2, 90), (3, 70)):
            self.assertEqual(self._ingest(_report(
                "cwt-system", f"2026-08-0{day}T00:00:00+00:00", score,
            )), IngestionStatus.INGESTED)
        series = score_trends_by_version(self.database, ScoreTrendQuery(
            "cwt-system", datetime(2026, 8, 1, tzinfo=timezone.utc),
            datetime(2026, 8, 4, tzinfo=timezone.utc), "1",
        ))[0]
        self.assertEqual([point.score for point in series.points], [80, 90, 70])
        self.assertEqual((series.average_score, series.best_score, series.worst_score,
                          series.overall_change, series.trend),
                         (80.0, 90, 70, -10, "DECLINED"))

    def test_invalid_version_fails_before_any_durable_write(self):
        value = _report("cwt-system", "2026-08-01T00:00:00+00:00", 91)
        value["security_score"]["scoring_version"] = "model-selected"
        self.assertEqual(self._ingest(value), IngestionStatus.INVALID)
        counts = tuple(self.database.connection.execute(
            f"SELECT COUNT(*) FROM {table}"
        ).fetchone()[0] for table in ("systems", "reports", "score_history", "findings"))
        self.assertEqual(counts, (0, 0, 0, 0))

    def test_duplicate_ingestion_and_integrity_remain_unchanged(self):
        value = _report("cwt-system", "2026-08-01T00:00:00+00:00", 91)
        self.assertEqual(self._ingest(value), IngestionStatus.INGESTED)
        self.number -= 1
        self.assertEqual(self._ingest(value), IngestionStatus.DUPLICATE)
        self.assertEqual(self.database.connection.execute(
            "SELECT COUNT(*) FROM score_history"
        ).fetchone()[0], 1)
        self.assertEqual(check_integrity(self.database).health, "HEALTHY")

    def test_score_query_rejects_unsupported_version(self):
        with self.assertRaises(MemoryQueryError):
            ScoreTrendQuery(
                "cwt-system", datetime(2026, 8, 1, tzinfo=timezone.utc),
                datetime(2026, 8, 2, tzinfo=timezone.utc), "3",
            )


if __name__ == "__main__":
    unittest.main()
