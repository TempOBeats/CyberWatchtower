import dataclasses
import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import cyberwatchtower.application as application
from cyberwatchtower.application import _history as history_boundary
from cyberwatchtower.application import _memory as memory_boundary
from cyberwatchtower.application import reports as report_boundary
from cyberwatchtower.memory import open_memory_database
from cyberwatchtower.memory.errors import (
    MemoryCorrupt,
    MemoryIncompatibleVersion,
    MemoryIntegrityError,
    MemoryLocked,
    MemoryMigrationChecksumMismatch,
    MemoryUnavailable,
)
from cyberwatchtower.memory.ingestion import _ingest_trusted_report, ingest_report
from cyberwatchtower.memory.ingestion_models import (
    IngestionStatus,
    ReportIngestionRequest,
)
from cyberwatchtower.memory.integrity import check_integrity, verify_canonical_report
from cyberwatchtower.memory.integrity_models import ReportVerificationStatus
from cyberwatchtower.memory.normalizers import normalize_report
from cyberwatchtower.report_contracts import (
    canonical_report_bytes,
    canonical_report_digest,
)


SYSTEM_ID = "system:memory"


def _report(*, score=88, generated_at="2026-09-05T00:00:00+00:00"):
    return {
        "schema_version": "1.1",
        "generated_at": generated_at,
        "system": {"system_id": SYSTEM_ID, "hostname": "display-host"},
        "coverage": {"network_socket_inspection": "COMPLETE"},
        "security_score": {
            "score": score,
            "risk_level": "LOW",
            "counts": {"LOW": 1},
        },
        "findings": [{
            "finding_id": "finding:memory",
            "title": "Memory finding",
            "description": "A deterministic condition.",
            "severity": "LOW",
            "recommendation": "Review it.",
            "evidence": ["Port: 8080"],
            "confidence": 90,
            "technique_id": None,
            "source": "network",
            "kind": "RISK",
            "assessment_state": "CONFIRMED",
        }],
    }


def _material(report=None):
    raw = report or _report()
    normalized, _omitted = normalize_report(raw)
    digest = canonical_report_digest(raw)
    return memory_boundary._TrustedReportMaterial(
        report_id=application.ReportId("report:" + digest),
        canonical_digest=digest,
        canonical_bytes=canonical_report_bytes(raw),
        normalized_report=normalized,
        system_id=SYSTEM_ID,
        schema_version=normalized.schema_version,
        generated_at=report_boundary._utc_timestamp(normalized.generated_at),
    )


class _Snapshot:
    def __init__(self, material, completeness=application.ReportCatalogCompleteness.COMPLETE):
        self.material = material
        self.completeness = completeness

    def find(self, report_id):
        return object() if self.material and report_id == self.material.report_id else None


class _Repository:
    def __init__(self, material, completeness=application.ReportCatalogCompleteness.COMPLETE):
        self.material = material
        self.snapshot = _Snapshot(material, completeness)
        self.reads = 0

    def catalog_for_system(self, system_id):
        self.system_id = system_id
        return self.snapshot

    def read_trusted_material(self, snapshot, *, report_id, expected_system_id):
        self.reads += 1
        return self.material


class _Port:
    def __init__(self, status=application.MemoryIngestionStatus.INGESTED, error=None):
        self.status = status
        self.error = error
        self.materials = []
        self.close_calls = 0

    def ingest_trusted_report(self, material):
        self.materials.append(material)
        if self.error:
            raise self.error
        return memory_boundary._MemoryIngestionRecord(self.status, material.schema_version)

    def close(self):
        self.close_calls += 1


class _Factory:
    def __init__(self, port=None, error=None):
        self.port = port or _Port()
        self.error = error
        self.opens = 0

    def open_writable(self):
        self.opens += 1
        if self.error:
            raise self.error
        return self.port


def _invoke(repository, factory, material=None, app=None):
    material = material or repository.material
    app = app or application.CyberWatchtowerApplication()
    request = application.IngestSavedReportIntoMemoryRequest(
        SYSTEM_ID, material.report_id
    )
    with patch(
        "cyberwatchtower.application.reports._default_report_repository",
        return_value=repository,
    ), patch.object(
        memory_boundary,
        "_default_memory_factory",
        return_value=factory,
    ):
        return app.ingest_saved_report_into_memory(request)


class ApplicationMemoryIngestionTests(unittest.TestCase):
    def test_trusted_material_rejects_oversized_bytes_before_memory_resolution(self):
        material = _material()
        oversized = b"x" * (10 * 1024 * 1024 + 1)
        digest = hashlib.sha256(oversized).hexdigest()
        with (
            patch.object(memory_boundary, "_default_memory_factory") as factory,
            self.assertRaises(ValueError),
        ):
            dataclasses.replace(
                material,
                report_id=application.ReportId("report:" + digest),
                canonical_digest=digest,
                canonical_bytes=oversized,
            )
        factory.assert_not_called()

    def test_history_operation_id_precedes_invalid_request_and_no_io(self):
        with patch.object(
            history_boundary,
            "_history_operation_id",
            return_value="historyop:" + "a" * 32,
        ) as operation_id, patch(
            "cyberwatchtower.application.reports._default_report_repository"
        ) as repository, self.assertRaises(
            application.CyberWatchtowerApplicationError
        ) as caught:
            application.CyberWatchtowerApplication().ingest_saved_report_into_memory(object())
        operation_id.assert_called_once_with()
        repository.assert_not_called()
        self.assertEqual(caught.exception.failure.code, application.ApplicationErrorCode.INVALID_REQUEST)

    def test_one_secure_snapshot_precedes_memory_open_and_pathless_material_is_passed(self):
        material = _material()
        repository = _Repository(material)
        port = _Port()
        factory = _Factory(port)
        result = _invoke(repository, factory)
        self.assertEqual(result.status, application.MemoryIngestionStatus.INGESTED)
        self.assertEqual(factory.opens, 1)
        self.assertEqual(repository.reads, 1)
        self.assertIs(port.materials[0], material)
        self.assertFalse(any("path" in field.name for field in dataclasses.fields(material)))
        self.assertNotIn("path", repr(result).casefold())
        self.assertEqual(port.close_calls, 1)

    def test_incomplete_or_missing_report_never_opens_memory(self):
        material = _material()
        cases = (
            (_Repository(material, application.ReportCatalogCompleteness.INCOMPLETE),
             application.ApplicationErrorCode.INTEGRITY_FAILURE),
            (_Repository(None), application.ApplicationErrorCode.NOT_FOUND),
        )
        for repository, code in cases:
            with self.subTest(code=code):
                factory = _Factory()
                request = application.IngestSavedReportIntoMemoryRequest(
                    SYSTEM_ID, material.report_id
                )
                with patch(
                    "cyberwatchtower.application.reports._default_report_repository",
                    return_value=repository,
                ), patch.object(
                    memory_boundary, "_default_memory_factory", return_value=factory
                ), self.assertRaises(application.CyberWatchtowerApplicationError) as caught:
                    application.CyberWatchtowerApplication().ingest_saved_report_into_memory(request)
                self.assertEqual(caught.exception.failure.code, code)
                self.assertEqual(factory.opens, 0)

    def test_system_mismatch_cannot_be_rescued_by_hostname(self):
        material = _material()
        mismatched = dataclasses.replace(
            material,
            system_id="system:other",
            normalized_report=dataclasses.replace(
                material.normalized_report,
                native_system_id="system:other",
            ),
        )
        repository = _Repository(mismatched)
        factory = _Factory()
        request = application.IngestSavedReportIntoMemoryRequest(
            SYSTEM_ID, material.report_id
        )
        with patch(
            "cyberwatchtower.application.reports._default_report_repository",
            return_value=repository,
        ), patch.object(
            memory_boundary, "_default_memory_factory", return_value=factory
        ), self.assertRaises(application.CyberWatchtowerApplicationError) as caught:
            application.CyberWatchtowerApplication().ingest_saved_report_into_memory(request)
        self.assertEqual(caught.exception.failure.code, application.ApplicationErrorCode.INTEGRITY_FAILURE)
        self.assertEqual(factory.opens, 0)

    def test_disabled_configuration_is_lazy_cached_and_has_no_fallback(self):
        material = _material()
        repository = _Repository(material)
        app = application.CyberWatchtowerApplication()
        with patch.object(
            memory_boundary.os.environ, "get", return_value=None
        ) as getenv:
            self.assertEqual(getenv.call_count, 0)
            for _ in range(2):
                with patch(
                    "cyberwatchtower.application.reports._default_report_repository",
                    return_value=repository,
                ), self.assertRaises(application.CyberWatchtowerApplicationError) as caught:
                    app.ingest_saved_report_into_memory(
                        application.IngestSavedReportIntoMemoryRequest(
                            SYSTEM_ID, material.report_id
                        )
                    )
                self.assertEqual(
                    caught.exception.failure.code,
                    application.ApplicationErrorCode.COMPONENT_UNAVAILABLE,
                )
            self.assertEqual(getenv.call_count, 1)
        self.assertIsNone(app._memory_factory)

    def test_resolved_factory_is_cached_and_environment_cannot_redirect_instance(self):
        material = _material()
        repository = _Repository(material)
        first = _Factory(_Port())
        second = _Factory(_Port())
        app = application.CyberWatchtowerApplication()
        with patch(
            "cyberwatchtower.application.reports._default_report_repository",
            return_value=repository,
        ), patch.object(
            memory_boundary,
            "_default_memory_factory",
            side_effect=(first, second),
        ) as resolver:
            request = application.IngestSavedReportIntoMemoryRequest(
                SYSTEM_ID, material.report_id
            )
            app.ingest_saved_report_into_memory(request)
            app.ingest_saved_report_into_memory(request)
        resolver.assert_called_once_with()
        self.assertEqual(first.opens, 2)
        self.assertEqual(second.opens, 0)

    def test_status_projection_and_deterministic_close_on_all_outcomes(self):
        material = _material()
        for status in (
            application.MemoryIngestionStatus.INGESTED,
            application.MemoryIngestionStatus.ALREADY_PRESENT,
        ):
            with self.subTest(status=status):
                port = _Port(status)
                result = _invoke(_Repository(material), _Factory(port))
                self.assertEqual(result.status, status)
                self.assertEqual(port.close_calls, 1)
        port = _Port(error=MemoryIntegrityError("private database path"))
        with self.assertRaises(application.CyberWatchtowerApplicationError) as caught:
            _invoke(_Repository(material), _Factory(port))
        self.assertEqual(caught.exception.failure.code, application.ApplicationErrorCode.INTEGRITY_FAILURE)
        self.assertEqual(port.close_calls, 1)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn("path", repr(caught.exception.failure).casefold())
        unexpected = _Port(error=RuntimeError("unexpected /private/database"))
        with self.assertRaises(application.CyberWatchtowerApplicationError) as caught:
            _invoke(_Repository(material), _Factory(unexpected))
        self.assertEqual(
            caught.exception.failure.code,
            application.ApplicationErrorCode.INTERNAL_FAILURE,
        )
        self.assertEqual(unexpected.close_calls, 1)

    def test_lock_is_one_attempt_retryable_storage_failure(self):
        material = _material()
        factory = _Factory(error=MemoryLocked("locked /private/memory.db"))
        with self.assertRaises(application.CyberWatchtowerApplicationError) as caught:
            _invoke(_Repository(material), factory)
        self.assertEqual(factory.opens, 1)
        self.assertEqual(caught.exception.failure.code, application.ApplicationErrorCode.STORAGE_FAILURE)
        self.assertTrue(caught.exception.failure.retryable)
        self.assertNotIn("private", repr(caught.exception.failure).casefold())

    def test_application_never_invokes_legacy_path_ingestion_or_renormalizes(self):
        material = _material()
        with patch(
            "cyberwatchtower.memory.service.ingest_report"
        ) as legacy, patch(
            "cyberwatchtower.memory.ingestion.normalize_report"
        ) as normalizer:
            _invoke(_Repository(material), _Factory(_Port()))
        legacy.assert_not_called()
        normalizer.assert_not_called()

    def test_real_private_factory_end_to_end_is_pathless_and_idempotent(self):
        raw = _report()
        material = _material(raw)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory, "reports")
            root.mkdir()
            (root / "report.json").write_text(json.dumps(raw), encoding="utf-8")
            database_path = Path(directory, "memory", "memory.db")
            app = application.CyberWatchtowerApplication()
            request = application.IngestSavedReportIntoMemoryRequest(
                SYSTEM_ID, material.report_id
            )
            with patch(
                "cyberwatchtower.application.reports._default_report_repository",
                return_value=report_boundary._FileReportRepository(root),
            ), patch.dict(
                memory_boundary.os.environ,
                {"CYBERWATCHTOWER_MEMORY_DB": str(database_path)},
                clear=False,
            ):
                first = app.ingest_saved_report_into_memory(request)
                repeat = app.ingest_saved_report_into_memory(request)
            with open_memory_database(database_path) as database:
                provenance = database.connection.execute(
                    "SELECT source_path,source_filename FROM reports"
                ).fetchone()
                counts = database.connection.execute(
                    "SELECT COUNT(*) FROM finding_lifecycle_events"
                ).fetchone()[0]
        self.assertEqual(first.status, application.MemoryIngestionStatus.INGESTED)
        self.assertEqual(repeat.status, application.MemoryIngestionStatus.ALREADY_PRESENT)
        self.assertEqual(tuple(provenance), (None, None))
        self.assertEqual(counts, 1)

    def test_raced_fifo_candidate_fails_before_memory_resolution(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO fixtures are unavailable on this platform.")

        raw = _report()
        material = _material(raw)
        real_open = os.open
        real_fdopen = os.fdopen
        candidate_open_count = 0
        candidate_read_count = 0
        raced_descriptors = []

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory, "reports")
            root.mkdir()
            candidate = root / "report.json"
            candidate.write_text(json.dumps(raw), encoding="utf-8")
            original = candidate.with_suffix(".original")
            repository = report_boundary._FileReportRepository(root)

            def race_second_candidate_open(path, flags, mode=0o777, *, dir_fd=None):
                nonlocal candidate_open_count
                if path == candidate.name and dir_fd is not None:
                    candidate_open_count += 1
                    self.assertTrue(flags & os.O_NOFOLLOW)
                    self.assertTrue(flags & os.O_NONBLOCK)
                    if candidate_open_count == 2:
                        candidate.rename(original)
                        os.mkfifo(candidate)
                        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
                        raced_descriptors.append(descriptor)
                        return descriptor
                return real_open(path, flags, mode, dir_fd=dir_fd)

            def observe_candidate_read(descriptor, *args, **kwargs):
                nonlocal candidate_read_count
                candidate_read_count += 1
                return real_fdopen(descriptor, *args, **kwargs)

            with patch(
                "cyberwatchtower.application.reports._default_report_repository",
                return_value=repository,
            ), patch.object(
                memory_boundary,
                "_default_memory_factory",
            ) as memory_factory, patch.object(
                report_boundary.os,
                "open",
                side_effect=race_second_candidate_open,
            ), patch.object(
                report_boundary.os,
                "fdopen",
                side_effect=observe_candidate_read,
            ), self.assertRaises(
                application.CyberWatchtowerApplicationError
            ) as caught:
                application.CyberWatchtowerApplication(
                ).ingest_saved_report_into_memory(
                    application.IngestSavedReportIntoMemoryRequest(
                        SYSTEM_ID,
                        material.report_id,
                    )
                )

            self.assertEqual(
                caught.exception.failure.code,
                application.ApplicationErrorCode.INTEGRITY_FAILURE,
            )
            self.assertIsNone(caught.exception.__cause__)
            self.assertIsNone(caught.exception.__context__)
            self.assertNotIn(str(root), repr(caught.exception.failure))
            self.assertEqual(candidate_open_count, 2)
            self.assertEqual(candidate_read_count, 1)
            memory_factory.assert_not_called()
            self.assertEqual(len(raced_descriptors), 1)
            with self.assertRaises(OSError):
                os.fstat(raced_descriptors[0])

    def test_memory_failure_provenance_is_safely_classified(self):
        material = _material()
        cases = (
            (MemoryIncompatibleVersion("newer /private/db"),
             application.ApplicationErrorCode.COMPATIBILITY_FAILURE, False),
            (MemoryMigrationChecksumMismatch("checksum /private/db"),
             application.ApplicationErrorCode.INTEGRITY_FAILURE, False),
            (MemoryCorrupt("corrupt /private/db"),
             application.ApplicationErrorCode.INTEGRITY_FAILURE, False),
            (PermissionError("/private/db"),
             application.ApplicationErrorCode.PERMISSION_DENIED, False),
            (MemoryUnavailable("I/O /private/db"),
             application.ApplicationErrorCode.STORAGE_FAILURE, False),
        )
        for error, code, retryable in cases:
            with self.subTest(code=code):
                with self.assertRaises(application.CyberWatchtowerApplicationError) as caught:
                    _invoke(_Repository(material), _Factory(error=error))
                self.assertEqual(caught.exception.failure.code, code)
                self.assertEqual(caught.exception.failure.retryable, retryable)
                self.assertIsNone(caught.exception.__cause__)
                self.assertIsNone(caught.exception.__context__)
                self.assertNotIn("private", repr(caught.exception.failure).casefold())

    def test_real_newer_and_corrupt_databases_are_classified_without_ingestion(self):
        with tempfile.TemporaryDirectory() as directory:
            newer = Path(directory, "newer.db")
            connection = sqlite3.connect(newer)
            connection.execute("PRAGMA user_version=99")
            connection.close()
            corrupt = Path(directory, "corrupt.db")
            corrupt.write_bytes(b"not a sqlite database")
            cases = (
                (newer, application.ApplicationErrorCode.COMPATIBILITY_FAILURE),
                (corrupt, application.ApplicationErrorCode.INTEGRITY_FAILURE),
            )
            for path, code in cases:
                with self.subTest(code=code), self.assertRaises(
                    memory_boundary._MemoryOperationFailure
                ) as caught:
                    memory_boundary._ConfiguredMemoryFactory(path).open_writable()
                self.assertEqual(caught.exception.code, code)


class TrustedMemoryIngestionSQLiteTests(unittest.TestCase):
    def _ingest(self, database, material):
        return _ingest_trusted_report(
            database,
            public_report_id=material.report_id.value,
            canonical_digest=material.canonical_digest,
            canonical_bytes=material.canonical_bytes,
            normalized_report=material.normalized_report,
            expected_system_id=material.system_id,
            generated_at=material.generated_at,
        )

    def test_real_schema_initialization_pathless_ingestion_and_idempotence(self):
        material = _material()
        with tempfile.TemporaryDirectory() as directory:
            with open_memory_database(Path(directory, "private", "memory.db")) as database:
                first = self._ingest(database, material)
                before = {
                    table: database.connection.execute(
                        f"SELECT COUNT(*) FROM {table}"
                    ).fetchone()[0]
                    for table in (
                        "reports", "score_history", "finding_occurrences",
                        "finding_lifecycle_events",
                    )
                }
                repeat = self._ingest(database, material)
                after = {
                    table: database.connection.execute(
                        f"SELECT COUNT(*) FROM {table}"
                    ).fetchone()[0]
                    for table in before
                }
                row = database.connection.execute(
                    "SELECT source_path,source_filename FROM reports"
                ).fetchone()
                verification = verify_canonical_report(
                    database, system_id=SYSTEM_ID, report_id=first.report_id
                )
                integrity = check_integrity(database)
                version = database.connection.execute("PRAGMA user_version").fetchone()[0]
        self.assertEqual(first.status, IngestionStatus.INGESTED)
        self.assertEqual(repeat.status, IngestionStatus.DUPLICATE)
        self.assertEqual(before, after)
        self.assertEqual(tuple(row), (None, None))
        self.assertEqual(version, 8)
        self.assertEqual(
            verification.status,
            ReportVerificationStatus.NOT_APPLICABLE_PATHLESS_SOURCE,
        )
        self.assertNotIn(
            "REPORT_SOURCE_UNVERIFIED",
            {diagnostic.code for diagnostic in integrity.diagnostics},
        )

    def test_trusted_route_is_bounded_coherent_and_does_not_normalize_again(self):
        material = _material()
        with tempfile.TemporaryDirectory() as directory:
            with open_memory_database(Path(directory, "memory.db")) as database, patch(
                "cyberwatchtower.memory.ingestion.normalize_report"
            ) as normalizer:
                self._ingest(database, material)
            normalizer.assert_not_called()
        bad_bytes = b"x" * (10 * 1024 * 1024 + 1)
        with tempfile.TemporaryDirectory() as directory:
            with open_memory_database(Path(directory, "memory.db")) as database:
                with self.assertRaises(MemoryIntegrityError):
                    _ingest_trusted_report(
                        database,
                        public_report_id=material.report_id.value,
                        canonical_digest=material.canonical_digest,
                        canonical_bytes=bad_bytes,
                        normalized_report=material.normalized_report,
                        expected_system_id=material.system_id,
                        generated_at=material.generated_at,
                    )
                self.assertEqual(
                    database.connection.execute("SELECT COUNT(*) FROM reports").fetchone()[0],
                    0,
                )

    def test_trusted_route_rejects_chronology_identity_and_duplicate_finding_contradictions(self):
        material = _material()
        duplicate_report = dataclasses.replace(
            material.normalized_report,
            findings=(
                material.normalized_report.findings[0],
                material.normalized_report.findings[0],
            ),
        )
        cases = (
            {"public_report_id": "report:" + "0" * 64},
            {"generated_at": datetime(2026, 9, 6, tzinfo=timezone.utc)},
            {"normalized_report": duplicate_report},
            {"expected_system_id": "system:other"},
        )
        for changes in cases:
            with self.subTest(changes=tuple(changes)), tempfile.TemporaryDirectory() as directory:
                values = {
                    "public_report_id": material.report_id.value,
                    "canonical_digest": material.canonical_digest,
                    "canonical_bytes": material.canonical_bytes,
                    "normalized_report": material.normalized_report,
                    "expected_system_id": material.system_id,
                    "generated_at": material.generated_at,
                }
                values.update(changes)
                with open_memory_database(Path(directory, "memory.db")) as database:
                    with self.assertRaises(MemoryIntegrityError):
                        _ingest_trusted_report(database, **values)
                    self.assertEqual(
                        database.connection.execute(
                            "SELECT COUNT(*) FROM reports"
                        ).fetchone()[0],
                        0,
                    )

    def test_contradictory_duplicate_fails_integrity_without_mutation(self):
        material = _material()
        with tempfile.TemporaryDirectory() as directory:
            with open_memory_database(Path(directory, "memory.db")) as database:
                first = self._ingest(database, material)
                database.connection.execute(
                    "UPDATE score_history SET score=1 WHERE report_id=?",
                    (first.report_id,),
                )
                database.connection.commit()
                with self.assertRaises(MemoryIntegrityError):
                    self._ingest(database, material)
                stored = database.connection.execute(
                    "SELECT score FROM score_history WHERE report_id=?", (first.report_id,)
                ).fetchone()[0]
        self.assertEqual(stored, 1)

    def test_failed_lifecycle_write_rolls_back_entire_trusted_ingestion(self):
        material = _material()
        with tempfile.TemporaryDirectory() as directory:
            with open_memory_database(Path(directory, "memory.db")) as database:
                database.connection.execute(
                    """CREATE TRIGGER deny_lifecycle BEFORE INSERT ON finding_lifecycle_events
                       BEGIN SELECT RAISE(ABORT, 'denied'); END"""
                )
                database.connection.commit()
                with self.assertRaises(Exception):
                    self._ingest(database, material)
                counts = tuple(
                    database.connection.execute(
                        f"SELECT COUNT(*) FROM {table}"
                    ).fetchone()[0]
                    for table in (
                        "systems", "reports", "score_history", "findings",
                        "finding_occurrences", "finding_lifecycle_events",
                    )
                )
        self.assertEqual(counts, (0, 0, 0, 0, 0, 0))

    def test_legacy_path_ingestion_remains_operational(self):
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory, "report.json")
            report_path.write_text(json.dumps(_report()), encoding="utf-8")
            with open_memory_database(Path(directory, "memory.db")) as database:
                result = ingest_report(database, ReportIngestionRequest(report_path))
                source = database.connection.execute(
                    "SELECT source_path,source_filename FROM reports"
                ).fetchone()
        self.assertEqual(result.status, IngestionStatus.INGESTED)
        self.assertEqual(tuple(source), (str(report_path), report_path.name))

    def test_pathless_and_legacy_routes_share_lifecycle_semantics(self):
        material = _material()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_path = root / "report.json"
            report_path.write_text(json.dumps(_report()), encoding="utf-8")
            with open_memory_database(root / "legacy.db") as legacy:
                legacy_result = ingest_report(legacy, ReportIngestionRequest(report_path))
                legacy_state = tuple(legacy.connection.execute(
                    """SELECT lifecycle_state,occurrence_count,reopened_count
                       FROM findings WHERE system_id=?""", (SYSTEM_ID,)
                ).fetchone())
                legacy_events = tuple(row[0] for row in legacy.connection.execute(
                    "SELECT event_type FROM finding_lifecycle_events ORDER BY event_id"
                ))
            with open_memory_database(root / "trusted.db") as trusted:
                trusted_result = self._ingest(trusted, material)
                trusted_state = tuple(trusted.connection.execute(
                    """SELECT lifecycle_state,occurrence_count,reopened_count
                       FROM findings WHERE system_id=?""", (SYSTEM_ID,)
                ).fetchone())
                trusted_events = tuple(row[0] for row in trusted.connection.execute(
                    "SELECT event_type FROM finding_lifecycle_events ORDER BY event_id"
                ))
        self.assertEqual(legacy_result.status, IngestionStatus.INGESTED)
        self.assertEqual(trusted_result.status, IngestionStatus.INGESTED)
        self.assertEqual(legacy_state, trusted_state)
        self.assertEqual(legacy_events, trusted_events)


if __name__ == "__main__":
    unittest.main()
