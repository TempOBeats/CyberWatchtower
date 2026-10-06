import dataclasses
import inspect
import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from unittest import mock

import cyberwatchtower.application as application
from cyberwatchtower.application import (
    ApplicationComponent,
    ApplicationErrorCode,
    ApplicationFailure,
    AssessmentState,
    CompareSavedReportsRequest,
    ComparisonFindingSummary,
    FindingKind,
    FindingLifecycleEvent,
    FindingLifecycleState,
    FindingTimelineResult,
    GetFindingTimelineRequest,
    GetMemoryHealthRequest,
    GetScoreHistoryRequest,
    IngestSavedReportIntoMemoryRequest,
    LIFECYCLE_EVENT_PRECEDENCE,
    LifecycleEventType,
    ListRecurringFindingsRequest,
    MemoryDiagnosticCategory,
    MemoryDiagnosticCode,
    MemoryDiagnosticSeverity,
    MemoryFindingSummary,
    MemoryHealthDiagnostic,
    MemoryHealthResult,
    MemoryHealthState,
    MemoryIngestionStatus,
    MemoryIntegrityState,
    RecurringFindingsResult,
    ReportId,
    SavedReportComparisonResult,
    SavedReportMemoryIngestionResult,
    SavedReportReference,
    ScoreHistoryPoint,
    ScoreHistoryResult,
    ScoreHistorySeries,
    ScoreTrendState,
    ScoringVersion,
    Severity,
    FINDING_ID_MAX,
    MEMORY_HEALTH_MAX_DIAGNOSTICS,
    RECURRING_DEFAULT_LIMIT,
    RECURRING_MAX_LIMIT,
    SCORE_HISTORY_DEFAULT_LIMIT,
    SCORE_HISTORY_MAX_LIMIT,
    SCORE_HISTORY_MAX_RANGE_DAYS,
    SYSTEM_ID_MAX,
    TIMELINE_DEFAULT_LIMIT,
    TIMELINE_MAX_LIMIT,
)
from cyberwatchtower.application._history import (
    _history_operation_id,
    _start_history_operation,
)
from cyberwatchtower.application._memory import (
    _MemoryFactory,
    _MemoryPort,
    _TrustedReportMaterial,
)
from cyberwatchtower.application.reports import (
    _FileReportRepository,
    _ReportRepositoryPort,
)
from cyberwatchtower.memory.ingestion_models import (
    NormalizedReport,
    NormalizedScore,
)


OPERATION_ID = "historyop:" + "a" * 32
SYSTEM_ID = "system-1"
PREVIOUS_ID = ReportId("report:" + "1" * 64)
CURRENT_ID = ReportId("report:" + "2" * 64)
NOW = datetime(2026, 1, 2, tzinfo=timezone.utc)


def _finding(finding_id="finding-1", occurrence_count=2, last_seen_at=NOW):
    return MemoryFindingSummary(
        finding_id=finding_id,
        title="Finding",
        severity=Severity.HIGH,
        source="network",
        kind=FindingKind.RISK,
        assessment_state=AssessmentState.CONFIRMED,
        occurrence_count=occurrence_count,
        first_seen_at=NOW - timedelta(days=1),
        last_seen_at=last_seen_at,
        lifecycle_state=FindingLifecycleState.ACTIVE,
        reopen_count=0,
    )


def _comparison_finding(finding_id="finding-1"):
    return ComparisonFindingSummary(
        finding_id=finding_id,
        title="Finding",
        severity=Severity.HIGH,
        source="network",
        kind=FindingKind.RISK,
        assessment_state=AssessmentState.CONFIRMED,
    )


class ApplicationHistoryContractTests(unittest.TestCase):
    def test_public_e3_dtos_are_frozen_slotted_dataclasses(self):
        names = (
            "CompareSavedReportsRequest",
            "SavedReportReference",
            "ComparisonFindingSummary",
            "SavedReportComparisonResult",
            "IngestSavedReportIntoMemoryRequest",
            "SavedReportMemoryIngestionResult",
            "ListRecurringFindingsRequest",
            "MemoryFindingSummary",
            "RecurringFindingsResult",
            "GetFindingTimelineRequest",
            "FindingLifecycleEvent",
            "FindingTimelineResult",
            "GetScoreHistoryRequest",
            "ScoreHistoryPoint",
            "ScoreHistorySeries",
            "ScoreHistoryResult",
            "GetMemoryHealthRequest",
            "MemoryHealthDiagnostic",
            "MemoryHealthResult",
        )
        for name in names:
            with self.subTest(name=name):
                dto = getattr(application, name)
                self.assertTrue(dataclasses.is_dataclass(dto))
                self.assertTrue(dto.__dataclass_params__.frozen)
                self.assertIn("__slots__", dto.__dict__)

    def test_history_operation_id_and_failure_correlation_are_exact(self):
        generated = _history_operation_id()
        self.assertRegex(generated, r"^historyop:[0-9a-f]{32}$")
        from uuid import UUID
        self.assertEqual(
            UUID(hex=generated.removeprefix("historyop:")).version,
            4,
        )
        ApplicationFailure(
            ApplicationErrorCode.INVALID_REQUEST,
            "The history request is invalid.",
            False,
            ApplicationComponent.APPLICATION,
            generated,
        )
        for invalid in (
            "historyop:" + "A" * 32,
            "historyop:" + "a" * 31,
            "history:" + "a" * 32,
            "assessment:" + "a" * 32 + "0",
        ):
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                ApplicationFailure(
                    ApplicationErrorCode.INVALID_REQUEST,
                    "The history request is invalid.",
                    False,
                    ApplicationComponent.APPLICATION,
                    invalid,
                )

    def test_start_history_operation_generates_id_before_validation(self):
        events = []

        def generate():
            events.append("id")
            return OPERATION_ID

        def validate(value):
            events.append(("validate", value))
            return False

        with mock.patch(
            "cyberwatchtower.application._history._history_operation_id",
            side_effect=generate,
        ):
            operation_id, valid = _start_history_operation(object(), validate)
        self.assertEqual(operation_id, OPERATION_ID)
        self.assertFalse(valid)
        self.assertEqual(events[0], "id")
        self.assertEqual(events[1][0], "validate")

    def test_comparison_request_reuses_exact_system_and_report_id_validation(self):
        request = CompareSavedReportsRequest(SYSTEM_ID, PREVIOUS_ID, CURRENT_ID)
        self.assertEqual(request.system_id, SYSTEM_ID)
        for system_id in (" system-1", "system-1 ", "system\u200b1", ""):
            with self.subTest(system_id=repr(system_id)), self.assertRaises(ValueError):
                CompareSavedReportsRequest(system_id, PREVIOUS_ID, CURRENT_ID)
        with self.assertRaises(TypeError):
            CompareSavedReportsRequest(SYSTEM_ID, PREVIOUS_ID.value, CURRENT_ID)
        with self.assertRaises(ValueError):
            CompareSavedReportsRequest(SYSTEM_ID, PREVIOUS_ID, PREVIOUS_ID)
        with self.assertRaises(ValueError):
            ReportId("report:" + "A" * 64)

    def test_comparison_result_shape_order_and_trend_invariants(self):
        previous = SavedReportReference(PREVIOUS_ID, NOW - timedelta(days=1))
        current = SavedReportReference(CURRENT_ID, NOW)
        added = (_comparison_finding("a"), _comparison_finding("b"))
        result = SavedReportComparisonResult(
            operation_id=OPERATION_ID,
            system_id=SYSTEM_ID,
            previous_report=previous,
            current_report=current,
            previous_score=70,
            current_score=80,
            previous_risk="HIGH",
            current_risk="MODERATE",
            previous_scoring_version=ScoringVersion.V2,
            current_scoring_version=ScoringVersion.V2,
            score_trend=ScoreTrendState.IMPROVED,
            score_change=10,
            added_findings=added,
            resolved_findings=(),
            uncertain_disappearances=(),
        )
        self.assertIsInstance(result.added_findings, tuple)
        with self.assertRaises(FrozenInstanceError):
            result.current_score = 1
        with self.assertRaises(ValueError):
            dataclasses.replace(
                result,
                current_scoring_version=ScoringVersion.V1,
            )
        with self.assertRaises(ValueError):
            dataclasses.replace(result, score_change=-10)
        with self.assertRaises(ValueError):
            dataclasses.replace(result, added_findings=tuple(reversed(added)))

    def test_ingestion_contract_is_pathless_and_status_is_exact(self):
        request = IngestSavedReportIntoMemoryRequest(SYSTEM_ID, CURRENT_ID)
        result = SavedReportMemoryIngestionResult(
            OPERATION_ID,
            MemoryIngestionStatus.INGESTED,
            CURRENT_ID,
            SYSTEM_ID,
            "1.7",
        )
        self.assertEqual(
            tuple(item.value for item in MemoryIngestionStatus),
            ("INGESTED", "ALREADY_PRESENT"),
        )
        self.assertEqual(
            tuple(field.name for field in dataclasses.fields(request)),
            ("system_id", "report_id"),
        )
        self.assertEqual(result.report_id, CURRENT_ID)

    def test_frozen_bounds_are_exact(self):
        self.assertEqual(SYSTEM_ID_MAX, 4096)
        self.assertEqual(FINDING_ID_MAX, 512)
        self.assertEqual(RECURRING_DEFAULT_LIMIT, 50)
        self.assertEqual(RECURRING_MAX_LIMIT, 200)
        self.assertEqual(TIMELINE_DEFAULT_LIMIT, 100)
        self.assertEqual(TIMELINE_MAX_LIMIT, 500)
        self.assertEqual(SCORE_HISTORY_DEFAULT_LIMIT, 100)
        self.assertEqual(SCORE_HISTORY_MAX_LIMIT, 500)
        self.assertEqual(SCORE_HISTORY_MAX_RANGE_DAYS, 366)
        self.assertEqual(MEMORY_HEALTH_MAX_DIAGNOSTICS, 32)

    def test_supporting_enums_are_exact_closed_vocabularies(self):
        self.assertEqual(
            tuple(item.value for item in ScoreTrendState),
            ("IMPROVED", "DECLINED", "UNCHANGED", "INCOMPARABLE"),
        )
        self.assertEqual(
            tuple(item.value for item in FindingLifecycleState),
            ("ACTIVE", "RESOLVED", "RESOLUTION_UNCERTAIN"),
        )
        self.assertEqual(
            tuple(item.value for item in MemoryDiagnosticSeverity),
            ("INFO", "WARNING", "ERROR"),
        )
        self.assertEqual(
            tuple(item.value for item in MemoryDiagnosticCategory),
            ("CONFIGURATION", "STORAGE", "SCHEMA", "INTEGRITY"),
        )
        self.assertEqual(
            tuple(item.value for item in MemoryDiagnosticCode),
            (
                "DISABLED", "UNINITIALIZED", "AVAILABLE", "DEGRADED",
                "MIGRATION_REQUIRED", "INCOMPATIBLE_SCHEMA", "CORRUPT",
                "UNAVAILABLE", "PERMISSION_DENIED", "LOCKED",
                "INTEGRITY_WARNING", "INTEGRITY_FAILURE",
            ),
        )

    def test_recurring_request_bounds_types_and_result_count(self):
        self.assertEqual(ListRecurringFindingsRequest(SYSTEM_ID).limit, 50)
        for limit in (1, 200):
            ListRecurringFindingsRequest(SYSTEM_ID, limit, False)
        for limit in (0, 201, True, 1.0, "1"):
            with self.subTest(limit=limit), self.assertRaises((TypeError, ValueError)):
                ListRecurringFindingsRequest(SYSTEM_ID, limit, False)
        with self.assertRaises(TypeError):
            ListRecurringFindingsRequest(SYSTEM_ID, 50, 1)
        findings = (_finding("a", 3), _finding("b", 2, NOW - timedelta(hours=1)))
        result = RecurringFindingsResult(
            OPERATION_ID, SYSTEM_ID, findings, 2, True
        )
        self.assertEqual(result.returned_count, 2)
        with self.assertRaises(ValueError):
            dataclasses.replace(result, returned_count=1)
        with self.assertRaises(TypeError):
            dataclasses.replace(result, has_more=1)
        with self.assertRaises(ValueError):
            dataclasses.replace(result, findings=tuple(reversed(findings)))
        with self.assertRaises(ValueError):
            RecurringFindingsResult(
                OPERATION_ID,
                SYSTEM_ID,
                (_finding(),) * 201,
                201,
                True,
            )

    def test_finding_id_validation_is_exact_and_not_normalizing(self):
        request = GetFindingTimelineRequest(SYSTEM_ID, "finding-e\u0301", 1)
        self.assertEqual(request.finding_id, "finding-e\u0301")
        for finding_id in ("", " x", "x ", "x\n", "x\u200by", "x" * 513):
            with self.subTest(value=repr(finding_id)), self.assertRaises(ValueError):
                GetFindingTimelineRequest(SYSTEM_ID, finding_id)
        for limit in (1, 500):
            GetFindingTimelineRequest(SYSTEM_ID, "finding", limit)
        for limit in (0, 501, True, 1.0):
            with self.subTest(limit=limit), self.assertRaises((TypeError, ValueError)):
                GetFindingTimelineRequest(SYSTEM_ID, "finding", limit)

    def test_timeline_vocabulary_precedence_order_and_count(self):
        self.assertEqual(
            tuple(item.value for item in LifecycleEventType),
            (
                "FIRST_SEEN",
                "SEEN",
                "RESOLVED",
                "REOPENED",
                "SEVERITY_CHANGED",
                "ASSESSMENT_STATE_CHANGED",
                "KIND_CHANGED",
            ),
        )
        self.assertEqual(
            LIFECYCLE_EVENT_PRECEDENCE,
            (
                LifecycleEventType.FIRST_SEEN,
                LifecycleEventType.SEEN,
                LifecycleEventType.REOPENED,
                LifecycleEventType.SEVERITY_CHANGED,
                LifecycleEventType.ASSESSMENT_STATE_CHANGED,
                LifecycleEventType.KIND_CHANGED,
                LifecycleEventType.RESOLVED,
            ),
        )
        events = (
            FindingLifecycleEvent(
                LifecycleEventType.FIRST_SEEN, NOW, CURRENT_ID, None, None
            ),
            FindingLifecycleEvent(
                LifecycleEventType.SEEN, NOW, CURRENT_ID, None, None
            ),
        )
        result = FindingTimelineResult(
            OPERATION_ID, SYSTEM_ID, "finding-1", _finding(), events, 2, False
        )
        self.assertEqual(result.returned_count, 2)
        with self.assertRaises(ValueError):
            dataclasses.replace(result, events=tuple(reversed(events)))
        with self.assertRaises(ValueError):
            dataclasses.replace(result, returned_count=1)
        with self.assertRaises(TypeError):
            dataclasses.replace(result, has_more=1)
        with self.assertRaises(ValueError):
            FindingTimelineResult(
                OPERATION_ID,
                SYSTEM_ID,
                "finding-1",
                _finding(),
                (events[0],) * 501,
                501,
                True,
            )

    def test_score_history_request_bounds_range_and_versions(self):
        start = NOW - timedelta(days=366)
        for version in (None, "1", "2"):
            for limit in (1, 500):
                GetScoreHistoryRequest(SYSTEM_ID, start, NOW, limit, version)
        invalid_ranges = (
            (NOW.replace(tzinfo=None), NOW),
            (NOW, NOW.replace(tzinfo=None)),
            (NOW, NOW - timedelta(seconds=1)),
            (NOW - timedelta(days=366, microseconds=1), NOW),
        )
        for start_at, end_at in invalid_ranges:
            with self.subTest(start=start_at, end=end_at), self.assertRaises(ValueError):
                GetScoreHistoryRequest(SYSTEM_ID, start_at, end_at)
        for limit in (0, 501, True, 1.0):
            with self.subTest(limit=limit), self.assertRaises((TypeError, ValueError)):
                GetScoreHistoryRequest(SYSTEM_ID, start, NOW, limit)
        for version in ("v2", 2, "3", ScoringVersion.V2):
            with self.subTest(version=version), self.assertRaises(ValueError):
                GetScoreHistoryRequest(SYSTEM_ID, start, NOW, 100, version)

    def test_score_history_series_is_versioned_ordered_and_counted(self):
        points = (
            ScoreHistoryPoint(PREVIOUS_ID, NOW - timedelta(days=1), 70, "HIGH", ScoringVersion.V2),
            ScoreHistoryPoint(CURRENT_ID, NOW, 80, "MODERATE", ScoringVersion.V2),
        )
        series = ScoreHistorySeries(ScoringVersion.V2, points, 2, False)
        result = ScoreHistoryResult(OPERATION_ID, SYSTEM_ID, (series,))
        self.assertEqual(result.series[0].points, points)
        with self.assertRaises(ValueError):
            dataclasses.replace(series, returned_count=1)
        with self.assertRaises(ValueError):
            dataclasses.replace(series, points=tuple(reversed(points)))
        with self.assertRaises(TypeError):
            dataclasses.replace(series, has_more=1)
        with self.assertRaises(ValueError):
            ScoreHistorySeries(
                ScoringVersion.V1,
                points,
                2,
                False,
            )
        with self.assertRaises(ValueError):
            ScoreHistorySeries(
                ScoringVersion.V2,
                (points[0],) * 501,
                501,
                True,
            )

    def test_health_contract_has_closed_states_bounds_and_schema_eight(self):
        self.assertEqual(dataclasses.fields(GetMemoryHealthRequest()), ())
        self.assertEqual(
            tuple(item.value for item in MemoryHealthState),
            (
                "DISABLED", "UNINITIALIZED", "AVAILABLE", "DEGRADED",
                "MIGRATION_REQUIRED", "INCOMPATIBLE", "CORRUPT", "UNAVAILABLE",
            ),
        )
        self.assertEqual(
            tuple(item.value for item in MemoryIntegrityState),
            ("NOT_CHECKED", "PASS", "WARNING", "FAIL", "UNAVAILABLE"),
        )
        diagnostic = MemoryHealthDiagnostic(
            MemoryDiagnosticSeverity.INFO,
            MemoryDiagnosticCategory.STORAGE,
            MemoryDiagnosticCode.AVAILABLE,
            "Persistent Security Memory is available.",
            1,
        )
        result = MemoryHealthResult(
            OPERATION_ID,
            MemoryHealthState.AVAILABLE,
            8,
            8,
            MemoryIntegrityState.PASS,
            (diagnostic,),
        )
        self.assertEqual(result.expected_schema_version, 8)
        with self.assertRaises(ValueError):
            dataclasses.replace(result, expected_schema_version=7)
        with self.assertRaises(ValueError):
            dataclasses.replace(result, diagnostics=(diagnostic,) * 33)

    def test_public_contracts_contain_no_storage_or_sensitive_fields(self):
        prohibited = {
            "path", "root", "source_path", "source_filename", "database_path",
            "row_id", "event_id", "occurrence_id", "connection", "cursor",
            "descriptor", "inode", "device", "evidence", "raw_report",
            "canonical_bytes", "normalized_report",
        }
        e3_names = (
            "CompareSavedReportsRequest", "SavedReportReference",
            "ComparisonFindingSummary", "SavedReportComparisonResult",
            "IngestSavedReportIntoMemoryRequest",
            "SavedReportMemoryIngestionResult", "ListRecurringFindingsRequest",
            "MemoryFindingSummary", "RecurringFindingsResult",
            "GetFindingTimelineRequest", "FindingLifecycleEvent",
            "FindingTimelineResult", "GetScoreHistoryRequest",
            "ScoreHistoryPoint", "ScoreHistorySeries", "ScoreHistoryResult",
            "GetMemoryHealthRequest", "MemoryHealthDiagnostic",
            "MemoryHealthResult",
        )
        for name in e3_names:
            value = getattr(application, name)
            if not dataclasses.is_dataclass(value):
                continue
            with self.subTest(name=name):
                fields = {field.name for field in dataclasses.fields(value)}
                self.assertTrue(fields.isdisjoint(prohibited), (name, fields & prohibited))
                annotations = " ".join(str(item) for item in value.__annotations__.values())
                for mutable in ("list", "dict", "set", "Path", "Connection", "Cursor"):
                    self.assertNotIn(mutable, annotations)

    def test_private_trusted_material_is_frozen_immutable_and_not_exported(self):
        normalized = NormalizedReport(
            schema_version="1.7",
            generated_at=NOW.isoformat(),
            native_system_id=SYSTEM_ID,
            hostname="host",
            coverage=(),
            score=NormalizedScore("2", 100, "LOW", ()),
            findings=(),
        )
        canonical_bytes = b"trusted canonical bytes"
        import hashlib
        digest = hashlib.sha256(canonical_bytes).hexdigest()
        material = _TrustedReportMaterial(
            ReportId("report:" + digest),
            digest,
            canonical_bytes,
            normalized,
            SYSTEM_ID,
            "1.7",
            NOW,
        )
        self.assertEqual(material.canonical_bytes, canonical_bytes)
        self.assertNotIn("_TrustedReportMaterial", application.__all__)
        self.assertNotIn("_MemoryPort", application.__all__)
        self.assertNotIn("_MemoryFactory", application.__all__)
        for prohibited in ("path", "root", "descriptor", "inode", "device"):
            self.assertNotIn(
                prohibited,
                {field.name for field in dataclasses.fields(_TrustedReportMaterial)},
            )
        with self.assertRaises(FrozenInstanceError):
            material.system_id = "changed"
        self.assertTrue(inspect.isclass(_MemoryPort))
        self.assertTrue(inspect.isclass(_MemoryFactory))

    def test_private_port_shapes_are_storage_neutral_and_explicitly_owned(self):
        self.assertEqual(
            {
                name for name, value in _MemoryPort.__dict__.items()
                if inspect.isfunction(value)
            },
            {
                "ingest_trusted_report", "recurring_findings",
                "finding_timeline", "score_history", "health", "close",
                "__init__",
            },
        )
        self.assertEqual(
            {
                name for name, value in _MemoryFactory.__dict__.items()
                if inspect.isfunction(value)
            },
            {"open_read_only", "open_writable", "inspect_health", "__init__"},
        )
        for protocol in (_MemoryPort, _MemoryFactory):
            annotations = []
            for method in protocol.__dict__.values():
                if not inspect.isfunction(method):
                    continue
                signature = inspect.signature(method)
                annotations.extend(
                    parameter.annotation
                    for parameter in signature.parameters.values()
                )
                annotations.append(signature.return_annotation)
            rendered = " ".join(str(value) for value in annotations)
            for prohibited in ("sqlite", "Connection", "Cursor", "Path"):
                self.assertNotIn(prohibited, rendered)

    def test_private_repository_seam_requires_snapshot_and_is_implemented_in_e4(self):
        signature = inspect.signature(
            _ReportRepositoryPort.read_trusted_material
        )
        self.assertEqual(
            tuple(signature.parameters),
            ("self", "snapshot", "report_id", "expected_system_id"),
        )
        self.assertEqual(
            signature.return_annotation,
            "_TrustedReportMaterial",
        )
        self.assertTrue(hasattr(_FileReportRepository, "read_trusted_material"))
        implementation = inspect.signature(_FileReportRepository.read_trusted_material)
        self.assertEqual(
            tuple(implementation.parameters),
            ("self", "snapshot", "report_id", "expected_system_id"),
        )

    def test_contract_construction_and_zero_arg_facade_are_io_free(self):
        with mock.patch("builtins.open", side_effect=AssertionError("I/O")), mock.patch(
            "os.open", side_effect=AssertionError("I/O")
        ):
            application.CyberWatchtowerApplication()
            CompareSavedReportsRequest(SYSTEM_ID, PREVIOUS_ID, CURRENT_ID)
            IngestSavedReportIntoMemoryRequest(SYSTEM_ID, CURRENT_ID)
            ListRecurringFindingsRequest(SYSTEM_ID)
            GetFindingTimelineRequest(SYSTEM_ID, "finding")
            GetScoreHistoryRequest(SYSTEM_ID, NOW, NOW)
            GetMemoryHealthRequest()

    def test_facade_activates_exactly_the_frozen_e4_e5_e6_operations(self):
        facade = application.CyberWatchtowerApplication
        self.assertTrue(hasattr(facade, "compare_saved_reports"))
        self.assertTrue(hasattr(facade, "ingest_saved_report_into_memory"))
        for name in (
            "list_recurring_findings",
            "get_finding_timeline",
            "get_score_history",
            "get_memory_health",
        ):
            self.assertTrue(hasattr(facade, name), name)


if __name__ == "__main__":
    unittest.main()
