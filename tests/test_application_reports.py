import dataclasses
import copy
import errno
import inspect
import json
import os
import re
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

import cyberwatchtower.application as application
from cyberwatchtower.application import assessment as assessment_boundary
from cyberwatchtower.application import (
    ApplicationComponent,
    ApplicationErrorCode,
    ApplicationFailure,
    AssessmentAssuranceSummary,
    DomainCoverage,
    EvidenceProjectionState,
    GetLatestSavedReportRequest,
    GetSavedReportRequest,
    ListSavedReportsRequest,
    ProjectionNotice,
    ProjectionNoticeCode,
    ReportCatalogCompleteness,
    ReportCompatibilityState,
    ReportId,
    SavedCurrentSystemAssessmentResult,
    SavedReportCatalog,
    SavedReportCatalogDiagnostics,
    SavedReportCompatibility,
    SavedReportDetail,
    SavedReportField,
    SavedReportFinding,
    SavedReportScore,
    SavedReportSummary,
    SavedReportSystemSummary,
    SeverityCount,
)
from cyberwatchtower.application._privacy import (
    _project_evidence,
    _required_text_is_sensitive,
)
from cyberwatchtower.application.assessment import _report_operation_id
from cyberwatchtower.application import reports as report_boundary
from cyberwatchtower.models import AssessmentState, FindingKind, Severity
from cyberwatchtower.report_contracts import (
    AssessmentAssurance,
    CoverageState,
    ScanDomain,
    canonical_report_digest,
)
from cyberwatchtower.scoring_contracts import ScoringVersion

from tests.test_application_assessment import _assess, scanner_result


REPORT_ID = ReportId("report:" + "a" * 64)
REPORT_OPERATION_ID = "reportop:" + "b" * 32
GENERATED_AT = datetime(2026, 9, 23, 12, 0, tzinfo=timezone.utc)


def _compatibility():
    return SavedReportCompatibility(
        ReportCompatibilityState.CURRENT,
        (),
        (),
    )


def _coverage():
    return (
        DomainCoverage(
            ScanDomain.NETWORK_SOCKET_INSPECTION,
            CoverageState.COMPLETE,
        ),
    )


def _assurance():
    return AssessmentAssuranceSummary(AssessmentAssurance.COMPLETE, ())


def _summary():
    return SavedReportSummary(
        report_id=REPORT_ID,
        generated_at=GENERATED_AT,
        schema_version="1.7",
        system_id="system:test",
        scoring_version=ScoringVersion.V1,
        score=100,
        risk_level="LOW",
        finding_count=0,
        coverage=_coverage(),
        assurance=_assurance(),
        compatibility=_compatibility(),
    )


def _diagnostics():
    return SavedReportCatalogDiagnostics(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)


def _saved_score():
    return SavedReportScore(
        ScoringVersion.V1,
        100,
        "LOW",
        tuple(SeverityCount(severity, 0) for severity in Severity),
        None,
    )


def _saved_finding():
    return SavedReportFinding(
        finding_id="finding:test",
        title="Historical finding",
        description=None,
        severity=Severity.INFO,
        recommendation=None,
        evidence=(),
        evidence_projection_state=EvidenceProjectionState.COMPLETE,
        omitted_evidence_count=0,
        confidence=80,
        technique_id=None,
        source="legacy",
        kind=FindingKind.RISK,
        assessment_state=AssessmentState.POTENTIAL,
        metadata_inferred=True,
        network_context=None,
        runtime_instance_count=1,
    )


def _detail():
    return SavedReportDetail(
        operation_id=REPORT_OPERATION_ID,
        report_id=REPORT_ID,
        generated_at=GENERATED_AT,
        schema_version="1.7",
        system=SavedReportSystemSummary("system:test", "test-host"),
        findings=(_saved_finding(),),
        score=_saved_score(),
        coverage=_coverage(),
        assurance=_assurance(),
        compatibility=_compatibility(),
        projection_notices=(
            ProjectionNotice(
                ProjectionNoticeCode.EVIDENCE_REDACTED,
                "finding:test",
                1,
            ),
        ),
    )


class ApplicationReportContractTests(unittest.TestCase):
    def test_report_id_accepts_only_exact_lowercase_semantic_syntax(self):
        self.assertEqual(ReportId("report:" + "0" * 64).value, "report:" + "0" * 64)
        invalid = (
            "",
            "report:" + "a" * 63,
            "report:" + "a" * 65,
            "report:" + "A" * 64,
            " report:" + "a" * 64,
            "report:" + "a" * 64 + " ",
            "assessment:" + "a" * 64,
            "report:../" + "a" * 59,
            "/reports/" + "a" * 64,
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                ReportId(value)

    def test_report_requests_are_frozen_slotted_and_system_scoped(self):
        requests = (
            ListSavedReportsRequest("system:test"),
            GetSavedReportRequest(REPORT_ID, "system:test"),
            GetLatestSavedReportRequest("system:test"),
        )
        for request in requests:
            with self.subTest(request=type(request).__name__):
                self.assertFalse(hasattr(request, "__dict__"))
                with self.assertRaises(
                    (FrozenInstanceError, AttributeError, TypeError)
                ):
                    request.system_id = "system:other"

        invalid_system_ids = (
            "",
            " system:test",
            "system:test ",
            "system:\nsecret",
            "system:\u200dhidden",
            "x" * 4097,
        )
        for value in invalid_system_ids:
            with self.subTest(value=repr(value)), self.assertRaises(ValueError):
                ListSavedReportsRequest(value)
        case_sensitive = ListSavedReportsRequest("System:Case")
        self.assertEqual(case_sensitive.system_id, "System:Case")
        self.assertNotEqual(case_sensitive.system_id, "system:case")

    def test_report_enums_are_closed_to_the_frozen_values(self):
        self.assertEqual(
            tuple(item.value for item in ReportCatalogCompleteness),
            ("COMPLETE", "INCOMPLETE"),
        )
        self.assertEqual(
            tuple(item.value for item in ReportCompatibilityState),
            ("CURRENT", "LEGACY_NORMALIZED"),
        )
        self.assertEqual(
            tuple(item.value for item in SavedReportField),
            (
                "ASSESSMENT_DOMAINS",
                "COVERAGE",
                "ASSURANCE",
                "FINDING_METADATA",
                "RUNTIME_MULTIPLICITY",
                "SCORING_VERSION",
                "RISK_LEVEL",
                "SEVERITY_COUNTS",
                "SCORING_BREAKDOWN",
            ),
        )

    def test_report_contracts_are_deeply_immutable(self):
        catalog = SavedReportCatalog(
            REPORT_OPERATION_ID,
            (_summary(),),
            ReportCatalogCompleteness.COMPLETE,
            0,
            _diagnostics(),
        )
        detail = _detail()
        values = (
            REPORT_ID,
            _compatibility(),
            _diagnostics(),
            _summary(),
            catalog,
            detail.system,
            detail.score,
            detail.findings[0],
            detail,
        )
        for value in values:
            with self.subTest(value=type(value).__name__):
                self.assertTrue(dataclasses.is_dataclass(value))
                self.assertFalse(hasattr(value, "__dict__"))
                with self.assertRaises(
                    (FrozenInstanceError, AttributeError, TypeError)
                ):
                    value.synthetic = True
        self.assertIsInstance(catalog.reports, tuple)
        self.assertIsInstance(detail.findings, tuple)
        self.assertIsInstance(detail.findings[0].evidence, tuple)
        self.assertIsInstance(detail.score.counts, tuple)

    def test_contracts_reject_mutable_nested_collections(self):
        with self.assertRaises(TypeError):
            SavedReportCompatibility(ReportCompatibilityState.CURRENT, [], ())
        with self.assertRaises(TypeError):
            SavedReportCatalog(
                REPORT_OPERATION_ID,
                [],
                ReportCatalogCompleteness.COMPLETE,
                0,
                _diagnostics(),
            )
        with self.assertRaises(TypeError):
            SavedReportScore(ScoringVersion.V1, 100, "LOW", [], None)

    def test_diagnostics_require_nonnegative_integer_counts(self):
        for value in (-1, True, 1.5):
            with self.subTest(value=value), self.assertRaises(ValueError):
                SavedReportCatalogDiagnostics(value, 0, 0, 0, 0, 0, 0, 0, 0, 0)

    def test_saved_summary_and_detail_require_aware_timestamps(self):
        summary = _summary()
        with self.assertRaises(ValueError):
            dataclasses.replace(summary, generated_at=datetime(2026, 9, 23))
        with self.assertRaises(ValueError):
            dataclasses.replace(_detail(), generated_at=datetime(2026, 9, 23))

    def test_saved_score_supports_validated_v1_and_complete_v2_shape(self):
        self.assertEqual(_saved_score().scoring_version, ScoringVersion.V1)
        with self.assertRaises(ValueError):
            dataclasses.replace(_saved_score(), scoring_version=ScoringVersion.V2)

    def test_saved_finding_has_no_coverage_or_presentation_group(self):
        fields = {field.name for field in dataclasses.fields(SavedReportFinding)}
        self.assertNotIn("coverage_domains", fields)
        self.assertNotIn("presentation_group_id", fields)
        self.assertNotIn("path", fields)

    def test_existing_projection_notice_is_reused(self):
        detail = _detail()
        self.assertIsInstance(detail.projection_notices[0], ProjectionNotice)
        self.assertEqual(
            detail.projection_notices[0].code,
            ProjectionNoticeCode.EVIDENCE_REDACTED,
        )

    def test_saved_current_result_has_no_second_operation_identity(self):
        assessment, _ = _assess(scanner_result())
        result = SavedCurrentSystemAssessmentResult(assessment, _summary())
        self.assertEqual(
            {field.name for field in dataclasses.fields(result)},
            {"assessment", "report"},
        )

    def test_report_operation_generator_uses_distinct_uuid4_form(self):
        first = _report_operation_id()
        second = _report_operation_id()
        self.assertRegex(first, re.compile(r"^reportop:[0-9a-f]{32}$"))
        self.assertNotEqual(first, second)
        parsed = UUID(hex=first.removeprefix("reportop:"))
        self.assertEqual(parsed.version, 4)
        self.assertNotEqual(
            first.removeprefix("reportop:"),
            REPORT_ID.value.removeprefix("report:"),
        )

    def test_application_failure_accepts_only_closed_operation_id_families(self):
        self.assertTrue({
            ApplicationErrorCode.INVALID_REQUEST,
            ApplicationErrorCode.NOT_FOUND,
            ApplicationErrorCode.CONFLICT,
            ApplicationErrorCode.PERMISSION_DENIED,
            ApplicationErrorCode.COMPATIBILITY_FAILURE,
            ApplicationErrorCode.INTEGRITY_FAILURE,
            ApplicationErrorCode.STORAGE_FAILURE,
            ApplicationErrorCode.PRIVACY_POLICY_BLOCKED,
            ApplicationErrorCode.INTERNAL_FAILURE,
            ApplicationErrorCode.UNSUPPORTED_PLATFORM,
        }.issubset(set(ApplicationErrorCode)))
        for operation_id in (
            "assessment:" + "a" * 32,
            REPORT_OPERATION_ID,
        ):
            ApplicationFailure(
                ApplicationErrorCode.INVALID_REQUEST,
                "Safe failure.",
                False,
                ApplicationComponent.APPLICATION,
                operation_id,
            )
        for operation_id in (
            "job:" + "a" * 32,
            "report:" + "a" * 64,
            "reportop:" + "A" * 32,
            "reportop:" + "a" * 31,
        ):
            with self.subTest(operation_id=operation_id), self.assertRaises(ValueError):
                ApplicationFailure(
                    ApplicationErrorCode.INVALID_REQUEST,
                    "Safe failure.",
                    False,
                    ApplicationComponent.APPLICATION,
                    operation_id,
                )

    def test_shared_privacy_policy_preserves_structural_allowlists(self):
        network, state, omitted = _project_evidence(
            "network",
            [
                "Protocol: tcp",
                "Address: 0.0.0.0",
                "Application: display-name",
                "Friendly: harmless",
            ],
        )
        self.assertEqual(
            tuple(item.category.value for item in network),
            ("PROTOCOL", "ADDRESS"),
        )
        self.assertEqual(state, EvidenceProjectionState.REDACTED)
        self.assertEqual(omitted, 2)

        firewall, _, _ = _project_evidence(
            "firewall",
            ["Input policy: DROP", "Forward policy: DROP", "Output policy: ACCEPT"],
        )
        self.assertEqual(
            tuple(item.category.value for item in firewall),
            ("INPUT_POLICY", "FORWARD_POLICY", "OUTPUT_POLICY"),
        )

        inbound, _, _ = _project_evidence(
            "firewall_inbound_policy",
            [
                "Profile: public",
                "Firewall enabled: true",
                "Default inbound action: block",
                "Block all inbound: false",
            ],
        )
        self.assertEqual(
            tuple(item.category.value for item in inbound),
            (
                "PROFILE",
                "FIREWALL_ENABLED",
                "DEFAULT_INBOUND_ACTION",
                "BLOCK_ALL_INBOUND",
            ),
        )

    def test_shared_privacy_markers_reject_but_never_authorize(self):
        projected, state, omitted = _project_evidence(
            "network",
            [
                "Protocol: tcp password",
                "Friendly: harmless value",
                "Protocol: udp",
            ],
        )
        self.assertEqual(
            tuple((item.category.value, item.value) for item in projected),
            (("PROTOCOL", "udp"),),
        )
        self.assertEqual(state, EvidenceProjectionState.REDACTED)
        self.assertEqual(omitted, 2)
        self.assertTrue(_required_text_is_sensitive(("password=/tmp/private",)))
        self.assertFalse(_required_text_is_sensitive(("bounded display text", None)))

    def test_public_report_contracts_contain_no_path_or_provider_claim(self):
        report_types = (
            ReportId,
            ListSavedReportsRequest,
            GetSavedReportRequest,
            GetLatestSavedReportRequest,
            SavedReportCompatibility,
            SavedReportCatalogDiagnostics,
            SavedReportSummary,
            SavedReportCatalog,
            SavedReportSystemSummary,
            SavedReportScore,
            SavedReportFinding,
            SavedReportDetail,
            SavedCurrentSystemAssessmentResult,
        )
        prohibited = {
            "path", "filename", "directory", "glob", "uri", "storage_key",
            "provider_safe", "safe_to_send", "raw_report", "database_id",
        }
        for dto in report_types:
            with self.subTest(dto=dto.__name__):
                names = {field.name.casefold() for field in dataclasses.fields(dto)}
                self.assertTrue(names.isdisjoint(prohibited))
                self.assertFalse(hasattr(dto, "to_dict"))
                annotations = " ".join(
                    str(value) for value in dto.__annotations__.values()
                )
                for mutable in ("list", "dict", "set", "Mapping", "Path"):
                    self.assertNotIn(mutable, annotations)
        self.assertFalse(any(name.startswith("_") for name in application.__all__))
        self.assertEqual(
            tuple(
                inspect.signature(
                    application.CyberWatchtowerApplication
                ).parameters
            ),
            (),
        )


def _current_report(
    *,
    system_id="system:test",
    hostname="test-host",
    generated_at="2026-09-23T12:00:00+00:00",
):
    raw = scanner_result()
    finding = raw["findings"][0]
    return {
        "schema_version": "1.7",
        "generated_at": generated_at,
        "system": {
            "system_id": system_id,
            "hostname": hostname,
            "username": "private-user",
        },
        "assessment_domains": list(raw["assessment_domains"]),
        "coverage": dict(raw["coverage"]),
        "assessment_assurance": {
            "level": raw["assessment_assurance"]["level"],
            "limitations": list(raw["assessment_assurance"]["limitations"]),
        },
        "security_score": copy.deepcopy(raw["score"]),
        "findings": [{
            "finding_id": finding.finding_id,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity.value,
            "recommendation": finding.recommendation,
            "evidence": list(finding.evidence),
            "confidence": finding.confidence,
            "technique_id": finding.technique_id,
            "source": finding.source,
            "kind": finding.kind.value,
            "assessment_state": finding.assessment_state.value,
            "runtime_instance_count": finding.runtime_instance_count,
            "network_context": copy.deepcopy(finding.network_context),
        }],
    }


def _legacy_report(*, system_id=None, generated_at="2026-09-22T12:00:00Z"):
    system = {"hostname": "legacy-host"}
    if system_id is not None:
        system["system_id"] = system_id
    return {
        "schema_version": "1.0",
        "generated_at": generated_at,
        "system": system,
        "security_score": {"score": 95},
        "findings": [{
            "title": "Legacy listener",
            "severity": "LOW",
            "evidence": ["Protocol: udp", "Port: 3702"],
        }],
    }


def _write_report(root: Path, name: str, report: object) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / name
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return path


def _call_with_root(root: Path, method: str, request):
    repository = report_boundary._FileReportRepository(root)
    with patch(
        "cyberwatchtower.application.reports._default_report_repository",
        return_value=repository,
    ), patch("cyberwatchtower.scanner.run_scan") as scan, patch.object(
        report_boundary.reporting,
        "_save_json_report_with_receipt",
    ) as save:
        result = getattr(application.CyberWatchtowerApplication(), method)(request)
    scan.assert_not_called()
    save.assert_not_called()
    return result


def _failure_with_root(root: Path, method: str, request):
    repository = report_boundary._FileReportRepository(root)
    with patch(
        "cyberwatchtower.application.reports._default_report_repository",
        return_value=repository,
    ), patch("cyberwatchtower.scanner.run_scan") as scan, patch.object(
        report_boundary.reporting,
        "_save_json_report_with_receipt",
    ) as save:
        with unittest.TestCase().assertRaises(
            application.CyberWatchtowerApplicationError
        ) as caught:
            getattr(application.CyberWatchtowerApplication(), method)(request)
    scan.assert_not_called()
    save.assert_not_called()
    return caught.exception.failure


def _assess_and_save_with_root(root: Path, raw):
    repository = report_boundary._FileReportRepository(root)
    with patch(
        "cyberwatchtower.application.reports._default_report_repository",
        return_value=repository,
    ), patch(
        "cyberwatchtower.scanner.run_scan",
        return_value=raw,
    ) as scan:
        result = application.CyberWatchtowerApplication(
        ).assess_and_save_current_system(
            application.CurrentSystemAssessmentRequest()
        )
    scan.assert_called_once_with()
    return result


def _exception_graph(error):
    pending = [error]
    seen = set()
    result = []
    while pending:
        current = pending.pop()
        identity = id(current)
        if identity in seen:
            continue
        seen.add(identity)
        result.append(current)
        for related in (current.__cause__, current.__context__):
            if related is not None:
                pending.append(related)
    return tuple(result)


def _assert_private_exception_graph_is_detached(test, error):
    graph = _exception_graph(error)
    rendered = " ".join(
        f"{type(item).__name__}:{item!s}:{item!r}" for item in graph
    )
    test.assertEqual(graph, (error,))
    test.assertFalse(any(isinstance(item, OSError) for item in graph))
    test.assertNotIn("/private/sentinel/report.json", rendered)
    test.assertNotIn("SECRET_ERRNO_SENTINEL", rendered)


class _FakeScandir:
    def __init__(self, names, counter=None):
        self._names = iter(names)
        self._counter = counter

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def __iter__(self):
        return self

    def __next__(self):
        name = next(self._names)
        if self._counter is not None:
            self._counter[0] += 1
        return type("FakeDirectoryEntry", (), {"name": name})()


class AssessAndSaveCurrentSystemTests(unittest.TestCase):
    def test_success_scans_once_projects_and_saves_the_same_object(self):
        raw = scanner_result()
        projected = []
        saved = []
        real_project = assessment_boundary._project_result
        real_save = report_boundary.reporting._save_json_report_with_receipt

        def record_project(value, operation_id):
            projected.append(value)
            return real_project(value, operation_id)

        def record_save(value, report_directory):
            saved.append(value)
            return real_save(value, report_directory)

        with tempfile.TemporaryDirectory() as directory, patch.object(
            assessment_boundary,
            "_project_result",
            side_effect=record_project,
        ), patch.object(
            report_boundary.reporting,
            "_save_json_report_with_receipt",
            side_effect=record_save,
        ):
            root = Path(directory, "private-reports")
            result = _assess_and_save_with_root(root, raw)
            canonical = tuple(root.glob("*.json"))

        self.assertEqual(projected, [raw])
        self.assertEqual(saved, [raw])
        self.assertIs(projected[0], raw)
        self.assertIs(saved[0], raw)
        self.assertRegex(result.assessment.operation_id, r"^assessment:[0-9a-f]{32}$")
        self.assertEqual(result.assessment.system.system_id, "system:test")
        self.assertEqual(result.report.system_id, "system:test")
        self.assertEqual(len(canonical), 1)

    def test_successful_round_trip_summary_comes_from_canonical_readback(self):
        raw = scanner_result()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory, "private-reports")
            result = _assess_and_save_with_root(root, raw)
            canonical, = root.glob("*.json")
            report = json.loads(canonical.read_text(encoding="utf-8"))

        self.assertEqual(
            result.report.report_id.value,
            "report:" + canonical_report_digest(report),
        )
        self.assertEqual(result.report.schema_version, "1.7")
        self.assertEqual(result.report.system_id, report["system"]["system_id"])
        self.assertEqual(result.report.score, report["security_score"]["score"])
        self.assertEqual(result.report.finding_count, len(report["findings"]))
        self.assertFalse(hasattr(result, "path"))
        self.assertFalse(hasattr(result.report, "path"))

    def test_authoritative_system_id_is_required_before_writer(self):
        variants = (
            None,
            "",
            7,
            " system:test",
            "system:test ",
            "bad\nidentity",
            "x" * 4097,
        )
        for value in variants:
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                raw = scanner_result()
                if value is None:
                    raw["system"].pop("system_id")
                else:
                    raw["system"]["system_id"] = value
                root = Path(directory, "private-reports")
                repository = report_boundary._FileReportRepository(root)
                with patch(
                    "cyberwatchtower.application.reports._default_report_repository",
                    return_value=repository,
                ), patch(
                    "cyberwatchtower.scanner.run_scan",
                    return_value=raw,
                ) as scan, patch.object(
                    report_boundary.reporting,
                    "_save_json_report_with_receipt",
                ) as save:
                    with self.assertRaises(
                        application.CyberWatchtowerApplicationError
                    ) as caught:
                        application.CyberWatchtowerApplication(
                        ).assess_and_save_current_system(
                            application.CurrentSystemAssessmentRequest()
                        )
                scan.assert_called_once_with()
                save.assert_not_called()
                self.assertEqual(
                    caught.exception.failure.code,
                    ApplicationErrorCode.COMPATIBILITY_FAILURE,
                )
                self.assertEqual(tuple(Path(directory).rglob("*.json")), ())

    def test_authoritative_system_id_rejects_unicode_format_before_writer(self):
        raw = scanner_result()
        raw["system"]["system_id"] = "system:\u200bhidden"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory, "private-reports")
            repository = report_boundary._FileReportRepository(root)
            with patch(
                "cyberwatchtower.application.reports._default_report_repository",
                return_value=repository,
            ), patch(
                "cyberwatchtower.scanner.run_scan",
                return_value=raw,
            ) as scan, patch.object(
                report_boundary.reporting,
                "_save_json_report_with_receipt",
            ) as save:
                with self.assertRaises(
                    application.CyberWatchtowerApplicationError
                ) as caught:
                    application.CyberWatchtowerApplication(
                    ).assess_and_save_current_system(
                        application.CurrentSystemAssessmentRequest()
                    )

        scan.assert_called_once_with()
        save.assert_not_called()
        self.assertEqual(
            caught.exception.failure.code,
            ApplicationErrorCode.COMPATIBILITY_FAILURE,
        )
        self.assertEqual(tuple(Path(directory).rglob("*.json")), ())

    def test_invalid_request_has_assessment_operation_id_and_no_side_effects(self):
        with patch("cyberwatchtower.scanner.run_scan") as scan, patch(
            "cyberwatchtower.application.reports._default_report_repository"
        ) as repository:
            with self.assertRaises(
                application.CyberWatchtowerApplicationError
            ) as caught:
                application.CyberWatchtowerApplication(
                ).assess_and_save_current_system(object())
        scan.assert_not_called()
        repository.assert_not_called()
        self.assertEqual(
            caught.exception.failure.code,
            ApplicationErrorCode.INVALID_REQUEST,
        )
        self.assertRegex(
            caught.exception.failure.operation_id,
            r"^assessment:[0-9a-f]{32}$",
        )

    def test_assessment_projection_matches_standalone_operation(self):
        raw = scanner_result()
        with tempfile.TemporaryDirectory() as directory:
            repository = report_boundary._FileReportRepository(
                Path(directory, "private-reports")
            )
            with patch(
                "cyberwatchtower.application.reports._default_report_repository",
                return_value=repository,
            ), patch(
                "cyberwatchtower.scanner.run_scan",
                side_effect=(raw, raw),
            ) as scan:
                facade = application.CyberWatchtowerApplication()
                standalone = facade.assess_current_system(
                    application.CurrentSystemAssessmentRequest()
                )
                saved = facade.assess_and_save_current_system(
                    application.CurrentSystemAssessmentRequest()
                )

        self.assertEqual(scan.call_count, 2)
        self.assertNotEqual(standalone.operation_id, saved.assessment.operation_id)
        self.assertEqual(
            standalone,
            dataclasses.replace(
                saved.assessment,
                operation_id=standalone.operation_id,
                completed_at=standalone.completed_at,
            ),
        )

    def test_readback_failures_are_typed_without_retry_or_rollback_claim(self):
        real_save = report_boundary.reporting._save_json_report_with_receipt
        for mode in ("disappear", "replace", "malformed", "scope"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory, "private-reports")
                repository = report_boundary._FileReportRepository(root)
                changed = []

                def tamper_after_publication(value, report_directory):
                    receipt = real_save(value, report_directory)
                    path = receipt.path
                    changed.append(True)
                    if mode == "disappear":
                        path.unlink()
                    elif mode == "replace":
                        path.rename(path.with_suffix(".original"))
                        path.write_text(
                            json.dumps(_current_report(hostname="replacement-host")),
                            encoding="utf-8",
                        )
                    elif mode == "malformed":
                        path.write_text("{malformed", encoding="utf-8")
                    elif mode == "scope":
                        path.write_text(
                            json.dumps(_current_report(system_id="system:other")),
                            encoding="utf-8",
                        )
                    return receipt

                with patch(
                    "cyberwatchtower.application.reports._default_report_repository",
                    return_value=repository,
                ), patch(
                    "cyberwatchtower.scanner.run_scan",
                    return_value=scanner_result(),
                ) as scan, patch.object(
                    report_boundary.reporting,
                    "_save_json_report_with_receipt",
                    side_effect=tamper_after_publication,
                ) as save:
                    with self.assertRaises(
                        application.CyberWatchtowerApplicationError
                    ) as caught:
                        application.CyberWatchtowerApplication(
                        ).assess_and_save_current_system(
                            application.CurrentSystemAssessmentRequest()
                        )
                scan.assert_called_once_with()
                save.assert_called_once()
                self.assertEqual(changed, [True])
                self.assertEqual(
                    caught.exception.failure.code,
                    ApplicationErrorCode.INTEGRITY_FAILURE,
                )
                self.assertRegex(
                    caught.exception.failure.operation_id,
                    r"^assessment:[0-9a-f]{32}$",
                )
                self.assertIsNone(caught.exception.__cause__)
                if mode == "replace":
                    replacement = _current_report(hostname="replacement-host")
                    self.assertNotIn(
                        "report:" + canonical_report_digest(replacement),
                        repr(caught.exception.failure),
                    )
                    self.assertNotIn(
                        "replacement-host",
                        repr(caught.exception.failure),
                    )
                if mode != "disappear":
                    self.assertEqual(len(tuple(root.glob("*.json"))), 1)

    def test_receipt_directory_descriptor_closes_once_after_successful_readback(self):
        real_save = report_boundary.reporting._save_json_report_with_receipt
        real_close = report_boundary.reporting._PublicationReceipt.close
        receipts = []
        close_calls = []
        events = []

        class ObservedRepository(report_boundary._FileReportRepository):
            def _read_published_candidate(self, receipt):
                os.fstat(receipt.directory_descriptor)
                events.append("readback")
                return super()._read_published_candidate(receipt)

        def capture_receipt(value, report_directory):
            receipt = real_save(value, report_directory)
            os.fstat(receipt.directory_descriptor)
            receipts.append((receipt, receipt.directory_descriptor))
            return receipt

        def recording_close(receipt):
            close_calls.append(receipt)
            events.append("close")
            return real_close(receipt)

        with tempfile.TemporaryDirectory() as directory:
            repository = ObservedRepository(Path(directory, "private-reports"))
            with patch.object(
                report_boundary.reporting,
                "_save_json_report_with_receipt",
                side_effect=capture_receipt,
            ), patch.object(
                report_boundary.reporting._PublicationReceipt,
                "close",
                new=recording_close,
            ):
                stored = repository.save_scanner_result(scanner_result())

            receipt, descriptor = receipts[0]
            self.assertEqual(stored.summary.system_id, "system:test")
            self.assertEqual(events, ["readback", "close"])
            self.assertEqual(close_calls, [receipt])
            self.assertEqual(receipt.directory_descriptor, -1)
            with self.assertRaises(OSError) as caught:
                os.fstat(descriptor)
            self.assertEqual(caught.exception.errno, errno.EBADF)

    def test_receipt_directory_descriptor_closes_once_after_replacement_failure(self):
        real_save = report_boundary.reporting._save_json_report_with_receipt
        real_close = report_boundary.reporting._PublicationReceipt.close
        receipts = []
        close_calls = []
        events = []

        class ObservedRepository(report_boundary._FileReportRepository):
            def _read_published_candidate(self, receipt):
                os.fstat(receipt.directory_descriptor)
                events.append("readback")
                return super()._read_published_candidate(receipt)

        def replace_after_publication(value, report_directory):
            receipt = real_save(value, report_directory)
            descriptor = receipt.directory_descriptor
            os.fstat(descriptor)
            receipt.path.rename(receipt.path.with_suffix(".original"))
            receipt.path.write_text(
                json.dumps(_current_report(hostname="replacement-host")),
                encoding="utf-8",
            )
            receipts.append((receipt, descriptor))
            return receipt

        def recording_close(receipt):
            close_calls.append(receipt)
            events.append("close")
            return real_close(receipt)

        with tempfile.TemporaryDirectory() as directory:
            repository = ObservedRepository(Path(directory, "private-reports"))
            with patch.object(
                report_boundary.reporting,
                "_save_json_report_with_receipt",
                side_effect=replace_after_publication,
            ), patch.object(
                report_boundary.reporting._PublicationReceipt,
                "close",
                new=recording_close,
            ):
                with self.assertRaises(
                    report_boundary._ReportOperationFailure
                ) as caught:
                    repository.save_scanner_result(scanner_result())

            receipt, descriptor = receipts[0]
            self.assertEqual(
                caught.exception.code,
                ApplicationErrorCode.INTEGRITY_FAILURE,
            )
            self.assertEqual(events, ["readback", "close"])
            self.assertEqual(close_calls, [receipt])
            self.assertEqual(receipt.directory_descriptor, -1)
            with self.assertRaises(OSError) as descriptor_error:
                os.fstat(descriptor)
            self.assertEqual(descriptor_error.exception.errno, errno.EBADF)

    def test_same_inode_same_size_content_mutation_fails_receipt_hash_binding(self):
        real_save = report_boundary.reporting._save_json_report_with_receipt
        identities = []
        changed_payloads = []
        result = None

        def mutate_after_publication(value, report_directory):
            receipt = real_save(value, report_directory)
            before = receipt.path.stat()
            original = receipt.path.read_bytes()
            changed = original.replace(b"test-host", b"pest-host", 1)
            self.assertNotEqual(changed, original)
            self.assertEqual(len(changed), len(original))
            with receipt.path.open("r+b") as stream:
                stream.write(changed)
                stream.flush()
                os.fsync(stream.fileno())
            after = receipt.path.stat()
            self.assertEqual(after.st_dev, before.st_dev)
            self.assertEqual(after.st_ino, before.st_ino)
            self.assertEqual(after.st_size, before.st_size)
            self.assertNotEqual(receipt.path.read_bytes(), original)
            identities.append(
                (before.st_dev, before.st_ino, before.st_size)
            )
            changed_payloads.append(changed)
            return receipt

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory, "private-reports")
            repository = report_boundary._FileReportRepository(root)
            with patch(
                "cyberwatchtower.application.reports._default_report_repository",
                return_value=repository,
            ), patch(
                "cyberwatchtower.scanner.run_scan",
                return_value=scanner_result(),
            ) as scan, patch.object(
                report_boundary.reporting,
                "_save_json_report_with_receipt",
                side_effect=mutate_after_publication,
            ) as save:
                with self.assertRaises(
                    application.CyberWatchtowerApplicationError
                ) as caught:
                    result = application.CyberWatchtowerApplication(
                    ).assess_and_save_current_system(
                        application.CurrentSystemAssessmentRequest()
                    )

            canonical, = root.glob("*.json")
            tampered_report = json.loads(changed_payloads[0].decode("utf-8"))
            tampered_report_id = "report:" + canonical_report_digest(tampered_report)
            self.assertEqual(canonical.read_bytes(), changed_payloads[0])

        scan.assert_called_once_with()
        save.assert_called_once()
        self.assertIsNone(result)
        self.assertEqual(len(identities), 1)
        self.assertEqual(
            caught.exception.failure.code,
            ApplicationErrorCode.INTEGRITY_FAILURE,
        )
        self.assertNotIn(tampered_report_id, repr(caught.exception.failure))
        self.assertNotIn("pest-host", repr(caught.exception.failure))
        self.assertNotIn("rollback", repr(caught.exception.failure).casefold())

    def test_repository_root_replacement_cannot_redirect_saved_readback(self):
        real_save = report_boundary.reporting._save_json_report_with_receipt
        replacement = _current_report(
            hostname="replacement-root-host",
            generated_at="2030-01-01T00:00:00+00:00",
        )
        replacement_id = "report:" + canonical_report_digest(replacement)

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "private-reports"
            original_root = base / "original-root"
            repository = report_boundary._FileReportRepository(root)

            def replace_root_after_publication(value, report_directory):
                receipt = real_save(value, report_directory)
                root.rename(original_root)
                root.mkdir()
                (root / receipt.canonical_name).write_text(
                    json.dumps(replacement),
                    encoding="utf-8",
                )
                return receipt

            with patch(
                "cyberwatchtower.application.reports._default_report_repository",
                return_value=repository,
            ), patch(
                "cyberwatchtower.scanner.run_scan",
                return_value=scanner_result(),
            ) as scan, patch.object(
                report_boundary.reporting,
                "_save_json_report_with_receipt",
                side_effect=replace_root_after_publication,
            ):
                with self.assertRaises(
                    application.CyberWatchtowerApplicationError
                ) as caught:
                    application.CyberWatchtowerApplication(
                    ).assess_and_save_current_system(
                        application.CurrentSystemAssessmentRequest()
                    )

        scan.assert_called_once_with()
        self.assertEqual(
            caught.exception.failure.code,
            ApplicationErrorCode.INTEGRITY_FAILURE,
        )
        self.assertNotIn(replacement_id, repr(caught.exception.failure))
        self.assertNotIn("replacement-root-host", repr(caught.exception.failure))

    def test_writer_failures_are_safely_translated_without_fallback(self):
        sentinel = "/private/sentinel/report.json SECRET_ERRNO_SENTINEL"
        cases = (
            (
                OSError(errno.ENOTSUP, sentinel),
                ApplicationErrorCode.COMPATIBILITY_FAILURE,
            ),
            (
                PermissionError(errno.EACCES, sentinel),
                ApplicationErrorCode.PERMISSION_DENIED,
            ),
            (
                OSError(errno.EIO, sentinel),
                ApplicationErrorCode.STORAGE_FAILURE,
            ),
            (
                report_boundary.reporting._CanonicalNameExhausted(
                    errno.EEXIST,
                    "all canonical names occupied",
                ),
                ApplicationErrorCode.CONFLICT,
            ),
            (
                FileExistsError(errno.EEXIST, sentinel),
                ApplicationErrorCode.STORAGE_FAILURE,
            ),
        )
        for writer_error, expected_code in cases:
            with self.subTest(code=expected_code), tempfile.TemporaryDirectory() as directory:
                root = Path(directory, "private-reports")
                root.mkdir()
                repository = report_boundary._FileReportRepository(root)
                with patch(
                    "cyberwatchtower.application.reports._default_report_repository",
                    return_value=repository,
                ), patch(
                    "cyberwatchtower.scanner.run_scan",
                    return_value=scanner_result(),
                ) as scan, patch.object(
                    report_boundary.reporting,
                    "_save_json_report_with_receipt",
                    side_effect=writer_error,
                ) as save:
                    with self.assertRaises(
                        application.CyberWatchtowerApplicationError
                    ) as caught:
                        application.CyberWatchtowerApplication(
                        ).assess_and_save_current_system(
                            application.CurrentSystemAssessmentRequest()
                        )
                scan.assert_called_once_with()
                save.assert_called_once()
                self.assertEqual(caught.exception.failure.code, expected_code)
                exposed = str(caught.exception).casefold()
                self.assertNotIn("secret", exposed)
                self.assertNotIn("/proc", exposed)
                self.assertNotIn("/private", exposed)
                self.assertNotIn("errno", exposed)
                self.assertIsNone(caught.exception.__cause__)
                _assert_private_exception_graph_is_detached(
                    self,
                    caught.exception,
                )
                self.assertEqual(tuple(root.glob("*.json")), ())

    def test_readback_and_internal_failure_exception_graphs_are_detached(self):
        sentinel = "/private/sentinel/report.json SECRET_ERRNO_SENTINEL"

        class ReadbackFailureRepository(report_boundary._FileReportRepository):
            def _read_published_candidate(self, receipt):
                try:
                    raise OSError(errno.EIO, sentinel)
                except OSError:
                    report_boundary._storage_failure()

        class InternalFailureRepository(report_boundary._FileReportRepository):
            def save_scanner_result(self, scanner_result):
                raise RuntimeError(sentinel)

        cases = (
            (
                ReadbackFailureRepository,
                ApplicationErrorCode.STORAGE_FAILURE,
            ),
            (
                InternalFailureRepository,
                ApplicationErrorCode.INTERNAL_FAILURE,
            ),
        )
        for repository_type, expected_code in cases:
            with self.subTest(code=expected_code), tempfile.TemporaryDirectory() as directory:
                repository = repository_type(Path(directory, "private-reports"))
                with patch(
                    "cyberwatchtower.application.reports._default_report_repository",
                    return_value=repository,
                ), patch(
                    "cyberwatchtower.scanner.run_scan",
                    return_value=scanner_result(),
                ) as scan:
                    with self.assertRaises(
                        application.CyberWatchtowerApplicationError
                    ) as caught:
                        application.CyberWatchtowerApplication(
                        ).assess_and_save_current_system(
                            application.CurrentSystemAssessmentRequest()
                        )
                scan.assert_called_once_with()
                self.assertEqual(caught.exception.failure.code, expected_code)
                _assert_private_exception_graph_is_detached(
                    self,
                    caught.exception,
                )

    def test_saved_result_exposes_no_storage_or_raw_report_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory, "private-root-marker")
            result = _assess_and_save_with_root(root, scanner_result())
            rendered = repr(result.report)

        self.assertNotIn(str(root), rendered)
        self.assertFalse(hasattr(result.report, "path"))
        self.assertFalse(hasattr(result.report, "filename"))
        self.assertFalse(hasattr(result.report, "raw_report"))
        self.assertFalse(hasattr(result.report, "username"))
        self.assertFalse(hasattr(result.report, "operation_id"))
        self.assertNotIn("reportop:", repr(result))


class ApplicationReportReadBoundaryTests(unittest.TestCase):
    def _post_enumeration_root_swap_fixture(self, directory):
        base = Path(directory)
        root = base / "reports"
        trusted_report = _current_report(hostname="trusted-root-a")
        replacement_report = _current_report(hostname="replacement-root-b")
        _write_report(root, "report.json", trusted_report)
        replacement_root = base / "root-b"
        _write_report(replacement_root, "report.json", replacement_report)

        class SwappingRepository(report_boundary._FileReportRepository):
            def __init__(self, repository_root):
                super().__init__(repository_root)
                self.swap_count = 0

            def _read_candidate(self, candidate, root_authority):
                trusted_backup = self._root.with_name("root-a-retained")
                self._root.rename(trusted_backup)
                replacement_root.rename(self._root)
                self.swap_count += 1
                try:
                    return super()._read_candidate(candidate, root_authority)
                finally:
                    self._root.rename(replacement_root)
                    trusted_backup.rename(self._root)

        return (
            root,
            SwappingRepository(root),
            ReportId("report:" + canonical_report_digest(trusted_report)),
            ReportId("report:" + canonical_report_digest(replacement_report)),
        )

    def test_list_candidate_readback_cannot_follow_post_enumeration_root_aba(self):
        with tempfile.TemporaryDirectory() as directory:
            root, repository, trusted_id, replacement_id = (
                self._post_enumeration_root_swap_fixture(directory)
            )
            with patch(
                "cyberwatchtower.application.reports._default_report_repository",
                return_value=repository,
            ), patch("cyberwatchtower.scanner.run_scan") as scan, patch.object(
                report_boundary.reporting,
                "_save_json_report_with_receipt",
            ) as save:
                catalog = application.CyberWatchtowerApplication().list_saved_reports(
                    ListSavedReportsRequest("system:test")
                )
            scan.assert_not_called()
            save.assert_not_called()
            returned_ids = tuple(item.report_id for item in catalog.reports)
            self.assertEqual(returned_ids, (trusted_id,))
            self.assertNotIn(replacement_id, returned_ids)
            self.assertGreaterEqual(repository.swap_count, 1)
            self.assertTrue(root.is_dir())

    def test_get_candidate_readback_cannot_follow_post_enumeration_root_aba(self):
        with tempfile.TemporaryDirectory() as directory:
            root, repository, _trusted_id, replacement_id = (
                self._post_enumeration_root_swap_fixture(directory)
            )
            with patch(
                "cyberwatchtower.application.reports._default_report_repository",
                return_value=repository,
            ), patch("cyberwatchtower.scanner.run_scan") as scan, patch.object(
                report_boundary.reporting,
                "_save_json_report_with_receipt",
            ) as save, self.assertRaises(
                application.CyberWatchtowerApplicationError
            ) as caught:
                application.CyberWatchtowerApplication().get_saved_report(
                    GetSavedReportRequest(replacement_id, "system:test")
                )
            scan.assert_not_called()
            save.assert_not_called()
            self.assertEqual(
                caught.exception.failure.code,
                ApplicationErrorCode.NOT_FOUND,
            )
            self.assertGreaterEqual(repository.swap_count, 1)
            self.assertTrue(root.is_dir())

    def test_latest_candidate_readback_cannot_follow_post_enumeration_root_aba(self):
        with tempfile.TemporaryDirectory() as directory:
            root, repository, trusted_id, replacement_id = (
                self._post_enumeration_root_swap_fixture(directory)
            )
            with patch(
                "cyberwatchtower.application.reports._default_report_repository",
                return_value=repository,
            ), patch("cyberwatchtower.scanner.run_scan") as scan, patch.object(
                report_boundary.reporting,
                "_save_json_report_with_receipt",
            ) as save:
                detail = (
                    application.CyberWatchtowerApplication()
                    .get_latest_saved_report(
                        GetLatestSavedReportRequest("system:test")
                    )
                )
            scan.assert_not_called()
            save.assert_not_called()
            self.assertEqual(detail.report_id, trusted_id)
            self.assertNotEqual(detail.report_id, replacement_id)
            self.assertEqual(detail.system.hostname, "trusted-root-a")
            self.assertGreaterEqual(repository.swap_count, 2)
            self.assertTrue(root.is_dir())

    def test_trusted_root_handles_close_once_for_all_read_operation_paths(self):
        real_close = report_boundary._TrustedRootHandle.close

        class TrackingRepository(report_boundary._FileReportRepository):
            def __init__(self, root, fail_on_read_number=None):
                super().__init__(root)
                self.fail_on_read_number = fail_on_read_number
                self.handles = []
                self.read_count = 0

            def _open_trusted_root_handle(self, trusted):
                handle = super()._open_trusted_root_handle(trusted)
                os.fstat(handle.directory_descriptor)
                self.handles.append(handle)
                return handle

            def _read_candidate(self, candidate, root_authority):
                self.read_count += 1
                if self.read_count == self.fail_on_read_number:
                    report_boundary._integrity_failure()
                return super()._read_candidate(candidate, root_authority)

        cases = (
            (
                "list_success",
                "list_saved_reports",
                ListSavedReportsRequest("system:test"),
                None,
                False,
            ),
            (
                "list_failure",
                "list_saved_reports",
                ListSavedReportsRequest("system:test"),
                1,
                True,
            ),
            (
                "get_success",
                "get_saved_report",
                None,
                None,
                False,
            ),
            (
                "get_failure",
                "get_saved_report",
                None,
                2,
                True,
            ),
            (
                "latest_success",
                "get_latest_saved_report",
                GetLatestSavedReportRequest("system:test"),
                None,
                False,
            ),
            (
                "latest_failure",
                "get_latest_saved_report",
                GetLatestSavedReportRequest("system:test"),
                2,
                True,
            ),
        )
        for label, method, request, fail_on_read, expect_failure in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory, "reports")
                report = _current_report()
                _write_report(root, "report.json", report)
                report_id = ReportId("report:" + canonical_report_digest(report))
                if request is None:
                    request = GetSavedReportRequest(report_id, "system:test")
                repository = TrackingRepository(root, fail_on_read)
                close_calls = []

                def tracking_close(handle):
                    close_calls.append((id(handle), handle.directory_descriptor))
                    real_close(handle)

                with patch.object(
                    report_boundary._TrustedRootHandle,
                    "close",
                    new=tracking_close,
                ), patch(
                    "cyberwatchtower.application.reports._default_report_repository",
                    return_value=repository,
                ), patch("cyberwatchtower.scanner.run_scan") as scan, patch.object(
                    report_boundary.reporting,
                    "_save_json_report_with_receipt",
                ) as save:
                    if expect_failure:
                        with self.assertRaises(
                            application.CyberWatchtowerApplicationError
                        ) as caught:
                            getattr(
                                application.CyberWatchtowerApplication(),
                                method,
                            )(request)
                        self.assertEqual(
                            caught.exception.failure.code,
                            ApplicationErrorCode.INTEGRITY_FAILURE,
                        )
                    else:
                        getattr(
                            application.CyberWatchtowerApplication(),
                            method,
                        )(request)
                scan.assert_not_called()
                save.assert_not_called()
                self.assertTrue(repository.handles)
                for handle in repository.handles:
                    self.assertEqual(handle.directory_descriptor, -1)
                    self.assertEqual(
                        sum(
                            call_id == id(handle)
                            for call_id, _descriptor in close_calls
                        ),
                        1,
                    )
                self.assertTrue(
                    all(descriptor >= 0 for _call_id, descriptor in close_calls)
                )

    def test_one_trusted_root_handle_serves_all_catalog_candidates(self):
        class ObservingRepository(report_boundary._FileReportRepository):
            def __init__(self, root):
                super().__init__(root)
                self.handle_ids = []
                self.handles = []

            def _open_trusted_root_handle(self, trusted):
                handle = super()._open_trusted_root_handle(trusted)
                self.handles.append(handle)
                return handle

            def _read_candidate(self, candidate, root_authority):
                os.fstat(root_authority.directory_descriptor)
                self.handle_ids.append(id(root_authority))
                return super()._read_candidate(candidate, root_authority)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory, "reports")
            _write_report(
                root,
                "first.json",
                _current_report(generated_at="2026-09-23T10:00:00+00:00"),
            )
            _write_report(
                root,
                "second.json",
                _current_report(generated_at="2026-09-23T11:00:00+00:00"),
            )
            repository = ObservingRepository(root)
            with patch(
                "cyberwatchtower.application.reports._default_report_repository",
                return_value=repository,
            ):
                catalog = application.CyberWatchtowerApplication().list_saved_reports(
                    ListSavedReportsRequest("system:test")
                )
        self.assertEqual(len(catalog.reports), 2)
        self.assertEqual(len(repository.handle_ids), 2)
        self.assertEqual(len(set(repository.handle_ids)), 1)
        self.assertEqual(len(repository.handles), 1)
        self.assertEqual(repository.handles[0].directory_descriptor, -1)

    def test_missing_and_empty_roots_are_complete_empty_catalogs(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for root in (base / "missing", base / "empty"):
                if root.name == "empty":
                    root.mkdir()
                with self.subTest(root=root.name):
                    catalog = _call_with_root(
                        root,
                        "list_saved_reports",
                        ListSavedReportsRequest("system:test"),
                    )
                    self.assertEqual(catalog.reports, ())
                    self.assertEqual(
                        catalog.completeness,
                        ReportCatalogCompleteness.COMPLETE,
                    )
                    self.assertEqual(catalog.omitted_count, 0)

    def test_native_system_scope_and_hostname_never_cross_contaminate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_report(root, "a.json", _current_report(
                system_id="system:a", hostname="shared-host"
            ))
            _write_report(root, "b.json", _current_report(
                system_id="system:b", hostname="shared-host"
            ))
            catalog = _call_with_root(
                root,
                "list_saved_reports",
                ListSavedReportsRequest("system:a"),
            )
        self.assertEqual(len(catalog.reports), 1)
        self.assertEqual(catalog.reports[0].system_id, "system:a")
        self.assertEqual(catalog.completeness, ReportCatalogCompleteness.COMPLETE)

    def test_unresolved_legacy_is_omitted_and_makes_catalog_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_report(root, "legacy.json", _legacy_report())
            catalog = _call_with_root(
                root,
                "list_saved_reports",
                ListSavedReportsRequest("system:test"),
            )
        self.assertEqual(catalog.reports, ())
        self.assertEqual(catalog.completeness, ReportCatalogCompleteness.INCOMPLETE)
        self.assertEqual(catalog.omitted_count, 1)
        self.assertEqual(catalog.diagnostics.unresolved_system_count, 1)

    def test_digest_identity_ordering_and_semantic_duplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            later_a = _current_report(generated_at="2026-09-23T12:00:00-04:00")
            later_b = copy.deepcopy(later_a)
            later_b["system"]["username"] = "different-private-user"
            earlier = _current_report(generated_at="2026-09-23T10:00:00+00:00")
            duplicate = copy.deepcopy(later_a)
            duplicate["_report_path"] = "/private/ignored.json"
            for name, report in (
                ("z.json", later_a),
                ("a.json", duplicate),
                ("middle.json", later_b),
                ("early.json", earlier),
            ):
                _write_report(root, name, report)
            catalog = _call_with_root(
                root,
                "list_saved_reports",
                ListSavedReportsRequest("system:test"),
            )
        expected_ids = {
            "report:" + canonical_report_digest(report)
            for report in (later_a, later_b, earlier)
        }
        self.assertEqual({item.report_id.value for item in catalog.reports}, expected_ids)
        self.assertEqual(catalog.diagnostics.duplicate_count, 1)
        self.assertEqual(catalog.omitted_count, 0)
        self.assertEqual(catalog.completeness, ReportCatalogCompleteness.COMPLETE)
        self.assertEqual(
            tuple((item.generated_at, item.report_id.value) for item in catalog.reports),
            tuple(sorted(
                (item.generated_at, item.report_id.value)
                for item in catalog.reports
            )),
        )
        self.assertTrue(all(item.generated_at.utcoffset().total_seconds() == 0 for item in catalog.reports))

    def test_malformed_nonobject_unsupported_and_oversized_are_diagnostic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "malformed.json").write_text("{not json", encoding="utf-8")
            (root / "nonobject.json").write_text("[]", encoding="utf-8")
            future = {"schema_version": "9.0"}
            _write_report(root, "future.json", future)
            (root / "oversized.json").write_text("x" * 129, encoding="utf-8")
            with patch.object(report_boundary, "MAX_REPORT_BYTES", 128):
                catalog = _call_with_root(
                    root,
                    "list_saved_reports",
                    ListSavedReportsRequest("system:test"),
                )
        self.assertEqual(catalog.omitted_count, 4)
        self.assertEqual(catalog.diagnostics.malformed_count, 2)
        self.assertEqual(catalog.diagnostics.unsupported_count, 1)
        self.assertEqual(catalog.diagnostics.oversized_count, 1)
        self.assertEqual(catalog.completeness, ReportCatalogCompleteness.INCOMPLETE)

    def test_symlink_and_nonregular_candidates_are_never_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory, "reports")
            outside = Path(directory, "outside.json")
            outside.write_text(json.dumps(_current_report()), encoding="utf-8")
            root.mkdir()
            (root / "link.json").symlink_to(outside)
            (root / "directory.json").mkdir()
            catalog = _call_with_root(
                root,
                "list_saved_reports",
                ListSavedReportsRequest("system:test"),
            )
        self.assertEqual(catalog.omitted_count, 2)
        self.assertEqual(catalog.diagnostics.symlink_count, 1)
        self.assertEqual(catalog.diagnostics.nonregular_count, 1)
        self.assertEqual(catalog.completeness, ReportCatalogCompleteness.INCOMPLETE)

    def test_candidate_disappearance_permission_and_io_have_one_category_each(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_report(root, "candidate.json", _current_report())
            for issue, field in (
                (report_boundary._CandidateIssue.DISAPPEARED, "disappeared_count"),
                (report_boundary._CandidateIssue.PERMISSION_DENIED, "permission_denied_count"),
                (report_boundary._CandidateIssue.IO_ERROR, "io_error_count"),
            ):
                repository = report_boundary._FileReportRepository(root)
                with self.subTest(issue=issue), patch.object(
                    report_boundary._FileReportRepository,
                    "_read_bytes",
                    side_effect=report_boundary._CandidateReadFailure(issue),
                ):
                    snapshot = repository.catalog_for_system("system:test")
                    diagnostics = snapshot.diagnostics
                    self.assertEqual(snapshot.omitted_count, 1)
                    self.assertEqual(getattr(diagnostics, field), 1)
                    self.assertEqual(
                        sum(
                            getattr(diagnostics, name)
                            for name in (
                                "malformed_count", "unsupported_count",
                                "oversized_count", "permission_denied_count",
                                "io_error_count", "symlink_count",
                                "nonregular_count", "disappeared_count",
                                "unresolved_system_count",
                            )
                        ),
                        1,
                    )

    def test_root_permission_storage_symlink_and_non_directory_fail_atomically(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "reports"
            root.mkdir()
            for exception, code in (
                (PermissionError(), ApplicationErrorCode.PERMISSION_DENIED),
                (OSError("private path"), ApplicationErrorCode.STORAGE_FAILURE),
            ):
                with self.subTest(code=code), patch.object(
                    report_boundary.os, "scandir", side_effect=exception
                ):
                    failure = _failure_with_root(
                        root,
                        "list_saved_reports",
                        ListSavedReportsRequest("system:test"),
                    )
                    self.assertEqual(failure.code, code)
                    self.assertNotIn(str(root), failure.message)

            real = base / "real"
            real.mkdir()
            link = base / "link"
            link.symlink_to(real, target_is_directory=True)
            file_root = base / "file-root"
            file_root.write_text("not a directory", encoding="utf-8")
            for invalid_root in (link, file_root):
                with self.subTest(root=invalid_root.name):
                    failure = _failure_with_root(
                        invalid_root,
                        "list_saved_reports",
                        ListSavedReportsRequest("system:test"),
                    )
                    self.assertEqual(
                        failure.code,
                        ApplicationErrorCode.INTEGRITY_FAILURE,
                    )

    def test_out_of_scope_valid_report_does_not_make_catalog_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_report(root, "other.json", _current_report(system_id="system:other"))
            catalog = _call_with_root(
                root,
                "list_saved_reports",
                ListSavedReportsRequest("system:test"),
            )
        self.assertEqual(catalog.reports, ())
        self.assertEqual(catalog.omitted_count, 0)
        self.assertEqual(catalog.completeness, ReportCatalogCompleteness.COMPLETE)

    def test_get_by_id_reopens_revalidates_and_preserves_historical_detail(self):
        class CountingRepository(report_boundary._FileReportRepository):
            def __init__(self, root):
                super().__init__(root)
                self.read_count = 0

            def _read_candidate(self, path, resolved_root):
                self.read_count += 1
                return super()._read_candidate(path, resolved_root)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = _current_report(
                generated_at="2026-09-23T08:00:00-04:00"
            )
            _write_report(root, "report.json", report)
            repository = CountingRepository(root)
            report_id = ReportId("report:" + canonical_report_digest(report))
            with patch(
                "cyberwatchtower.application.reports._default_report_repository",
                return_value=repository,
            ), patch("cyberwatchtower.scanner.run_scan") as scan:
                detail = application.CyberWatchtowerApplication().get_saved_report(
                    GetSavedReportRequest(report_id, "system:test")
                )
            scan.assert_not_called()
        self.assertEqual(repository.read_count, 2)
        self.assertEqual(detail.report_id, report_id)
        self.assertEqual(detail.generated_at.isoformat(), "2026-09-23T12:00:00+00:00")
        self.assertEqual(detail.system.system_id, "system:test")
        self.assertEqual(detail.system.hostname, "test-host")
        self.assertFalse(hasattr(detail.system, "username"))
        self.assertEqual(detail.score.scoring_version, ScoringVersion.V2)
        self.assertIsNotNone(detail.score.breakdown)
        self.assertEqual(detail.findings[0].runtime_instance_count, 2)

    def test_get_not_found_requires_complete_visibility(self):
        missing = ReportId("report:" + "f" * 64)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            complete = _failure_with_root(
                root,
                "get_saved_report",
                GetSavedReportRequest(missing, "system:test"),
            )
            (root / "malformed.json").write_text("{", encoding="utf-8")
            incomplete = _failure_with_root(
                root,
                "get_saved_report",
                GetSavedReportRequest(missing, "system:test"),
            )
        self.assertEqual(complete.code, ApplicationErrorCode.NOT_FOUND)
        self.assertEqual(incomplete.code, ApplicationErrorCode.INTEGRITY_FAILURE)

    def test_selected_mutation_or_scope_change_fails_integrity(self):
        class MutatingRepository(report_boundary._FileReportRepository):
            def __init__(self, root, path):
                super().__init__(root)
                self.path = path

            def catalog_for_system(self, system_id):
                snapshot = super().catalog_for_system(system_id)
                changed = _current_report(system_id="system:other")
                self.path.write_text(json.dumps(changed), encoding="utf-8")
                return snapshot

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = _current_report()
            path = _write_report(root, "report.json", report)
            repository = MutatingRepository(root, path)
            report_id = ReportId("report:" + canonical_report_digest(report))
            with patch(
                "cyberwatchtower.application.reports._default_report_repository",
                return_value=repository,
            ):
                with self.assertRaises(
                    application.CyberWatchtowerApplicationError
                ) as caught:
                    application.CyberWatchtowerApplication().get_saved_report(
                        GetSavedReportRequest(report_id, "system:test")
                    )
        self.assertEqual(
            caught.exception.failure.code,
            ApplicationErrorCode.INTEGRITY_FAILURE,
        )

    def test_latest_is_deterministic_and_fails_closed_when_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = _current_report(generated_at="2026-09-23T10:00:00+00:00")
            second = _current_report(generated_at="2026-09-23T11:00:00+00:00")
            _write_report(root, "z.json", first)
            _write_report(root, "a.json", second)
            latest = _call_with_root(
                root,
                "get_latest_saved_report",
                GetLatestSavedReportRequest("system:test"),
            )
            self.assertEqual(
                latest.report_id.value,
                "report:" + canonical_report_digest(second),
            )
            (root / "malformed.json").write_text("{", encoding="utf-8")
            failure = _failure_with_root(
                root,
                "get_latest_saved_report",
                GetLatestSavedReportRequest("system:test"),
            )
        self.assertEqual(failure.code, ApplicationErrorCode.INTEGRITY_FAILURE)

    def test_latest_complete_empty_returns_none(self):
        with tempfile.TemporaryDirectory() as directory:
            result = _call_with_root(
                Path(directory),
                "get_latest_saved_report",
                GetLatestSavedReportRequest("system:test"),
            )
        self.assertIsNone(result)

    def test_legacy_defaults_and_v1_score_are_explicitly_marked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = _legacy_report(system_id="system:legacy")
            _write_report(root, "legacy.json", report)
            detail = _call_with_root(
                root,
                "get_latest_saved_report",
                GetLatestSavedReportRequest("system:legacy"),
            )
        self.assertEqual(detail.score.scoring_version, ScoringVersion.V1)
        self.assertEqual(detail.score.score, 95)
        self.assertIsNone(detail.score.breakdown)
        self.assertIsNone(detail.assurance)
        self.assertTrue(detail.findings[0].metadata_inferred)
        self.assertIsNone(detail.findings[0].description)
        self.assertIsNone(detail.findings[0].recommendation)
        self.assertEqual(detail.findings[0].runtime_instance_count, 1)
        self.assertEqual(
            detail.compatibility.state,
            ReportCompatibilityState.LEGACY_NORMALIZED,
        )
        self.assertTrue({
            SavedReportField.ASSESSMENT_DOMAINS,
            SavedReportField.COVERAGE,
            SavedReportField.FINDING_METADATA,
            SavedReportField.RUNTIME_MULTIPLICITY,
            SavedReportField.SCORING_VERSION,
            SavedReportField.RISK_LEVEL,
            SavedReportField.SEVERITY_COUNTS,
        }.issubset(set(detail.compatibility.defaulted_fields)))
        self.assertEqual(
            set(detail.compatibility.unavailable_fields),
            {SavedReportField.ASSURANCE, SavedReportField.SCORING_BREAKDOWN},
        )

    def test_network_and_privacy_projection_preserve_stored_semantics(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = _current_report()
            _write_report(root, "report.json", report)
            detail = _call_with_root(
                root,
                "get_latest_saved_report",
                GetLatestSavedReportRequest("system:test"),
            )
        finding = detail.findings[0]
        self.assertEqual(
            finding.network_context.reachability_state.value,
            "POTENTIALLY_REACHABLE",
        )
        self.assertEqual(
            finding.network_context.firewall_policy.evaluated_policy_disposition.value,
            "ALLOW",
        )
        self.assertNotEqual(
            finding.network_context.reachability_state.value,
            "CONFIRMED_REACHABLE",
        )
        self.assertEqual(
            tuple(item.category.value for item in finding.evidence),
            ("PROTOCOL", "ADDRESS", "PORT", "PROCESS"),
        )
        self.assertEqual(finding.omitted_evidence_count, 3)
        self.assertEqual(finding.evidence_projection_state, EvidenceProjectionState.REDACTED)
        self.assertEqual(len(detail.findings), 1)
        self.assertEqual(detail.projection_notices[0].omitted_count, 3)

    def test_sensitive_required_content_fails_privacy_atomically(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = _current_report()
            report["findings"][0]["description"] = "password=/private/value"
            _write_report(root, "report.json", report)
            report_id = ReportId("report:" + canonical_report_digest(report))
            failure = _failure_with_root(
                root,
                "get_saved_report",
                GetSavedReportRequest(report_id, "system:test"),
            )
        self.assertEqual(failure.code, ApplicationErrorCode.PRIVACY_POLICY_BLOCKED)

    def test_report_operation_id_is_created_before_request_validation(self):
        fixed = "reportop:" + "c" * 32
        with patch(
            "cyberwatchtower.application.assessment._report_operation_id",
            return_value=fixed,
        ) as generator, patch(
            "cyberwatchtower.application.reports._default_report_repository"
        ) as factory:
            with self.assertRaises(
                application.CyberWatchtowerApplicationError
            ) as caught:
                application.CyberWatchtowerApplication().list_saved_reports(object())
        generator.assert_called_once_with()
        factory.assert_not_called()
        self.assertEqual(caught.exception.failure.operation_id, fixed)
        self.assertEqual(caught.exception.failure.code, ApplicationErrorCode.INVALID_REQUEST)

    def test_facade_revalidates_exact_request_values_before_repository_access(self):
        invalid = object.__new__(ListSavedReportsRequest)
        object.__setattr__(invalid, "system_id", " system:test")
        with patch(
            "cyberwatchtower.application.assessment._report_operation_id",
            return_value="reportop:" + "d" * 32,
        ), patch(
            "cyberwatchtower.application.reports._default_report_repository"
        ) as factory:
            with self.assertRaises(
                application.CyberWatchtowerApplicationError
            ) as caught:
                application.CyberWatchtowerApplication().list_saved_reports(invalid)
        factory.assert_not_called()
        self.assertEqual(
            caught.exception.failure.code,
            ApplicationErrorCode.INVALID_REQUEST,
        )

    def test_candidate_limit_is_inclusive_and_ignores_noncandidates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = report_boundary._FileReportRepository(root)
            accepted = (
                f"report-{index}.json"
                for index in range(report_boundary.MAX_REPORT_CANDIDATES)
            )
            with patch.object(
                report_boundary.os,
                "scandir",
                return_value=_FakeScandir(accepted),
            ):
                _root_state, root_handle, names = repository._root_candidates()
            try:
                self.assertEqual(
                    len(names),
                    report_boundary.MAX_REPORT_CANDIDATES,
                )
            finally:
                root_handle.close()

            names = (
                [f"ignored-{index}.txt" for index in range(32)]
                + ["internal.tmp", "one.json"]
            )
            with patch.object(
                report_boundary,
                "MAX_REPORT_CANDIDATES",
                1,
            ), patch.object(
                report_boundary.os,
                "scandir",
                return_value=_FakeScandir(names),
            ):
                _root_state, root_handle, names = repository._root_candidates()
            try:
                self.assertEqual(names, ("one.json",))
            finally:
                root_handle.close()

    def test_candidate_limit_stops_at_first_excess_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = report_boundary._FileReportRepository(root)
            counter = [0]
            names = (f"report-{index}.json" for index in range(100))
            with patch.object(
                report_boundary,
                "MAX_REPORT_CANDIDATES",
                3,
            ), patch.object(
                report_boundary.os,
                "scandir",
                return_value=_FakeScandir(names, counter),
            ), self.assertRaises(report_boundary._ReportOperationFailure) as caught:
                repository._root_candidates()
        self.assertEqual(caught.exception.code, ApplicationErrorCode.INTEGRITY_FAILURE)
        self.assertEqual(counter[0], 4)

    def test_candidate_limit_failure_is_atomic_for_all_read_operations(self):
        requests = (
            (
                "list_saved_reports",
                ListSavedReportsRequest("system:test"),
            ),
            (
                "get_saved_report",
                GetSavedReportRequest(
                    ReportId("report:" + "f" * 64),
                    "system:test",
                ),
            ),
            (
                "get_latest_saved_report",
                GetLatestSavedReportRequest("system:test"),
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for method, request in requests:
                names = (f"report-{index}.json" for index in range(4))
                with self.subTest(method=method), patch.object(
                    report_boundary,
                    "MAX_REPORT_CANDIDATES",
                    3,
                ), patch.object(
                    report_boundary.os,
                    "scandir",
                    return_value=_FakeScandir(names),
                ):
                    failure = _failure_with_root(root, method, request)
                    self.assertEqual(
                        failure.code,
                        ApplicationErrorCode.INTEGRITY_FAILURE,
                    )

    def test_unsupported_object_bound_enumeration_fails_all_reads_before_aba(self):
        requests = (
            ("list_saved_reports", ListSavedReportsRequest("system:test")),
            (
                "get_saved_report",
                GetSavedReportRequest(
                    ReportId("report:" + "f" * 64),
                    "system:test",
                ),
            ),
            (
                "get_latest_saved_report",
                GetLatestSavedReportRequest("system:test"),
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory, "reports")
            _write_report(root, "authoritative.json", _current_report())
            real_scandir = os.scandir

            class InsecureAbaFallback:
                def __init__(self, _target):
                    self._original = root.with_name("root-a")
                    self._replacement = root.with_name("root-b")
                    root.rename(self._original)
                    root.mkdir()
                    self._iterator = real_scandir(root)

                def __enter__(self):
                    return self._iterator

                def __exit__(self, *_args):
                    self._iterator.close()
                    root.rename(self._replacement)
                    self._original.rename(root)
                    return False

            for method, request in requests:
                with self.subTest(method=method), patch.object(
                    report_boundary,
                    "_SCANDIR_SUPPORTS_FD",
                    False,
                ), patch.object(
                    report_boundary.os,
                    "scandir",
                    side_effect=InsecureAbaFallback,
                ) as scandir:
                    failure = _failure_with_root(root, method, request)
                    self.assertEqual(
                        failure.code,
                        ApplicationErrorCode.INTEGRITY_FAILURE,
                    )
                    scandir.assert_not_called()

    def test_descriptor_enumeration_remains_bound_to_root_a_across_aba(self):
        if not report_boundary._SCANDIR_SUPPORTS_FD:
            self.skipTest("runtime does not support descriptor-bound scandir")

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "reports"
            report = _current_report()
            _write_report(root, "authoritative.json", report)
            original = base / "root-a"
            replacement = base / "root-b"
            real_scandir = os.scandir

            class SwappingScandir:
                def __init__(self, descriptor):
                    root.rename(original)
                    root.mkdir()
                    self._iterator = real_scandir(descriptor)

                def __enter__(self):
                    return self._iterator

                def __exit__(self, *_args):
                    self._iterator.close()
                    root.rename(replacement)
                    original.rename(root)
                    return False

            with patch.object(
                report_boundary.os,
                "scandir",
                side_effect=SwappingScandir,
            ):
                catalog = _call_with_root(
                    root,
                    "list_saved_reports",
                    ListSavedReportsRequest("system:test"),
                )
        self.assertEqual(len(catalog.reports), 1)
        self.assertEqual(
            catalog.reports[0].report_id.value,
            "report:" + canonical_report_digest(report),
        )
        self.assertEqual(catalog.completeness, ReportCatalogCompleteness.COMPLETE)

    def test_missing_root_requires_object_bound_relative_lookup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory, "missing")
            with patch.object(
                report_boundary,
                "_RELATIVE_OPEN_SUPPORTED",
                False,
            ):
                failure = _failure_with_root(
                    root,
                    "list_saved_reports",
                    ListSavedReportsRequest("system:test"),
                )
        self.assertEqual(failure.code, ApplicationErrorCode.INTEGRITY_FAILURE)

    def test_root_replacement_cannot_return_empty_authoritative_results(self):
        class ReplacingRepository(report_boundary._FileReportRepository):
            def _enumerate_candidate_paths(self, trusted):
                backup = self._root.with_name(self._root.name + "-original")
                self._root.rename(backup)
                self._root.mkdir()
                return super()._enumerate_candidate_paths(trusted)

        requests = (
            ("list_saved_reports", ListSavedReportsRequest("system:test")),
            (
                "get_saved_report",
                GetSavedReportRequest(
                    ReportId("report:" + "f" * 64),
                    "system:test",
                ),
            ),
            (
                "get_latest_saved_report",
                GetLatestSavedReportRequest("system:test"),
            ),
        )
        for method, request in requests:
            with self.subTest(method=method), tempfile.TemporaryDirectory() as directory:
                root = Path(directory, "reports")
                root.mkdir()
                repository = ReplacingRepository(root)
                with patch(
                    "cyberwatchtower.application.reports._default_report_repository",
                    return_value=repository,
                ):
                    with self.assertRaises(
                        application.CyberWatchtowerApplicationError
                    ) as caught:
                        getattr(
                            application.CyberWatchtowerApplication(),
                            method,
                        )(request)
                self.assertEqual(
                    caught.exception.failure.code,
                    ApplicationErrorCode.INTEGRITY_FAILURE,
                )

    def test_root_disappearance_symlink_and_non_directory_fail_closed(self):
        class ChangingRepository(report_boundary._FileReportRepository):
            def __init__(self, root, replacement):
                super().__init__(root)
                self.replacement = replacement

            def _enumerate_candidate_paths(self, trusted):
                paths = super()._enumerate_candidate_paths(trusted)
                backup = self._root.with_name(self._root.name + "-original")
                self._root.rename(backup)
                if self.replacement == "symlink":
                    self._root.symlink_to(backup, target_is_directory=True)
                elif self.replacement == "file":
                    self._root.write_text("not a directory", encoding="utf-8")
                return paths

        for replacement in ("missing", "symlink", "file"):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as directory:
                root = Path(directory, "reports")
                root.mkdir()
                repository = ChangingRepository(root, replacement)
                with patch(
                    "cyberwatchtower.application.reports._default_report_repository",
                    return_value=repository,
                ):
                    with self.assertRaises(
                        application.CyberWatchtowerApplicationError
                    ) as caught:
                        application.CyberWatchtowerApplication().list_saved_reports(
                            ListSavedReportsRequest("system:test")
                        )
                self.assertEqual(
                    caught.exception.failure.code,
                    ApplicationErrorCode.INTEGRITY_FAILURE,
                )

    def test_missing_root_that_appears_before_snapshot_use_fails_closed(self):
        class AppearingRepository(report_boundary._FileReportRepository):
            def catalog_for_system(self, system_id):
                snapshot = super().catalog_for_system(system_id)
                self._root.mkdir()
                return snapshot

        requests = (
            ("list_saved_reports", ListSavedReportsRequest("system:test")),
            (
                "get_saved_report",
                GetSavedReportRequest(
                    ReportId("report:" + "f" * 64),
                    "system:test",
                ),
            ),
            (
                "get_latest_saved_report",
                GetLatestSavedReportRequest("system:test"),
            ),
        )
        for method, request in requests:
            with self.subTest(method=method), tempfile.TemporaryDirectory() as directory:
                root = Path(directory, "missing")
                repository = AppearingRepository(root)
                with patch(
                    "cyberwatchtower.application.reports._default_report_repository",
                    return_value=repository,
                ):
                    with self.assertRaises(
                        application.CyberWatchtowerApplicationError
                    ) as caught:
                        getattr(
                            application.CyberWatchtowerApplication(),
                            method,
                        )(request)
                self.assertEqual(
                    caught.exception.failure.code,
                    ApplicationErrorCode.INTEGRITY_FAILURE,
                )

    def test_root_replacement_after_snapshot_prevents_detail_success(self):
        class ReplacingAfterSnapshotRepository(
            report_boundary._FileReportRepository
        ):
            def catalog_for_system(self, system_id):
                snapshot = super().catalog_for_system(system_id)
                backup = self._root.with_name(self._root.name + "-original")
                self._root.rename(backup)
                self._root.mkdir()
                return snapshot

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory, "reports")
            report = _current_report()
            _write_report(root, "report.json", report)
            repository = ReplacingAfterSnapshotRepository(root)
            report_id = ReportId("report:" + canonical_report_digest(report))
            with patch(
                "cyberwatchtower.application.reports._default_report_repository",
                return_value=repository,
            ):
                with self.assertRaises(
                    application.CyberWatchtowerApplicationError
                ) as caught:
                    application.CyberWatchtowerApplication().get_saved_report(
                        GetSavedReportRequest(report_id, "system:test")
                    )
        self.assertEqual(
            caught.exception.failure.code,
            ApplicationErrorCode.INTEGRITY_FAILURE,
        )

    def test_digest_collision_with_unequal_canonical_bytes_fails_integrity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_report(root, "first.json", _current_report(
                generated_at="2026-09-23T10:00:00+00:00"
            ))
            _write_report(root, "second.json", _current_report(
                generated_at="2026-09-23T11:00:00+00:00"
            ))
            with patch.object(
                report_boundary,
                "canonical_report_digest",
                return_value="c" * 64,
            ):
                failure = _failure_with_root(
                    root,
                    "list_saved_reports",
                    ListSavedReportsRequest("system:test"),
                )
        self.assertEqual(failure.code, ApplicationErrorCode.INTEGRITY_FAILURE)

    def test_invalid_utf8_is_malformed_and_never_leaks_decoder_text(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "invalid.json").write_bytes(b'{"schema_version":"1.7"}\xff')
            catalog = _call_with_root(
                root,
                "list_saved_reports",
                ListSavedReportsRequest("system:test"),
            )
        self.assertEqual(catalog.completeness, ReportCatalogCompleteness.INCOMPLETE)
        self.assertEqual(catalog.omitted_count, 1)
        self.assertEqual(catalog.diagnostics.malformed_count, 1)

    def test_network_projection_forwards_enclosing_historical_schema(self):
        network_context = _current_report()["findings"][0]["network_context"]
        parsed = report_boundary.reachability_from_report(
            network_context,
            report_schema_version="1.7",
        )
        with patch.object(
            report_boundary,
            "reachability_from_report",
            return_value=parsed,
        ) as parser:
            for version in ("1.6", "1.7"):
                with self.subTest(version=version):
                    projected = report_boundary._project_network_context(
                        network_context,
                        report_schema_version=version,
                    )
                    self.assertIsNotNone(projected)
        self.assertEqual(
            tuple(
                call.kwargs["report_schema_version"]
                for call in parser.call_args_list
            ),
            ("1.6", "1.7"),
        )

    def test_nofollow_detects_replaced_candidate_with_descriptor_relative_open(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "reports"
            candidate = _write_report(root, "report.json", _current_report())
            outside = _write_report(base, "outside.json", _current_report())
            original = candidate.with_suffix(".original")
            real_open = os.open
            replaced = False

            def replace_before_open(path, flags, *, dir_fd=None):
                nonlocal replaced
                if path == candidate.name and dir_fd is not None and not replaced:
                    candidate.rename(original)
                    candidate.symlink_to(outside)
                    replaced = True
                return real_open(path, flags, dir_fd=dir_fd)

            with patch.object(
                report_boundary.os,
                "open",
                side_effect=replace_before_open,
            ):
                catalog = _call_with_root(
                    root,
                    "list_saved_reports",
                    ListSavedReportsRequest("system:test"),
                )
        self.assertTrue(replaced)
        self.assertEqual(catalog.reports, ())
        self.assertEqual(catalog.completeness, ReportCatalogCompleteness.INCOMPLETE)
        self.assertEqual(catalog.diagnostics.symlink_count, 1)

    def test_candidate_and_trusted_reread_regular_to_fifo_races_fail_without_read(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO fixtures are unavailable on this platform.")

        for phase in ("catalog", "trusted_reread"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                root = Path(directory, "reports")
                report = _current_report()
                candidate = _write_report(root, "report.json", report)
                report_id = ReportId("report:" + canonical_report_digest(report))
                repository = report_boundary._FileReportRepository(root)
                snapshot = None
                if phase == "trusted_reread":
                    snapshot = repository.catalog_for_system("system:test")

                original = candidate.with_suffix(".original")
                real_open = os.open
                opened_descriptors = []
                replaced = False

                def replace_with_fifo_before_open(path, flags, *, dir_fd=None):
                    nonlocal replaced
                    if path == candidate.name and dir_fd is not None and not replaced:
                        self.assertTrue(flags & os.O_NOFOLLOW)
                        self.assertTrue(flags & os.O_NONBLOCK)
                        candidate.rename(original)
                        os.mkfifo(candidate)
                        replaced = True
                        descriptor = real_open(path, flags, dir_fd=dir_fd)
                        opened_descriptors.append(descriptor)
                        return descriptor
                    return real_open(path, flags, dir_fd=dir_fd)

                with patch.object(
                    report_boundary.os,
                    "open",
                    side_effect=replace_with_fifo_before_open,
                ), patch.object(
                    report_boundary.os,
                    "fdopen",
                    side_effect=AssertionError("raced FIFO must not be read"),
                ):
                    if phase == "catalog":
                        result = repository.catalog_for_system("system:test")
                        self.assertEqual(result.reports, ())
                        self.assertEqual(
                            result.completeness,
                            ReportCatalogCompleteness.INCOMPLETE,
                        )
                        self.assertEqual(result.diagnostics.nonregular_count, 1)
                    else:
                        with self.assertRaises(
                            report_boundary._ReportOperationFailure
                        ) as caught:
                            repository.read_trusted_material(
                                snapshot,
                                report_id=report_id,
                                expected_system_id="system:test",
                            )
                        self.assertEqual(
                            caught.exception.code,
                            ApplicationErrorCode.INTEGRITY_FAILURE,
                        )
                        self.assertNotIn(str(root), repr(caught.exception))

                self.assertTrue(replaced)
                self.assertEqual(len(opened_descriptors), 1)
                with self.assertRaises(OSError) as closed:
                    os.fstat(opened_descriptors[0])
                self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_publication_reread_regular_to_fifo_race_is_nonblocking_and_closed(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO fixtures are unavailable on this platform.")

        real_save = report_boundary.reporting._save_json_report_with_receipt
        real_open = os.open
        receipts = []
        opened_descriptors = []
        published_name = None

        def publish_then_replace_with_fifo(value, report_directory):
            nonlocal published_name
            receipt = real_save(value, report_directory)
            published_name = receipt.canonical_name
            receipt.path.rename(receipt.path.with_suffix(".original"))
            os.mkfifo(receipt.path)
            receipts.append((receipt, receipt.directory_descriptor))
            return receipt

        def observe_publication_open(path, flags, mode=0o777, *, dir_fd=None):
            if path == published_name and dir_fd is not None:
                self.assertTrue(flags & os.O_NOFOLLOW)
                self.assertTrue(flags & os.O_NONBLOCK)
                descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
                opened_descriptors.append(descriptor)
                return descriptor
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory, "reports")
            repository = report_boundary._FileReportRepository(root)
            with patch.object(
                report_boundary.reporting,
                "_save_json_report_with_receipt",
                side_effect=publish_then_replace_with_fifo,
            ), patch.object(
                report_boundary.os,
                "open",
                side_effect=observe_publication_open,
            ), patch.object(
                report_boundary.os,
                "read",
                side_effect=AssertionError("raced FIFO must not be read"),
            ), self.assertRaises(
                report_boundary._ReportOperationFailure
            ) as caught:
                repository.save_scanner_result(scanner_result())

            self.assertEqual(
                caught.exception.code,
                ApplicationErrorCode.INTEGRITY_FAILURE,
            )
            self.assertNotIn(str(root), repr(caught.exception))
            self.assertEqual(len(opened_descriptors), 1)
            with self.assertRaises(OSError) as closed:
                os.fstat(opened_descriptors[0])
            self.assertEqual(closed.exception.errno, errno.EBADF)
            receipt, directory_descriptor = receipts[0]
            self.assertEqual(receipt.directory_descriptor, -1)
            with self.assertRaises(OSError) as root_closed:
                os.fstat(directory_descriptor)
            self.assertEqual(root_closed.exception.errno, errno.EBADF)

    def test_candidate_open_flags_fstat_before_read_and_missing_support_fails_closed(self):
        real_open = os.open
        real_fstat = os.fstat
        real_fdopen = os.fdopen
        candidate_descriptors = set()
        events = []

        def observe_open(path, flags, *, dir_fd=None):
            descriptor = real_open(path, flags, dir_fd=dir_fd)
            if path == "report.json" and dir_fd is not None:
                self.assertTrue(flags & os.O_NOFOLLOW)
                self.assertTrue(flags & os.O_NONBLOCK)
                candidate_descriptors.add(descriptor)
                events.append("open")
            return descriptor

        def observe_fstat(descriptor):
            if descriptor in candidate_descriptors:
                events.append("fstat")
            return real_fstat(descriptor)

        def observe_fdopen(descriptor, *args, **kwargs):
            if descriptor in candidate_descriptors:
                events.append("read")
            return real_fdopen(descriptor, *args, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory, "reports")
            _write_report(root, "report.json", _current_report())
            repository = report_boundary._FileReportRepository(root)
            with patch.object(
                report_boundary.os,
                "open",
                side_effect=observe_open,
            ), patch.object(
                report_boundary.os,
                "fstat",
                side_effect=observe_fstat,
            ), patch.object(
                report_boundary.os,
                "fdopen",
                side_effect=observe_fdopen,
            ):
                result = repository.catalog_for_system("system:test")
            self.assertEqual(len(result.reports), 1)
            self.assertEqual(events, ["open", "fstat", "read"])

            with patch.object(report_boundary.os, "O_NONBLOCK", 0), self.assertRaises(
                report_boundary._ReportOperationFailure
            ) as caught:
                repository.catalog_for_system("system:test")
            self.assertEqual(
                caught.exception.code,
                ApplicationErrorCode.INTEGRITY_FAILURE,
            )

    def test_descriptor_relative_read_error_graph_is_detached(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory, "reports")
            candidate = _write_report(root, "report.json", _current_report())
            real_open = os.open

            def fail_candidate_open(path, flags, *, dir_fd=None):
                if path == candidate.name and dir_fd is not None:
                    raise OSError(
                        errno.EIO,
                        "SECRET_ERRNO_SENTINEL",
                        "/private/sentinel/report.json",
                    )
                return real_open(path, flags, dir_fd=dir_fd)

            repository = report_boundary._FileReportRepository(root)
            with patch(
                "cyberwatchtower.application.reports._default_report_repository",
                return_value=repository,
            ), patch.object(
                report_boundary.os,
                "open",
                side_effect=fail_candidate_open,
            ), self.assertRaises(
                application.CyberWatchtowerApplicationError
            ) as caught:
                application.CyberWatchtowerApplication().get_latest_saved_report(
                    GetLatestSavedReportRequest("system:test")
                )
        self.assertEqual(
            caught.exception.failure.code,
            ApplicationErrorCode.INTEGRITY_FAILURE,
        )
        _assert_private_exception_graph_is_detached(self, caught.exception)

    def test_private_repository_uses_canonical_writer_and_bounded_read_authority(self):
        source = inspect.getsource(report_boundary)
        self.assertEqual(report_boundary.MAX_REPORT_BYTES, 10 * 1024 * 1024)
        self.assertEqual(report_boundary.MAX_REPORT_CANDIDATES, 4096)
        self.assertEqual(
            report_boundary._SCANDIR_SUPPORTS_FD,
            os.scandir in os.supports_fd,
        )
        self.assertEqual(
            report_boundary._RELATIVE_OPEN_SUPPORTED,
            os.open in os.supports_dir_fd,
        )
        self.assertEqual(
            report_boundary._RELATIVE_LSTAT_SUPPORTED,
            os.stat in os.supports_dir_fd
            and os.stat in os.supports_follow_symlinks,
        )
        self.assertEqual(report_boundary._DEFAULT_REPORT_ROOT, Path("reports"))
        self.assertEqual(
            source.count("reporting._save_json_report_with_receipt("),
            1,
        )
        self.assertNotIn("reporting.save_json_report(", source)
        self.assertNotIn("memory.ingestion", source)
        self.assertNotIn("sqlite3", source)
        self.assertNotIn("assessment import", source)
        self.assertNotIn("mkdir(", source)
        self.assertNotIn("write_text(", source)
        self.assertNotIn("write_bytes(", source)
        self.assertNotIn("unlink(", source)
        self.assertNotIn("rename(", source)
        self.assertNotIn("request.report_id.value", source)
        self.assertNotIn("provider_safe", source)
        self.assertNotIn("safe_to_send", source)
        self.assertFalse(any(
            name.startswith("_Report") or name.startswith("_FileReport")
            for name in application.__all__
        ))


if __name__ == "__main__":
    unittest.main()
