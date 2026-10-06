import dataclasses
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import cyberwatchtower.application as application
from cyberwatchtower.application import _history as history_boundary
from cyberwatchtower.application import reports as report_boundary
from cyberwatchtower.application._memory import _TrustedReportMaterial
from cyberwatchtower.application.errors import ApplicationComponent, ApplicationErrorCode
from cyberwatchtower.history import compare_reports
from cyberwatchtower.memory.normalizers import normalize_report
from cyberwatchtower.report_contracts import (
    canonical_report_bytes,
    canonical_report_digest,
)


SYSTEM_ID = "system:test"


def _finding(finding_id, *, source="network", title=None):
    return {
        "finding_id": finding_id,
        "title": title or finding_id,
        "severity": "MEDIUM",
        "source": source,
        "evidence": [],
    }


def _report(
    generated_at,
    *,
    system_id=SYSTEM_ID,
    hostname="display-host",
    score=80,
    risk="MODERATE",
    findings=(),
    coverage="COMPLETE",
):
    return {
        "schema_version": "1.0",
        "generated_at": generated_at,
        "system": {"system_id": system_id, "hostname": hostname},
        "security_score": {
            "score": score,
            "risk_level": risk,
            "counts": {},
        },
        "coverage": {"network_socket_inspection": coverage},
        "findings": list(findings),
    }


def _report_id(report):
    return application.ReportId("report:" + canonical_report_digest(report))


def _material(report):
    normalized, _omitted = normalize_report(report)
    digest = canonical_report_digest(report)
    return _TrustedReportMaterial(
        report_id=application.ReportId("report:" + digest),
        canonical_digest=digest,
        canonical_bytes=canonical_report_bytes(report),
        normalized_report=normalized,
        system_id=normalized.native_system_id,
        schema_version=normalized.schema_version,
        generated_at=report_boundary._utc_timestamp(normalized.generated_at),
    )


def _write(root, name, report):
    root.mkdir(parents=True, exist_ok=True)
    (root / name).write_text(json.dumps(report), encoding="utf-8")


class _FakeSnapshot:
    def __init__(self, report_ids, completeness=application.ReportCatalogCompleteness.COMPLETE):
        self.completeness = completeness
        self._report_ids = frozenset(report_ids)

    def find(self, report_id):
        return object() if report_id in self._report_ids else None


class _FakeRepository:
    def __init__(self, materials, *, completeness=application.ReportCatalogCompleteness.COMPLETE):
        self.materials = dict(materials)
        self.snapshot = _FakeSnapshot(self.materials, completeness)
        self.catalog_calls = 0
        self.reads = []

    def catalog_for_system(self, system_id):
        self.catalog_calls += 1
        self.catalog_system_id = system_id
        return self.snapshot

    def read_trusted_material(self, snapshot, *, report_id, expected_system_id):
        self.reads.append((snapshot, report_id, expected_system_id))
        return self.materials[report_id]


def _invoke(repository, request):
    with patch(
        "cyberwatchtower.application.reports._default_report_repository",
        return_value=repository,
    ), patch("cyberwatchtower.history.load_reports") as legacy_loader:
        result = application.CyberWatchtowerApplication().compare_saved_reports(request)
    legacy_loader.assert_not_called()
    return result


class ApplicationHistoryComparisonTests(unittest.TestCase):
    def test_digest_bytes_and_report_id_use_the_frozen_canonical_authority(self):
        report = _report("2026-09-01T00:00:00+00:00")
        canonical = canonical_report_bytes(report)
        digest = canonical_report_digest(report)
        material = _material(report)
        self.assertEqual(hashlib.sha256(canonical).hexdigest(), digest)
        self.assertEqual(material.canonical_bytes, canonical)
        self.assertEqual(material.canonical_digest, digest)
        self.assertEqual(material.report_id.value, "report:" + digest)

    def test_history_operation_id_precedes_invalid_request_validation(self):
        with patch.object(
            history_boundary,
            "_history_operation_id",
            return_value="historyop:" + "a" * 32,
        ) as operation_id, self.assertRaises(
            application.CyberWatchtowerApplicationError
        ) as caught:
            application.CyberWatchtowerApplication().compare_saved_reports(object())
        operation_id.assert_called_once_with()
        self.assertEqual(caught.exception.failure.operation_id, "historyop:" + "a" * 32)
        self.assertEqual(caught.exception.failure.code, ApplicationErrorCode.INVALID_REQUEST)

    def test_forged_same_report_id_request_is_rejected_without_io(self):
        report_id = application.ReportId("report:" + "a" * 64)
        request = object.__new__(application.CompareSavedReportsRequest)
        object.__setattr__(request, "system_id", SYSTEM_ID)
        object.__setattr__(request, "previous_report_id", report_id)
        object.__setattr__(request, "current_report_id", report_id)
        with patch(
            "cyberwatchtower.application.reports._default_report_repository"
        ) as repository, self.assertRaises(
            application.CyberWatchtowerApplicationError
        ) as caught:
            application.CyberWatchtowerApplication().compare_saved_reports(request)
        repository.assert_not_called()
        self.assertEqual(caught.exception.failure.code, ApplicationErrorCode.INVALID_REQUEST)

    def test_one_complete_snapshot_supplies_both_trusted_reports(self):
        previous = _material(_report("2026-09-01T00:00:00+00:00"))
        current = _material(_report("2026-09-02T00:00:00+00:00", score=90))
        repository = _FakeRepository({previous.report_id: previous, current.report_id: current})
        result = _invoke(repository, application.CompareSavedReportsRequest(
            SYSTEM_ID, previous.report_id, current.report_id
        ))
        self.assertEqual(repository.catalog_calls, 1)
        self.assertEqual(len(repository.reads), 2)
        self.assertTrue(all(read[0] is repository.snapshot for read in repository.reads))
        self.assertEqual(result.score_change, 10)

    def test_trusted_material_must_match_each_requested_report_id(self):
        previous = _material(_report("2026-09-01T00:00:00+00:00"))
        current = _material(_report("2026-09-02T00:00:00+00:00", score=90))

        class MisdirectingRepository(_FakeRepository):
            def read_trusted_material(self, snapshot, *, report_id, expected_system_id):
                self.reads.append((snapshot, report_id, expected_system_id))
                return current if report_id == previous.report_id else previous

        repository = MisdirectingRepository({
            previous.report_id: previous,
            current.report_id: current,
        })
        with patch(
            "cyberwatchtower.application.reports._default_report_repository",
            return_value=repository,
        ), self.assertRaises(application.CyberWatchtowerApplicationError) as caught:
            application.CyberWatchtowerApplication().compare_saved_reports(
                application.CompareSavedReportsRequest(
                    SYSTEM_ID, previous.report_id, current.report_id
                )
            )
        self.assertEqual(caught.exception.failure.code, ApplicationErrorCode.INTEGRITY_FAILURE)

    def test_incomplete_snapshot_fails_integrity_before_any_read(self):
        previous = _material(_report("2026-09-01T00:00:00+00:00"))
        current = _material(_report("2026-09-02T00:00:00+00:00"))
        repository = _FakeRepository(
            {previous.report_id: previous, current.report_id: current},
            completeness=application.ReportCatalogCompleteness.INCOMPLETE,
        )
        with patch(
            "cyberwatchtower.application.reports._default_report_repository",
            return_value=repository,
        ), self.assertRaises(application.CyberWatchtowerApplicationError) as caught:
            application.CyberWatchtowerApplication().compare_saved_reports(
                application.CompareSavedReportsRequest(
                    SYSTEM_ID, previous.report_id, current.report_id
                )
            )
        self.assertEqual(caught.exception.failure.code, ApplicationErrorCode.INTEGRITY_FAILURE)
        self.assertFalse(repository.reads)

    def test_complete_snapshot_missing_either_report_is_not_found(self):
        previous = _material(_report("2026-09-01T00:00:00+00:00"))
        current = _material(_report("2026-09-02T00:00:00+00:00", score=81))
        for retained in ({current.report_id: current}, {previous.report_id: previous}):
            with self.subTest(retained=tuple(retained)):
                repository = _FakeRepository(retained)
                with patch(
                    "cyberwatchtower.application.reports._default_report_repository",
                    return_value=repository,
                ), self.assertRaises(application.CyberWatchtowerApplicationError) as caught:
                    application.CyberWatchtowerApplication().compare_saved_reports(
                        application.CompareSavedReportsRequest(
                            SYSTEM_ID, previous.report_id, current.report_id
                        )
                    )
                self.assertEqual(caught.exception.failure.code, ApplicationErrorCode.NOT_FOUND)
                self.assertFalse(repository.reads)

    def test_inverted_and_equal_time_reversed_chronology_are_invalid(self):
        chronological = (
            _material(_report("2026-09-01T00:00:00+00:00")),
            _material(_report("2026-09-02T00:00:00+00:00", score=81)),
        )
        equal = [
            _material(_report("2026-09-03T00:00:00+00:00", score=score))
            for score in (82, 83)
        ]
        equal.sort(key=lambda item: item.report_id.value)
        cases = ((chronological[1], chronological[0]), (equal[1], equal[0]))
        for previous, current in cases:
            with self.subTest(previous=previous.report_id.value):
                repository = _FakeRepository({
                    previous.report_id: previous,
                    current.report_id: current,
                })
                with patch(
                    "cyberwatchtower.application.reports._default_report_repository",
                    return_value=repository,
                ), self.assertRaises(application.CyberWatchtowerApplicationError) as caught:
                    application.CyberWatchtowerApplication().compare_saved_reports(
                        application.CompareSavedReportsRequest(
                            SYSTEM_ID, previous.report_id, current.report_id
                        )
                    )
                self.assertEqual(
                    caught.exception.failure.code,
                    ApplicationErrorCode.INVALID_REQUEST,
                )

    def test_equal_time_report_id_tie_break_accepts_ascending_order(self):
        reports = [
            _material(_report("2026-09-03T00:00:00+00:00", score=score))
            for score in (82, 83)
        ]
        reports.sort(key=lambda item: item.report_id.value)
        repository = _FakeRepository({item.report_id: item for item in reports})
        result = _invoke(repository, application.CompareSavedReportsRequest(
            SYSTEM_ID, reports[0].report_id, reports[1].report_id
        ))
        self.assertEqual(result.previous_report.report_id, reports[0].report_id)
        self.assertEqual(result.current_report.report_id, reports[1].report_id)

    def test_exact_system_scope_cannot_be_rescued_by_hostname(self):
        previous = _material(_report(
            "2026-09-01T00:00:00+00:00", system_id="system:other", hostname="same-host"
        ))
        current = _material(_report(
            "2026-09-02T00:00:00+00:00", system_id="system:other", hostname="same-host"
        ))
        repository = _FakeRepository({previous.report_id: previous, current.report_id: current})
        with patch(
            "cyberwatchtower.application.reports._default_report_repository",
            return_value=repository,
        ), self.assertRaises(application.CyberWatchtowerApplicationError) as caught:
            application.CyberWatchtowerApplication().compare_saved_reports(
                application.CompareSavedReportsRequest(
                    SYSTEM_ID, previous.report_id, current.report_id
                )
            )
        self.assertEqual(caught.exception.failure.code, ApplicationErrorCode.INTEGRITY_FAILURE)

    def test_unresolved_legacy_candidate_makes_visibility_incomplete(self):
        unresolved = _report("2026-09-01T00:00:00+00:00")
        del unresolved["system"]["system_id"]
        current = _report("2026-09-02T00:00:00+00:00", score=81)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write(root, "previous.json", unresolved)
            _write(root, "current.json", current)
            request = application.CompareSavedReportsRequest(
                SYSTEM_ID, _report_id(unresolved), _report_id(current)
            )
            with patch(
                "cyberwatchtower.application.reports._default_report_repository",
                return_value=report_boundary._FileReportRepository(root),
            ), self.assertRaises(application.CyberWatchtowerApplicationError) as caught:
                application.CyberWatchtowerApplication().compare_saved_reports(request)
        self.assertEqual(caught.exception.failure.code, ApplicationErrorCode.INTEGRITY_FAILURE)

    def test_added_resolved_uncertain_ordering_and_privacy_projection(self):
        previous = _material(_report(
            "2026-09-01T00:00:00+00:00",
            findings=(_finding("resolved:z"), _finding("resolved:a")),
        ))
        current = _material(_report(
            "2026-09-02T00:00:00+00:00",
            score=90,
            findings=(_finding("added:z"), _finding("added:a")),
        ))
        repository = _FakeRepository({previous.report_id: previous, current.report_id: current})
        result = _invoke(repository, application.CompareSavedReportsRequest(
            SYSTEM_ID, previous.report_id, current.report_id
        ))
        self.assertEqual(
            [item.finding_id for item in result.added_findings],
            ["added:a", "added:z"],
        )
        self.assertEqual(
            [item.finding_id for item in result.resolved_findings],
            ["resolved:a", "resolved:z"],
        )
        self.assertFalse(result.uncertain_disappearances)
        rendered = repr(result)
        for prohibited in ("evidence", "canonical_bytes", "source_path", "_report_path"):
            self.assertNotIn(prohibited, rendered)

    def test_uncovered_disappearance_is_uncertain_not_resolved(self):
        previous = _material(_report(
            "2026-09-01T00:00:00+00:00", findings=(_finding("finding:gone"),)
        ))
        current = _material(_report(
            "2026-09-02T00:00:00+00:00", score=90, findings=(), coverage="INCOMPLETE"
        ))
        repository = _FakeRepository({previous.report_id: previous, current.report_id: current})
        result = _invoke(repository, application.CompareSavedReportsRequest(
            SYSTEM_ID, previous.report_id, current.report_id
        ))
        self.assertFalse(result.resolved_findings)
        self.assertEqual(
            tuple(item.finding_id for item in result.uncertain_disappearances),
            ("finding:gone",),
        )

    def test_duplicate_effective_identity_fails_closed_defensively(self):
        previous = _material(_report(
            "2026-09-01T00:00:00+00:00", findings=(_finding("finding:duplicate"),)
        ))
        current = _material(_report("2026-09-02T00:00:00+00:00", score=81))
        duplicate_normalized = dataclasses.replace(
            previous.normalized_report,
            findings=(
                previous.normalized_report.findings[0],
                previous.normalized_report.findings[0],
            ),
        )
        previous = dataclasses.replace(previous, normalized_report=duplicate_normalized)
        repository = _FakeRepository({previous.report_id: previous, current.report_id: current})
        with patch(
            "cyberwatchtower.application.reports._default_report_repository",
            return_value=repository,
        ), self.assertRaises(application.CyberWatchtowerApplicationError) as caught:
            application.CyberWatchtowerApplication().compare_saved_reports(
                application.CompareSavedReportsRequest(
                    SYSTEM_ID, previous.report_id, current.report_id
                )
            )
        self.assertEqual(caught.exception.failure.code, ApplicationErrorCode.INTEGRITY_FAILURE)

    def test_score_trends_and_stored_risk_are_preserved(self):
        cases = ((80, 90, "IMPROVED", 10), (90, 80, "DECLINED", -10), (80, 80, "UNCHANGED", 0))
        for old, new, trend, change in cases:
            with self.subTest(trend=trend):
                previous = _material(_report(
                    "2026-09-01T00:00:00+00:00", score=old, risk="HIGH"
                ))
                current = _material(_report(
                    "2026-09-02T00:00:00+00:00", score=new, risk="LOW"
                ))
                repository = _FakeRepository({
                    previous.report_id: previous,
                    current.report_id: current,
                })
                result = _invoke(repository, application.CompareSavedReportsRequest(
                    SYSTEM_ID, previous.report_id, current.report_id
                ))
                self.assertEqual(result.score_trend.value, trend)
                self.assertEqual(result.score_change, change)
                self.assertEqual((result.previous_risk, result.current_risk), ("HIGH", "LOW"))

    def test_different_scoring_versions_are_incomparable(self):
        previous = _material(_report("2026-09-01T00:00:00+00:00", score=10))
        current = _material(_report("2026-09-02T00:00:00+00:00", score=90))
        current_score = dataclasses.replace(current.normalized_report.score, scoring_version="2")
        current = dataclasses.replace(
            current,
            normalized_report=dataclasses.replace(current.normalized_report, score=current_score),
        )
        repository = _FakeRepository({previous.report_id: previous, current.report_id: current})
        result = _invoke(repository, application.CompareSavedReportsRequest(
            SYSTEM_ID, previous.report_id, current.report_id
        ))
        self.assertEqual(result.score_trend, application.ScoreTrendState.INCOMPARABLE)
        self.assertIsNone(result.score_change)

    def test_repository_failure_provenance_and_exception_graph_are_safe(self):
        previous = _material(_report("2026-09-01T00:00:00+00:00"))
        current = _material(_report("2026-09-02T00:00:00+00:00", score=81))
        request = application.CompareSavedReportsRequest(
            SYSTEM_ID, previous.report_id, current.report_id
        )
        for code in (
            ApplicationErrorCode.PERMISSION_DENIED,
            ApplicationErrorCode.STORAGE_FAILURE,
            ApplicationErrorCode.INTEGRITY_FAILURE,
        ):
            with self.subTest(code=code):
                repository = _FakeRepository({})
                repository.catalog_for_system = lambda _system_id, code=code: (_ for _ in ()).throw(
                    report_boundary._ReportOperationFailure(code, ApplicationComponent.STORAGE)
                )
                with patch(
                    "cyberwatchtower.application.reports._default_report_repository",
                    return_value=repository,
                ), self.assertRaises(application.CyberWatchtowerApplicationError) as caught:
                    application.CyberWatchtowerApplication().compare_saved_reports(request)
                self.assertEqual(caught.exception.failure.code, code)
                self.assertIsNone(caught.exception.__cause__)
                self.assertIsNone(caught.exception.__context__)

        class RawFailureRepository:
            def catalog_for_system(self, _system_id):
                raise OSError(5, "/private/report-root")

        with patch(
            "cyberwatchtower.application.reports._default_report_repository",
            return_value=RawFailureRepository(),
        ), self.assertRaises(application.CyberWatchtowerApplicationError) as caught:
            application.CyberWatchtowerApplication().compare_saved_reports(request)
        self.assertEqual(caught.exception.failure.code, ApplicationErrorCode.INTERNAL_FAILURE)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn("private", repr(caught.exception.failure).casefold())

    def test_trusted_material_read_is_descriptor_bound_and_closes_handles(self):
        real_close = report_boundary._TrustedRootHandle.close

        class TrackingRepository(report_boundary._FileReportRepository):
            def __init__(self, root):
                super().__init__(root)
                self.handles = []

            def _open_trusted_root_handle(self, trusted):
                handle = super()._open_trusted_root_handle(trusted)
                self.handles.append(handle)
                return handle

        previous_report = _report("2026-09-01T00:00:00+00:00")
        current_report = _report("2026-09-02T00:00:00+00:00", score=81)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write(root, "previous.json", previous_report)
            _write(root, "current.json", current_report)
            repository = TrackingRepository(root)
            with patch.object(
                report_boundary._TrustedRootHandle,
                "close",
                autospec=True,
                side_effect=real_close,
            ) as close:
                _invoke(repository, application.CompareSavedReportsRequest(
                    SYSTEM_ID, _report_id(previous_report), _report_id(current_report)
                ))
        self.assertGreaterEqual(len(repository.handles), 3)
        self.assertTrue(all(handle.directory_descriptor == -1 for handle in repository.handles))
        self.assertEqual(close.call_count, len(repository.handles))

    def test_trusted_material_read_cannot_follow_post_snapshot_root_aba(self):
        base_report = _report("2026-09-01T00:00:00+00:00")
        current_report = _report("2026-09-02T00:00:00+00:00", score=81)
        replacement_previous = _report(
            "2026-09-01T00:00:00+00:00", hostname="root-b", score=10
        )
        replacement_current = _report(
            "2026-09-02T00:00:00+00:00", hostname="root-b", score=20
        )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "reports"
            replacement = base / "root-b"
            _write(root, "previous.json", base_report)
            _write(root, "current.json", current_report)
            _write(replacement, "previous.json", replacement_previous)
            _write(replacement, "current.json", replacement_current)

            class SwappingRepository(report_boundary._FileReportRepository):
                def __init__(self, repository_root):
                    super().__init__(repository_root)
                    self.after_snapshot = False
                    self.swaps = 0

                def catalog_for_system(self, system_id):
                    snapshot = super().catalog_for_system(system_id)
                    self.after_snapshot = True
                    return snapshot

                def _read_candidate(self, name, root_handle):
                    if not self.after_snapshot:
                        return super()._read_candidate(name, root_handle)
                    retained = self._root.with_name("root-a-retained")
                    self._root.rename(retained)
                    replacement.rename(self._root)
                    self.swaps += 1
                    try:
                        return super()._read_candidate(name, root_handle)
                    finally:
                        self._root.rename(replacement)
                        retained.rename(self._root)

            repository = SwappingRepository(root)
            with patch("cyberwatchtower.scanner.run_scan") as scan, patch.object(
                report_boundary.reporting,
                "_save_json_report_with_receipt",
            ) as save:
                result = _invoke(repository, application.CompareSavedReportsRequest(
                    SYSTEM_ID, _report_id(base_report), _report_id(current_report)
                ))
            scan.assert_not_called()
            save.assert_not_called()
        self.assertEqual(result.previous_score, 80)
        self.assertEqual(result.current_score, 81)
        self.assertGreaterEqual(repository.swaps, 2)
        self.assertNotEqual(result.previous_report.report_id, _report_id(replacement_previous))
        self.assertNotEqual(result.current_report.report_id, _report_id(replacement_current))

    def test_candidate_replacement_after_snapshot_fails_integrity(self):
        previous_report = _report("2026-09-01T00:00:00+00:00")
        current_report = _report("2026-09-02T00:00:00+00:00", score=81)
        replacement = _report("2026-09-01T00:00:00+00:00", score=10)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write(root, "previous.json", previous_report)
            _write(root, "current.json", current_report)

            class ReplacingRepository(report_boundary._FileReportRepository):
                def catalog_for_system(self, system_id):
                    snapshot = super().catalog_for_system(system_id)
                    (self._root / "previous.json").unlink()
                    _write(self._root, "previous.json", replacement)
                    return snapshot

            with patch(
                "cyberwatchtower.application.reports._default_report_repository",
                return_value=ReplacingRepository(root),
            ), self.assertRaises(application.CyberWatchtowerApplicationError) as caught:
                application.CyberWatchtowerApplication().compare_saved_reports(
                    application.CompareSavedReportsRequest(
                        SYSTEM_ID, _report_id(previous_report), _report_id(current_report)
                    )
                )
        self.assertEqual(caught.exception.failure.code, ApplicationErrorCode.INTEGRITY_FAILURE)

    def test_symlink_and_nonregular_candidates_never_enter_comparison(self):
        previous = _report("2026-09-01T00:00:00+00:00")
        current = _report("2026-09-02T00:00:00+00:00", score=81)
        for candidate_kind in ("symlink", "fifo"):
            with self.subTest(kind=candidate_kind), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                root = base / "reports"
                _write(root, "previous.json", previous)
                if candidate_kind == "symlink":
                    target = base / "outside.json"
                    target.write_text(json.dumps(current), encoding="utf-8")
                    (root / "current.json").symlink_to(target)
                else:
                    os.mkfifo(root / "current.json")
                with patch(
                    "cyberwatchtower.application.reports._default_report_repository",
                    return_value=report_boundary._FileReportRepository(root),
                ), self.assertRaises(application.CyberWatchtowerApplicationError) as caught:
                    application.CyberWatchtowerApplication().compare_saved_reports(
                        application.CompareSavedReportsRequest(
                            SYSTEM_ID, _report_id(previous), _report_id(current)
                        )
                    )
                self.assertEqual(
                    caught.exception.failure.code,
                    ApplicationErrorCode.INTEGRITY_FAILURE,
                )

    def test_legacy_compare_reports_delegation_preserves_public_shape(self):
        previous = _report(
            "2026-09-01T00:00:00+00:00", findings=(_finding("finding:gone"),)
        )
        current = _report(
            "2026-09-02T00:00:00+00:00", score=90, findings=(_finding("finding:new"),)
        )
        result = compare_reports(previous, current)
        self.assertEqual(result["trend"], "IMPROVED")
        self.assertEqual(result["new_findings"], current["findings"])
        self.assertEqual(result["resolved_findings"], previous["findings"])

    def test_facade_construction_remains_zero_argument_and_io_free(self):
        with patch(
            "cyberwatchtower.application.reports._default_report_repository"
        ) as repository:
            instance = application.CyberWatchtowerApplication()
        self.assertIsInstance(instance, application.CyberWatchtowerApplication)
        repository.assert_not_called()


if __name__ == "__main__":
    unittest.main()
