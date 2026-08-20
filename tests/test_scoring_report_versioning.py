import copy
import inspect
import json
import tempfile
import unittest
from pathlib import Path

from cyberwatchtower.history import compare_reports
from cyberwatchtower.intelligence import analyze_history
from cyberwatchtower.memory import open_memory_database
from cyberwatchtower.memory.ingestion import ingest_report
from cyberwatchtower.memory.ingestion_models import (
    IngestionStatus,
    ReportIngestionRequest,
)
from cyberwatchtower.memory.normalizers import normalize_report
from cyberwatchtower.models import AssessmentState, Finding, FindingKind, Severity
from cyberwatchtower.platform import BindExposure
from cyberwatchtower.reachability import RemoteReachabilityState
from cyberwatchtower.reporting import save_json_report
from cyberwatchtower.scoring import calculate_security_score
from cyberwatchtower.scoring_contracts import (
    NetworkScoringIdentity,
    ScoringCategory,
    ScoringFinding,
)
from cyberwatchtower.scoring_v2 import calculate_security_score_v2


def report_finding(finding_id: str = "finding:one") -> dict:
    return {
        "finding_id": finding_id,
        "title": "Deterministic risk",
        "description": "A deterministic condition.",
        "severity": "MEDIUM",
        "recommendation": "Review the condition.",
        "evidence": [],
        "confidence": 100,
        "technique_id": None,
        "source": "firewall_inbound_policy",
        "kind": "RISK",
        "assessment_state": "CONFIRMED",
    }


def raw_report(
    schema_version: str,
    *,
    score: dict | None = None,
    findings: list[dict] | None = None,
) -> dict:
    report = {
        "schema_version": schema_version,
        "generated_at": "2026-08-20T12:00:00+00:00",
        "system": {"system_id": "cwt-test", "hostname": "test-host"},
        "coverage": {"firewall_inbound_policy": "COMPLETE"},
        "security_score": score or {
            "score": 89,
            "risk_level": "MODERATE",
            "counts": {"MEDIUM": 1},
        },
        "findings": findings if findings is not None else [report_finding()],
    }
    if schema_version in {"1.2", "1.3", "1.4"}:
        report["assessment_domains"] = ["firewall_inbound_policy"]
    return report


def serialized_v2_report(*, two_groups: bool = False) -> dict:
    findings = [Finding(
        "Deterministic risk",
        "A deterministic condition.",
        Severity.MEDIUM,
        "Review the condition.",
        finding_id="finding:one",
        source="firewall_inbound_policy",
        kind=FindingKind.RISK,
        assessment_state=AssessmentState.CONFIRMED,
    )]
    scoring_findings = [ScoringFinding(
        "finding:one",
        Severity.MEDIUM,
        FindingKind.RISK,
        AssessmentState.CONFIRMED,
        "firewall_inbound_policy",
        ScoringCategory.FIREWALL_POSTURE,
    )]
    if two_groups:
        findings.append(Finding(
            "Second deterministic risk",
            "Another deterministic condition.",
            Severity.LOW,
            "Review the condition.",
            finding_id="finding:two",
            source="deterministic",
            kind=FindingKind.RISK,
            assessment_state=AssessmentState.POTENTIAL,
        ))
        scoring_findings.append(ScoringFinding(
            "finding:two",
            Severity.LOW,
            FindingKind.RISK,
            AssessmentState.POTENTIAL,
            "deterministic",
            ScoringCategory.OTHER_DETERMINISTIC_RISK,
        ))
    results = {
        "system": {"system_id": "cwt-test", "hostname": "test-host"},
        "assessment_domains": ["firewall_inbound_policy"],
        "coverage": {"firewall_inbound_policy": "COMPLETE"},
        "findings": findings,
        "score": calculate_security_score_v2(tuple(scoring_findings)),
    }
    with tempfile.TemporaryDirectory() as directory:
        path = save_json_report(results, directory)
        return json.loads(path.read_text(encoding="utf-8"))


class ScoringReportContractTests(unittest.TestCase):
    def test_schemas_10_through_13_normalize_as_v1_without_recomputation(self):
        normalized = []
        for version in ("1.0", "1.1", "1.2", "1.3"):
            report = raw_report(version)
            report["security_score"]["score"] = 17
            report["security_score"]["risk_level"] = "LOW"
            result, _ = normalize_report(report)
            normalized.append(result)
        self.assertEqual([item.schema_version for item in normalized], [
            "1.0", "1.1", "1.2", "1.3",
        ])
        self.assertTrue(all(item.score.scoring_version == "1" for item in normalized))
        self.assertTrue(all(item.score.score == 17 for item in normalized))
        self.assertTrue(all(item.score.risk_level == "LOW" for item in normalized))

    def test_legacy_score_field_defaults_remain_unchanged(self):
        legacy = raw_report("1.0", score={"score": 95, "legacy_note": "kept"})
        normalized, _ = normalize_report(legacy)
        self.assertEqual(normalized.score.risk_level, "UNKNOWN")
        structured = raw_report("1.1", score={"score": 95})
        with self.assertRaises(ValueError):
            normalize_report(structured)

    def test_schema_14_v1_is_explicit_and_memory_compatible_without_migration(self):
        report = raw_report("1.4")
        report["security_score"]["scoring_version"] = "1"
        normalized, _ = normalize_report(report)
        self.assertEqual(normalized.score.scoring_version, "1")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "report.json")
            path.write_text(json.dumps(report), encoding="utf-8")
            with open_memory_database(Path(directory, "memory.db")) as database:
                result = ingest_report(database, ReportIngestionRequest(path))
                stored = database.connection.execute(
                    "SELECT score, risk_level FROM score_history"
                ).fetchone()
        self.assertEqual(result.status, IngestionStatus.INGESTED)
        self.assertEqual(tuple(stored), (89, "MODERATE"))

    def test_schema_14_v2_breakdown_is_closed_and_guardrail_explicit(self):
        report = serialized_v2_report()
        normalized, _ = normalize_report(report)
        score = report["security_score"]
        breakdown = score["breakdown"]
        guardrail = breakdown["guardrail"]
        self.assertEqual(normalized.score.scoring_version, "2")
        self.assertEqual((score["score"], score["risk_level"]), (89, "MODERATE"))
        self.assertEqual(breakdown["total_effective_penalty"], 11)
        self.assertEqual(guardrail["category_applied_penalty_total"], 10)
        self.assertEqual(guardrail["additional_guardrail_penalty"], 1)
        self.assertEqual(guardrail["effective_penalty_total"], 11)
        self.assertEqual(guardrail["effective_score_ceiling"], 89)
        self.assertTrue(guardrail["applied"])

    def test_invalid_version_and_malformed_breakdown_fail_closed(self):
        invalid_version = raw_report("1.4")
        invalid_version["security_score"]["scoring_version"] = "model-selected"
        with self.assertRaises(ValueError):
            normalize_report(invalid_version)

        mutations = (
            lambda score: score["breakdown"]["categories"][0].update(
                category="UNKNOWN"
            ),
            lambda score: score["breakdown"]["contributors"][0].update(
                basis_code="MODEL_INTERPRETATION"
            ),
            lambda score: score["breakdown"]["contributors"][0].update(
                raw_penalty=-1
            ),
            lambda score: score["breakdown"]["guardrail"].update(
                additional_guardrail_penalty=0
            ),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                report = serialized_v2_report()
                mutation(report["security_score"])
                with self.assertRaises(ValueError):
                    normalize_report(report)

    def test_duplicate_groups_members_and_unknown_references_fail_closed(self):
        duplicate_group = serialized_v2_report(two_groups=True)
        contributors = duplicate_group["security_score"]["breakdown"]["contributors"]
        contributors[1]["group_id"] = contributors[0]["group_id"]
        with self.assertRaises(ValueError):
            normalize_report(duplicate_group)

        duplicate_member = serialized_v2_report()
        member_ids = duplicate_member["security_score"]["breakdown"]["contributors"][0]["finding_ids"]
        member_ids.append(member_ids[0])
        with self.assertRaises(ValueError):
            normalize_report(duplicate_member)

        unknown_member = serialized_v2_report()
        unknown_member["security_score"]["breakdown"]["contributors"][0]["finding_ids"] = ["finding:absent"]
        with self.assertRaises(ValueError):
            normalize_report(unknown_member)

    def test_breakdown_rejects_private_or_arbitrary_fields(self):
        report = serialized_v2_report()
        breakdown = report["security_score"]["breakdown"]
        serialized = json.dumps(breakdown)
        for prohibited in (
            "address", "port", "pid", "hostname", "machine_id", "path",
            "evidence", "recommendation", "provider", "native_error",
        ):
            self.assertNotIn(prohibited, serialized.casefold())
        breakdown["contributors"][0]["native_error"] = "SECRET_CANARY"
        with self.assertRaises(ValueError):
            normalize_report(report)

    def test_structured_private_scoring_identity_is_not_serialized(self):
        canary = "PRIVATE_APPLICATION_CANARY"
        finding = Finding(
            "Listener", "Bound listener", Severity.MEDIUM, "Review it.",
            finding_id="finding:listener", source="network",
            kind=FindingKind.RISK,
            assessment_state=AssessmentState.POTENTIAL,
        )
        scoring_finding = ScoringFinding(
            "finding:listener", Severity.MEDIUM, FindingKind.RISK,
            AssessmentState.POTENTIAL, "network",
            ScoringCategory.NETWORK_EXPOSURE,
            NetworkScoringIdentity(
                "tcp", 443, BindExposure.ALL_INTERFACES,
                RemoteReachabilityState.POTENTIALLY_REACHABLE,
                application_identity=canary,
            ),
        )
        results = {
            "system": {"system_id": "cwt-test", "hostname": "host"},
            "assessment_domains": ["network_socket_inspection"],
            "coverage": {"network_socket_inspection": "COMPLETE"},
            "findings": [finding],
            "score": calculate_security_score_v2((scoring_finding,)),
        }
        with tempfile.TemporaryDirectory() as directory:
            report = json.loads(
                save_json_report(results, directory).read_text(encoding="utf-8")
            )
        self.assertNotIn(canary, json.dumps(report["security_score"]))

    def test_production_scanner_uses_v2_and_v1_remains_callable(self):
        import cyberwatchtower.scanner as scanner

        scanner_source = inspect.getsource(scanner)
        self.assertNotIn("from .scoring import calculate_security_score", scanner_source)
        self.assertIn("from .scoring_v2 import calculate_security_score_v2", scanner_source)
        legacy = calculate_security_score([])
        v2 = calculate_security_score_v2(())
        self.assertEqual(legacy["score"], 100)
        self.assertEqual(v2.score, 100)


class ScoringVersionHistoryTests(unittest.TestCase):
    def report(self, score: int, version: str | None, findings=None) -> dict:
        security_score = {
            "score": score,
            "risk_level": "LOW",
            "counts": {},
        }
        if version is not None:
            security_score["scoring_version"] = version
        return {
            "generated_at": "2026-08-20T12:00:00+00:00",
            "security_score": security_score,
            "coverage": {"network_socket_inspection": "COMPLETE"},
            "findings": findings or [],
        }

    def test_same_version_comparison_keeps_exact_numeric_semantics(self):
        comparison = compare_reports(self.report(70, "2"), self.report(90, "2"))
        self.assertEqual(comparison["change"], 20)
        self.assertEqual(comparison["trend"], "IMPROVED")
        self.assertFalse(comparison["scoring_methodology_changed"])

    def test_both_cross_version_directions_are_methodology_transitions(self):
        for previous, current in (("1", "2"), ("2", "1"), (None, "2")):
            with self.subTest(previous=previous, current=current):
                comparison = compare_reports(
                    self.report(0, previous), self.report(82, current)
                )
                self.assertIsNone(comparison["change"])
                self.assertEqual(
                    comparison["trend"], "SCORING_VERSION_CHANGED"
                )
                self.assertTrue(comparison["scoring_methodology_changed"])

    def test_scoring_transition_does_not_interrupt_finding_continuity(self):
        finding = report_finding("finding:stable")
        comparison = compare_reports(
            self.report(0, "1", [finding]),
            self.report(89, "2", [copy.deepcopy(finding)]),
        )
        self.assertEqual(comparison["new_findings"], [])
        self.assertEqual(comparison["resolved_findings"], [])
        self.assertEqual(comparison["uncertain_findings"], [])

    def test_mixed_versions_are_segmented_and_not_averaged(self):
        stable_finding = report_finding("finding:stable")
        reports = [
            self.report(0, None, [copy.deepcopy(stable_finding)]),
            self.report(20, "1", [copy.deepcopy(stable_finding)]),
            self.report(82, "2", [copy.deepcopy(stable_finding)]),
            self.report(90, "2", [copy.deepcopy(stable_finding)]),
        ]
        intelligence = analyze_history(reports)
        self.assertIsNone(intelligence["average_score"])
        self.assertIsNone(intelligence["best_score"])
        self.assertIsNone(intelligence["worst_score"])
        self.assertIsNone(intelligence["overall_change"])
        self.assertEqual(
            intelligence["overall_trend"], "SCORING_VERSION_CHANGED"
        )
        self.assertTrue(intelligence["mixed_scoring_versions"])
        self.assertEqual(
            intelligence["score_series_by_version"]["1"]["average_score"],
            10,
        )
        self.assertEqual(
            intelligence["score_series_by_version"]["2"]["average_score"],
            86,
        )
        self.assertEqual(len(intelligence["findings"]), 1)
        self.assertEqual(intelligence["findings"][0]["occurrences"], 4)


if __name__ == "__main__":
    unittest.main()
