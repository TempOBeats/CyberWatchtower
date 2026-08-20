import json
import tempfile
import unittest
from pathlib import Path

from cyberwatchtower.history import load_reports
from cyberwatchtower.models import Finding, Severity
from cyberwatchtower.report_contracts import (
    CURRENT_REPORT_SCHEMA_VERSION,
    LEGACY_REPORT_SCHEMA_VERSION,
    CoverageState,
    LegacyIdentityResolution,
    LegacyIdentityState,
    LegacyLinkPolicy,
    ScanDomain,
    assessment_assurance_summary,
    canonical_report_digest,
    report_assessment_domains,
    normalize_coverage,
    report_schema_version,
)
from cyberwatchtower.reporting import save_json_report
from cyberwatchtower.memory.normalizers import normalize_report


class ReportContractTests(unittest.TestCase):
    def test_legacy_report_without_schema_or_coverage_remains_readable(self):
        legacy = {
            "generated_at": "2026-08-13T00:00:00+00:00",
            "system": {"hostname": "legacy"},
            "security_score": {"score": 100},
            "findings": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "legacy.json").write_text(json.dumps(legacy), encoding="utf-8")
            loaded = load_reports(directory, hostname="legacy")
        self.assertEqual(report_schema_version(loaded[0]), LEGACY_REPORT_SCHEMA_VERSION)
        self.assertNotIn("coverage", loaded[0])

    def test_new_report_serializes_schema_and_conservative_coverage(self):
        results = {
            "system": {"hostname": "host"},
            "score": {"score": 100, "risk_level": "LOW", "counts": {}},
            "findings": [Finding("Info", "Info", Severity.INFO, "None")],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = save_json_report(results, directory)
            report = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(report["schema_version"], CURRENT_REPORT_SCHEMA_VERSION)
        self.assertEqual(
            report["assessment_domains"],
            [
                "firewall_technology",
                "iptables_input_policy",
                "network_socket_inspection",
            ],
        )
        self.assertEqual(
            set(report["coverage"].values()),
            {CoverageState.UNKNOWN.value},
        )
        self.assertEqual(report["assessment_assurance"]["level"], "INCOMPLETE")
        self.assertEqual(len(report["assessment_assurance"]["limitations"]), 3)

    def test_schema_11_without_applicability_keeps_legacy_domains(self):
        report = {"schema_version": "1.1"}
        self.assertEqual(
            tuple(domain.value for domain in report_assessment_domains(report)),
            (
                "firewall_technology",
                "iptables_input_policy",
                "network_socket_inspection",
            ),
        )

    def test_schemas_10_through_12_remain_readable_without_reachability_inference(self):
        base = {
            "generated_at": "2026-08-13T00:00:00+00:00",
            "system": {"hostname": "legacy", "system_id": "system:legacy"},
            "security_score": {
                "score": 90, "risk_level": "LOW", "counts": {"MEDIUM": 1},
            },
            "findings": [{
                "finding_id": "legacy-listener", "title": "Legacy listener",
                "description": "Recorded under its original semantics.",
                "severity": "MEDIUM", "recommendation": "Review it.",
                "evidence": ["Port: 8080"], "confidence": 90,
                "source": "network", "kind": "RISK",
                "assessment_state": "CONFIRMED",
            }],
        }
        reports = []
        for version in ("1.0", "1.1", "1.2"):
            report = json.loads(json.dumps(base))
            report["schema_version"] = version
            if version == "1.2":
                report["assessment_domains"] = ["network_socket_inspection"]
            report["coverage"] = {"network_socket_inspection": "COMPLETE"}
            reports.append(normalize_report(report)[0])
        self.assertEqual([item.schema_version for item in reports], ["1.0", "1.1", "1.2"])
        self.assertTrue(all(
            item.findings[0].assessment_state == "CONFIRMED" for item in reports
        ))

    def test_new_report_network_context_is_closed_and_explicit(self):
        results = {
            "system": {"hostname": "host"},
            "assessment_domains": ["network_socket_inspection", "network_reachability"],
            "coverage": {
                "network_socket_inspection": "COMPLETE",
                "network_reachability": "INCOMPLETE",
            },
            "score": {"score": 90, "risk_level": "LOW", "counts": {"MEDIUM": 1}},
            "findings": [Finding(
                "Bound service", "Bind observed", Severity.MEDIUM, "Review it",
                source="network", network_context={
                    "bind_exposure": "all_interfaces",
                    "bind_epistemic_role": "OBSERVED_FACT",
                    "reachability_state": "POTENTIALLY_REACHABLE",
                    "reachability_epistemic_role": "DETERMINISTIC_DERIVATION",
                    "evidence_basis": ["SOCKET_WILDCARD_BIND"],
                },
            )],
        }
        with tempfile.TemporaryDirectory() as directory:
            report = json.loads(save_json_report(results, directory).read_text())
        normalized, _ = normalize_report(report)
        self.assertEqual(normalized.schema_version, "1.3")
        report["findings"][0]["network_context"]["reachability_state"] = "MODEL_SAYS_SAFE"
        with self.assertRaises(ValueError):
            normalize_report(report)

    def test_assurance_uses_only_explicitly_applicable_domains(self):
        coverage = {
            ScanDomain.FIREWALL_TECHNOLOGY.value: "COMPLETE",
            ScanDomain.FIREWALL_INBOUND_POLICY.value: "COMPLETE",
            ScanDomain.IPTABLES_INPUT_POLICY.value: "UNKNOWN",
        }
        assurance = assessment_assurance_summary(
            coverage,
            (
                ScanDomain.FIREWALL_TECHNOLOGY,
                ScanDomain.FIREWALL_INBOUND_POLICY,
            ),
        )
        self.assertEqual(assurance, {"level": "COMPLETE", "limitations": ()})

    def test_applicable_domain_with_missing_coverage_becomes_unknown(self):
        coverage = normalize_coverage(
            {ScanDomain.FIREWALL_TECHNOLOGY.value: "COMPLETE"},
            (
                ScanDomain.FIREWALL_TECHNOLOGY,
                ScanDomain.FIREWALL_INBOUND_POLICY,
            ),
        )
        self.assertEqual(coverage, {
            "firewall_technology": "COMPLETE",
            "firewall_inbound_policy": "UNKNOWN",
        })
        self.assertEqual(
            assessment_assurance_summary(
                coverage,
                (
                    ScanDomain.FIREWALL_TECHNOLOGY,
                    ScanDomain.FIREWALL_INBOUND_POLICY,
                ),
            )["level"],
            "PARTIAL",
        )

    def test_invalid_applicability_fails_closed(self):
        for value in ([], ["unknown_domain"], ["firewall_technology"] * 2, "network"):
            with self.subTest(value=value), self.assertRaises((TypeError, ValueError)):
                report_assessment_domains({"schema_version": "1.2", "assessment_domains": value})

    def test_coverage_normalization_preserves_valid_states_and_unknowns_invalid(self):
        coverage = normalize_coverage({
            ScanDomain.NETWORK_SOCKET_INSPECTION.value: CoverageState.COMPLETE.value,
            ScanDomain.IPTABLES_INPUT_POLICY.value: "unexpected",
        })
        self.assertEqual(coverage[ScanDomain.NETWORK_SOCKET_INSPECTION.value], "COMPLETE")
        self.assertEqual(coverage[ScanDomain.IPTABLES_INPUT_POLICY.value], "UNKNOWN")

    def test_digest_ignores_key_order_whitespace_and_ingestion_metadata(self):
        first = {
            "system": {"hostname": "host"},
            "findings": [{"title": "Finding", "severity": "LOW"}],
            "_report_path": "/first/report.json",
            "ingested_at": "2026-01-01T00:00:00Z",
        }
        second = json.loads('{ "findings" : [ { "severity":"LOW", "title":"Finding" } ], "system":{"hostname":"host"}, "_report_path":"/other.json", "ingested_at":"later" }')
        self.assertEqual(canonical_report_digest(first), canonical_report_digest(second))

    def test_digest_changes_for_authoritative_content_but_not_finding_identity(self):
        first = {"findings": [{"finding_id": "stable", "severity": "LOW"}]}
        second = {"findings": [{"finding_id": "stable", "severity": "HIGH"}]}
        self.assertNotEqual(canonical_report_digest(first), canonical_report_digest(second))
        self.assertEqual(first["findings"][0]["finding_id"], second["findings"][0]["finding_id"])

    def test_legacy_identity_resolution_is_explicit_typed_data(self):
        resolution = LegacyIdentityResolution(
            LegacyIdentityState.UNRESOLVED,
            None,
            "legacy-host",
            LegacyLinkPolicy.REQUIRE_USER_LINK,
            "Hostname is ambiguous.",
        )
        self.assertEqual(resolution.state, LegacyIdentityState.UNRESOLVED)
        self.assertIsNone(resolution.system_id)


if __name__ == "__main__":
    unittest.main()
