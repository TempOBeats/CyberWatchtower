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
    canonical_report_digest,
    normalize_coverage,
    report_schema_version,
)
from cyberwatchtower.reporting import save_json_report


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
            set(report["coverage"].values()),
            {CoverageState.UNKNOWN.value},
        )

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
