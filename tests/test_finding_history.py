import unittest
from unittest.mock import patch

from cyberwatchtower.finding_identity import finding_identity
from cyberwatchtower.history import compare_reports
from cyberwatchtower.report_contracts import CoverageState, ScanDomain
from cyberwatchtower.intelligence import analyze_history


class HistoryComparisonTests(unittest.TestCase):
    def test_comparison_preserves_authoritative_source_schema_versions(self):
        previous = {
            "schema_version": "1.5",
            "security_score": {"score": 90},
            "findings": [{
                "title": "Resolved", "source": "network", "evidence": [],
            }],
        }
        current = {
            "schema_version": "1.6",
            "security_score": {"score": 90},
            "coverage": {"network_socket_inspection": "COMPLETE"},
            "findings": [{
                "title": "New", "source": "network", "evidence": [],
            }],
        }

        comparison = compare_reports(previous, current)

        self.assertEqual(comparison["previous_report_schema_version"], "1.5")
        self.assertEqual(comparison["current_report_schema_version"], "1.6")
        self.assertEqual(comparison["new_findings"][0]["title"], "New")
        self.assertEqual(comparison["resolved_findings"][0]["title"], "Resolved")

    def test_uncertain_findings_retain_previous_report_side_provenance(self):
        previous_finding = {
            "title": "Uncertain", "source": "network", "evidence": [],
        }
        previous = {
            "schema_version": "1.5",
            "security_score": {"score": 90},
            "findings": [previous_finding],
        }
        current = {
            "schema_version": "1.6",
            "security_score": {"score": 90},
            "coverage": {"network_socket_inspection": "INCOMPLETE"},
            "findings": [],
        }

        comparison = compare_reports(previous, current)

        self.assertEqual(comparison["previous_report_schema_version"], "1.5")
        self.assertEqual(comparison["current_report_schema_version"], "1.6")
        self.assertEqual(comparison["uncertain_findings"], [previous_finding])
        self.assertIs(comparison["uncertain_findings"][0], previous_finding)

    def test_absent_finding_resolves_only_with_complete_relevant_coverage(self):
        finding = {
            "title": "Exposed service", "severity": "HIGH", "source": "network",
            "evidence": ["Protocol: tcp", "Port: 443"],
        }
        previous = {"security_score": {"score": 80}, "findings": [finding]}
        for state, resolved, uncertain in (
            (CoverageState.COMPLETE, 1, 0),
            (CoverageState.INCOMPLETE, 0, 1),
            (CoverageState.UNKNOWN, 0, 1),
        ):
            with self.subTest(coverage=state.value):
                current = {
                    "security_score": {"score": 100},
                    "coverage": {
                        ScanDomain.NETWORK_SOCKET_INSPECTION.value: state.value,
                    },
                    "findings": [],
                }
                comparison = compare_reports(previous, current)
                self.assertEqual(len(comparison["resolved_findings"]), resolved)
                self.assertEqual(len(comparison["uncertain_findings"]), uncertain)

    def test_reappearance_after_uncertain_disappearance_is_not_a_resolution(self):
        finding = {
            "title": "Exposed service", "severity": "HIGH", "source": "network",
            "evidence": ["Protocol: tcp", "Port: 443"],
        }
        missing = {
            "security_score": {"score": 100},
            "coverage": {ScanDomain.NETWORK_SOCKET_INSPECTION.value: "INCOMPLETE"},
            "findings": [],
        }
        present = {
            "security_score": {"score": 80},
            "coverage": {ScanDomain.NETWORK_SOCKET_INSPECTION.value: "COMPLETE"},
            "findings": [finding],
        }
        uncertain = compare_reports(present, missing)
        reappeared = compare_reports(missing, present)
        self.assertFalse(uncertain["resolved_findings"])
        self.assertTrue(uncertain["uncertain_findings"])
        self.assertNotIn("reopened_findings", reappeared)

    def test_platform_firewall_source_uses_only_inbound_policy_coverage(self):
        finding = {
            "title": "Inbound firewall policy is permissive",
            "severity": "MEDIUM",
            "source": "firewall_inbound_policy",
            "evidence": [],
        }
        previous = {"security_score": {"score": 90}, "findings": [finding]}
        base = {
            "schema_version": "1.2",
            "assessment_domains": ["firewall_inbound_policy"],
            "security_score": {"score": 100},
            "findings": [],
        }
        for state, resolved in (("COMPLETE", True), ("INCOMPLETE", False), ("UNKNOWN", False)):
            with self.subTest(state=state):
                current = {**base, "coverage": {
                    "firewall_inbound_policy": state,
                    "iptables_input_policy": "COMPLETE",
                }}
                comparison = compare_reports(previous, current)
                self.assertEqual(bool(comparison["resolved_findings"]), resolved)
                self.assertEqual(bool(comparison["uncertain_findings"]), not resolved)
    def test_distinct_unknown_services_are_not_collapsed_by_title(self):
        previous = {
            "security_score": {"score": 90},
            "findings": [
                {
                    "title": "Unknown service listening on all interfaces",
                    "severity": "MEDIUM",
                    "source": "network",
                    "evidence": ["Protocol: tcp", "Port: 1111"],
                },
                {
                    "title": "Unknown service listening on all interfaces",
                    "severity": "MEDIUM",
                    "source": "network",
                    "evidence": ["Protocol: tcp", "Port: 2222"],
                },
            ],
        }
        current = {
            "security_score": {"score": 90},
            "coverage": {ScanDomain.NETWORK_SOCKET_INSPECTION.value: "COMPLETE"},
            "findings": [
                {
                    "title": "Unknown service listening on all interfaces",
                    "severity": "MEDIUM",
                    "source": "network",
                    "evidence": ["Protocol: tcp", "Port: 3333"],
                }
            ],
        }

        comparison = compare_reports(previous, current)

        self.assertEqual(len(comparison["new_findings"]), 1)
        self.assertEqual(len(comparison["resolved_findings"]), 2)

    def test_identity_uses_application_when_present(self):
        base = {
            "title": "Unknown service listening on all interfaces",
            "evidence": [
                "Protocol: udp",
                "Address: 0.0.0.0",
                "Port: 3702",
                "Process: python3",
            ],
        }
        with_application = {
            **base,
            "evidence": [*base["evidence"], "Application: /usr/bin/wsdd"],
        }

        self.assertNotEqual(
            finding_identity(base),
            finding_identity(with_application),
        )

    def test_intelligence_tracks_same_title_services_separately(self):
        report = {
            "generated_at": "2026-08-13T12:00:00+00:00",
            "security_score": {"score": 80},
            "findings": [
                {
                    "title": "Unknown service listening on all interfaces",
                    "severity": "MEDIUM",
                    "evidence": ["Protocol: tcp", "Port: 1111"],
                },
                {
                    "title": "Unknown service listening on all interfaces",
                    "severity": "MEDIUM",
                    "evidence": ["Protocol: tcp", "Port: 2222"],
                },
            ],
        }

        result = analyze_history([report])

        self.assertEqual(len(result["findings"]), 2)

    def test_intelligence_uses_each_source_report_schema_for_grouping(self):
        reports = [
            {
                "schema_version": version,
                "generated_at": f"2026-08-{day:02d}T12:00:00+00:00",
                "security_score": {"score": 80},
                "findings": [{
                    "title": "Listener",
                    "severity": "MEDIUM",
                    "evidence": ["Protocol: tcp", "Port: 8080"],
                }],
            }
            for day, version in ((13, "1.5"), (14, "1.6"))
        ]

        with patch(
            "cyberwatchtower.intelligence.report_listener_group_id",
            return_value="presentation:stable",
        ) as group_id:
            result = analyze_history(reports)

        self.assertEqual(
            [call.kwargs["report_schema_version"] for call in group_id.call_args_list],
            ["1.5", "1.6"],
        )
        self.assertEqual(
            result["findings"][0]["presentation_group_id"],
            "presentation:stable",
        )


if __name__ == "__main__":
    unittest.main()
