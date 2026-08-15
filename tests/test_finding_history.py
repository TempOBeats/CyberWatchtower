import unittest

from cyberwatchtower.finding_identity import finding_identity
from cyberwatchtower.history import compare_reports
from cyberwatchtower.report_contracts import CoverageState, ScanDomain
from cyberwatchtower.intelligence import analyze_history


class HistoryComparisonTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
