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
