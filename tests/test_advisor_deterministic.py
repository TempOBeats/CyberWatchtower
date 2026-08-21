import copy
import unittest

from cyberwatchtower.advisor.context import build_advisor_context
from cyberwatchtower.advisor.deterministic import build_deterministic_advisory
from cyberwatchtower.models import AssessmentState, FindingKind


def _current_report():
    return {
        "security_score": {
            "score": 70,
            "risk_level": "HIGH",
            "counts": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 2,
                "LOW": 1,
                "INFO": 1,
            },
        },
        "findings": [
            {
                "finding_id": "service-wsdd",
                "title": "WSDD service listening on all interfaces",
                "description": "A UDP service is bound to all interfaces.",
                "severity": "MEDIUM",
                "recommendation": "Restrict WSDD exposure if it is not required.",
                "confidence": 90,
                "source": "network",
                "kind": "RISK",
                "assessment_state": "CONFIRMED",
                "evidence": [
                    "Protocol: udp",
                    "Address: 0.0.0.0",
                    "Port: 3702",
                    "Process: python3",
                    "Application: /usr/bin/wsdd",
                    "Service/Application: WSDD",
                    "Exposure: all interfaces",
                    "Inspection error: token=secret",
                ],
            },
            {
                "finding_id": "socket-gap",
                "title": "Listening-service inspection incomplete",
                "description": "Socket inspection did not complete.",
                "severity": "LOW",
                "recommendation": "Run a complete authorized socket inspection.",
                "confidence": 100,
                "source": "network",
                "kind": "COVERAGE_GAP",
                "assessment_state": "INCOMPLETE",
                "evidence": ["Inspection error: password=secret"],
            },
            {
                "finding_id": "firewall-observation",
                "title": "Firewall technology detected",
                "description": "A firewall tool was detected.",
                "severity": "INFO",
                "recommendation": "Review the active firewall policy.",
                "confidence": 95,
                "source": "firewall",
                "kind": "OBSERVATION",
                "assessment_state": "INFORMATIONAL",
                "evidence": ["Detected tools: nftables"],
            },
        ],
    }


class AdvisorContextTests(unittest.TestCase):
    def test_legacy_finding_is_potential_and_never_confirmed(self):
        report = {
            "security_score": {"score": 95, "risk_level": "LOW", "counts": {}},
            "findings": [
                {
                    "title": "Legacy ambiguous finding",
                    "severity": "LOW",
                    "recommendation": "Verify it.",
                }
            ],
        }

        context = build_advisor_context(report, None, None)

        self.assertEqual(context.findings[0].kind, FindingKind.RISK)
        self.assertEqual(
            context.findings[0].assessment_state,
            AssessmentState.POTENTIAL,
        )
        self.assertTrue(context.findings[0].metadata_inferred)

    def test_legacy_advice_preserves_uncertainty_and_source_recommendation(self):
        source_recommendation = "Verify whether this legacy condition still applies."
        report = {
            "security_score": {"score": 95, "risk_level": "LOW", "counts": {}},
            "findings": [
                {
                    "finding_id": "legacy-risk",
                    "title": "Legacy ambiguous finding",
                    "description": "An older report recorded an ambiguous condition.",
                    "severity": "LOW",
                    "recommendation": source_recommendation,
                    "confidence": 70,
                }
            ],
        }

        context = build_advisor_context(report, None, None)
        advisory = build_deterministic_advisory(context)
        action = advisory.actions[0]

        self.assertEqual(action.assessment_state, AssessmentState.POTENTIAL)
        self.assertEqual(action.action, source_recommendation)
        self.assertIn("may affect", action.rationale)
        self.assertIn("inferred conservatively", action.rationale)
        self.assertIn("not a confirmed finding", action.rationale)
        self.assertNotIn("CyberWatchtower confirmed", action.rationale)

    def test_context_joins_new_and_recurring_state_and_filters_unsafe_evidence(self):
        report = _current_report()
        comparison = {
            "previous_score": 80,
            "change": -10,
            "trend": "DECLINED",
            "new_findings": [report["findings"][0]],
            "resolved_findings": [],
        }
        intelligence = {
            "total_scans": 4,
            "average_score": 82.5,
            "overall_trend": "DECLINED",
            "findings": [
                {"finding_id": "service-wsdd", "occurrences": 3},
            ],
        }

        context = build_advisor_context(report, comparison, intelligence)
        wsdd = context.findings[0]

        self.assertTrue(wsdd.is_new)
        self.assertTrue(wsdd.is_recurring)
        self.assertEqual(wsdd.application_name, "WSDD")
        self.assertNotIn("secret", repr(context))


class DeterministicAdvisorTests(unittest.TestCase):
    def test_actions_group_structurally_equivalent_listener_controls(self):
        report = _current_report()
        first = dict(report["findings"][0])
        first.update({
            "finding_id": "dns-a", "recommendation": "Verify DNS exposure.",
            "network_context": {
                "bind_exposure": "all_interfaces",
                "bind_epistemic_role": "OBSERVED_FACT",
                "reachability_state": "POTENTIALLY_REACHABLE",
                "reachability_epistemic_role": "DETERMINISTIC_DERIVATION",
                "evidence_basis": ["SOCKET_WILDCARD_BIND"],
            },
            "assessment_state": "POTENTIAL",
            "evidence": ["Protocol: udp", "Port: 53", "Process: dns.exe"],
        })
        second = dict(first)
        second.update({
            "finding_id": "dns-b",
            "evidence": ["Protocol: udp", "Port: 5353", "Process: dns.exe"],
        })
        report["findings"] = [first, second]
        before = copy.deepcopy(report)

        advisory = build_deterministic_advisory(
            build_advisor_context(report, None, None)
        )

        self.assertEqual(len(advisory.actions), 1)
        self.assertEqual(advisory.actions[0].finding_ids, ("dns-a", "dns-b"))
        self.assertIn("covers 2 related listener findings", advisory.actions[0].rationale)
        self.assertEqual(report, before)
        self.assertEqual(report["security_score"], before["security_score"])

    def test_unknown_listener_controls_on_different_ports_remain_separate(self):
        report = _current_report()
        template = dict(report["findings"][0])
        template.update({
            "recommendation": "Verify unknown exposure.",
            "network_context": {
                "bind_exposure": "all_interfaces",
                "bind_epistemic_role": "OBSERVED_FACT",
                "reachability_state": "POTENTIALLY_REACHABLE",
                "reachability_epistemic_role": "DETERMINISTIC_DERIVATION",
                "evidence_basis": ["SOCKET_WILDCARD_BIND"],
            },
            "assessment_state": "POTENTIAL",
        })
        first = dict(template, finding_id="unknown-a", evidence=["Protocol: udp", "Port: 1"])
        second = dict(template, finding_id="unknown-b", evidence=["Protocol: udp", "Port: 2"])
        report["findings"] = [first, second]

        advisory = build_deterministic_advisory(
            build_advisor_context(report, None, None)
        )

        self.assertEqual(len(advisory.actions), 2)
    def test_advisory_summarizes_priorities_changes_recurrence_and_coverage(self):
        report = _current_report()
        comparison = {
            "previous_score": 80,
            "change": -10,
            "trend": "DECLINED",
            "new_findings": [report["findings"][0]],
            "resolved_findings": [],
        }
        intelligence = {
            "total_scans": 4,
            "average_score": 82.5,
            "overall_trend": "DECLINED",
            "findings": [
                {"finding_id": "service-wsdd", "occurrences": 3},
            ],
        }
        context = build_advisor_context(report, comparison, intelligence)

        advisory = build_deterministic_advisory(context)

        self.assertIn("70/100", advisory.posture_summary)
        self.assertEqual(advisory.important_finding_ids[0], "service-wsdd")
        self.assertEqual(advisory.actions[0].finding_ids, ("service-wsdd",))
        self.assertIn("Process Intelligence", advisory.actions[0].rationale)
        self.assertIn("DECLINED", advisory.changes_summary)
        self.assertIn("3 scans", advisory.recurring_summary)
        self.assertIn("Listening-service inspection incomplete", advisory.coverage_warnings)
        self.assertLessEqual(len(advisory.next_steps), 3)

    def test_observations_are_not_remediation_actions(self):
        context = build_advisor_context(_current_report(), None, None)

        advisory = build_deterministic_advisory(context)

        action_ids = {
            finding_id
            for action in advisory.actions
            for finding_id in action.finding_ids
        }
        self.assertNotIn("firewall-observation", action_ids)

    def test_resolved_findings_are_not_current_actions(self):
        report = _current_report()
        comparison = {
            "previous_score": 60,
            "change": 10,
            "trend": "IMPROVED",
            "new_findings": [],
            "resolved_findings": [
                {
                    "finding_id": "resolved-risk",
                    "title": "Resolved risk",
                    "severity": "HIGH",
                }
            ],
        }
        context = build_advisor_context(report, comparison, None)

        advisory = build_deterministic_advisory(context)

        self.assertNotIn(
            "resolved-risk",
            {fid for action in advisory.actions for fid in action.finding_ids},
        )


if __name__ == "__main__":
    unittest.main()
