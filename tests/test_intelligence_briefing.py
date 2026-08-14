import unittest

from cyberwatchtower.briefing.builder import build_security_briefing
from cyberwatchtower.briefing.rendering import render_grounded_response
from cyberwatchtower.core.grounding import validate_grounding
from cyberwatchtower.history import compare_reports


def _report():
    return {
        "system": {"hostname": "host", "system_id": "cwt-test"},
        "security_score": {"score": 70, "risk_level": "MEDIUM", "counts": {"HIGH": 1}},
        "findings": [{
            "title": "Exposed service",
            "description": "A listener is exposed.",
            "severity": "HIGH",
            "recommendation": "Restrict the listener.",
            "confidence": 95,
            "source": "network",
            "kind": "RISK",
            "assessment_state": "CONFIRMED",
            "evidence": ["Protocol: tcp", "Port: 8080", "Process: python3", "Service/Application: WSDD"],
        }],
    }


class SecurityBriefingTests(unittest.TestCase):
    def test_incomplete_coverage_is_separate_from_score_and_never_full_assurance(self):
        report = _report()
        report["security_score"] = {"score": 100, "risk_level": "LOW", "counts": {}}
        report["findings"] = []
        report["coverage"] = {
            "firewall_technology": "COMPLETE",
            "iptables_input_policy": "INCOMPLETE",
            "network_socket_inspection": "COMPLETE",
        }
        report["assessment_assurance"] = {"level": "COMPLETE", "limitations": []}
        briefing = build_security_briefing(report, None, None)
        rendered = render_grounded_response(briefing.response)
        self.assertIn("100/100", rendered)
        self.assertIn("Assessment assurance is PARTIAL", rendered)
        self.assertIn("iptables INPUT policy was not completely assessed", rendered)
    def test_briefing_reuses_advisor_and_is_grounded(self):
        briefing = build_security_briefing(_report(), None, None)
        self.assertTrue(validate_grounding(briefing.response).valid)
        rendered = render_grounded_response(briefing.response)
        self.assertIn("Exposed service", rendered)
        self.assertIn("Process Intelligence attributed the WSDD application", rendered)

    def test_legacy_uncertainty_is_explicit_in_structured_briefing(self):
        report = _report()
        report["findings"][0].pop("kind")
        report["findings"][0].pop("assessment_state")
        briefing = build_security_briefing(report, None, None)
        rendered = render_grounded_response(briefing.response)
        self.assertIn("POTENTIAL", rendered)
        self.assertIn("not confirmed", rendered)
        self.assertNotIn("confirmed the Exposed service condition", rendered)

    def test_briefing_and_changed_answer_do_not_claim_uncertain_resolution(self):
        previous = _report()
        current = _report()
        current["security_score"] = {"score": 100, "risk_level": "LOW", "counts": {}}
        current["coverage"] = {"network_socket_inspection": "INCOMPLETE"}
        current["findings"] = []
        comparison = compare_reports(previous, current)
        briefing = build_security_briefing(current, comparison, None)
        rendered = render_grounded_response(briefing.response)
        self.assertIn("Disappearance uncertain", rendered)
        self.assertNotIn("Resolved: Exposed service", rendered)


if __name__ == "__main__":
    unittest.main()
