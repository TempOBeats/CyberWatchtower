import unittest

from cyberwatchtower.briefing.builder import build_security_briefing
from cyberwatchtower.briefing.rendering import render_grounded_response
from cyberwatchtower.core.grounding import validate_grounding


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


if __name__ == "__main__":
    unittest.main()
