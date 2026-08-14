import tempfile
import unittest

from cyberwatchtower.capabilities.registry import (
    CapabilityDefinition,
    PermissionClass,
    build_read_only_registry,
)
from cyberwatchtower.conversation.session import ConversationSession
from cyberwatchtower.core.grounding import validate_grounding
from cyberwatchtower.core.orchestrator import IntelligenceOrchestrator, OrchestratorState


def _reports():
    finding = {
        "title": "Exposed service",
        "description": "A listener is exposed.",
        "severity": "HIGH",
        "recommendation": "Restrict the listener.",
        "confidence": 95,
        "source": "network",
        "kind": "RISK",
        "assessment_state": "CONFIRMED",
        "evidence": ["Protocol: tcp", "Port: 8080"],
    }
    base = {
        "generated_at": "2026-08-12T00:00:00+00:00",
        "system": {"system_id": "cwt-test", "hostname": "host"},
        "security_score": {"score": 90, "risk_level": "LOW", "counts": {}},
        "findings": [],
    }
    current = {
        **base,
        "generated_at": "2026-08-13T00:00:00+00:00",
        "security_score": {"score": 70, "risk_level": "MEDIUM", "counts": {"HIGH": 1}},
        "findings": [finding],
    }
    return (base, current)


class OrchestratorConversationTests(unittest.TestCase):
    def test_briefing_runs_typed_read_only_state_machine(self):
        result = IntelligenceOrchestrator().handle(
            "Give me my security briefing", reports=_reports()
        )
        self.assertEqual(result.state, OrchestratorState.COMPLETED)
        self.assertIn(OrchestratorState.POLICY_CHECKED, result.states)
        self.assertEqual(
            tuple(item.capability_id for item in result.plan.requests),
            ("load_reports", "compare_scans"),
        )
        self.assertTrue(validate_grounding(result.response).valid)

    def test_pronoun_resolves_to_finding_from_previous_briefing(self):
        session = ConversationSession()
        first = IntelligenceOrchestrator().handle(
            "Give me my security briefing", session=session, reports=_reports()
        )
        session.focus(first.response.finding_ids[0])
        followup = IntelligenceOrchestrator().handle(
            "Why is it dangerous?", session=session, reports=_reports()
        )
        self.assertEqual(followup.response.finding_ids, (session.focused_finding_id,))
        self.assertIn("confirmed", followup.response.sections[0].claims[0].text)

    def test_unresolved_pronoun_requires_clarification(self):
        result = IntelligenceOrchestrator().handle(
            "Why is it dangerous?", reports=_reports()
        )
        self.assertEqual(result.state, OrchestratorState.CLARIFICATION_REQUIRED)

    def test_no_reports_is_safe_deterministic_response(self):
        with tempfile.TemporaryDirectory() as directory:
            result = IntelligenceOrchestrator().handle(
                "Give me my security briefing", report_directory=directory
            )
        self.assertEqual(result.state, OrchestratorState.COMPLETED)
        self.assertIn("No saved", result.response.sections[0].claims[0].text)

    def test_reports_from_different_system_ids_are_not_compared(self):
        first, current = _reports()
        other = {
            **current,
            "generated_at": "2026-08-14T00:00:00+00:00",
            "system": {"system_id": "cwt-other", "hostname": "host"},
            "security_score": {"score": 40, "risk_level": "HIGH", "counts": {}},
            "findings": [],
        }
        result = IntelligenceOrchestrator().handle(
            "Give me my security briefing", reports=(first, current, other)
        )
        changes = next(
            section for section in result.response.sections if section.section_id == "changes"
        )
        self.assertIn("No previous same-host scan", changes.claims[0].text)

    def test_gateway_failure_falls_back_to_deterministic_intent_selection(self):
        class FailingGateway:
            def select_intent(self, request):
                raise RuntimeError("provider unavailable")

        result = IntelligenceOrchestrator(gateway=FailingGateway()).handle(
            "Give me my security briefing", reports=_reports()
        )
        self.assertEqual(result.state, OrchestratorState.COMPLETED)
        self.assertEqual(result.response.intent, "SECURITY_BRIEFING")

    def test_orchestrator_cannot_manufacture_capability_approval(self):
        registry = build_read_only_registry()
        registry = registry.with_overrides(CapabilityDefinition(
            "load_reports",
            PermissionClass.USER_APPROVAL_REQUIRED,
            lambda request, context: (),
        ))
        with self.assertRaises(PermissionError):
            IntelligenceOrchestrator(registry=registry).handle(
                "Give me my security briefing", reports=_reports()
            )


if __name__ == "__main__":
    unittest.main()
