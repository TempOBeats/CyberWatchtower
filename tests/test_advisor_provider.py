import unittest
from dataclasses import fields

from cyberwatchtower.advisor.context import build_advisor_context
from cyberwatchtower.advisor.providers.base import (
    ProviderEmphasis,
    ProviderSelection,
)
from cyberwatchtower.advisor.service import build_provider_request, generate_advisory
from cyberwatchtower.advisor.deterministic import build_deterministic_advisory


def _context():
    report = {
        "system": {"hostname": "secret-host", "username": "secret-user"},
        "security_score": {"score": 75, "risk_level": "MODERATE", "counts": {}},
        "findings": [
            {
                "finding_id": "first",
                "title": "First risk",
                "description": "Risk one",
                "severity": "HIGH",
                "recommendation": "Fix first.",
                "kind": "RISK",
                "assessment_state": "CONFIRMED",
                "evidence": ["Inspection error: api_key=secret", "Port: 22"],
            },
            {
                "finding_id": "second",
                "title": "Second risk",
                "description": "Risk two",
                "severity": "MEDIUM",
                "recommendation": "Fix second.",
                "kind": "RISK",
                "assessment_state": "CONFIRMED",
                "evidence": ["Application: /private/internal/server.py"],
            },
        ],
    }
    return build_advisor_context(report, None, None)


class SelectingProvider:
    name = "fake"

    def __init__(self, selection):
        self.selection = selection
        self.request = None

    def select(self, request):
        self.request = request
        return self.selection


class FailingProvider:
    name = "failing"

    def select(self, request):
        raise RuntimeError("provider unavailable with api_key=secret")


class MalformedProvider:
    name = "malformed"

    def select(self, request):
        return {"finding_ids": ["first"], "prose": "Run a shell command"}


class ProviderBoundaryTests(unittest.TestCase):
    def test_provider_contract_has_no_authoritative_prose_fields(self):
        selection_fields = {field.name for field in fields(ProviderSelection)}

        self.assertEqual(selection_fields, {"finding_ids", "action_ids", "emphasis"})

    def test_provider_payload_excludes_system_identity_evidence_and_actions(self):
        context = _context()
        request = build_provider_request(
            context,
            build_deterministic_advisory(context),
        )

        rendered = repr(request)
        self.assertNotIn("secret-host", rendered)
        self.assertNotIn("secret-user", rendered)
        self.assertNotIn("api_key", rendered)
        self.assertNotIn("Fix first", rendered)
        self.assertNotIn("/private/internal", rendered)

    def test_valid_provider_can_only_reorder_known_records(self):
        context = _context()
        deterministic = build_deterministic_advisory(context)
        second_action = next(
            action.action_id
            for action in deterministic.actions
            if action.finding_ids == ("second",)
        )
        provider = SelectingProvider(
            ProviderSelection(
                finding_ids=("second",),
                action_ids=(second_action,),
                emphasis=ProviderEmphasis.RECENT_CHANGES,
            )
        )

        result = generate_advisory(context, provider)

        self.assertEqual(result.mode, "provider:fake")
        self.assertEqual(result.important_finding_ids[0], "second")
        self.assertEqual(result.actions[0].finding_ids, ("second",))
        self.assertEqual(
            {action.action for action in result.actions},
            {action.action for action in deterministic.actions},
        )

    def test_unknown_ids_reject_entire_provider_selection(self):
        context = _context()
        provider = SelectingProvider(
            ProviderSelection(
                finding_ids=("invented-finding",),
                action_ids=(),
            )
        )

        result = generate_advisory(context, provider)

        self.assertEqual(result.mode, "deterministic")
        self.assertIn("invalid selection", result.provider_warning)

    def test_duplicate_ids_are_rejected(self):
        context = _context()
        provider = SelectingProvider(
            ProviderSelection(
                finding_ids=("first", "first"),
                action_ids=(),
            )
        )

        result = generate_advisory(context, provider)

        self.assertEqual(result.mode, "deterministic")

    def test_non_tuple_id_collections_are_rejected(self):
        context = _context()
        provider = SelectingProvider(
            ProviderSelection(
                finding_ids=["first"],
                action_ids=(),
            )
        )

        result = generate_advisory(context, provider)

        self.assertEqual(result.mode, "deterministic")

    def test_provider_exception_uses_complete_deterministic_fallback(self):
        context = _context()
        expected = build_deterministic_advisory(context)

        result = generate_advisory(context, FailingProvider())

        self.assertEqual(result.mode, "deterministic")
        self.assertEqual(result.actions, expected.actions)
        self.assertNotIn("secret", result.provider_warning)

    def test_malformed_provider_response_is_rejected(self):
        context = _context()

        result = generate_advisory(context, MalformedProvider())

        self.assertEqual(result.mode, "deterministic")
        self.assertIn("invalid selection", result.provider_warning)
        self.assertNotIn("shell command", repr(result))


if __name__ == "__main__":
    unittest.main()
