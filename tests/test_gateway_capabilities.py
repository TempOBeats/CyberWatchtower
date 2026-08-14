import unittest

from cyberwatchtower.capabilities.registry import (
    ApprovalRequired,
    CapabilityContext,
    CapabilityDefinition,
    CapabilityDenied,
    CapabilityRegistry,
    CapabilityRequest,
    PermissionClass,
    build_read_only_registry,
)
from cyberwatchtower.model_gateway.deterministic import DeterministicGateway, GatewayIntent


class DeterministicGatewayTests(unittest.TestCase):
    def test_selects_only_bounded_supported_intents(self):
        gateway = DeterministicGateway()
        self.assertEqual(
            gateway.select_intent("Give me my security briefing").intent,
            GatewayIntent.SECURITY_BRIEFING.value,
        )
        self.assertEqual(
            gateway.select_intent("Run rm -rf").intent,
            GatewayIntent.UNSUPPORTED.value,
        )


class CapabilityRegistryTests(unittest.TestCase):
    def test_only_saved_data_capabilities_are_automatic(self):
        registry = build_read_only_registry()
        for name in ("load_reports", "compare_scans", "explain_finding"):
            self.assertEqual(registry.definition(name).permission, PermissionClass.READ_ONLY)
        for name in ("scan_host", "inspect_process", "inspect_service"):
            self.assertEqual(
                registry.definition(name).permission,
                PermissionClass.USER_APPROVAL_REQUIRED,
            )

    def test_fresh_collection_has_no_manufacturable_approval_shortcut(self):
        registry = build_read_only_registry()
        with self.assertRaises(ApprovalRequired):
            registry.execute(
                CapabilityRequest("scan_host", {}),
                CapabilityContext(),
            )

    def test_approval_required_capability_cannot_execute_without_approval(self):
        registry = CapabilityRegistry()
        registry.register(CapabilityDefinition(
            "inspect_process",
            PermissionClass.USER_APPROVAL_REQUIRED,
            lambda request, context: "executed",
        ))
        with self.assertRaises(ApprovalRequired):
            registry.execute(
                CapabilityRequest("inspect_process", {"pid": 1}),
                CapabilityContext(),
            )

    def test_unregistered_shell_capability_is_denied(self):
        with self.assertRaises(CapabilityDenied):
            build_read_only_registry().execute(
                CapabilityRequest("shell", {"command": "id"}),
                CapabilityContext(),
            )


if __name__ == "__main__":
    unittest.main()
