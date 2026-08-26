import dataclasses
import inspect
import unittest

from cyberwatchtower.platform.windows import (
    APPROVED_FIREWALL_PROPERTY_GETTERS,
    APPROVED_PROPERTY_GETTER_COUNT,
    MAX_PROPERTY_GETTERS_PER_RULE,
    RESERVED_PROPERTY_GETTER_CAPACITY,
    WINDOWS_FIREWALL_COM_INIT_FLAGS,
    WINDOWS_FIREWALL_COM_METHODS,
    WindowsComCleanupStack,
    WindowsComContractError,
    WindowsComFailureCategory,
    WindowsComInitializationLease,
    WindowsComInitializationResult,
    WindowsComMethodKind,
    WindowsComOperationAccounting,
    WindowsComResourceKind,
    WindowsFirewallPropertyGetter,
    WindowsFirewallRuleInterfacePlan,
    WindowsOwnedBstr,
    WindowsOwnedVariant,
    WindowsSafeArrayElementType,
    WindowsSafeArrayValue,
    WindowsVariantType,
)
from cyberwatchtower.platform.windows import firewall_com_contracts as contracts


class WindowsFirewallComAbiTests(unittest.TestCase):
    def test_fixed_guids_and_com_initialization_flags(self):
        self.assertEqual(
            contracts.CLSID_NET_FW_POLICY2,
            "e2b3c97f-6ae1-41ac-817a-f6f92166d7dd",
        )
        self.assertEqual(
            contracts.IID_INET_FW_POLICY2,
            "98325047-c671-4174-8d81-defcd3f03186",
        )
        self.assertEqual(
            {
                contracts.IID_IUNKNOWN, contracts.IID_IENUMVARIANT,
                contracts.IID_INET_FW_RULES, contracts.IID_INET_FW_RULE,
                contracts.IID_INET_FW_RULE2, contracts.IID_INET_FW_RULE3,
            },
            {
                "00000000-0000-0000-c000-000000000046",
                "00020404-0000-0000-c000-000000000046",
                "9c4c6277-5027-441e-afae-ca1f542da009",
                "af230d27-baba-4e42-aced-f524f22cfce2",
                "9c27c8da-189b-4dde-89f7-8b39a316782c",
                "b21563ff-d696-4222-ab46-4e89b73ab34a",
            },
        )
        self.assertEqual(WINDOWS_FIREWALL_COM_INIT_FLAGS, 0x6)

    def test_vtable_is_fixed_read_only_and_contains_no_dispatch_surface(self):
        methods = {(item.interface.value, item.name, item.vtable_index)
                   for item in WINDOWS_FIREWALL_COM_METHODS}
        self.assertIn(("INET_FW_POLICY2", "get_Rules", 18), methods)
        self.assertIn(("INET_FW_RULES", "get_Count", 7), methods)
        self.assertIn(("INET_FW_RULES", "get__NewEnum", 11), methods)
        self.assertIn(("IENUMVARIANT", "Next", 3), methods)
        exposed = {item.name for item in WINDOWS_FIREWALL_COM_METHODS}
        self.assertTrue({"QueryInterface", "AddRef", "Release"} <= exposed)
        self.assertFalse(set(contracts.PROHIBITED_FIREWALL_COM_MEMBERS) & exposed)
        self.assertFalse(any(name.startswith("put_") for name in exposed))
        with self.assertRaises(ValueError):
            contracts.WindowsComMethod(
                contracts.WindowsComInterface.RULE,
                "get_Name",
                7,
                WindowsComMethodKind.PROPERTY_GETTER,
            )

    def test_exact_getter_allowlist_has_one_reserved_but_unusable_budget_slot(self):
        getters = tuple(
            method.name for method in WINDOWS_FIREWALL_COM_METHODS
            if method.kind == WindowsComMethodKind.PROPERTY_GETTER
        )
        self.assertEqual(
            getters, tuple(value.value for value in WindowsFirewallPropertyGetter)
        )
        self.assertEqual(APPROVED_FIREWALL_PROPERTY_GETTERS,
                         tuple(WindowsFirewallPropertyGetter))
        self.assertEqual(APPROVED_PROPERTY_GETTER_COUNT, 21)
        self.assertEqual(MAX_PROPERTY_GETTERS_PER_RULE, 22)
        self.assertEqual(RESERVED_PROPERTY_GETTER_CAPACITY, 1)
        self.assertNotIn("get_LocalUserOwner", getters)
        with self.assertRaises(WindowsComContractError):
            WindowsComOperationAccounting().record_property_getter("get_Name")

    def test_rule2_fallback_and_rule3_presence_plans_are_closed(self):
        full = WindowsFirewallRuleInterfacePlan(True, True)
        fallback = WindowsFirewallRuleInterfacePlan(False, False)
        self.assertEqual(
            full.edge_getter,
            WindowsFirewallPropertyGetter.EDGE_TRAVERSAL_OPTIONS,
        )
        self.assertEqual(
            fallback.edge_getter, WindowsFirewallPropertyGetter.EDGE_TRAVERSAL
        )
        self.assertEqual(len(full.rule3_presence_getters), 5)
        self.assertEqual(fallback.rule3_presence_getters, ())
        self.assertTrue(full.rule3_predicates_decidable)
        self.assertFalse(fallback.rule3_predicates_decidable)
        with self.assertRaises(TypeError):
            WindowsFirewallRuleInterfacePlan(1, False)


class WindowsFirewallComOwnershipTests(unittest.TestCase):
    def test_successful_initialization_results_own_exactly_one_uninitialize(self):
        for result in (
            WindowsComInitializationResult.S_OK,
            WindowsComInitializationResult.S_FALSE,
        ):
            calls = []
            lease = WindowsComInitializationLease(result, lambda: calls.append("u"))
            lease.close()
            lease.close()
            self.assertEqual(calls, ["u"])

    def test_failed_initialization_never_uninitializes_and_is_sanitized(self):
        for result, category in (
            (WindowsComInitializationResult.RPC_E_CHANGED_MODE,
             WindowsComFailureCategory.INTERNAL_ERROR),
            (WindowsComInitializationResult.FAILURE,
             WindowsComFailureCategory.INTERNAL_ERROR),
        ):
            calls = []
            with self.assertRaises(WindowsComContractError) as caught:
                WindowsComInitializationLease(result, lambda: calls.append("u"))
            self.assertEqual(caught.exception.category, category)
            self.assertEqual(calls, [])
            self.assertNotIn("SECRET_NATIVE_ERROR", repr(caught.exception))

    def test_interfaces_release_once_in_reverse_acquisition_order(self):
        released = []
        stack = WindowsComCleanupStack()
        for kind in (
            WindowsComResourceKind.POLICY2,
            WindowsComResourceKind.RULES,
            WindowsComResourceKind.NEW_ENUM_UNKNOWN,
            WindowsComResourceKind.ENUMVARIANT,
            WindowsComResourceKind.RULE,
            WindowsComResourceKind.RULE2,
            WindowsComResourceKind.RULE3,
        ):
            stack.own(kind, lambda value=kind: released.append(value))
        stack.close()
        stack.close()
        self.assertEqual(released, list(reversed((
            WindowsComResourceKind.POLICY2,
            WindowsComResourceKind.RULES,
            WindowsComResourceKind.NEW_ENUM_UNKNOWN,
            WindowsComResourceKind.ENUMVARIANT,
            WindowsComResourceKind.RULE,
            WindowsComResourceKind.RULE2,
            WindowsComResourceKind.RULE3,
        ))))

    def test_cleanup_continues_after_release_failure_without_native_text(self):
        released = []
        stack = WindowsComCleanupStack()
        stack.own(WindowsComResourceKind.POLICY2,
                  lambda: released.append("policy"))

        def failing_release():
            released.append("rule")
            raise RuntimeError("SECRET_RELEASE_FAILURE")

        stack.own(WindowsComResourceKind.RULE, failing_release)
        with self.assertRaises(WindowsComContractError) as caught:
            stack.close()
        self.assertEqual(released, ["rule", "policy"])
        self.assertNotIn("SECRET_RELEASE_FAILURE", str(caught.exception))

    def test_bstr_is_redacted_copied_and_freed_on_success_or_validation_failure(self):
        secret = "PRIVATE_PATH_CANARY"
        freed = []
        with WindowsOwnedBstr(secret, lambda: freed.append("success")) as value:
            self.assertEqual(value.copy_bounded(64), secret)
            self.assertNotIn(secret, repr(value))
        with self.assertRaises(WindowsComContractError):
            with WindowsOwnedBstr(secret, lambda: freed.append("failure")) as value:
                value.copy_bounded(2)
        self.assertEqual(freed, ["success", "failure"])

    def test_direct_cleanup_failures_are_sanitized(self):
        def fail():
            raise RuntimeError("SECRET_NATIVE_CLEANUP")

        resources = (
            WindowsComInitializationLease(WindowsComInitializationResult.S_OK, fail),
            WindowsOwnedBstr("PRIVATE", fail),
            WindowsOwnedVariant(
                WindowsVariantType.I4, 1, lambda: None, fail
            ),
        )
        for resource in resources:
            with self.subTest(resource=type(resource).__name__):
                with self.assertRaises(WindowsComContractError) as caught:
                    resource.close()
                self.assertEqual(
                    caught.exception.category,
                    WindowsComFailureCategory.INTERNAL_ERROR,
                )
                self.assertNotIn("SECRET_NATIVE_CLEANUP", str(caught.exception))

    def test_variant_is_initialized_and_cleared_for_valid_and_malformed_values(self):
        events = []
        with WindowsOwnedVariant(
            WindowsVariantType.DISPATCH, object(),
            lambda: events.append("init-valid"),
            lambda: events.append("clear-valid"),
        ) as value:
            self.assertIsNotNone(value.extract(WindowsVariantType.DISPATCH))
        with self.assertRaises(WindowsComContractError):
            with WindowsOwnedVariant(
                WindowsVariantType.BY_REFERENCE, "PRIVATE_VARIANT_CANARY",
                lambda: events.append("init-invalid"),
                lambda: events.append("clear-invalid"),
            ) as value:
                value.extract(WindowsVariantType.BSTR)
        self.assertEqual(events, [
            "init-valid", "clear-valid", "init-invalid", "clear-invalid",
        ])

    def test_safearray_uses_variant_ownership_and_clears_exactly_once(self):
        events = []
        value = WindowsOwnedVariant(
            WindowsVariantType.ARRAY_VARIANT,
            WindowsSafeArrayValue(
                1, WindowsSafeArrayElementType.VARIANT, ("LAN", "Wireless")
            ),
            lambda: events.append("init"), lambda: events.append("clear"),
        )
        self.assertEqual(value.extract_safearray(), ("LAN", "Wireless"))
        value.close()
        value.close()
        self.assertEqual(events, ["init", "clear"])
        with self.assertRaises(WindowsComContractError):
            with WindowsOwnedVariant(
                WindowsVariantType.ARRAY_VARIANT, (object(),),
                lambda: None, lambda: events.append("malformed-clear"),
            ) as malformed:
                malformed.extract_safearray()
        self.assertEqual(events[-1], "malformed-clear")
        for dimensions, element_type, values in (
            (2, WindowsSafeArrayElementType.VARIANT, ("LAN",)),
            (1, "ARBITRARY", ("LAN",)),
            (1, WindowsSafeArrayElementType.BSTR, (object(),)),
        ):
            with self.subTest(dimensions=dimensions, element_type=element_type):
                with self.assertRaises((TypeError, WindowsComContractError)):
                    WindowsSafeArrayValue(dimensions, element_type, values)


class WindowsFirewallComAccountingAndAuthorityTests(unittest.TestCase):
    def test_operation_classes_are_accounted_independently(self):
        ledger = WindowsComOperationAccounting()
        for _ in range(MAX_PROPERTY_GETTERS_PER_RULE):
            ledger.record_property_getter(WindowsFirewallPropertyGetter.ENABLED)
        ledger.record_query_interface()
        ledger.record_enumeration()
        ledger.record_release()
        ledger.record_initialization()
        ledger.record_cleanup()
        self.assertEqual(dataclasses.asdict(ledger), {
            "property_getters": 22,
            "query_interfaces": 1,
            "enumeration_operations": 1,
            "interface_releases": 1,
            "initialization_operations": 1,
            "cleanup_operations": 1,
        })
        with self.assertRaises(WindowsComContractError) as caught:
            ledger.record_property_getter(WindowsFirewallPropertyGetter.ACTION)
        self.assertEqual(
            caught.exception.category, WindowsComFailureCategory.LIMIT_EXCEEDED
        )

    def test_failure_contract_is_closed_and_contains_no_native_diagnostics(self):
        self.assertEqual(
            {value.value for value in WindowsComFailureCategory},
            {
                "API_UNAVAILABLE", "ACCESS_DENIED", "COLLECTION_INCOMPLETE",
                "LIMIT_EXCEEDED", "INVALID_RESULT", "TIMEOUT", "UNSUPPORTED",
                "INTERNAL_ERROR",
            },
        )
        error = WindowsComContractError(WindowsComFailureCategory.ACCESS_DENIED)
        self.assertEqual(str(error), "ACCESS_DENIED")
        self.assertFalse(hasattr(error, "hresult"))
        self.assertFalse(hasattr(error, "message"))

    def test_contract_module_is_portable_and_has_no_native_or_execution_surface(self):
        source = inspect.getsource(contracts).casefold()
        for marker in (
            "ctypes", "windll", "cocreateinstance(", "subprocess", "shell=true",
            "powershell", "netsh", "winreg", "socket.socket",
        ):
            with self.subTest(marker=marker):
                self.assertNotIn(marker, source)
        self.assertNotIn("collect_firewall_rules", source)

    def test_phase_has_no_production_routing_or_authority_expansion(self):
        from pathlib import Path

        package = Path(__file__).parents[1] / "src" / "cyberwatchtower"
        for relative in (
            "scanner.py", "platform/windows/api_native.py",
            "platform/windows/adapter.py", "scoring_v2.py", "reporting.py",
        ):
            source = (package / relative).read_text(encoding="utf-8")
            self.assertNotIn("firewall_com_contracts", source)
        changed_source = inspect.getsource(contracts).casefold()
        for marker in (
            "subprocess", "shell", "powershell", "netsh", "winreg",
            "socket", "requests", "urlopen", "cocreateinstance(",
        ):
            with self.subTest(marker=marker):
                self.assertNotIn(marker, changed_source)


if __name__ == "__main__":
    unittest.main()
