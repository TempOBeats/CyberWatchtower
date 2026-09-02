import ctypes
import ipaddress
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from cyberwatchtower.firewall_policy import MAX_VALUES_PER_CONDITION

from cyberwatchtower.platform.windows.firewall_com_contracts import (
    WindowsComContractError,
    WindowsComFailureCategory,
    WindowsComInitializationLease,
    WindowsComInitializationResult,
    WindowsOwnedBstr,
)
from cyberwatchtower.platform.windows.firewall_rule_ipc import (
    run_isolated_windows_firewall_helper,
)
from cyberwatchtower.platform.windows.firewall_rule_transport import (
    WindowsFirewallSubprocessLauncher,
)
from cyberwatchtower.platform.windows.firewall_com_contracts import (
    WindowsFirewallPropertyGetter,
    WindowsVariantType,
)
from cyberwatchtower.platform.windows.firewall_rule_models import (
    WindowsFirewallPolicyView,
    WindowsFirewallRuleCollectionResult,
    WindowsFirewallRuleResultCode,
    WindowsRawFirewallUnsupportedFeature,
)
from cyberwatchtower.platform.windows import firewall_rule_helper
from cyberwatchtower.platform.windows.firewall_rule_native import (
    _GUID,
    _VARIANT,
    _VT_DISPATCH,
    _NativeEnumVariant,
    _NativeRule,
    _CtypesFirewallRuntime,
    collect_native_windows_firewall_rules,
)
from cyberwatchtower.platform.windows.firewall_rule_reader import _tokenize_csv
from cyberwatchtower.platform.windows.firewall_rule_collection import (
    collect_windows_firewall_rules_from_collection,
)
from tests.test_windows_firewall_rule_collection import (
    MockEnumVariant,
    MockRulesCollection,
    fixture,
)
from tests.test_windows_firewall_rule_reader import MockFirewallRule


class _Policy:
    def __init__(self, rules, events, failure=None, release_failure=False):
        self.rules, self.events = rules, events
        self.failure, self.release_failure = failure, release_failure

    def get_rules(self):
        self.events.append("get-rules")
        if self.failure:
            raise WindowsComContractError(self.failure)
        return self.rules

    def release(self):
        self.events.append("release-policy")
        if self.release_failure:
            raise RuntimeError("PRIVATE_RELEASE_ERROR")


class _Runtime:
    def __init__(self, rules, init=WindowsComInitializationResult.S_OK,
                 activation_failure=None, policy_failure=None,
                 policy_release_failure=False):
        self.events = []
        self.rules, self.init = rules, init
        self.activation_failure, self.policy_failure = activation_failure, policy_failure
        self.policy_release_failure = policy_release_failure

    def initialize(self):
        self.events.append("initialize")
        return WindowsComInitializationLease(
            self.init, lambda: self.events.append("uninitialize"))

    def activate_policy2(self):
        self.events.append("activate-policy")
        if self.activation_failure:
            raise WindowsComContractError(self.activation_failure)
        return _Policy(self.rules, self.events, self.policy_failure,
                       self.policy_release_failure)


class NativeFirewallCollectorPortableTests(unittest.TestCase):
    @unittest.skipIf(sys.platform == "win32", "non-Windows import-safety check")
    def test_native_runtime_fails_closed_without_loading_windows_libraries(self):
        result = collect_native_windows_firewall_rules()
        self.assertEqual(result.state,
                         WindowsFirewallRuleResultCode.API_UNAVAILABLE)

    def test_helper_selects_native_collector_only_inside_windows_child(self):
        expected = WindowsFirewallRuleCollectionResult(
            WindowsFirewallRuleResultCode.COMPLETE,
            WindowsFirewallPolicyView.CURRENT_POLICY_VIEW,
        )
        with patch.object(firewall_rule_helper.sys, "platform", "win32"), patch(
            "cyberwatchtower.platform.windows.firewall_rule_native."
            "collect_native_windows_firewall_rules",
            return_value=expected,
        ) as collect:
            self.assertIs(firewall_rule_helper._collect_backend(), expected)
        collect.assert_called_once_with()

    def test_s_ok_and_s_false_initialize_collect_and_cleanup_in_order(self):
        for initialization in (WindowsComInitializationResult.S_OK,
                               WindowsComInitializationResult.S_FALSE):
            runtime = _Runtime(fixture(), initialization)
            result = collect_native_windows_firewall_rules(runtime)
            self.assertEqual(result.state, WindowsFirewallRuleResultCode.COMPLETE)
            self.assertEqual(runtime.events[-2:],
                             ["release-policy", "uninitialize"])

    def test_changed_mode_and_activation_failures_are_sanitized(self):
        runtime = _Runtime(fixture(), WindowsComInitializationResult.RPC_E_CHANGED_MODE)
        self.assertEqual(collect_native_windows_firewall_rules(runtime).state,
                         WindowsFirewallRuleResultCode.INTERNAL_ERROR)
        self.assertNotIn("uninitialize", runtime.events)
        for failure, expected in (
            (WindowsComFailureCategory.API_UNAVAILABLE,
             WindowsFirewallRuleResultCode.API_UNAVAILABLE),
            (WindowsComFailureCategory.ACCESS_DENIED,
             WindowsFirewallRuleResultCode.ACCESS_DENIED),
        ):
            runtime = _Runtime(fixture(), activation_failure=failure)
            result = collect_native_windows_firewall_rules(runtime)
            self.assertEqual(result.state, expected)
            self.assertEqual(runtime.events[-1], "uninitialize")

    def test_rules_flow_only_through_existing_collection_engine(self):
        for rules, expected in ((fixture(), WindowsFirewallRuleResultCode.COMPLETE),
                                (fixture(MockFirewallRule()),
                                 WindowsFirewallRuleResultCode.COMPLETE),
                                (fixture(reported_count=1),
                                 WindowsFirewallRuleResultCode.COLLECTION_INCOMPLETE)):
            result = collect_native_windows_firewall_rules(_Runtime(rules))
            self.assertEqual(result.state, expected)

    def test_exact_rule_limit_remains_supported(self):
        events = []
        enumerator = MockEnumVariant(events=events, lazy_count=8192)
        result = collect_native_windows_firewall_rules(
            _Runtime(MockRulesCollection(8192, enumerator, events=events)))
        self.assertEqual(result.state, WindowsFirewallRuleResultCode.COMPLETE)
        self.assertEqual(len(result.rules), 8192)

    def test_primary_failure_precedes_cleanup_failure(self):
        runtime = _Runtime(
            fixture(), policy_failure=WindowsComFailureCategory.ACCESS_DENIED,
            policy_release_failure=True)
        self.assertEqual(collect_native_windows_firewall_rules(runtime).state,
                         WindowsFirewallRuleResultCode.ACCESS_DENIED)
        runtime = _Runtime(fixture(), policy_release_failure=True)
        self.assertEqual(collect_native_windows_firewall_rules(runtime).state,
                         WindowsFirewallRuleResultCode.INTERNAL_ERROR)

    def test_native_abi_shapes_are_fixed_and_import_safe(self):
        self.assertEqual(ctypes_size(_GUID), 16)
        self.assertIn(ctypes_size(_VARIANT), (16, 24))
        source = Path(__file__).parents[1] / (
            "src/cyberwatchtower/platform/windows/firewall_rule_native.py")
        text = source.read_text()
        for prohibited in ("GetIDsOfNames", "Invoke", "get_Name", "get_Description",
                           "get_Grouping", "get_LocalUserOwner", "PowerShell",
                           "netsh", "winreg", "socket."):
            self.assertNotIn(prohibited, text)

    def test_edge_traversal_abi_is_variant_bool_and_not_bstr(self):
        from cyberwatchtower.platform.windows.firewall_com_contracts import (
            WINDOWS_FIREWALL_COM_METHODS,
            WindowsComInterface,
        )
        method = next(
            item for item in WINDOWS_FIREWALL_COM_METHODS
            if item.name == "get_EdgeTraversal"
        )
        self.assertEqual(method.interface, WindowsComInterface.RULE)
        self.assertEqual(method.vtable_index, 39)
        self.assertEqual(ctypes.sizeof(ctypes.c_int16), 2)

        class SyntheticRuntime(_CtypesFirewallRuntime):
            carrier_value = -1

            def call(runtime_self, _pointer, slot, restype, output):
                self.assertEqual(slot, 39)
                self.assertIs(restype, ctypes.c_int32)
                ctypes.cast(
                    output, ctypes.POINTER(ctypes.c_int16)
                ).contents.value = runtime_self.carrier_value
                return 0

        runtime = SyntheticRuntime(None, None)
        self.assertIs(runtime.boolean(ctypes.c_void_p(1), 39), True)
        runtime.carrier_value = 0
        self.assertIs(runtime.boolean(ctypes.c_void_p(1), 39), False)
        runtime.carrier_value = 1
        with self.assertRaises(WindowsComContractError):
            runtime.boolean(ctypes.c_void_p(1), 39)

        class CarrierRuntime:
            def boolean(self, _pointer, slot):
                self.slot = slot
                return True
            def bstr(self, *_args):
                raise AssertionError("BSTR path must not serve EdgeTraversal")
        carrier = CarrierRuntime()
        rule = _NativeRule(ctypes.c_void_p(1), carrier)
        self.assertIs(rule.get_edge_traversal(), True)
        self.assertEqual(carrier.slot, 39)

    def test_local_ports_bstr_abi_optional_values_and_cleanup_are_closed(self):
        class OleAut:
            def __init__(self):
                self.length = 0
                self.frees = 0
                self.length_failure = False

            def SysStringLen(self, _pointer):
                if self.length_failure:
                    raise RuntimeError("PRIVATE_LENGTH_CANARY")
                return self.length

            def SysFreeString(self, _pointer):
                self.frees += 1

        class SyntheticRuntime(_CtypesFirewallRuntime):
            output_address = 0

            def call(runtime_self, _pointer, slot, restype, output):
                self.assertEqual(slot, 17)
                self.assertIs(restype, ctypes.c_int32)
                ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p)).contents.value = (
                    runtime_self.output_address
                )
                return 0

        oleaut = OleAut()
        runtime = SyntheticRuntime(None, oleaut)
        rule = _NativeRule(ctypes.c_void_p(1), runtime)

        self.assertIsNone(rule.get_local_ports())
        self.assertEqual(oleaut.frees, 0)

        empty = ctypes.create_unicode_buffer(1)
        runtime.output_address = ctypes.addressof(empty)
        oleaut.length = 0
        self.assertIsNone(rule.get_local_ports())
        self.assertEqual(oleaut.frees, 1)

        embedded = ctypes.create_unicode_buffer("A\x00B")
        runtime.output_address = ctypes.addressof(embedded)
        oleaut.length = 3
        owned = rule.get_local_ports()
        self.assertIsInstance(owned, WindowsOwnedBstr)
        with self.assertRaises(WindowsComContractError):
            owned.copy_bounded(64)
        owned.close()
        owned.close()
        self.assertEqual(oleaut.frees, 2)

        oleaut.length_failure = True
        with self.assertRaises(WindowsComContractError) as caught:
            rule.get_local_ports()
        self.assertEqual(caught.exception.category,
                         WindowsComFailureCategory.INVALID_RESULT)
        self.assertEqual(oleaut.frees, 3)

    def test_csv_tokenization_is_bounded_and_fail_closed(self):
        for value, expected in (
            ("1", ("1",)),
            ("1,2", ("1", "2")),
            (" 1 , 2 ", ("1", "2")),
        ):
            with self.subTest(valid=value):
                self.assertEqual(_tokenize_csv(value), expected)

        maximum = ",".join("1" for _ in range(MAX_VALUES_PER_CONDITION))
        self.assertEqual(len(_tokenize_csv(maximum)), MAX_VALUES_PER_CONDITION)
        over = maximum + ",1"
        with self.assertRaises(WindowsComContractError):
            _tokenize_csv(over)

        for value in (",1", "1,", "1,,2", ","):
            with self.subTest(empty=value):
                with self.assertRaises(WindowsComContractError) as caught:
                    _tokenize_csv(value)
                self.assertEqual(caught.exception.category,
                                 WindowsComFailureCategory.INVALID_RESULT)
                self.assertNotIn(value, repr(caught.exception))

        mock = MockFirewallRule()
        mock.local_ports = "SYNTHETIC_KEYWORD"
        result = collect_native_windows_firewall_rules(_Runtime(fixture(mock)))
        self.assertEqual(result.state, WindowsFirewallRuleResultCode.INVALID_RESULT)

    def test_local_ports_empty_element_recovers_only_as_unmodeled_predicate(self):
        for value in (",443", "443,", "443,,8443"):
            with self.subTest(value=value):
                mock = MockFirewallRule()
                mock.local_ports = value
                result = collect_native_windows_firewall_rules(
                    _Runtime(fixture(mock))
                )
                self.assertEqual(
                    result.state, WindowsFirewallRuleResultCode.COMPLETE
                )
                self.assertEqual(len(result.rules), 1)
                rule = result.rules[0]
                self.assertEqual(rule.local_ports, ())
                self.assertIn(
                    WindowsRawFirewallUnsupportedFeature.UNMODELED_NATIVE_PREDICATE,
                    rule.unsupported_features,
                )
                self.assertNotIn(value, repr(rule))
                self.assertEqual(
                    mock.freed.count(WindowsFirewallPropertyGetter.LOCAL_PORTS.value),
                    1,
                )
                self.assertIn(
                    WindowsFirewallPropertyGetter.REMOTE_ADDRESSES, mock.calls
                )

    def test_local_ports_recovery_remains_narrow(self):
        cases = (
            {"protocol": 1, "local_ports": "443,"},
            {"local_ports": "SYNTHETIC_KEYWORD"},
        )
        for changes in cases:
            with self.subTest(changes=tuple(changes)):
                mock = MockFirewallRule()
                for name, value in changes.items():
                    setattr(mock, name, value)
                result = collect_native_windows_firewall_rules(
                    _Runtime(fixture(mock))
                )
                self.assertEqual(
                    result.state, WindowsFirewallRuleResultCode.INVALID_RESULT
                )

        with self.assertRaises(WindowsComContractError):
            _tokenize_csv(",".join(
                "1" for _ in range(MAX_VALUES_PER_CONDITION + 1)
            ))

    def test_reused_native_pointer_creates_distinct_occurrence_wrappers(self):
        runtime = _SyntheticEnumRuntime((0x1111, 0x1111, None))
        enumerator = _NativeEnumVariant(object(), runtime)
        first = enumerator.next_one()
        second = enumerator.next_one()
        end = enumerator.next_one()
        first_element = first.value.extract(WindowsVariantType.DISPATCH)
        second_element = second.value.extract(WindowsVariantType.DISPATCH)
        self.assertIsNot(first_element, second_element)
        self.assertEqual(end.fetched, 0)
        first.value.close()
        second.value.close()
        self.assertEqual(runtime.variant_initializations, 3)
        self.assertEqual(runtime.variant_clears, 3)
        rendered = repr((first, second, first_element, second_element))
        self.assertNotIn("4369", rendered)
        self.assertNotIn("0x1111", rendered)

    def test_enum_next_uses_fresh_zeroed_output_storage_per_call(self):
        runtime = _SyntheticEnumRuntime((0x1111, None))
        enumerator = _NativeEnumVariant(object(), runtime)
        item = enumerator.next_one()
        item.value.close()
        end = enumerator.next_one()

        self.assertEqual(end.state.value, "END")
        self.assertEqual(end.fetched, 0)
        self.assertEqual(runtime.precall_states, [
            (0, 0, 0, 0, 0),
            (0, 0, 0, 0, 0),
        ])
        self.assertEqual(runtime.variant_initializations, 2)
        self.assertEqual(runtime.variant_clears, 2)
        self.assertEqual(ctypes.sizeof(ctypes.c_uint32), 4)
        expected_variant_size = 24 if ctypes.sizeof(ctypes.c_void_p) == 8 else 16
        self.assertEqual(ctypes.sizeof(_VARIANT), expected_variant_size)
        self.assertEqual(
            ctypes.alignment(_VARIANT), ctypes.alignment(ctypes.c_void_p)
        )

    def test_reused_pointer_passes_collection_but_same_wrapper_still_fails(self):
        runtime = _SyntheticEnumRuntime((0x1111, 0x1111, None))
        enumerator = _NativeEnumVariant(object(), runtime)
        rules = MockRulesCollection(2, enumerator, events=[])
        with patch(
            "cyberwatchtower.platform.windows.firewall_rule_native."
            "_NativeRuleElement.query_rule",
            side_effect=(MockFirewallRule(), MockFirewallRule()),
        ):
            result = collect_windows_firewall_rules_from_collection(rules)
        self.assertEqual(result.state, WindowsFirewallRuleResultCode.COMPLETE)
        self.assertEqual(runtime.variant_clears, 3)

        shared = fixture(MockFirewallRule()).new_enum.enumerator.elements[0]
        broken = MockEnumVariant((shared, shared))
        rejected = collect_windows_firewall_rules_from_collection(
            MockRulesCollection(2, broken)
        )
        self.assertEqual(rejected.state, WindowsFirewallRuleResultCode.INVALID_RESULT)

    def test_raw_rule_validation_remains_fail_closed_and_private(self):
        cases = (
            ("direction", 999),
            ("local_ports", "PRIVATE_PORT_CANARY"),
            ("local_addresses", "PRIVATE_ADDRESS_CANARY"),
            ("service_name", "PRIVATE/SERVICE/CANARY"),
            ("interface_types", "PRIVATE_INTERFACE_TYPE_CANARY"),
        )
        for attribute, value in cases:
            with self.subTest(attribute=attribute):
                rule = MockFirewallRule()
                setattr(rule, attribute, value)
                result = collect_native_windows_firewall_rules(_Runtime(fixture(rule)))
                self.assertEqual(result.state, WindowsFirewallRuleResultCode.INVALID_RESULT)
                self.assertNotIn("PRIVATE", repr(result))

    def test_windows_address_expressions_remain_strict_and_typed(self):
        from cyberwatchtower.platform.windows.firewall_rule_models import _raw_address
        for accepted in (
            "*", "LocalSubnet", "192.0.2.1", "2001:db8::1",
            "192.0.2.0/24", "2001:db8::/64", "192.0.2.0/255.255.255.0",
        ):
            _raw_address(accepted, "redacted")
        from cyberwatchtower.platform.windows.firewall_rule_models import (
            RawWindowsFirewallIPv4AddressRange,
        )
        range_text = "192.0.2.1-192.0.2.9"
        address_range = _raw_address(range_text, "redacted")
        self.assertIsInstance(address_range, RawWindowsFirewallIPv4AddressRange)
        self.assertEqual(address_range.start, ipaddress.IPv4Address("192.0.2.1"))
        self.assertEqual(address_range.end, ipaddress.IPv4Address("192.0.2.9"))
        self.assertNotIsInstance(address_range, str)
        self.assertNotIn(range_text, repr(address_range))
        for rejected in (
            "DefaultGateway", "DHCP", "DNS", "WINS",
            "PRIVATEALPHABETICCANARY",
        ):
            with self.assertRaises(ValueError):
                _raw_address(rejected, "redacted")
        from cyberwatchtower.platform.windows.firewall_rule_models import (
            RawWindowsFirewallIPv6AddressRange,
        )
        ipv6_range = _raw_address("2001:db8::1-2001:db8::9", "redacted")
        self.assertIsInstance(ipv6_range, RawWindowsFirewallIPv6AddressRange)

        from cyberwatchtower.platform.windows.firewall_rule_models import (
            RawWindowsFirewallRule,
            WindowsFirewallPolicyView,
            WindowsRawFirewallRuleAction,
            WindowsRawFirewallRuleDirection,
            WindowsRawFirewallUnsupportedFeature,
        )
        defaults = dict(
            policy_view=WindowsFirewallPolicyView.CURRENT_POLICY_VIEW,
            enabled=True,
            direction=WindowsRawFirewallRuleDirection.INBOUND,
            action=WindowsRawFirewallRuleAction.ALLOW,
            profile_mask=1,
            protocol=6,
        )
        direct_cases = (
            {"application_path": object()},
            {"interfaces": (object(),)},
            {"edge_traversal": "PRIVATE_EDGE_CANARY"},
            {"local_ports": ("*", "1")},
            {"unsupported_features": (
                WindowsRawFirewallUnsupportedFeature.UNMODELED_NATIVE_PREDICATE,
                WindowsRawFirewallUnsupportedFeature.UNMODELED_NATIVE_PREDICATE,
            )},
            {"remote_addresses": tuple(str(index) for index in range(257))},
        )
        for overrides in direct_cases:
            with self.subTest(fields=tuple(overrides)):
                with self.assertRaises((TypeError, ValueError)):
                    RawWindowsFirewallRule(**defaults, **overrides)


class _SyntheticEnumRuntime:
    def __init__(self, pointers):
        self.pointers = iter(pointers)
        self.variant_initializations = 0
        self.variant_clears = 0
        self.precall_states = []

    def initialize_variant(self, variant):
        self.variant_initializations += 1

    def clear_variant(self, variant):
        self.variant_clears += 1

    def release(self, pointer):
        pass

    def call(self, pointer, slot, restype, celt, variant_pointer, fetched_pointer):
        import ctypes
        value = next(self.pointers)
        variant = ctypes.cast(variant_pointer, ctypes.POINTER(_VARIANT)).contents
        fetched = ctypes.cast(
            fetched_pointer, ctypes.POINTER(ctypes.c_uint32)
        ).contents
        self.precall_states.append((
            int(variant.vt), int(variant.reserved1), int(variant.reserved2),
            int(variant.reserved3), int(fetched.value),
        ))
        if value is None:
            fetched.value = 0
            return 1
        variant.vt = _VT_DISPATCH
        variant.dispatch = value
        fetched.value = 1
        return 0


def ctypes_size(value):
    import ctypes
    return ctypes.sizeof(value)


@unittest.skipUnless(
    sys.platform == "win32" and
    os.environ.get("CYBERWATCHTOWER_VALIDATE_NATIVE_FIREWALL_RULES") == "1",
    "guarded native Windows Firewall validation requires explicit opt-in",
)
class GuardedNativeWindowsFirewallTests(unittest.TestCase):
    def test_isolated_native_current_policy_collection(self):
        launcher = WindowsFirewallSubprocessLauncher()
        result = run_isolated_windows_firewall_helper(launcher)
        self.assertEqual(
            result.state, WindowsFirewallRuleResultCode.COMPLETE,
            "guarded native Windows Firewall collection must complete",
        )
        self.assertLessEqual(len(result.rules), 8192)
        self.assertNotIn("C:\\", repr(result))


if __name__ == "__main__":
    unittest.main()
