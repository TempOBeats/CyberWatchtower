import dataclasses
import inspect
import unittest

from cyberwatchtower.platform.windows import (
    MAX_PROPERTY_GETTERS_PER_RULE,
    RawWindowsFirewallRule,
    WindowsComContractError,
    WindowsComFailureCategory,
    WindowsComInterfaceAvailability,
    WindowsComOperationAccounting,
    WindowsFirewallPropertyGetter,
    WindowsFirewallRule2Query,
    WindowsFirewallRule3Query,
    WindowsFirewallRuleCollectionResult,
    WindowsFirewallRuleReaderProtocol,
    WindowsFirewallRuleResultCode,
    WindowsRawFirewallUnsupportedFeature,
    WindowsOwnedBstr,
    WindowsOwnedVariant,
    WindowsSafeArrayElementType,
    WindowsSafeArrayValue,
    WindowsVariantType,
    normalize_windows_firewall_rules,
    read_windows_firewall_rule,
)
from cyberwatchtower.platform.windows import firewall_rule_reader as reader


class MockRule2:
    def __init__(self, owner):
        self.owner = owner

    def get_edge_traversal_options(self):
        return self.owner._get(
            WindowsFirewallPropertyGetter.EDGE_TRAVERSAL_OPTIONS,
            self.owner.edge_options,
        )

    def release(self):
        self.owner._release("rule2")


class MockRule3:
    def __init__(self, owner):
        self.owner = owner

    def _text(self, getter, value):
        self.owner._get(getter, None)
        return self.owner._bstr(value, getter.value) if value is not None else None

    def get_local_app_package_id(self):
        return self._text(
            WindowsFirewallPropertyGetter.LOCAL_APP_PACKAGE_ID,
            self.owner.local_app_package_id,
        )

    def get_local_user_authorized_list(self):
        return self._text(
            WindowsFirewallPropertyGetter.LOCAL_USER_AUTHORIZED_LIST,
            self.owner.local_user_authorized_list,
        )

    def get_remote_machine_authorized_list(self):
        return self._text(
            WindowsFirewallPropertyGetter.REMOTE_MACHINE_AUTHORIZED_LIST,
            self.owner.remote_machine_authorized_list,
        )

    def get_remote_user_authorized_list(self):
        return self._text(
            WindowsFirewallPropertyGetter.REMOTE_USER_AUTHORIZED_LIST,
            self.owner.remote_user_authorized_list,
        )

    def get_secure_flags(self):
        return self.owner._get(
            WindowsFirewallPropertyGetter.SECURE_FLAGS, self.owner.secure_flags
        )

    def release(self):
        self.owner._release("rule3")


class MockFirewallRule:
    """Fixed-method mock; there is no arbitrary property dispatch surface."""

    def __init__(self):
        self.enabled = True
        self.direction = reader.WINDOWS_NET_FW_RULE_DIR_IN
        self.action = reader.WINDOWS_NET_FW_ACTION_ALLOW
        self.profiles = 0x4
        self.protocol = 6
        self.local_ports = "443"
        self.remote_ports = None
        self.local_addresses = "*"
        self.remote_addresses = "*"
        self.application_name = None
        self.service_name = None
        self.interface_types = "All"
        self.interfaces = ()
        self.interface_dimensions = 1
        self.interface_element_type = WindowsSafeArrayElementType.VARIANT
        self.icmp_types_and_codes = None
        self.edge_options = reader.WINDOWS_EDGE_TRAVERSAL_DENY
        self.edge_traversal = False
        self.rule2_available = True
        self.rule3_available = True
        self.local_app_package_id = None
        self.local_user_authorized_list = None
        self.remote_machine_authorized_list = None
        self.remote_user_authorized_list = None
        self.secure_flags = 0
        self.failed_getters = frozenset()
        self.failure_category = WindowsComFailureCategory.ACCESS_DENIED
        self.query2_failure = None
        self.query3_failure = None
        self.release_failures = frozenset()
        self.calls = []
        self.freed = []
        self.variant_initialized = 0
        self.variant_cleared = 0
        self.released = []

    def _get(self, getter, value):
        self.calls.append(getter)
        if getter in self.failed_getters:
            raise WindowsComContractError(self.failure_category)
        return value

    def _bstr(self, value, label):
        return WindowsOwnedBstr(value, lambda: self.freed.append(label))

    def _text(self, getter, value):
        self._get(getter, None)
        return self._bstr(value, getter.value) if value is not None else None

    def _release(self, name):
        self.released.append(name)
        if name in self.release_failures:
            raise RuntimeError("PRIVATE_NATIVE_RELEASE_CANARY")

    def get_enabled(self):
        return self._get(WindowsFirewallPropertyGetter.ENABLED, self.enabled)

    def get_direction(self):
        return self._get(WindowsFirewallPropertyGetter.DIRECTION, self.direction)

    def get_action(self):
        return self._get(WindowsFirewallPropertyGetter.ACTION, self.action)

    def get_profiles(self):
        return self._get(WindowsFirewallPropertyGetter.PROFILES, self.profiles)

    def get_protocol(self):
        return self._get(WindowsFirewallPropertyGetter.PROTOCOL, self.protocol)

    def get_local_ports(self):
        return self._text(WindowsFirewallPropertyGetter.LOCAL_PORTS,
                          self.local_ports)

    def get_remote_ports(self):
        return self._text(WindowsFirewallPropertyGetter.REMOTE_PORTS,
                          self.remote_ports)

    def get_local_addresses(self):
        return self._text(WindowsFirewallPropertyGetter.LOCAL_ADDRESSES,
                          self.local_addresses)

    def get_remote_addresses(self):
        return self._text(WindowsFirewallPropertyGetter.REMOTE_ADDRESSES,
                          self.remote_addresses)

    def get_application_name(self):
        return self._text(WindowsFirewallPropertyGetter.APPLICATION_NAME,
                          self.application_name)

    def get_service_name(self):
        return self._text(WindowsFirewallPropertyGetter.SERVICE_NAME,
                          self.service_name)

    def get_interface_types(self):
        return self._text(WindowsFirewallPropertyGetter.INTERFACE_TYPES,
                          self.interface_types)

    def get_interfaces(self):
        self._get(WindowsFirewallPropertyGetter.INTERFACES, None)
        return WindowsOwnedVariant(
            WindowsVariantType.ARRAY_VARIANT,
            WindowsSafeArrayValue(
                self.interface_dimensions,
                self.interface_element_type,
                self.interfaces,
            ),
            self._initialize_variant,
            self._clear_variant,
        )

    def _initialize_variant(self):
        self.variant_initialized += 1

    def _clear_variant(self):
        self.variant_cleared += 1

    def get_icmp_types_and_codes(self):
        return self._text(WindowsFirewallPropertyGetter.ICMP_TYPES_AND_CODES,
                          self.icmp_types_and_codes)

    def get_edge_traversal(self):
        return self._get(WindowsFirewallPropertyGetter.EDGE_TRAVERSAL,
                         self.edge_traversal)

    def query_rule2(self):
        self.calls.append("query_rule2")
        if self.query2_failure is not None:
            raise WindowsComContractError(self.query2_failure)
        if self.rule2_available:
            return WindowsFirewallRule2Query(
                WindowsComInterfaceAvailability.AVAILABLE, MockRule2(self)
            )
        return WindowsFirewallRule2Query(
            WindowsComInterfaceAvailability.UNAVAILABLE
        )

    def query_rule3(self):
        self.calls.append("query_rule3")
        if self.query3_failure is not None:
            raise WindowsComContractError(self.query3_failure)
        if self.rule3_available:
            return WindowsFirewallRule3Query(
                WindowsComInterfaceAvailability.AVAILABLE, MockRule3(self)
            )
        return WindowsFirewallRule3Query(
            WindowsComInterfaceAvailability.UNAVAILABLE
        )

    def release(self):
        self._release("rule")


class WindowsFirewallSingleRuleReaderTests(unittest.TestCase):
    def test_basic_rule_reads_normalizes_and_releases_in_reverse_order(self):
        mock = MockFirewallRule()
        mock.application_name = r"C:\Program Files\Private Canary\app.exe"
        mock.interfaces = ("PRIVATE_INTERFACE_CANARY",)
        ledger = WindowsComOperationAccounting()

        first = read_windows_firewall_rule(mock, accounting=ledger)
        self.assertIsInstance(first.rule, RawWindowsFirewallRule)
        self.assertIsNone(first.failure)
        self.assertEqual(mock.released, ["rule3", "rule2", "rule"])
        self.assertEqual(mock.variant_initialized, 1)
        self.assertEqual(mock.variant_cleared, 1)
        self.assertEqual(ledger.query_interfaces, 2)
        self.assertEqual(ledger.interface_releases, 3)
        self.assertEqual(ledger.cleanup_operations, 3)
        text = repr(first)
        self.assertNotIn("Private Canary", text)
        self.assertNotIn("PRIVATE_INTERFACE_CANARY", text)

        normalized = normalize_windows_firewall_rules(
            WindowsFirewallRuleCollectionResult(
                WindowsFirewallRuleResultCode.COMPLETE,
                first.rule.policy_view,
                (first.rule,),
            )
        )
        self.assertIsNone(normalized.failure)
        self.assertEqual(len(normalized.rules), 1)
        self.assertNotIn("Private Canary", repr(normalized))
        self.assertNotIn("PRIVATE_INTERFACE_CANARY", repr(normalized))

    def test_getter_order_is_fixed_and_conditional(self):
        mock = MockFirewallRule()
        result = read_windows_firewall_rule(mock)
        self.assertIsNotNone(result.rule)
        self.assertEqual(mock.calls, [
            WindowsFirewallPropertyGetter.ENABLED,
            WindowsFirewallPropertyGetter.DIRECTION,
            WindowsFirewallPropertyGetter.ACTION,
            WindowsFirewallPropertyGetter.PROFILES,
            WindowsFirewallPropertyGetter.PROTOCOL,
            WindowsFirewallPropertyGetter.LOCAL_PORTS,
            WindowsFirewallPropertyGetter.REMOTE_PORTS,
            WindowsFirewallPropertyGetter.LOCAL_ADDRESSES,
            WindowsFirewallPropertyGetter.REMOTE_ADDRESSES,
            WindowsFirewallPropertyGetter.APPLICATION_NAME,
            WindowsFirewallPropertyGetter.SERVICE_NAME,
            WindowsFirewallPropertyGetter.INTERFACE_TYPES,
            WindowsFirewallPropertyGetter.INTERFACES,
            "query_rule2",
            WindowsFirewallPropertyGetter.EDGE_TRAVERSAL_OPTIONS,
            "query_rule3",
            WindowsFirewallPropertyGetter.LOCAL_APP_PACKAGE_ID,
            WindowsFirewallPropertyGetter.LOCAL_USER_AUTHORIZED_LIST,
            WindowsFirewallPropertyGetter.REMOTE_MACHINE_AUTHORIZED_LIST,
            WindowsFirewallPropertyGetter.REMOTE_USER_AUTHORIZED_LIST,
            WindowsFirewallPropertyGetter.SECURE_FLAGS,
        ])

    def test_rule2_fallback_and_rule3_unavailable_are_explicit(self):
        mock = MockFirewallRule()
        mock.rule2_available = False
        mock.rule3_available = False
        result = read_windows_firewall_rule(mock)
        self.assertIsNotNone(result.rule)
        self.assertIn(
            WindowsRawFirewallUnsupportedFeature.UNMODELED_NATIVE_PREDICATE,
            result.rule.unsupported_features,
        )
        self.assertIn(WindowsFirewallPropertyGetter.EDGE_TRAVERSAL, mock.calls)
        self.assertNotIn(
            WindowsFirewallPropertyGetter.EDGE_TRAVERSAL_OPTIONS, mock.calls
        )
        self.assertEqual(mock.released, ["rule"])

    def test_icmp_and_rule3_predicates_are_read_only_when_applicable(self):
        mock = MockFirewallRule()
        mock.protocol = 1
        mock.icmp_types_and_codes = "8:*"
        mock.local_app_package_id = "PRIVATE_PACKAGE_CANARY"
        mock.local_user_authorized_list = "PRIVATE_USER_CANARY"
        mock.remote_machine_authorized_list = "PRIVATE_MACHINE_CANARY"
        result = read_windows_firewall_rule(mock)
        self.assertIsNotNone(result.rule)
        self.assertIn(WindowsFirewallPropertyGetter.ICMP_TYPES_AND_CODES,
                      mock.calls)
        self.assertEqual(set(result.rule.unsupported_features), {
            WindowsRawFirewallUnsupportedFeature.ICMP_TYPE_CONDITION,
            WindowsRawFirewallUnsupportedFeature.PACKAGE_SCOPE,
            WindowsRawFirewallUnsupportedFeature.LOCAL_USER_SCOPE,
            WindowsRawFirewallUnsupportedFeature.UNMODELED_NATIVE_PREDICATE,
        })
        for canary in ("PRIVATE_PACKAGE_CANARY", "PRIVATE_USER_CANARY",
                       "PRIVATE_MACHINE_CANARY"):
            self.assertNotIn(canary, repr(result))

    def test_tcp_never_reads_icmp_condition(self):
        mock = MockFirewallRule()
        mock.failed_getters = frozenset({
            WindowsFirewallPropertyGetter.ICMP_TYPES_AND_CODES
        })
        result = read_windows_firewall_rule(mock)
        self.assertIsNotNone(result.rule)
        self.assertNotIn(WindowsFirewallPropertyGetter.ICMP_TYPES_AND_CODES,
                         mock.calls)

    def test_ports_addresses_service_and_interfaces_flow_to_raw_validation(self):
        mock = MockFirewallRule()
        mock.protocol = 17
        mock.action = reader.WINDOWS_NET_FW_ACTION_BLOCK
        mock.local_ports = "53,1000-1005"
        mock.local_addresses = "192.0.2.1,2001:db8::1"
        mock.service_name = "Dnscache"
        mock.interface_types = "LAN"
        mock.interfaces = ()
        result = read_windows_firewall_rule(mock)
        self.assertIsNotNone(result.rule)
        self.assertEqual(result.rule.local_ports, ("1000-1005", "53"))
        self.assertEqual(result.rule.local_addresses,
                         ("192.0.2.1", "2001:db8::1"))
        self.assertEqual(result.rule.service_name, "Dnscache")

    def test_any_protocol_and_ports_and_application_scope_are_supported(self):
        mock = MockFirewallRule()
        mock.protocol = 256
        mock.local_ports = "*"
        mock.remote_ports = "*"
        mock.application_name = r"C:\Program Files\Private\agent.exe"
        result = read_windows_firewall_rule(mock)
        self.assertIsNotNone(result.rule)
        self.assertEqual(result.rule.protocol, 256)
        self.assertEqual(result.rule.local_ports, ("*",))
        normalized = normalize_windows_firewall_rules(
            WindowsFirewallRuleCollectionResult(
                WindowsFirewallRuleResultCode.COMPLETE,
                result.rule.policy_view,
                (result.rule,),
            )
        )
        self.assertIsNone(normalized.failure)
        self.assertNotIn("Program Files", repr(normalized))

    def test_safearray_empty_multiple_and_malformed_values(self):
        for values in ((), ("one",), ("one", "two")):
            with self.subTest(values=values):
                mock = MockFirewallRule()
                mock.interfaces = values
                result = read_windows_firewall_rule(mock)
                self.assertIsNotNone(result.rule)
                self.assertEqual(len(result.rule.interfaces), len(values))
                self.assertEqual(mock.variant_cleared, 1)
        mock = MockFirewallRule()
        mock.interface_dimensions = 2
        result = read_windows_firewall_rule(mock)
        self.assertEqual(result.failure, WindowsComFailureCategory.INVALID_RESULT)
        self.assertEqual(mock.released, ["rule"])

    def test_malformed_bstr_and_variant_fail_closed_after_cleanup(self):
        mock = MockFirewallRule()
        mock.application_name = "PRIVATE_PATH_CANARY\nCONTROL"
        result = read_windows_firewall_rule(mock)
        self.assertEqual(result.failure, WindowsComFailureCategory.INVALID_RESULT)
        self.assertNotIn("PRIVATE_PATH_CANARY", repr(result))
        self.assertIn(WindowsFirewallPropertyGetter.APPLICATION_NAME.value,
                      mock.freed)
        self.assertEqual(mock.released, ["rule"])

        class WrongVariantRule(MockFirewallRule):
            def get_interfaces(self):
                self._get(WindowsFirewallPropertyGetter.INTERFACES, None)
                return WindowsOwnedVariant(
                    WindowsVariantType.BSTR,
                    "PRIVATE_VARIANT_CANARY",
                    self._initialize_variant,
                    self._clear_variant,
                )

        wrong = WrongVariantRule()
        result = read_windows_firewall_rule(wrong)
        self.assertEqual(result.failure, WindowsComFailureCategory.INVALID_RESULT)
        self.assertEqual(wrong.variant_initialized, 1)
        self.assertEqual(wrong.variant_cleared, 1)
        self.assertNotIn("PRIVATE_VARIANT_CANARY", repr(result))

    def test_getter_failures_are_sanitized_and_cleanup_is_exact(self):
        getters = tuple(WindowsFirewallPropertyGetter)
        for getter in getters:
            with self.subTest(getter=getter):
                mock = MockFirewallRule()
                if getter == WindowsFirewallPropertyGetter.ICMP_TYPES_AND_CODES:
                    mock.protocol = 1
                if getter == WindowsFirewallPropertyGetter.EDGE_TRAVERSAL:
                    mock.rule2_available = False
                mock.failed_getters = frozenset({getter})
                result = read_windows_firewall_rule(mock)
                self.assertEqual(result.failure,
                                 WindowsComFailureCategory.ACCESS_DENIED)
                self.assertNotIn("PRIVATE_NATIVE", repr(result))
                self.assertEqual(mock.released.count("rule"), 1)
                self.assertLessEqual(mock.released.count("rule2"), 1)
                self.assertLessEqual(mock.released.count("rule3"), 1)

    def test_query_failure_and_getter_limit_fail_closed(self):
        mock = MockFirewallRule()
        mock.query2_failure = WindowsComFailureCategory.UNSUPPORTED
        result = read_windows_firewall_rule(mock)
        self.assertEqual(result.failure, WindowsComFailureCategory.UNSUPPORTED)
        self.assertEqual(mock.released, ["rule"])

        mock = MockFirewallRule()
        ledger = WindowsComOperationAccounting(
            property_getters=MAX_PROPERTY_GETTERS_PER_RULE
        )
        result = read_windows_firewall_rule(mock, accounting=ledger)
        self.assertEqual(result.failure,
                         WindowsComFailureCategory.LIMIT_EXCEEDED)
        self.assertEqual(mock.calls, [])
        self.assertEqual(mock.released, ["rule"])

    def test_raw_validation_failure_is_closed_and_bstrs_are_freed(self):
        mock = MockFirewallRule()
        mock.local_ports = "99999"
        result = read_windows_firewall_rule(mock)
        self.assertEqual(result.failure, WindowsComFailureCategory.INVALID_RESULT)
        self.assertEqual(mock.released, ["rule3", "rule2", "rule"])
        self.assertIn(WindowsFirewallPropertyGetter.LOCAL_PORTS.value, mock.freed)

    def test_cleanup_failure_does_not_replace_primary_failure(self):
        mock = MockFirewallRule()
        mock.enabled = "INVALID_PRIVATE_CANARY"
        mock.release_failures = frozenset({"rule"})
        result = read_windows_firewall_rule(mock)
        self.assertEqual(result.failure, WindowsComFailureCategory.INVALID_RESULT)
        self.assertNotIn("CANARY", repr(result))

        cleanup_only = MockFirewallRule()
        cleanup_only.release_failures = frozenset({"rule"})
        result = read_windows_firewall_rule(cleanup_only)
        self.assertEqual(result.failure, WindowsComFailureCategory.INTERNAL_ERROR)

    def test_reader_is_deterministic_and_does_not_mutate_mock_values(self):
        first_mock = MockFirewallRule()
        second_mock = MockFirewallRule()
        first = read_windows_firewall_rule(first_mock)
        second = read_windows_firewall_rule(second_mock)
        self.assertEqual(first, second)
        self.assertEqual(first_mock.local_ports, "443")
        self.assertEqual(second_mock.local_ports, "443")


class WindowsFirewallSingleRuleAuthorityTests(unittest.TestCase):
    def test_protocol_is_fixed_and_safe_on_non_windows(self):
        self.assertIsInstance(MockFirewallRule(), WindowsFirewallRuleReaderProtocol)
        source = inspect.getsource(reader)
        for prohibited in (
            "ctypes", "WinDLL", "CoCreateInstance", "subprocess", "shell=True",
            "PowerShell", "netsh", "os.system", "GetIDsOfNames", "Invoke(",
            "put_", "get_Name", "get_Description", "get_Grouping",
            "get_LocalUserOwner", ".Add(", ".Remove(", ".Item(",
        ):
            self.assertNotIn(prohibited, source)

    def test_safe_results_have_no_arbitrary_metadata_or_private_fields(self):
        fields = {item.name for item in dataclasses.fields(
            reader.WindowsFirewallSingleRuleReadResult
        )}
        self.assertEqual(fields, {"rule", "failure"})
        query_fields = {
            item.name for item in dataclasses.fields(reader.WindowsFirewallRule2Query)
        }
        self.assertEqual(query_fields, {"availability", "interface"})
        self.assertNotIn("PRIVATE_POINTER_CANARY",
                         repr(reader.WindowsFirewallRule2Query(
                             WindowsComInterfaceAvailability.AVAILABLE,
                             MockRule2(MockFirewallRule()),
                         )))


if __name__ == "__main__":
    unittest.main()
