import inspect
from pathlib import Path
import unittest
from unittest.mock import patch

from cyberwatchtower.firewall_policy import MAX_FIREWALL_RULES
from cyberwatchtower.platform.windows import (
    MAX_FIREWALL_ENUMERATION_OPERATIONS,
    WindowsComContractError,
    WindowsComFailureCategory,
    WindowsComOperationAccounting,
    WindowsFirewallEnumerationState,
    WindowsFirewallEnumerationStep,
    WindowsFirewallEnumVariantProtocol,
    WindowsFirewallNewEnumProtocol,
    WindowsFirewallRuleCollectionResult,
    WindowsFirewallRuleElementProtocol,
    WindowsFirewallRuleResultCode,
    WindowsFirewallRulesCollectionProtocol,
    WindowsOwnedVariant,
    WindowsVariantType,
    collect_windows_firewall_rules_from_collection,
    normalize_windows_firewall_rules,
)
from cyberwatchtower.platform.windows import firewall_rule_collection as collection
from tests.test_windows_firewall_rule_reader import MockFirewallRule


class MockRuleElement:
    def __init__(self, rule, events, *, failure=None):
        self.rule = rule
        self.events = events
        self.failure = failure

    def __repr__(self):
        return "MockRuleElement(<redacted>)"

    def query_rule(self):
        self.events.append("query-rule")
        if self.failure is not None:
            raise WindowsComContractError(self.failure)
        return self.rule


class MockEnumVariant:
    def __init__(
        self,
        elements=(),
        *,
        events=None,
        next_failure_at=None,
        malformed_at=None,
        malformed_fetched_at=None,
        wrong_variant_at=None,
        lazy_count=None,
    ):
        self.elements = tuple(elements)
        self.events = events if events is not None else []
        self.next_failure_at = next_failure_at
        self.malformed_at = malformed_at
        self.malformed_fetched_at = malformed_fetched_at
        self.wrong_variant_at = wrong_variant_at
        self.lazy_count = lazy_count
        self.position = 0
        self.variant_initializations = 0
        self.variant_clears = 0
        self.release_failure = False

    def next_one(self):
        index = self.position
        self.position += 1
        self.events.append("next")
        if index == self.next_failure_at:
            raise WindowsComContractError(WindowsComFailureCategory.ACCESS_DENIED)
        if index == self.malformed_at:
            return object()
        if self.lazy_count is not None and index < self.lazy_count:
            rule = MockFirewallRule()
            element = MockRuleElement(rule, self.events)
        elif index < len(self.elements):
            element = self.elements[index]
        else:
            return WindowsFirewallEnumerationStep(
                WindowsFirewallEnumerationState.END, 0
            )
        variant_type = (
            WindowsVariantType.BSTR
            if index == self.wrong_variant_at else WindowsVariantType.DISPATCH
        )
        variant = WindowsOwnedVariant(
            variant_type,
            element,
            self._initialize_variant,
            self._clear_variant,
        )
        if index == self.malformed_fetched_at:
            return WindowsFirewallEnumerationStep(
                WindowsFirewallEnumerationState.ITEM, 2, variant
            )
        return WindowsFirewallEnumerationStep(
            WindowsFirewallEnumerationState.ITEM, 1, variant
        )

    def _initialize_variant(self):
        self.variant_initializations += 1

    def _clear_variant(self):
        self.variant_clears += 1
        self.events.append("clear-variant")

    def release(self):
        self.events.append("release-enumerator")
        if self.release_failure:
            raise RuntimeError("PRIVATE_ENUMERATOR_RELEASE_CANARY")


class MockNewEnum:
    def __init__(self, enumerator, events):
        self.enumerator = enumerator
        self.events = events
        self.query_failure = None
        self.release_failure = False

    def query_enum_variant(self):
        self.events.append("query-enumerator")
        if self.query_failure is not None:
            raise WindowsComContractError(self.query_failure)
        return self.enumerator

    def release(self):
        self.events.append("release-new-enum")
        if self.release_failure:
            raise RuntimeError("PRIVATE_NEW_ENUM_RELEASE_CANARY")


class MockRulesCollection:
    def __init__(self, count, enumerator, *, events=None):
        self.count = count
        self.events = events if events is not None else enumerator.events
        self.new_enum = MockNewEnum(enumerator, self.events)
        self.count_failure = None
        self.new_enum_failure = None
        self.release_failure = False

    def get_count(self):
        self.events.append("count")
        if self.count_failure is not None:
            raise WindowsComContractError(self.count_failure)
        return self.count

    def get_new_enum(self):
        self.events.append("new-enum")
        if self.new_enum_failure is not None:
            raise WindowsComContractError(self.new_enum_failure)
        return self.new_enum

    def release(self):
        self.events.append("release-rules")
        if self.release_failure:
            raise RuntimeError("PRIVATE_RULES_RELEASE_CANARY")


def fixture(*rules, reported_count=None):
    events = []
    elements = tuple(MockRuleElement(rule, events) for rule in rules)
    enumerator = MockEnumVariant(elements, events=events)
    return MockRulesCollection(
        len(rules) if reported_count is None else reported_count,
        enumerator,
        events=events,
    )


class WindowsFirewallRuleCollectionContractTests(unittest.TestCase):
    def test_collection_protocols_are_fixed_and_import_safe(self):
        rules = fixture()
        self.assertIsInstance(rules, WindowsFirewallRulesCollectionProtocol)
        self.assertIsInstance(rules.new_enum, WindowsFirewallNewEnumProtocol)
        self.assertIsInstance(rules.new_enum.enumerator,
                              WindowsFirewallEnumVariantProtocol)
        element = MockRuleElement(MockFirewallRule(), [])
        self.assertIsInstance(element, WindowsFirewallRuleElementProtocol)
        self.assertEqual(
            MAX_FIREWALL_ENUMERATION_OPERATIONS, MAX_FIREWALL_RULES + 3
        )
        with self.assertRaises(TypeError):
            collect_windows_firewall_rules_from_collection({})

    def test_enumeration_step_is_closed_and_redacts_value(self):
        element = MockRuleElement(MockFirewallRule(), [])
        value = WindowsOwnedVariant(
            WindowsVariantType.DISPATCH, element, lambda: None, lambda: None
        )
        step = WindowsFirewallEnumerationStep(
            WindowsFirewallEnumerationState.ITEM, 1, value
        )
        self.assertNotIn("MockRuleElement", repr(step))
        with self.assertRaises((TypeError, ValueError)):
            WindowsFirewallEnumerationStep(
                WindowsFirewallEnumerationState.ITEM, True, value
            )
        malformed = WindowsFirewallEnumerationStep(
            WindowsFirewallEnumerationState.END, 1, value
        )
        self.assertEqual(malformed.fetched, 1)
        value.close()


class WindowsFirewallRuleCollectionEngineTests(unittest.TestCase):
    def test_zero_one_and_multiple_rules_are_complete(self):
        cases = ((), (MockFirewallRule(),),
                 (MockFirewallRule(), MockFirewallRule()))
        cases[2][0].local_ports = "443"
        cases[2][1].local_ports = "53"
        cases[2][1].protocol = 17
        cases[2][1].action = 0
        for rules in cases:
            with self.subTest(count=len(rules)):
                source = fixture(*rules)
                result = collect_windows_firewall_rules_from_collection(source)
                self.assertEqual(result.state,
                                 WindowsFirewallRuleResultCode.COMPLETE)
                self.assertEqual(len(result.rules), len(rules))
                self.assertEqual(source.events[-3:], [
                    "release-enumerator", "release-new-enum", "release-rules"
                ])

    def test_mixed_rules_normalize_deterministically_across_permutations(self):
        allow = MockFirewallRule()
        allow.local_ports = "443"
        block = MockFirewallRule()
        block.local_ports = "53"
        block.protocol = 17
        block.action = 0
        left = collect_windows_firewall_rules_from_collection(fixture(allow, block))

        allow2 = MockFirewallRule()
        allow2.local_ports = "443"
        block2 = MockFirewallRule()
        block2.local_ports = "53"
        block2.protocol = 17
        block2.action = 0
        right = collect_windows_firewall_rules_from_collection(fixture(block2, allow2))
        self.assertEqual(left, right)
        self.assertEqual(
            normalize_windows_firewall_rules(left),
            normalize_windows_firewall_rules(right),
        )

    def test_count_validation_and_limits_fail_closed(self):
        cases = (
            (-1, WindowsFirewallRuleResultCode.INVALID_RESULT),
            (True, WindowsFirewallRuleResultCode.INVALID_RESULT),
            ("1", WindowsFirewallRuleResultCode.INVALID_RESULT),
            (MAX_FIREWALL_RULES + 1,
             WindowsFirewallRuleResultCode.LIMIT_EXCEEDED),
        )
        for count, expected in cases:
            with self.subTest(count=count):
                source = fixture(reported_count=count)
                result = collect_windows_firewall_rules_from_collection(source)
                self.assertEqual(result.state, expected)
                self.assertEqual(result.rules, ())
                self.assertEqual(source.events[-1], "release-rules")

    def test_exact_maximum_count_is_valid_and_bounded(self):
        events = []
        enumerator = MockEnumVariant(events=events, lazy_count=MAX_FIREWALL_RULES)
        source = MockRulesCollection(MAX_FIREWALL_RULES, enumerator, events=events)
        ledger = WindowsComOperationAccounting()
        result = collect_windows_firewall_rules_from_collection(
            source, accounting=ledger
        )
        self.assertEqual(result.state, WindowsFirewallRuleResultCode.COMPLETE)
        self.assertEqual(len(result.rules), MAX_FIREWALL_RULES)
        self.assertEqual(ledger.enumeration_operations,
                         MAX_FIREWALL_ENUMERATION_OPERATIONS)
        self.assertEqual(enumerator.position, MAX_FIREWALL_RULES + 1)

    def test_early_eof_and_over_enumeration_are_incomplete_without_prefix(self):
        early = fixture(MockFirewallRule(), reported_count=2)
        result = collect_windows_firewall_rules_from_collection(early)
        self.assertEqual(result.state,
                         WindowsFirewallRuleResultCode.COLLECTION_INCOMPLETE)
        self.assertEqual(result.rules, ())

        over = fixture(MockFirewallRule(), MockFirewallRule(), reported_count=1)
        result = collect_windows_firewall_rules_from_collection(over)
        self.assertEqual(result.state,
                         WindowsFirewallRuleResultCode.COLLECTION_INCOMPLETE)
        self.assertEqual(result.rules, ())
        self.assertEqual(over.new_enum.enumerator.variant_clears, 2)

    def test_malicious_enumerator_is_bounded(self):
        events = []
        enumerator = MockEnumVariant(events=events,
                                    lazy_count=MAX_FIREWALL_RULES + 1)
        source = MockRulesCollection(MAX_FIREWALL_RULES, enumerator, events=events)
        ledger = WindowsComOperationAccounting()
        result = collect_windows_firewall_rules_from_collection(
            source, accounting=ledger
        )
        self.assertEqual(result.state,
                         WindowsFirewallRuleResultCode.COLLECTION_INCOMPLETE)
        self.assertLessEqual(ledger.enumeration_operations,
                             MAX_FIREWALL_ENUMERATION_OPERATIONS)
        self.assertEqual(enumerator.position, MAX_FIREWALL_RULES + 1)

        exhausted = WindowsComOperationAccounting(
            enumeration_operations=MAX_FIREWALL_ENUMERATION_OPERATIONS
        )
        source = fixture()
        result = collect_windows_firewall_rules_from_collection(
            source, accounting=exhausted
        )
        self.assertEqual(result.state, WindowsFirewallRuleResultCode.LIMIT_EXCEEDED)
        self.assertEqual(source.events, ["release-rules"])

    def test_collection_acquisition_and_next_failures_are_sanitized(self):
        source = fixture()
        source.new_enum_failure = WindowsComFailureCategory.API_UNAVAILABLE
        self.assertEqual(
            collect_windows_firewall_rules_from_collection(source).state,
            WindowsFirewallRuleResultCode.API_UNAVAILABLE,
        )

        source = fixture()
        source.new_enum.query_failure = WindowsComFailureCategory.UNSUPPORTED
        self.assertEqual(
            collect_windows_firewall_rules_from_collection(source).state,
            WindowsFirewallRuleResultCode.UNSUPPORTED,
        )

        source = fixture(MockFirewallRule())
        source.new_enum.enumerator.next_failure_at = 0
        self.assertEqual(
            collect_windows_firewall_rules_from_collection(source).state,
            WindowsFirewallRuleResultCode.ACCESS_DENIED,
        )
        self.assertEqual(source.events[-3:], [
            "release-enumerator", "release-new-enum", "release-rules"
        ])

    def test_every_closed_native_failure_category_maps_without_diagnostics(self):
        for category in WindowsComFailureCategory:
            with self.subTest(category=category):
                source = fixture()
                source.count_failure = category
                result = collect_windows_firewall_rules_from_collection(source)
                self.assertEqual(
                    result.state, WindowsFirewallRuleResultCode(category.value)
                )
                self.assertEqual(result.rules, ())

    def test_success_lifetime_and_accounting_counts_are_exact(self):
        rule = MockFirewallRule()
        source = fixture(rule)
        ledger = WindowsComOperationAccounting()
        result = collect_windows_firewall_rules_from_collection(
            source, accounting=ledger
        )
        self.assertEqual(result.state, WindowsFirewallRuleResultCode.COMPLETE)
        self.assertEqual(source.new_enum.enumerator.variant_initializations, 1)
        self.assertEqual(source.new_enum.enumerator.variant_clears, 1)
        self.assertEqual(rule.released, ["rule3", "rule2", "rule"])
        self.assertEqual(ledger.enumeration_operations, 4)
        self.assertEqual(ledger.property_getters, 19)
        self.assertEqual(ledger.query_interfaces, 4)
        self.assertEqual(ledger.interface_releases, 6)
        self.assertEqual(ledger.cleanup_operations, 7)

    def test_malformed_step_variant_and_rule_interface_fail_closed(self):
        malformed = fixture(MockFirewallRule())
        malformed.new_enum.enumerator.malformed_at = 0
        self.assertEqual(
            collect_windows_firewall_rules_from_collection(malformed).state,
            WindowsFirewallRuleResultCode.INVALID_RESULT,
        )

        malformed_fetched = fixture(MockFirewallRule())
        malformed_fetched.new_enum.enumerator.malformed_fetched_at = 0
        result = collect_windows_firewall_rules_from_collection(malformed_fetched)
        self.assertEqual(result.state, WindowsFirewallRuleResultCode.INVALID_RESULT)
        self.assertEqual(
            malformed_fetched.new_enum.enumerator.variant_clears, 1
        )

        wrong_variant = fixture(MockFirewallRule())
        wrong_variant.new_enum.enumerator.wrong_variant_at = 0
        result = collect_windows_firewall_rules_from_collection(wrong_variant)
        self.assertEqual(result.state, WindowsFirewallRuleResultCode.INVALID_RESULT)
        self.assertEqual(wrong_variant.new_enum.enumerator.variant_clears, 1)

        events = []
        element = MockRuleElement(object(), events)
        source = MockRulesCollection(1, MockEnumVariant((element,), events=events),
                                     events=events)
        self.assertEqual(
            collect_windows_firewall_rules_from_collection(source).state,
            WindowsFirewallRuleResultCode.INVALID_RESULT,
        )

    def test_rule_reader_failure_stops_and_returns_no_prefix(self):
        good = MockFirewallRule()
        bad = MockFirewallRule()
        bad.enabled = "PRIVATE_INVALID_RULE_CANARY"
        source = fixture(good, bad, MockFirewallRule())
        result = collect_windows_firewall_rules_from_collection(source)
        self.assertEqual(result.state, WindowsFirewallRuleResultCode.INVALID_RESULT)
        self.assertEqual(result.rules, ())
        self.assertEqual(source.new_enum.enumerator.position, 2)
        self.assertNotIn("PRIVATE_INVALID_RULE_CANARY", repr(result))

    def test_repeated_dispatch_element_is_rejected_after_variant_cleanup(self):
        events = []
        element = MockRuleElement(MockFirewallRule(), events)
        enumerator = MockEnumVariant((element, element), events=events)
        source = MockRulesCollection(2, enumerator, events=events)
        result = collect_windows_firewall_rules_from_collection(source)
        self.assertEqual(result.state, WindowsFirewallRuleResultCode.INVALID_RESULT)
        self.assertEqual(enumerator.variant_clears, 2)
        self.assertEqual(result.rules, ())

    def test_cleanup_failure_is_sanitized_and_primary_failure_wins(self):
        source = fixture()
        source.release_failure = True
        result = collect_windows_firewall_rules_from_collection(source)
        self.assertEqual(result.state, WindowsFirewallRuleResultCode.INTERNAL_ERROR)
        self.assertNotIn("PRIVATE_RULES_RELEASE_CANARY", repr(result))

        source = fixture(reported_count=-1)
        source.release_failure = True
        result = collect_windows_firewall_rules_from_collection(source)
        self.assertEqual(result.state, WindowsFirewallRuleResultCode.INVALID_RESULT)

    def test_exact_normalized_duplicates_collapse_only_in_normalizer(self):
        source = fixture(MockFirewallRule(), MockFirewallRule())
        raw = collect_windows_firewall_rules_from_collection(source)
        self.assertEqual(raw.state, WindowsFirewallRuleResultCode.COMPLETE)
        self.assertEqual(len(raw.rules), 2)
        normalized = normalize_windows_firewall_rules(raw)
        self.assertEqual(len(normalized.rules), 1)

    def test_normalized_semantic_collision_fails_closed(self):
        first = MockFirewallRule()
        second = MockFirewallRule()
        second.local_ports = "8443"
        with patch(
            "cyberwatchtower.platform.windows.firewall_rules."
            "semantic_firewall_rule_id",
            return_value="a" * 64,
        ):
            result = collect_windows_firewall_rules_from_collection(
                fixture(first, second)
            )
        self.assertEqual(result.state, WindowsFirewallRuleResultCode.INVALID_RESULT)
        self.assertEqual(result.rules, ())

    def test_operation_accounting_keeps_per_rule_getter_limits_separate(self):
        source = fixture(MockFirewallRule(), MockFirewallRule())
        ledger = WindowsComOperationAccounting()
        result = collect_windows_firewall_rules_from_collection(
            source, accounting=ledger
        )
        self.assertEqual(result.state, WindowsFirewallRuleResultCode.COMPLETE)
        self.assertEqual(ledger.enumeration_operations, 5)
        self.assertGreater(ledger.property_getters, 22)
        self.assertEqual(ledger.query_interfaces, 7)
        self.assertEqual(ledger.interface_releases, 9)


class WindowsFirewallRuleCollectionPrivacyAndAuthorityTests(unittest.TestCase):
    def test_private_values_never_escape_success_or_failure(self):
        rule = MockFirewallRule()
        rule.application_name = r"C:\PRIVATE_PATH_CANARY\secret.exe"
        rule.interfaces = ("PRIVATE_INTERFACE_CANARY",)
        complete = collect_windows_firewall_rules_from_collection(fixture(rule))
        rendered = repr(complete)
        self.assertNotIn("PRIVATE_PATH_CANARY", rendered)
        self.assertNotIn("PRIVATE_INTERFACE_CANARY", rendered)
        self.assertNotIn("secret.exe", rendered)

        events = []
        element = MockRuleElement(
            MockFirewallRule(), events,
            failure=WindowsComFailureCategory.INTERNAL_ERROR,
        )
        failed = collect_windows_firewall_rules_from_collection(
            MockRulesCollection(1, MockEnumVariant((element,), events=events),
                                events=events)
        )
        self.assertNotIn("PRIVATE", repr(failed))

    def test_module_has_no_native_execution_or_dynamic_dispatch_surface(self):
        source = inspect.getsource(collection)
        for prohibited in (
            "ctypes", "WinDLL", "CoCreateInstance", "subprocess", "Popen",
            "shell=True", "PowerShell", "netsh", "winreg", "GetIDsOfNames",
            "IDispatch", "Invoke(", "getattr(", "setattr(", "put_", ".Add(",
            ".Remove(", ".Item(",
        ):
            self.assertNotIn(prohibited, source)

    def test_collection_engine_has_no_production_authority_routing(self):
        root = Path(__file__).parents[1] / "src" / "cyberwatchtower"
        targets = (
            root / "platform" / "windows" / "api_native.py",
            root / "platform" / "windows" / "adapter.py",
            root / "scanner.py",
            root / "scoring.py",
            root / "scoring_projection.py",
        )
        targets += tuple((root / "advisor").glob("*.py"))
        targets += tuple((root / "briefing").glob("*.py"))
        targets += tuple((root / "model_gateway").glob("*.py"))
        for target in targets:
            source = target.read_text(encoding="utf-8")
            self.assertNotIn("firewall_rule_collection", source)
            self.assertNotIn("collect_windows_firewall_rules_from_collection",
                             source)


if __name__ == "__main__":
    unittest.main()
