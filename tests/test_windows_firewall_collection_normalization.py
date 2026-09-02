import dataclasses
import ipaddress
import unittest

from cyberwatchtower.firewall_policy import MAX_CONDITIONS_PER_RULE
from cyberwatchtower.platform.windows.firewall_rule_models import (
    RawWindowsFirewallIPv4AddressRange,
    RawWindowsFirewallIPv6AddressRange,
    RawWindowsApplicationPath,
    RawWindowsFirewallRule,
    RawWindowsInterfaceIdentity,
    WindowsFirewallPolicyView,
    WindowsFirewallRuleCollectionResult,
    WindowsFirewallRuleResultCode,
    WindowsRawFirewallRuleAction,
    WindowsRawFirewallRuleDirection,
    WindowsRawFirewallInterfaceType,
    WindowsRawFirewallUnsupportedFeature,
)
from cyberwatchtower.platform.windows.firewall_rules import (
    normalize_windows_firewall_rules,
)


def _rule(**changes):
    values = {
        "policy_view": WindowsFirewallPolicyView.CURRENT_POLICY_VIEW,
        "enabled": True,
        "direction": WindowsRawFirewallRuleDirection.INBOUND,
        "action": WindowsRawFirewallRuleAction.ALLOW,
        "profile_mask": 4,
        "protocol": 6,
        "local_ports": ("443",),
        "local_addresses": ("*",),
    }
    values.update(changes)
    return RawWindowsFirewallRule(**values)


def _result(*rules):
    return WindowsFirewallRuleCollectionResult(
        WindowsFirewallRuleResultCode.COMPLETE,
        WindowsFirewallPolicyView.CURRENT_POLICY_VIEW,
        tuple(rules),
    )


class CompletedCollectionNormalizationTests(unittest.TestCase):
    def test_condition_bound_failure_remains_fail_closed(self):
        addresses = tuple(
            str(ipaddress.IPv4Address(index + 1))
            for index in range(MAX_CONDITIONS_PER_RULE)
        )
        normalized = normalize_windows_firewall_rules(
            _result(_rule(local_addresses=addresses))
        )
        self.assertEqual(
            normalized.failure, WindowsFirewallRuleResultCode.INVALID_RESULT
        )

    def test_neutral_aggregate_condition_bound_64_and_65(self):
        def addresses(count):
            return tuple(
                str(ipaddress.IPv4Address(index + 1)) for index in range(count)
            )

        at_limit = normalize_windows_firewall_rules(_result(_rule(
            local_ports=(), local_addresses=addresses(61)
        )))
        self.assertIsNone(at_limit.failure)

        over_limit = normalize_windows_firewall_rules(_result(_rule(
            local_ports=(), local_addresses=addresses(62)
        )))
        self.assertEqual(
            over_limit.failure, WindowsFirewallRuleResultCode.INVALID_RESULT
        )

    def test_raw_256_value_condition_is_valid_but_neutral_aggregate_rejects(self):
        addresses = tuple(
            str(ipaddress.IPv4Address(index + 1)) for index in range(256)
        )
        raw = _rule(local_ports=(), local_addresses=addresses)
        self.assertEqual(len(raw.local_addresses), 256)
        normalized = normalize_windows_firewall_rules(_result(raw))
        self.assertEqual(
            normalized.failure, WindowsFirewallRuleResultCode.INVALID_RESULT
        )

    def test_exact_duplicates_collapse_after_complete_validation(self):
        rule = _rule()
        normalized = normalize_windows_firewall_rules(_result(rule, rule))
        self.assertIsNone(normalized.failure)
        self.assertEqual(len(normalized.rules), 1)

    def test_distinct_raw_unsupported_origins_can_normalize_identically(self):
        local_user = _rule(unsupported_features=(
            WindowsRawFirewallUnsupportedFeature.LOCAL_USER_SCOPE,
        ))
        package = dataclasses.replace(local_user, unsupported_features=(
            WindowsRawFirewallUnsupportedFeature.PACKAGE_SCOPE,
        ))
        normalized = normalize_windows_firewall_rules(_result(local_user, package))
        self.assertIsNone(normalized.failure)
        self.assertEqual(len(normalized.rules), 1)

    def test_generic_unmodeled_raw_origins_can_normalize_identically(self):
        icmp = _rule(unsupported_features=(
            WindowsRawFirewallUnsupportedFeature.ICMP_TYPE_CONDITION,
        ))
        native = dataclasses.replace(icmp, unsupported_features=(
            WindowsRawFirewallUnsupportedFeature.UNMODELED_NATIVE_PREDICATE,
        ))
        normalized = normalize_windows_firewall_rules(_result(icmp, native))
        self.assertIsNone(normalized.failure)
        self.assertEqual(len(normalized.rules), 1)

    def test_recovered_empty_ports_normalize_with_unsupported_marker(self):
        recovered = _rule(
            local_ports=(), remote_ports=(),
            unsupported_features=(
                WindowsRawFirewallUnsupportedFeature.UNMODELED_NATIVE_PREDICATE,
            ),
        )
        normalized = normalize_windows_firewall_rules(_result(recovered))
        self.assertIsNone(normalized.failure)
        self.assertEqual(normalized.rules[0].local_ports, ())
        self.assertTrue(normalized.rules[0].unsupported_features)

    def test_valid_and_recovered_port_combinations_normalize(self):
        cases = (
            _rule(local_ports=("443",), remote_ports=(), unsupported_features=(
                WindowsRawFirewallUnsupportedFeature.UNMODELED_NATIVE_PREDICATE,
            )),
            _rule(local_ports=(), remote_ports=("443",), unsupported_features=(
                WindowsRawFirewallUnsupportedFeature.UNMODELED_NATIVE_PREDICATE,
            )),
        )
        for rule in cases:
            with self.subTest(local=bool(rule.local_ports)):
                normalized = normalize_windows_firewall_rules(_result(rule))
                self.assertIsNone(normalized.failure)

    def test_mixed_typed_ranges_normalize_and_order_deterministically(self):
        ipv4 = RawWindowsFirewallIPv4AddressRange(
            ipaddress.IPv4Address("192.0.2.1"),
            ipaddress.IPv4Address("192.0.2.20"),
        )
        ipv6 = RawWindowsFirewallIPv6AddressRange(
            ipaddress.IPv6Address("2001:db8::1"),
            ipaddress.IPv6Address("2001:db8::20"),
        )
        forward = normalize_windows_firewall_rules(_result(
            _rule(local_addresses=(ipv4,)),
            _rule(local_addresses=(ipv6,)),
        ))
        reverse = normalize_windows_firewall_rules(_result(
            _rule(local_addresses=(ipv6,)),
            _rule(local_addresses=(ipv4,)),
        ))
        self.assertIsNone(forward.failure)
        self.assertEqual(forward.rules, reverse.rules)

    def test_legitimate_field_matrix_normalizes(self):
        cases = (
            _rule(protocol=6),
            _rule(protocol=17),
            _rule(protocol=256, local_ports=()),
            _rule(local_ports=(), remote_ports=()),
            _rule(local_ports=("80", "443", "1000-2000")),
            _rule(local_addresses=("192.0.2.1",)),
            _rule(local_addresses=("2001:db8::1",)),
            _rule(local_addresses=("192.0.2.0/24",)),
            _rule(local_addresses=("2001:db8::/64",)),
            _rule(application_path=RawWindowsApplicationPath(
                "C:\\Program Files\\Synthetic\\app.exe"
            )),
            _rule(service_name="Synthetic.Service"),
            _rule(interfaces=(RawWindowsInterfaceIdentity("Synthetic Interface"),)),
            _rule(interface_types=(WindowsRawFirewallInterfaceType.LAN,)),
            _rule(edge_traversal=False),
            _rule(edge_traversal=True),
            _rule(unsupported_features=tuple(
                WindowsRawFirewallUnsupportedFeature
            )),
        )
        for number, rule in enumerate(cases):
            with self.subTest(case=number):
                normalized = normalize_windows_firewall_rules(_result(rule))
                self.assertIsNone(normalized.failure)

    def test_unrepresentable_application_recovers_and_interface_remains_fail_closed(self):
        unrepresentable_application = _rule(
            application_path=RawWindowsApplicationPath("relative\\app.exe")
        )
        normalized = normalize_windows_firewall_rules(
            _result(unrepresentable_application)
        )
        self.assertIsNone(normalized.failure)
        self.assertTrue(normalized.rules[0].unsupported_features)

        blank_interface = _rule(
            interfaces=(RawWindowsInterfaceIdentity("   "),)
        )
        normalized = normalize_windows_firewall_rules(_result(blank_interface))
        self.assertEqual(
            normalized.failure, WindowsFirewallRuleResultCode.INVALID_RESULT
        )
        rendered = repr(normalized)
        self.assertNotIn("relative", rendered)
        self.assertNotIn("Synthetic", rendered)


if __name__ == "__main__":
    unittest.main()
