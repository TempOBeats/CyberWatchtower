import dataclasses
import ipaddress
import unittest

from cyberwatchtower.firewall_policy import (
    AddressConditionKind,
    ApplicationConditionKind,
    FirewallAddressCondition,
    FirewallApplicationCondition,
    FirewallIPv4AddressRange,
    FirewallInterfaceCondition,
    FirewallPlatformTechnology,
    FirewallPortRange,
    FirewallRuleAction,
    FirewallRuleApplicability,
    FirewallRuleDirection,
    FirewallRuleEnabledState,
    FirewallRuleObservation,
    FirewallRuleUnsupportedFeature,
    InterfaceConditionKind,
    ListenerPolicySubject,
    evaluate_listener_policy,
    semantic_firewall_rule_id,
)
from cyberwatchtower.platform.models import BindExposure, FirewallProfile, NetworkProtocol
from cyberwatchtower.platform.windows.firewall_com_contracts import (
    WindowsComContractError,
    WindowsComFailureCategory,
)
from cyberwatchtower.platform.windows.firewall_rule_ipc import (
    WindowsFirewallHelperResponse,
    WindowsFirewallIpcV2Address,
    WindowsFirewallIpcV2AddressKind,
    WindowsFirewallIpcV2Rule,
    WindowsFirewallIpcV2Response,
    decode_windows_firewall_ipc_v2_response,
    encode_windows_firewall_helper_response,
    encode_windows_firewall_ipc_v2_response,
    windows_firewall_ipc_v2_address_to_raw,
    windows_firewall_ipc_v2_rule_to_raw,
    windows_firewall_raw_address_to_ipc_v2,
    windows_firewall_raw_rule_to_ipc_v2,
)
from cyberwatchtower.platform.windows.firewall_rule_models import (
    RawWindowsFirewallIPv4AddressRange,
    RawWindowsFirewallRule,
    WindowsFirewallPolicyView,
    WindowsFirewallRuleCollectionResult,
    WindowsFirewallRuleResultCode,
    WindowsRawFirewallRuleAction,
    WindowsRawFirewallRuleDirection,
)
from cyberwatchtower.platform.windows.firewall_rules import (
    normalize_windows_firewall_rules,
)
from cyberwatchtower.report_contracts import CoverageState


VIEW = WindowsFirewallPolicyView.CURRENT_POLICY_VIEW


def _raw_rule(**changes):
    values = {
        "policy_view": VIEW,
        "enabled": True,
        "direction": WindowsRawFirewallRuleDirection.INBOUND,
        "action": WindowsRawFirewallRuleAction.ALLOW,
        "profile_mask": 4,
        "protocol": 6,
        "local_ports": ("443",),
        "local_addresses": ("*",),
        "remote_addresses": (),
    }
    values.update(changes)
    return RawWindowsFirewallRule(**values)


def _neutral_rule(*, action=FirewallRuleAction.ALLOW, local_addresses=(),
                  remote_addresses=(), unsupported=()):
    values = {
        "technology": FirewallPlatformTechnology.WINDOWS_FIREWALL,
        "enabled": FirewallRuleEnabledState.ENABLED,
        "direction": FirewallRuleDirection.INBOUND,
        "action": action,
        "profiles": (FirewallProfile.PUBLIC,),
        "protocol": NetworkProtocol.TCP,
        "local_ports": (FirewallPortRange(443, 443),),
        "local_addresses": local_addresses,
        "remote_addresses": remote_addresses,
        "application": FirewallApplicationCondition(ApplicationConditionKind.ANY),
        "interface": FirewallInterfaceCondition(InterfaceConditionKind.ANY),
        "edge_traversal": False,
        "unsupported_features": unsupported,
    }
    return FirewallRuleObservation(semantic_firewall_rule_id(**values), **values)


def _subject(address="192.0.2.10"):
    return ListenerPolicySubject(
        NetworkProtocol.TCP, 443, BindExposure.INTERFACE, address,
        (FirewallProfile.PUBLIC,),
    )


class RawAndNeutralRangeContractTests(unittest.TestCase):
    def test_raw_range_is_closed_immutable_ordered_and_ipv4_only(self):
        low = ipaddress.IPv4Address("0.0.0.0")
        high = ipaddress.IPv4Address("255.255.255.255")
        value = RawWindowsFirewallIPv4AddressRange(low, high)
        self.assertEqual((value.start, value.end), (low, high))
        self.assertFalse(hasattr(value, "__dict__"))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            value.start = high
        self.assertEqual(
            RawWindowsFirewallIPv4AddressRange(low, low),
            RawWindowsFirewallIPv4AddressRange(ipaddress.IPv4Address(0), low),
        )
        invalid = (
            (high, low),
            (ipaddress.IPv6Address("::1"), high),
            (low, ipaddress.IPv6Address("::1")),
            ("192.0.2.1", high),
            (low, 1),
        )
        for start, end in invalid:
            with self.subTest(start_type=type(start), end_type=type(end)), \
                    self.assertRaises((TypeError, ValueError)):
                RawWindowsFirewallIPv4AddressRange(start, end)

    def test_neutral_range_and_condition_kind_value_contract_are_closed(self):
        start = ipaddress.IPv4Address("192.0.2.1")
        end = ipaddress.IPv4Address("192.0.2.20")
        value = FirewallIPv4AddressRange(start, end)
        condition = FirewallAddressCondition(AddressConditionKind.IPV4_RANGE, value)
        self.assertEqual(condition.value, value)
        self.assertFalse(hasattr(value, "__dict__"))
        invalid_conditions = (
            (AddressConditionKind.IPV4_RANGE, None),
            (AddressConditionKind.IPV4_RANGE, "192.0.2.1-192.0.2.20"),
            (AddressConditionKind.EXACT, value),
            (AddressConditionKind.ANY, value),
        )
        for kind, invalid in invalid_conditions:
            with self.subTest(kind=kind), self.assertRaises((TypeError, ValueError)):
                FirewallAddressCondition(kind, invalid)


class V2RawBridgeTests(unittest.TestCase):
    def test_every_v2_address_kind_round_trips_through_raw_domain(self):
        values = (
            WindowsFirewallIpcV2Address(WindowsFirewallIpcV2AddressKind.ANY),
            WindowsFirewallIpcV2Address(
                WindowsFirewallIpcV2AddressKind.LOCAL_SUBNET
            ),
            WindowsFirewallIpcV2Address(
                WindowsFirewallIpcV2AddressKind.IPV4, "192.0.2.1"
            ),
            WindowsFirewallIpcV2Address(
                WindowsFirewallIpcV2AddressKind.IPV6, "2001:db8::1"
            ),
            WindowsFirewallIpcV2Address(
                WindowsFirewallIpcV2AddressKind.IPV4_CIDR, "192.0.2.99/24"
            ),
            WindowsFirewallIpcV2Address(
                WindowsFirewallIpcV2AddressKind.IPV6_CIDR, "2001:db8::1/32"
            ),
            WindowsFirewallIpcV2Address(
                WindowsFirewallIpcV2AddressKind.IPV4_RANGE,
                start="192.0.2.1", end="192.0.2.20",
            ),
        )
        for value in values:
            with self.subTest(kind=value.kind):
                raw = windows_firewall_ipc_v2_address_to_raw(value)
                self.assertEqual(windows_firewall_raw_address_to_ipc_v2(raw), value)
        dotted = windows_firewall_raw_address_to_ipc_v2("192.0.2.99/255.255.255.0")
        self.assertEqual(dotted.kind, WindowsFirewallIpcV2AddressKind.IPV4_CIDR)
        self.assertEqual(dotted.value, "192.0.2.0/24")
        with self.assertRaises(WindowsComContractError) as caught:
            windows_firewall_raw_address_to_ipc_v2("PRIVATE_ARBITRARY_TEXT")
        self.assertEqual(caught.exception.category,
                         WindowsComFailureCategory.INVALID_RESULT)
        self.assertNotIn("PRIVATE", str(caught.exception))

    def test_complete_rule_bridge_preserves_structural_range(self):
        wire_range = WindowsFirewallIpcV2Address(
            WindowsFirewallIpcV2AddressKind.IPV4_RANGE,
            start="198.51.100.1", end="198.51.100.20",
        )
        wire = WindowsFirewallIpcV2Rule(
            True, WindowsRawFirewallRuleDirection.INBOUND,
            WindowsRawFirewallRuleAction.ALLOW, 4, 6,
            local_ports=("443",), remote_addresses=(wire_range,),
        )
        raw = windows_firewall_ipc_v2_rule_to_raw(wire)
        self.assertIsInstance(raw.remote_addresses[0],
                              RawWindowsFirewallIPv4AddressRange)
        self.assertEqual(windows_firewall_raw_rule_to_ipc_v2(raw), wire)
        self.assertNotIn("198.51.100.1-198.51.100.20", repr(raw))


class NormalizationIdentityAndApplicabilityTests(unittest.TestCase):
    def test_range_normalizes_structurally_without_changing_existing_forms(self):
        raw_range = RawWindowsFirewallIPv4AddressRange(
            ipaddress.IPv4Address("192.0.2.1"),
            ipaddress.IPv4Address("192.0.2.20"),
        )
        raw = _raw_rule(local_addresses=(
            "LocalSubnet", "198.51.100.1", "198.51.100.0/24", raw_range,
        ))
        normalized = normalize_windows_firewall_rules(
            WindowsFirewallRuleCollectionResult(
                WindowsFirewallRuleResultCode.COMPLETE, VIEW, (raw,)
            )
        )
        self.assertIsNone(normalized.failure)
        addresses = normalized.rules[0].local_addresses
        self.assertEqual({value.kind for value in addresses}, {
            AddressConditionKind.SUPPORTED_SPECIAL_SCOPE,
            AddressConditionKind.EXACT,
            AddressConditionKind.CIDR,
            AddressConditionKind.IPV4_RANGE,
        })
        range_condition = next(
            value for value in addresses
            if value.kind == AddressConditionKind.IPV4_RANGE
        )
        self.assertIsInstance(range_condition.value, FirewallIPv4AddressRange)
        self.assertNotIsInstance(range_condition.value, str)
        self.assertIn(
            FirewallRuleUnsupportedFeature.UNMODELED_PLATFORM_PREDICATE,
            normalized.rules[0].unsupported_features,
        )

    def test_range_semantic_identity_is_structural_and_distinct(self):
        first = FirewallIPv4AddressRange(
            ipaddress.IPv4Address("192.0.2.1"),
            ipaddress.IPv4Address("192.0.2.20"),
        )
        equivalent = FirewallIPv4AddressRange(
            ipaddress.IPv4Address(int(first.start)),
            ipaddress.IPv4Address(int(first.end)),
        )
        range_rule = _neutral_rule(local_addresses=(
            FirewallAddressCondition(AddressConditionKind.IPV4_RANGE, first),
        ))
        same = _neutral_rule(local_addresses=(
            FirewallAddressCondition(AddressConditionKind.IPV4_RANGE, equivalent),
        ))
        changed_start = _neutral_rule(local_addresses=(
            FirewallAddressCondition(
                AddressConditionKind.IPV4_RANGE,
                FirewallIPv4AddressRange(ipaddress.IPv4Address("192.0.2.2"), first.end),
            ),
        ))
        changed_end = _neutral_rule(local_addresses=(
            FirewallAddressCondition(
                AddressConditionKind.IPV4_RANGE,
                FirewallIPv4AddressRange(first.start, ipaddress.IPv4Address("192.0.2.21")),
            ),
        ))
        exact = _neutral_rule(local_addresses=(
            FirewallAddressCondition(AddressConditionKind.EXACT, "192.0.2.1"),
        ))
        cidr = _neutral_rule(local_addresses=(
            FirewallAddressCondition(AddressConditionKind.CIDR, "192.0.2.0/24"),
        ))
        self.assertEqual(range_rule.semantic_rule_id, same.semantic_rule_id)
        self.assertEqual(len({
            range_rule.semantic_rule_id, changed_start.semantic_rule_id,
            changed_end.semantic_rule_id, exact.semantic_rule_id,
            cidr.semantic_rule_id,
        }), 5)

    def test_local_and_remote_ranges_are_conservatively_incomplete(self):
        condition = FirewallAddressCondition(
            AddressConditionKind.IPV4_RANGE,
            FirewallIPv4AddressRange(
                ipaddress.IPv4Address("192.0.2.1"),
                ipaddress.IPv4Address("192.0.2.20"),
            ),
        )
        marker = (FirewallRuleUnsupportedFeature.UNMODELED_PLATFORM_PREDICATE,)
        for action in (FirewallRuleAction.ALLOW, FirewallRuleAction.BLOCK):
            for changes in (
                {"local_addresses": (condition,), "unsupported": marker},
                {"remote_addresses": (condition,), "unsupported": marker},
            ):
                with self.subTest(action=action, changes=changes):
                    result = evaluate_listener_policy(
                        _subject(), (_neutral_rule(action=action, **changes),),
                        CoverageState.COMPLETE,
                    )
                    self.assertEqual(result.applicability,
                                     FirewallRuleApplicability.INCOMPLETE)
        for condition in (
            FirewallAddressCondition(AddressConditionKind.ANY),
            FirewallAddressCondition(AddressConditionKind.EXACT, "192.0.2.10"),
            FirewallAddressCondition(AddressConditionKind.CIDR, "192.0.2.0/24"),
        ):
            result = evaluate_listener_policy(
                _subject(), (_neutral_rule(local_addresses=(condition,)),),
                CoverageState.COMPLETE,
            )
            self.assertEqual(result.applicability,
                             FirewallRuleApplicability.MATCHING_ALLOW)


class ProductionRangeIntegrationTests(unittest.TestCase):
    def test_range_text_becomes_typed_but_typed_range_cannot_cross_v1(self):
        parsed = _raw_rule(local_addresses=("192.0.2.1-192.0.2.20",))
        self.assertIsInstance(
            parsed.local_addresses[0], RawWindowsFirewallIPv4AddressRange
        )
        typed = RawWindowsFirewallIPv4AddressRange(
            ipaddress.IPv4Address("192.0.2.1"),
            ipaddress.IPv4Address("192.0.2.20"),
        )
        raw = _raw_rule(local_addresses=(typed,))
        response = WindowsFirewallHelperResponse(
            "1", VIEW, WindowsFirewallRuleCollectionResult(
                WindowsFirewallRuleResultCode.COMPLETE, VIEW, (raw,)
            )
        )
        with self.assertRaises(WindowsComContractError) as caught:
            encode_windows_firewall_helper_response(response)
        self.assertEqual(caught.exception.category,
                         WindowsComFailureCategory.INVALID_RESULT)
        self.assertNotIn("192.0.2.1", str(caught.exception))

    def test_shared_parser_accepts_only_strict_ipv4_ranges(self):
        for field in ("local_addresses", "remote_addresses"):
            for expression in (
                "0.0.0.0-255.255.255.255",
                "192.0.2.10-192.0.2.10",
            ):
                with self.subTest(field=field, expression=expression):
                    parsed = _raw_rule(**{field: (expression,)})
                    value = getattr(parsed, field)[0]
                    self.assertIsInstance(
                        value, RawWindowsFirewallIPv4AddressRange
                    )
                    self.assertNotIsInstance(value, str)
                    self.assertNotIn(expression, repr(value))
        invalid = (
            "192.0.2.20-192.0.2.1",
            "192.0.2.1-2001:db8::1", "-192.0.2.1", "192.0.2.1-",
            "192.0.2.1-192.0.2.2-192.0.2.3", "DefaultGateway", "DHCP",
            "DNS", "WINS", "arbitrary", "192.0.2.1 - 192.0.2.2",
        )
        for expression in invalid:
            with self.subTest(expression=expression), self.assertRaises(ValueError):
                _raw_rule(remote_addresses=(expression,))

    def test_v2_pipeline_preserves_range_to_conservative_policy(self):
        raw = _raw_rule(
            remote_addresses=("198.51.100.1-198.51.100.20",)
        )
        wire_rule = windows_firewall_raw_rule_to_ipc_v2(raw)
        encoded = encode_windows_firewall_ipc_v2_response(
            WindowsFirewallIpcV2Response(
                "2", VIEW, WindowsFirewallRuleResultCode.COMPLETE, (wire_rule,)
            )
        )
        decoded = decode_windows_firewall_ipc_v2_response(encoded)
        parent_raw = windows_firewall_ipc_v2_rule_to_raw(decoded.rules[0])
        self.assertIsInstance(
            parent_raw.remote_addresses[0],
            RawWindowsFirewallIPv4AddressRange,
        )
        normalized = normalize_windows_firewall_rules(
            WindowsFirewallRuleCollectionResult(
                WindowsFirewallRuleResultCode.COMPLETE, VIEW, (parent_raw,)
            )
        )
        self.assertIsNone(normalized.failure)
        condition = normalized.rules[0].remote_addresses[0]
        self.assertEqual(condition.kind, AddressConditionKind.IPV4_RANGE)
        self.assertIsInstance(condition.value, FirewallIPv4AddressRange)
        result = evaluate_listener_policy(
            _subject(), normalized.rules, CoverageState.COMPLETE
        )
        self.assertEqual(result.applicability, FirewallRuleApplicability.INCOMPLETE)
        self.assertNotIn("198.51.100.1-198.51.100.20", repr(parent_raw))


if __name__ == "__main__":
    unittest.main()
