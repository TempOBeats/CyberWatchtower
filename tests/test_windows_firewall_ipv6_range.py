import dataclasses
import ipaddress
import json
import unittest

from cyberwatchtower.firewall_policy import (
    AddressConditionKind,
    FirewallAddressCondition,
    FirewallIPv4AddressRange,
    FirewallIPv6AddressRange,
    FirewallRuleApplicability,
    FirewallRuleAction,
    FirewallRuleUnsupportedFeature,
    evaluate_listener_policy,
)
from cyberwatchtower.platform.windows.firewall_com_contracts import (
    WindowsComContractError,
    WindowsComFailureCategory,
)
from cyberwatchtower.platform.windows.firewall_rule_ipc import (
    WindowsFirewallHelperResponse,
    WindowsFirewallIpcPayload,
    WindowsFirewallIpcPayloadKind,
    WindowsFirewallIpcV2Address,
    WindowsFirewallIpcV2AddressKind,
    WindowsFirewallIpcV2Response,
    WindowsFirewallIpcV2Rule,
    decode_windows_firewall_ipc_v2_response,
    encode_windows_firewall_helper_response,
    encode_windows_firewall_ipc_v2_response,
    windows_firewall_ipc_v2_address_to_raw,
    windows_firewall_raw_address_to_ipc_v2,
)
from cyberwatchtower.platform.windows.firewall_rule_models import (
    RawWindowsFirewallIPv4AddressRange,
    RawWindowsFirewallIPv6AddressRange,
    RawWindowsFirewallRule,
    WindowsFirewallPolicyView,
    WindowsFirewallRuleCollectionResult,
    WindowsFirewallRuleResultCode,
    WindowsRawFirewallRuleAction,
    WindowsRawFirewallRuleDirection,
    _raw_address,
)
from cyberwatchtower.platform.windows.firewall_rules import (
    normalize_windows_firewall_rules,
)
from cyberwatchtower.report_contracts import CoverageState
from tests.test_windows_firewall_ipv4_range import _neutral_rule, _subject


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
    }
    values.update(changes)
    return RawWindowsFirewallRule(**values)


def _wire_rule(addresses):
    return WindowsFirewallIpcV2Rule(
        True, WindowsRawFirewallRuleDirection.INBOUND,
        WindowsRawFirewallRuleAction.ALLOW, 4, 6,
        local_ports=("443",), remote_addresses=tuple(addresses),
    )


class IPv6RangeWireTests(unittest.TestCase):
    def test_valid_ranges_canonicalize_sort_and_serialize_deterministically(self):
        expanded = WindowsFirewallIpcV2Address(
            WindowsFirewallIpcV2AddressKind.IPV6_RANGE,
            start="2001:0db8:0000:0000:0000:0000:0000:0001",
            end="2001:0db8:0000:0000:0000:0000:0000:0009",
        )
        equal = WindowsFirewallIpcV2Address(
            WindowsFirewallIpcV2AddressKind.IPV6_RANGE,
            start="2001:db8::10", end="2001:db8::10",
        )
        self.assertEqual((expanded.start, expanded.end),
                         ("2001:db8::1", "2001:db8::9"))
        response = WindowsFirewallIpcV2Response(
            "2", VIEW, WindowsFirewallRuleResultCode.COMPLETE,
            (_wire_rule((equal, expanded)),),
        )
        first = encode_windows_firewall_ipc_v2_response(response)
        second = encode_windows_firewall_ipc_v2_response(response)
        self.assertEqual(first.consume_inside_boundary(),
                         second.consume_inside_boundary())
        self.assertEqual(decode_windows_firewall_ipc_v2_response(first), response)
        self.assertNotIn("2001:db8", repr(first))

    def test_invalid_range_objects_and_arrays_fail_closed(self):
        invalid = (
            {"start": "192.0.2.1", "end": "192.0.2.2"},
            {"start": "2001:db8::1", "end": "192.0.2.2"},
            {"start": "2001:db8::9", "end": "2001:db8::1"},
            {"start": "bad", "end": "2001:db8::1"},
            {"start": 1, "end": "2001:db8::1"},
            {"start": None, "end": "2001:db8::1"},
        )
        for values in invalid:
            with self.subTest(values=values), self.assertRaises(ValueError):
                WindowsFirewallIpcV2Address(
                    WindowsFirewallIpcV2AddressKind.IPV6_RANGE, **values
                )
        value = WindowsFirewallIpcV2Address(
            WindowsFirewallIpcV2AddressKind.IPV6_RANGE,
            start="2001:db8::1", end="2001:db8::9",
        )
        for addresses in ((value, value), (
            WindowsFirewallIpcV2Address(WindowsFirewallIpcV2AddressKind.ANY),
            value,
        )):
            with self.assertRaises(ValueError):
                _wire_rule(addresses)

    def test_exact_wire_shape_and_malformed_json_members_are_rejected(self):
        address = WindowsFirewallIpcV2Address(
            WindowsFirewallIpcV2AddressKind.IPV6_RANGE,
            start="2001:db8::1", end="2001:db8::9",
        )
        response = WindowsFirewallIpcV2Response(
            "2", VIEW, WindowsFirewallRuleResultCode.COMPLETE,
            (_wire_rule((address,)),),
        )
        data = json.loads(encode_windows_firewall_ipc_v2_response(
            response
        ).consume_inside_boundary())
        encoded = data["rules"][0]["remote_addresses"][0]
        self.assertEqual(encoded, {
            "end": "2001:db8::9", "kind": "IPV6_RANGE",
            "start": "2001:db8::1",
        })
        for mutation in (
            {"kind": "IPV6_RANGE", "end": "2001:db8::9"},
            {"kind": "IPV6_RANGE", "start": "2001:db8::1"},
            {**encoded, "extra": "PRIVATE"},
            {"kind": "UNKNOWN", "start": "2001:db8::1",
             "end": "2001:db8::9"},
            "2001:db8::1-2001:db8::9",
        ):
            candidate = json.loads(json.dumps(data))
            candidate["rules"][0]["remote_addresses"] = [mutation]
            payload = WindowsFirewallIpcPayload(
                WindowsFirewallIpcPayloadKind.RESPONSE,
                json.dumps(candidate, separators=(",", ":")).encode(),
            )
            with self.assertRaises(WindowsComContractError):
                decode_windows_firewall_ipc_v2_response(payload)


class IPv6RangeDomainTests(unittest.TestCase):
    def test_raw_and_neutral_types_are_closed_immutable_and_ordered(self):
        low, high = ipaddress.IPv6Address("::"), ipaddress.IPv6Address("ffff::")
        for range_type in (
            RawWindowsFirewallIPv6AddressRange, FirewallIPv6AddressRange,
        ):
            value = range_type(low, high)
            self.assertEqual(range_type(low, low).start, low)
            self.assertFalse(hasattr(value, "__dict__"))
            with self.assertRaises(dataclasses.FrozenInstanceError):
                value.start = high
            for start, end in (
                (high, low), (ipaddress.IPv4Address("192.0.2.1"), high),
                (low, ipaddress.IPv4Address("192.0.2.1")), ("::1", high),
                (low, object()),
            ):
                with self.assertRaises((TypeError, ValueError)):
                    range_type(start, end)
        ipv6_range = FirewallIPv6AddressRange(low, high)
        ipv4_range = FirewallIPv4AddressRange(
            ipaddress.IPv4Address("192.0.2.1"),
            ipaddress.IPv4Address("192.0.2.9"),
        )
        invalid_conditions = (
            (AddressConditionKind.IPV6_RANGE, None),
            (AddressConditionKind.IPV6_RANGE, "::1-::9"),
            (AddressConditionKind.IPV6_RANGE, ipaddress.IPv6Network("::/64")),
            (AddressConditionKind.IPV6_RANGE, ipv4_range),
            (AddressConditionKind.IPV4_RANGE, ipv6_range),
            (AddressConditionKind.EXACT, ipv6_range),
            (AddressConditionKind.ANY, ipv6_range),
        )
        for kind, value in invalid_conditions:
            with self.assertRaises((TypeError, ValueError)):
                FirewallAddressCondition(kind, value)

    def test_bridges_are_structural_and_v1_rejects_typed_range(self):
        wire = WindowsFirewallIpcV2Address(
            WindowsFirewallIpcV2AddressKind.IPV6_RANGE,
            start="2001:0db8::1", end="2001:db8::9",
        )
        raw = windows_firewall_ipc_v2_address_to_raw(wire)
        self.assertIsInstance(raw, RawWindowsFirewallIPv6AddressRange)
        self.assertEqual(windows_firewall_raw_address_to_ipc_v2(raw), wire)
        self.assertNotIn("2001:db8::1-2001:db8::9", repr(raw))
        rule = _raw_rule(remote_addresses=(raw,))
        response = WindowsFirewallHelperResponse(
            "1", VIEW, WindowsFirewallRuleCollectionResult(
                WindowsFirewallRuleResultCode.COMPLETE, VIEW, (rule,)
            ),
        )
        with self.assertRaises(WindowsComContractError) as caught:
            encode_windows_firewall_helper_response(response)
        self.assertEqual(caught.exception.category,
                         WindowsComFailureCategory.INVALID_RESULT)

    def test_native_text_parser_accepts_only_strict_family_ranges(self):
        examples = (
            ("2001:db8::1-2001:db8::9", "2001:db8::1", "2001:db8::9"),
            (
                "2001:0db8:0000:0000:0000:0000:0000:0001-"
                "2001:0db8:0000:0000:0000:0000:0000:0009",
                "2001:db8::1", "2001:db8::9",
            ),
            ("2001:db8::5-2001:db8::5", "2001:db8::5", "2001:db8::5"),
        )
        for expression, start, end in examples:
            parsed_v6 = _raw_address(expression, "redacted")
            self.assertIsInstance(parsed_v6, RawWindowsFirewallIPv6AddressRange)
            self.assertEqual(str(parsed_v6.start), start)
            self.assertEqual(str(parsed_v6.end), end)
            self.assertNotIsInstance(parsed_v6, str)
            self.assertNotIn(expression, repr(parsed_v6))
        parsed = _raw_address("192.0.2.1-192.0.2.9", "redacted")
        self.assertIsInstance(parsed, RawWindowsFirewallIPv4AddressRange)
        invalid = (
            "2001:db8::9-2001:db8::1", "192.0.2.1-2001:db8::1",
            "2001:db8::1-192.0.2.1", "-2001:db8::1", "2001:db8::1-",
            "2001:db8::1-2001:db8::2-extra", "2001:db8::gg-2001:db8::2",
            "2001:db8::1 - 2001:db8::2", "DefaultGateway", "DHCP",
            "DNS", "WINS", "arbitrary",
        )
        for expression in invalid:
            with self.assertRaises(ValueError):
                _raw_address(expression, "redacted")

    def test_normalization_identity_and_applicability_are_conservative(self):
        raw_range = _raw_address(
            "2001:db8::1-2001:db8::9", "redacted"
        )
        self.assertIsInstance(raw_range, RawWindowsFirewallIPv6AddressRange)
        raw = _raw_rule(remote_addresses=(raw_range,))
        normalized = normalize_windows_firewall_rules(
            WindowsFirewallRuleCollectionResult(
                WindowsFirewallRuleResultCode.COMPLETE, VIEW, (raw,)
            )
        )
        self.assertIsNone(normalized.failure)
        condition = normalized.rules[0].remote_addresses[0]
        self.assertEqual(condition.kind, AddressConditionKind.IPV6_RANGE)
        self.assertIsInstance(condition.value, FirewallIPv6AddressRange)
        self.assertIn(
            FirewallRuleUnsupportedFeature.UNMODELED_PLATFORM_PREDICATE,
            normalized.rules[0].unsupported_features,
        )
        same = _neutral_rule(remote_addresses=(condition,), unsupported=(
            FirewallRuleUnsupportedFeature.UNMODELED_PLATFORM_PREDICATE,
        ))
        changed = FirewallAddressCondition(
            AddressConditionKind.IPV6_RANGE,
            FirewallIPv6AddressRange(
                ipaddress.IPv6Address("2001:db8::2"), raw_range.end
            ),
        )
        different = _neutral_rule(remote_addresses=(changed,), unsupported=(
            FirewallRuleUnsupportedFeature.UNMODELED_PLATFORM_PREDICATE,
        ))
        changed_end = _neutral_rule(remote_addresses=(FirewallAddressCondition(
            AddressConditionKind.IPV6_RANGE,
            FirewallIPv6AddressRange(
                raw_range.start, ipaddress.IPv6Address("2001:db8::a")
            ),
        ),))
        exact = _neutral_rule(remote_addresses=(FirewallAddressCondition(
            AddressConditionKind.EXACT, "2001:db8::1"
        ),))
        cidr = _neutral_rule(remote_addresses=(FirewallAddressCondition(
            AddressConditionKind.CIDR, "2001:db8::/64"
        ),))
        ipv4 = _neutral_rule(remote_addresses=(FirewallAddressCondition(
            AddressConditionKind.IPV4_RANGE,
            FirewallIPv4AddressRange(
                ipaddress.IPv4Address("192.0.2.1"),
                ipaddress.IPv4Address("192.0.2.9"),
            ),
        ),))
        self.assertNotEqual(same.semantic_rule_id, different.semantic_rule_id)
        self.assertNotEqual(same.semantic_rule_id, ipv4.semantic_rule_id)
        self.assertEqual(len({
            same.semantic_rule_id, different.semantic_rule_id,
            changed_end.semantic_rule_id, exact.semantic_rule_id,
            cidr.semantic_rule_id, ipv4.semantic_rule_id,
        }), 6)
        for action in (FirewallRuleAction.ALLOW, FirewallRuleAction.BLOCK):
            rule = _neutral_rule(
                action=action, remote_addresses=(condition,), unsupported=(
                    FirewallRuleUnsupportedFeature.UNMODELED_PLATFORM_PREDICATE,
                ),
            )
            result = evaluate_listener_policy(
                _subject("2001:db8::5"), (rule,), CoverageState.COMPLETE
            )
            self.assertEqual(result.applicability,
                             FirewallRuleApplicability.INCOMPLETE)


if __name__ == "__main__":
    unittest.main()
