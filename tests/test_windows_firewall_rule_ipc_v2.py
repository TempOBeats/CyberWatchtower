import json
import unittest

from cyberwatchtower.platform.windows.firewall_com_contracts import (
    WindowsComContractError,
    WindowsComFailureCategory,
)
from cyberwatchtower.platform.windows.firewall_rule_ipc import (
    MAX_WINDOWS_FIREWALL_IPC_RESPONSE_BYTES,
    WINDOWS_FIREWALL_IPC_PROTOCOL_VERSION,
    WINDOWS_FIREWALL_IPC_PROTOCOL_VERSION_V2,
    WindowsFirewallHelperRequest,
    WindowsFirewallIpcPayload,
    WindowsFirewallIpcPayloadKind,
    WindowsFirewallIpcV2Address,
    WindowsFirewallIpcV2AddressKind,
    WindowsFirewallIpcV2Request,
    WindowsFirewallIpcV2Response,
    WindowsFirewallIpcV2Rule,
    decode_windows_firewall_helper_request,
    decode_windows_firewall_helper_response,
    decode_windows_firewall_ipc_request_for_version,
    decode_windows_firewall_ipc_response_for_version,
    decode_windows_firewall_ipc_v2_request,
    decode_windows_firewall_ipc_v2_response,
    encode_windows_firewall_helper_request,
    encode_windows_firewall_ipc_v2_request,
    encode_windows_firewall_ipc_v2_response,
)
from cyberwatchtower.platform.windows.firewall_rule_models import (
    RawWindowsApplicationPath,
    RawWindowsInterfaceIdentity,
    WindowsFirewallPolicyView,
    WindowsFirewallRuleResultCode,
    WindowsRawFirewallRuleAction,
    WindowsRawFirewallRuleDirection,
)


def _address(kind, value=None, *, start=None, end=None):
    return WindowsFirewallIpcV2Address(kind, value, start, end)


def _rule(*, local=(), remote=(), path=None, interface=None):
    return WindowsFirewallIpcV2Rule(
        enabled=True,
        direction=WindowsRawFirewallRuleDirection.INBOUND,
        action=WindowsRawFirewallRuleAction.ALLOW,
        profile_mask=4,
        protocol=6,
        local_ports=("443",),
        local_addresses=tuple(local),
        remote_addresses=tuple(remote),
        application_path=RawWindowsApplicationPath(path) if path else None,
        interfaces=(RawWindowsInterfaceIdentity(interface),) if interface else (),
        edge_traversal=False,
    )


def _response(*rules, result=WindowsFirewallRuleResultCode.COMPLETE):
    return WindowsFirewallIpcV2Response(
        "2", WindowsFirewallPolicyView.CURRENT_POLICY_VIEW, result, tuple(rules)
    )


def _wire_rule(addresses):
    return {
        "action": "ALLOW", "application_path": None,
        "direction": "INBOUND", "edge_traversal": False,
        "enabled": True, "interface_types": [], "interfaces": [],
        "local_addresses": addresses, "local_ports": ["443"],
        "profile_mask": 4, "protocol": 6, "remote_addresses": [],
        "remote_ports": [], "service_name": None,
        "unsupported_features": [],
    }


def _payload(value, kind=WindowsFirewallIpcPayloadKind.RESPONSE):
    return WindowsFirewallIpcPayload(
        kind, json.dumps(value, separators=(",", ":")).encode("utf-8")
    )


def _wire_response(addresses):
    return {
        "authority": "CURRENT_POLICY_VIEW", "protocol_version": "2",
        "result": "COMPLETE", "rules": [_wire_rule(addresses)],
    }


class V2ValidVectorTests(unittest.TestCase):
    def test_v2_request_round_trip_and_retained_v1_codec_are_distinct(self):
        request = encode_windows_firewall_ipc_v2_request(
            WindowsFirewallIpcV2Request()
        )
        self.assertEqual(decode_windows_firewall_ipc_v2_request(request),
                         WindowsFirewallIpcV2Request())
        self.assertEqual(json.loads(request.consume_inside_boundary()), {
            "operation": "COLLECT_WINDOWS_FIREWALL_CURRENT_POLICY",
            "protocol_version": "2",
        })
        self.assertEqual(WINDOWS_FIREWALL_IPC_PROTOCOL_VERSION, "1")
        self.assertEqual(WINDOWS_FIREWALL_IPC_PROTOCOL_VERSION_V2, "2")
        retained_v1 = json.loads(encode_windows_firewall_helper_request(
            WindowsFirewallHelperRequest()).consume_inside_boundary())
        self.assertEqual(retained_v1["protocol_version"], "1")

    def test_all_closed_address_forms_round_trip_canonically(self):
        values = (
            _address(WindowsFirewallIpcV2AddressKind.LOCAL_SUBNET),
            _address(WindowsFirewallIpcV2AddressKind.IPV4, "192.0.2.1"),
            _address(WindowsFirewallIpcV2AddressKind.IPV6, "2001:0db8::1"),
            _address(WindowsFirewallIpcV2AddressKind.IPV4_CIDR,
                     "192.0.2.99/24"),
            _address(WindowsFirewallIpcV2AddressKind.IPV6_CIDR,
                     "2001:0db8:0:0::1/32"),
            _address(WindowsFirewallIpcV2AddressKind.IPV4_RANGE,
                     start="192.0.2.20", end="192.0.2.30"),
        )
        response = _response(_rule(local=tuple(reversed(values))))
        first = encode_windows_firewall_ipc_v2_response(response)
        second = encode_windows_firewall_ipc_v2_response(response)
        self.assertEqual(first.consume_inside_boundary(), second.consume_inside_boundary())
        decoded = decode_windows_firewall_ipc_v2_response(first)
        self.assertEqual(decoded, response)
        self.assertEqual(decoded.rules[0].local_addresses, values)
        encoded = json.loads(first.consume_inside_boundary())
        self.assertEqual(encoded["rules"][0]["local_addresses"][-1], {
            "end": "192.0.2.30", "kind": "IPV4_RANGE",
            "start": "192.0.2.20",
        })
        self.assertEqual(values[2].value, "2001:db8::1")
        self.assertEqual(values[3].value, "192.0.2.0/24")
        self.assertEqual(values[4].value, "2001:db8::/32")

    def test_empty_any_equal_endpoint_multiple_and_maximum_condition(self):
        empty = decode_windows_firewall_ipc_v2_response(
            encode_windows_firewall_ipc_v2_response(_response(_rule()))
        )
        self.assertEqual(empty.rules[0].local_addresses, ())
        any_value = _address(WindowsFirewallIpcV2AddressKind.ANY)
        equal_range = _address(
            WindowsFirewallIpcV2AddressKind.IPV4_RANGE,
            start="198.51.100.9", end="198.51.100.9",
        )
        self.assertEqual(decode_windows_firewall_ipc_v2_response(
            encode_windows_firewall_ipc_v2_response(
                _response(_rule(local=(any_value,)), _rule(remote=(equal_range,)))
            )
        ).rules[1].remote_addresses, (equal_range,))
        maximum = tuple(_address(
            WindowsFirewallIpcV2AddressKind.IPV4, f"10.0.0.{index}"
        ) for index in range(256))
        result = decode_windows_firewall_ipc_v2_response(
            encode_windows_firewall_ipc_v2_response(_response(_rule(local=maximum)))
        )
        self.assertEqual(len(result.rules[0].local_addresses), 256)


class V2InvalidVectorTests(unittest.TestCase):
    def assertInvalidAddresses(self, addresses):
        with self.assertRaises(WindowsComContractError) as caught:
            decode_windows_firewall_ipc_v2_response(_payload(
                _wire_response(addresses)
            ))
        self.assertEqual(caught.exception.category,
                         WindowsComFailureCategory.INVALID_RESULT)

    def test_invalid_tagged_shapes_fail_closed(self):
        cases = (
            ["192.0.2.1"],
            [{"kind": "IPV4", "value": "192.0.2.1"}, "192.0.2.2"],
            [{}], [{"kind": "UNKNOWN"}], [{"kind": "IPV4", "value": "192.0.2.1", "x": 1}],
            [{"kind": 1, "value": "192.0.2.1"}], [{"kind": "IPV4"}],
            [{"kind": "ANY", "value": "192.0.2.1"}],
            [{"kind": "LOCAL_SUBNET", "value": "x"}],
            [{"kind": "IPV4", "value": "PRIVATE_CANARY"}],
            [{"kind": "IPV4", "value": None}],
            [{"kind": "IPV6", "value": "PRIVATE_IPV6_CANARY"}],
            [{"kind": "IPV4_CIDR", "value": "PRIVATE_V4_CIDR"}],
            [{"kind": "IPV6_CIDR", "value": "PRIVATE_V6_CIDR"}],
            [{"kind": "IPV6", "value": "192.0.2.1"}],
            [{"kind": "IPV4_CIDR", "value": "2001:db8::/32"}],
            [{"kind": "IPV6_CIDR", "value": "192.0.2.0/24"}],
            [{"kind": "IPV4", "value": "::ffff:192.0.2.1"}],
            [{"kind": "IPV4_RANGE", "end": "192.0.2.2"}],
            [{"kind": "IPV4_RANGE", "start": "192.0.2.1"}],
            [{"kind": "IPV4_RANGE", "start": "192.0.2.1", "end": "192.0.2.2", "x": 1}],
            [{"kind": "IPV4_RANGE", "start": "PRIVATE_START", "end": "192.0.2.2"}],
            [{"kind": "IPV4_RANGE", "start": "192.0.2.1", "end": "PRIVATE_END"}],
            [{"kind": "IPV4_RANGE", "start": "2001:db8::1", "end": "2001:db8::2"}],
            [{"kind": "IPV4_RANGE", "start": "192.0.2.1", "end": "2001:db8::2"}],
            [{"kind": "IPV4_RANGE", "start": "192.0.2.2", "end": "192.0.2.1"}],
            [{"kind": "IPV4_RANGE", "start": None, "end": "192.0.2.1"}],
            [{"kind": "ANY"}, {"kind": "IPV4", "value": "192.0.2.1"}],
            [{"kind": "DHCP"}],
            [None], [1],
        )
        for addresses in cases:
            with self.subTest(addresses=addresses):
                self.assertInvalidAddresses(addresses)

    def test_semantic_duplicates_and_condition_limit_fail(self):
        duplicate_cases = (
            [
                {"kind": "IPV4", "value": "192.0.2.1"},
                {"kind": "IPV4", "value": "192.0.2.1"},
            ],
            [
                {"kind": "IPV4_CIDR", "value": "192.0.2.99/24"},
                {"kind": "IPV4_CIDR", "value": "192.0.2.0/24"},
            ],
            [
                {"kind": "IPV4_RANGE", "start": "192.0.2.1", "end": "192.0.2.2"},
                {"kind": "IPV4_RANGE", "start": "192.0.2.1", "end": "192.0.2.2"},
            ],
        )
        for addresses in duplicate_cases:
            with self.subTest(addresses=addresses):
                self.assertInvalidAddresses(addresses)
        self.assertInvalidAddresses([
            {"kind": "IPV4", "value": f"10.0.{index // 256}.{index % 256}"}
            for index in range(257)
        ])

    def test_duplicate_keys_depth_and_oversize_fail_closed(self):
        duplicate = (
            b'{"authority":"CURRENT_POLICY_VIEW","protocol_version":"2",'
            b'"result":"COMPLETE","rules":[{"action":"ALLOW",'
            b'"application_path":null,"direction":"INBOUND",'
            b'"edge_traversal":false,"enabled":true,"interface_types":[],'
            b'"interfaces":[],"local_addresses":[{"kind":"ANY","kind":"ANY"}],'
            b'"local_ports":[],"profile_mask":4,"protocol":6,'
            b'"remote_addresses":[],"remote_ports":[],"service_name":null,'
            b'"unsupported_features":[]}]}'
        )
        with self.assertRaises(WindowsComContractError):
            decode_windows_firewall_ipc_v2_response(WindowsFirewallIpcPayload(
                WindowsFirewallIpcPayloadKind.RESPONSE, duplicate
            ))
        too_deep = _wire_response([])
        too_deep["rules"][0]["local_addresses"] = [
            {"kind": "ANY", "nested": {"too": "deep"}}
        ]
        with self.assertRaises(WindowsComContractError) as caught:
            decode_windows_firewall_ipc_v2_response(_payload(too_deep))
        self.assertEqual(caught.exception.category,
                         WindowsComFailureCategory.LIMIT_EXCEEDED)
        large = _rule(path="X" * 4096)
        with self.assertRaises(WindowsComContractError) as caught:
            encode_windows_firewall_ipc_v2_response(_response(*(large,) * 2100))
        self.assertEqual(caught.exception.category,
                         WindowsComFailureCategory.LIMIT_EXCEEDED)
        self.assertEqual(MAX_WINDOWS_FIREWALL_IPC_RESPONSE_BYTES, 8 * 1024 * 1024)


class V2VersionAndPrivacyTests(unittest.TestCase):
    def test_cross_version_and_malformed_versions_fail_without_fallback(self):
        v1_request = encode_windows_firewall_helper_request(WindowsFirewallHelperRequest())
        v2_request = encode_windows_firewall_ipc_v2_request(WindowsFirewallIpcV2Request())
        with self.assertRaises(WindowsComContractError) as first:
            decode_windows_firewall_ipc_v2_request(v1_request)
        with self.assertRaises(WindowsComContractError) as second:
            decode_windows_firewall_helper_request(v2_request)
        self.assertEqual(first.exception.category, WindowsComFailureCategory.UNSUPPORTED)
        self.assertEqual(second.exception.category, WindowsComFailureCategory.UNSUPPORTED)
        self.assertEqual(
            decode_windows_firewall_ipc_request_for_version(v1_request, "1"),
            WindowsFirewallHelperRequest(),
        )
        self.assertEqual(
            decode_windows_firewall_ipc_request_for_version(v2_request, "2"),
            WindowsFirewallIpcV2Request(),
        )
        with self.assertRaises(WindowsComContractError):
            decode_windows_firewall_ipc_request_for_version(v1_request, "2")
        with self.assertRaises(WindowsComContractError):
            decode_windows_firewall_ipc_request_for_version(v2_request, "1")
        v2_response = encode_windows_firewall_ipc_v2_response(_response())
        with self.assertRaises(WindowsComContractError) as caught:
            decode_windows_firewall_helper_response(v2_response)
        self.assertEqual(caught.exception.category, WindowsComFailureCategory.UNSUPPORTED)
        v1_response = _payload({
            "authority": "CURRENT_POLICY_VIEW", "protocol_version": "1",
            "result": "COMPLETE", "rules": [],
        })
        with self.assertRaises(WindowsComContractError) as caught:
            decode_windows_firewall_ipc_v2_response(v1_response)
        self.assertEqual(caught.exception.category, WindowsComFailureCategory.UNSUPPORTED)
        self.assertEqual(
            decode_windows_firewall_ipc_response_for_version(v2_response, "2"),
            _response(),
        )
        self.assertEqual(
            decode_windows_firewall_ipc_response_for_version(
                v1_response, "1"
            ).protocol_version,
            "1",
        )
        with self.assertRaises(WindowsComContractError):
            decode_windows_firewall_ipc_response_for_version(v2_response, "1")
        with self.assertRaises(WindowsComContractError):
            decode_windows_firewall_ipc_response_for_version(v1_response, "2")
        for version, category in ((3, WindowsComFailureCategory.INVALID_RESULT),
                                  ("999", WindowsComFailureCategory.UNSUPPORTED)):
            value = {"operation": "COLLECT_WINDOWS_FIREWALL_CURRENT_POLICY",
                     "protocol_version": version}
            with self.assertRaises(WindowsComContractError) as caught:
                decode_windows_firewall_ipc_v2_request(_payload(
                    value, WindowsFirewallIpcPayloadKind.REQUEST
                ))
            self.assertEqual(caught.exception.category, category)

    def test_v2_rejects_v1_addresses_and_v1_rejects_v2_before_rule_decode(self):
        self.assertInvalidV2(["*"])
        v2_rule = _wire_rule([{"kind": "ANY"}])
        v2_rule["local_addresses"] = [{"kind": "ANY"}]
        v1_envelope = {
            "authority": "CURRENT_POLICY_VIEW", "protocol_version": "1",
            "result": "COMPLETE", "rules": [v2_rule],
        }
        with self.assertRaises(WindowsComContractError):
            decode_windows_firewall_helper_response(_payload(v1_envelope))

    def assertInvalidV2(self, addresses):
        with self.assertRaises(WindowsComContractError):
            decode_windows_firewall_ipc_v2_response(_payload(
                _wire_response(addresses)
            ))

    def test_private_values_are_redacted_from_objects_and_failures(self):
        endpoint = "203.0.113.77"
        path = r"C:\PRIVATE\secret.exe"
        interface = "PRIVATE_INTERFACE"
        address = _address(WindowsFirewallIpcV2AddressKind.IPV4, endpoint)
        response = _response(_rule(local=(address,), path=path, interface=interface))
        payload = encode_windows_firewall_ipc_v2_response(response)
        for rendered in (repr(address), str(address), repr(response), repr(payload), str(payload)):
            self.assertNotIn(endpoint, rendered)
            self.assertNotIn(path, rendered)
            self.assertNotIn(interface, rendered)
        invalid = _payload(_wire_response([
            {"kind": "IPV4", "value": "PRIVATE_ADDRESS_CANARY"}
        ]))
        with self.assertRaises(WindowsComContractError) as caught:
            decode_windows_firewall_ipc_v2_response(invalid)
        self.assertNotIn("PRIVATE_ADDRESS_CANARY", str(caught.exception))
        self.assertNotIn("PRIVATE_ADDRESS_CANARY", repr(caught.exception))


if __name__ == "__main__":
    unittest.main()
