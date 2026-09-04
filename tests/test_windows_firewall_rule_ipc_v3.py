import json
import unittest

from cyberwatchtower.firewall_policy import (
    MAX_FIREWALL_RULES,
    FirewallRuleUnsupportedFeature,
    FirewallUnmodeledPlatformProvenance,
)
from cyberwatchtower.platform.windows.firewall_com_contracts import (
    WindowsComContractError,
    WindowsComFailureCategory,
)
from cyberwatchtower.platform.windows.firewall_rule_ipc import (
    MAX_WINDOWS_FIREWALL_IPC_REQUEST_BYTES,
    MAX_WINDOWS_FIREWALL_IPC_RESPONSE_BYTES,
    WINDOWS_FIREWALL_IPC_PROTOCOL_VERSION_V3,
    WindowsFirewallIpcPayload,
    WindowsFirewallIpcPayloadKind,
    WindowsFirewallIpcV2Request,
    WindowsFirewallIpcV2Response,
    WindowsFirewallIpcV2Rule,
    WindowsFirewallIpcV3Request,
    WindowsFirewallIpcV3Response,
    WindowsFirewallIpcV3Rule,
    decode_windows_firewall_ipc_v2_response,
    decode_windows_firewall_ipc_request_for_version,
    decode_windows_firewall_ipc_response_for_version,
    decode_windows_firewall_ipc_v3_request,
    decode_windows_firewall_ipc_v3_response,
    encode_windows_firewall_ipc_v2_response,
    encode_windows_firewall_ipc_v3_request,
    encode_windows_firewall_ipc_v3_response,
    windows_firewall_ipc_v3_rule_to_raw,
    windows_firewall_raw_rule_to_ipc_v3,
)
from cyberwatchtower.platform.windows.firewall_rule_models import (
    RawWindowsFirewallRule,
    WindowsFirewallPolicyView,
    WindowsFirewallRuleResultCode,
    WindowsRawFirewallRuleAction,
    WindowsRawFirewallRuleDirection,
    WindowsRawFirewallUnsupportedFeature,
)
from cyberwatchtower.platform.windows.firewall_rule_models import (
    WindowsFirewallRuleCollectionResult,
)
from cyberwatchtower.platform.windows.firewall_rules import (
    normalize_windows_firewall_rules,
)


VIEW = WindowsFirewallPolicyView.CURRENT_POLICY_VIEW
PROVENANCE = tuple(
    feature for feature in WindowsRawFirewallUnsupportedFeature
    if feature.value in {
        "RECOVERED_LOCAL_PORTS", "RECOVERED_REMOTE_PORTS",
        "RULE2_UNAVAILABLE", "RULE3_UNAVAILABLE",
        "REMOTE_PRINCIPAL_OR_SECURE_SCOPE", "EDGE_TRAVERSAL_DEFERRED",
    }
)


def _rule(*features):
    return RawWindowsFirewallRule(
        VIEW, True, WindowsRawFirewallRuleDirection.INBOUND,
        WindowsRawFirewallRuleAction.ALLOW, 4, 6,
        local_ports=("443",), local_addresses=("*",),
        unsupported_features=tuple(features),
    )


def _payload(value, kind=WindowsFirewallIpcPayloadKind.RESPONSE):
    return WindowsFirewallIpcPayload(
        kind, json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    )


class FixedV3ContractTests(unittest.TestCase):
    def test_request_is_fixed_deterministic_and_version_isolated(self):
        request = WindowsFirewallIpcV3Request()
        first = encode_windows_firewall_ipc_v3_request(request)
        second = encode_windows_firewall_ipc_v3_request(request)
        self.assertEqual(WINDOWS_FIREWALL_IPC_PROTOCOL_VERSION_V3, "3")
        self.assertEqual(first.consume_inside_boundary(), second.consume_inside_boundary())
        self.assertEqual(decode_windows_firewall_ipc_v3_request(first), request)
        self.assertEqual(
            decode_windows_firewall_ipc_request_for_version(first, "3"), request
        )
        v2 = encode_windows_firewall_ipc_v3_request
        with self.assertRaises(TypeError):
            v2(WindowsFirewallIpcV2Request())

    def test_each_refined_origin_and_catch_all_round_trip(self):
        for feature in (*PROVENANCE,
                        WindowsRawFirewallUnsupportedFeature.UNMODELED_NATIVE_PREDICATE):
            with self.subTest(feature=feature):
                raw = _rule(feature)
                response = WindowsFirewallIpcV3Response(
                    "3", VIEW, WindowsFirewallRuleResultCode.COMPLETE,
                    (windows_firewall_raw_rule_to_ipc_v3(raw),),
                )
                decoded = decode_windows_firewall_ipc_v3_response(
                    encode_windows_firewall_ipc_v3_response(response)
                )
                self.assertEqual(
                    decode_windows_firewall_ipc_response_for_version(
                        encode_windows_firewall_ipc_v3_response(response), "3"
                    ),
                    response,
                )
                self.assertEqual(windows_firewall_ipc_v3_rule_to_raw(
                    decoded.rules[0]
                ), raw)

    def test_refined_origins_preserve_one_security_semantic(self):
        for feature in PROVENANCE:
            with self.subTest(feature=feature):
                normalized = normalize_windows_firewall_rules(
                    WindowsFirewallRuleCollectionResult(
                        WindowsFirewallRuleResultCode.COMPLETE, VIEW,
                        (_rule(feature),),
                    )
                ).rules[0]
                self.assertIn(
                    FirewallRuleUnsupportedFeature.UNMODELED_PLATFORM_PREDICATE,
                    normalized.unsupported_features,
                )
                self.assertEqual(
                    normalized.unmodeled_platform_provenance,
                    (FirewallUnmodeledPlatformProvenance(feature.value),),
                )
        generic = normalize_windows_firewall_rules(
            WindowsFirewallRuleCollectionResult(
                WindowsFirewallRuleResultCode.COMPLETE, VIEW,
                (_rule(WindowsRawFirewallUnsupportedFeature.UNMODELED_NATIVE_PREDICATE),),
            )
        ).rules[0]
        self.assertEqual(generic.unmodeled_platform_provenance, (
            FirewallUnmodeledPlatformProvenance.OTHER_CLOSED_ORIGIN,
        ))
        refined = normalize_windows_firewall_rules(
            WindowsFirewallRuleCollectionResult(
                WindowsFirewallRuleResultCode.COMPLETE, VIEW,
                (_rule(PROVENANCE[0]),),
            )
        ).rules[0]
        self.assertEqual(refined, generic)
        self.assertEqual(refined.semantic_rule_id, generic.semantic_rule_id)

    def test_multiple_origins_are_unique_sorted_and_deterministic(self):
        values = tuple(reversed(PROVENANCE))
        wire = windows_firewall_raw_rule_to_ipc_v3(_rule(*values))
        self.assertEqual(wire.unsupported_features,
                         tuple(sorted(PROVENANCE, key=lambda item: item.value)))
        response = WindowsFirewallIpcV3Response(
            "3", VIEW, WindowsFirewallRuleResultCode.COMPLETE, (wire,)
        )
        self.assertEqual(
            encode_windows_firewall_ipc_v3_response(response).consume_inside_boundary(),
            encode_windows_firewall_ipc_v3_response(response).consume_inside_boundary(),
        )
        with self.assertRaises(ValueError):
            _rule(PROVENANCE[0], PROVENANCE[0])

    def test_v2_vocabulary_remains_frozen(self):
        for feature in PROVENANCE:
            with self.subTest(feature=feature), self.assertRaises(ValueError):
                WindowsFirewallIpcV2Rule(
                    True, WindowsRawFirewallRuleDirection.INBOUND,
                    WindowsRawFirewallRuleAction.ALLOW, 4, 6,
                    unsupported_features=(feature,),
                )
            data = json.loads(encode_windows_firewall_ipc_v3_response(
                WindowsFirewallIpcV3Response(
                    "3", VIEW, WindowsFirewallRuleResultCode.COMPLETE,
                    (windows_firewall_raw_rule_to_ipc_v3(_rule(feature)),),
                )
            ).consume_inside_boundary())
            data["protocol_version"] = "2"
            with self.subTest(wire_feature=feature), self.assertRaises(
                WindowsComContractError
            ):
                decode_windows_firewall_ipc_v2_response(_payload(data))
        original = WindowsFirewallIpcV2Response(
            "2", VIEW, WindowsFirewallRuleResultCode.COMPLETE,
            (WindowsFirewallIpcV2Rule(
                True, WindowsRawFirewallRuleDirection.INBOUND,
                WindowsRawFirewallRuleAction.ALLOW, 4, 6,
                unsupported_features=(
                    WindowsRawFirewallUnsupportedFeature.UNMODELED_NATIVE_PREDICATE,
                ),
            ),),
        )
        self.assertEqual(decode_windows_firewall_ipc_v2_response(
            encode_windows_firewall_ipc_v2_response(original)
        ), original)

    def test_unknown_enum_fields_and_versions_fail_closed(self):
        base = {
            "authority": VIEW.value, "protocol_version": "3",
            "result": "COMPLETE", "rules": [],
        }
        complete_rule = {
            "action": "ALLOW", "application_path": None,
            "direction": "INBOUND", "edge_traversal": False,
            "enabled": True, "interface_types": [], "interfaces": [],
            "local_addresses": [], "local_ports": [], "profile_mask": 4,
            "protocol": 6, "remote_addresses": [], "remote_ports": [],
            "service_name": None, "unsupported_features": [],
        }
        invalid_rules = (
            {**complete_rule, "unsupported_features": ["ARBITRARY"]},
            {key: value for key, value in complete_rule.items()
             if key != "unsupported_features"},
            {**complete_rule, "extra": 1},
        )
        for rule in invalid_rules:
            with self.assertRaises(WindowsComContractError):
                decode_windows_firewall_ipc_v3_response(_payload({**base, "rules": [rule]}))
        for version in ("1", "2", "999"):
            with self.assertRaises(WindowsComContractError) as caught:
                decode_windows_firewall_ipc_v3_response(_payload({**base,
                                                                  "protocol_version": version}))
            self.assertEqual(caught.exception.category,
                             WindowsComFailureCategory.UNSUPPORTED)

    def test_duplicate_key_and_malformed_json_fail_closed(self):
        duplicate = WindowsFirewallIpcPayload(
            WindowsFirewallIpcPayloadKind.RESPONSE,
            b'{"authority":"CURRENT_POLICY_VIEW","protocol_version":"3",'
            b'"protocol_version":"3","result":"COMPLETE","rules":[]}',
        )
        malformed = WindowsFirewallIpcPayload(
            WindowsFirewallIpcPayloadKind.RESPONSE, b"{bad"
        )
        for payload in (duplicate, malformed):
            with self.assertRaises(WindowsComContractError):
                decode_windows_firewall_ipc_v3_response(payload)

    def test_v3_preserves_payload_depth_and_rule_bounds(self):
        for kind, size in (
            (WindowsFirewallIpcPayloadKind.REQUEST,
             MAX_WINDOWS_FIREWALL_IPC_REQUEST_BYTES + 1),
            (WindowsFirewallIpcPayloadKind.RESPONSE,
             MAX_WINDOWS_FIREWALL_IPC_RESPONSE_BYTES + 1),
        ):
            with self.assertRaises(WindowsComContractError) as caught:
                WindowsFirewallIpcPayload(kind, b"x" * size)
            self.assertEqual(caught.exception.category,
                             WindowsComFailureCategory.LIMIT_EXCEEDED)
        excessive = {
            "authority": VIEW.value, "protocol_version": "3",
            "result": "COMPLETE", "rules": [{}] * (MAX_FIREWALL_RULES + 1),
        }
        with self.assertRaises(WindowsComContractError):
            decode_windows_firewall_ipc_v3_response(_payload(excessive))
        nested = []
        for _ in range(7):
            nested = [nested]
        with self.assertRaises(WindowsComContractError):
            decode_windows_firewall_ipc_v3_response(_payload(nested))


if __name__ == "__main__":
    unittest.main()
