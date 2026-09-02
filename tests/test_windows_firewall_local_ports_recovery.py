import dataclasses
import unittest

from cyberwatchtower.firewall_policy import (
    FirewallRuleAction,
    FirewallRuleApplicability,
    FirewallRuleUnsupportedFeature,
    ListenerPolicySubject,
    evaluate_listener_policy,
)
from cyberwatchtower.platform.models import BindExposure, FirewallProfile, NetworkProtocol
from cyberwatchtower.platform.windows.firewall_rule_ipc import (
    WindowsFirewallIpcV2Response,
    decode_windows_firewall_ipc_v2_response,
    encode_windows_firewall_ipc_v2_response,
    windows_firewall_ipc_v2_rule_to_raw,
    windows_firewall_raw_rule_to_ipc_v2,
)
from cyberwatchtower.platform.windows.firewall_rule_models import (
    WindowsFirewallPolicyView,
    WindowsFirewallRuleCollectionResult,
    WindowsFirewallRuleResultCode,
    WindowsRawFirewallRuleAction,
    WindowsRawFirewallUnsupportedFeature,
)
from cyberwatchtower.platform.windows.firewall_rule_native import (
    collect_native_windows_firewall_rules,
)
from cyberwatchtower.platform.windows.firewall_rules import (
    normalize_windows_firewall_rules,
)
from cyberwatchtower.report_contracts import CoverageState
from tests.test_windows_firewall_rule_collection import fixture
from tests.test_windows_firewall_rule_native import _Runtime
from tests.test_windows_firewall_rule_reader import MockFirewallRule


VIEW = WindowsFirewallPolicyView.CURRENT_POLICY_VIEW


def _collect_recovered(*, action=WindowsRawFirewallRuleAction.ALLOW, **changes):
    mock = MockFirewallRule()
    mock.action = 1 if action == WindowsRawFirewallRuleAction.ALLOW else 0
    mock.local_ports = "PRIVATE_PORT_CANARY,"
    for name, value in changes.items():
        setattr(mock, name, value)
    result = collect_native_windows_firewall_rules(_Runtime(fixture(mock)))
    if result.state != WindowsFirewallRuleResultCode.COMPLETE:
        raise AssertionError("synthetic LocalPorts recovery did not complete")
    return result, mock


def _normalize(result):
    normalized = normalize_windows_firewall_rules(result)
    if normalized.failure is not None:
        raise AssertionError("synthetic recovered rule did not normalize")
    return normalized.rules[0]


class LocalPortsConservativeRecoveryTests(unittest.TestCase):
    def test_recovered_rule_survives_v2_round_trip_without_private_text(self):
        result, _ = _collect_recovered()
        raw = result.rules[0]
        wire = WindowsFirewallIpcV2Response(
            "2", VIEW, WindowsFirewallRuleResultCode.COMPLETE,
            (windows_firewall_raw_rule_to_ipc_v2(raw),),
        )
        decoded = decode_windows_firewall_ipc_v2_response(
            encode_windows_firewall_ipc_v2_response(wire)
        )
        parent_raw = windows_firewall_ipc_v2_rule_to_raw(decoded.rules[0])
        self.assertEqual(parent_raw.local_ports, ())
        self.assertEqual(parent_raw.unsupported_features, (
            WindowsRawFirewallUnsupportedFeature.UNMODELED_NATIVE_PREDICATE,
        ))
        self.assertNotIn("PRIVATE_PORT_CANARY", repr(parent_raw))

    def test_normalization_and_identity_distinguish_unknown_from_unrestricted(self):
        result, _ = _collect_recovered()
        unknown = _normalize(result)
        self.assertEqual(unknown.local_ports, ())
        self.assertEqual(unknown.unsupported_features, (
            FirewallRuleUnsupportedFeature.UNMODELED_PLATFORM_PREDICATE,
        ))

        raw = result.rules[0]
        unrestricted_raw = dataclasses.replace(raw, unsupported_features=())
        unrestricted = _normalize(WindowsFirewallRuleCollectionResult(
            WindowsFirewallRuleResultCode.COMPLETE, VIEW, (unrestricted_raw,)
        ))
        valid_raw = dataclasses.replace(
            raw, local_ports=("443",), unsupported_features=()
        )
        valid = _normalize(WindowsFirewallRuleCollectionResult(
            WindowsFirewallRuleResultCode.COMPLETE, VIEW, (valid_raw,)
        ))
        self.assertEqual(len({
            unknown.semantic_rule_id,
            unrestricted.semantic_rule_id,
            valid.semantic_rule_id,
        }), 3)

    def test_allow_block_listener_and_multiple_rule_cases_remain_incomplete(self):
        allow_result, _ = _collect_recovered()
        block_result, _ = _collect_recovered(
            action=WindowsRawFirewallRuleAction.BLOCK
        )
        allow = _normalize(allow_result)
        block = _normalize(block_result)
        complete_allow = _normalize(WindowsFirewallRuleCollectionResult(
            WindowsFirewallRuleResultCode.COMPLETE, VIEW,
            (dataclasses.replace(
                allow_result.rules[0], unsupported_features=()
            ),),
        ))
        complete_block = _normalize(WindowsFirewallRuleCollectionResult(
            WindowsFirewallRuleResultCode.COMPLETE, VIEW,
            (dataclasses.replace(
                block_result.rules[0], unsupported_features=()
            ),),
        ))
        subject = allow_subject = ListenerPolicySubject(
            NetworkProtocol.TCP, 443, BindExposure.ALL_INTERFACES, "0.0.0.0",
            (FirewallProfile.PUBLIC,),
        )
        exact_subject = dataclasses.replace(
            allow_subject, bind_exposure=BindExposure.INTERFACE,
            local_address="192.0.2.10",
        )
        for candidate in (subject, exact_subject):
            for rules in (
                (allow,),
                (block,),
                tuple(sorted((allow, block), key=lambda item: item.semantic_rule_id)),
                tuple(sorted(
                    (complete_allow, block), key=lambda item: item.semantic_rule_id
                )),
                tuple(sorted(
                    (complete_block, allow), key=lambda item: item.semantic_rule_id
                )),
            ):
                with self.subTest(candidate=candidate, rules=len(rules)):
                    assessment = evaluate_listener_policy(
                        candidate, rules, CoverageState.COMPLETE
                    )
                    self.assertEqual(
                        assessment.applicability,
                        FirewallRuleApplicability.INCOMPLETE,
                    )

    def test_modeled_exclusion_still_returns_no_match(self):
        cases = (
            ({}, ListenerPolicySubject(
                NetworkProtocol.UDP, 443, BindExposure.ALL_INTERFACES, "0.0.0.0",
                (FirewallProfile.PUBLIC,),
            )),
            ({}, ListenerPolicySubject(
                NetworkProtocol.TCP, 443, BindExposure.ALL_INTERFACES, "0.0.0.0",
                (FirewallProfile.DOMAIN,),
            )),
            ({"local_addresses": "192.0.2.1"}, ListenerPolicySubject(
                NetworkProtocol.TCP, 443, BindExposure.INTERFACE, "192.0.2.2",
                (FirewallProfile.PUBLIC,),
            )),
        )
        for changes, excluded in cases:
            with self.subTest(changes=changes, protocol=excluded.protocol):
                result, _ = _collect_recovered(**changes)
                unknown = _normalize(result)
                assessment = evaluate_listener_policy(
                    excluded, (unknown,), CoverageState.COMPLETE
                )
                self.assertEqual(
                    assessment.applicability, FirewallRuleApplicability.NO_MATCH
                )

if __name__ == "__main__":
    unittest.main()
