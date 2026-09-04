import dataclasses
import unittest

from cyberwatchtower.firewall_policy import (
    MAX_VALUES_PER_CONDITION,
    FirewallRuleApplicability,
    FirewallRuleUnsupportedFeature,
    ListenerPolicySubject,
    evaluate_listener_policy,
)
from cyberwatchtower.platform.models import BindExposure, FirewallProfile, NetworkProtocol
from cyberwatchtower.platform.windows.firewall_com_contracts import (
    WindowsComContractError,
    WindowsComFailureCategory,
    WindowsFirewallPropertyGetter,
)
from cyberwatchtower.platform.windows.firewall_rule_ipc import (
    WindowsFirewallIpcV3Response,
    decode_windows_firewall_ipc_v3_response,
    encode_windows_firewall_ipc_v3_response,
    windows_firewall_ipc_v3_rule_to_raw,
    windows_firewall_raw_rule_to_ipc_v3,
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
from cyberwatchtower.platform.windows.firewall_rule_reader import _tokenize_csv
from cyberwatchtower.report_contracts import CoverageState
from tests.test_windows_firewall_rule_collection import fixture
from tests.test_windows_firewall_rule_native import _Runtime
from tests.test_windows_firewall_rule_reader import MockFirewallRule


VIEW = WindowsFirewallPolicyView.CURRENT_POLICY_VIEW


def _collect_ports(
    *, local_ports="443", remote_ports="PRIVATE_REMOTE_PORT_CANARY,",
    action=WindowsRawFirewallRuleAction.ALLOW, **changes,
):
    mock = MockFirewallRule()
    mock.local_ports = local_ports
    mock.remote_ports = remote_ports
    mock.action = 1 if action == WindowsRawFirewallRuleAction.ALLOW else 0
    for name, value in changes.items():
        setattr(mock, name, value)
    result = collect_native_windows_firewall_rules(_Runtime(fixture(mock)))
    return result, mock


def _normalize(result):
    normalized = normalize_windows_firewall_rules(result)
    if normalized.failure is not None:
        raise AssertionError("synthetic recovered rule did not normalize")
    return normalized.rules[0]


class RemotePortsConservativeRecoveryTests(unittest.TestCase):
    def test_remote_empty_elements_recover_without_retaining_text(self):
        for value in (",443", "443,", "443,,8443"):
            with self.subTest(value=value):
                result, mock = _collect_ports(remote_ports=value)
                self.assertEqual(result.state, WindowsFirewallRuleResultCode.COMPLETE)
                raw = result.rules[0]
                self.assertEqual(raw.local_ports, ("443",))
                self.assertEqual(raw.remote_ports, ())
                self.assertEqual(raw.unsupported_features, (
                    WindowsRawFirewallUnsupportedFeature.RECOVERED_REMOTE_PORTS,
                ))
                self.assertNotIn(value, repr(raw))
                self.assertEqual(mock.freed.count(
                    WindowsFirewallPropertyGetter.REMOTE_PORTS.value
                ), 1)
                self.assertIn(
                    WindowsFirewallPropertyGetter.REMOTE_ADDRESSES, mock.calls
                )

    def test_local_remote_partial_and_combined_recovery_are_atomic(self):
        cases = (
            ("443,", "8443", (), ("8443",)),
            ("443", "8443,", ("443",), ()),
            ("443,", "8443,", (), ()),
            ("443", "8443", ("443",), ("8443",)),
        )
        for local, remote, expected_local, expected_remote in cases:
            with self.subTest(local=local, remote=remote):
                result, _ = _collect_ports(
                    local_ports=local, remote_ports=remote
                )
                self.assertEqual(result.state, WindowsFirewallRuleResultCode.COMPLETE)
                raw = result.rules[0]
                self.assertEqual(raw.local_ports, expected_local)
                self.assertEqual(raw.remote_ports, expected_remote)
                expected_features = tuple(sorted((
                    *((WindowsRawFirewallUnsupportedFeature.RECOVERED_LOCAL_PORTS,)
                      if local.endswith(",") else ()),
                    *((WindowsRawFirewallUnsupportedFeature.RECOVERED_REMOTE_PORTS,)
                      if remote.endswith(",") else ()),
                ), key=lambda item: item.value))
                self.assertEqual(raw.unsupported_features, expected_features)

    def test_remote_recovery_remains_narrow(self):
        cases = (
            {"protocol": 1, "remote_ports": "443,"},
            {"protocol": object(), "remote_ports": "443,"},
            {"remote_ports": "SYNTHETIC_KEYWORD"},
            {"remote_ports": "99999"},
            {"remote_ports": "9000-8000"},
            {"remote_ports": "PRIVATE_CONTROL_CANARY\x00"},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                result, _ = _collect_ports(**changes)
                self.assertEqual(
                    result.state, WindowsFirewallRuleResultCode.INVALID_RESULT
                )

        mock = MockFirewallRule()
        mock.failed_getters = frozenset({
            WindowsFirewallPropertyGetter.REMOTE_PORTS
        })
        mock.failure_category = WindowsComFailureCategory.ACCESS_DENIED
        failed = collect_native_windows_firewall_rules(_Runtime(fixture(mock)))
        self.assertEqual(failed.state, WindowsFirewallRuleResultCode.ACCESS_DENIED)

        with self.assertRaises(WindowsComContractError):
            _tokenize_csv(",".join(
                "1" for _ in range(MAX_VALUES_PER_CONDITION + 1)
            ))

    def test_v3_normalization_identity_and_policy_are_conservative(self):
        remote_result, _ = _collect_ports()
        remote_block_result, _ = _collect_ports(
            action=WindowsRawFirewallRuleAction.BLOCK
        )
        both_result, _ = _collect_ports(local_ports="443,")
        for result in (remote_result, remote_block_result, both_result):
            raw = result.rules[0]
            wire = WindowsFirewallIpcV3Response(
                "3", VIEW, WindowsFirewallRuleResultCode.COMPLETE,
                (windows_firewall_raw_rule_to_ipc_v3(raw),),
            )
            decoded = decode_windows_firewall_ipc_v3_response(
                encode_windows_firewall_ipc_v3_response(wire)
            )
            parent_raw = windows_firewall_ipc_v3_rule_to_raw(decoded.rules[0])
            self.assertEqual(parent_raw, raw)
            self.assertNotIn("PRIVATE_REMOTE_PORT_CANARY", repr(parent_raw))
            neutral = _normalize(WindowsFirewallRuleCollectionResult(
                WindowsFirewallRuleResultCode.COMPLETE, VIEW, (parent_raw,)
            ))
            self.assertIn(
                FirewallRuleUnsupportedFeature.UNMODELED_PLATFORM_PREDICATE,
                neutral.unsupported_features,
            )
            for exposure, address in (
                (BindExposure.ALL_INTERFACES, "0.0.0.0"),
                (BindExposure.INTERFACE, "192.0.2.10"),
            ):
                subject = ListenerPolicySubject(
                    NetworkProtocol.TCP, 443, exposure, address,
                    (FirewallProfile.PUBLIC,),
                )
                assessment = evaluate_listener_policy(
                    subject, (neutral,), CoverageState.COMPLETE
                )
                self.assertEqual(
                    assessment.applicability, FirewallRuleApplicability.INCOMPLETE
                )

    def test_identity_collapse_is_only_the_closed_unknown_state(self):
        local_result, _ = _collect_ports(
            local_ports="443,", remote_ports=None
        )
        remote_result, _ = _collect_ports(
            local_ports=None, remote_ports="443,"
        )
        both_result, _ = _collect_ports(local_ports="443,", remote_ports="8443,")
        local = _normalize(local_result)
        remote = _normalize(remote_result)
        both = _normalize(both_result)
        self.assertEqual(
            {local.semantic_rule_id, remote.semantic_rule_id, both.semantic_rule_id},
            {local.semantic_rule_id},
        )
        unrestricted_raw = dataclasses.replace(
            local_result.rules[0], unsupported_features=()
        )
        unrestricted = _normalize(WindowsFirewallRuleCollectionResult(
            WindowsFirewallRuleResultCode.COMPLETE, VIEW, (unrestricted_raw,)
        ))
        self.assertNotEqual(local.semantic_rule_id, unrestricted.semantic_rule_id)

        valid_local_raw = dataclasses.replace(
            local_result.rules[0], local_ports=("443",), unsupported_features=()
        )
        valid_remote_raw = dataclasses.replace(
            local_result.rules[0], remote_ports=("443",), unsupported_features=()
        )
        valid_local = _normalize(WindowsFirewallRuleCollectionResult(
            WindowsFirewallRuleResultCode.COMPLETE, VIEW, (valid_local_raw,)
        ))
        valid_remote = _normalize(WindowsFirewallRuleCollectionResult(
            WindowsFirewallRuleResultCode.COMPLETE, VIEW, (valid_remote_raw,)
        ))
        self.assertEqual(len({
            local.semantic_rule_id,
            unrestricted.semantic_rule_id,
            valid_local.semantic_rule_id,
            valid_remote.semantic_rule_id,
        }), 4)

if __name__ == "__main__":
    unittest.main()
