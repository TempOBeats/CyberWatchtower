import dataclasses
import unittest
from unittest.mock import patch

from cyberwatchtower.firewall_policy import (
    ApplicationConditionKind,
    FirewallRuleAction,
    FirewallRuleApplicability,
    FirewallRuleUnsupportedFeature,
    InterfaceConditionKind,
    ListenerPolicySubject,
    evaluate_listener_policy,
)
from cyberwatchtower.platform.models import (
    BindExposure,
    FirewallProfile,
    NetworkProtocol,
)
from cyberwatchtower.platform.windows.firewall_rule_ipc import (
    windows_firewall_ipc_v2_rule_to_raw,
    windows_firewall_raw_rule_to_ipc_v2,
)
from cyberwatchtower.platform.windows.firewall_rule_models import (
    MAX_RAW_WINDOWS_APPLICATION_PATH,
    RawWindowsApplicationPath,
    RawWindowsFirewallRule,
    WindowsFirewallPolicyView,
    WindowsFirewallRuleCollectionResult,
    WindowsFirewallRuleResultCode,
    WindowsRawFirewallRuleAction,
    WindowsRawFirewallRuleDirection,
    WindowsRawFirewallUnsupportedFeature,
)
from cyberwatchtower.platform.windows.firewall_rules import (
    _WindowsApplicationIdentityKind,
    _WindowsApplicationIdentityResult,
    _windows_application_identity_result,
    normalize_windows_firewall_rules,
    windows_application_identity,
)
from cyberwatchtower.report_contracts import CoverageState


_EXACT_PATH = "C:\\Program Files\\Synthetic\\app.exe"
_EXACT_IDENTITY = (
    "c9f5e2885d26228db1b47ad06f1beb3059b23e8dab7a4f50cba021b95d95ff53"
)


def _raw_rule(**changes) -> RawWindowsFirewallRule:
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


def _normalize(*rules: RawWindowsFirewallRule):
    return normalize_windows_firewall_rules(WindowsFirewallRuleCollectionResult(
        WindowsFirewallRuleResultCode.COMPLETE,
        WindowsFirewallPolicyView.CURRENT_POLICY_VIEW,
        tuple(rules),
    ))


def _subject(**changes) -> ListenerPolicySubject:
    values = {
        "protocol": NetworkProtocol.TCP,
        "local_port": 443,
        "bind_exposure": BindExposure.ALL_INTERFACES,
        "local_address": "0.0.0.0",
        "profiles": (FirewallProfile.PUBLIC,),
        "application_digest": "a" * 64,
        "service_identity": "windows-service:synthetic.service",
        "interface": InterfaceConditionKind.LAN,
    }
    values.update(changes)
    return ListenerPolicySubject(**values)


class WindowsApplicationIdentityResultTests(unittest.TestCase):
    def test_exact_identity_result_preserves_the_frozen_digest_contract(self):
        result = _windows_application_identity_result(
            RawWindowsApplicationPath(_EXACT_PATH)
        )
        self.assertEqual(result.kind, _WindowsApplicationIdentityKind.EXACT)
        self.assertEqual(result.identity, _EXACT_IDENTITY)
        self.assertEqual(
            windows_application_identity(RawWindowsApplicationPath(
                "c:/program files/synthetic/APP.EXE"
            )),
            _EXACT_IDENTITY,
        )

    def test_valid_unrepresentable_result_carries_no_private_value(self):
        result = _windows_application_identity_result(
            RawWindowsApplicationPath("synthetic\\app.exe")
        )
        self.assertEqual(
            result,
            _WindowsApplicationIdentityResult(
                _WindowsApplicationIdentityKind.UNREPRESENTABLE
            ),
        )
        self.assertIsNone(result.identity)
        self.assertNotIn("synthetic", repr(result).casefold())
        with self.assertRaises(ValueError):
            windows_application_identity(
                RawWindowsApplicationPath("synthetic\\app.exe")
            )

    def test_structural_and_unexpected_failures_remain_fatal(self):
        with self.assertRaises(TypeError):
            _windows_application_identity_result("C:\\app.exe")
        with self.assertRaises(ValueError):
            RawWindowsApplicationPath("bad\x00value")
        with self.assertRaises(ValueError):
            RawWindowsApplicationPath(
                "x" * (MAX_RAW_WINDOWS_APPLICATION_PATH + 1)
            )
        with patch.object(
            RawWindowsApplicationPath,
            "consume_for_normalization",
            side_effect=RuntimeError,
        ):
            with self.assertRaises(RuntimeError):
                _windows_application_identity_result(
                    RawWindowsApplicationPath(_EXACT_PATH)
                )

    def test_typed_result_invariants_reject_invalid_state(self):
        with self.assertRaises(ValueError):
            _WindowsApplicationIdentityResult(
                _WindowsApplicationIdentityKind.EXACT
            )
        with self.assertRaises(ValueError):
            _WindowsApplicationIdentityResult(
                _WindowsApplicationIdentityKind.EXACT, "z" * 64
            )
        with self.assertRaises(ValueError):
            _WindowsApplicationIdentityResult(
                _WindowsApplicationIdentityKind.UNREPRESENTABLE, "a" * 64
            )


class WindowsApplicationRecoveryTests(unittest.TestCase):
    def test_absent_exact_and_unrepresentable_states_remain_distinct(self):
        absent = _normalize(_raw_rule()).rules[0]
        exact = _normalize(_raw_rule(
            application_path=RawWindowsApplicationPath(_EXACT_PATH)
        )).rules[0]
        unknown = _normalize(_raw_rule(
            application_path=RawWindowsApplicationPath("synthetic\\app.exe")
        )).rules[0]

        self.assertEqual(absent.application.kind, ApplicationConditionKind.ANY)
        self.assertEqual(absent.unsupported_features, ())
        self.assertEqual(
            exact.application.kind, ApplicationConditionKind.APPLICATION_DIGEST
        )
        self.assertEqual(exact.application.value, _EXACT_IDENTITY)
        self.assertEqual(exact.unsupported_features, ())
        self.assertEqual(unknown.application.kind, ApplicationConditionKind.ANY)
        self.assertEqual(unknown.unsupported_features, (
            FirewallRuleUnsupportedFeature.UNMODELED_PLATFORM_PREDICATE,
        ))
        self.assertEqual(len({
            absent.semantic_rule_id, exact.semantic_rule_id,
            unknown.semantic_rule_id,
        }), 3)

    def test_unrepresentable_application_preserves_service_and_other_fields(self):
        raw = _raw_rule(
            application_path=RawWindowsApplicationPath("synthetic\\app.exe"),
            service_name="Synthetic.Service",
            remote_ports=("8443",),
            remote_addresses=("192.0.2.0/24",),
            edge_traversal=True,
        )
        normalized = _normalize(raw).rules[0]
        self.assertEqual(
            normalized.application.kind,
            ApplicationConditionKind.SERVICE_IDENTITY,
        )
        self.assertEqual(
            normalized.application.value, "windows-service:synthetic.service"
        )
        self.assertTrue(normalized.edge_traversal)
        self.assertTrue(normalized.remote_addresses)
        self.assertIn(
            FirewallRuleUnsupportedFeature.REMOTE_PORT_RESTRICTED,
            normalized.unsupported_features,
        )
        self.assertIn(
            FirewallRuleUnsupportedFeature.UNMODELED_PLATFORM_PREDICATE,
            normalized.unsupported_features,
        )

    def test_port_recovery_markers_deduplicate_with_application_recovery(self):
        cases = (
            (),
            (WindowsRawFirewallUnsupportedFeature.UNMODELED_NATIVE_PREDICATE,),
        )
        for raw_features in cases:
            for local_ports, remote_ports in (
                (("443",), ()),
                ((), ("443",)),
                ((), ()),
            ):
                with self.subTest(
                    raw_features=raw_features,
                    local_ports=local_ports,
                    remote_ports=remote_ports,
                ):
                    rule = _normalize(_raw_rule(
                        application_path=RawWindowsApplicationPath(
                            "synthetic\\app.exe"
                        ),
                        local_ports=local_ports,
                        remote_ports=remote_ports,
                        unsupported_features=raw_features,
                    )).rules[0]
                    self.assertEqual(
                        rule.unsupported_features.count(
                            FirewallRuleUnsupportedFeature
                            .UNMODELED_PLATFORM_PREDICATE
                        ),
                        1,
                    )
                    self.assertEqual(bool(rule.local_ports), bool(local_ports))

    def test_recovered_allow_and_block_are_incomplete_for_known_subjects(self):
        allow = _normalize(_raw_rule(
            application_path=RawWindowsApplicationPath("synthetic\\allow.exe")
        )).rules[0]
        block = _normalize(_raw_rule(
            action=WindowsRawFirewallRuleAction.BLOCK,
            application_path=RawWindowsApplicationPath("synthetic\\block.exe"),
        )).rules[0]
        self.assertEqual(allow.action, FirewallRuleAction.ALLOW)
        self.assertEqual(block.action, FirewallRuleAction.BLOCK)
        for candidate in (
            _subject(bind_exposure=BindExposure.ALL_INTERFACES),
            _subject(bind_exposure=BindExposure.INTERFACE),
        ):
            for rule in (allow, block):
                with self.subTest(action=rule.action, exposure=candidate.bind_exposure):
                    assessment = evaluate_listener_policy(
                        candidate, (rule,), CoverageState.COMPLETE
                    )
                    self.assertEqual(
                        assessment.applicability,
                        FirewallRuleApplicability.INCOMPLETE,
                    )

    def test_independent_mismatch_still_excludes_recovered_rule(self):
        cases = (
            _raw_rule(enabled=False),
            _raw_rule(direction=WindowsRawFirewallRuleDirection.OUTBOUND),
            _raw_rule(profile_mask=1),
            _raw_rule(protocol=17),
            _raw_rule(local_ports=("80",)),
            _raw_rule(local_addresses=("192.0.2.1",)),
            _raw_rule(service_name="Other.Service"),
        )
        for raw in cases:
            raw = dataclasses.replace(
                raw,
                application_path=RawWindowsApplicationPath(
                    "synthetic\\excluded.exe"
                ),
            )
            with self.subTest(raw=repr(raw)):
                normalized = _normalize(raw).rules[0]
                assessment = evaluate_listener_policy(
                    _subject(), (normalized,), CoverageState.COMPLETE
                )
                self.assertEqual(
                    assessment.applicability, FirewallRuleApplicability.NO_MATCH
                )

    def test_private_provenance_collapses_as_an_exact_safe_duplicate(self):
        first = _raw_rule(application_path=RawWindowsApplicationPath(
            "synthetic\\first.exe"
        ))
        second = _raw_rule(application_path=RawWindowsApplicationPath(
            "synthetic\\second.exe"
        ))
        normalized = _normalize(first, second)
        self.assertIsNone(normalized.failure)
        self.assertEqual(len(normalized.rules), 1)
        self.assertEqual(
            evaluate_listener_policy(
                _subject(), normalized.rules, normalized.coverage
            ).applicability,
            FirewallRuleApplicability.INCOMPLETE,
        )
        self.assertNotIn("synthetic", repr(normalized).casefold())

    def test_ipc_v2_round_trip_retains_raw_type_until_normalization(self):
        raw = _raw_rule(application_path=RawWindowsApplicationPath(
            "synthetic\\app.exe"
        ))
        reconstructed = windows_firewall_ipc_v2_rule_to_raw(
            windows_firewall_raw_rule_to_ipc_v2(raw)
        )
        self.assertEqual(reconstructed, raw)
        self.assertIsInstance(
            reconstructed.application_path, RawWindowsApplicationPath
        )
        normalized = _normalize(reconstructed)
        self.assertIsNone(normalized.failure)
        self.assertEqual(
            normalized.rules[0].application.kind, ApplicationConditionKind.ANY
        )


if __name__ == "__main__":
    unittest.main()
