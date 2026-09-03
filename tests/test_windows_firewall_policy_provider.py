import unittest
from pathlib import Path
from unittest.mock import patch

from cyberwatchtower.firewall_policy import FirewallRuleApplicability
from cyberwatchtower.platform.windows import FakeWindowsApi, WindowsPlatformAdapter
from cyberwatchtower.platform.windows.firewall_policy_provider import (
    IsolatedWindowsFirewallPolicyProvider,
)
from cyberwatchtower.platform.windows.firewall_rule_ipc import (
    WindowsFirewallHelperExitCode,
    WindowsFirewallHelperWaitResult,
    WindowsFirewallHelperWaitState,
    decode_windows_firewall_ipc_v2_request,
    WindowsFirewallIpcV2Response,
    windows_firewall_raw_rule_to_ipc_v2,
)
from cyberwatchtower.platform.windows.firewall_rule_models import (
    RawWindowsApplicationPath,
    RawWindowsInterfaceIdentity,
    WindowsFirewallPolicyView,
    WindowsFirewallRuleResultCode,
    WindowsRawFirewallRuleAction,
)
from cyberwatchtower.reachability import RemoteReachabilityState
from cyberwatchtower.scanner import _default_platform_adapter, run_scan

from tests.test_windows_firewall_rule_ipc import _production_payload
from tests.test_windows_firewall_scan_integration import raw_rule
from tests.test_windows_platform_integration import fixture


class FakeHelperProcess:
    def __init__(self, payload):
        self.payload = payload
        self.events = []

    def wait_for_response(self, timeout_ms):
        self.events.append(("wait", timeout_ms))
        return WindowsFirewallHelperWaitResult(
            WindowsFirewallHelperWaitState.RESPONSE, self.payload
        )

    def request_termination(self):
        self.events.append("terminate")

    def wait_after_termination(self, timeout_ms):
        raise AssertionError("completed fake response must not be terminated")

    def force_kill(self):
        raise AssertionError("completed fake response must not be killed")

    def reap(self):
        self.events.append("reap")
        return WindowsFirewallHelperExitCode.SUCCESS


class FakeHelperLauncher:
    def __init__(self, payload):
        self.process = FakeHelperProcess(payload)
        self.calls = 0
        self.request = None

    def start(self, request):
        self.calls += 1
        self.request = decode_windows_firewall_ipc_v2_request(request)
        return self.process


def provider_for(state, *rules):
    return IsolatedWindowsFirewallPolicyProvider(FakeHelperLauncher(
        _production_payload(tuple(rules), state)
    ))


def network_finding(result):
    return next(item for item in result["findings"] if item.source == "network")


class ProductionProviderContractTests(unittest.TestCase):
    def test_provider_uses_fixed_v2_runner_and_existing_normalizer(self):
        provider = provider_for(
            WindowsFirewallRuleResultCode.COMPLETE, raw_rule()
        )
        result = provider.collect_normalized_firewall_policy()
        self.assertEqual(result.coverage.value, "COMPLETE")
        self.assertEqual(len(result.rules), 1)
        self.assertEqual(provider.launcher.calls, 1)
        self.assertEqual(provider.launcher.request.protocol_version, "2")
        self.assertEqual(provider.launcher.process.events[-1], "reap")

    def test_all_closed_results_preserve_normalized_failure_contract(self):
        for state in WindowsFirewallRuleResultCode:
            rules = (
                (raw_rule(),)
                if state == WindowsFirewallRuleResultCode.COMPLETE
                else ()
            )
            with self.subTest(state=state):
                result = provider_for(state, *rules).collect_normalized_firewall_policy()
                expected = (
                    "COMPLETE"
                    if state == WindowsFirewallRuleResultCode.COMPLETE
                    else "UNKNOWN"
                    if state in {
                        WindowsFirewallRuleResultCode.API_UNAVAILABLE,
                        WindowsFirewallRuleResultCode.UNSUPPORTED,
                    }
                    else "INCOMPLETE"
                )
                self.assertEqual(result.coverage.value, expected)
                self.assertEqual(
                    result.failure,
                    None if state == WindowsFirewallRuleResultCode.COMPLETE else state,
                )

    def test_failed_v2_response_cannot_carry_a_partial_prefix(self):
        with self.assertRaises(ValueError):
            WindowsFirewallIpcV2Response(
                "2",
                WindowsFirewallPolicyView.CURRENT_POLICY_VIEW,
                WindowsFirewallRuleResultCode.COLLECTION_INCOMPLETE,
                (windows_firewall_raw_rule_to_ipc_v2(raw_rule()),),
            )

    def test_constructor_has_no_launch_or_import_time_side_effect(self):
        launcher = FakeHelperLauncher(_production_payload())
        provider = IsolatedWindowsFirewallPolicyProvider(launcher)
        adapter = WindowsPlatformAdapter(FakeWindowsApi(fixture()), provider)
        self.assertIs(adapter._firewall_policy_provider, provider)
        self.assertEqual(launcher.calls, 0)

    def test_parent_side_exceptions_and_wrong_normalizer_type_fail_closed(self):
        provider = IsolatedWindowsFirewallPolicyProvider()
        cases = (
            patch(
                "cyberwatchtower.platform.windows.firewall_policy_provider."
                "WindowsFirewallSubprocessLauncher",
                side_effect=RuntimeError("PRIVATE_LAUNCHER_CANARY"),
            ),
            patch(
                "cyberwatchtower.platform.windows.firewall_policy_provider."
                "run_isolated_windows_firewall_helper",
                side_effect=RuntimeError("PRIVATE_RUNNER_CANARY"),
            ),
            patch(
                "cyberwatchtower.platform.windows.firewall_policy_provider."
                "normalize_windows_firewall_rules",
                side_effect=RuntimeError("PRIVATE_NORMALIZER_CANARY"),
            ),
            patch(
                "cyberwatchtower.platform.windows.firewall_policy_provider."
                "normalize_windows_firewall_rules",
                return_value=None,
            ),
        )
        for failure in cases:
            with self.subTest(failure=failure), failure:
                result = provider.collect_normalized_firewall_policy()
            self.assertEqual(result.coverage.value, "INCOMPLETE")
            self.assertEqual(
                result.failure, WindowsFirewallRuleResultCode.INTERNAL_ERROR
            )
            self.assertNotIn("PRIVATE", repr(result))

    def test_default_windows_factory_owns_real_provider_without_collecting(self):
        with patch(
            "cyberwatchtower.platform.selection.platform.system",
            return_value="Windows",
        ):
            adapter = _default_platform_adapter()
        self.assertIsInstance(adapter, WindowsPlatformAdapter)
        self.assertIsInstance(
            adapter._firewall_policy_provider,
            IsolatedWindowsFirewallPolicyProvider,
        )
        self.assertIsNone(adapter._firewall_policy_provider.launcher)


class ProductionProviderScannerTests(unittest.TestCase):
    def scan(self, state, *rules):
        provider = provider_for(state, *rules)
        result = run_scan(WindowsPlatformAdapter(FakeWindowsApi(fixture()), provider))
        return provider, result

    def test_complete_allow_and_block_reach_report_context(self):
        cases = (
            (
                raw_rule(),
                FirewallRuleApplicability.MATCHING_ALLOW,
                RemoteReachabilityState.POTENTIALLY_REACHABLE,
            ),
            (
                raw_rule(action=WindowsRawFirewallRuleAction.BLOCK),
                FirewallRuleApplicability.MATCHING_BLOCK,
                RemoteReachabilityState.BLOCKED_BY_OBSERVED_POLICY,
            ),
        )
        for rule, applicability, reachability in cases:
            with self.subTest(applicability=applicability):
                provider, result = self.scan(
                    WindowsFirewallRuleResultCode.COMPLETE, rule
                )
                context = network_finding(result).network_context
                self.assertEqual(
                    context["policy_assessment"]["applicability"],
                    applicability.value,
                )
                self.assertEqual(context["reachability_state"], reachability.value)
                self.assertNotEqual(
                    context["reachability_state"],
                    RemoteReachabilityState.CONFIRMED_REACHABLE.value,
                )
                self.assertEqual(provider.launcher.calls, 1)

    def test_private_rule_values_do_not_cross_provider_or_scanner_state(self):
        application = r"C:\PRIVATE_PROVIDER_CANARY\secret.exe"
        interface = "PRIVATE_INTERFACE_CANARY"
        provider = provider_for(
            WindowsFirewallRuleResultCode.COMPLETE,
            raw_rule(
                application_path=RawWindowsApplicationPath(application),
                interfaces=(RawWindowsInterfaceIdentity(interface),),
            ),
        )
        normalized = provider.collect_normalized_firewall_policy()
        result = run_scan(WindowsPlatformAdapter(
            FakeWindowsApi(fixture()),
            provider_for(
                WindowsFirewallRuleResultCode.COMPLETE,
                raw_rule(
                    application_path=RawWindowsApplicationPath(application),
                    interfaces=(RawWindowsInterfaceIdentity(interface),),
                ),
            ),
        ))
        for boundary in (repr(normalized), repr(result)):
            self.assertNotIn(application, boundary)
            self.assertNotIn(interface, boundary)

    def test_failure_matrix_keeps_socket_findings_and_ignores_partial_prefix(self):
        for state in WindowsFirewallRuleResultCode:
            if state == WindowsFirewallRuleResultCode.COMPLETE:
                continue
            rules = ()
            with self.subTest(state=state):
                _, result = self.scan(state, *rules)
                finding = network_finding(result)
                expected_coverage = (
                    "UNKNOWN"
                    if state in {
                        WindowsFirewallRuleResultCode.API_UNAVAILABLE,
                        WindowsFirewallRuleResultCode.UNSUPPORTED,
                    }
                    else "INCOMPLETE"
                )
                expected_assessment = (
                    FirewallRuleApplicability.UNSUPPORTED
                    if expected_coverage == "UNKNOWN"
                    else FirewallRuleApplicability.INCOMPLETE
                )
                self.assertEqual(
                    result["coverage"]["network_socket_inspection"], "COMPLETE"
                )
                self.assertEqual(
                    result["coverage"]["host_firewall_rule_collection"],
                    expected_coverage,
                )
                self.assertEqual(
                    finding.network_context["policy_assessment"]["applicability"],
                    expected_assessment.value,
                )
                self.assertEqual(
                    finding.network_context["policy_assessment"][
                        "matching_rule_digests"
                    ],
                    [],
                )
                self.assertEqual(
                    finding.network_context["reachability_state"],
                    RemoteReachabilityState.POTENTIALLY_REACHABLE.value,
                )

    def test_default_adapter_route_uses_fake_launch_boundary(self):
        launcher = FakeHelperLauncher(_production_payload((raw_rule(),)))
        with patch(
            "cyberwatchtower.platform.windows.firewall_policy_provider."
            "WindowsFirewallSubprocessLauncher",
            return_value=launcher,
        ) as launcher_type:
            result = run_scan(WindowsPlatformAdapter(FakeWindowsApi(fixture())))
        launcher_type.assert_called_once_with()
        self.assertEqual(launcher.calls, 1)
        self.assertEqual(
            network_finding(result).network_context["policy_assessment"][
                "applicability"
            ],
            FirewallRuleApplicability.MATCHING_ALLOW.value,
        )

    def test_parent_imports_exclude_native_and_scanner_excludes_helper_layers(self):
        root = Path(__file__).parents[1] / "src" / "cyberwatchtower"
        provider = (root / "platform/windows/firewall_policy_provider.py").read_text(
            encoding="utf-8"
        ).casefold()
        scanner = (root / "scanner.py").read_text(encoding="utf-8").casefold()
        integration = (
            root / "platform/windows/firewall_policy_integration.py"
        ).read_text(encoding="utf-8").casefold()
        self.assertNotIn("firewall_rule_native", provider)
        self.assertNotIn("firewall_rule_native", integration)
        for forbidden in (
            "firewall_rule_native",
            "firewall_rule_helper",
            "firewall_rule_ipc",
            "firewall_rule_transport",
        ):
            self.assertNotIn(forbidden, scanner)


if __name__ == "__main__":
    unittest.main()
