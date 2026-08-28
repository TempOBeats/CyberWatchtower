import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from cyberwatchtower.platform.windows.firewall_com_contracts import (
    WindowsComContractError,
    WindowsComFailureCategory,
    WindowsComInitializationLease,
    WindowsComInitializationResult,
)
from cyberwatchtower.platform.windows.firewall_rule_ipc import (
    run_isolated_windows_firewall_helper,
)
from cyberwatchtower.platform.windows.firewall_rule_transport import (
    WindowsFirewallSubprocessLauncher,
)
from cyberwatchtower.platform.windows.firewall_rule_models import (
    WindowsFirewallPolicyView,
    WindowsFirewallRuleCollectionResult,
    WindowsFirewallRuleResultCode,
)
from cyberwatchtower.platform.windows import firewall_rule_helper
from cyberwatchtower.platform.windows.firewall_rule_native import (
    _GUID,
    _VARIANT,
    collect_native_windows_firewall_rules,
)
from tests.test_windows_firewall_rule_collection import (
    MockEnumVariant,
    MockRulesCollection,
    fixture,
)
from tests.test_windows_firewall_rule_reader import MockFirewallRule


class _Policy:
    def __init__(self, rules, events, failure=None, release_failure=False):
        self.rules, self.events = rules, events
        self.failure, self.release_failure = failure, release_failure

    def get_rules(self):
        self.events.append("get-rules")
        if self.failure:
            raise WindowsComContractError(self.failure)
        return self.rules

    def release(self):
        self.events.append("release-policy")
        if self.release_failure:
            raise RuntimeError("PRIVATE_RELEASE_ERROR")


class _Runtime:
    def __init__(self, rules, init=WindowsComInitializationResult.S_OK,
                 activation_failure=None, policy_failure=None,
                 policy_release_failure=False):
        self.events = []
        self.rules, self.init = rules, init
        self.activation_failure, self.policy_failure = activation_failure, policy_failure
        self.policy_release_failure = policy_release_failure

    def initialize(self):
        self.events.append("initialize")
        return WindowsComInitializationLease(
            self.init, lambda: self.events.append("uninitialize"))

    def activate_policy2(self):
        self.events.append("activate-policy")
        if self.activation_failure:
            raise WindowsComContractError(self.activation_failure)
        return _Policy(self.rules, self.events, self.policy_failure,
                       self.policy_release_failure)


class NativeFirewallCollectorPortableTests(unittest.TestCase):
    @unittest.skipIf(sys.platform == "win32", "non-Windows import-safety check")
    def test_native_runtime_fails_closed_without_loading_windows_libraries(self):
        result = collect_native_windows_firewall_rules()
        self.assertEqual(result.state,
                         WindowsFirewallRuleResultCode.API_UNAVAILABLE)

    def test_helper_selects_native_collector_only_inside_windows_child(self):
        expected = WindowsFirewallRuleCollectionResult(
            WindowsFirewallRuleResultCode.COMPLETE,
            WindowsFirewallPolicyView.CURRENT_POLICY_VIEW,
        )
        with patch.object(firewall_rule_helper.sys, "platform", "win32"), patch(
            "cyberwatchtower.platform.windows.firewall_rule_native."
            "collect_native_windows_firewall_rules",
            return_value=expected,
        ) as collect:
            self.assertIs(firewall_rule_helper._collect_backend(), expected)
        collect.assert_called_once_with()

    def test_s_ok_and_s_false_initialize_collect_and_cleanup_in_order(self):
        for initialization in (WindowsComInitializationResult.S_OK,
                               WindowsComInitializationResult.S_FALSE):
            runtime = _Runtime(fixture(), initialization)
            result = collect_native_windows_firewall_rules(runtime)
            self.assertEqual(result.state, WindowsFirewallRuleResultCode.COMPLETE)
            self.assertEqual(runtime.events[-2:],
                             ["release-policy", "uninitialize"])

    def test_changed_mode_and_activation_failures_are_sanitized(self):
        runtime = _Runtime(fixture(), WindowsComInitializationResult.RPC_E_CHANGED_MODE)
        self.assertEqual(collect_native_windows_firewall_rules(runtime).state,
                         WindowsFirewallRuleResultCode.INTERNAL_ERROR)
        self.assertNotIn("uninitialize", runtime.events)
        for failure, expected in (
            (WindowsComFailureCategory.API_UNAVAILABLE,
             WindowsFirewallRuleResultCode.API_UNAVAILABLE),
            (WindowsComFailureCategory.ACCESS_DENIED,
             WindowsFirewallRuleResultCode.ACCESS_DENIED),
        ):
            runtime = _Runtime(fixture(), activation_failure=failure)
            result = collect_native_windows_firewall_rules(runtime)
            self.assertEqual(result.state, expected)
            self.assertEqual(runtime.events[-1], "uninitialize")

    def test_rules_flow_only_through_existing_collection_engine(self):
        for rules, expected in ((fixture(), WindowsFirewallRuleResultCode.COMPLETE),
                                (fixture(MockFirewallRule()),
                                 WindowsFirewallRuleResultCode.COMPLETE),
                                (fixture(reported_count=1),
                                 WindowsFirewallRuleResultCode.COLLECTION_INCOMPLETE)):
            result = collect_native_windows_firewall_rules(_Runtime(rules))
            self.assertEqual(result.state, expected)

    def test_exact_rule_limit_remains_supported(self):
        events = []
        enumerator = MockEnumVariant(events=events, lazy_count=8192)
        result = collect_native_windows_firewall_rules(
            _Runtime(MockRulesCollection(8192, enumerator, events=events)))
        self.assertEqual(result.state, WindowsFirewallRuleResultCode.COMPLETE)
        self.assertEqual(len(result.rules), 8192)

    def test_primary_failure_precedes_cleanup_failure(self):
        runtime = _Runtime(
            fixture(), policy_failure=WindowsComFailureCategory.ACCESS_DENIED,
            policy_release_failure=True)
        self.assertEqual(collect_native_windows_firewall_rules(runtime).state,
                         WindowsFirewallRuleResultCode.ACCESS_DENIED)
        runtime = _Runtime(fixture(), policy_release_failure=True)
        self.assertEqual(collect_native_windows_firewall_rules(runtime).state,
                         WindowsFirewallRuleResultCode.INTERNAL_ERROR)

    def test_native_abi_shapes_are_fixed_and_import_safe(self):
        self.assertEqual(ctypes_size(_GUID), 16)
        self.assertIn(ctypes_size(_VARIANT), (16, 24))
        source = Path(__file__).parents[1] / (
            "src/cyberwatchtower/platform/windows/firewall_rule_native.py")
        text = source.read_text()
        for prohibited in ("GetIDsOfNames", "Invoke", "get_Name", "get_Description",
                           "get_Grouping", "get_LocalUserOwner", "PowerShell",
                           "netsh", "winreg", "socket."):
            self.assertNotIn(prohibited, text)


def ctypes_size(value):
    import ctypes
    return ctypes.sizeof(value)


@unittest.skipUnless(
    sys.platform == "win32" and
    os.environ.get("CYBERWATCHTOWER_VALIDATE_NATIVE_FIREWALL_RULES") == "1",
    "guarded native Windows Firewall validation requires explicit opt-in",
)
class GuardedNativeWindowsFirewallTests(unittest.TestCase):
    def test_isolated_native_current_policy_collection(self):
        result = run_isolated_windows_firewall_helper(
            WindowsFirewallSubprocessLauncher())
        self.assertEqual(result.state, WindowsFirewallRuleResultCode.COMPLETE)
        self.assertLessEqual(len(result.rules), 8192)
        self.assertNotIn("C:\\", repr(result))


if __name__ == "__main__":
    unittest.main()
