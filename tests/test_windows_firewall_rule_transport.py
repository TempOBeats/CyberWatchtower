import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

from cyberwatchtower.platform.windows.firewall_rule_ipc import (
    MAX_WINDOWS_FIREWALL_IPC_REQUEST_BYTES,
    WindowsFirewallHelperLifecycle,
    WindowsFirewallHelperLifecycleState,
    WindowsFirewallHelperRequest,
    WindowsFirewallIpcPayload,
    WindowsFirewallIpcPayloadKind,
    encode_windows_firewall_helper_request,
    run_isolated_windows_firewall_helper,
)
from cyberwatchtower.platform.windows.firewall_rule_models import (
    WindowsFirewallRuleResultCode,
)
from cyberwatchtower.platform.windows.firewall_rule_transport import (
    WindowsFirewallSubprocessLauncher,
)


_REAL_POPEN = subprocess.Popen
_FIXTURE = Path(__file__).parent / "fixtures/windows_firewall_helper_fault.py"


class RealHelperTransportTests(unittest.TestCase):
    def test_fixed_helper_is_deterministic_and_reaped(self):
        results = []
        for _ in range(2):
            lifecycle = WindowsFirewallHelperLifecycle()
            with self._scenario("empty_complete"):
                result = run_isolated_windows_firewall_helper(
                    WindowsFirewallSubprocessLauncher(), lifecycle=lifecycle)
            self.assertEqual(result.state, WindowsFirewallRuleResultCode.COMPLETE)
            self.assertEqual(result.rules, ())
            self.assertEqual(lifecycle.events[-1],
                             WindowsFirewallHelperLifecycleState.REAPED)
            results.append(result)
        self.assertEqual(results[0], results[1])

    @unittest.skipIf(sys.platform == "win32", "portable test avoids native COM")
    def test_fixed_production_helper_is_closed_when_api_is_unavailable(self):
        result = run_isolated_windows_firewall_helper(
            WindowsFirewallSubprocessLauncher())
        self.assertEqual(result.state,
                         WindowsFirewallRuleResultCode.API_UNAVAILABLE)

    def test_one_many_rules_and_closed_failure_cross_real_process(self):
        for scenario, count in (("one_rule", 1), ("many_rules", 64)):
            with self._scenario(scenario):
                result = run_isolated_windows_firewall_helper(
                    WindowsFirewallSubprocessLauncher())
            self.assertEqual(result.state, WindowsFirewallRuleResultCode.COMPLETE)
            self.assertEqual(len(result.rules), count)
        with self._scenario("helper_failure"):
            result = run_isolated_windows_firewall_helper(
                WindowsFirewallSubprocessLauncher())
        self.assertEqual(result.state, WindowsFirewallRuleResultCode.API_UNAVAILABLE)

    def test_malformed_responses_fail_closed_without_canaries(self):
        scenarios = {
            "malformed": WindowsFirewallRuleResultCode.INVALID_RESULT,
            "truncated": WindowsFirewallRuleResultCode.INVALID_RESULT,
            "duplicate_keys": WindowsFirewallRuleResultCode.INVALID_RESULT,
            "unknown_field": WindowsFirewallRuleResultCode.INVALID_RESULT,
            "unsupported_version": WindowsFirewallRuleResultCode.UNSUPPORTED,
            "invalid_authority": WindowsFirewallRuleResultCode.INVALID_RESULT,
            "invalid_result": WindowsFirewallRuleResultCode.INVALID_RESULT,
            "invalid_rule": WindowsFirewallRuleResultCode.INVALID_RESULT,
        }
        for scenario, expected in scenarios.items():
            with self.subTest(scenario=scenario), self._scenario(scenario):
                result = run_isolated_windows_firewall_helper(
                    WindowsFirewallSubprocessLauncher())
                self.assertEqual(result.state, expected)
                safe = repr(result)
                for canary in ("PRIVATE", "HRESULT", "secret.exe", "canary"):
                    self.assertNotIn(canary, safe)

    def test_oversized_response_is_bounded_and_sanitized(self):
        started = time.monotonic()
        with self._scenario("oversized"):
            result = run_isolated_windows_firewall_helper(
                WindowsFirewallSubprocessLauncher())
        self.assertEqual(result.state, WindowsFirewallRuleResultCode.LIMIT_EXCEEDED)
        self.assertLess(time.monotonic() - started, 15)

    def test_parent_timeout_terminates_and_reaps_real_child(self):
        lifecycle = WindowsFirewallHelperLifecycle()
        with self._scenario("hang"):
            with patch("cyberwatchtower.platform.windows.firewall_rule_ipc."
                       "WINDOWS_FIREWALL_HELPER_TIMEOUT_MS", 100):
                result = run_isolated_windows_firewall_helper(
                    WindowsFirewallSubprocessLauncher(), lifecycle=lifecycle)
        self.assertEqual(result.state, WindowsFirewallRuleResultCode.TIMEOUT)
        self.assertIn(WindowsFirewallHelperLifecycleState.TERMINATION_REQUESTED,
                      lifecycle.events)
        self.assertEqual(lifecycle.events[-1],
                         WindowsFirewallHelperLifecycleState.REAPED)

    @unittest.skipIf(os.name == "nt", "TerminateProcess cannot be ignored on Windows")
    def test_ignored_termination_forces_kill_and_reaps(self):
        lifecycle = WindowsFirewallHelperLifecycle()
        with self._scenario("ignore_terminate"):
            with patch("cyberwatchtower.platform.windows.firewall_rule_ipc."
                       "WINDOWS_FIREWALL_HELPER_TIMEOUT_MS", 500), patch(
                           "cyberwatchtower.platform.windows.firewall_rule_ipc."
                           "WINDOWS_FIREWALL_HELPER_TERMINATION_GRACE_MS", 100):
                result = run_isolated_windows_firewall_helper(
                    WindowsFirewallSubprocessLauncher(), lifecycle=lifecycle)
        self.assertEqual(result.state, WindowsFirewallRuleResultCode.TIMEOUT)
        self.assertIn(WindowsFirewallHelperLifecycleState.FORCED_KILL,
                      lifecycle.events)
        self.assertEqual(lifecycle.events[-1],
                         WindowsFirewallHelperLifecycleState.REAPED)

    def test_abnormal_exit_and_spawn_failure_are_closed(self):
        with self._scenario("abnormal"):
            result = run_isolated_windows_firewall_helper(
                WindowsFirewallSubprocessLauncher())
        self.assertEqual(result.state, WindowsFirewallRuleResultCode.INVALID_RESULT)
        with self._scenario("abnormal_valid"):
            result = run_isolated_windows_firewall_helper(
                WindowsFirewallSubprocessLauncher())
        self.assertEqual(result.state, WindowsFirewallRuleResultCode.INTERNAL_ERROR)
        with patch("cyberwatchtower.platform.windows.firewall_rule_transport."
                   "subprocess.Popen", side_effect=OSError("PRIVATE_NATIVE_ERROR")):
            result = run_isolated_windows_firewall_helper(
                WindowsFirewallSubprocessLauncher())
        self.assertEqual(result.state, WindowsFirewallRuleResultCode.API_UNAVAILABLE)
        self.assertNotIn("PRIVATE", repr(result))

    def test_environment_secret_is_not_forwarded(self):
        with patch.dict(os.environ, {"CYBERWATCHTOWER_PRIVATE_SECRET": "SECRET"}):
            with self._scenario("environment"):
                result = run_isolated_windows_firewall_helper(
                    WindowsFirewallSubprocessLauncher())
        self.assertEqual(result.state, WindowsFirewallRuleResultCode.INVALID_RESULT)
        self.assertNotIn("SECRET", repr(result))

    def test_real_helper_rejects_malformed_oversized_and_trailing_requests(self):
        valid = encode_windows_firewall_helper_request(
            WindowsFirewallHelperRequest()).consume_inside_boundary()
        payloads = (
            b"{bad",
            b"x" * (MAX_WINDOWS_FIREWALL_IPC_REQUEST_BYTES + 1),
            valid + valid,
            b'{"operation":"COLLECT_WINDOWS_FIREWALL_CURRENT_POLICY",'
            b'"protocol_version":"1","extra":1}',
            b'{"operation":"COLLECT_WINDOWS_FIREWALL_CURRENT_POLICY",'
            b'"operation":"COLLECT_WINDOWS_FIREWALL_CURRENT_POLICY",'
            b'"protocol_version":"1"}',
            b'{"operation":"COLLECT_WINDOWS_FIREWALL_CURRENT_POLICY",'
            b'"protocol_version":"999"}',
        )
        for payload in payloads:
            process = _REAL_POPEN(
                (sys.executable, "-I", "-m",
                 "cyberwatchtower.platform.windows.firewall_rule_helper"),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, shell=False,
            )
            stdout, stderr = process.communicate(payload, timeout=5)
            self.assertEqual(process.returncode, 2)
            self.assertEqual(stdout, b"")
            self.assertEqual(stderr, b"")

    def test_launcher_is_fixed_and_native_authority_is_helper_confined(self):
        with self.assertRaises(TypeError):
            WindowsFirewallSubprocessLauncher("arbitrary")
        root = Path(__file__).resolve().parents[1]
        transport = (root / "src/cyberwatchtower/platform/windows/"
                     "firewall_rule_transport.py").read_text()
        helper = (root / "src/cyberwatchtower/platform/windows/"
                  "firewall_rule_helper.py").read_text()
        native = (root / "src/cyberwatchtower/platform/windows/"
                  "firewall_rule_native.py").read_text()
        transport_folded = transport.casefold()
        for prohibited in (
            "cocreateinstance", "inetfwrules", "win32com", "comtypes",
            "powershell", "netsh", "wmi", "winreg", "shell=true", "eval(",
            "exec(", "pickle", "marshal", "socket.",
        ):
            self.assertNotIn(prohibited, transport_folded)
        self.assertIn("firewall_rule_native", helper)
        for prohibited in (
            "GetIDsOfNames", "Invoke", "get_Name", "get_Description",
            "get_Grouping", "get_LocalUserOwner", "PowerShell", "netsh",
            "winreg", "socket.", "put_", ".Add(", ".Remove(", ".Item(",
        ):
            self.assertNotIn(prohibited, native)
        for production in ("api_native.py", "adapter.py"):
            text = (root / "src/cyberwatchtower/platform/windows" / production).read_text()
            self.assertNotIn("firewall_rule_native", text)
            self.assertNotIn("firewall_rule_transport", text)
        self.assertNotIn("firewall_rule_native",
                         (root / "src/cyberwatchtower/scanner.py").read_text())
        self.assertNotIn("firewall_rule_transport",
                         (root / "src/cyberwatchtower/scanner.py").read_text())

    def _scenario(self, scenario):
        def launch(_fixed_args, **kwargs):
            environment = dict(kwargs.get("env") or {})
            kwargs["env"] = environment
            return _REAL_POPEN((sys.executable, str(_FIXTURE), scenario), **kwargs)

        return patch("cyberwatchtower.platform.windows.firewall_rule_transport."
                     "subprocess.Popen", side_effect=launch)


if __name__ == "__main__":
    unittest.main()
