import json
from pathlib import Path
import unittest

from cyberwatchtower.platform.windows.firewall_rule_ipc import (
    MAX_WINDOWS_FIREWALL_IPC_REQUEST_BYTES,
    MAX_WINDOWS_FIREWALL_IPC_RESPONSE_BYTES,
    WINDOWS_FIREWALL_HELPER_TIMEOUT_MS,
    WindowsFirewallHelperExitCode,
    WindowsFirewallHelperLifecycle,
    WindowsFirewallHelperLifecycleState,
    WindowsFirewallHelperRequest,
    WindowsFirewallHelperResponse,
    WindowsFirewallHelperTerminationState,
    WindowsFirewallHelperWaitResult,
    WindowsFirewallHelperWaitState,
    WindowsFirewallIpcPayload,
    WindowsFirewallIpcPayloadKind,
    WindowsFirewallIpcV2Request,
    WindowsFirewallIpcV2Response,
    decode_windows_firewall_helper_request,
    decode_windows_firewall_helper_response,
    encode_windows_firewall_helper_request,
    encode_windows_firewall_helper_response,
    decode_windows_firewall_ipc_v2_request,
    encode_windows_firewall_ipc_v2_response,
    windows_firewall_raw_rule_to_ipc_v2,
    run_isolated_windows_firewall_helper,
)
from cyberwatchtower.platform.windows.firewall_com_contracts import (
    WindowsComContractError,
    WindowsComFailureCategory,
)
from cyberwatchtower.platform.windows.firewall_rule_models import (
    RawWindowsApplicationPath,
    RawWindowsFirewallRule,
    RawWindowsInterfaceIdentity,
    WindowsFirewallPolicyView,
    WindowsFirewallRuleCollectionResult,
    WindowsFirewallRuleResultCode,
    WindowsRawFirewallRuleAction,
    WindowsRawFirewallRuleDirection,
)
from cyberwatchtower.platform.windows.firewall_rules import normalize_windows_firewall_rules


def _rule(port="443", path=None, interface=None):
    return RawWindowsFirewallRule(
        WindowsFirewallPolicyView.CURRENT_POLICY_VIEW, True,
        WindowsRawFirewallRuleDirection.INBOUND,
        WindowsRawFirewallRuleAction.ALLOW, 4, 6,
        local_ports=(port,), local_addresses=("*",),
        application_path=RawWindowsApplicationPath(path) if path else None,
        interfaces=(RawWindowsInterfaceIdentity(interface),) if interface else (),
    )


def _response(rules=(), state=WindowsFirewallRuleResultCode.COMPLETE):
    result = WindowsFirewallRuleCollectionResult(
        state, WindowsFirewallPolicyView.CURRENT_POLICY_VIEW, tuple(rules))
    return WindowsFirewallHelperResponse(
        "1", WindowsFirewallPolicyView.CURRENT_POLICY_VIEW, result)


def _production_payload(rules=(), state=WindowsFirewallRuleResultCode.COMPLETE):
    return encode_windows_firewall_ipc_v2_response(WindowsFirewallIpcV2Response(
        "2", WindowsFirewallPolicyView.CURRENT_POLICY_VIEW, state,
        tuple(windows_firewall_raw_rule_to_ipc_v2(rule) for rule in rules),
    ))


class _Process:
    def __init__(self, wait, termination=WindowsFirewallHelperTerminationState.EXITED,
                 exit_code=WindowsFirewallHelperExitCode.SUCCESS, errors=()):
        self.wait = wait
        self.termination = termination
        self.exit_code = exit_code
        self.errors = set(errors)
        self.events = []

    def wait_for_response(self, timeout_ms):
        self.events.append(("wait", timeout_ms))
        if "wait" in self.errors:
            raise RuntimeError("PRIVATE_NATIVE_ERROR")
        return self.wait

    def request_termination(self):
        self.events.append("terminate")
        if "terminate" in self.errors:
            raise RuntimeError("PRIVATE_NATIVE_ERROR")

    def wait_after_termination(self, timeout_ms):
        self.events.append(("grace", timeout_ms))
        return self.termination

    def force_kill(self):
        self.events.append("kill")
        if "kill" in self.errors:
            raise RuntimeError("PRIVATE_NATIVE_ERROR")

    def reap(self):
        self.events.append("reap")
        if "reap" in self.errors:
            raise RuntimeError("PRIVATE_NATIVE_ERROR")
        return self.exit_code


class _Launcher:
    def __init__(self, process=None, fail=False):
        self.process = process
        self.fail = fail

    def start(self, request):
        self.request = decode_windows_firewall_ipc_v2_request(request)
        if self.request != WindowsFirewallIpcV2Request():
            raise RuntimeError("unexpected fixed request")
        if self.fail:
            raise RuntimeError("PRIVATE_ENV_SECRET")
        return self.process


class SerializationTests(unittest.TestCase):
    def test_request_round_trip_is_deterministic_and_closed(self):
        first = encode_windows_firewall_helper_request(WindowsFirewallHelperRequest())
        second = encode_windows_firewall_helper_request(WindowsFirewallHelperRequest())
        self.assertEqual(first.consume_inside_boundary(), second.consume_inside_boundary())
        self.assertEqual(decode_windows_firewall_helper_request(first), WindowsFirewallHelperRequest())
        cases = (
            (b'{"operation":"COLLECT_WINDOWS_FIREWALL_CURRENT_POLICY","protocol_version":"1","extra":1}', WindowsComFailureCategory.INVALID_RESULT),
            (b'{"operation":"COLLECT_WINDOWS_FIREWALL_CURRENT_POLICY","protocol_version":"2"}', WindowsComFailureCategory.UNSUPPORTED),
        )
        for raw, expected in cases:
            with self.assertRaises(WindowsComContractError) as caught:
                decode_windows_firewall_helper_request(WindowsFirewallIpcPayload(
                    WindowsFirewallIpcPayloadKind.REQUEST, raw))
            self.assertEqual(caught.exception.category, expected)

    def test_request_and_response_size_limits(self):
        for kind, size in ((WindowsFirewallIpcPayloadKind.REQUEST,
                            MAX_WINDOWS_FIREWALL_IPC_REQUEST_BYTES),
                           (WindowsFirewallIpcPayloadKind.RESPONSE,
                            MAX_WINDOWS_FIREWALL_IPC_RESPONSE_BYTES)):
            with self.assertRaises(WindowsComContractError) as caught:
                WindowsFirewallIpcPayload(kind, b"x" * (size + 1))
            self.assertEqual(caught.exception.category,
                             WindowsComFailureCategory.LIMIT_EXCEEDED)

    def test_empty_one_many_and_maximum_responses(self):
        for rules in ((), (_rule(),), (_rule("80"), _rule("443")), (_rule(),) * 8192):
            decoded = decode_windows_firewall_helper_response(
                encode_windows_firewall_helper_response(_response(rules)))
            self.assertEqual(len(decoded.result.rules), len(rules))
            self.assertEqual(set(decoded.result.rules), set(rules))

    def test_response_order_is_irrelevant_and_malformed_data_fails(self):
        encoded = encode_windows_firewall_helper_response(_response((_rule(),)))
        reordered = json.dumps(json.loads(encoded.consume_inside_boundary()), indent=1).encode()
        self.assertEqual(decode_windows_firewall_helper_response(
            WindowsFirewallIpcPayload(WindowsFirewallIpcPayloadKind.RESPONSE,
                                      reordered)).result.rules, (_rule(),))
        mutations = (b"{", encoded.consume_inside_boundary()[:-1],
                     b'{"authority":"CURRENT_POLICY_VIEW","protocol_version":"1","result":"BAD","rules":[]}',
                     b'{"authority":"CURRENT_POLICY_VIEW","protocol_version":"1","result":"COMPLETE","rules":[],"extra":0}',
                     b'{"authority":"CURRENT_POLICY_VIEW","authority":"CURRENT_POLICY_VIEW","protocol_version":"1","result":"COMPLETE","rules":[]}')
        for raw in mutations:
            with self.assertRaises(WindowsComContractError):
                decode_windows_firewall_helper_response(WindowsFirewallIpcPayload(
                    WindowsFirewallIpcPayloadKind.RESPONSE, raw))

    def test_invalid_raw_rule_fails_closed(self):
        data = json.loads(encode_windows_firewall_helper_response(
            _response((_rule(),))).consume_inside_boundary())
        data["rules"][0]["profile_mask"] = True
        with self.assertRaises(WindowsComContractError):
            decode_windows_firewall_helper_response(WindowsFirewallIpcPayload(
                WindowsFirewallIpcPayloadKind.RESPONSE,
                json.dumps(data, separators=(",", ":")).encode()))
        data["rules"][0]["profile_mask"] = 4
        data["rules"][0]["application_path"] = "PRIVATE\u0000PATH"
        with self.assertRaises(WindowsComContractError) as caught:
            decode_windows_firewall_helper_response(WindowsFirewallIpcPayload(
                WindowsFirewallIpcPayloadKind.RESPONSE,
                json.dumps(data, separators=(",", ":")).encode()))
        self.assertEqual(caught.exception.category,
                         WindowsComFailureCategory.INVALID_RESULT)
        self.assertNotIn("PRIVATE", str(caught.exception))

    def test_private_fields_stay_redacted_and_use_existing_normalizer(self):
        path, interface = r"C:\\PRIVATE\\secret.exe", "PRIVATE_INTERFACE"
        payload = encode_windows_firewall_helper_response(
            _response((_rule(path=path, interface=interface),)))
        self.assertNotIn(path, repr(payload))
        self.assertNotIn(interface, repr(payload))
        result = decode_windows_firewall_helper_response(payload).result
        self.assertNotIn(path, repr(result))
        self.assertNotIn(interface, repr(result))
        normalized = normalize_windows_firewall_rules(result)
        self.assertIsNone(normalized.failure)
        self.assertNotIn(path, repr(normalized))
        self.assertNotIn(interface, repr(normalized))


class LifecycleTests(unittest.TestCase):
    def test_success_and_abnormal_exit(self):
        payload = _production_payload()
        wait = WindowsFirewallHelperWaitResult(WindowsFirewallHelperWaitState.RESPONSE,
                                               payload)
        process = _Process(wait)
        trace = WindowsFirewallHelperLifecycle()
        self.assertEqual(run_isolated_windows_firewall_helper(
            _Launcher(process), lifecycle=trace).state,
            WindowsFirewallRuleResultCode.COMPLETE)
        self.assertEqual(process.events, [("wait", WINDOWS_FIREWALL_HELPER_TIMEOUT_MS), "reap"])
        self.assertEqual(trace.events[-1], WindowsFirewallHelperLifecycleState.REAPED)
        process = _Process(wait, exit_code=WindowsFirewallHelperExitCode.HELPER_FAILURE)
        self.assertEqual(run_isolated_windows_firewall_helper(_Launcher(process)).state,
                         WindowsFirewallRuleResultCode.INTERNAL_ERROR)

    def test_fixed_parent_rejects_v1_response_without_fallback(self):
        v1_payload = encode_windows_firewall_helper_response(_response())
        process = _Process(WindowsFirewallHelperWaitResult(
            WindowsFirewallHelperWaitState.RESPONSE, v1_payload
        ))
        launcher = _Launcher(process)
        result = run_isolated_windows_firewall_helper(launcher)
        self.assertEqual(result.state, WindowsFirewallRuleResultCode.UNSUPPORTED)
        self.assertEqual(launcher.request.protocol_version, "2")
        self.assertEqual(process.events, [
            ("wait", WINDOWS_FIREWALL_HELPER_TIMEOUT_MS), "reap"
        ])

    def test_timeout_terminates_or_kills_then_reaps(self):
        wait = WindowsFirewallHelperWaitResult(WindowsFirewallHelperWaitState.TIMEOUT)
        for termination, suffix in (
            (WindowsFirewallHelperTerminationState.EXITED,
             ["terminate", ("grace", 1000), "reap"]),
            (WindowsFirewallHelperTerminationState.KILL_REQUIRED,
             ["terminate", ("grace", 1000), "kill", "reap"]),
        ):
            process = _Process(wait, termination)
            self.assertEqual(run_isolated_windows_firewall_helper(
                _Launcher(process)).state, WindowsFirewallRuleResultCode.TIMEOUT)
            self.assertEqual(process.events[1:], suffix)

    def test_spawn_failure_and_primary_failure_precedence(self):
        self.assertEqual(run_isolated_windows_firewall_helper(
            _Launcher(fail=True)).state, WindowsFirewallRuleResultCode.INTERNAL_ERROR)
        malformed = WindowsFirewallIpcPayload(WindowsFirewallIpcPayloadKind.RESPONSE,
                                              b"{bad")
        process = _Process(WindowsFirewallHelperWaitResult(
            WindowsFirewallHelperWaitState.RESPONSE, malformed), errors={"reap"})
        self.assertEqual(run_isolated_windows_firewall_helper(
            _Launcher(process)).state, WindowsFirewallRuleResultCode.INVALID_RESULT)
        timeout = WindowsFirewallHelperWaitResult(WindowsFirewallHelperWaitState.TIMEOUT)
        process = _Process(timeout, WindowsFirewallHelperTerminationState.KILL_REQUIRED,
                           errors={"kill", "reap"})
        self.assertEqual(run_isolated_windows_firewall_helper(
            _Launcher(process)).state, WindowsFirewallRuleResultCode.TIMEOUT)

    def test_protocol_exit_and_invalid_wait_are_sanitized(self):
        payload = _production_payload()
        process = _Process(WindowsFirewallHelperWaitResult(
            WindowsFirewallHelperWaitState.RESPONSE, payload),
            exit_code=WindowsFirewallHelperExitCode.PROTOCOL_FAILURE)
        self.assertEqual(run_isolated_windows_firewall_helper(
            _Launcher(process)).state, WindowsFirewallRuleResultCode.INVALID_RESULT)
        process = _Process(object())
        self.assertEqual(run_isolated_windows_firewall_helper(
            _Launcher(process)).state, WindowsFirewallRuleResultCode.INVALID_RESULT)
        self.assertIn("reap", process.events)
        process = _Process(WindowsFirewallHelperWaitResult(
            WindowsFirewallHelperWaitState.RESPONSE, payload), exit_code=99)
        self.assertEqual(run_isolated_windows_firewall_helper(
            _Launcher(process)).state, WindowsFirewallRuleResultCode.INTERNAL_ERROR)
        process = _Process(WindowsFirewallHelperWaitResult(
            WindowsFirewallHelperWaitState.RESPONSE, payload), errors={"reap"})
        self.assertEqual(run_isolated_windows_firewall_helper(
            _Launcher(process)).state, WindowsFirewallRuleResultCode.INTERNAL_ERROR)


class AuthorityTests(unittest.TestCase):
    def test_ipc_contract_is_mock_only_and_not_production_routed(self):
        root = Path(__file__).resolve().parents[1]
        source = (root / "src/cyberwatchtower/platform/windows/firewall_rule_ipc.py").read_text()
        lowered = source.casefold()
        for prohibited in ("cocreateinstance", "windll", "shell=true", "powershell",
                           "netsh", "winreg", "socket.", "idispatch", ".add(",
                           ".remove(", ".item("):
            self.assertNotIn(prohibited, lowered)
        self.assertNotIn("import subprocess", source)
        for name in ("api_native.py", "adapter.py"):
            production = (root / "src/cyberwatchtower/platform/windows" / name).read_text()
            self.assertNotIn("firewall_rule_ipc", production)
            self.assertNotIn("collect_windows_firewall_rules_from_collection", production)
        for name in ("scanner.py", "scoring.py", "reporting.py"):
            self.assertNotIn("firewall_rule_ipc",
                             (root / "src/cyberwatchtower" / name).read_text())


if __name__ == "__main__":
    unittest.main()
