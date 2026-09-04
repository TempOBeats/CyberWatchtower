"""Fixed-purpose isolated helper for bounded Windows Firewall collection."""

from __future__ import annotations

import sys

from .firewall_rule_ipc import (
    MAX_WINDOWS_FIREWALL_IPC_REQUEST_BYTES,
    WindowsFirewallHelperExitCode,
    WINDOWS_FIREWALL_IPC_PROTOCOL_VERSION_V3,
    WindowsFirewallIpcV3Request,
    WindowsFirewallIpcV3Response,
    WindowsFirewallIpcPayload,
    WindowsFirewallIpcPayloadKind,
    decode_windows_firewall_ipc_v3_request,
    encode_windows_firewall_ipc_v3_response,
    windows_firewall_raw_rule_to_ipc_v3,
)
from .firewall_com_contracts import WindowsComContractError
from .firewall_rule_models import (
    WindowsFirewallPolicyView,
    WindowsFirewallRuleCollectionResult,
    WindowsFirewallRuleResultCode,
)
def _collect_backend() -> WindowsFirewallRuleCollectionResult:
    if sys.platform != "win32":
        return WindowsFirewallRuleCollectionResult(
            WindowsFirewallRuleResultCode.API_UNAVAILABLE,
            WindowsFirewallPolicyView.CURRENT_POLICY_VIEW,
        )
    # Imported only inside the isolated Windows helper after request validation.
    from .firewall_rule_native import collect_native_windows_firewall_rules

    return collect_native_windows_firewall_rules()


def main() -> int:
    """Read one closed request, collect inside the helper, then exit."""

    try:
        raw = sys.stdin.buffer.read(MAX_WINDOWS_FIREWALL_IPC_REQUEST_BYTES + 1)
        request = WindowsFirewallIpcPayload(
            WindowsFirewallIpcPayloadKind.REQUEST, raw
        )
        decoded = decode_windows_firewall_ipc_v3_request(request)
        if decoded != WindowsFirewallIpcV3Request():
            raise ValueError("fixed helper request is invalid.")
    except Exception:
        # Invalid requests produce no response or private error content.
        return int(WindowsFirewallHelperExitCode.PROTOCOL_FAILURE)

    try:
        result = _collect_backend()
        response = encode_windows_firewall_ipc_v3_response(
            WindowsFirewallIpcV3Response(
                WINDOWS_FIREWALL_IPC_PROTOCOL_VERSION_V3,
                WindowsFirewallPolicyView.CURRENT_POLICY_VIEW,
                result.state,
                tuple(windows_firewall_raw_rule_to_ipc_v3(rule)
                      for rule in result.rules),
            )
        )
        sys.stdout.buffer.write(response.consume_inside_boundary())
        sys.stdout.buffer.flush()
        return int(WindowsFirewallHelperExitCode.SUCCESS)
    except WindowsComContractError as exc:
        try:
            result = WindowsFirewallRuleCollectionResult(
                WindowsFirewallRuleResultCode(exc.category.value),
                WindowsFirewallPolicyView.CURRENT_POLICY_VIEW,
            )
            response = encode_windows_firewall_ipc_v3_response(
                WindowsFirewallIpcV3Response(
                    WINDOWS_FIREWALL_IPC_PROTOCOL_VERSION_V3,
                    WindowsFirewallPolicyView.CURRENT_POLICY_VIEW,
                    result.state,
                )
            )
            sys.stdout.buffer.write(response.consume_inside_boundary())
            sys.stdout.buffer.flush()
            return int(WindowsFirewallHelperExitCode.SUCCESS)
        except Exception:
            return int(WindowsFirewallHelperExitCode.PROTOCOL_FAILURE)
    except Exception:
        # The fixed helper emits no exception/native text or traceback.
        return int(WindowsFirewallHelperExitCode.PROTOCOL_FAILURE)

if __name__ == "__main__":
    raise SystemExit(main())
