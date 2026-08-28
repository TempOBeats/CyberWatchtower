"""Fixed-purpose isolated helper for bounded Windows Firewall collection."""

from __future__ import annotations

import sys

from .firewall_rule_ipc import (
    MAX_WINDOWS_FIREWALL_IPC_REQUEST_BYTES,
    WindowsFirewallHelperExitCode,
    WindowsFirewallHelperResponse,
    WindowsFirewallIpcPayload,
    WindowsFirewallIpcPayloadKind,
    decode_windows_firewall_helper_request,
    encode_windows_firewall_helper_response,
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
        decode_windows_firewall_helper_request(request)
    except Exception:
        # Invalid requests produce no response or private diagnostic content.
        return int(WindowsFirewallHelperExitCode.PROTOCOL_FAILURE)

    try:
        result = _collect_backend()
        response = encode_windows_firewall_helper_response(
            WindowsFirewallHelperResponse(
                "1", WindowsFirewallPolicyView.CURRENT_POLICY_VIEW, result
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
            response = encode_windows_firewall_helper_response(
                WindowsFirewallHelperResponse(
                    "1", WindowsFirewallPolicyView.CURRENT_POLICY_VIEW, result
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
