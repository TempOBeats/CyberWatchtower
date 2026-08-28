"""Fixed-purpose Phase 2B.5 helper using a deterministic non-native backend."""

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
from .firewall_rule_models import (
    WindowsFirewallPolicyView,
    WindowsFirewallRuleCollectionResult,
    WindowsFirewallRuleResultCode,
)


def main() -> int:
    """Read one closed request, return one empty fake collection, then exit."""

    try:
        raw = sys.stdin.buffer.read(MAX_WINDOWS_FIREWALL_IPC_REQUEST_BYTES + 1)
        request = WindowsFirewallIpcPayload(
            WindowsFirewallIpcPayloadKind.REQUEST, raw
        )
        decode_windows_firewall_helper_request(request)
        result = WindowsFirewallRuleCollectionResult(
            WindowsFirewallRuleResultCode.COMPLETE,
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
        # The fixed helper emits no exception/native text or traceback.
        return int(WindowsFirewallHelperExitCode.PROTOCOL_FAILURE)


if __name__ == "__main__":
    raise SystemExit(main())
