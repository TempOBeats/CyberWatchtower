"""Test-only child behaviors for the real Phase 2B.5 process boundary."""

from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import sys
import time


def _closed_response(result="COMPLETE", rules=None):
    return json.dumps({
        "authority": "CURRENT_POLICY_VIEW",
        "protocol_version": "1",
        "result": result,
        "rules": [] if rules is None else rules,
    }, sort_keys=True, separators=(",", ":")).encode()


def main():
    scenario = sys.argv[1]
    sys.stdin.buffer.read(257)
    if scenario == "hang":
        time.sleep(60)
        return 0
    if scenario == "ignore_terminate":
        if os.name != "nt":
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        time.sleep(60)
        return 0
    if scenario == "abnormal":
        return 17
    if scenario == "abnormal_valid":
        sys.stdout.buffer.write(_closed_response())
        return 17
    if scenario == "helper_failure":
        sys.stdout.buffer.write(_closed_response("API_UNAVAILABLE"))
        return 0
    if scenario == "malformed":
        sys.stdout.buffer.write(b'{"PRIVATE_NATIVE_ERROR":')
        return 2
    if scenario == "truncated":
        sys.stdout.buffer.write(_closed_response()[:-1])
        return 2
    if scenario == "duplicate_keys":
        sys.stdout.buffer.write(b'{"authority":"CURRENT_POLICY_VIEW",'
                                b'"authority":"CURRENT_POLICY_VIEW",'
                                b'"protocol_version":"1","result":"COMPLETE","rules":[]}')
        return 2
    if scenario == "unknown_field":
        value = json.loads(_closed_response())
        value["PRIVATE_RULE_NAME"] = "canary"
        sys.stdout.buffer.write(json.dumps(value).encode())
        return 2
    if scenario == "unsupported_version":
        value = json.loads(_closed_response())
        value["protocol_version"] = "999"
        sys.stdout.buffer.write(json.dumps(value).encode())
        return 2
    if scenario == "invalid_authority":
        value = json.loads(_closed_response())
        value["authority"] = "EFFECTIVE_POLICY"
        sys.stdout.buffer.write(json.dumps(value).encode())
        return 2
    if scenario == "invalid_result":
        sys.stdout.buffer.write(_closed_response("PRIVATE_HRESULT"))
        return 2
    if scenario == "invalid_rule":
        sys.stdout.buffer.write(_closed_response(rules=[{"application_path":
            r"C:\\PRIVATE\\secret.exe"}]))
        return 2
    if scenario == "oversized":
        sys.stdout.buffer.write(b"x" * (8 * 1024 * 1024 + 1))
        return 2
    if scenario == "environment":
        canary = os.environ.get("CYBERWATCHTOWER_PRIVATE_SECRET", "absent")
        sys.stdout.buffer.write(canary.encode())
        return 2
    if scenario in {"one_rule", "many_rules"}:
        rule = {
            "action": "ALLOW", "application_path": None,
            "direction": "INBOUND", "edge_traversal": False,
            "enabled": True, "interface_types": [], "interfaces": [],
            "local_addresses": ["*"], "local_ports": ["443"],
            "profile_mask": 4, "protocol": 6, "remote_addresses": [],
            "remote_ports": [], "service_name": None,
            "unsupported_features": [],
        }
        rules = [rule] if scenario == "one_rule" else [
            {**rule, "local_ports": [str(10_000 + index)]}
            for index in range(64)
        ]
        sys.stdout.buffer.write(_closed_response(rules=rules))
        return 0
    raise AssertionError(Path(__file__).name)


if __name__ == "__main__":
    raise SystemExit(main())
