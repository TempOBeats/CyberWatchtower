"""Portable isolation and IPC contracts for Windows Firewall rule collection.

No process launcher or native COM implementation exists here.  The fixed
launcher/process protocols and deterministic JSON envelopes are exercised with
portable fakes so a future parent can enforce a hard deadline around a known
internal helper.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum
import json
from typing import Protocol, runtime_checkable

from cyberwatchtower.firewall_policy import (
    MAX_FIREWALL_RULES,
    MAX_NORMALIZED_TOKEN,
    MAX_VALUES_PER_CONDITION,
)

from .firewall_com_contracts import (
    WindowsComContractError,
    WindowsComFailureCategory,
)
from .firewall_rule_models import (
    MAX_RAW_WINDOWS_APPLICATION_PATH,
    RawWindowsApplicationPath,
    RawWindowsFirewallRule,
    RawWindowsInterfaceIdentity,
    WindowsFirewallPolicyView,
    WindowsFirewallRuleCollectionResult,
    WindowsFirewallRuleResultCode,
    WindowsRawFirewallInterfaceType,
    WindowsRawFirewallRuleAction,
    WindowsRawFirewallRuleDirection,
    WindowsRawFirewallUnsupportedFeature,
)
from .firewall_rules import normalize_windows_firewall_rules


WINDOWS_FIREWALL_IPC_PROTOCOL_VERSION = "1"
WINDOWS_FIREWALL_HELPER_TIMEOUT_MS = 15_000
WINDOWS_FIREWALL_HELPER_TERMINATION_GRACE_MS = 1_000
MAX_WINDOWS_FIREWALL_IPC_REQUEST_BYTES = 256
MAX_WINDOWS_FIREWALL_IPC_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_WINDOWS_FIREWALL_IPC_JSON_DEPTH = 6


class WindowsFirewallIpcOperation(str, Enum):
    COLLECT_CURRENT_POLICY = "COLLECT_WINDOWS_FIREWALL_CURRENT_POLICY"


class WindowsFirewallIpcPayloadKind(str, Enum):
    REQUEST = "REQUEST"
    RESPONSE = "RESPONSE"


class WindowsFirewallHelperWaitState(str, Enum):
    RESPONSE = "RESPONSE"
    TIMEOUT = "TIMEOUT"


class WindowsFirewallHelperTerminationState(str, Enum):
    EXITED = "EXITED"
    KILL_REQUIRED = "KILL_REQUIRED"


class WindowsFirewallHelperExitCode(IntEnum):
    SUCCESS = 0
    HELPER_FAILURE = 1
    PROTOCOL_FAILURE = 2


class WindowsFirewallHelperLifecycleState(str, Enum):
    NOT_STARTED = "NOT_STARTED"
    STARTED = "STARTED"
    REQUEST_DELIVERED = "REQUEST_DELIVERED"
    RESPONSE_RECEIVED = "RESPONSE_RECEIVED"
    GRACEFUL_EXIT = "GRACEFUL_EXIT"
    TIMEOUT = "TIMEOUT"
    TERMINATION_REQUESTED = "TERMINATION_REQUESTED"
    FORCED_KILL = "FORCED_KILL"
    REAPED = "REAPED"
    SPAWN_FAILURE = "SPAWN_FAILURE"
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
    ABNORMAL_EXIT = "ABNORMAL_EXIT"
    REAP_FAILED = "REAP_FAILED"


class WindowsFirewallIpcPayload:
    """Bounded opaque bytes; repr/str never reveal private IPC contents."""

    __slots__ = ("kind", "_data", "_sealed")

    def __init__(self, kind: WindowsFirewallIpcPayloadKind, data: bytes) -> None:
        if not isinstance(kind, WindowsFirewallIpcPayloadKind):
            raise TypeError("IPC payload kind must use the closed enum.")
        if not isinstance(data, bytes):
            raise TypeError("IPC payload must be immutable bytes.")
        maximum = (
            MAX_WINDOWS_FIREWALL_IPC_REQUEST_BYTES
            if kind == WindowsFirewallIpcPayloadKind.REQUEST
            else MAX_WINDOWS_FIREWALL_IPC_RESPONSE_BYTES
        )
        if not data:
            raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)
        if len(data) > maximum:
            raise WindowsComContractError(WindowsComFailureCategory.LIMIT_EXCEEDED)
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "_data", data)
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError("IPC payload is immutable.")
        object.__setattr__(self, name, value)

    def __repr__(self) -> str:
        return f"WindowsFirewallIpcPayload({self.kind.value}, <redacted>)"

    __str__ = __repr__

    def consume_inside_boundary(self) -> bytes:
        return self._data


@dataclass(frozen=True, slots=True)
class WindowsFirewallHelperRequest:
    protocol_version: str = WINDOWS_FIREWALL_IPC_PROTOCOL_VERSION
    operation: WindowsFirewallIpcOperation = (
        WindowsFirewallIpcOperation.COLLECT_CURRENT_POLICY
    )

    def __post_init__(self) -> None:
        if self.protocol_version != WINDOWS_FIREWALL_IPC_PROTOCOL_VERSION:
            raise WindowsComContractError(WindowsComFailureCategory.UNSUPPORTED)
        if not isinstance(self.operation, WindowsFirewallIpcOperation):
            raise TypeError("helper operation must use the closed enum.")


@dataclass(frozen=True, slots=True)
class WindowsFirewallHelperResponse:
    protocol_version: str
    authority: WindowsFirewallPolicyView
    result: WindowsFirewallRuleCollectionResult

    def __post_init__(self) -> None:
        if self.protocol_version != WINDOWS_FIREWALL_IPC_PROTOCOL_VERSION:
            raise WindowsComContractError(WindowsComFailureCategory.UNSUPPORTED)
        if self.authority != WindowsFirewallPolicyView.CURRENT_POLICY_VIEW:
            raise ValueError("helper authority must remain current-policy view.")
        if not isinstance(self.result, WindowsFirewallRuleCollectionResult):
            raise TypeError("helper response requires the typed rule result.")
        if self.result.policy_view != self.authority:
            raise ValueError("helper result authority does not match envelope.")
        if self.result.state != WindowsFirewallRuleResultCode.COMPLETE \
                and self.result.rules:
            raise ValueError("failed helper response cannot retain raw rules.")
        if normalize_windows_firewall_rules(self.result).failure is not None \
                and self.result.state == WindowsFirewallRuleResultCode.COMPLETE:
            raise ValueError("helper response contains invalid normalized rules.")


@dataclass(frozen=True, slots=True)
class WindowsFirewallHelperWaitResult:
    state: WindowsFirewallHelperWaitState
    payload: WindowsFirewallIpcPayload | None = field(
        default=None, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        if not isinstance(self.state, WindowsFirewallHelperWaitState):
            raise TypeError("helper wait state must use the closed enum.")
        if self.state == WindowsFirewallHelperWaitState.RESPONSE:
            if not isinstance(self.payload, WindowsFirewallIpcPayload) \
                    or self.payload.kind != WindowsFirewallIpcPayloadKind.RESPONSE:
                raise ValueError("response wait state requires a response payload.")
        elif self.payload is not None:
            raise ValueError("timeout wait state cannot carry a payload.")


@runtime_checkable
class WindowsFirewallHelperProcessProtocol(Protocol):
    def wait_for_response(self, timeout_ms: int) -> WindowsFirewallHelperWaitResult: ...

    def request_termination(self) -> None: ...

    def wait_after_termination(
        self, timeout_ms: int
    ) -> WindowsFirewallHelperTerminationState: ...

    def force_kill(self) -> None: ...

    def reap(self) -> WindowsFirewallHelperExitCode: ...


@runtime_checkable
class WindowsFirewallHelperLauncherProtocol(Protocol):
    """Fixed helper launch seam; callers cannot supply executable details."""

    def start(
        self, request: WindowsFirewallIpcPayload
    ) -> WindowsFirewallHelperProcessProtocol: ...


class WindowsFirewallHelperLifecycle:
    __slots__ = ("_events",)

    _ALLOWED = {
        WindowsFirewallHelperLifecycleState.NOT_STARTED: {
            WindowsFirewallHelperLifecycleState.STARTED,
            WindowsFirewallHelperLifecycleState.SPAWN_FAILURE,
        },
        WindowsFirewallHelperLifecycleState.STARTED: {
            WindowsFirewallHelperLifecycleState.REQUEST_DELIVERED,
        },
        WindowsFirewallHelperLifecycleState.REQUEST_DELIVERED: {
            WindowsFirewallHelperLifecycleState.RESPONSE_RECEIVED,
            WindowsFirewallHelperLifecycleState.TIMEOUT,
        },
        WindowsFirewallHelperLifecycleState.RESPONSE_RECEIVED: {
            WindowsFirewallHelperLifecycleState.GRACEFUL_EXIT,
            WindowsFirewallHelperLifecycleState.MALFORMED_RESPONSE,
            WindowsFirewallHelperLifecycleState.ABNORMAL_EXIT,
            WindowsFirewallHelperLifecycleState.REAP_FAILED,
        },
        WindowsFirewallHelperLifecycleState.GRACEFUL_EXIT: {
            WindowsFirewallHelperLifecycleState.REAPED,
        },
        WindowsFirewallHelperLifecycleState.MALFORMED_RESPONSE: {
            WindowsFirewallHelperLifecycleState.REAPED,
            WindowsFirewallHelperLifecycleState.REAP_FAILED,
        },
        WindowsFirewallHelperLifecycleState.ABNORMAL_EXIT: {
            WindowsFirewallHelperLifecycleState.REAPED,
            WindowsFirewallHelperLifecycleState.REAP_FAILED,
        },
        WindowsFirewallHelperLifecycleState.TIMEOUT: {
            WindowsFirewallHelperLifecycleState.TERMINATION_REQUESTED,
        },
        WindowsFirewallHelperLifecycleState.TERMINATION_REQUESTED: {
            WindowsFirewallHelperLifecycleState.GRACEFUL_EXIT,
            WindowsFirewallHelperLifecycleState.FORCED_KILL,
            WindowsFirewallHelperLifecycleState.REAP_FAILED,
        },
        WindowsFirewallHelperLifecycleState.FORCED_KILL: {
            WindowsFirewallHelperLifecycleState.REAPED,
            WindowsFirewallHelperLifecycleState.REAP_FAILED,
        },
    }

    def __init__(self) -> None:
        self._events = [WindowsFirewallHelperLifecycleState.NOT_STARTED]

    @property
    def events(self) -> tuple[WindowsFirewallHelperLifecycleState, ...]:
        return tuple(self._events)

    def transition(self, state: WindowsFirewallHelperLifecycleState) -> None:
        if not isinstance(state, WindowsFirewallHelperLifecycleState):
            raise TypeError("helper lifecycle state must use the closed enum.")
        if state not in self._ALLOWED.get(self._events[-1], set()):
            raise WindowsComContractError(WindowsComFailureCategory.INTERNAL_ERROR)
        self._events.append(state)


def encode_windows_firewall_helper_request(
    request: WindowsFirewallHelperRequest,
) -> WindowsFirewallIpcPayload:
    if not isinstance(request, WindowsFirewallHelperRequest):
        raise TypeError("request encoder requires the closed request contract.")
    return _payload(
        WindowsFirewallIpcPayloadKind.REQUEST,
        {
            "operation": request.operation.value,
            "protocol_version": request.protocol_version,
        },
    )


def decode_windows_firewall_helper_request(
    payload: WindowsFirewallIpcPayload,
) -> WindowsFirewallHelperRequest:
    value = _decode_payload(payload, WindowsFirewallIpcPayloadKind.REQUEST)
    _exact_fields(value, {"operation", "protocol_version"})
    version = value["protocol_version"]
    if version != WINDOWS_FIREWALL_IPC_PROTOCOL_VERSION:
        raise WindowsComContractError(WindowsComFailureCategory.UNSUPPORTED)
    try:
        operation = WindowsFirewallIpcOperation(value["operation"])
        return WindowsFirewallHelperRequest(version, operation)
    except WindowsComContractError:
        raise
    except (TypeError, ValueError):
        raise WindowsComContractError(
            WindowsComFailureCategory.INVALID_RESULT
        ) from None


def encode_windows_firewall_helper_response(
    response: WindowsFirewallHelperResponse,
) -> WindowsFirewallIpcPayload:
    if not isinstance(response, WindowsFirewallHelperResponse):
        raise TypeError("response encoder requires the closed response contract.")
    return _payload(
        WindowsFirewallIpcPayloadKind.RESPONSE,
        {
            "authority": response.authority.value,
            "protocol_version": response.protocol_version,
            "result": response.result.state.value,
            "rules": [_encode_rule(rule) for rule in response.result.rules],
        },
    )


def decode_windows_firewall_helper_response(
    payload: WindowsFirewallIpcPayload,
) -> WindowsFirewallHelperResponse:
    value = _decode_payload(payload, WindowsFirewallIpcPayloadKind.RESPONSE)
    _exact_fields(value, {"authority", "protocol_version", "result", "rules"})
    version = value["protocol_version"]
    if version != WINDOWS_FIREWALL_IPC_PROTOCOL_VERSION:
        raise WindowsComContractError(WindowsComFailureCategory.UNSUPPORTED)
    try:
        authority = WindowsFirewallPolicyView(value["authority"])
        state = WindowsFirewallRuleResultCode(value["result"])
        encoded_rules = value["rules"]
        if not isinstance(encoded_rules, list) or len(encoded_rules) > MAX_FIREWALL_RULES:
            raise ValueError
        rules = tuple(_decode_rule(item, authority) for item in encoded_rules)
        result = WindowsFirewallRuleCollectionResult(state, authority, rules)
        return WindowsFirewallHelperResponse(version, authority, result)
    except WindowsComContractError:
        raise
    except (KeyError, TypeError, ValueError):
        raise WindowsComContractError(
            WindowsComFailureCategory.INVALID_RESULT
        ) from None


def run_isolated_windows_firewall_helper(
    launcher: WindowsFirewallHelperLauncherProtocol,
    *,
    lifecycle: WindowsFirewallHelperLifecycle | None = None,
) -> WindowsFirewallRuleCollectionResult:
    """Run one fixed request through a mocked parent-owned process lifecycle."""

    if not isinstance(launcher, WindowsFirewallHelperLauncherProtocol):
        raise TypeError("helper runner requires the fixed launcher protocol.")
    trace = lifecycle or WindowsFirewallHelperLifecycle()
    if not isinstance(trace, WindowsFirewallHelperLifecycle) \
            or trace.events != (WindowsFirewallHelperLifecycleState.NOT_STARTED,):
        raise TypeError("helper lifecycle must be a fresh typed tracker.")
    try:
        request = encode_windows_firewall_helper_request(
            WindowsFirewallHelperRequest()
        )
        process = launcher.start(request)
        if not isinstance(process, WindowsFirewallHelperProcessProtocol):
            raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)
    except WindowsComContractError as exc:
        trace.transition(WindowsFirewallHelperLifecycleState.SPAWN_FAILURE)
        return _failure(_result_code(exc.category))
    except Exception:
        trace.transition(WindowsFirewallHelperLifecycleState.SPAWN_FAILURE)
        return _failure(WindowsFirewallRuleResultCode.INTERNAL_ERROR)
    trace.transition(WindowsFirewallHelperLifecycleState.STARTED)
    trace.transition(WindowsFirewallHelperLifecycleState.REQUEST_DELIVERED)
    try:
        wait = process.wait_for_response(WINDOWS_FIREWALL_HELPER_TIMEOUT_MS)
    except WindowsComContractError as exc:
        return _terminate_and_reap(process, trace, _result_code(exc.category))
    except Exception:
        return _terminate_and_reap(
            process, trace, WindowsFirewallRuleResultCode.INTERNAL_ERROR
        )
    if not isinstance(wait, WindowsFirewallHelperWaitResult):
        return _terminate_and_reap(
            process, trace, WindowsFirewallRuleResultCode.INVALID_RESULT
        )
    if wait.state == WindowsFirewallHelperWaitState.TIMEOUT:
        trace.transition(WindowsFirewallHelperLifecycleState.TIMEOUT)
        return _terminate_and_reap(
            process, trace, WindowsFirewallRuleResultCode.TIMEOUT,
            timeout_already_recorded=True,
        )
    trace.transition(WindowsFirewallHelperLifecycleState.RESPONSE_RECEIVED)
    primary: WindowsFirewallRuleResultCode | None = None
    response = None
    try:
        response = decode_windows_firewall_helper_response(wait.payload)
    except WindowsComContractError as exc:
        primary = _result_code(exc.category)
        trace.transition(WindowsFirewallHelperLifecycleState.MALFORMED_RESPONSE)
    exit_code = _reap_response(process, trace, primary)
    if primary is not None:
        return _failure(primary)
    if exit_code is None:
        return _failure(WindowsFirewallRuleResultCode.INTERNAL_ERROR)
    if exit_code == WindowsFirewallHelperExitCode.PROTOCOL_FAILURE:
        return _failure(WindowsFirewallRuleResultCode.INVALID_RESULT)
    if exit_code != WindowsFirewallHelperExitCode.SUCCESS:
        return _failure(WindowsFirewallRuleResultCode.INTERNAL_ERROR)
    assert response is not None
    return response.result


def _terminate_and_reap(
    process: WindowsFirewallHelperProcessProtocol,
    trace: WindowsFirewallHelperLifecycle,
    primary: WindowsFirewallRuleResultCode,
    *,
    timeout_already_recorded: bool = False,
) -> WindowsFirewallRuleCollectionResult:
    if not timeout_already_recorded:
        trace.transition(WindowsFirewallHelperLifecycleState.TIMEOUT)
    trace.transition(WindowsFirewallHelperLifecycleState.TERMINATION_REQUESTED)
    kill_required = False
    try:
        process.request_termination()
        state = process.wait_after_termination(
            WINDOWS_FIREWALL_HELPER_TERMINATION_GRACE_MS
        )
        if not isinstance(state, WindowsFirewallHelperTerminationState):
            kill_required = True
        elif state == WindowsFirewallHelperTerminationState.EXITED:
            trace.transition(WindowsFirewallHelperLifecycleState.GRACEFUL_EXIT)
        else:
            kill_required = True
    except Exception:
        kill_required = True
    if kill_required:
        trace.transition(WindowsFirewallHelperLifecycleState.FORCED_KILL)
        try:
            process.force_kill()
        except Exception:
            pass
    try:
        process.reap()
        trace.transition(WindowsFirewallHelperLifecycleState.REAPED)
    except Exception:
        trace.transition(WindowsFirewallHelperLifecycleState.REAP_FAILED)
    return _failure(primary)


def _reap_response(
    process: WindowsFirewallHelperProcessProtocol,
    trace: WindowsFirewallHelperLifecycle,
    primary: WindowsFirewallRuleResultCode | None,
) -> WindowsFirewallHelperExitCode | None:
    try:
        value = process.reap()
    except Exception:
        trace.transition(WindowsFirewallHelperLifecycleState.REAP_FAILED)
        return None
    if primary is None:
        if not isinstance(value, WindowsFirewallHelperExitCode) \
                or value != WindowsFirewallHelperExitCode.SUCCESS:
            trace.transition(WindowsFirewallHelperLifecycleState.ABNORMAL_EXIT)
        else:
            trace.transition(WindowsFirewallHelperLifecycleState.GRACEFUL_EXIT)
    trace.transition(WindowsFirewallHelperLifecycleState.REAPED)
    return value if isinstance(value, WindowsFirewallHelperExitCode) else None


def _encode_rule(rule: RawWindowsFirewallRule) -> dict[str, object]:
    return {
        "action": rule.action.value,
        "application_path": (
            rule.application_path.consume_for_normalization()
            if rule.application_path is not None else None
        ),
        "direction": rule.direction.value,
        "edge_traversal": rule.edge_traversal,
        "enabled": rule.enabled,
        "interface_types": [value.value for value in rule.interface_types],
        "interfaces": [value.consume_for_normalization() for value in rule.interfaces],
        "local_addresses": list(rule.local_addresses),
        "local_ports": list(rule.local_ports),
        "profile_mask": rule.profile_mask,
        "protocol": rule.protocol,
        "remote_addresses": list(rule.remote_addresses),
        "remote_ports": list(rule.remote_ports),
        "service_name": rule.service_name,
        "unsupported_features": [
            value.value for value in rule.unsupported_features
        ],
    }


_RULE_FIELDS = {
    "action", "application_path", "direction", "edge_traversal", "enabled",
    "interface_types", "interfaces", "local_addresses", "local_ports",
    "profile_mask", "protocol", "remote_addresses", "remote_ports",
    "service_name", "unsupported_features",
}


def _decode_rule(value: object, authority: WindowsFirewallPolicyView):
    _exact_fields(value, _RULE_FIELDS)
    application = value["application_path"]
    interfaces = value["interfaces"]
    if application is not None and not isinstance(application, str):
        raise ValueError
    if not isinstance(interfaces, list):
        raise ValueError
    return RawWindowsFirewallRule(
        policy_view=authority,
        enabled=value["enabled"],
        direction=WindowsRawFirewallRuleDirection(value["direction"]),
        action=WindowsRawFirewallRuleAction(value["action"]),
        profile_mask=value["profile_mask"],
        protocol=value["protocol"],
        local_ports=_text_tuple(value["local_ports"]),
        remote_ports=_text_tuple(value["remote_ports"]),
        local_addresses=_text_tuple(value["local_addresses"]),
        remote_addresses=_text_tuple(value["remote_addresses"]),
        application_path=(
            RawWindowsApplicationPath(application) if application is not None else None
        ),
        service_name=value["service_name"],
        interface_types=tuple(
            WindowsRawFirewallInterfaceType(item)
            for item in _text_tuple(value["interface_types"])
        ),
        interfaces=tuple(
            RawWindowsInterfaceIdentity(item) for item in _text_tuple(interfaces)
        ),
        edge_traversal=value["edge_traversal"],
        unsupported_features=tuple(
            WindowsRawFirewallUnsupportedFeature(item)
            for item in _text_tuple(value["unsupported_features"])
        ),
    )


def _text_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > MAX_VALUES_PER_CONDITION \
            or not all(isinstance(item, str) for item in value):
        raise ValueError
    return tuple(value)


def _payload(
    kind: WindowsFirewallIpcPayloadKind,
    value: dict[str, object],
) -> WindowsFirewallIpcPayload:
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise WindowsComContractError(
            WindowsComFailureCategory.INVALID_RESULT
        ) from None
    return WindowsFirewallIpcPayload(kind, encoded)


def _decode_payload(
    payload: WindowsFirewallIpcPayload,
    expected: WindowsFirewallIpcPayloadKind,
) -> dict[str, object]:
    if not isinstance(payload, WindowsFirewallIpcPayload) \
            or payload.kind != expected:
        raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)
    try:
        value = json.loads(
            payload.consume_inside_boundary().decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda _: _reject_constant(),
        )
        _validate_json_bounds(value)
        if not isinstance(value, dict):
            raise ValueError
        return value
    except WindowsComContractError:
        raise
    except Exception:
        raise WindowsComContractError(
            WindowsComFailureCategory.INVALID_RESULT
        ) from None


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def _reject_constant():
    raise ValueError


def _validate_json_bounds(value: object, depth: int = 1) -> None:
    if depth > MAX_WINDOWS_FIREWALL_IPC_JSON_DEPTH:
        raise WindowsComContractError(WindowsComFailureCategory.LIMIT_EXCEEDED)
    if isinstance(value, dict):
        if len(value) > 32 or not all(isinstance(key, str) for key in value):
            raise WindowsComContractError(WindowsComFailureCategory.LIMIT_EXCEEDED)
        for key, item in value.items():
            if len(key) > MAX_NORMALIZED_TOKEN:
                raise WindowsComContractError(
                    WindowsComFailureCategory.LIMIT_EXCEEDED
                )
            _validate_json_bounds(item, depth + 1)
    elif isinstance(value, list):
        if len(value) > MAX_FIREWALL_RULES:
            raise WindowsComContractError(WindowsComFailureCategory.LIMIT_EXCEEDED)
        for item in value:
            _validate_json_bounds(item, depth + 1)
    elif isinstance(value, str):
        if len(value) > MAX_RAW_WINDOWS_APPLICATION_PATH:
            raise WindowsComContractError(WindowsComFailureCategory.LIMIT_EXCEEDED)
    elif value is not None and not isinstance(value, (bool, int)):
        raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)


def _exact_fields(value: object, expected: set[str]) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)


def _result_code(category: WindowsComFailureCategory) -> WindowsFirewallRuleResultCode:
    return WindowsFirewallRuleResultCode(category.value)


def _failure(state: WindowsFirewallRuleResultCode) -> WindowsFirewallRuleCollectionResult:
    return WindowsFirewallRuleCollectionResult(
        state, WindowsFirewallPolicyView.CURRENT_POLICY_VIEW
    )
