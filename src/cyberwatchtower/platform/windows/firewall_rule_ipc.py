"""Portable isolation and IPC contracts for Windows Firewall rule collection.

No process launcher or native COM implementation exists here.  The fixed
launcher/process protocols and deterministic JSON envelopes are exercised with
portable fakes so a future parent can enforce a hard deadline around a known
internal helper.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum
import ipaddress
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
    RawWindowsFirewallIPv4AddressRange,
    RawWindowsFirewallIPv6AddressRange,
    RawWindowsInterfaceIdentity,
    WindowsRawFirewallAddress,
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
WINDOWS_FIREWALL_IPC_PROTOCOL_VERSION_V2 = "2"
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


class WindowsFirewallIpcV2AddressKind(str, Enum):
    ANY = "ANY"
    LOCAL_SUBNET = "LOCAL_SUBNET"
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    IPV4_CIDR = "IPV4_CIDR"
    IPV6_CIDR = "IPV6_CIDR"
    IPV4_RANGE = "IPV4_RANGE"
    IPV6_RANGE = "IPV6_RANGE"


_V2_ADDRESS_KIND_ORDER = {
    kind: index for index, kind in enumerate(WindowsFirewallIpcV2AddressKind)
}


@dataclass(frozen=True, slots=True, repr=False)
class WindowsFirewallIpcV2Address:
    """Closed v2-wire address; address values are redacted from repr/str."""

    kind: WindowsFirewallIpcV2AddressKind
    value: str | None = None
    start: str | None = None
    end: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, WindowsFirewallIpcV2AddressKind):
            raise TypeError("v2 address kind must use the closed enum.")
        if self.kind in {
            WindowsFirewallIpcV2AddressKind.ANY,
            WindowsFirewallIpcV2AddressKind.LOCAL_SUBNET,
        }:
            if any(item is not None for item in (self.value, self.start, self.end)):
                raise ValueError("v2 symbolic address cannot carry a value.")
            return
        if self.kind in {
            WindowsFirewallIpcV2AddressKind.IPV4_RANGE,
            WindowsFirewallIpcV2AddressKind.IPV6_RANGE,
        }:
            if self.value is not None or not isinstance(self.start, str) \
                    or not isinstance(self.end, str):
                raise ValueError("v2 address range requires closed endpoints.")
            try:
                address_type = (
                    ipaddress.IPv4Address
                    if self.kind == WindowsFirewallIpcV2AddressKind.IPV4_RANGE
                    else ipaddress.IPv6Address
                )
                first = address_type(self.start)
                last = address_type(self.end)
            except ValueError:
                raise ValueError("v2 address range endpoints are invalid.") from None
            if first > last:
                raise ValueError("v2 address range endpoints are invalid.")
            object.__setattr__(self, "start", str(first))
            object.__setattr__(self, "end", str(last))
            return
        if not isinstance(self.value, str) or self.start is not None \
                or self.end is not None:
            raise ValueError("v2 address requires one closed value.")
        try:
            parsed = (
                ipaddress.ip_network(self.value, strict=False)
                if self.kind in {
                    WindowsFirewallIpcV2AddressKind.IPV4_CIDR,
                    WindowsFirewallIpcV2AddressKind.IPV6_CIDR,
                }
                else ipaddress.ip_address(self.value)
            )
        except ValueError:
            raise ValueError("v2 address value is invalid.") from None
        expected = {
            WindowsFirewallIpcV2AddressKind.IPV4: ipaddress.IPv4Address,
            WindowsFirewallIpcV2AddressKind.IPV6: ipaddress.IPv6Address,
            WindowsFirewallIpcV2AddressKind.IPV4_CIDR: ipaddress.IPv4Network,
            WindowsFirewallIpcV2AddressKind.IPV6_CIDR: ipaddress.IPv6Network,
        }[self.kind]
        if not isinstance(parsed, expected):
            raise ValueError("v2 address family does not match its kind.")
        object.__setattr__(self, "value", str(parsed))

    def __repr__(self) -> str:
        return f"WindowsFirewallIpcV2Address({self.kind.value}, <redacted>)"

    __str__ = __repr__


def _v2_address_sort_key(
    address: WindowsFirewallIpcV2Address,
) -> tuple[int, str, str]:
    return (
        _V2_ADDRESS_KIND_ORDER[address.kind],
        address.value or address.start or "",
        address.end or "",
    )


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
class WindowsFirewallIpcV2Request:
    protocol_version: str = WINDOWS_FIREWALL_IPC_PROTOCOL_VERSION_V2
    operation: WindowsFirewallIpcOperation = (
        WindowsFirewallIpcOperation.COLLECT_CURRENT_POLICY
    )

    def __post_init__(self) -> None:
        if self.protocol_version != WINDOWS_FIREWALL_IPC_PROTOCOL_VERSION_V2:
            raise WindowsComContractError(WindowsComFailureCategory.UNSUPPORTED)
        if not isinstance(self.operation, WindowsFirewallIpcOperation):
            raise TypeError("v2 helper operation must use the closed enum.")


@dataclass(frozen=True, slots=True)
class WindowsFirewallIpcV2Rule:
    enabled: bool
    direction: WindowsRawFirewallRuleDirection
    action: WindowsRawFirewallRuleAction
    profile_mask: int
    protocol: int
    local_ports: tuple[str, ...] = ()
    remote_ports: tuple[str, ...] = ()
    local_addresses: tuple[WindowsFirewallIpcV2Address, ...] = ()
    remote_addresses: tuple[WindowsFirewallIpcV2Address, ...] = ()
    application_path: RawWindowsApplicationPath | None = None
    service_name: str | None = None
    interface_types: tuple[WindowsRawFirewallInterfaceType, ...] = ()
    interfaces: tuple[RawWindowsInterfaceIdentity, ...] = ()
    edge_traversal: bool | None = None
    unsupported_features: tuple[WindowsRawFirewallUnsupportedFeature, ...] = ()

    def __post_init__(self) -> None:
        validated = RawWindowsFirewallRule(
            WindowsFirewallPolicyView.CURRENT_POLICY_VIEW,
            self.enabled,
            self.direction,
            self.action,
            self.profile_mask,
            self.protocol,
            self.local_ports,
            self.remote_ports,
            (),
            (),
            self.application_path,
            self.service_name,
            self.interface_types,
            self.interfaces,
            self.edge_traversal,
            self.unsupported_features,
        )
        for name in (
            "local_ports", "remote_ports", "application_path", "service_name",
            "interface_types", "interfaces", "edge_traversal",
            "unsupported_features",
        ):
            object.__setattr__(self, name, getattr(validated, name))
        for name in ("local_addresses", "remote_addresses"):
            values = getattr(self, name)
            if not isinstance(values, tuple) or not all(
                isinstance(value, WindowsFirewallIpcV2Address) for value in values
            ):
                raise TypeError("v2 addresses must use an immutable closed tuple.")
            if len(values) > MAX_VALUES_PER_CONDITION:
                raise ValueError("v2 address condition exceeds the value bound.")
            if len(set(values)) != len(values):
                raise ValueError("v2 address condition cannot contain duplicates.")
            if any(value.kind == WindowsFirewallIpcV2AddressKind.ANY for value in values) \
                    and len(values) != 1:
                raise ValueError("v2 ANY cannot be combined with explicit addresses.")
            object.__setattr__(self, name, tuple(sorted(
                values, key=_v2_address_sort_key
            )))


@dataclass(frozen=True, slots=True)
class WindowsFirewallIpcV2Response:
    protocol_version: str
    authority: WindowsFirewallPolicyView
    result: WindowsFirewallRuleResultCode
    rules: tuple[WindowsFirewallIpcV2Rule, ...] = ()

    def __post_init__(self) -> None:
        if self.protocol_version != WINDOWS_FIREWALL_IPC_PROTOCOL_VERSION_V2:
            raise WindowsComContractError(WindowsComFailureCategory.UNSUPPORTED)
        if self.authority != WindowsFirewallPolicyView.CURRENT_POLICY_VIEW:
            raise ValueError("v2 helper authority must remain current-policy view.")
        if not isinstance(self.result, WindowsFirewallRuleResultCode):
            raise TypeError("v2 result must use the closed result enum.")
        if not isinstance(self.rules, tuple) or not all(
            isinstance(rule, WindowsFirewallIpcV2Rule) for rule in self.rules
        ):
            raise TypeError("v2 response rules must use an immutable closed tuple.")
        if len(self.rules) > MAX_FIREWALL_RULES:
            raise ValueError("v2 response exceeds the rule bound.")
        if self.result != WindowsFirewallRuleResultCode.COMPLETE and self.rules:
            raise ValueError("failed v2 response cannot retain raw rules.")


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


def encode_windows_firewall_ipc_v2_request(
    request: WindowsFirewallIpcV2Request,
) -> WindowsFirewallIpcPayload:
    if not isinstance(request, WindowsFirewallIpcV2Request):
        raise TypeError("v2 request encoder requires the closed v2 contract.")
    return _payload_v2(
        WindowsFirewallIpcPayloadKind.REQUEST,
        {
            "operation": request.operation.value,
            "protocol_version": request.protocol_version,
        },
    )


def decode_windows_firewall_ipc_v2_request(
    payload: WindowsFirewallIpcPayload,
) -> WindowsFirewallIpcV2Request:
    value = _decode_payload(payload, WindowsFirewallIpcPayloadKind.REQUEST)
    _exact_fields(value, {"operation", "protocol_version"})
    _require_protocol_version(value["protocol_version"],
                              WINDOWS_FIREWALL_IPC_PROTOCOL_VERSION_V2)
    try:
        return WindowsFirewallIpcV2Request(
            value["protocol_version"], WindowsFirewallIpcOperation(value["operation"])
        )
    except WindowsComContractError:
        raise
    except (TypeError, ValueError):
        raise WindowsComContractError(
            WindowsComFailureCategory.INVALID_RESULT
        ) from None


def encode_windows_firewall_ipc_v2_response(
    response: WindowsFirewallIpcV2Response,
) -> WindowsFirewallIpcPayload:
    if not isinstance(response, WindowsFirewallIpcV2Response):
        raise TypeError("v2 response encoder requires the closed v2 contract.")
    return _payload_v2(
        WindowsFirewallIpcPayloadKind.RESPONSE,
        {
            "authority": response.authority.value,
            "protocol_version": response.protocol_version,
            "result": response.result.value,
            "rules": [_encode_v2_rule(rule) for rule in response.rules],
        },
    )


def decode_windows_firewall_ipc_v2_response(
    payload: WindowsFirewallIpcPayload,
) -> WindowsFirewallIpcV2Response:
    value = _decode_payload(payload, WindowsFirewallIpcPayloadKind.RESPONSE)
    _exact_fields(value, {"authority", "protocol_version", "result", "rules"})
    _require_protocol_version(value["protocol_version"],
                              WINDOWS_FIREWALL_IPC_PROTOCOL_VERSION_V2)
    try:
        authority = WindowsFirewallPolicyView(value["authority"])
        result = WindowsFirewallRuleResultCode(value["result"])
        encoded_rules = value["rules"]
        if not isinstance(encoded_rules, list) or len(encoded_rules) > MAX_FIREWALL_RULES:
            raise ValueError
        rules = tuple(_decode_v2_rule(item) for item in encoded_rules)
        return WindowsFirewallIpcV2Response(
            value["protocol_version"], authority, result, rules
        )
    except WindowsComContractError:
        raise
    except (KeyError, TypeError, ValueError):
        raise WindowsComContractError(
            WindowsComFailureCategory.INVALID_RESULT
        ) from None


def _require_protocol_version(value: object, expected: str) -> None:
    if not isinstance(value, str):
        raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)
    if value != expected:
        raise WindowsComContractError(WindowsComFailureCategory.UNSUPPORTED)


def decode_windows_firewall_ipc_request_for_version(
    payload: WindowsFirewallIpcPayload,
    expected_version: str,
) -> WindowsFirewallHelperRequest | WindowsFirewallIpcV2Request:
    """Strict portable dispatch; production continues calling the v1 decoder."""

    _require_supported_protocol_version(expected_version)
    if expected_version == WINDOWS_FIREWALL_IPC_PROTOCOL_VERSION:
        return decode_windows_firewall_helper_request(payload)
    return decode_windows_firewall_ipc_v2_request(payload)


def decode_windows_firewall_ipc_response_for_version(
    payload: WindowsFirewallIpcPayload,
    expected_version: str,
) -> WindowsFirewallHelperResponse | WindowsFirewallIpcV2Response:
    """Decode only the version requested; never sniff, retry, or downgrade."""

    _require_supported_protocol_version(expected_version)
    if expected_version == WINDOWS_FIREWALL_IPC_PROTOCOL_VERSION:
        return decode_windows_firewall_helper_response(payload)
    return decode_windows_firewall_ipc_v2_response(payload)


def _require_supported_protocol_version(value: object) -> None:
    if not isinstance(value, str):
        raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)
    if value not in {
        WINDOWS_FIREWALL_IPC_PROTOCOL_VERSION,
        WINDOWS_FIREWALL_IPC_PROTOCOL_VERSION_V2,
    }:
        raise WindowsComContractError(WindowsComFailureCategory.UNSUPPORTED)


def windows_firewall_ipc_v2_address_to_raw(
    address: WindowsFirewallIpcV2Address,
) -> WindowsRawFirewallAddress:
    if not isinstance(address, WindowsFirewallIpcV2Address):
        raise TypeError("v2-to-raw conversion requires a validated v2 address.")
    if address.kind == WindowsFirewallIpcV2AddressKind.ANY:
        return "*"
    if address.kind == WindowsFirewallIpcV2AddressKind.LOCAL_SUBNET:
        return "LocalSubnet"
    if address.kind == WindowsFirewallIpcV2AddressKind.IPV4_RANGE:
        assert address.start is not None and address.end is not None
        return RawWindowsFirewallIPv4AddressRange(
            ipaddress.IPv4Address(address.start), ipaddress.IPv4Address(address.end)
        )
    if address.kind == WindowsFirewallIpcV2AddressKind.IPV6_RANGE:
        assert address.start is not None and address.end is not None
        return RawWindowsFirewallIPv6AddressRange(
            ipaddress.IPv6Address(address.start), ipaddress.IPv6Address(address.end)
        )
    assert address.value is not None
    return address.value


def windows_firewall_raw_address_to_ipc_v2(
    address: WindowsRawFirewallAddress,
) -> WindowsFirewallIpcV2Address:
    if isinstance(address, RawWindowsFirewallIPv4AddressRange):
        return WindowsFirewallIpcV2Address(
            WindowsFirewallIpcV2AddressKind.IPV4_RANGE,
            start=str(address.start), end=str(address.end),
        )
    if isinstance(address, RawWindowsFirewallIPv6AddressRange):
        return WindowsFirewallIpcV2Address(
            WindowsFirewallIpcV2AddressKind.IPV6_RANGE,
            start=str(address.start), end=str(address.end),
        )
    if not isinstance(address, str):
        raise TypeError("raw-to-v2 conversion requires the closed raw address union.")
    if address == "*":
        return WindowsFirewallIpcV2Address(WindowsFirewallIpcV2AddressKind.ANY)
    if address.casefold() == "localsubnet":
        return WindowsFirewallIpcV2Address(
            WindowsFirewallIpcV2AddressKind.LOCAL_SUBNET
        )
    try:
        if "/" in address:
            parsed = ipaddress.ip_network(address, strict=False)
            kind = (
                WindowsFirewallIpcV2AddressKind.IPV4_CIDR
                if isinstance(parsed, ipaddress.IPv4Network)
                else WindowsFirewallIpcV2AddressKind.IPV6_CIDR
            )
        else:
            parsed = ipaddress.ip_address(address)
            kind = (
                WindowsFirewallIpcV2AddressKind.IPV4
                if isinstance(parsed, ipaddress.IPv4Address)
                else WindowsFirewallIpcV2AddressKind.IPV6
            )
        return WindowsFirewallIpcV2Address(kind, value=str(parsed))
    except ValueError:
        raise WindowsComContractError(
            WindowsComFailureCategory.INVALID_RESULT
        ) from None


def windows_firewall_ipc_v2_rule_to_raw(
    rule: WindowsFirewallIpcV2Rule,
) -> RawWindowsFirewallRule:
    if not isinstance(rule, WindowsFirewallIpcV2Rule):
        raise TypeError("v2-to-raw conversion requires a validated v2 rule.")
    return RawWindowsFirewallRule(
        policy_view=WindowsFirewallPolicyView.CURRENT_POLICY_VIEW,
        enabled=rule.enabled,
        direction=rule.direction,
        action=rule.action,
        profile_mask=rule.profile_mask,
        protocol=rule.protocol,
        local_ports=rule.local_ports,
        remote_ports=rule.remote_ports,
        local_addresses=tuple(
            windows_firewall_ipc_v2_address_to_raw(value)
            for value in rule.local_addresses
        ),
        remote_addresses=tuple(
            windows_firewall_ipc_v2_address_to_raw(value)
            for value in rule.remote_addresses
        ),
        application_path=rule.application_path,
        service_name=rule.service_name,
        interface_types=rule.interface_types,
        interfaces=rule.interfaces,
        edge_traversal=rule.edge_traversal,
        unsupported_features=rule.unsupported_features,
    )


def windows_firewall_raw_rule_to_ipc_v2(
    rule: RawWindowsFirewallRule,
) -> WindowsFirewallIpcV2Rule:
    if not isinstance(rule, RawWindowsFirewallRule):
        raise TypeError("raw-to-v2 conversion requires a validated raw rule.")
    return WindowsFirewallIpcV2Rule(
        enabled=rule.enabled,
        direction=rule.direction,
        action=rule.action,
        profile_mask=rule.profile_mask,
        protocol=rule.protocol,
        local_ports=rule.local_ports,
        remote_ports=rule.remote_ports,
        local_addresses=tuple(
            windows_firewall_raw_address_to_ipc_v2(value)
            for value in rule.local_addresses
        ),
        remote_addresses=tuple(
            windows_firewall_raw_address_to_ipc_v2(value)
            for value in rule.remote_addresses
        ),
        application_path=rule.application_path,
        service_name=rule.service_name,
        interface_types=rule.interface_types,
        interfaces=rule.interfaces,
        edge_traversal=rule.edge_traversal,
        unsupported_features=rule.unsupported_features,
    )


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
        request = encode_windows_firewall_ipc_v2_request(
            WindowsFirewallIpcV2Request()
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
        response = decode_windows_firewall_ipc_v2_response(wait.payload)
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
    return WindowsFirewallRuleCollectionResult(
        response.result,
        response.authority,
        tuple(windows_firewall_ipc_v2_rule_to_raw(rule) for rule in response.rules),
    )


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


def _encode_v2_rule(rule: WindowsFirewallIpcV2Rule) -> dict[str, object]:
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
        "local_addresses": [_encode_v2_address(value)
                            for value in rule.local_addresses],
        "local_ports": list(rule.local_ports),
        "profile_mask": rule.profile_mask,
        "protocol": rule.protocol,
        "remote_addresses": [_encode_v2_address(value)
                             for value in rule.remote_addresses],
        "remote_ports": list(rule.remote_ports),
        "service_name": rule.service_name,
        "unsupported_features": [
            value.value for value in rule.unsupported_features
        ],
    }


def _decode_v2_rule(value: object) -> WindowsFirewallIpcV2Rule:
    _exact_fields(value, _RULE_FIELDS)
    application = value["application_path"]
    interfaces = value["interfaces"]
    if application is not None and not isinstance(application, str):
        raise ValueError
    if not isinstance(interfaces, list):
        raise ValueError
    return WindowsFirewallIpcV2Rule(
        enabled=value["enabled"],
        direction=WindowsRawFirewallRuleDirection(value["direction"]),
        action=WindowsRawFirewallRuleAction(value["action"]),
        profile_mask=value["profile_mask"],
        protocol=value["protocol"],
        local_ports=_text_tuple(value["local_ports"]),
        remote_ports=_text_tuple(value["remote_ports"]),
        local_addresses=_decode_v2_addresses(value["local_addresses"]),
        remote_addresses=_decode_v2_addresses(value["remote_addresses"]),
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


def _encode_v2_address(address: WindowsFirewallIpcV2Address) -> dict[str, str]:
    if address.kind in {
        WindowsFirewallIpcV2AddressKind.ANY,
        WindowsFirewallIpcV2AddressKind.LOCAL_SUBNET,
    }:
        return {"kind": address.kind.value}
    if address.kind in {
        WindowsFirewallIpcV2AddressKind.IPV4_RANGE,
        WindowsFirewallIpcV2AddressKind.IPV6_RANGE,
    }:
        assert address.start is not None and address.end is not None
        return {"end": address.end, "kind": address.kind.value,
                "start": address.start}
    assert address.value is not None
    return {"kind": address.kind.value, "value": address.value}


def _decode_v2_addresses(value: object) -> tuple[WindowsFirewallIpcV2Address, ...]:
    if not isinstance(value, list) or len(value) > MAX_VALUES_PER_CONDITION:
        raise ValueError
    return tuple(_decode_v2_address(item) for item in value)


def _decode_v2_address(value: object) -> WindowsFirewallIpcV2Address:
    if not isinstance(value, dict):
        raise ValueError
    kind_value = value.get("kind")
    if not isinstance(kind_value, str):
        raise ValueError
    kind = WindowsFirewallIpcV2AddressKind(kind_value)
    if kind in {
        WindowsFirewallIpcV2AddressKind.ANY,
        WindowsFirewallIpcV2AddressKind.LOCAL_SUBNET,
    }:
        _exact_fields(value, {"kind"})
        return WindowsFirewallIpcV2Address(kind)
    if kind in {
        WindowsFirewallIpcV2AddressKind.IPV4_RANGE,
        WindowsFirewallIpcV2AddressKind.IPV6_RANGE,
    }:
        _exact_fields(value, {"end", "kind", "start"})
        return WindowsFirewallIpcV2Address(
            kind, start=value["start"], end=value["end"]
        )
    _exact_fields(value, {"kind", "value"})
    return WindowsFirewallIpcV2Address(kind, value=value["value"])


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


def _payload_v2(
    kind: WindowsFirewallIpcPayloadKind,
    value: dict[str, object],
) -> WindowsFirewallIpcPayload:
    maximum = (
        MAX_WINDOWS_FIREWALL_IPC_REQUEST_BYTES
        if kind == WindowsFirewallIpcPayloadKind.REQUEST
        else MAX_WINDOWS_FIREWALL_IPC_RESPONSE_BYTES
    )
    chunks: list[bytes] = []
    size = 0
    encoder = json.JSONEncoder(
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    )
    try:
        for chunk in encoder.iterencode(value):
            encoded = chunk.encode("utf-8")
            size += len(encoded)
            if size > maximum:
                raise WindowsComContractError(
                    WindowsComFailureCategory.LIMIT_EXCEEDED
                )
            chunks.append(encoded)
    except WindowsComContractError:
        raise
    except (TypeError, ValueError):
        raise WindowsComContractError(
            WindowsComFailureCategory.INVALID_RESULT
        ) from None
    return WindowsFirewallIpcPayload(kind, b"".join(chunks))


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
