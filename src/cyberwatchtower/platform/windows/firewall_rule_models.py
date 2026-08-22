"""Private non-native Windows Firewall rule DTO and result contracts."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import ipaddress
import unicodedata

from cyberwatchtower.firewall_policy import (
    MAX_FIREWALL_RULES,
    MAX_NORMALIZED_TOKEN,
    MAX_VALUES_PER_CONDITION,
)


MAX_RAW_WINDOWS_APPLICATION_PATH = 4_096
WINDOWS_FIREWALL_ALL_PROFILES = 0x7FFFFFFF
WINDOWS_FIREWALL_KNOWN_PROFILE_MASK = 0x7
WINDOWS_FIREWALL_PROTOCOL_ANY = 256
MAX_WINDOWS_FIREWALL_PROTOCOL = 256


class WindowsFirewallPolicyView(str, Enum):
    CURRENT_POLICY_VIEW = "CURRENT_POLICY_VIEW"


class WindowsRawFirewallRuleDirection(str, Enum):
    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"


class WindowsRawFirewallRuleAction(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


class WindowsRawFirewallInterfaceType(str, Enum):
    ANY = "ANY"
    LAN = "LAN"
    WIRELESS = "WIRELESS"
    REMOTE_ACCESS = "REMOTE_ACCESS"


class WindowsRawFirewallUnsupportedFeature(str, Enum):
    ICMP_TYPE_CONDITION = "ICMP_TYPE_CONDITION"
    LOCAL_USER_SCOPE = "LOCAL_USER_SCOPE"
    PACKAGE_SCOPE = "PACKAGE_SCOPE"
    DYNAMIC_KEYWORD_ADDRESS = "DYNAMIC_KEYWORD_ADDRESS"
    UNMODELED_NATIVE_PREDICATE = "UNMODELED_NATIVE_PREDICATE"


class WindowsFirewallRuleResultCode(str, Enum):
    COMPLETE = "COMPLETE"
    API_UNAVAILABLE = "API_UNAVAILABLE"
    ACCESS_DENIED = "ACCESS_DENIED"
    COLLECTION_INCOMPLETE = "COLLECTION_INCOMPLETE"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    INVALID_RESULT = "INVALID_RESULT"
    TIMEOUT = "TIMEOUT"
    UNSUPPORTED = "UNSUPPORTED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


def _raw_token(value: object, field: str, maximum: int = MAX_NORMALIZED_TOKEN) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"{field} is outside the supported bound.")
    if any(unicodedata.category(char) in {"Cc", "Cf"} for char in value):
        raise ValueError(f"{field} contains prohibited controls.")
    return value


def _raw_port(value: str, field: str) -> None:
    if value == "*":
        return
    parts = value.split("-", 1)
    if not all(part.isdigit() for part in parts):
        raise ValueError(f"{field} contains an invalid port expression.")
    numbers = tuple(int(part) for part in parts)
    if any(not 0 <= number <= 65_535 for number in numbers) \
            or len(numbers) == 2 and numbers[0] > numbers[1]:
        raise ValueError(f"{field} contains an invalid port range.")


def _raw_address(value: str, field: str) -> None:
    if value == "*" or value.casefold() == "localsubnet":
        return
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"{field} contains an invalid address expression.") from exc


class RawWindowsApplicationPath:
    """Transient private path available only to the trusted normalizer."""

    __slots__ = ("_value", "_sealed")

    def __init__(self, value: str) -> None:
        _raw_token(value, "Windows firewall application path",
                   MAX_RAW_WINDOWS_APPLICATION_PATH)
        object.__setattr__(self, "_value", value)
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError("raw Windows application path is immutable.")
        object.__setattr__(self, name, value)

    def __repr__(self) -> str:
        return "RawWindowsApplicationPath(<redacted>)"

    __str__ = __repr__

    def __eq__(self, other: object) -> bool:
        return isinstance(other, RawWindowsApplicationPath) and (
            self._value == other._value
        )

    def __hash__(self) -> int:
        return hash(self._value)

    def consume_for_normalization(self) -> str:
        return self._value


class RawWindowsInterfaceIdentity:
    """Transient private interface token reduced to a digest during normalization."""

    __slots__ = ("_value", "_sealed")

    def __init__(self, value: str) -> None:
        _raw_token(value, "Windows firewall interface identity")
        object.__setattr__(self, "_value", value)
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError("raw Windows interface identity is immutable.")
        object.__setattr__(self, name, value)

    def __repr__(self) -> str:
        return "RawWindowsInterfaceIdentity(<redacted>)"

    __str__ = __repr__

    def __eq__(self, other: object) -> bool:
        return isinstance(other, RawWindowsInterfaceIdentity) and (
            self._value == other._value
        )

    def __hash__(self) -> int:
        return hash(self._value)

    def consume_for_normalization(self) -> str:
        return self._value


@dataclass(frozen=True, slots=True)
class RawWindowsFirewallRule:
    policy_view: WindowsFirewallPolicyView
    enabled: bool
    direction: WindowsRawFirewallRuleDirection
    action: WindowsRawFirewallRuleAction
    profile_mask: int
    protocol: int
    local_ports: tuple[str, ...] = ()
    remote_ports: tuple[str, ...] = ()
    local_addresses: tuple[str, ...] = ()
    remote_addresses: tuple[str, ...] = ()
    application_path: RawWindowsApplicationPath | None = None
    service_name: str | None = None
    interface_types: tuple[WindowsRawFirewallInterfaceType, ...] = ()
    interfaces: tuple[RawWindowsInterfaceIdentity, ...] = ()
    edge_traversal: bool | None = None
    unsupported_features: tuple[WindowsRawFirewallUnsupportedFeature, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.policy_view, WindowsFirewallPolicyView):
            raise TypeError("Windows policy view must use the closed enum.")
        if not isinstance(self.enabled, bool):
            raise TypeError("Windows rule enabled state must be boolean.")
        if not isinstance(self.direction, WindowsRawFirewallRuleDirection):
            raise TypeError("Windows rule direction must use the closed enum.")
        if not isinstance(self.action, WindowsRawFirewallRuleAction):
            raise TypeError("Windows rule action must use the closed enum.")
        if isinstance(self.profile_mask, bool) or not isinstance(
            self.profile_mask, int
        ) or self.profile_mask not in {
            WINDOWS_FIREWALL_ALL_PROFILES, *range(1, 8),
        }:
            raise ValueError("Windows firewall profile mask is invalid.")
        if isinstance(self.protocol, bool) or not isinstance(self.protocol, int) \
                or not 0 <= self.protocol <= MAX_WINDOWS_FIREWALL_PROTOCOL:
            raise ValueError("Windows firewall protocol is invalid.")
        for name in (
            "local_ports", "remote_ports", "local_addresses", "remote_addresses"
        ):
            values = getattr(self, name)
            if not isinstance(values, tuple) or not all(
                isinstance(value, str) for value in values
            ):
                raise TypeError(f"{name} must be an immutable text tuple.")
            if len(values) > MAX_VALUES_PER_CONDITION:
                raise ValueError(f"{name} exceeds the supported value bound.")
            for value in values:
                _raw_token(value, f"Windows firewall {name}")
                if "ports" in name:
                    _raw_port(value, f"Windows firewall {name}")
                else:
                    _raw_address(value, f"Windows firewall {name}")
            if len(set(values)) != len(values):
                raise ValueError(f"{name} cannot contain duplicates.")
            if "*" in values and len(values) != 1:
                raise ValueError(f"{name} cannot combine ANY with explicit values.")
            object.__setattr__(self, name, tuple(sorted(values)))
        if self.application_path is not None and not isinstance(
            self.application_path, RawWindowsApplicationPath
        ):
            raise TypeError("application path must use the private raw type.")
        if self.service_name is not None:
            _raw_token(self.service_name, "Windows service name")
            if any(not (character.isalnum() or character in "_.-")
                   for character in self.service_name):
                raise ValueError("Windows service name is not canonical.")
        self._closed_tuple(
            "interface types", self.interface_types, WindowsRawFirewallInterfaceType
        )
        self._closed_tuple(
            "interfaces", self.interfaces, RawWindowsInterfaceIdentity
        )
        self._closed_tuple(
            "unsupported features", self.unsupported_features,
            WindowsRawFirewallUnsupportedFeature,
        )
        if self.edge_traversal is not None and not isinstance(
            self.edge_traversal, bool
        ):
            raise TypeError("edge traversal must be boolean or unknown.")
        object.__setattr__(self, "interface_types", tuple(sorted(
            self.interface_types, key=lambda value: value.value
        )))
        object.__setattr__(self, "interfaces", tuple(sorted(
            self.interfaces,
            key=lambda value: _private_sort_digest(
                b"cyberwatchtower:windows-firewall-raw-interface-sort:v1",
                value.consume_for_normalization(),
            ),
        )))
        object.__setattr__(self, "unsupported_features", tuple(sorted(
            self.unsupported_features, key=lambda value: value.value
        )))

    @staticmethod
    def _closed_tuple(name: str, values: tuple, expected: type) -> None:
        if not isinstance(values, tuple) or not all(
            isinstance(value, expected) for value in values
        ):
            raise TypeError(f"{name} must be an immutable typed tuple.")
        if len(values) > MAX_VALUES_PER_CONDITION:
            raise ValueError(f"{name} exceeds the supported value bound.")
        if len(set(values)) != len(values):
            raise ValueError(f"{name} cannot contain duplicates.")


@dataclass(frozen=True, slots=True)
class WindowsFirewallRuleCollectionResult:
    state: WindowsFirewallRuleResultCode
    policy_view: WindowsFirewallPolicyView
    rules: tuple[RawWindowsFirewallRule, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.state, WindowsFirewallRuleResultCode):
            raise TypeError("rule result state must use the closed enum.")
        if not isinstance(self.policy_view, WindowsFirewallPolicyView):
            raise TypeError("rule policy view must use the closed enum.")
        if not isinstance(self.rules, tuple) or not all(
            isinstance(rule, RawWindowsFirewallRule) for rule in self.rules
        ):
            raise TypeError("rule result must use an immutable raw-rule tuple.")
        if len(self.rules) > MAX_FIREWALL_RULES:
            raise ValueError("rule result exceeds the supported rule bound.")
        if any(rule.policy_view != self.policy_view for rule in self.rules):
            raise ValueError("rule result contains a mismatched policy view.")
        if self.rules and self.state not in {
            WindowsFirewallRuleResultCode.COMPLETE,
            WindowsFirewallRuleResultCode.COLLECTION_INCOMPLETE,
        }:
            raise ValueError("only complete or partial results may carry rules.")
        object.__setattr__(self, "rules", tuple(sorted(
            self.rules, key=_raw_rule_sort_key
        )))


def _private_sort_digest(namespace: bytes, value: str) -> str:
    return hashlib.sha256(namespace + b"\0" + value.encode("utf-8")).hexdigest()


def _raw_rule_sort_key(rule: RawWindowsFirewallRule) -> tuple:
    path_digest = (
        _private_sort_digest(
            b"cyberwatchtower:windows-firewall-raw-path-sort:v1",
            rule.application_path.consume_for_normalization(),
        )
        if rule.application_path is not None else ""
    )
    interface_digests = tuple(sorted(
        _private_sort_digest(
            b"cyberwatchtower:windows-firewall-raw-interface-sort:v1",
            value.consume_for_normalization(),
        )
        for value in rule.interfaces
    ))
    return (
        rule.policy_view.value, rule.enabled, rule.direction.value,
        rule.action.value, rule.profile_mask, rule.protocol,
        tuple(sorted(rule.local_ports)), tuple(sorted(rule.remote_ports)),
        tuple(sorted(rule.local_addresses)), tuple(sorted(rule.remote_addresses)),
        path_digest, rule.service_name or "",
        tuple(sorted(value.value for value in rule.interface_types)),
        interface_digests, -1 if rule.edge_traversal is None else rule.edge_traversal,
        tuple(sorted(value.value for value in rule.unsupported_features)),
    )
