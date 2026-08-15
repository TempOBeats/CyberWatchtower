"""Immutable internal DTOs for future Windows-native API implementations."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Generic, TypeVar
import unicodedata

from ..models import (
    FirewallEnablement as WindowsFirewallEnablement,
    FirewallInboundAction as WindowsFirewallAction,
    FirewallProfile as WindowsFirewallProfile,
    FirewallProfileState as WindowsProfileState,
)
from .errors import WindowsFailureCode, safe_windows_failure_message


MAX_RAW_TEXT = 1024
MAX_RAW_MACHINE_IDENTITY_TEXT = 256
_SENSITIVE_MARKERS = (
    "api_key=", "apikey=", "authorization:", "bearer ", "command_line=",
    "credential=", "environment=", "password=", "token=",
)


def _bounded_text(value: object, name: str, maximum: int = MAX_RAW_TEXT) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"{name} is outside the supported bound.")
    if any(unicodedata.category(char) in {"Cc", "Cf"} for char in value):
        raise ValueError(f"{name} contains prohibited control characters.")
    if any(marker in value.casefold() for marker in _SENSITIVE_MARKERS):
        raise ValueError(f"{name} contains prohibited sensitive material.")
    return value


def _positive_integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer.")
    return value


def _endpoint_pid(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("Windows endpoint PID must be a non-negative integer.")
    return value


class WindowsAddressFamily(str, Enum):
    IPV4 = "IPV4"
    IPV6 = "IPV6"


class WindowsTcpState(str, Enum):
    LISTEN = "LISTEN"


class WindowsServiceState(str, Enum):
    RUNNING = "RUNNING"
    STOPPED = "STOPPED"
    OTHER = "OTHER"


@dataclass(frozen=True, slots=True)
class RawWindowsSystemInfo:
    hostname: str
    product_name: str
    version: str
    build: str
    architecture: str
    user_label: str | None = None

    def __post_init__(self) -> None:
        for name in ("hostname", "product_name", "version", "build", "architecture"):
            _bounded_text(getattr(self, name), f"Windows system {name}")
        if self.user_label is not None:
            _bounded_text(self.user_label, "Windows current user label")


class RawMachineIdentity:
    """Local identity material that must be consumed only by system-id derivation."""

    __slots__ = ("_value", "_sealed")

    def __init__(self, value: str) -> None:
        if (
            not isinstance(value, str)
            or not value
            or len(value) > MAX_RAW_MACHINE_IDENTITY_TEXT
        ):
            raise ValueError("raw Windows machine identity is outside the supported bound.")
        if any(unicodedata.category(char) in {"Cc", "Cf"} for char in value):
            raise ValueError("raw Windows machine identity contains prohibited controls.")
        object.__setattr__(self, "_value", value)
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError("raw Windows machine identity is immutable.")
        object.__setattr__(self, name, value)

    def __repr__(self) -> str:
        return "RawMachineIdentity(<redacted>)"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, RawMachineIdentity) and self._value == other._value

    def consume_for_derivation(self) -> str:
        """Return local material only to the future trusted derivation boundary."""

        return self._value


def _validated_address(family: WindowsAddressFamily, value: object) -> str:
    if not isinstance(family, WindowsAddressFamily):
        raise TypeError("address family must use the closed enum.")
    text = _bounded_text(value, "Windows endpoint address", 64)
    try:
        parsed = ip_address(text)
    except ValueError as exc:
        raise ValueError("Windows endpoint address is invalid.") from exc
    expected = IPv4Address if family == WindowsAddressFamily.IPV4 else IPv6Address
    if not isinstance(parsed, expected):
        raise ValueError("Windows endpoint address does not match its family.")
    return str(parsed)


def _validated_port(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ValueError("Windows endpoint port is invalid.")
    return value


@dataclass(frozen=True, slots=True)
class RawTcpEndpoint:
    family: WindowsAddressFamily
    address: str
    port: int
    pid: int
    state: WindowsTcpState

    def __post_init__(self) -> None:
        object.__setattr__(self, "address", _validated_address(self.family, self.address))
        _validated_port(self.port)
        _endpoint_pid(self.pid)
        if not isinstance(self.state, WindowsTcpState):
            raise TypeError("TCP state must use the closed enum.")


@dataclass(frozen=True, slots=True)
class RawUdpEndpoint:
    family: WindowsAddressFamily
    address: str
    port: int
    pid: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "address", _validated_address(self.family, self.address))
        _validated_port(self.port)
        _endpoint_pid(self.pid)


@dataclass(frozen=True, slots=True)
class RawProcessInfo:
    pid: int
    image_name: str
    image_path: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        _positive_integer(self.pid, "Windows process PID")
        _bounded_text(self.image_name, "Windows process image name")
        if self.image_path is not None:
            _bounded_text(self.image_path, "Windows process image path", 4096)


@dataclass(frozen=True, slots=True)
class RawServiceInfo:
    service_name: str
    display_name: str
    pid: int
    state: WindowsServiceState

    def __post_init__(self) -> None:
        _bounded_text(self.service_name, "Windows service name")
        _bounded_text(self.display_name, "Windows service display name")
        _positive_integer(self.pid, "Windows service PID")
        if not isinstance(self.state, WindowsServiceState):
            raise TypeError("service state must use the closed enum.")


@dataclass(frozen=True, slots=True)
class RawFirewallProfile:
    profile: WindowsFirewallProfile
    state: WindowsProfileState
    enablement: WindowsFirewallEnablement
    default_inbound_action: WindowsFirewallAction
    block_all_inbound: bool | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.profile, WindowsFirewallProfile):
            raise TypeError("firewall profile must use the closed enum.")
        if not isinstance(self.state, WindowsProfileState):
            raise TypeError("firewall profile state must use the closed enum.")
        if not isinstance(self.enablement, WindowsFirewallEnablement):
            raise TypeError("firewall enablement must use the closed enum.")
        if not isinstance(self.default_inbound_action, WindowsFirewallAction):
            raise TypeError("firewall inbound action must use the closed enum.")
        if self.block_all_inbound is not None and not isinstance(
            self.block_all_inbound, bool
        ):
            raise TypeError("block-all-inbound state must be boolean or unknown.")


T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class WindowsApiResult(Generic[T]):
    value: T | None = None
    failure: WindowsFailureCode | None = None

    def __post_init__(self) -> None:
        if self.failure is not None and not isinstance(self.failure, WindowsFailureCode):
            raise TypeError("Windows API failure must use the closed enum.")
        if self.value is None and self.failure is None:
            raise ValueError("Windows API result must contain a value or failure.")
        if self.value is not None and self.failure not in {
            None, WindowsFailureCode.PARTIAL_RESULT
        }:
            raise ValueError("Only a typed partial result may carry data and failure.")

    @property
    def succeeded(self) -> bool:
        return self.failure is None

    @property
    def message(self) -> str | None:
        return (
            safe_windows_failure_message(self.failure)
            if self.failure is not None else None
        )
