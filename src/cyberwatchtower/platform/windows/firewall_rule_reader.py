"""Portable fixed-purpose reader for one mocked Windows Firewall COM rule.

This module performs no native loading or COM activation.  Its protocols model
only the approved Phase 2B getter surface so ownership and validation can be
exercised before an isolated native collector exists.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, runtime_checkable

from cyberwatchtower.firewall_policy import (
    MAX_NORMALIZED_TOKEN,
    MAX_VALUES_PER_CONDITION,
)

from .firewall_com_contracts import (
    WindowsComCleanupStack,
    WindowsComContractError,
    WindowsComFailureCategory,
    WindowsComOperationAccounting,
    WindowsComResourceKind,
    WindowsFirewallPropertyGetter,
    WindowsOwnedBstr,
    WindowsOwnedVariant,
)
from .firewall_rule_models import (
    MAX_RAW_WINDOWS_APPLICATION_PATH,
    RawWindowsApplicationPath,
    RawWindowsFirewallRule,
    RawWindowsInterfaceIdentity,
    WindowsFirewallPolicyView,
    WindowsRawFirewallInterfaceType,
    WindowsRawFirewallRuleAction,
    WindowsRawFirewallRuleDirection,
    WindowsRawFirewallUnsupportedFeature,
)


WINDOWS_NET_FW_RULE_DIR_IN = 1
WINDOWS_NET_FW_RULE_DIR_OUT = 2
WINDOWS_NET_FW_ACTION_BLOCK = 0
WINDOWS_NET_FW_ACTION_ALLOW = 1
WINDOWS_EDGE_TRAVERSAL_DENY = 0
WINDOWS_EDGE_TRAVERSAL_ALLOW = 1
WINDOWS_EDGE_TRAVERSAL_DEFER_TO_APP = 2
WINDOWS_EDGE_TRAVERSAL_DEFER_TO_USER = 3
WINDOWS_ICMP_PROTOCOLS = frozenset({1, 58})


class WindowsComInterfaceAvailability(str, Enum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"


@runtime_checkable
class WindowsFirewallRule2ReaderProtocol(Protocol):
    def get_edge_traversal_options(self) -> int: ...

    def release(self) -> None: ...


@runtime_checkable
class WindowsFirewallRule3ReaderProtocol(Protocol):
    def get_local_app_package_id(self) -> WindowsOwnedBstr | None: ...

    def get_local_user_authorized_list(self) -> WindowsOwnedBstr | None: ...

    def get_remote_machine_authorized_list(self) -> WindowsOwnedBstr | None: ...

    def get_remote_user_authorized_list(self) -> WindowsOwnedBstr | None: ...

    def get_secure_flags(self) -> int: ...

    def release(self) -> None: ...


@dataclass(frozen=True, slots=True)
class WindowsFirewallRule2Query:
    availability: WindowsComInterfaceAvailability
    interface: WindowsFirewallRule2ReaderProtocol | None = field(
        default=None, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        _validate_query(self.availability, self.interface,
                        WindowsFirewallRule2ReaderProtocol)


@dataclass(frozen=True, slots=True)
class WindowsFirewallRule3Query:
    availability: WindowsComInterfaceAvailability
    interface: WindowsFirewallRule3ReaderProtocol | None = field(
        default=None, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        _validate_query(self.availability, self.interface,
                        WindowsFirewallRule3ReaderProtocol)


@runtime_checkable
class WindowsFirewallRuleReaderProtocol(Protocol):
    """The closed base-rule surface consumed by the portable reader."""

    def get_enabled(self) -> bool: ...
    def get_direction(self) -> int: ...
    def get_action(self) -> int: ...
    def get_profiles(self) -> int: ...
    def get_protocol(self) -> int: ...
    def get_local_ports(self) -> WindowsOwnedBstr | None: ...
    def get_remote_ports(self) -> WindowsOwnedBstr | None: ...
    def get_local_addresses(self) -> WindowsOwnedBstr | None: ...
    def get_remote_addresses(self) -> WindowsOwnedBstr | None: ...
    def get_application_name(self) -> WindowsOwnedBstr | None: ...
    def get_service_name(self) -> WindowsOwnedBstr | None: ...
    def get_interface_types(self) -> WindowsOwnedBstr | None: ...
    def get_interfaces(self) -> WindowsOwnedVariant: ...
    def get_icmp_types_and_codes(self) -> WindowsOwnedBstr | None: ...
    def get_edge_traversal(self) -> bool: ...
    def query_rule2(self) -> WindowsFirewallRule2Query: ...
    def query_rule3(self) -> WindowsFirewallRule3Query: ...
    def release(self) -> None: ...


@dataclass(frozen=True, slots=True)
class WindowsFirewallSingleRuleReadResult:
    rule: RawWindowsFirewallRule | None = None
    failure: WindowsComFailureCategory | None = None

    def __post_init__(self) -> None:
        if (self.rule is None) == (self.failure is None):
            raise ValueError("single-rule result requires exactly one outcome.")
        if self.rule is not None and not isinstance(
            self.rule, RawWindowsFirewallRule
        ):
            raise TypeError("single-rule success must carry the typed raw rule.")
        if self.failure is not None and not isinstance(
            self.failure, WindowsComFailureCategory
        ):
            raise TypeError("single-rule failure must use the closed category.")


def _validate_query(availability, interface, expected) -> None:
    if not isinstance(availability, WindowsComInterfaceAvailability):
        raise TypeError("interface availability must use the closed enum.")
    if availability == WindowsComInterfaceAvailability.AVAILABLE:
        if not isinstance(interface, expected):
            raise TypeError("available interface query requires the fixed protocol.")
    elif interface is not None:
        raise ValueError("unavailable interface query cannot carry an interface.")
