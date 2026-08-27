"""Portable mock-only Windows Firewall rule collection engine.

The engine owns one already-acquired Rules collection and exercises only the
fixed Count, _NewEnum, IEnumVARIANT, and single-rule reader contracts.  It does
not load COM, activate Windows Firewall objects, or provide production routing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, runtime_checkable

from cyberwatchtower.firewall_policy import MAX_FIREWALL_RULES

from .firewall_com_contracts import (
    WindowsComCleanupStack,
    WindowsComContractError,
    WindowsComFailureCategory,
    WindowsComOperationAccounting,
    WindowsComResourceKind,
    WindowsOwnedVariant,
    WindowsVariantType,
)
from .firewall_rule_models import (
    RawWindowsFirewallRule,
    WindowsFirewallPolicyView,
    WindowsFirewallRuleCollectionResult,
    WindowsFirewallRuleResultCode,
)
from .firewall_rule_reader import (
    WindowsFirewallRuleReaderProtocol,
    read_windows_firewall_rule,
)
from .firewall_rules import normalize_windows_firewall_rules


MAX_FIREWALL_ENUMERATION_OPERATIONS = MAX_FIREWALL_RULES + 3


class WindowsFirewallEnumerationState(str, Enum):
    ITEM = "ITEM"
    END = "END"


@runtime_checkable
class WindowsFirewallRuleElementProtocol(Protocol):
    """Fixed dispatch-element seam used only to acquire the base Rule interface."""

    def query_rule(self) -> WindowsFirewallRuleReaderProtocol: ...


@dataclass(frozen=True, slots=True)
class WindowsFirewallEnumerationStep:
    state: WindowsFirewallEnumerationState
    fetched: int
    value: WindowsOwnedVariant | None = field(
        default=None, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        if not isinstance(self.state, WindowsFirewallEnumerationState):
            raise TypeError("enumeration state must use the closed enum.")
        if isinstance(self.fetched, bool) or not isinstance(self.fetched, int):
            raise TypeError("enumeration fetched count must be an integer.")
        if self.value is not None and not isinstance(
            self.value, WindowsOwnedVariant
        ):
            raise TypeError("enumeration value must use the owned VARIANT contract.")


@runtime_checkable
class WindowsFirewallEnumVariantProtocol(Protocol):
    def next_one(self) -> WindowsFirewallEnumerationStep: ...

    def release(self) -> None: ...


@runtime_checkable
class WindowsFirewallNewEnumProtocol(Protocol):
    def query_enum_variant(self) -> WindowsFirewallEnumVariantProtocol: ...

    def release(self) -> None: ...


@runtime_checkable
class WindowsFirewallRulesCollectionProtocol(Protocol):
    def get_count(self) -> int: ...

    def get_new_enum(self) -> WindowsFirewallNewEnumProtocol: ...

    def release(self) -> None: ...
