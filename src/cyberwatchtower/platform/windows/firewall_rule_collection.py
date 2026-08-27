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


def collect_windows_firewall_rules_from_collection(
    rules: WindowsFirewallRulesCollectionProtocol,
    *,
    accounting: WindowsComOperationAccounting | None = None,
) -> WindowsFirewallRuleCollectionResult:
    """Collect a validated current-policy rule set from a fixed mocked boundary."""

    if not isinstance(rules, WindowsFirewallRulesCollectionProtocol):
        raise TypeError("rule collection requires the fixed typed interface.")
    ledger = accounting or WindowsComOperationAccounting()
    if not isinstance(ledger, WindowsComOperationAccounting):
        raise TypeError("COM accounting must use the typed contract.")
    cleanup = WindowsComCleanupStack()
    cleanup.own(
        WindowsComResourceKind.RULES,
        _release_callback(rules, ledger),
    )
    failure: WindowsFirewallRuleResultCode | None = None
    collected = ()
    try:
        collected, failure = _collect(rules, ledger, cleanup)
    except WindowsComContractError as exc:
        failure = _result_code(exc.category)
    except (TypeError, ValueError):
        failure = WindowsFirewallRuleResultCode.INVALID_RESULT
    except Exception:
        failure = WindowsFirewallRuleResultCode.INTERNAL_ERROR
    try:
        cleanup.close()
    except WindowsComContractError:
        if failure is None:
            failure = WindowsFirewallRuleResultCode.INTERNAL_ERROR
    if failure is not None:
        return _failure_result(failure)
    result = WindowsFirewallRuleCollectionResult(
        WindowsFirewallRuleResultCode.COMPLETE,
        WindowsFirewallPolicyView.CURRENT_POLICY_VIEW,
        collected,
    )
    normalized = normalize_windows_firewall_rules(result)
    if normalized.failure is not None:
        return _failure_result(WindowsFirewallRuleResultCode.INVALID_RESULT)
    return result


def _collect(
    rules: WindowsFirewallRulesCollectionProtocol,
    ledger: WindowsComOperationAccounting,
    cleanup: WindowsComCleanupStack,
) -> tuple[
    tuple[RawWindowsFirewallRule, ...],
    WindowsFirewallRuleResultCode | None,
]:
    reported_count = _collection_call(rules.get_count, ledger)
    if isinstance(reported_count, bool) or not isinstance(reported_count, int) \
            or reported_count < 0:
        raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)
    if reported_count > MAX_FIREWALL_RULES:
        raise WindowsComContractError(WindowsComFailureCategory.LIMIT_EXCEEDED)

    new_enum = _collection_call(rules.get_new_enum, ledger)
    if not isinstance(new_enum, WindowsFirewallNewEnumProtocol):
        raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)
    cleanup.own(
        WindowsComResourceKind.NEW_ENUM_UNKNOWN,
        _release_callback(new_enum, ledger),
    )
    ledger.record_query_interface()
    enumerator = _query_enum_variant(new_enum)
    cleanup.own(
        WindowsComResourceKind.ENUMVARIANT,
        _release_callback(enumerator, ledger),
    )

    raw_rules = []
    seen_element_ids: set[int] = set()
    retained_elements: list[WindowsFirewallRuleElementProtocol] = []
    while True:
        step = _next(enumerator, ledger)
        if step.state == WindowsFirewallEnumerationState.END:
            break
        raw = _read_element(step, ledger, seen_element_ids, retained_elements)
        if raw is None:
            raise WindowsComContractError(
                WindowsComFailureCategory.INVALID_RESULT
            )
        raw_rules.append(raw)
        if len(raw_rules) > reported_count:
            return (), WindowsFirewallRuleResultCode.COLLECTION_INCOMPLETE
    if len(raw_rules) != reported_count:
        return (), WindowsFirewallRuleResultCode.COLLECTION_INCOMPLETE
    return tuple(raw_rules), None


def _read_element(
    step: WindowsFirewallEnumerationStep,
    ledger: WindowsComOperationAccounting,
    seen_element_ids: set[int],
    retained_elements: list[WindowsFirewallRuleElementProtocol],
) -> RawWindowsFirewallRule:
    owned = step.value
    if not isinstance(owned, WindowsOwnedVariant):
        raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)
    primary: WindowsComFailureCategory | None = None
    rule_interface = None
    try:
        element = owned.extract(WindowsVariantType.DISPATCH)
        if not isinstance(element, WindowsFirewallRuleElementProtocol):
            raise WindowsComContractError(
                WindowsComFailureCategory.INVALID_RESULT
            )
        identity = id(element)
        if identity in seen_element_ids:
            raise WindowsComContractError(
                WindowsComFailureCategory.INVALID_RESULT
            )
        seen_element_ids.add(identity)
        retained_elements.append(element)
        ledger.record_query_interface()
        rule_interface = _query_rule(element)
    except WindowsComContractError as exc:
        primary = exc.category
    except (TypeError, ValueError):
        primary = WindowsComFailureCategory.INVALID_RESULT
    except Exception:
        primary = WindowsComFailureCategory.INTERNAL_ERROR
    try:
        owned.close()
        ledger.record_cleanup()
    except WindowsComContractError:
        if primary is None:
            primary = WindowsComFailureCategory.INTERNAL_ERROR
    if primary is not None:
        if rule_interface is not None:
            try:
                ledger.record_release()
                ledger.record_cleanup()
                rule_interface.release()
            except Exception:
                pass
        raise WindowsComContractError(primary)
    per_rule = WindowsComOperationAccounting()
    result = read_windows_firewall_rule(rule_interface, accounting=per_rule)
    _merge_rule_accounting(ledger, per_rule)
    if result.failure is not None:
        raise WindowsComContractError(result.failure)
    return result.rule


def _collection_call(call, ledger: WindowsComOperationAccounting):
    _record_enumeration(ledger)
    try:
        return call()
    except WindowsComContractError:
        raise
    except (TypeError, ValueError):
        raise WindowsComContractError(
            WindowsComFailureCategory.INVALID_RESULT
        ) from None
    except Exception:
        raise WindowsComContractError(
            WindowsComFailureCategory.INTERNAL_ERROR
        ) from None


def _query_enum_variant(
    value: WindowsFirewallNewEnumProtocol,
) -> WindowsFirewallEnumVariantProtocol:
    try:
        result = value.query_enum_variant()
    except WindowsComContractError:
        raise
    except Exception:
        raise WindowsComContractError(
            WindowsComFailureCategory.INTERNAL_ERROR
        ) from None
    if not isinstance(result, WindowsFirewallEnumVariantProtocol):
        raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)
    return result


def _query_rule(
    value: WindowsFirewallRuleElementProtocol,
) -> WindowsFirewallRuleReaderProtocol:
    try:
        result = value.query_rule()
    except WindowsComContractError:
        raise
    except Exception:
        raise WindowsComContractError(
            WindowsComFailureCategory.INTERNAL_ERROR
        ) from None
    if not isinstance(result, WindowsFirewallRuleReaderProtocol):
        raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)
    return result


def _next(
    enumerator: WindowsFirewallEnumVariantProtocol,
    ledger: WindowsComOperationAccounting,
) -> WindowsFirewallEnumerationStep:
    value = _collection_call(enumerator.next_one, ledger)
    if not isinstance(value, WindowsFirewallEnumerationStep):
        raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)
    valid = (
        value.state == WindowsFirewallEnumerationState.ITEM
        and value.fetched == 1
        and isinstance(value.value, WindowsOwnedVariant)
    ) or (
        value.state == WindowsFirewallEnumerationState.END
        and value.fetched == 0
        and value.value is None
    )
    if not valid:
        if isinstance(value.value, WindowsOwnedVariant):
            try:
                value.value.close()
                ledger.record_cleanup()
            except WindowsComContractError:
                pass
        raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)
    return value


def _record_enumeration(ledger: WindowsComOperationAccounting) -> None:
    if ledger.enumeration_operations >= MAX_FIREWALL_ENUMERATION_OPERATIONS:
        raise WindowsComContractError(WindowsComFailureCategory.LIMIT_EXCEEDED)
    ledger.record_enumeration()


def _merge_rule_accounting(
    collection: WindowsComOperationAccounting,
    per_rule: WindowsComOperationAccounting,
) -> None:
    collection.property_getters += per_rule.property_getters
    collection.query_interfaces += per_rule.query_interfaces
    collection.interface_releases += per_rule.interface_releases
    collection.initialization_operations += per_rule.initialization_operations
    collection.cleanup_operations += per_rule.cleanup_operations


def _release_callback(interface, ledger: WindowsComOperationAccounting):
    def release() -> None:
        ledger.record_release()
        ledger.record_cleanup()
        interface.release()

    return release


def _result_code(category: WindowsComFailureCategory) -> WindowsFirewallRuleResultCode:
    return WindowsFirewallRuleResultCode(category.value)


def _failure_result(
    state: WindowsFirewallRuleResultCode,
) -> WindowsFirewallRuleCollectionResult:
    return WindowsFirewallRuleCollectionResult(
        state, WindowsFirewallPolicyView.CURRENT_POLICY_VIEW
    )
