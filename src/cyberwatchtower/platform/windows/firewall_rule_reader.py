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


class _WindowsFirewallCsvFailureReason(str, Enum):
    EMPTY_ELEMENT = "EMPTY_ELEMENT"
    ENTRY_LIMIT_EXCEEDED = "ENTRY_LIMIT_EXCEEDED"


class _WindowsFirewallCsvError(WindowsComContractError):
    """Sanitized closed CSV failure used for narrow internal recovery."""

    __slots__ = ("reason",)

    def __init__(self, reason: _WindowsFirewallCsvFailureReason) -> None:
        if not isinstance(reason, _WindowsFirewallCsvFailureReason):
            raise TypeError("CSV failure must use the closed reason.")
        self.reason = reason
        super().__init__(WindowsComFailureCategory.INVALID_RESULT)


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


def read_windows_firewall_rule(
    interface: WindowsFirewallRuleReaderProtocol,
    *,
    accounting: WindowsComOperationAccounting | None = None,
) -> WindowsFirewallSingleRuleReadResult:
    """Read one already-acquired mocked rule and release all owned interfaces."""

    if not isinstance(interface, WindowsFirewallRuleReaderProtocol):
        raise TypeError("single-rule reader requires the fixed typed interface.")
    ledger = accounting or WindowsComOperationAccounting()
    if not isinstance(ledger, WindowsComOperationAccounting):
        raise TypeError("COM accounting must use the typed contract.")
    cleanup = WindowsComCleanupStack()
    cleanup.own(
        WindowsComResourceKind.RULE,
        _release_callback(interface, ledger),
    )
    primary: WindowsComFailureCategory | None = None
    rule: RawWindowsFirewallRule | None = None
    try:
        rule = _read_rule(interface, ledger, cleanup)
    except WindowsComContractError as exc:
        primary = exc.category
    except (TypeError, ValueError):
        primary = WindowsComFailureCategory.INVALID_RESULT
    except Exception:
        primary = WindowsComFailureCategory.INTERNAL_ERROR
    try:
        cleanup.close()
    except WindowsComContractError as exc:
        if primary is None:
            primary = exc.category
    if primary is not None:
        return WindowsFirewallSingleRuleReadResult(failure=primary)
    return WindowsFirewallSingleRuleReadResult(rule=rule)


def _read_rule(
    base: WindowsFirewallRuleReaderProtocol,
    ledger: WindowsComOperationAccounting,
    cleanup: WindowsComCleanupStack,
) -> RawWindowsFirewallRule:
    enabled = _scalar(base.get_enabled, WindowsFirewallPropertyGetter.ENABLED, ledger)
    direction = _scalar(base.get_direction, WindowsFirewallPropertyGetter.DIRECTION,
                        ledger)
    action = _scalar(base.get_action, WindowsFirewallPropertyGetter.ACTION, ledger)
    profiles = _scalar(base.get_profiles, WindowsFirewallPropertyGetter.PROFILES,
                       ledger)
    protocol = _scalar(base.get_protocol, WindowsFirewallPropertyGetter.PROTOCOL,
                       ledger)
    protocol_value = _require_int(protocol)
    unsupported: set[WindowsRawFirewallUnsupportedFeature] = set()
    try:
        local_ports = _csv_bstr(
            base.get_local_ports, WindowsFirewallPropertyGetter.LOCAL_PORTS, ledger
        )
    except _WindowsFirewallCsvError as exc:
        if exc.reason != _WindowsFirewallCsvFailureReason.EMPTY_ELEMENT \
                or protocol_value not in {6, 17}:
            raise
        local_ports = ()
        unsupported.add(
            WindowsRawFirewallUnsupportedFeature.UNMODELED_NATIVE_PREDICATE
        )
    try:
        remote_ports = _csv_bstr(
            base.get_remote_ports, WindowsFirewallPropertyGetter.REMOTE_PORTS,
            ledger,
        )
    except _WindowsFirewallCsvError as exc:
        if exc.reason != _WindowsFirewallCsvFailureReason.EMPTY_ELEMENT \
                or protocol_value not in {6, 17}:
            raise
        remote_ports = ()
        unsupported.add(
            WindowsRawFirewallUnsupportedFeature.UNMODELED_NATIVE_PREDICATE
        )
    local_addresses = _csv_bstr(
        base.get_local_addresses, WindowsFirewallPropertyGetter.LOCAL_ADDRESSES,
        ledger,
    )
    remote_addresses = _csv_bstr(
        base.get_remote_addresses, WindowsFirewallPropertyGetter.REMOTE_ADDRESSES,
        ledger,
    )
    application_text = _optional_bstr(
        base.get_application_name,
        WindowsFirewallPropertyGetter.APPLICATION_NAME,
        ledger,
        MAX_RAW_WINDOWS_APPLICATION_PATH,
    )
    service_name = _optional_bstr(
        base.get_service_name, WindowsFirewallPropertyGetter.SERVICE_NAME, ledger
    )
    interface_types_text = _optional_bstr(
        base.get_interface_types,
        WindowsFirewallPropertyGetter.INTERFACE_TYPES,
        ledger,
    )
    interfaces = _interfaces(base, ledger)
    if _require_int(protocol) in WINDOWS_ICMP_PROTOCOLS:
        icmp = _optional_bstr(
            base.get_icmp_types_and_codes,
            WindowsFirewallPropertyGetter.ICMP_TYPES_AND_CODES,
            ledger,
        )
        if icmp is not None:
            unsupported.add(
                WindowsRawFirewallUnsupportedFeature.ICMP_TYPE_CONDITION
            )

    ledger.record_query_interface()
    rule2_query = _query(base.query_rule2)
    if rule2_query.availability == WindowsComInterfaceAvailability.AVAILABLE:
        rule2 = rule2_query.interface
        assert rule2 is not None
        cleanup.own(WindowsComResourceKind.RULE2, _release_callback(rule2, ledger))
        edge_options = _scalar(
            rule2.get_edge_traversal_options,
            WindowsFirewallPropertyGetter.EDGE_TRAVERSAL_OPTIONS,
            ledger,
        )
        edge_traversal = _edge_options(edge_options, unsupported)
    else:
        unsupported.add(
            WindowsRawFirewallUnsupportedFeature.UNMODELED_NATIVE_PREDICATE
        )
        edge_traversal = _strict_bool(_scalar(
            base.get_edge_traversal,
            WindowsFirewallPropertyGetter.EDGE_TRAVERSAL,
            ledger,
        ))

    ledger.record_query_interface()
    rule3_query = _query(base.query_rule3)
    if rule3_query.availability == WindowsComInterfaceAvailability.AVAILABLE:
        rule3 = rule3_query.interface
        assert rule3 is not None
        cleanup.own(WindowsComResourceKind.RULE3, _release_callback(rule3, ledger))
        _read_rule3_predicates(rule3, ledger, unsupported)
    else:
        unsupported.add(
            WindowsRawFirewallUnsupportedFeature.UNMODELED_NATIVE_PREDICATE
        )

    enabled_value = _strict_bool(enabled)
    direction_value = {
        WINDOWS_NET_FW_RULE_DIR_IN: WindowsRawFirewallRuleDirection.INBOUND,
        WINDOWS_NET_FW_RULE_DIR_OUT: WindowsRawFirewallRuleDirection.OUTBOUND,
    }.get(_require_int(direction))
    action_value = {
        WINDOWS_NET_FW_ACTION_BLOCK: WindowsRawFirewallRuleAction.BLOCK,
        WINDOWS_NET_FW_ACTION_ALLOW: WindowsRawFirewallRuleAction.ALLOW,
    }.get(_require_int(action))
    application_value = (
        RawWindowsApplicationPath(application_text)
        if application_text is not None else None
    )
    interface_type_values = _interface_types(interface_types_text)
    interface_values = tuple(RawWindowsInterfaceIdentity(item) for item in interfaces)
    return RawWindowsFirewallRule(
        policy_view=WindowsFirewallPolicyView.CURRENT_POLICY_VIEW,
        enabled=enabled_value,
        direction=direction_value,
        action=action_value,
        profile_mask=_require_int(profiles),
        protocol=protocol_value,
        local_ports=local_ports,
        remote_ports=remote_ports,
        local_addresses=local_addresses,
        remote_addresses=remote_addresses,
        application_path=application_value,
        service_name=service_name,
        interface_types=interface_type_values,
        interfaces=interface_values,
        edge_traversal=edge_traversal,
        unsupported_features=tuple(sorted(unsupported, key=lambda item: item.value)),
    )


def _read_rule3_predicates(
    rule3: WindowsFirewallRule3ReaderProtocol,
    ledger: WindowsComOperationAccounting,
    unsupported: set[WindowsRawFirewallUnsupportedFeature],
) -> None:
    package = _optional_bstr(
        rule3.get_local_app_package_id,
        WindowsFirewallPropertyGetter.LOCAL_APP_PACKAGE_ID,
        ledger,
    )
    local_users = _optional_bstr(
        rule3.get_local_user_authorized_list,
        WindowsFirewallPropertyGetter.LOCAL_USER_AUTHORIZED_LIST,
        ledger,
    )
    remote_machines = _optional_bstr(
        rule3.get_remote_machine_authorized_list,
        WindowsFirewallPropertyGetter.REMOTE_MACHINE_AUTHORIZED_LIST,
        ledger,
    )
    remote_users = _optional_bstr(
        rule3.get_remote_user_authorized_list,
        WindowsFirewallPropertyGetter.REMOTE_USER_AUTHORIZED_LIST,
        ledger,
    )
    secure_flags = _scalar(
        rule3.get_secure_flags,
        WindowsFirewallPropertyGetter.SECURE_FLAGS,
        ledger,
    )
    if package is not None:
        unsupported.add(WindowsRawFirewallUnsupportedFeature.PACKAGE_SCOPE)
    if local_users is not None:
        unsupported.add(WindowsRawFirewallUnsupportedFeature.LOCAL_USER_SCOPE)
    if remote_machines is not None or remote_users is not None \
            or _require_int(secure_flags) != 0:
        unsupported.add(
            WindowsRawFirewallUnsupportedFeature.UNMODELED_NATIVE_PREDICATE
        )


def _scalar(call, getter, ledger):
    ledger.record_property_getter(getter)
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


def _optional_bstr(
    call,
    getter: WindowsFirewallPropertyGetter,
    ledger: WindowsComOperationAccounting,
    maximum: int = MAX_NORMALIZED_TOKEN,
) -> str | None:
    owned = _scalar(call, getter, ledger)
    if owned is None:
        return None
    if not isinstance(owned, WindowsOwnedBstr):
        raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)
    primary: WindowsComContractError | None = None
    value: str | None = None
    try:
        value = owned.copy_bounded(maximum)
    except WindowsComContractError as exc:
        primary = exc
    try:
        owned.close()
    except WindowsComContractError as exc:
        if primary is None:
            primary = exc
    if primary is not None:
        raise primary
    return value


def _csv_bstr(call, getter, ledger) -> tuple[str, ...]:
    value = _optional_bstr(call, getter, ledger)
    if value is None:
        return ()
    return _tokenize_csv(value)


def _tokenize_csv(value: str) -> tuple[str, ...]:
    parts = tuple(item.strip() for item in value.split(","))
    if not parts or any(not item for item in parts):
        raise _WindowsFirewallCsvError(
            _WindowsFirewallCsvFailureReason.EMPTY_ELEMENT
        )
    if len(parts) > MAX_VALUES_PER_CONDITION:
        raise _WindowsFirewallCsvError(
            _WindowsFirewallCsvFailureReason.ENTRY_LIMIT_EXCEEDED
        )
    return parts


def _interfaces(
    base: WindowsFirewallRuleReaderProtocol,
    ledger: WindowsComOperationAccounting,
) -> tuple[str, ...]:
    owned = _scalar(
        base.get_interfaces, WindowsFirewallPropertyGetter.INTERFACES, ledger
    )
    if not isinstance(owned, WindowsOwnedVariant):
        raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)
    primary: WindowsComContractError | None = None
    values: tuple[str, ...] = ()
    try:
        values = owned.extract_safearray()
        if len(values) > MAX_VALUES_PER_CONDITION or any(
            not item or len(item) > MAX_NORMALIZED_TOKEN for item in values
        ):
            raise WindowsComContractError(
                WindowsComFailureCategory.INVALID_RESULT
            )
    except WindowsComContractError as exc:
        primary = exc
    try:
        owned.close()
    except WindowsComContractError as exc:
        if primary is None:
            primary = exc
    if primary is not None:
        raise primary
    return values


def _interface_types(value: str | None) -> tuple[WindowsRawFirewallInterfaceType, ...]:
    if value is None:
        return ()
    mapping = {
        "all": WindowsRawFirewallInterfaceType.ANY,
        "lan": WindowsRawFirewallInterfaceType.LAN,
        "wireless": WindowsRawFirewallInterfaceType.WIRELESS,
        "remoteaccess": WindowsRawFirewallInterfaceType.REMOTE_ACCESS,
    }
    try:
        values = tuple(mapping[item.strip().replace(" ", "").casefold()]
                       for item in value.split(","))
    except KeyError:
        raise WindowsComContractError(
            WindowsComFailureCategory.INVALID_RESULT
        ) from None
    return values


def _edge_options(
    value: object,
    unsupported: set[WindowsRawFirewallUnsupportedFeature],
) -> bool | None:
    option = _require_int(value)
    if option == WINDOWS_EDGE_TRAVERSAL_DENY:
        return False
    if option == WINDOWS_EDGE_TRAVERSAL_ALLOW:
        return True
    if option in {
        WINDOWS_EDGE_TRAVERSAL_DEFER_TO_APP,
        WINDOWS_EDGE_TRAVERSAL_DEFER_TO_USER,
    }:
        unsupported.add(
            WindowsRawFirewallUnsupportedFeature.UNMODELED_NATIVE_PREDICATE
        )
        return None
    raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)


def _strict_bool(value: object) -> bool:
    if not isinstance(value, bool):
        raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)
    return value


def _require_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)
    return value


def _query(call):
    try:
        result = call()
    except WindowsComContractError:
        raise
    except Exception:
        raise WindowsComContractError(
            WindowsComFailureCategory.INTERNAL_ERROR
        ) from None
    if not isinstance(result, (WindowsFirewallRule2Query, WindowsFirewallRule3Query)):
        raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)
    return result


def _validate_query(availability, interface, expected) -> None:
    if not isinstance(availability, WindowsComInterfaceAvailability):
        raise TypeError("interface availability must use the closed enum.")
    if availability == WindowsComInterfaceAvailability.AVAILABLE:
        if not isinstance(interface, expected):
            raise TypeError("available interface query requires the fixed protocol.")
    elif interface is not None:
        raise ValueError("unavailable interface query cannot carry an interface.")


def _release_callback(interface, ledger: WindowsComOperationAccounting):
    def release() -> None:
        ledger.record_release()
        ledger.record_cleanup()
        interface.release()

    return release
