"""Pure normalization for future Windows Firewall current-policy rule data."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import ipaddress
import ntpath

from cyberwatchtower.firewall_policy import (
    AddressConditionKind,
    ApplicationConditionKind,
    FirewallAddressCondition,
    FirewallApplicationCondition,
    FirewallInterfaceCondition,
    FirewallPlatformTechnology,
    FirewallPortRange,
    FirewallRuleAction,
    FirewallRuleDirection,
    FirewallRuleEnabledState,
    FirewallRuleObservation,
    FirewallRuleUnsupportedFeature,
    InterfaceConditionKind,
    MAX_CONDITIONS_PER_RULE,
    MAX_FIREWALL_RULES,
    MAX_NORMALIZED_TOKEN,
    MAX_VALUES_PER_CONDITION,
    normalize_firewall_rules,
    semantic_firewall_rule_id,
)
from cyberwatchtower.platform.models import FirewallProfile, NetworkProtocol
from cyberwatchtower.report_contracts import CoverageState

from .firewall_rule_models import (
    WINDOWS_FIREWALL_ALL_PROFILES,
    WINDOWS_FIREWALL_PROTOCOL_ANY,
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


WINDOWS_FIREWALL_MAX_GETTER_OPERATIONS_PER_RULE = 20


class WindowsComOwnershipRequirement(str, Enum):
    COINITIALIZEEX_AND_COUNINITIALIZE_OWNERSHIP = (
        "COINITIALIZEEX_AND_COUNINITIALIZE_OWNERSHIP"
    )
    QUERY_INTERFACE_ADDREF_RELEASE = "QUERY_INTERFACE_ADDREF_RELEASE"
    POLICY_INTERFACE_RELEASE = "POLICY_INTERFACE_RELEASE"
    RULE_COLLECTION_RELEASE = "RULE_COLLECTION_RELEASE"
    UNKNOWN_INTERFACE_RELEASE = "UNKNOWN_INTERFACE_RELEASE"
    ENUMERATOR_RELEASE = "ENUMERATOR_RELEASE"
    RULE_RELEASE_EACH_ITERATION = "RULE_RELEASE_EACH_ITERATION"
    BSTR_FREE = "BSTR_FREE"
    VARIANT_CLEAR = "VARIANT_CLEAR"
    SAFEARRAY_RELEASE = "SAFEARRAY_RELEASE"
    CLEANUP_ON_ALL_FAILURES = "CLEANUP_ON_ALL_FAILURES"


class WindowsComGetterDeadlineGuarantee(str, Enum):
    NON_PREEMPTIBLE_IN_PROCESS = "NON_PREEMPTIBLE_IN_PROCESS"


@dataclass(frozen=True, slots=True)
class WindowsFirewallComEnumerationContract:
    requirements: tuple[WindowsComOwnershipRequirement, ...]
    max_rules: int
    max_getter_operations_per_rule: int
    max_conditions_per_rule: int
    max_values_per_condition: int
    max_normalized_token: int
    acquisition_deadline_required: bool
    getter_deadline_guarantee: WindowsComGetterDeadlineGuarantee

    def __post_init__(self) -> None:
        if not isinstance(self.requirements, tuple) or not self.requirements \
                or not all(isinstance(value, WindowsComOwnershipRequirement)
                           for value in self.requirements) \
                or len(set(self.requirements)) != len(self.requirements):
            raise ValueError("COM ownership requirements must be a unique closed tuple.")
        if self.requirements != tuple(WindowsComOwnershipRequirement):
            raise ValueError("COM ownership contract must include every requirement.")
        if self.max_rules != MAX_FIREWALL_RULES \
                or self.max_conditions_per_rule != MAX_CONDITIONS_PER_RULE \
                or self.max_values_per_condition != MAX_VALUES_PER_CONDITION \
                or self.max_normalized_token != MAX_NORMALIZED_TOKEN:
            raise ValueError("COM enumeration bounds must reuse neutral limits.")
        if self.max_getter_operations_per_rule <= 0:
            raise ValueError("getter operation bound must be positive.")
        if self.acquisition_deadline_required is not True:
            raise ValueError("future enumeration requires an acquisition deadline.")
        if not isinstance(
            self.getter_deadline_guarantee, WindowsComGetterDeadlineGuarantee
        ):
            raise TypeError("getter deadline guarantee must use the closed enum.")


WINDOWS_FIREWALL_COM_ENUMERATION_CONTRACT = WindowsFirewallComEnumerationContract(
    tuple(WindowsComOwnershipRequirement),
    MAX_FIREWALL_RULES,
    WINDOWS_FIREWALL_MAX_GETTER_OPERATIONS_PER_RULE,
    MAX_CONDITIONS_PER_RULE,
    MAX_VALUES_PER_CONDITION,
    MAX_NORMALIZED_TOKEN,
    True,
    WindowsComGetterDeadlineGuarantee.NON_PREEMPTIBLE_IN_PROCESS,
)


@dataclass(frozen=True, slots=True)
class WindowsFirewallRuleNormalizationResult:
    policy_view: WindowsFirewallPolicyView
    coverage: CoverageState
    rules: tuple[FirewallRuleObservation, ...] = ()
    failure: WindowsFirewallRuleResultCode | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.policy_view, WindowsFirewallPolicyView):
            raise TypeError("normalized policy view must use the closed enum.")
        if not isinstance(self.coverage, CoverageState):
            raise TypeError("normalized coverage must use the closed enum.")
        if not isinstance(self.rules, tuple) or not all(
            isinstance(rule, FirewallRuleObservation) for rule in self.rules
        ):
            raise TypeError("normalized rules must use an immutable typed tuple.")
        if self.failure is not None and not isinstance(
            self.failure, WindowsFirewallRuleResultCode
        ):
            raise TypeError("normalized failure must use the closed enum.")
        if self.coverage == CoverageState.COMPLETE and self.failure is not None:
            raise ValueError("complete normalized rules cannot carry failure.")
        if self.coverage != CoverageState.COMPLETE and self.failure is None:
            raise ValueError("incomplete normalized rules require typed failure.")


def windows_application_identity(path: RawWindowsApplicationPath) -> str:
    """Reduce a private full path to a domain-separated opaque identity."""

    if not isinstance(path, RawWindowsApplicationPath):
        raise TypeError("application identity requires the private raw path type.")
    raw = path.consume_for_normalization().replace("/", "\\")
    normalized = ntpath.normcase(ntpath.normpath(raw))
    if not ntpath.isabs(normalized) or normalized in {".", "\\"}:
        raise ValueError("Windows application path must be absolute.")
    return hashlib.sha256(
        b"cyberwatchtower:windows-firewall-application:v1\0"
        + normalized.encode("utf-8")
    ).hexdigest()


def _interface_identity(value: RawWindowsInterfaceIdentity) -> str:
    if not isinstance(value, RawWindowsInterfaceIdentity):
        raise TypeError("interface identity requires the private raw type.")
    normalized = value.consume_for_normalization().strip().casefold()
    if not normalized:
        raise ValueError("Windows interface identity is empty.")
    return hashlib.sha256(
        b"cyberwatchtower:windows-firewall-interface:v1\0"
        + normalized.encode("utf-8")
    ).hexdigest()


def _profiles(mask: int) -> tuple[FirewallProfile, ...]:
    if mask == WINDOWS_FIREWALL_ALL_PROFILES:
        return ()
    mapping = (
        (0x1, FirewallProfile.DOMAIN),
        (0x2, FirewallProfile.PRIVATE),
        (0x4, FirewallProfile.PUBLIC),
    )
    return tuple(profile for bit, profile in mapping if mask & bit)


def _protocol(value: int) -> tuple[NetworkProtocol | None, bool]:
    if value == 6:
        return NetworkProtocol.TCP, False
    if value == 17:
        return NetworkProtocol.UDP, False
    if value == WINDOWS_FIREWALL_PROTOCOL_ANY:
        return None, False
    return None, True


def _ports(values: tuple[str, ...]) -> tuple[FirewallPortRange, ...]:
    if not values or values == ("*",):
        return ()
    if "*" in values:
        raise ValueError("ANY port cannot be combined with explicit ports.")
    parsed = []
    for value in values:
        parts = value.split("-", 1)
        if len(parts) == 1:
            if not parts[0].isdigit():
                raise ValueError("Windows firewall port is invalid.")
            start = end = int(parts[0])
        else:
            if not all(part.isdigit() for part in parts):
                raise ValueError("Windows firewall port range is invalid.")
            start, end = map(int, parts)
        parsed.append(FirewallPortRange(start, end))
    return tuple(sorted(set(parsed), key=repr))


def _addresses(values: tuple[str, ...]) -> tuple[FirewallAddressCondition, ...]:
    if not values or values == ("*",):
        return ()
    if "*" in values:
        raise ValueError("ANY address cannot be combined with explicit addresses.")
    parsed = []
    for value in values:
        if value.casefold() == "localsubnet":
            condition = FirewallAddressCondition(
                AddressConditionKind.SUPPORTED_SPECIAL_SCOPE, "LOCAL_SUBNET"
            )
        elif "/" in value:
            ipaddress.ip_network(value, strict=False)
            condition = FirewallAddressCondition(AddressConditionKind.CIDR, value)
        else:
            ipaddress.ip_address(value)
            condition = FirewallAddressCondition(AddressConditionKind.EXACT, value)
        parsed.append(condition)
    return tuple(sorted(set(parsed), key=repr))


def _service_identity(value: str) -> str:
    if not value or len(value) > MAX_NORMALIZED_TOKEN or any(
        not (character.isalnum() or character in "_.-") for character in value
    ):
        raise ValueError("Windows service name is outside the canonical contract.")
    return f"windows-service:{value.casefold()}"


def _application(
    raw: RawWindowsFirewallRule,
    unsupported: set[FirewallRuleUnsupportedFeature],
) -> FirewallApplicationCondition:
    if raw.application_path is not None and raw.service_name is not None:
        unsupported.add(FirewallRuleUnsupportedFeature.UNMODELED_PLATFORM_PREDICATE)
    if raw.service_name is not None:
        return FirewallApplicationCondition(
            ApplicationConditionKind.SERVICE_IDENTITY,
            _service_identity(raw.service_name),
        )
    if raw.application_path is not None:
        return FirewallApplicationCondition(
            ApplicationConditionKind.APPLICATION_DIGEST,
            windows_application_identity(raw.application_path),
        )
    return FirewallApplicationCondition(ApplicationConditionKind.ANY)


def _interface(
    raw: RawWindowsFirewallRule,
    unsupported: set[FirewallRuleUnsupportedFeature],
) -> FirewallInterfaceCondition:
    explicit_types = tuple(
        value for value in raw.interface_types
        if value != WindowsRawFirewallInterfaceType.ANY
    )
    if WindowsRawFirewallInterfaceType.ANY in raw.interface_types and explicit_types:
        raise ValueError("ANY interface type cannot accompany explicit types.")
    if len(raw.interfaces) == 1 and not explicit_types:
        return FirewallInterfaceCondition(
            InterfaceConditionKind.INTERFACE_DIGEST,
            _interface_identity(raw.interfaces[0]),
        )
    if len(raw.interfaces) > 1 or (raw.interfaces and explicit_types):
        unsupported.add(FirewallRuleUnsupportedFeature.UNMODELED_PLATFORM_PREDICATE)
    if len(explicit_types) == 1:
        kind = {
            WindowsRawFirewallInterfaceType.LAN: InterfaceConditionKind.LAN,
            WindowsRawFirewallInterfaceType.WIRELESS: InterfaceConditionKind.WIRELESS,
            WindowsRawFirewallInterfaceType.REMOTE_ACCESS:
                InterfaceConditionKind.REMOTE_ACCESS,
        }[explicit_types[0]]
        return FirewallInterfaceCondition(kind)
    if len(explicit_types) > 1:
        unsupported.add(FirewallRuleUnsupportedFeature.UNMODELED_PLATFORM_PREDICATE)
    return FirewallInterfaceCondition(InterfaceConditionKind.ANY)


def _normalize_rule(raw: RawWindowsFirewallRule) -> FirewallRuleObservation:
    unsupported: set[FirewallRuleUnsupportedFeature] = set()
    protocol, protocol_unsupported = _protocol(raw.protocol)
    if protocol_unsupported:
        unsupported.add(FirewallRuleUnsupportedFeature.UNMODELED_PLATFORM_PREDICATE)
    remote_ports = _ports(raw.remote_ports)
    if remote_ports:
        unsupported.add(FirewallRuleUnsupportedFeature.REMOTE_PORT_RESTRICTED)
    remote_addresses = _addresses(raw.remote_addresses)
    if remote_addresses:
        unsupported.add(FirewallRuleUnsupportedFeature.REMOTE_ADDRESS_RESTRICTED)
    for feature in raw.unsupported_features:
        if feature in {
            WindowsRawFirewallUnsupportedFeature.LOCAL_USER_SCOPE,
            WindowsRawFirewallUnsupportedFeature.PACKAGE_SCOPE,
        }:
            unsupported.add(FirewallRuleUnsupportedFeature.USER_OR_PACKAGE_SCOPE)
        else:
            unsupported.add(FirewallRuleUnsupportedFeature.UNMODELED_PLATFORM_PREDICATE)
    application = _application(raw, unsupported)
    interface = _interface(raw, unsupported)
    values = {
        "technology": FirewallPlatformTechnology.WINDOWS_FIREWALL,
        "enabled": (
            FirewallRuleEnabledState.ENABLED
            if raw.enabled else FirewallRuleEnabledState.DISABLED
        ),
        "direction": (
            FirewallRuleDirection.INBOUND
            if raw.direction == WindowsRawFirewallRuleDirection.INBOUND
            else FirewallRuleDirection.OUTBOUND
        ),
        "action": (
            FirewallRuleAction.ALLOW
            if raw.action == WindowsRawFirewallRuleAction.ALLOW
            else FirewallRuleAction.BLOCK
        ),
        "profiles": _profiles(raw.profile_mask),
        "protocol": protocol,
        "local_ports": _ports(raw.local_ports),
        "local_addresses": _addresses(raw.local_addresses),
        "remote_addresses": remote_addresses,
        "application": application,
        "interface": interface,
        "edge_traversal": raw.edge_traversal,
        "unsupported_features": tuple(sorted(unsupported, key=lambda item: item.value)),
    }
    return FirewallRuleObservation(
        semantic_firewall_rule_id(**values), **values
    )


def normalize_windows_firewall_rules(
    result: WindowsFirewallRuleCollectionResult,
) -> WindowsFirewallRuleNormalizationResult:
    """Normalize a typed current-policy fixture without invoking native APIs."""

    if not isinstance(result, WindowsFirewallRuleCollectionResult):
        raise TypeError("Windows rule normalization requires a typed result.")
    if result.state not in {
        WindowsFirewallRuleResultCode.COMPLETE,
        WindowsFirewallRuleResultCode.COLLECTION_INCOMPLETE,
    }:
        coverage = (
            CoverageState.UNKNOWN
            if result.state in {
                WindowsFirewallRuleResultCode.API_UNAVAILABLE,
                WindowsFirewallRuleResultCode.UNSUPPORTED,
            }
            else CoverageState.INCOMPLETE
        )
        return WindowsFirewallRuleNormalizationResult(
            result.policy_view, coverage, failure=result.state
        )
    try:
        rules = normalize_firewall_rules(tuple(
            _normalize_rule(rule) for rule in result.rules
        ))
    except (KeyError, TypeError, ValueError):
        return WindowsFirewallRuleNormalizationResult(
            result.policy_view,
            CoverageState.INCOMPLETE,
            failure=WindowsFirewallRuleResultCode.INVALID_RESULT,
        )
    if result.state == WindowsFirewallRuleResultCode.COLLECTION_INCOMPLETE:
        return WindowsFirewallRuleNormalizationResult(
            result.policy_view,
            CoverageState.INCOMPLETE,
            rules,
            WindowsFirewallRuleResultCode.COLLECTION_INCOMPLETE,
        )
    return WindowsFirewallRuleNormalizationResult(
        result.policy_view, CoverageState.COMPLETE, rules
    )
