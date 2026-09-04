"""Closed platform-neutral contracts for host-firewall rule applicability."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import ipaddress
import json
import unicodedata

from .platform.models import BindExposure, FirewallProfile, NetworkProtocol
from .report_contracts import CoverageState


MAX_FIREWALL_RULES = 8_192
MAX_CONDITIONS_PER_RULE = 64
MAX_VALUES_PER_CONDITION = 256
MAX_NORMALIZED_TOKEN = 256
MAX_MATCHED_RULE_DIGESTS_PER_LISTENER = 16
MAX_POLICY_DIAGNOSTIC_LISTENERS = 8_192
_SHA256_HEX_LENGTH = 64


class FirewallPlatformTechnology(str, Enum):
    WINDOWS_FIREWALL = "WINDOWS_FIREWALL"
    NFTABLES = "NFTABLES"
    IPTABLES = "IPTABLES"
    UNKNOWN = "UNKNOWN"


class FirewallRuleDirection(str, Enum):
    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"


class FirewallRuleAction(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


class FirewallRuleEnabledState(str, Enum):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"
    UNKNOWN = "UNKNOWN"


class FirewallDefaultPolicyContext(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    UNKNOWN = "UNKNOWN"


class FirewallRuleApplicability(str, Enum):
    MATCHING_ALLOW = "MATCHING_ALLOW"
    MATCHING_BLOCK = "MATCHING_BLOCK"
    NO_MATCH = "NO_MATCH"
    AMBIGUOUS = "AMBIGUOUS"
    CONFLICTING = "CONFLICTING"
    INCOMPLETE = "INCOMPLETE"
    UNSUPPORTED = "UNSUPPORTED"


class FirewallConditionMatch(str, Enum):
    MATCH = "MATCH"
    NO_MATCH = "NO_MATCH"
    INDETERMINATE = "INDETERMINATE"


class FirewallPolicyIndeterminateCause(str, Enum):
    UNSUPPORTED_FEATURE = "UNSUPPORTED_FEATURE"
    REMOTE_ADDRESS_UNCERTAINTY = "REMOTE_ADDRESS_UNCERTAINTY"
    INTERFACE_UNCERTAINTY = "INTERFACE_UNCERTAINTY"
    MISSING_APPLICATION_IDENTITY = "MISSING_APPLICATION_IDENTITY"
    MISSING_SERVICE_IDENTITY = "MISSING_SERVICE_IDENTITY"
    UNKNOWN_ENABLEMENT_OR_STATE = "UNKNOWN_ENABLEMENT_OR_STATE"
    TYPED_RANGE_OR_PARSE_UNCERTAINTY = "TYPED_RANGE_OR_PARSE_UNCERTAINTY"
    PROFILE_UNCERTAINTY = "PROFILE_UNCERTAINTY"
    OTHER_CLOSED_INDETERMINATE = "OTHER_CLOSED_INDETERMINATE"


class FirewallPolicyDiagnosticStatus(str, Enum):
    COMPLETE = "COMPLETE"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    INVALID_RESULT = "INVALID_RESULT"


class FirewallUnsupportedFeatureDiagnosticSubtype(str, Enum):
    REMOTE_ADDRESS_RESTRICTED = "REMOTE_ADDRESS_RESTRICTED"
    REMOTE_PORT_RESTRICTED = "REMOTE_PORT_RESTRICTED"
    USER_OR_PACKAGE_SCOPE = "USER_OR_PACKAGE_SCOPE"
    UNMODELED_PLATFORM_PREDICATE = "UNMODELED_PLATFORM_PREDICATE"
    PRECEDENCE_UNPROVEN = "PRECEDENCE_UNPROVEN"


class FirewallRemoteUncertaintyShape(str, Enum):
    LOCAL_SUBNET = "LOCAL_SUBNET"
    EXPLICIT_RESTRICTION = "EXPLICIT_RESTRICTION"
    MIXED_SUPPORTED_RESTRICTION = "MIXED_SUPPORTED_RESTRICTION"
    OTHER_CLOSED_RESTRICTION = "OTHER_CLOSED_RESTRICTION"


class FirewallUnmodeledPlatformProvenance(str, Enum):
    RECOVERED_LOCAL_PORTS = "RECOVERED_LOCAL_PORTS"
    RECOVERED_REMOTE_PORTS = "RECOVERED_REMOTE_PORTS"
    RULE2_UNAVAILABLE = "RULE2_UNAVAILABLE"
    RULE3_UNAVAILABLE = "RULE3_UNAVAILABLE"
    REMOTE_PRINCIPAL_OR_SECURE_SCOPE = "REMOTE_PRINCIPAL_OR_SECURE_SCOPE"
    EDGE_TRAVERSAL_DEFERRED = "EDGE_TRAVERSAL_DEFERRED"
    OTHER_CLOSED_ORIGIN = "OTHER_CLOSED_ORIGIN"


class AddressConditionKind(str, Enum):
    ANY = "ANY"
    EXACT = "EXACT"
    CIDR = "CIDR"
    SUPPORTED_SPECIAL_SCOPE = "SUPPORTED_SPECIAL_SCOPE"
    IPV4_RANGE = "IPV4_RANGE"
    IPV6_RANGE = "IPV6_RANGE"


class ApplicationConditionKind(str, Enum):
    ANY = "ANY"
    APPLICATION_DIGEST = "APPLICATION_DIGEST"
    SERVICE_IDENTITY = "SERVICE_IDENTITY"


class InterfaceConditionKind(str, Enum):
    ANY = "ANY"
    LAN = "LAN"
    WIRELESS = "WIRELESS"
    REMOTE_ACCESS = "REMOTE_ACCESS"
    INTERFACE_DIGEST = "INTERFACE_DIGEST"


class FirewallSpecialAddressScope(str, Enum):
    LOOPBACK = "LOOPBACK"
    LOCAL_SUBNET = "LOCAL_SUBNET"


class FirewallRuleUnsupportedFeature(str, Enum):
    REMOTE_ADDRESS_RESTRICTED = "REMOTE_ADDRESS_RESTRICTED"
    REMOTE_PORT_RESTRICTED = "REMOTE_PORT_RESTRICTED"
    USER_OR_PACKAGE_SCOPE = "USER_OR_PACKAGE_SCOPE"
    UNMODELED_PLATFORM_PREDICATE = "UNMODELED_PLATFORM_PREDICATE"
    PRECEDENCE_UNPROVEN = "PRECEDENCE_UNPROVEN"


class ListenerPolicyBasis(str, Enum):
    EXPLICIT_UNIVERSAL_BLOCK = "EXPLICIT_UNIVERSAL_BLOCK"
    EXPLICIT_ALLOW = "EXPLICIT_ALLOW"
    NO_APPLICABLE_RULE = "NO_APPLICABLE_RULE"
    DEFAULT_POLICY_CONTEXT = "DEFAULT_POLICY_CONTEXT"
    POLICY_CONFLICT = "POLICY_CONFLICT"
    POLICY_EVALUATION_INCOMPLETE = "POLICY_EVALUATION_INCOMPLETE"
    POLICY_TECHNOLOGY_UNSUPPORTED = "POLICY_TECHNOLOGY_UNSUPPORTED"


def _token(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_NORMALIZED_TOKEN:
        raise ValueError(f"{field_name} is outside the supported bound.")
    if any(unicodedata.category(char) in {"Cc", "Cf"} for char in value):
        raise ValueError(f"{field_name} contains prohibited controls.")
    return value


def _digest(value: object, field_name: str) -> str:
    token = _token(value, field_name)
    if len(token) != _SHA256_HEX_LENGTH:
        raise ValueError(f"{field_name} must be a SHA-256 digest.")
    try:
        int(token, 16)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be hexadecimal.") from exc
    return token.casefold()


def _service_identity(value: object, field_name: str) -> str:
    token = _token(value, field_name)
    if token != token.casefold() or not token.startswith((
        "windows-service:", "systemd-service:", "service:",
    )) or any(not (char.isalnum() or char in "._:-") for char in token):
        raise ValueError(f"{field_name} must use a canonical service identity.")
    return token


@dataclass(frozen=True, slots=True, order=True)
class FirewallPortRange:
    start: int
    end: int

    def __post_init__(self) -> None:
        if any(isinstance(value, bool) or not isinstance(value, int)
               for value in (self.start, self.end)):
            raise TypeError("firewall ports must be integers.")
        if not 0 <= self.start <= self.end <= 65_535:
            raise ValueError("firewall port range is invalid.")


@dataclass(frozen=True, slots=True, order=True)
class FirewallIPv4AddressRange:
    start: ipaddress.IPv4Address
    end: ipaddress.IPv4Address

    def __post_init__(self) -> None:
        if not isinstance(self.start, ipaddress.IPv4Address) \
                or not isinstance(self.end, ipaddress.IPv4Address):
            raise TypeError("firewall IPv4 range requires IPv4Address endpoints.")
        if self.start > self.end:
            raise ValueError("firewall IPv4 range endpoints are reversed.")


@dataclass(frozen=True, slots=True, order=True)
class FirewallIPv6AddressRange:
    start: ipaddress.IPv6Address
    end: ipaddress.IPv6Address

    def __post_init__(self) -> None:
        if not isinstance(self.start, ipaddress.IPv6Address) \
                or not isinstance(self.end, ipaddress.IPv6Address):
            raise TypeError("firewall IPv6 range requires IPv6Address endpoints.")
        if self.start > self.end:
            raise ValueError("firewall IPv6 range endpoints are reversed.")


@dataclass(frozen=True, slots=True, order=True)
class FirewallAddressCondition:
    kind: AddressConditionKind
    value: str | FirewallIPv4AddressRange | FirewallIPv6AddressRange | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, AddressConditionKind):
            raise TypeError("address condition kind must use the closed enum.")
        if self.kind == AddressConditionKind.ANY:
            if self.value is not None:
                raise ValueError("ANY address condition cannot carry a value.")
            return
        if self.kind == AddressConditionKind.IPV4_RANGE:
            if not isinstance(self.value, FirewallIPv4AddressRange):
                raise TypeError("IPv4 range condition requires the closed range type.")
            return
        if self.kind == AddressConditionKind.IPV6_RANGE:
            if not isinstance(self.value, FirewallIPv6AddressRange):
                raise TypeError("IPv6 range condition requires the closed range type.")
            return
        if isinstance(self.value, (
            FirewallIPv4AddressRange, FirewallIPv6AddressRange,
        )):
            raise TypeError("non-range address condition cannot carry a range.")
        value = _token(self.value, "address condition")
        if self.kind == AddressConditionKind.EXACT:
            object.__setattr__(self, "value", str(ipaddress.ip_address(value)))
        elif self.kind == AddressConditionKind.CIDR:
            object.__setattr__(
                self, "value", str(ipaddress.ip_network(value, strict=False))
            )
        else:
            FirewallSpecialAddressScope(value)


@dataclass(frozen=True, slots=True, order=True)
class FirewallApplicationCondition:
    kind: ApplicationConditionKind
    value: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ApplicationConditionKind):
            raise TypeError("application condition kind must use the closed enum.")
        if self.kind == ApplicationConditionKind.ANY:
            if self.value is not None:
                raise ValueError("ANY application condition cannot carry a value.")
        elif self.kind == ApplicationConditionKind.APPLICATION_DIGEST:
            object.__setattr__(self, "value", _digest(self.value, "application digest"))
        else:
            object.__setattr__(
                self, "value", _service_identity(self.value, "service identity")
            )


@dataclass(frozen=True, slots=True, order=True)
class FirewallInterfaceCondition:
    kind: InterfaceConditionKind
    value: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, InterfaceConditionKind):
            raise TypeError("interface condition kind must use the closed enum.")
        if self.kind == InterfaceConditionKind.INTERFACE_DIGEST:
            object.__setattr__(self, "value", _digest(self.value, "interface digest"))
        elif self.value is not None:
            raise ValueError("interface-type conditions cannot carry a value.")


@dataclass(frozen=True, slots=True)
class FirewallRuleObservation:
    semantic_rule_id: str
    technology: FirewallPlatformTechnology
    enabled: FirewallRuleEnabledState
    direction: FirewallRuleDirection
    action: FirewallRuleAction
    profiles: tuple[FirewallProfile, ...]
    protocol: NetworkProtocol | None
    local_ports: tuple[FirewallPortRange, ...]
    local_addresses: tuple[FirewallAddressCondition, ...]
    remote_addresses: tuple[FirewallAddressCondition, ...]
    application: FirewallApplicationCondition
    interface: FirewallInterfaceCondition
    edge_traversal: bool | None = None
    unsupported_features: tuple[FirewallRuleUnsupportedFeature, ...] = ()
    unmodeled_platform_provenance: tuple[
        FirewallUnmodeledPlatformProvenance, ...
    ] = field(default=(), compare=False)

    def __post_init__(self) -> None:
        supplied_identity = _digest(
            self.semantic_rule_id, "semantic rule id"
        )
        object.__setattr__(self, "semantic_rule_id", supplied_identity)
        if not isinstance(self.technology, FirewallPlatformTechnology):
            raise TypeError("firewall technology must use the closed enum.")
        if not isinstance(self.enabled, FirewallRuleEnabledState):
            raise TypeError("rule enabled state must use the closed enum.")
        if not isinstance(self.direction, FirewallRuleDirection):
            raise TypeError("rule direction must use the closed enum.")
        if not isinstance(self.action, FirewallRuleAction):
            raise TypeError("rule action must use the closed enum.")
        if self.protocol is not None and not isinstance(self.protocol, NetworkProtocol):
            raise TypeError("rule protocol must use the closed enum or ANY.")
        self._validate_tuple("profiles", self.profiles, FirewallProfile)
        self._validate_tuple("local ports", self.local_ports, FirewallPortRange)
        self._validate_tuple(
            "local addresses", self.local_addresses, FirewallAddressCondition
        )
        self._validate_tuple(
            "remote addresses", self.remote_addresses, FirewallAddressCondition
        )
        self._validate_tuple(
            "unsupported features", self.unsupported_features,
            FirewallRuleUnsupportedFeature,
        )
        self._validate_tuple(
            "unmodeled platform provenance", self.unmodeled_platform_provenance,
            FirewallUnmodeledPlatformProvenance,
        )
        if self.unmodeled_platform_provenance and (
            FirewallRuleUnsupportedFeature.UNMODELED_PLATFORM_PREDICATE
            not in self.unsupported_features
        ):
            raise ValueError("diagnostic provenance requires unmodeled semantics.")
        if not isinstance(self.application, FirewallApplicationCondition):
            raise TypeError("rule application condition is invalid.")
        if not isinstance(self.interface, FirewallInterfaceCondition):
            raise TypeError("rule interface condition is invalid.")
        if self.edge_traversal is not None and not isinstance(self.edge_traversal, bool):
            raise TypeError("edge traversal must be boolean or unknown.")
        condition_count = (
            len(self.profiles) + len(self.local_ports) + len(self.local_addresses)
            + len(self.remote_addresses) + 2 + len(self.unsupported_features)
        )
        if condition_count > MAX_CONDITIONS_PER_RULE:
            raise ValueError("rule exceeds the condition bound.")
        expected_identity = semantic_firewall_rule_id(
            technology=self.technology, enabled=self.enabled,
            direction=self.direction, action=self.action, profiles=self.profiles,
            protocol=self.protocol, local_ports=self.local_ports,
            local_addresses=self.local_addresses,
            remote_addresses=self.remote_addresses,
            application=self.application, interface=self.interface,
            edge_traversal=self.edge_traversal,
            unsupported_features=self.unsupported_features,
        )
        if supplied_identity != expected_identity:
            raise ValueError("semantic rule id does not match normalized rule fields.")

    @staticmethod
    def _validate_tuple(name: str, values: tuple, expected: type) -> None:
        if not isinstance(values, tuple) or not all(
            isinstance(value, expected) for value in values
        ):
            raise TypeError(f"{name} must be a closed immutable tuple.")
        if len(values) > MAX_VALUES_PER_CONDITION:
            raise ValueError(f"{name} exceeds the value bound.")
        if len(set(values)) != len(values):
            raise ValueError(f"{name} cannot contain duplicates.")
        if tuple(sorted(values, key=repr)) != values:
            raise ValueError(f"{name} must be deterministically ordered.")


@dataclass(frozen=True, slots=True)
class ListenerPolicySubject:
    protocol: NetworkProtocol
    local_port: int
    bind_exposure: BindExposure
    local_address: str
    profiles: tuple[FirewallProfile, ...]
    application_digest: str | None = None
    service_identity: str | None = None
    interface: InterfaceConditionKind | None = None
    interface_digest: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.protocol, NetworkProtocol):
            raise TypeError("listener protocol must use the closed enum.")
        if isinstance(self.local_port, bool) or not isinstance(self.local_port, int) \
                or not 0 <= self.local_port <= 65_535:
            raise ValueError("listener port is invalid.")
        if not isinstance(self.bind_exposure, BindExposure):
            raise TypeError("listener bind exposure must use the closed enum.")
        address = _token(self.local_address, "listener address")
        ipaddress.ip_address(address.split("%", 1)[0])
        if not isinstance(self.profiles, tuple) or not all(
            isinstance(profile, FirewallProfile) for profile in self.profiles
        ) or len(set(self.profiles)) != len(self.profiles):
            raise ValueError("listener profiles must be a unique closed tuple.")
        if self.application_digest is not None:
            object.__setattr__(self, "application_digest", _digest(
                self.application_digest, "listener application digest"
            ))
        if self.service_identity is not None:
            object.__setattr__(self, "service_identity", _service_identity(
                self.service_identity, "listener service identity"
            ))
        if self.interface is not None and not isinstance(
            self.interface, InterfaceConditionKind
        ):
            raise TypeError("listener interface must use the closed enum.")
        if self.interface_digest is not None:
            object.__setattr__(self, "interface_digest", _digest(
                self.interface_digest, "listener interface digest"
            ))


@dataclass(frozen=True, slots=True, order=True)
class FirewallRuleMatch:
    semantic_rule_id: str
    action: FirewallRuleAction
    condition_match: FirewallConditionMatch
    universally_applicable: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "semantic_rule_id", _digest(
            self.semantic_rule_id, "matched rule id"
        ))
        if not isinstance(self.action, FirewallRuleAction):
            raise TypeError("matched action must use the closed enum.")
        if not isinstance(self.condition_match, FirewallConditionMatch):
            raise TypeError("condition match must use the closed enum.")
        if not isinstance(self.universally_applicable, bool):
            raise TypeError("universal applicability must be boolean.")


@dataclass(frozen=True, slots=True)
class ListenerPolicyAssessment:
    applicability: FirewallRuleApplicability
    default_policy_context: FirewallDefaultPolicyContext
    matches: tuple[FirewallRuleMatch, ...]
    evidence_basis: tuple[ListenerPolicyBasis, ...]
    collection_coverage: CoverageState
    applicability_coverage: CoverageState

    def __post_init__(self) -> None:
        if not isinstance(self.applicability, FirewallRuleApplicability):
            raise TypeError("applicability must use the closed enum.")
        if not isinstance(self.default_policy_context, FirewallDefaultPolicyContext):
            raise TypeError("default policy context must use the closed enum.")
        if not isinstance(self.matches, tuple) or not all(
            isinstance(match, FirewallRuleMatch) for match in self.matches
        ):
            raise TypeError("matches must be an immutable typed tuple.")
        if len(self.matches) > MAX_MATCHED_RULE_DIGESTS_PER_LISTENER:
            raise ValueError("matched rules exceed the listener bound.")
        identities = tuple(match.semantic_rule_id for match in self.matches)
        if len(set(identities)) != len(identities):
            raise ValueError("matched rule identities must be unique.")
        if tuple(sorted(self.matches)) != self.matches:
            raise ValueError("matched rules must be deterministically ordered.")
        if not isinstance(self.evidence_basis, tuple) or not self.evidence_basis \
                or not all(isinstance(value, ListenerPolicyBasis)
                           for value in self.evidence_basis) \
                or len(set(self.evidence_basis)) != len(self.evidence_basis):
            raise ValueError("policy evidence basis must be a unique closed tuple.")
        if not isinstance(self.collection_coverage, CoverageState) or not isinstance(
            self.applicability_coverage, CoverageState
        ):
            raise TypeError("policy coverage must use the closed enum.")
        complete_results = {
            FirewallRuleApplicability.MATCHING_ALLOW,
            FirewallRuleApplicability.MATCHING_BLOCK,
            FirewallRuleApplicability.NO_MATCH,
        }
        if (self.applicability in complete_results) != (
            self.applicability_coverage == CoverageState.COMPLETE
        ):
            raise ValueError("applicability result and coverage are inconsistent.")
        if self.applicability == FirewallRuleApplicability.MATCHING_BLOCK and (
            not self.matches or any(
                match.action != FirewallRuleAction.BLOCK
                or match.condition_match != FirewallConditionMatch.MATCH
                or not match.universally_applicable
                for match in self.matches
            )
        ):
            raise ValueError("matching block requires universal explicit block matches.")
        if self.applicability == FirewallRuleApplicability.MATCHING_ALLOW and (
            not self.matches or any(
                match.action != FirewallRuleAction.ALLOW
                or match.condition_match != FirewallConditionMatch.MATCH
                for match in self.matches
            )
        ):
            raise ValueError("matching allow requires explicit allow matches.")
        if self.applicability == FirewallRuleApplicability.NO_MATCH and self.matches:
            raise ValueError("no-match assessment cannot contain matches.")

    def to_report_mapping(self) -> dict[str, object]:
        return {
            "applicability": self.applicability.value,
            "default_policy_context": self.default_policy_context.value,
            "evidence_basis": [value.value for value in self.evidence_basis],
            "matching_rule_digests": [
                match.semantic_rule_id for match in self.matches
                if match.condition_match != FirewallConditionMatch.NO_MATCH
            ],
            "rule_collection_coverage": self.collection_coverage.value,
            "rule_applicability_coverage": self.applicability_coverage.value,
        }


@dataclass(frozen=True, slots=True)
class ListenerPolicyDiagnostic:
    assessment: ListenerPolicyAssessment
    causes: tuple[FirewallPolicyIndeterminateCause, ...]
    unsupported_feature_subtypes: tuple[
        FirewallUnsupportedFeatureDiagnosticSubtype, ...
    ] = ()
    remote_uncertainty_shapes: tuple[FirewallRemoteUncertaintyShape, ...] = ()
    unmodeled_platform_provenance: tuple[
        FirewallUnmodeledPlatformProvenance, ...
    ] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.assessment, ListenerPolicyAssessment):
            raise TypeError("diagnostic assessment must use the typed contract.")
        if not isinstance(self.causes, tuple) or not all(
            isinstance(value, FirewallPolicyIndeterminateCause)
            for value in self.causes
        ):
            raise TypeError("diagnostic causes must use a closed immutable tuple.")
        if len(set(self.causes)) != len(self.causes) or tuple(sorted(
            self.causes, key=lambda value: value.value
        )) != self.causes:
            raise ValueError("diagnostic causes must be unique and ordered.")
        if self.assessment.applicability != FirewallRuleApplicability.INCOMPLETE \
                and (self.causes or self.unsupported_feature_subtypes
                     or self.remote_uncertainty_shapes
                     or self.unmodeled_platform_provenance):
            raise ValueError("only incomplete assessments may carry diagnostics.")
        for name, values, expected in (
            ("unsupported feature subtypes", self.unsupported_feature_subtypes,
             FirewallUnsupportedFeatureDiagnosticSubtype),
            ("remote uncertainty shapes", self.remote_uncertainty_shapes,
             FirewallRemoteUncertaintyShape),
            ("unmodeled platform provenance", self.unmodeled_platform_provenance,
             FirewallUnmodeledPlatformProvenance),
        ):
            if not isinstance(values, tuple) or not all(
                isinstance(value, expected) for value in values
            ):
                raise TypeError(f"diagnostic {name} must use a closed tuple.")
            if len(set(values)) != len(values) or tuple(sorted(
                values, key=lambda value: value.value
            )) != values:
                raise ValueError(f"diagnostic {name} must be unique and ordered.")
        if self.unsupported_feature_subtypes and (
            FirewallPolicyIndeterminateCause.UNSUPPORTED_FEATURE not in self.causes
        ):
            raise ValueError("unsupported subtypes require the closed cause.")
        if self.remote_uncertainty_shapes and (
            FirewallPolicyIndeterminateCause.REMOTE_ADDRESS_UNCERTAINTY
            not in self.causes
        ):
            raise ValueError("remote shapes require the closed cause.")
        if self.unmodeled_platform_provenance and (
            FirewallPolicyIndeterminateCause.UNSUPPORTED_FEATURE not in self.causes
        ):
            raise ValueError("unmodeled provenance requires the closed cause.")


@dataclass(frozen=True, slots=True)
class FirewallPolicyDiagnosticSummary:
    status: FirewallPolicyDiagnosticStatus
    total_listener_assessments: int
    incomplete_listener_assessments: int
    category_counts: tuple[
        tuple[FirewallPolicyIndeterminateCause, int], ...
    ] = ()
    unsupported_feature_subtype_listener_counts: tuple[
        tuple[FirewallUnsupportedFeatureDiagnosticSubtype, int], ...
    ] = ()
    remote_uncertainty_shape_listener_counts: tuple[
        tuple[FirewallRemoteUncertaintyShape, int], ...
    ] = ()
    unmodeled_platform_provenance_listener_counts: tuple[
        tuple[FirewallUnmodeledPlatformProvenance, int], ...
    ] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.status, FirewallPolicyDiagnosticStatus):
            raise TypeError("diagnostic status must use the closed enum.")
        for value in (
            self.total_listener_assessments,
            self.incomplete_listener_assessments,
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("diagnostic listener counts must be non-negative.")
        if self.incomplete_listener_assessments > self.total_listener_assessments:
            raise ValueError("incomplete diagnostics cannot exceed the total.")
        if self.total_listener_assessments > MAX_POLICY_DIAGNOSTIC_LISTENERS:
            raise ValueError("diagnostic listener count exceeds the bound.")
        for name, values, expected in (
            ("category counts", self.category_counts,
             FirewallPolicyIndeterminateCause),
            ("unsupported subtype counts",
             self.unsupported_feature_subtype_listener_counts,
             FirewallUnsupportedFeatureDiagnosticSubtype),
            ("remote shape counts", self.remote_uncertainty_shape_listener_counts,
             FirewallRemoteUncertaintyShape),
            ("unmodeled provenance counts",
             self.unmodeled_platform_provenance_listener_counts,
             FirewallUnmodeledPlatformProvenance),
        ):
            if not isinstance(values, tuple) or not all(
                isinstance(item, tuple) and len(item) == 2
                and isinstance(item[0], expected)
                and isinstance(item[1], int) and not isinstance(item[1], bool)
                and 0 < item[1] <= self.incomplete_listener_assessments
                for item in values
            ):
                raise TypeError(f"diagnostic {name} must be closed and bounded.")
            keys = tuple(item[0] for item in values)
            if len(set(keys)) != len(keys) or tuple(sorted(
                values, key=lambda item: item[0].value
            )) != values:
                raise ValueError(f"diagnostic {name} must be unique and ordered.")
        categories = dict(self.category_counts)
        if self.unsupported_feature_subtype_listener_counts and (
            FirewallPolicyIndeterminateCause.UNSUPPORTED_FEATURE not in categories
        ):
            raise ValueError("unsupported subtype counts require the closed cause.")
        if self.remote_uncertainty_shape_listener_counts and (
            FirewallPolicyIndeterminateCause.REMOTE_ADDRESS_UNCERTAINTY
            not in categories
        ):
            raise ValueError("remote shape counts require the closed cause.")
        if self.unmodeled_platform_provenance_listener_counts and (
            FirewallPolicyIndeterminateCause.UNSUPPORTED_FEATURE not in categories
        ):
            raise ValueError("unmodeled provenance counts require the closed cause.")
        if self.status != FirewallPolicyDiagnosticStatus.COMPLETE and (
            self.total_listener_assessments
            or self.incomplete_listener_assessments
            or self.category_counts
            or self.unsupported_feature_subtype_listener_counts
            or self.remote_uncertainty_shape_listener_counts
            or self.unmodeled_platform_provenance_listener_counts
        ):
            raise ValueError("failed diagnostics cannot carry partial output.")

    def to_safe_mapping(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "total_listener_assessments": self.total_listener_assessments,
            "incomplete_listener_assessments": (
                self.incomplete_listener_assessments
            ),
            "category_counts": {
                category.value: count for category, count in self.category_counts
            },
            "unsupported_feature_subtype_listener_counts": {
                subtype.value: count
                for subtype, count
                in self.unsupported_feature_subtype_listener_counts
            },
            "remote_uncertainty_shape_listener_counts": {
                shape.value: count
                for shape, count in self.remote_uncertainty_shape_listener_counts
            },
            "unmodeled_platform_provenance_listener_counts": {
                origin.value: count
                for origin, count
                in self.unmodeled_platform_provenance_listener_counts
            },
        }


def semantic_firewall_rule_id(
    *, technology: FirewallPlatformTechnology, enabled: FirewallRuleEnabledState,
    direction: FirewallRuleDirection, action: FirewallRuleAction,
    profiles: tuple[FirewallProfile, ...], protocol: NetworkProtocol | None,
    local_ports: tuple[FirewallPortRange, ...],
    local_addresses: tuple[FirewallAddressCondition, ...],
    remote_addresses: tuple[FirewallAddressCondition, ...],
    application: FirewallApplicationCondition,
    interface: FirewallInterfaceCondition,
    edge_traversal: bool | None,
    unsupported_features: tuple[FirewallRuleUnsupportedFeature, ...] = (),
) -> str:
    """Digest normalized closed rule fields with an explicit domain separator."""

    payload = {
        "technology": technology.value, "enabled": enabled.value,
        "direction": direction.value, "action": action.value,
        "profiles": [value.value for value in profiles],
        "protocol": protocol.value if protocol is not None else None,
        "local_ports": [[value.start, value.end] for value in local_ports],
        "local_addresses": [_address_identity(value) for value in local_addresses],
        "remote_addresses": [_address_identity(value) for value in remote_addresses],
        "application": [application.kind.value, application.value],
        "interface": [interface.kind.value, interface.value],
        "edge_traversal": edge_traversal,
        "unsupported_features": [value.value for value in unsupported_features],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(b"cyberwatchtower:firewall-rule:v1\0" + encoded).hexdigest()


def _address_identity(condition: FirewallAddressCondition) -> list[object]:
    if condition.kind in {
        AddressConditionKind.IPV4_RANGE, AddressConditionKind.IPV6_RANGE,
    }:
        assert isinstance(condition.value, (
            FirewallIPv4AddressRange, FirewallIPv6AddressRange,
        ))
        return [condition.kind.value, str(condition.value.start),
                str(condition.value.end)]
    return [condition.kind.value, condition.value]


def _address_matches(
    condition: FirewallAddressCondition, address: str
) -> FirewallConditionMatch:
    parsed = ipaddress.ip_address(address.split("%", 1)[0])
    if condition.kind == AddressConditionKind.ANY:
        return FirewallConditionMatch.MATCH
    if condition.kind == AddressConditionKind.EXACT:
        matched = parsed == ipaddress.ip_address(condition.value)
        return (FirewallConditionMatch.MATCH if matched
                else FirewallConditionMatch.NO_MATCH)
    if condition.kind == AddressConditionKind.CIDR:
        matched = parsed in ipaddress.ip_network(condition.value, strict=False)
        return (FirewallConditionMatch.MATCH if matched
                else FirewallConditionMatch.NO_MATCH)
    if condition.kind in {
        AddressConditionKind.IPV4_RANGE, AddressConditionKind.IPV6_RANGE,
    }:
        return FirewallConditionMatch.INDETERMINATE
    scope = FirewallSpecialAddressScope(condition.value)
    matched = parsed.is_loopback if scope == FirewallSpecialAddressScope.LOOPBACK else False
    return (FirewallConditionMatch.MATCH if matched
            else FirewallConditionMatch.NO_MATCH)


def _remote_uncertainty_shapes(
    conditions: tuple[FirewallAddressCondition, ...],
) -> tuple[FirewallRemoteUncertaintyShape, ...]:
    non_any = tuple(
        condition for condition in conditions
        if condition.kind != AddressConditionKind.ANY
    )
    has_local_subnet = any(
        condition.kind == AddressConditionKind.SUPPORTED_SPECIAL_SCOPE
        and condition.value == FirewallSpecialAddressScope.LOCAL_SUBNET.value
        for condition in non_any
    )
    has_explicit = any(condition.kind in {
        AddressConditionKind.EXACT,
        AddressConditionKind.CIDR,
        AddressConditionKind.IPV4_RANGE,
        AddressConditionKind.IPV6_RANGE,
    } for condition in non_any)
    if has_local_subnet and has_explicit:
        return (FirewallRemoteUncertaintyShape.MIXED_SUPPORTED_RESTRICTION,)
    if has_local_subnet:
        return (FirewallRemoteUncertaintyShape.LOCAL_SUBNET,)
    if has_explicit:
        return (FirewallRemoteUncertaintyShape.EXPLICIT_RESTRICTION,)
    return (FirewallRemoteUncertaintyShape.OTHER_CLOSED_RESTRICTION,)


def _rule_match_diagnostic_details(
    rule: FirewallRuleObservation, subject: ListenerPolicySubject
) -> tuple[
    FirewallRuleMatch | None,
    tuple[FirewallPolicyIndeterminateCause, ...],
    tuple[FirewallUnsupportedFeatureDiagnosticSubtype, ...],
    tuple[FirewallRemoteUncertaintyShape, ...],
    tuple[FirewallUnmodeledPlatformProvenance, ...],
]:
    if rule.enabled == FirewallRuleEnabledState.DISABLED \
            or rule.direction != FirewallRuleDirection.INBOUND:
        return None, (), (), (), ()
    causes: set[FirewallPolicyIndeterminateCause] = set()
    if rule.enabled == FirewallRuleEnabledState.UNKNOWN:
        causes.add(FirewallPolicyIndeterminateCause.UNKNOWN_ENABLEMENT_OR_STATE)
    if rule.unsupported_features:
        causes.add(FirewallPolicyIndeterminateCause.UNSUPPORTED_FEATURE)
    if rule.profiles:
        if not subject.profiles:
            causes.add(FirewallPolicyIndeterminateCause.PROFILE_UNCERTAINTY)
        elif set(rule.profiles).isdisjoint(subject.profiles):
            return None, (), (), (), ()
    if rule.protocol is not None and rule.protocol != subject.protocol:
        return None, (), (), (), ()
    if rule.local_ports and not any(
        value.start <= subject.local_port <= value.end for value in rule.local_ports
    ):
        return None, (), (), (), ()
    if rule.local_addresses:
        address_matches = tuple(
            _address_matches(value, subject.local_address)
            for value in rule.local_addresses
        )
        if FirewallConditionMatch.MATCH not in address_matches:
            if FirewallConditionMatch.INDETERMINATE in address_matches:
                causes.add(
                    FirewallPolicyIndeterminateCause.
                    TYPED_RANGE_OR_PARSE_UNCERTAINTY
                )
            else:
                return None, (), (), (), ()
    application = rule.application
    if application.kind == ApplicationConditionKind.APPLICATION_DIGEST:
        if subject.application_digest is None:
            causes.add(
                FirewallPolicyIndeterminateCause.MISSING_APPLICATION_IDENTITY
            )
        elif application.value != subject.application_digest:
            return None, (), (), (), ()
    elif application.kind == ApplicationConditionKind.SERVICE_IDENTITY:
        if subject.service_identity is None:
            causes.add(FirewallPolicyIndeterminateCause.MISSING_SERVICE_IDENTITY)
        elif application.value.casefold() != subject.service_identity.casefold():
            return None, (), (), (), ()
    interface = rule.interface
    if interface.kind == InterfaceConditionKind.INTERFACE_DIGEST:
        if subject.interface_digest is None:
            causes.add(FirewallPolicyIndeterminateCause.INTERFACE_UNCERTAINTY)
        elif interface.value != subject.interface_digest:
            return None, (), (), (), ()
    elif interface.kind != InterfaceConditionKind.ANY:
        if subject.interface is None:
            causes.add(FirewallPolicyIndeterminateCause.INTERFACE_UNCERTAINTY)
        elif interface.kind != subject.interface:
            return None, (), (), (), ()
    remote_is_any = not rule.remote_addresses or all(
        value.kind == AddressConditionKind.ANY for value in rule.remote_addresses
    )
    if not remote_is_any:
        causes.add(FirewallPolicyIndeterminateCause.REMOTE_ADDRESS_UNCERTAINTY)
    indeterminate = bool(causes)
    condition = (
        FirewallConditionMatch.INDETERMINATE
        if indeterminate else FirewallConditionMatch.MATCH
    )
    match = FirewallRuleMatch(
        rule.semantic_rule_id, rule.action, condition,
        condition == FirewallConditionMatch.MATCH and remote_is_any,
    )
    unsupported_subtypes = tuple(sorted((
        FirewallUnsupportedFeatureDiagnosticSubtype(feature.value)
        for feature in rule.unsupported_features
    ), key=lambda value: value.value))
    remote_shapes = (
        _remote_uncertainty_shapes(rule.remote_addresses)
        if not remote_is_any else ()
    )
    return (
        match,
        tuple(sorted(causes, key=lambda value: value.value)),
        unsupported_subtypes,
        remote_shapes,
        rule.unmodeled_platform_provenance,
    )


def _rule_match_with_diagnostics(
    rule: FirewallRuleObservation, subject: ListenerPolicySubject
) -> tuple[FirewallRuleMatch | None, tuple[FirewallPolicyIndeterminateCause, ...]]:
    match, causes, _, _, _ = _rule_match_diagnostic_details(rule, subject)
    return match, causes


def _rule_match(
    rule: FirewallRuleObservation, subject: ListenerPolicySubject
) -> FirewallRuleMatch | None:
    match, _ = _rule_match_with_diagnostics(rule, subject)
    return match


def evaluate_listener_policy(
    subject: ListenerPolicySubject,
    rules: tuple[FirewallRuleObservation, ...],
    collection_coverage: CoverageState,
    default_policy_context: FirewallDefaultPolicyContext = (
        FirewallDefaultPolicyContext.UNKNOWN
    ),
) -> ListenerPolicyAssessment:
    """Evaluate a validated rule snapshot without platform-specific precedence."""

    if not isinstance(subject, ListenerPolicySubject):
        raise TypeError("policy subject must use the typed contract.")
    if not isinstance(rules, tuple) or not all(
        isinstance(rule, FirewallRuleObservation) for rule in rules
    ):
        raise TypeError("rules must be an immutable typed tuple.")
    if len(rules) > MAX_FIREWALL_RULES:
        raise ValueError("rule snapshot exceeds the supported bound.")
    if not isinstance(collection_coverage, CoverageState):
        raise TypeError("collection coverage must use the closed enum.")
    if not isinstance(default_policy_context, FirewallDefaultPolicyContext):
        raise TypeError("default policy context must use the closed enum.")
    identities = tuple(rule.semantic_rule_id for rule in rules)
    if len(set(identities)) != len(identities):
        # Identical normalized rules may be removed by a collector only after its
        # complete validation; the neutral evaluator rejects ambiguous snapshots.
        raise ValueError("rule snapshot contains duplicate semantic identities.")
    if collection_coverage == CoverageState.UNKNOWN:
        return ListenerPolicyAssessment(
            FirewallRuleApplicability.UNSUPPORTED, default_policy_context, (),
            (ListenerPolicyBasis.POLICY_TECHNOLOGY_UNSUPPORTED,),
            collection_coverage, CoverageState.UNKNOWN,
        )
    if collection_coverage != CoverageState.COMPLETE:
        return ListenerPolicyAssessment(
            FirewallRuleApplicability.INCOMPLETE, default_policy_context, (),
            (ListenerPolicyBasis.POLICY_EVALUATION_INCOMPLETE,),
            collection_coverage, CoverageState.INCOMPLETE,
        )
    matches = tuple(sorted(filter(None, (
        _rule_match(rule, subject) for rule in rules
    ))))
    if len(matches) > MAX_MATCHED_RULE_DIGESTS_PER_LISTENER:
        return ListenerPolicyAssessment(
            FirewallRuleApplicability.INCOMPLETE, default_policy_context, (),
            (ListenerPolicyBasis.POLICY_EVALUATION_INCOMPLETE,),
            collection_coverage, CoverageState.INCOMPLETE,
        )
    if any(match.condition_match == FirewallConditionMatch.INDETERMINATE
           for match in matches):
        return ListenerPolicyAssessment(
            FirewallRuleApplicability.INCOMPLETE, default_policy_context, matches,
            (ListenerPolicyBasis.POLICY_EVALUATION_INCOMPLETE,),
            collection_coverage, CoverageState.INCOMPLETE,
        )
    actions = {match.action for match in matches}
    if actions == {FirewallRuleAction.ALLOW, FirewallRuleAction.BLOCK}:
        applicability = FirewallRuleApplicability.CONFLICTING
        basis = (ListenerPolicyBasis.POLICY_CONFLICT,)
        applicability_coverage = CoverageState.INCOMPLETE
    elif actions == {FirewallRuleAction.BLOCK} and all(
        match.universally_applicable for match in matches
    ):
        applicability = FirewallRuleApplicability.MATCHING_BLOCK
        basis = (ListenerPolicyBasis.EXPLICIT_UNIVERSAL_BLOCK,)
        applicability_coverage = CoverageState.COMPLETE
    elif actions == {FirewallRuleAction.ALLOW}:
        applicability = FirewallRuleApplicability.MATCHING_ALLOW
        basis = (ListenerPolicyBasis.EXPLICIT_ALLOW,)
        applicability_coverage = CoverageState.COMPLETE
    elif not actions:
        applicability = FirewallRuleApplicability.NO_MATCH
        basis = (
            ListenerPolicyBasis.NO_APPLICABLE_RULE,
            ListenerPolicyBasis.DEFAULT_POLICY_CONTEXT,
        )
        applicability_coverage = CoverageState.COMPLETE
    else:
        applicability = FirewallRuleApplicability.AMBIGUOUS
        basis = (ListenerPolicyBasis.POLICY_EVALUATION_INCOMPLETE,)
        applicability_coverage = CoverageState.INCOMPLETE
    return ListenerPolicyAssessment(
        applicability, default_policy_context, matches, basis, collection_coverage,
        applicability_coverage,
    )


def diagnose_listener_policy(
    subject: ListenerPolicySubject,
    rules: tuple[FirewallRuleObservation, ...],
    collection_coverage: CoverageState,
    default_policy_context: FirewallDefaultPolicyContext = (
        FirewallDefaultPolicyContext.UNKNOWN
    ),
) -> ListenerPolicyDiagnostic:
    """Return the frozen assessment plus privacy-safe indeterminate causes."""

    assessment = evaluate_listener_policy(
        subject, rules, collection_coverage, default_policy_context
    )
    if assessment.applicability != FirewallRuleApplicability.INCOMPLETE \
            or collection_coverage != CoverageState.COMPLETE:
        return ListenerPolicyDiagnostic(assessment, ())
    causes: set[FirewallPolicyIndeterminateCause] = set()
    unsupported_subtypes: set[FirewallUnsupportedFeatureDiagnosticSubtype] = set()
    remote_shapes: set[FirewallRemoteUncertaintyShape] = set()
    provenance: set[FirewallUnmodeledPlatformProvenance] = set()
    for rule in rules:
        match, match_causes, match_subtypes, match_remote_shapes, match_provenance = (
            _rule_match_diagnostic_details(rule, subject)
        )
        if match is not None \
                and match.condition_match == FirewallConditionMatch.INDETERMINATE:
            causes.update(match_causes)
            unsupported_subtypes.update(match_subtypes)
            remote_shapes.update(match_remote_shapes)
            provenance.update(match_provenance)
    if not causes and any(
        match.condition_match == FirewallConditionMatch.INDETERMINATE
        for match in assessment.matches
    ):
        causes.add(FirewallPolicyIndeterminateCause.OTHER_CLOSED_INDETERMINATE)
    return ListenerPolicyDiagnostic(
        assessment,
        tuple(sorted(causes, key=lambda value: value.value)),
        tuple(sorted(unsupported_subtypes, key=lambda value: value.value)),
        tuple(sorted(remote_shapes, key=lambda value: value.value)),
        tuple(sorted(provenance, key=lambda value: value.value)),
    )


def aggregate_listener_policy_diagnostics(
    diagnostics: tuple[ListenerPolicyDiagnostic, ...],
) -> FirewallPolicyDiagnosticSummary:
    """Aggregate closed per-listener causes without retaining identities."""

    if not isinstance(diagnostics, tuple) or not all(
        isinstance(value, ListenerPolicyDiagnostic) for value in diagnostics
    ):
        return FirewallPolicyDiagnosticSummary(
            FirewallPolicyDiagnosticStatus.INVALID_RESULT, 0, 0
        )
    if len(diagnostics) > MAX_POLICY_DIAGNOSTIC_LISTENERS:
        return FirewallPolicyDiagnosticSummary(
            FirewallPolicyDiagnosticStatus.LIMIT_EXCEEDED, 0, 0
        )
    incomplete = tuple(
        value for value in diagnostics
        if value.assessment.applicability == FirewallRuleApplicability.INCOMPLETE
    )
    counts = tuple(sorted((
        (category, sum(category in value.causes for value in incomplete))
        for category in FirewallPolicyIndeterminateCause
        if any(category in value.causes for value in incomplete)
    ), key=lambda item: item[0].value))
    unsupported_counts = tuple(sorted((
        (subtype, sum(
            subtype in value.unsupported_feature_subtypes for value in incomplete
        ))
        for subtype in FirewallUnsupportedFeatureDiagnosticSubtype
        if any(
            subtype in value.unsupported_feature_subtypes for value in incomplete
        )
    ), key=lambda item: item[0].value))
    remote_counts = tuple(sorted((
        (shape, sum(
            shape in value.remote_uncertainty_shapes for value in incomplete
        ))
        for shape in FirewallRemoteUncertaintyShape
        if any(shape in value.remote_uncertainty_shapes for value in incomplete)
    ), key=lambda item: item[0].value))
    provenance_counts = tuple(sorted((
        (origin, sum(
            origin in value.unmodeled_platform_provenance for value in incomplete
        ))
        for origin in FirewallUnmodeledPlatformProvenance
        if any(
            origin in value.unmodeled_platform_provenance for value in incomplete
        )
    ), key=lambda item: item[0].value))
    return FirewallPolicyDiagnosticSummary(
        FirewallPolicyDiagnosticStatus.COMPLETE,
        len(diagnostics),
        len(incomplete),
        counts,
        unsupported_counts,
        remote_counts,
        provenance_counts,
    )


def normalize_firewall_rules(
    rules: tuple[FirewallRuleObservation, ...],
) -> tuple[FirewallRuleObservation, ...]:
    """Validate every rule before deterministically removing exact duplicates."""

    if not isinstance(rules, tuple) or not all(
        isinstance(rule, FirewallRuleObservation) for rule in rules
    ):
        raise TypeError("rules must be an immutable typed tuple.")
    if len(rules) > MAX_FIREWALL_RULES:
        raise ValueError("rule snapshot exceeds the supported bound.")
    by_id: dict[str, FirewallRuleObservation] = {}
    for rule in rules:
        existing = by_id.get(rule.semantic_rule_id)
        if existing is not None and existing != rule:
            raise ValueError("semantic rule identity collision.")
        by_id[rule.semantic_rule_id] = rule
    return tuple(by_id[key] for key in sorted(by_id))


def firewall_rule_applicability_coverage(
    collection_coverage: CoverageState,
    assessments: tuple[ListenerPolicyAssessment, ...],
) -> CoverageState:
    """Derive rule-applicability coverage without conflating socket coverage."""

    if not isinstance(collection_coverage, CoverageState):
        raise TypeError("collection coverage must use the closed enum.")
    if not isinstance(assessments, tuple) or not all(
        isinstance(value, ListenerPolicyAssessment) for value in assessments
    ):
        raise TypeError("policy assessments must use an immutable typed tuple.")
    if collection_coverage == CoverageState.UNKNOWN:
        return CoverageState.UNKNOWN
    if collection_coverage != CoverageState.COMPLETE:
        return CoverageState.INCOMPLETE
    return (
        CoverageState.COMPLETE
        if all(value.applicability_coverage == CoverageState.COMPLETE
               for value in assessments)
        else CoverageState.INCOMPLETE
    )
