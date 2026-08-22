"""Closed platform-neutral contracts for host-firewall rule applicability."""

from __future__ import annotations

from dataclasses import dataclass
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


class AddressConditionKind(str, Enum):
    ANY = "ANY"
    EXACT = "EXACT"
    CIDR = "CIDR"
    SUPPORTED_SPECIAL_SCOPE = "SUPPORTED_SPECIAL_SCOPE"


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
class FirewallAddressCondition:
    kind: AddressConditionKind
    value: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, AddressConditionKind):
            raise TypeError("address condition kind must use the closed enum.")
        if self.kind == AddressConditionKind.ANY:
            if self.value is not None:
                raise ValueError("ANY address condition cannot carry a value.")
            return
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
        "local_addresses": [[value.kind.value, value.value] for value in local_addresses],
        "remote_addresses": [[value.kind.value, value.value] for value in remote_addresses],
        "application": [application.kind.value, application.value],
        "interface": [interface.kind.value, interface.value],
        "edge_traversal": edge_traversal,
        "unsupported_features": [value.value for value in unsupported_features],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(b"cyberwatchtower:firewall-rule:v1\0" + encoded).hexdigest()


def _address_matches(condition: FirewallAddressCondition, address: str) -> bool:
    parsed = ipaddress.ip_address(address.split("%", 1)[0])
    if condition.kind == AddressConditionKind.ANY:
        return True
    if condition.kind == AddressConditionKind.EXACT:
        return parsed == ipaddress.ip_address(condition.value)
    if condition.kind == AddressConditionKind.CIDR:
        return parsed in ipaddress.ip_network(condition.value, strict=False)
    scope = FirewallSpecialAddressScope(condition.value)
    return parsed.is_loopback if scope == FirewallSpecialAddressScope.LOOPBACK else False


def _rule_match(
    rule: FirewallRuleObservation, subject: ListenerPolicySubject
) -> FirewallRuleMatch | None:
    if rule.enabled == FirewallRuleEnabledState.DISABLED \
            or rule.direction != FirewallRuleDirection.INBOUND:
        return None
    indeterminate = rule.enabled == FirewallRuleEnabledState.UNKNOWN \
        or bool(rule.unsupported_features)
    if rule.profiles:
        if not subject.profiles:
            indeterminate = True
        elif set(rule.profiles).isdisjoint(subject.profiles):
            return None
    if rule.protocol is not None and rule.protocol != subject.protocol:
        return None
    if rule.local_ports and not any(
        value.start <= subject.local_port <= value.end for value in rule.local_ports
    ):
        return None
    if rule.local_addresses and not any(
        _address_matches(value, subject.local_address) for value in rule.local_addresses
    ):
        return None
    application = rule.application
    if application.kind == ApplicationConditionKind.APPLICATION_DIGEST:
        if subject.application_digest is None:
            indeterminate = True
        elif application.value != subject.application_digest:
            return None
    elif application.kind == ApplicationConditionKind.SERVICE_IDENTITY:
        if subject.service_identity is None:
            indeterminate = True
        elif application.value.casefold() != subject.service_identity.casefold():
            return None
    interface = rule.interface
    if interface.kind == InterfaceConditionKind.INTERFACE_DIGEST:
        if subject.interface_digest is None:
            indeterminate = True
        elif interface.value != subject.interface_digest:
            return None
    elif interface.kind != InterfaceConditionKind.ANY:
        if subject.interface is None:
            indeterminate = True
        elif interface.kind != subject.interface:
            return None
    remote_is_any = not rule.remote_addresses or all(
        value.kind == AddressConditionKind.ANY for value in rule.remote_addresses
    )
    if not remote_is_any:
        indeterminate = True
    condition = (
        FirewallConditionMatch.INDETERMINATE
        if indeterminate else FirewallConditionMatch.MATCH
    )
    return FirewallRuleMatch(
        rule.semantic_rule_id, rule.action, condition,
        condition == FirewallConditionMatch.MATCH and remote_is_any,
    )


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
