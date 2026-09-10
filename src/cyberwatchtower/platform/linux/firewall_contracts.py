"""Portable contracts for a bounded ordered Linux firewall-policy view."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
import hashlib

from cyberwatchtower.firewall_policy import (
    FirewallAddressCondition,
    FirewallInterfaceCondition,
    FirewallPortRange,
)
from cyberwatchtower.platform.models import NetworkProtocol


MAX_LINUX_FIREWALL_TABLES = 256
MAX_LINUX_FIREWALL_CHAINS = 8_192
MAX_LINUX_FIREWALL_RULES = 8_192
MAX_LINUX_EXPRESSIONS_PER_RULE = 64
MAX_LINUX_INLINE_SET_VALUES = 256
MAX_LINUX_CHAIN_DEPTH = 64
MAX_LINUX_TRAVERSAL_STEPS = 65_536
MAX_LINUX_NORMALIZED_TOKEN_LENGTH = 256


class LinuxFirewallPolicyAuthority(str, Enum):
    CURRENT_NETWORK_NAMESPACE_POLICY_VIEW = "CURRENT_NETWORK_NAMESPACE_POLICY_VIEW"


class LinuxNamespaceAlignment(str, Enum):
    SAME_CURRENT_NAMESPACE = "SAME_CURRENT_NAMESPACE"
    UNKNOWN = "UNKNOWN"


class LinuxFirewallFamily(str, Enum):
    INET = "inet"
    IPV4 = "ip"
    IPV6 = "ip6"
    ARP = "arp"
    BRIDGE = "bridge"
    NETDEV = "netdev"
    UNKNOWN = "unknown"


class LinuxFirewallHook(str, Enum):
    INPUT = "input"
    FORWARD = "forward"
    OUTPUT = "output"
    PREROUTING = "prerouting"
    POSTROUTING = "postrouting"
    INGRESS = "ingress"


class LinuxChainKind(str, Enum):
    BASE = "BASE"
    REGULAR = "REGULAR"


class LinuxChainPolicy(str, Enum):
    ACCEPT = "ACCEPT"
    DROP = "DROP"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


class LinuxVerdict(str, Enum):
    CONTINUE = "CONTINUE"
    ACCEPT = "ACCEPT"
    DROP = "DROP"
    REJECT = "REJECT"
    JUMP = "JUMP"
    GOTO = "GOTO"
    RETURN = "RETURN"


class LinuxCtState(str, Enum):
    ANY = "ANY"
    NEW = "NEW"
    ESTABLISHED = "ESTABLISHED"
    RELATED = "RELATED"
    INVALID = "INVALID"
    UNTRACKED = "UNTRACKED"


class LinuxPredicateKind(str, Enum):
    FAMILY = "FAMILY"
    PROTOCOL = "PROTOCOL"
    DESTINATION_PORT = "DESTINATION_PORT"
    SOURCE_ADDRESS = "SOURCE_ADDRESS"
    DESTINATION_ADDRESS = "DESTINATION_ADDRESS"
    INBOUND_INTERFACE = "INBOUND_INTERFACE"
    CT_STATE = "CT_STATE"
    UNSUPPORTED = "UNSUPPORTED"


class LinuxFirewallUnsupportedFeature(str, Enum):
    UNSUPPORTED_FAMILY = "UNSUPPORTED_FAMILY"
    UNSUPPORTED_HOOK = "UNSUPPORTED_HOOK"
    UNSUPPORTED_EXPRESSION = "UNSUPPORTED_EXPRESSION"
    UNRESOLVED_NAMED_SET = "UNRESOLVED_NAMED_SET"
    DYNAMIC_SET = "DYNAMIC_SET"
    MAP = "MAP"
    VERDICT_MAP = "VERDICT_MAP"
    PACKET_MARK_OR_META_DEPENDENCY = "PACKET_MARK_OR_META_DEPENDENCY"
    CGROUP = "CGROUP"
    UID_GID_OR_OWNER = "UID_GID_OR_OWNER"
    ROUTING_DEPENDENCY = "ROUTING_DEPENDENCY"
    NAMESPACE_UNCERTAINTY = "NAMESPACE_UNCERTAINTY"
    UNSUPPORTED_CHAIN_FLOW = "UNSUPPORTED_CHAIN_FLOW"
    AMBIGUOUS_PRIORITY_OR_ORDER = "AMBIGUOUS_PRIORITY_OR_ORDER"
    UNSUPPORTED_PROTOCOL = "UNSUPPORTED_PROTOCOL"
    UNSUPPORTED_ADDRESS_EXPRESSION = "UNSUPPORTED_ADDRESS_EXPRESSION"
    UNSUPPORTED_INTERFACE_EXPRESSION = "UNSUPPORTED_INTERFACE_EXPRESSION"
    UNSUPPORTED_CT_EXPRESSION = "UNSUPPORTED_CT_EXPRESSION"


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(f"{field} must be a SHA-256 digest.")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(f"{field} must be hexadecimal.") from exc
    return value.casefold()


def _scoped_identity(domain: str, *parts: str) -> str:
    material = bytearray(domain.encode("ascii"))
    for part in parts:
        encoded = part.encode("utf-8")
        material.extend(len(encoded).to_bytes(4, "big"))
        material.extend(encoded)
    return hashlib.sha256(material).hexdigest()


def linux_firewall_table_identity(
    family: LinuxFirewallFamily, structural_identity: str,
) -> str:
    if not isinstance(family, LinuxFirewallFamily):
        raise TypeError("table identity family must use the closed enum.")
    return _scoped_identity(
        "cyberwatchtower:linux-firewall-table:v1",
        family.value,
        _digest(structural_identity, "table structural identity"),
    )


def linux_firewall_chain_identity(
    parent_table_id: str, structural_identity: str,
) -> str:
    return _scoped_identity(
        "cyberwatchtower:linux-firewall-chain:v1",
        _digest(parent_table_id, "parent table id"),
        _digest(structural_identity, "chain structural identity"),
    )


def linux_firewall_rule_identity(
    parent_chain_id: str, structural_identity: str,
) -> str:
    return _scoped_identity(
        "cyberwatchtower:linux-firewall-rule:v1",
        _digest(parent_chain_id, "parent chain id"),
        _digest(structural_identity, "rule structural identity"),
    )


def _closed_tuple(values: tuple, expected: type, field: str, maximum: int) -> None:
    if not isinstance(values, tuple) or not all(isinstance(v, expected) for v in values):
        raise TypeError(f"{field} must be an immutable closed tuple.")
    if len(values) > maximum:
        raise ValueError(f"{field} exceeds its bound.")
    if len(set(values)) != len(values):
        raise ValueError(f"{field} cannot contain duplicates.")


@dataclass(frozen=True, slots=True)
class LinuxFirewallPredicate:
    kind: LinuxPredicateKind
    value: object

    def __post_init__(self) -> None:
        if not isinstance(self.kind, LinuxPredicateKind):
            raise TypeError("predicate kind must use the closed enum.")
        expected = {
            LinuxPredicateKind.FAMILY: LinuxFirewallFamily,
            LinuxPredicateKind.PROTOCOL: NetworkProtocol,
            LinuxPredicateKind.DESTINATION_PORT: tuple,
            LinuxPredicateKind.SOURCE_ADDRESS: tuple,
            LinuxPredicateKind.DESTINATION_ADDRESS: tuple,
            LinuxPredicateKind.INBOUND_INTERFACE: FirewallInterfaceCondition,
            LinuxPredicateKind.CT_STATE: LinuxCtState,
            LinuxPredicateKind.UNSUPPORTED: LinuxFirewallUnsupportedFeature,
        }[self.kind]
        if not isinstance(self.value, expected):
            raise TypeError("predicate value does not match its closed kind.")
        if self.kind == LinuxPredicateKind.DESTINATION_PORT:
            _closed_tuple(self.value, FirewallPortRange, "port values", MAX_LINUX_INLINE_SET_VALUES)
            if not self.value:
                raise ValueError("port predicates require at least one value.")
        elif self.kind in {LinuxPredicateKind.SOURCE_ADDRESS, LinuxPredicateKind.DESTINATION_ADDRESS}:
            _closed_tuple(self.value, FirewallAddressCondition, "address values", MAX_LINUX_INLINE_SET_VALUES)
            if not self.value:
                raise ValueError("address predicates require at least one value.")


@dataclass(frozen=True, slots=True)
class LinuxFirewallRule:
    semantic_rule_id: str
    expressions: tuple[LinuxFirewallPredicate, ...]
    verdict: LinuxVerdict
    target_chain_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "semantic_rule_id", _digest(self.semantic_rule_id, "rule id"))
        _closed_tuple(self.expressions, LinuxFirewallPredicate, "rule expressions", MAX_LINUX_EXPRESSIONS_PER_RULE)
        if not isinstance(self.verdict, LinuxVerdict):
            raise TypeError("rule verdict must use the closed enum.")
        needs_target = self.verdict in {LinuxVerdict.JUMP, LinuxVerdict.GOTO}
        if needs_target != (self.target_chain_id is not None):
            raise ValueError("only jump/goto verdicts require a target chain.")
        if self.target_chain_id is not None:
            object.__setattr__(self, "target_chain_id", _digest(self.target_chain_id, "target chain id"))


@dataclass(frozen=True, slots=True)
class LinuxFirewallChain:
    semantic_chain_id: str
    kind: LinuxChainKind
    rules: tuple[LinuxFirewallRule, ...]
    hook: LinuxFirewallHook | None = None
    priority: int | None = None
    policy: LinuxChainPolicy = LinuxChainPolicy.NONE

    def __post_init__(self) -> None:
        object.__setattr__(self, "semantic_chain_id", _digest(self.semantic_chain_id, "chain id"))
        if not isinstance(self.kind, LinuxChainKind) or not isinstance(self.policy, LinuxChainPolicy):
            raise TypeError("chain kind and policy must use closed enums.")
        _closed_tuple(self.rules, LinuxFirewallRule, "chain rules", MAX_LINUX_FIREWALL_RULES)
        identities = tuple(rule.semantic_rule_id for rule in self.rules)
        if len(set(identities)) != len(identities):
            raise ValueError("chain rule identities must be unique.")
        if self.kind == LinuxChainKind.BASE:
            if not isinstance(self.hook, LinuxFirewallHook):
                raise ValueError("base chains require a hook.")
            if isinstance(self.priority, bool) or not isinstance(self.priority, int):
                raise ValueError("base chains require an integer priority.")
            if self.policy == LinuxChainPolicy.NONE:
                raise ValueError("base chains require an explicit or unknown policy.")
        elif self.hook is not None or self.priority is not None or self.policy != LinuxChainPolicy.NONE:
            raise ValueError("regular chains cannot carry base-chain context.")


@dataclass(frozen=True, slots=True)
class LinuxFirewallTable:
    semantic_table_id: str
    family: LinuxFirewallFamily
    chains: tuple[LinuxFirewallChain, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.family, LinuxFirewallFamily):
            raise TypeError("table family must use the closed enum.")
        _closed_tuple(self.chains, LinuxFirewallChain, "table chains", MAX_LINUX_FIREWALL_CHAINS)
        table_id = linux_firewall_table_identity(
            self.family, _digest(self.semantic_table_id, "table structural identity")
        )
        chain_ids = {
            chain.semantic_chain_id: linux_firewall_chain_identity(
                table_id, chain.semantic_chain_id
            )
            for chain in self.chains
        }
        normalized_chains = []
        for chain in self.chains:
            chain_id = chain_ids[chain.semantic_chain_id]
            normalized_rules = tuple(
                replace(
                    rule,
                    semantic_rule_id=linux_firewall_rule_identity(
                        chain_id, rule.semantic_rule_id
                    ),
                    target_chain_id=(
                        chain_ids.get(rule.target_chain_id, rule.target_chain_id)
                        if rule.target_chain_id is not None else None
                    ),
                )
                for rule in chain.rules
            )
            normalized_chains.append(replace(
                chain, semantic_chain_id=chain_id, rules=normalized_rules
            ))
        object.__setattr__(self, "semantic_table_id", table_id)
        object.__setattr__(self, "chains", tuple(normalized_chains))
        identities = tuple(chain.semantic_chain_id for chain in normalized_chains)
        if len(set(identities)) != len(identities):
            raise ValueError("table chain identities must be unique.")


@dataclass(frozen=True, slots=True)
class LinuxFirewallPolicySnapshot:
    authority: LinuxFirewallPolicyAuthority
    namespace_alignment: LinuxNamespaceAlignment
    tables: tuple[LinuxFirewallTable, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.authority, LinuxFirewallPolicyAuthority):
            raise TypeError("policy authority must use the closed enum.")
        if not isinstance(self.namespace_alignment, LinuxNamespaceAlignment):
            raise TypeError("namespace alignment must use the closed enum.")
        _closed_tuple(self.tables, LinuxFirewallTable, "policy tables", MAX_LINUX_FIREWALL_TABLES)
        table_ids = tuple(table.semantic_table_id for table in self.tables)
        if len(set(table_ids)) != len(table_ids):
            raise ValueError("policy table identities must be unique.")
        chains = [chain for table in self.tables for chain in table.chains]
        if len(chains) > MAX_LINUX_FIREWALL_CHAINS:
            raise ValueError("policy snapshot exceeds the chain bound.")
        rules = [rule for chain in chains for rule in chain.rules]
        if len(rules) > MAX_LINUX_FIREWALL_RULES:
            raise ValueError("policy snapshot exceeds the rule bound.")
        chain_ids = [chain.semantic_chain_id for chain in chains]
        if len(set(chain_ids)) != len(chain_ids):
            raise ValueError("policy chain identities must be globally unique.")
        rule_ids = [rule.semantic_rule_id for rule in rules]
        if len(set(rule_ids)) != len(rule_ids):
            raise ValueError("policy rule identities must be globally unique.")
