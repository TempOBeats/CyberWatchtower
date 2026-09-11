"""Pure bounded parser from nftables JSON text to frozen Linux L2 contracts."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from typing import Any

from cyberwatchtower.firewall_policy import (
    AddressConditionKind,
    FirewallAddressCondition,
    FirewallInterfaceCondition,
    FirewallPortRange,
    InterfaceConditionKind,
)
from cyberwatchtower.platform.models import NetworkProtocol

from .firewall_contracts import (
    LinuxChainKind,
    LinuxChainPolicy,
    LinuxCtState,
    LinuxFirewallChain,
    LinuxFirewallFamily,
    LinuxFirewallHook,
    LinuxFirewallPolicyAuthority,
    LinuxFirewallPolicySnapshot,
    LinuxFirewallPredicate,
    LinuxFirewallRule,
    LinuxFirewallTable,
    LinuxFirewallUnsupportedFeature,
    LinuxNamespaceAlignment,
    LinuxPredicateKind,
    LinuxVerdict,
    MAX_LINUX_EXPRESSIONS_PER_RULE,
    MAX_LINUX_FIREWALL_CHAINS,
    MAX_LINUX_FIREWALL_RULES,
    MAX_LINUX_FIREWALL_TABLES,
    MAX_LINUX_INLINE_SET_VALUES,
    MAX_LINUX_NORMALIZED_TOKEN_LENGTH,
)
from .nftables_contracts import MAX_NFT_JSON_BYTES, NftParseResult, NftParseStatus


_IGNORABLE_OBJECTS = frozenset({"metainfo"})
_POLICY_OBJECTS = frozenset({"table", "chain", "rule"})
_IGNORABLE_EXPRESSIONS = frozenset({"counter", "comment"})
_INTERFACE_IDENTITY_DOMAIN = "cyberwatchtower:linux-firewall-interface:v1"


class _ParseFailure(Exception):
    def __init__(self, status: NftParseStatus):
        self.status = status


@dataclass(slots=True)
class _ChainRecord:
    family: LinuxFirewallFamily
    table_name: str
    name: str
    kind: LinuxChainKind
    hook: LinuxFirewallHook | None
    priority: int | None
    policy: LinuxChainPolicy
    unsupported: bool
    rules: list[dict[str, Any]]


def _digest(domain: str, *parts: str) -> str:
    material = bytearray(domain.encode("ascii"))
    for part in parts:
        encoded = part.encode("utf-8")
        material.extend(len(encoded).to_bytes(4, "big"))
        material.extend(encoded)
    return hashlib.sha256(material).hexdigest()


def _token(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise _ParseFailure(NftParseStatus.INVALID_VALUE)
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise _ParseFailure(NftParseStatus.INVALID_VALUE) from exc
    if size > MAX_LINUX_NORMALIZED_TOKEN_LENGTH or any(ord(char) < 32 for char in value):
        raise _ParseFailure(NftParseStatus.STRUCTURAL_LIMIT_EXCEEDED)
    return value


def _closed_mapping(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _ParseFailure(NftParseStatus.INVALID_VALUE)
    return value


def _family(value: object) -> LinuxFirewallFamily:
    token = _token(value)
    try:
        return LinuxFirewallFamily(token)
    except ValueError as exc:
        raise _ParseFailure(NftParseStatus.INVALID_VALUE) from exc


def _policy(value: object) -> LinuxChainPolicy:
    if value is None:
        return LinuxChainPolicy.NONE
    if not isinstance(value, str):
        raise _ParseFailure(NftParseStatus.INVALID_VALUE)
    return {
        "accept": LinuxChainPolicy.ACCEPT,
        "drop": LinuxChainPolicy.DROP,
        "unknown": LinuxChainPolicy.UNKNOWN,
    }.get(value.casefold(), LinuxChainPolicy.UNKNOWN)


def _port(value: object) -> FirewallPortRange:
    if isinstance(value, bool):
        raise _ParseFailure(NftParseStatus.INVALID_VALUE)
    if isinstance(value, int):
        start = end = value
    elif isinstance(value, dict) and set(value) == {"range"}:
        endpoints = value["range"]
        if (
            not isinstance(endpoints, list)
            or len(endpoints) != 2
            or any(isinstance(item, bool) or not isinstance(item, int) for item in endpoints)
        ):
            raise _ParseFailure(NftParseStatus.INVALID_VALUE)
        start, end = endpoints
    else:
        raise _ParseFailure(NftParseStatus.INVALID_VALUE)
    try:
        return FirewallPortRange(start, end)
    except (TypeError, ValueError) as exc:
        raise _ParseFailure(NftParseStatus.INVALID_VALUE) from exc


def _port_values(value: object) -> tuple[FirewallPortRange, ...]:
    if isinstance(value, dict) and set(value) not in ({"set"}, {"range"}):
        raise _ParseFailure(NftParseStatus.UNSUPPORTED_SEMANTICS)
    raw_values = value.get("set") if isinstance(value, dict) and set(value) == {"set"} else [value]
    if not isinstance(raw_values, list) or not raw_values:
        raise _ParseFailure(NftParseStatus.INVALID_VALUE)
    if len(raw_values) > MAX_LINUX_INLINE_SET_VALUES:
        raise _ParseFailure(NftParseStatus.STRUCTURAL_LIMIT_EXCEEDED)
    return tuple(sorted(set(_port(item) for item in raw_values)))


def _address_values(value: object, version: int) -> tuple[FirewallAddressCondition, ...]:
    if isinstance(value, dict):
        if set(value) != {"set"}:
            raise _ParseFailure(NftParseStatus.UNSUPPORTED_SEMANTICS)
        raw_values = value["set"]
    else:
        raw_values = [value]
    if not isinstance(raw_values, list) or not raw_values:
        raise _ParseFailure(NftParseStatus.INVALID_VALUE)
    if len(raw_values) > MAX_LINUX_INLINE_SET_VALUES:
        raise _ParseFailure(NftParseStatus.STRUCTURAL_LIMIT_EXCEEDED)
    result = []
    for item in raw_values:
        token = _token(item)
        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError as exc:
            raise _ParseFailure(NftParseStatus.INVALID_VALUE) from exc
        if network.version != version:
            raise _ParseFailure(NftParseStatus.INVALID_VALUE)
        if network.prefixlen == 0:
            result.append(FirewallAddressCondition(AddressConditionKind.ANY))
        else:
            result.append(FirewallAddressCondition(AddressConditionKind.CIDR, str(network)))
    canonical = {
        (item.kind.value, None if item.value is None else str(item.value)): item
        for item in result
    }
    return tuple(canonical[key] for key in sorted(canonical))


def _unsupported(feature: LinuxFirewallUnsupportedFeature) -> LinuxFirewallPredicate:
    return LinuxFirewallPredicate(LinuxPredicateKind.UNSUPPORTED, feature)


def _predicate_material(predicate: LinuxFirewallPredicate) -> object:
    value = predicate.value
    if isinstance(value, tuple):
        if predicate.kind == LinuxPredicateKind.DESTINATION_PORT:
            normalized = [[item.start, item.end] for item in value]
        else:
            normalized = [
                [item.kind.value, None if item.value is None else str(item.value)]
                for item in value
            ]
    elif isinstance(value, FirewallInterfaceCondition):
        normalized = [value.kind.value, value.value]
    else:
        normalized = value.value
    return [predicate.kind.value, normalized]


def _match_expression(value: object) -> tuple[LinuxFirewallPredicate, ...]:
    match = _closed_mapping(value)
    if set(match) != {"op", "left", "right"} or match["op"] != "==":
        return (_unsupported(LinuxFirewallUnsupportedFeature.UNSUPPORTED_EXPRESSION),)
    left = _closed_mapping(match["left"])
    right = match["right"]
    if set(left) == {"meta"}:
        meta = _closed_mapping(left["meta"])
        if set(meta) != {"key"}:
            return (_unsupported(LinuxFirewallUnsupportedFeature.PACKET_MARK_OR_META_DEPENDENCY),)
        key = meta["key"]
        if key == "l4proto" and isinstance(right, str) and right.casefold() in {"tcp", "udp"}:
            return (LinuxFirewallPredicate(
                LinuxPredicateKind.PROTOCOL, NetworkProtocol(right.casefold())
            ),)
        if key == "iifname" and isinstance(right, str):
            name = _token(right)
            interface_id = _digest(_INTERFACE_IDENTITY_DOMAIN, name)
            return (LinuxFirewallPredicate(
                LinuxPredicateKind.INBOUND_INTERFACE,
                FirewallInterfaceCondition(InterfaceConditionKind.INTERFACE_DIGEST, interface_id),
            ),)
        return (_unsupported(LinuxFirewallUnsupportedFeature.PACKET_MARK_OR_META_DEPENDENCY),)
    if set(left) == {"ct"}:
        ct = _closed_mapping(left["ct"])
        if set(ct) != {"key"} or ct["key"] != "state" or not isinstance(right, str):
            return (_unsupported(LinuxFirewallUnsupportedFeature.UNSUPPORTED_CT_EXPRESSION),)
        try:
            state = LinuxCtState(right.upper())
        except ValueError:
            return (_unsupported(LinuxFirewallUnsupportedFeature.UNSUPPORTED_CT_EXPRESSION),)
        return (LinuxFirewallPredicate(LinuxPredicateKind.CT_STATE, state),)
    if set(left) != {"payload"}:
        return (_unsupported(LinuxFirewallUnsupportedFeature.UNSUPPORTED_EXPRESSION),)
    payload = _closed_mapping(left["payload"])
    if set(payload) != {"protocol", "field"}:
        return (_unsupported(LinuxFirewallUnsupportedFeature.UNSUPPORTED_EXPRESSION),)
    protocol, field = payload["protocol"], payload["field"]
    if protocol in {"tcp", "udp"} and field == "dport":
        try:
            ports = _port_values(right)
        except _ParseFailure as exc:
            if exc.status == NftParseStatus.UNSUPPORTED_SEMANTICS:
                return (_unsupported(LinuxFirewallUnsupportedFeature.UNRESOLVED_NAMED_SET),)
            raise
        return (
            LinuxFirewallPredicate(LinuxPredicateKind.PROTOCOL, NetworkProtocol(protocol)),
            LinuxFirewallPredicate(LinuxPredicateKind.DESTINATION_PORT, ports),
        )
    address_fields = {
        ("ip", "saddr"): (LinuxPredicateKind.SOURCE_ADDRESS, 4),
        ("ip", "daddr"): (LinuxPredicateKind.DESTINATION_ADDRESS, 4),
        ("ip6", "saddr"): (LinuxPredicateKind.SOURCE_ADDRESS, 6),
        ("ip6", "daddr"): (LinuxPredicateKind.DESTINATION_ADDRESS, 6),
    }
    if (protocol, field) in address_fields:
        kind, version = address_fields[(protocol, field)]
        try:
            addresses = _address_values(right, version)
        except _ParseFailure as exc:
            if exc.status == NftParseStatus.UNSUPPORTED_SEMANTICS:
                return (_unsupported(LinuxFirewallUnsupportedFeature.UNRESOLVED_NAMED_SET),)
            raise
        family = LinuxFirewallFamily.IPV4 if version == 4 else LinuxFirewallFamily.IPV6
        return (
            LinuxFirewallPredicate(LinuxPredicateKind.FAMILY, family),
            LinuxFirewallPredicate(kind, addresses),
        )
    return (_unsupported(LinuxFirewallUnsupportedFeature.UNSUPPORTED_EXPRESSION),)


def _parse_rule(
    raw: dict[str, Any], family: LinuxFirewallFamily, table_name: str,
    chain_name: str, ordinal: int,
) -> tuple[LinuxFirewallRule, bool]:
    allowed = {"family", "table", "chain", "expr", "handle", "comment"}
    if set(raw) - allowed:
        unsupported = True
    else:
        unsupported = False
    if _family(raw.get("family")) != family or _token(raw.get("table")) != table_name \
            or _token(raw.get("chain")) != chain_name:
        raise _ParseFailure(NftParseStatus.INVALID_VALUE)
    expressions = raw.get("expr")
    if not isinstance(expressions, list):
        raise _ParseFailure(NftParseStatus.INVALID_VALUE)
    if len(expressions) > MAX_LINUX_EXPRESSIONS_PER_RULE:
        raise _ParseFailure(NftParseStatus.STRUCTURAL_LIMIT_EXCEEDED)
    predicates: list[LinuxFirewallPredicate] = []
    if unsupported:
        predicates.append(
            _unsupported(LinuxFirewallUnsupportedFeature.UNSUPPORTED_EXPRESSION)
        )
    verdict = LinuxVerdict.CONTINUE
    target: str | None = None
    for expression in expressions:
        item = _closed_mapping(expression)
        if len(item) != 1:
            raise _ParseFailure(NftParseStatus.INVALID_VALUE)
        key, value = next(iter(item.items()))
        if key in _IGNORABLE_EXPRESSIONS:
            continue
        if key == "match":
            parsed = _match_expression(value)
            predicates.extend(parsed)
            unsupported |= any(p.kind == LinuxPredicateKind.UNSUPPORTED for p in parsed)
            continue
        terminal = {
            "accept": LinuxVerdict.ACCEPT,
            "drop": LinuxVerdict.DROP,
            "reject": LinuxVerdict.REJECT,
            "return": LinuxVerdict.RETURN,
        }.get(key)
        if terminal is not None and value is None:
            if verdict != LinuxVerdict.CONTINUE:
                raise _ParseFailure(NftParseStatus.INVALID_VALUE)
            verdict = terminal
            continue
        if key in {"jump", "goto"} and isinstance(value, dict) and set(value) == {"target"}:
            if verdict != LinuxVerdict.CONTINUE:
                raise _ParseFailure(NftParseStatus.INVALID_VALUE)
            target_name = _token(value["target"])
            verdict = LinuxVerdict.JUMP if key == "jump" else LinuxVerdict.GOTO
            target = _digest("cyberwatchtower:linux-nft-chain-structural:v1", target_name)
            continue
        unsupported = True
        predicates.append(_unsupported(LinuxFirewallUnsupportedFeature.UNSUPPORTED_EXPRESSION))
    if len(predicates) > MAX_LINUX_EXPRESSIONS_PER_RULE:
        raise _ParseFailure(NftParseStatus.STRUCTURAL_LIMIT_EXCEEDED)
    material = json.dumps(
        {
            "predicates": [_predicate_material(item) for item in predicates],
            "target": target,
            "verdict": verdict.value,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    rule_id = _digest(
        "cyberwatchtower:linux-nft-rule-structural:v1",
        family.value, table_name, chain_name, str(ordinal), material,
    )
    return LinuxFirewallRule(rule_id, tuple(predicates), verdict, target), unsupported


def _decode(raw: bytes | str) -> object:
    if isinstance(raw, bytes):
        encoded = raw
        if len(encoded) > MAX_NFT_JSON_BYTES:
            raise _ParseFailure(NftParseStatus.INPUT_TOO_LARGE)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _ParseFailure(NftParseStatus.INVALID_JSON) from exc
    elif isinstance(raw, str):
        try:
            encoded = raw.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise _ParseFailure(NftParseStatus.INVALID_JSON) from exc
        text = raw
    else:
        raise _ParseFailure(NftParseStatus.INVALID_VALUE)
    if len(encoded) > MAX_NFT_JSON_BYTES:
        raise _ParseFailure(NftParseStatus.INPUT_TOO_LARGE)
    try:
        return json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise _ParseFailure(NftParseStatus.INVALID_JSON) from exc


def parse_nftables_json(
    raw: bytes | str,
    *,
    namespace_alignment: LinuxNamespaceAlignment = LinuxNamespaceAlignment.UNKNOWN,
) -> NftParseResult:
    """Decode and normalize caller-supplied nft JSON without native execution."""

    try:
        if not isinstance(namespace_alignment, LinuxNamespaceAlignment):
            raise _ParseFailure(NftParseStatus.INVALID_VALUE)
        root = _decode(raw)
        if not isinstance(root, dict) or set(root) != {"nftables"}:
            raise _ParseFailure(NftParseStatus.INVALID_ROOT)
        objects = root["nftables"]
        if not isinstance(objects, list):
            raise _ParseFailure(NftParseStatus.INVALID_ROOT)

        tables: dict[tuple[LinuxFirewallFamily, str], list[_ChainRecord]] = {}
        chain_records: dict[tuple[LinuxFirewallFamily, str, str], _ChainRecord] = {}
        pending_rules: list[dict[str, Any]] = []
        unsupported_document = False
        unsupported_semantics = False
        table_count = chain_count = rule_count = 0

        for entry in objects:
            item = _closed_mapping(entry)
            if len(item) != 1:
                raise _ParseFailure(NftParseStatus.INVALID_VALUE)
            kind, value = next(iter(item.items()))
            if kind in _IGNORABLE_OBJECTS:
                continue
            if kind not in _POLICY_OBJECTS:
                unsupported_document = True
                continue
            value = _closed_mapping(value)
            if kind == "table":
                allowed = {"family", "name", "handle", "comment"}
                unknown_table_fields = bool(set(value) - allowed)
                unsupported_semantics |= unknown_table_fields
                unsupported_document |= unknown_table_fields
                family = _family(value.get("family"))
                name = _token(value.get("name"))
                if family not in {
                    LinuxFirewallFamily.INET,
                    LinuxFirewallFamily.IPV4,
                    LinuxFirewallFamily.IPV6,
                }:
                    unsupported_semantics = True
                key = (family, name)
                if key in tables:
                    raise _ParseFailure(NftParseStatus.INVALID_VALUE)
                table_count += 1
                if table_count > MAX_LINUX_FIREWALL_TABLES:
                    raise _ParseFailure(NftParseStatus.STRUCTURAL_LIMIT_EXCEEDED)
                tables[key] = []
            elif kind == "chain":
                chain_count += 1
                if chain_count > MAX_LINUX_FIREWALL_CHAINS:
                    raise _ParseFailure(NftParseStatus.STRUCTURAL_LIMIT_EXCEEDED)
                allowed = {"family", "table", "name", "type", "hook", "prio", "policy", "handle", "comment"}
                family = _family(value.get("family"))
                table_name = _token(value.get("table"))
                name = _token(value.get("name"))
                key = (family, table_name, name)
                if key in chain_records:
                    raise _ParseFailure(NftParseStatus.INVALID_VALUE)
                hook_value = value.get("hook")
                if hook_value is None:
                    kind_value = LinuxChainKind.REGULAR
                    hook = None
                    priority = None
                    policy = LinuxChainPolicy.NONE
                else:
                    try:
                        hook = LinuxFirewallHook(_token(hook_value))
                    except ValueError:
                        unsupported_document = True
                        continue
                    priority = value.get("prio")
                    if isinstance(priority, bool) or not isinstance(priority, int):
                        raise _ParseFailure(NftParseStatus.INCOMPLETE_SEMANTICS)
                    kind_value = LinuxChainKind.BASE
                    policy = _policy(value.get("policy"))
                    if policy == LinuxChainPolicy.UNKNOWN:
                        unsupported_semantics = True
                unsupported_chain = bool(set(value) - allowed) or (
                    hook is not None and value.get("type") != "filter"
                ) or (hook is None and "type" in value)
                record = _ChainRecord(
                    family, table_name, name, kind_value, hook, priority, policy,
                    unsupported_chain, [],
                )
                unsupported_semantics |= record.unsupported
                chain_records[key] = record
            else:
                rule_count += 1
                if rule_count > MAX_LINUX_FIREWALL_RULES:
                    raise _ParseFailure(NftParseStatus.STRUCTURAL_LIMIT_EXCEEDED)
                pending_rules.append(value)

        for key, record in chain_records.items():
            table_key = key[:2]
            if table_key not in tables:
                raise _ParseFailure(NftParseStatus.INVALID_VALUE)
            tables[table_key].append(record)
        for raw_rule in pending_rules:
            key = (
                _family(raw_rule.get("family")),
                _token(raw_rule.get("table")),
                _token(raw_rule.get("chain")),
            )
            record = chain_records.get(key)
            if record is None:
                raise _ParseFailure(NftParseStatus.INVALID_VALUE)
            record.rules.append(raw_rule)

        normalized_tables = []
        for (family, table_name), records in tables.items():
            normalized_chains = []
            for record in records:
                rules = []
                if record.unsupported:
                    rules.append(LinuxFirewallRule(
                        _digest("cyberwatchtower:linux-nft-rule-structural:v1", family.value, table_name, record.name, "unsupported-chain"),
                        (_unsupported(LinuxFirewallUnsupportedFeature.UNSUPPORTED_CHAIN_FLOW),),
                        LinuxVerdict.CONTINUE,
                    ))
                for ordinal, raw_rule in enumerate(record.rules):
                    parsed, unsupported = _parse_rule(
                        raw_rule, family, table_name, record.name, ordinal
                    )
                    unsupported_semantics |= unsupported
                    rules.append(parsed)
                chain_id = _digest("cyberwatchtower:linux-nft-chain-structural:v1", record.name)
                normalized_chains.append(LinuxFirewallChain(
                    chain_id, record.kind, tuple(rules), record.hook,
                    record.priority, record.policy,
                ))
            table_id = _digest(
                "cyberwatchtower:linux-nft-table-structural:v1", family.value, table_name
            )
            normalized_tables.append(LinuxFirewallTable(
                table_id, family, tuple(normalized_chains)
            ))

        snapshot = LinuxFirewallPolicySnapshot(
            LinuxFirewallPolicyAuthority.CURRENT_NETWORK_NAMESPACE_POLICY_VIEW,
            LinuxNamespaceAlignment.UNKNOWN if unsupported_document else namespace_alignment,
            tuple(normalized_tables),
        )
        status = (
            NftParseStatus.UNSUPPORTED_SEMANTICS
            if unsupported_document or unsupported_semantics
            else NftParseStatus.SUCCESS
        )
        return NftParseResult(status, snapshot)
    except _ParseFailure as exc:
        return NftParseResult(exc.status)
    except (TypeError, ValueError, OverflowError):
        return NftParseResult(NftParseStatus.INVALID_VALUE)


__all__ = ["parse_nftables_json"]
