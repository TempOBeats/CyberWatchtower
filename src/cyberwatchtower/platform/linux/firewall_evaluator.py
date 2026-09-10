"""Pure bounded evaluator for normalized Linux inbound firewall policy."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import ipaddress

from cyberwatchtower.firewall_policy import (
    AddressConditionKind,
    EvaluatedPolicyDisposition,
    FirewallConditionMatch,
    FirewallDefaultPolicyContext,
    FirewallRuleAction,
    FirewallRuleApplicability,
    FirewallRuleMatch,
    InterfaceConditionKind,
    ListenerPolicyAssessment,
    ListenerPolicyBasis,
    ListenerPolicySubject,
    MAX_MATCHED_RULE_DIGESTS_PER_LISTENER,
)
from cyberwatchtower.report_contracts import CoverageState

from .firewall_contracts import (
    LinuxChainKind,
    LinuxChainPolicy,
    LinuxCtState,
    LinuxFirewallChain,
    LinuxFirewallFamily,
    LinuxFirewallHook,
    LinuxFirewallPolicySnapshot,
    LinuxNamespaceAlignment,
    LinuxPredicateKind,
    LinuxVerdict,
    MAX_LINUX_CHAIN_DEPTH,
    MAX_LINUX_TRAVERSAL_STEPS,
)


class _Flow(str, Enum):
    ACCEPT = "ACCEPT"
    DROP = "DROP"
    RETURN = "RETURN"
    INCOMPLETE = "INCOMPLETE"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(slots=True)
class _Budget:
    steps: int = 0

    def consume(self) -> bool:
        self.steps += 1
        return self.steps <= MAX_LINUX_TRAVERSAL_STEPS


@dataclass(frozen=True, slots=True)
class _ChainResult:
    flow: _Flow
    matches: tuple[FirewallRuleMatch, ...] = ()
    policy: LinuxChainPolicy | None = None


def _address_match(
    condition,
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool | None:
    if condition.kind == AddressConditionKind.ANY:
        return True
    if condition.kind == AddressConditionKind.EXACT:
        return address == ipaddress.ip_address(condition.value)
    if condition.kind == AddressConditionKind.CIDR:
        return address in ipaddress.ip_network(condition.value, strict=False)
    if condition.kind in {AddressConditionKind.IPV4_RANGE, AddressConditionKind.IPV6_RANGE}:
        if condition.value.start.version != address.version:
            return False
        return condition.value.start <= address <= condition.value.end
    if condition.kind == AddressConditionKind.SUPPORTED_SPECIAL_SCOPE:
        if condition.value == "LOOPBACK":
            return address.is_loopback
        return None
    return None


def _predicate_match(predicate, subject: ListenerPolicySubject) -> bool | None:
    if predicate.kind == LinuxPredicateKind.FAMILY:
        version = ipaddress.ip_address(subject.local_address.split("%", 1)[0]).version
        return predicate.value == LinuxFirewallFamily.INET or (
            predicate.value == LinuxFirewallFamily.IPV4 and version == 4
        ) or (predicate.value == LinuxFirewallFamily.IPV6 and version == 6)
    if predicate.kind == LinuxPredicateKind.PROTOCOL:
        return predicate.value == subject.protocol
    if predicate.kind == LinuxPredicateKind.DESTINATION_PORT:
        return any(item.start <= subject.local_port <= item.end for item in predicate.value)
    if predicate.kind == LinuxPredicateKind.SOURCE_ADDRESS:
        return True if all(item.kind == AddressConditionKind.ANY for item in predicate.value) else None
    if predicate.kind == LinuxPredicateKind.DESTINATION_ADDRESS:
        address = ipaddress.ip_address(subject.local_address.split("%", 1)[0])
        if address.is_unspecified:
            values = []
            for item in predicate.value:
                if item.kind == AddressConditionKind.ANY:
                    values.append(True)
                elif item.kind == AddressConditionKind.EXACT:
                    values.append(
                        False if ipaddress.ip_address(item.value).version != address.version
                        else None
                    )
                elif item.kind == AddressConditionKind.CIDR:
                    network = ipaddress.ip_network(item.value, strict=False)
                    values.append(
                        False if network.version != address.version
                        else True if network.prefixlen == 0 else None
                    )
                elif item.kind in {
                    AddressConditionKind.IPV4_RANGE,
                    AddressConditionKind.IPV6_RANGE,
                }:
                    values.append(
                        False if item.value.start.version != address.version else None
                    )
                else:
                    values.append(None)
            return True if True in values else (None if None in values else False)
        values = tuple(_address_match(item, address) for item in predicate.value)
        return True if True in values else (None if None in values else False)
    if predicate.kind == LinuxPredicateKind.INBOUND_INTERFACE:
        condition = predicate.value
        if condition.kind == InterfaceConditionKind.ANY:
            return True
        if condition.kind == InterfaceConditionKind.INTERFACE_DIGEST:
            return None if subject.interface_digest is None else condition.value == subject.interface_digest
        return None if subject.interface is None else condition.kind == subject.interface
    if predicate.kind == LinuxPredicateKind.CT_STATE:
        return True if predicate.value == LinuxCtState.ANY else None
    if predicate.kind == LinuxPredicateKind.UNSUPPORTED:
        return None
    raise AssertionError("closed predicate kind was not handled")


def _rule_match(rule, subject: ListenerPolicySubject) -> bool | None:
    indeterminate = False
    for expression in rule.expressions:
        result = _predicate_match(expression, subject)
        if result is False:
            return False
        if result is None:
            indeterminate = True
    return None if indeterminate else True


def _explicit_match(rule, action: FirewallRuleAction) -> FirewallRuleMatch:
    return FirewallRuleMatch(
        rule.semantic_rule_id, action, FirewallConditionMatch.MATCH, True
    )


def _fallthrough(chain: LinuxFirewallChain, matches: tuple[FirewallRuleMatch, ...]) -> _ChainResult:
    if chain.kind == LinuxChainKind.REGULAR:
        return _ChainResult(_Flow.RETURN, matches)
    if chain.policy == LinuxChainPolicy.ACCEPT:
        return _ChainResult(_Flow.ACCEPT, matches, chain.policy)
    if chain.policy == LinuxChainPolicy.DROP:
        return _ChainResult(_Flow.DROP, matches, chain.policy)
    return _ChainResult(_Flow.INCOMPLETE, matches, chain.policy)


def _evaluate_chain(
    chain: LinuxFirewallChain,
    chains: dict[str, LinuxFirewallChain],
    subject: ListenerPolicySubject,
    budget: _Budget,
    stack: tuple[str, ...],
) -> _ChainResult:
    if len(stack) >= MAX_LINUX_CHAIN_DEPTH or chain.semantic_chain_id in stack:
        return _ChainResult(_Flow.INCOMPLETE)
    stack = (*stack, chain.semantic_chain_id)
    matches: list[FirewallRuleMatch] = []
    for rule in chain.rules:
        if not budget.consume():
            return _ChainResult(_Flow.INCOMPLETE)
        applicable = _rule_match(rule, subject)
        if applicable is False:
            continue
        if applicable is None:
            return _ChainResult(_Flow.INCOMPLETE)
        if rule.verdict == LinuxVerdict.CONTINUE:
            continue
        if rule.verdict == LinuxVerdict.ACCEPT:
            matches.append(_explicit_match(rule, FirewallRuleAction.ALLOW))
            return _ChainResult(_Flow.ACCEPT, tuple(matches))
        if rule.verdict in {LinuxVerdict.DROP, LinuxVerdict.REJECT}:
            matches.append(_explicit_match(rule, FirewallRuleAction.BLOCK))
            return _ChainResult(_Flow.DROP, tuple(matches))
        if rule.verdict == LinuxVerdict.RETURN:
            return _fallthrough(chain, tuple(matches))
        target = chains.get(rule.target_chain_id)
        if target is None or target.kind != LinuxChainKind.REGULAR:
            return _ChainResult(_Flow.INCOMPLETE)
        child = _evaluate_chain(target, chains, subject, budget, stack)
        if child.flow in {_Flow.ACCEPT, _Flow.DROP, _Flow.INCOMPLETE, _Flow.UNSUPPORTED}:
            return _ChainResult(child.flow, (*matches, *child.matches), child.policy)
        if rule.verdict == LinuxVerdict.GOTO:
            return _fallthrough(chain, (*matches, *child.matches))
    return _fallthrough(chain, tuple(matches))


def _assessment(
    applicability,
    default,
    matches,
    basis,
    coverage,
    disposition=EvaluatedPolicyDisposition.NOT_ESTABLISHED,
) -> ListenerPolicyAssessment:
    return ListenerPolicyAssessment(
        applicability,
        default,
        tuple(sorted(matches)),
        basis,
        CoverageState.COMPLETE,
        coverage,
        disposition,
    )


def evaluate_linux_listener_policy(
    subject: ListenerPolicySubject,
    snapshot: LinuxFirewallPolicySnapshot,
) -> ListenerPolicyAssessment:
    """Evaluate the supported input-chain subset without claiming reachability."""

    if not isinstance(subject, ListenerPolicySubject):
        raise TypeError("subject must use ListenerPolicySubject.")
    if not isinstance(snapshot, LinuxFirewallPolicySnapshot):
        raise TypeError("snapshot must use LinuxFirewallPolicySnapshot.")
    if snapshot.namespace_alignment != LinuxNamespaceAlignment.SAME_CURRENT_NAMESPACE:
        return _assessment(
            FirewallRuleApplicability.INCOMPLETE,
            FirewallDefaultPolicyContext.UNKNOWN,
            (),
            (ListenerPolicyBasis.POLICY_EVALUATION_INCOMPLETE,),
            CoverageState.INCOMPLETE,
        )
    supported = {LinuxFirewallFamily.INET, LinuxFirewallFamily.IPV4, LinuxFirewallFamily.IPV6}
    if any(
        table.family not in supported
        and any(chain.kind == LinuxChainKind.BASE and chain.hook == LinuxFirewallHook.INPUT for chain in table.chains)
        for table in snapshot.tables
    ):
        return ListenerPolicyAssessment(
            FirewallRuleApplicability.UNSUPPORTED,
            FirewallDefaultPolicyContext.UNKNOWN,
            (),
            (ListenerPolicyBasis.POLICY_TECHNOLOGY_UNSUPPORTED,),
            CoverageState.COMPLETE,
            CoverageState.UNKNOWN,
        )
    version = ipaddress.ip_address(subject.local_address.split("%", 1)[0]).version
    applicable_families = {LinuxFirewallFamily.INET, LinuxFirewallFamily.IPV4 if version == 4 else LinuxFirewallFamily.IPV6}
    base_chains = [
        (chain, table) for table in snapshot.tables if table.family in applicable_families
        for chain in table.chains
        if chain.kind == LinuxChainKind.BASE and chain.hook == LinuxFirewallHook.INPUT
    ]
    priorities = [chain.priority for chain, _table in base_chains]
    if len(set(priorities)) != len(priorities):
        return _assessment(
            FirewallRuleApplicability.INCOMPLETE, FirewallDefaultPolicyContext.UNKNOWN,
            (), (ListenerPolicyBasis.POLICY_EVALUATION_INCOMPLETE,), CoverageState.INCOMPLETE,
        )
    base_chains.sort(key=lambda value: value[0].priority)
    budget = _Budget()
    matches: list[FirewallRuleMatch] = []
    policies: list[LinuxChainPolicy] = []
    for chain, table in base_chains:
        chains = {item.semantic_chain_id: item for item in table.chains}
        result = _evaluate_chain(chain, chains, subject, budget, ())
        matches.extend(result.matches)
        if len(matches) > MAX_MATCHED_RULE_DIGESTS_PER_LISTENER:
            result = _ChainResult(_Flow.INCOMPLETE)
        if result.policy is not None:
            policies.append(result.policy)
        if result.flow == _Flow.INCOMPLETE:
            return _assessment(
                FirewallRuleApplicability.INCOMPLETE, FirewallDefaultPolicyContext.UNKNOWN,
                (), (ListenerPolicyBasis.POLICY_EVALUATION_INCOMPLETE,), CoverageState.INCOMPLETE,
            )
        if result.flow == _Flow.DROP:
            if result.matches:
                return _assessment(
                    FirewallRuleApplicability.MATCHING_BLOCK,
                    FirewallDefaultPolicyContext.UNKNOWN,
                    result.matches,
                    (ListenerPolicyBasis.EXPLICIT_UNIVERSAL_BLOCK,),
                    CoverageState.COMPLETE,
                    EvaluatedPolicyDisposition.BLOCK,
                )
            allow_matches = tuple(
                match for match in matches
                if match.action == FirewallRuleAction.ALLOW
            )
            if allow_matches:
                return _assessment(
                    FirewallRuleApplicability.MATCHING_ALLOW,
                    FirewallDefaultPolicyContext.BLOCK,
                    allow_matches,
                    (ListenerPolicyBasis.EXPLICIT_ALLOW,
                     ListenerPolicyBasis.DEFAULT_POLICY_CONTEXT),
                    CoverageState.COMPLETE,
                    EvaluatedPolicyDisposition.BLOCK,
                )
            return _assessment(
                FirewallRuleApplicability.NO_MATCH,
                FirewallDefaultPolicyContext.BLOCK,
                (),
                (ListenerPolicyBasis.NO_APPLICABLE_RULE, ListenerPolicyBasis.DEFAULT_POLICY_CONTEXT),
                CoverageState.COMPLETE,
                EvaluatedPolicyDisposition.BLOCK,
            )
    if matches:
        return _assessment(
            FirewallRuleApplicability.MATCHING_ALLOW,
            FirewallDefaultPolicyContext.ALLOW if policies else FirewallDefaultPolicyContext.UNKNOWN,
            tuple(match for match in matches if match.action == FirewallRuleAction.ALLOW),
            (ListenerPolicyBasis.EXPLICIT_ALLOW,),
            CoverageState.COMPLETE,
            EvaluatedPolicyDisposition.ALLOW,
        )
    default = (
        FirewallDefaultPolicyContext.ALLOW
        if base_chains else FirewallDefaultPolicyContext.UNKNOWN
    )
    return _assessment(
        FirewallRuleApplicability.NO_MATCH,
        default,
        (),
        (ListenerPolicyBasis.NO_APPLICABLE_RULE, ListenerPolicyBasis.DEFAULT_POLICY_CONTEXT),
        CoverageState.COMPLETE,
        (
            EvaluatedPolicyDisposition.ALLOW
            if base_chains else EvaluatedPolicyDisposition.NOT_ESTABLISHED
        ),
    )
