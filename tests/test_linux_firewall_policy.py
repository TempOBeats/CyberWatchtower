import hashlib
import ipaddress
import unittest
from unittest.mock import patch

from cyberwatchtower.firewall_policy import (
    AddressConditionKind,
    EvaluatedPolicyDisposition,
    FirewallAddressCondition,
    FirewallDefaultPolicyContext,
    FirewallInterfaceCondition,
    FirewallIPv6AddressRange,
    FirewallPortRange,
    FirewallRuleApplicability,
    InterfaceConditionKind,
    ListenerPolicySubject,
)
from cyberwatchtower.platform.linux.firewall_contracts import (
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
    MAX_LINUX_CHAIN_DEPTH,
    MAX_LINUX_EXPRESSIONS_PER_RULE,
    MAX_LINUX_FIREWALL_CHAINS,
    MAX_LINUX_FIREWALL_RULES,
    MAX_LINUX_FIREWALL_TABLES,
    MAX_LINUX_INLINE_SET_VALUES,
    MAX_LINUX_NORMALIZED_TOKEN_LENGTH,
    MAX_LINUX_TRAVERSAL_STEPS,
    linux_firewall_chain_identity,
    linux_firewall_rule_identity,
    linux_firewall_table_identity,
)
from cyberwatchtower.platform.linux.firewall_evaluator import (
    evaluate_linux_listener_policy,
)
from cyberwatchtower.platform.linux import firewall_contracts
from cyberwatchtower.platform.models import (
    BindExposure,
    FirewallProfile,
    NetworkProtocol,
)
from cyberwatchtower.report_contracts import CoverageState
from cyberwatchtower.reachability import (
    RemoteReachabilityState,
    assess_listener_reachability,
)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def subject(**changes) -> ListenerPolicySubject:
    values = {
        "protocol": NetworkProtocol.TCP,
        "local_port": 443,
        "bind_exposure": BindExposure.ALL_INTERFACES,
        "local_address": "0.0.0.0",
        "profiles": (FirewallProfile.DEFAULT,),
    }
    values.update(changes)
    return ListenerPolicySubject(**values)


def predicate(kind, value) -> LinuxFirewallPredicate:
    return LinuxFirewallPredicate(kind, value)


def rule(name, verdict, *expressions, target=None) -> LinuxFirewallRule:
    return LinuxFirewallRule(digest(name), tuple(expressions), verdict, target)


def chain(name, *rules, policy=LinuxChainPolicy.ACCEPT, priority=0,
          hook=LinuxFirewallHook.INPUT, kind=LinuxChainKind.BASE):
    return LinuxFirewallChain(
        digest(name), kind, tuple(rules),
        hook if kind == LinuxChainKind.BASE else None,
        priority if kind == LinuxChainKind.BASE else None,
        policy if kind == LinuxChainKind.BASE else LinuxChainPolicy.NONE,
    )


def table(name, *chains, family=LinuxFirewallFamily.INET):
    return LinuxFirewallTable(digest(name), family, tuple(chains))


def snapshot(*tables, alignment=LinuxNamespaceAlignment.SAME_CURRENT_NAMESPACE):
    return LinuxFirewallPolicySnapshot(
        LinuxFirewallPolicyAuthority.CURRENT_NETWORK_NAMESPACE_POLICY_VIEW,
        alignment,
        tuple(tables),
    )


PORT_443 = predicate(
    LinuxPredicateKind.DESTINATION_PORT, (FirewallPortRange(443, 443),)
)
TCP = predicate(LinuxPredicateKind.PROTOCOL, NetworkProtocol.TCP)
UDP = predicate(LinuxPredicateKind.PROTOCOL, NetworkProtocol.UDP)
UNSUPPORTED = predicate(
    LinuxPredicateKind.UNSUPPORTED,
    LinuxFirewallUnsupportedFeature.UNSUPPORTED_EXPRESSION,
)


class LinuxFirewallPolicyContractTests(unittest.TestCase):
    def test_frozen_bounds_and_authority_are_closed(self):
        self.assertEqual((
            MAX_LINUX_FIREWALL_TABLES, MAX_LINUX_FIREWALL_CHAINS,
            MAX_LINUX_FIREWALL_RULES, MAX_LINUX_EXPRESSIONS_PER_RULE,
            MAX_LINUX_INLINE_SET_VALUES, MAX_LINUX_CHAIN_DEPTH,
            MAX_LINUX_TRAVERSAL_STEPS, MAX_LINUX_NORMALIZED_TOKEN_LENGTH,
        ), (256, 8192, 8192, 64, 256, 64, 65536, 256))
        with self.assertRaises(TypeError):
            LinuxFirewallPolicySnapshot("CURRENT", LinuxNamespaceAlignment.UNKNOWN, ())

    def test_invalid_and_duplicate_contracts_fail_at_construction(self):
        first = chain("duplicate")
        cases = (
            lambda: LinuxFirewallChain(digest("bad"), LinuxChainKind.BASE, (),
                                       LinuxFirewallHook.INPUT, True, LinuxChainPolicy.ACCEPT),
            lambda: table("dupes", first, first),
            lambda: snapshot(table("a"), table("a")),
            lambda: rule("jump", LinuxVerdict.JUMP),
            lambda: rule("accept", LinuxVerdict.ACCEPT, target=digest("target")),
            lambda: LinuxFirewallPredicate(LinuxPredicateKind.DESTINATION_PORT, ()),
        )
        for create in cases:
            with self.subTest(create=create), self.assertRaises((TypeError, ValueError)):
                create()

    def test_structural_identities_are_domain_separated_and_parent_scoped(self):
        duplicated_rule = rule("same-rule", LinuxVerdict.ACCEPT)
        duplicated_chain = chain("same-chain")
        first = table("one", chain("one", duplicated_rule), duplicated_chain)
        second = table("two", chain("two", duplicated_rule), duplicated_chain)
        other_family = table(
            "one", chain("one", duplicated_rule), family=LinuxFirewallFamily.IPV4
        )

        self.assertNotEqual(first.semantic_table_id, other_family.semantic_table_id)
        self.assertNotEqual(first.chains[1].semantic_chain_id,
                            second.chains[1].semantic_chain_id)
        self.assertNotEqual(first.chains[0].rules[0].semantic_rule_id,
                            second.chains[0].rules[0].semantic_rule_id)
        table_id = linux_firewall_table_identity(
            LinuxFirewallFamily.INET, digest("material")
        )
        chain_id = linux_firewall_chain_identity(table_id, digest("material"))
        rule_id = linux_firewall_rule_identity(chain_id, digest("material"))
        self.assertEqual(table_id, linux_firewall_table_identity(
            LinuxFirewallFamily.INET, digest("material")
        ))
        self.assertEqual(len({table_id, chain_id, rule_id}), 3)

    def test_collection_bounds_fail_closed_at_construction(self):
        cases = (
            ("MAX_LINUX_FIREWALL_TABLES", lambda: snapshot(table("one"), table("two"))),
            ("MAX_LINUX_FIREWALL_CHAINS", lambda: table("table", chain("one"), chain("two"))),
            ("MAX_LINUX_FIREWALL_RULES", lambda: chain(
                "chain", rule("one", LinuxVerdict.CONTINUE),
                rule("two", LinuxVerdict.CONTINUE),
            )),
            ("MAX_LINUX_EXPRESSIONS_PER_RULE", lambda: rule(
                "rule", LinuxVerdict.CONTINUE, TCP, PORT_443,
            )),
            ("MAX_LINUX_INLINE_SET_VALUES", lambda: predicate(
                LinuxPredicateKind.DESTINATION_PORT,
                (FirewallPortRange(80, 80), FirewallPortRange(443, 443)),
            )),
        )
        for bound, create in cases:
            with self.subTest(bound=bound), patch.object(firewall_contracts, bound, 1):
                with self.assertRaises(ValueError):
                    create()

    def test_expression_and_inline_set_exact_bounds(self):
        expressions = tuple(
            predicate(
                LinuxPredicateKind.DESTINATION_PORT,
                (FirewallPortRange(index, index),),
            )
            for index in range(1, MAX_LINUX_EXPRESSIONS_PER_RULE + 1)
        )
        self.assertEqual(
            len(rule("bounded", LinuxVerdict.CONTINUE, *expressions).expressions),
            MAX_LINUX_EXPRESSIONS_PER_RULE,
        )
        with self.assertRaises(ValueError):
            rule(
                "too-many-expressions", LinuxVerdict.CONTINUE,
                *expressions,
                predicate(LinuxPredicateKind.PROTOCOL, NetworkProtocol.TCP),
            )
        values = tuple(
            FirewallPortRange(index, index)
            for index in range(1, MAX_LINUX_INLINE_SET_VALUES + 1)
        )
        self.assertEqual(
            len(predicate(LinuxPredicateKind.DESTINATION_PORT, values).value),
            MAX_LINUX_INLINE_SET_VALUES,
        )
        with self.assertRaises(ValueError):
            predicate(
                LinuxPredicateKind.DESTINATION_PORT,
                (*values, FirewallPortRange(1024, 1024)),
            )

    def test_contracts_contain_only_closed_structural_metadata(self):
        value = snapshot(table("table", chain("input", rule(
            "rule", LinuxVerdict.CONTINUE, UNSUPPORTED
        ))))
        rendered = repr(value)
        for canary in ("/proc/", "command line", "username", "raw json"):
            self.assertNotIn(canary, rendered.casefold())


class LinuxFirewallPolicyEvaluatorTests(unittest.TestCase):
    def evaluate(self, value, current_subject=None):
        return evaluate_linux_listener_policy(current_subject or subject(), value)

    def test_empty_ruleset_and_accept_policy_are_no_match_defaults(self):
        empty = self.evaluate(snapshot())
        accepted = self.evaluate(snapshot(table("t", chain("input"))))
        self.assertEqual(empty.applicability, FirewallRuleApplicability.NO_MATCH)
        self.assertEqual(empty.default_policy_context, FirewallDefaultPolicyContext.UNKNOWN)
        self.assertEqual(accepted.applicability, FirewallRuleApplicability.NO_MATCH)
        self.assertEqual(accepted.default_policy_context, FirewallDefaultPolicyContext.ALLOW)
        self.assertEqual(
            accepted.evaluated_policy_disposition,
            EvaluatedPolicyDisposition.ALLOW,
        )

    def test_drop_policy_is_no_match_with_block_default_not_fabricated_rule(self):
        result = self.evaluate(snapshot(table(
            "t", chain("input", policy=LinuxChainPolicy.DROP)
        )))
        self.assertEqual(result.applicability, FirewallRuleApplicability.NO_MATCH)
        self.assertEqual(result.default_policy_context, FirewallDefaultPolicyContext.BLOCK)
        self.assertEqual(result.matches, ())
        self.assertEqual(
            result.evaluated_policy_disposition,
            EvaluatedPolicyDisposition.BLOCK,
        )
        reachability = assess_listener_reachability(
            BindExposure.ALL_INTERFACES, policy_assessment=result
        )
        self.assertEqual(
            reachability.state,
            RemoteReachabilityState.BLOCKED_BY_OBSERVED_POLICY,
        )

    def test_direct_accept_drop_and_reject_are_ordered_terminal_verdicts(self):
        cases = (
            (LinuxVerdict.ACCEPT, FirewallRuleApplicability.MATCHING_ALLOW,
             EvaluatedPolicyDisposition.ALLOW),
            (LinuxVerdict.DROP, FirewallRuleApplicability.MATCHING_BLOCK,
             EvaluatedPolicyDisposition.BLOCK),
            (LinuxVerdict.REJECT, FirewallRuleApplicability.MATCHING_BLOCK,
             EvaluatedPolicyDisposition.BLOCK),
        )
        for verdict, expected, disposition in cases:
            with self.subTest(verdict=verdict):
                result = self.evaluate(snapshot(table(
                    "t", chain("input", rule("terminal", verdict, PORT_443))
                )))
                self.assertEqual(result.applicability, expected)
                self.assertEqual(result.evaluated_policy_disposition, disposition)
                self.assertEqual(len(result.matches), 1)

    def test_nonmatch_falls_through_to_policy(self):
        result = self.evaluate(snapshot(table("t", chain(
            "input", rule("udp", LinuxVerdict.DROP, UDP),
            policy=LinuxChainPolicy.ACCEPT,
        ))))
        self.assertEqual(result.applicability, FirewallRuleApplicability.NO_MATCH)
        self.assertEqual(result.default_policy_context, FirewallDefaultPolicyContext.ALLOW)

    def test_rule_order_resolves_drop_and_accept_without_conflict(self):
        drop_first = self.evaluate(snapshot(table("t", chain(
            "input", rule("drop", LinuxVerdict.DROP), rule("allow", LinuxVerdict.ACCEPT)
        ))))
        accept_first = self.evaluate(snapshot(table("t", chain(
            "input2", rule("allow2", LinuxVerdict.ACCEPT), rule("drop2", LinuxVerdict.DROP)
        ))))
        self.assertEqual(drop_first.applicability, FirewallRuleApplicability.MATCHING_BLOCK)
        self.assertEqual(accept_first.applicability, FirewallRuleApplicability.MATCHING_ALLOW)
        self.assertEqual(drop_first.evaluated_policy_disposition,
                         EvaluatedPolicyDisposition.BLOCK)
        self.assertEqual(accept_first.evaluated_policy_disposition,
                         EvaluatedPolicyDisposition.ALLOW)
        self.assertNotEqual(drop_first.applicability, FirewallRuleApplicability.CONFLICTING)

    def test_jump_return_continues_parent_but_goto_skips_parent_remainder(self):
        child = chain("child", rule("return", LinuxVerdict.RETURN), kind=LinuxChainKind.REGULAR)
        jump_parent = chain(
            "jump-parent",
            rule("jump", LinuxVerdict.JUMP, target=child.semantic_chain_id),
            rule("drop-after-jump", LinuxVerdict.DROP),
        )
        goto_parent = chain(
            "goto-parent",
            rule("goto", LinuxVerdict.GOTO, target=child.semantic_chain_id),
            rule("drop-after-goto", LinuxVerdict.DROP),
            policy=LinuxChainPolicy.ACCEPT,
        )
        jumped = self.evaluate(snapshot(table("jump-table", jump_parent, child)))
        gone = self.evaluate(snapshot(table("goto-table", goto_parent, child)))
        self.assertEqual(jumped.applicability, FirewallRuleApplicability.MATCHING_BLOCK)
        self.assertEqual(gone.applicability, FirewallRuleApplicability.NO_MATCH)
        self.assertEqual(gone.default_policy_context, FirewallDefaultPolicyContext.ALLOW)

    def test_jump_exhaustion_resumes_but_goto_exhaustion_skips_remainder(self):
        child = chain("empty-child", kind=LinuxChainKind.REGULAR)
        jumped = self.evaluate(snapshot(table(
            "jump", chain(
                "parent",
                rule("jump", LinuxVerdict.JUMP, target=child.semantic_chain_id),
                rule("drop", LinuxVerdict.DROP),
            ), child,
        )))
        gone = self.evaluate(snapshot(table(
            "goto", chain(
                "parent",
                rule("goto", LinuxVerdict.GOTO, target=child.semantic_chain_id),
                rule("drop", LinuxVerdict.DROP),
            ), child,
        )))
        self.assertEqual(jumped.evaluated_policy_disposition,
                         EvaluatedPolicyDisposition.BLOCK)
        self.assertEqual(gone.evaluated_policy_disposition,
                         EvaluatedPolicyDisposition.ALLOW)

    def test_nested_chain_and_terminal_child_verdict(self):
        leaf = chain("leaf", rule("leaf-drop", LinuxVerdict.DROP), kind=LinuxChainKind.REGULAR)
        middle = chain("middle", rule("middle-jump", LinuxVerdict.JUMP,
                                      target=leaf.semantic_chain_id), kind=LinuxChainKind.REGULAR)
        base = chain("base", rule("base-jump", LinuxVerdict.JUMP,
                                  target=middle.semantic_chain_id))
        result = self.evaluate(snapshot(table("t", base, middle, leaf)))
        self.assertEqual(result.applicability, FirewallRuleApplicability.MATCHING_BLOCK)

    def test_chain_depth_and_traversal_step_exact_boundaries(self):
        child = chain("bounded-child", kind=LinuxChainKind.REGULAR)
        base = chain(
            "bounded-base",
            rule("bounded-jump", LinuxVerdict.JUMP,
                 target=child.semantic_chain_id),
        )
        value = snapshot(table("bounded-depth", base, child))
        with patch(
            "cyberwatchtower.platform.linux.firewall_evaluator.MAX_LINUX_CHAIN_DEPTH",
            2,
        ):
            self.assertEqual(
                self.evaluate(value).evaluated_policy_disposition,
                EvaluatedPolicyDisposition.ALLOW,
            )
        with patch(
            "cyberwatchtower.platform.linux.firewall_evaluator.MAX_LINUX_CHAIN_DEPTH",
            1,
        ):
            self.assertEqual(
                self.evaluate(value).evaluated_policy_disposition,
                EvaluatedPolicyDisposition.NOT_ESTABLISHED,
            )
        one_step = snapshot(table(
            "one-step", chain("one-step", rule("allow", LinuxVerdict.ACCEPT))
        ))
        two_steps = snapshot(table(
            "two-steps", chain(
                "two-steps",
                rule("continue", LinuxVerdict.CONTINUE),
                rule("allow", LinuxVerdict.ACCEPT),
            )
        ))
        with patch(
            "cyberwatchtower.platform.linux.firewall_evaluator.MAX_LINUX_TRAVERSAL_STEPS",
            1,
        ):
            self.assertEqual(
                self.evaluate(one_step).evaluated_policy_disposition,
                EvaluatedPolicyDisposition.ALLOW,
            )
            self.assertEqual(
                self.evaluate(two_steps).evaluated_policy_disposition,
                EvaluatedPolicyDisposition.NOT_ESTABLISHED,
            )

    def test_jump_targets_are_scoped_to_referring_table_and_family(self):
        local_target = chain(
            "target", rule("local-drop", LinuxVerdict.DROP),
            kind=LinuxChainKind.REGULAR,
        )
        foreign_target = chain(
            "target", rule("foreign-allow", LinuxVerdict.ACCEPT),
            kind=LinuxChainKind.REGULAR,
        )
        parent = chain(
            "parent",
            rule("jump", LinuxVerdict.JUMP,
                 target=local_target.semantic_chain_id),
        )
        same_table = self.evaluate(snapshot(
            table("local", parent, local_target),
            table("foreign", foreign_target),
        ))
        self.assertEqual(same_table.evaluated_policy_disposition,
                         EvaluatedPolicyDisposition.BLOCK)

        missing_local = self.evaluate(snapshot(
            table("local", parent),
            table("foreign", foreign_target),
        ))
        self.assertEqual(missing_local.applicability,
                         FirewallRuleApplicability.INCOMPLETE)
        self.assertEqual(missing_local.evaluated_policy_disposition,
                         EvaluatedPolicyDisposition.NOT_ESTABLISHED)

        cross_family = self.evaluate(snapshot(
            table("ipv4-parent", parent, family=LinuxFirewallFamily.IPV4),
            table("inet-target", foreign_target, family=LinuxFirewallFamily.INET),
        ))
        self.assertEqual(cross_family.applicability,
                         FirewallRuleApplicability.INCOMPLETE)
        self.assertEqual(cross_family.evaluated_policy_disposition,
                         EvaluatedPolicyDisposition.NOT_ESTABLISHED)

    def test_missing_target_cycle_depth_and_step_limits_are_incomplete(self):
        missing = chain("missing-base", rule("missing", LinuxVerdict.JUMP, target=digest("absent")))
        a_id, b_id = digest("a"), digest("b")
        a = LinuxFirewallChain(a_id, LinuxChainKind.BASE,
            (rule("a-jump", LinuxVerdict.JUMP, target=b_id),),
            LinuxFirewallHook.INPUT, 0, LinuxChainPolicy.ACCEPT)
        b = LinuxFirewallChain(b_id, LinuxChainKind.REGULAR,
            (rule("b-jump", LinuxVerdict.JUMP, target=a_id),))
        self.assertEqual(self.evaluate(snapshot(table("missing", missing))).applicability,
                         FirewallRuleApplicability.INCOMPLETE)
        missing_result = self.evaluate(snapshot(table("missing", missing)))
        cycle_result = self.evaluate(snapshot(table("cycle", a, b)))
        self.assertEqual(missing_result.evaluated_policy_disposition,
                         EvaluatedPolicyDisposition.NOT_ESTABLISHED)
        self.assertEqual(cycle_result.applicability,
                         FirewallRuleApplicability.INCOMPLETE)
        self.assertEqual(cycle_result.evaluated_policy_disposition,
                         EvaluatedPolicyDisposition.NOT_ESTABLISHED)
        child = chain("depth-child", rule("ret", LinuxVerdict.RETURN), kind=LinuxChainKind.REGULAR)
        base = chain("depth-base", rule("to-child", LinuxVerdict.JUMP, target=child.semantic_chain_id))
        with patch("cyberwatchtower.platform.linux.firewall_evaluator.MAX_LINUX_CHAIN_DEPTH", 1):
            depth_result = self.evaluate(snapshot(table("depth", base, child)))
            self.assertEqual(depth_result.applicability,
                             FirewallRuleApplicability.INCOMPLETE)
            self.assertEqual(depth_result.evaluated_policy_disposition,
                             EvaluatedPolicyDisposition.NOT_ESTABLISHED)
        steps = chain("steps", rule("continue", LinuxVerdict.CONTINUE),
                      rule("accept", LinuxVerdict.ACCEPT))
        with patch("cyberwatchtower.platform.linux.firewall_evaluator.MAX_LINUX_TRAVERSAL_STEPS", 1):
            step_result = self.evaluate(snapshot(table("steps", steps)))
            self.assertEqual(step_result.applicability,
                             FirewallRuleApplicability.INCOMPLETE)
            self.assertEqual(step_result.evaluated_policy_disposition,
                             EvaluatedPolicyDisposition.NOT_ESTABLISHED)

    def test_multiple_base_chains_use_priority_and_later_drop_can_override_accept(self):
        later_drop = chain("later", rule("later-drop", LinuxVerdict.DROP), priority=10)
        earlier_accept = chain("earlier", rule("early-accept", LinuxVerdict.ACCEPT), priority=-10)
        result = self.evaluate(snapshot(table("t", later_drop, earlier_accept)))
        self.assertEqual(result.applicability, FirewallRuleApplicability.MATCHING_BLOCK)
        self.assertEqual(result.evaluated_policy_disposition,
                         EvaluatedPolicyDisposition.BLOCK)

    def test_matching_allow_followed_by_later_base_drop_retains_allow_evidence(self):
        result = self.evaluate(snapshot(table(
            "t",
            chain("early", rule("allow", LinuxVerdict.ACCEPT), priority=-10),
            chain("late", policy=LinuxChainPolicy.DROP, priority=10),
        )))
        self.assertEqual(result.applicability,
                         FirewallRuleApplicability.MATCHING_ALLOW)
        self.assertEqual(result.default_policy_context,
                         FirewallDefaultPolicyContext.BLOCK)
        self.assertEqual(result.evaluated_policy_disposition,
                         EvaluatedPolicyDisposition.BLOCK)
        self.assertEqual(len(result.matches), 1)

    def test_equal_relevant_priority_is_incomplete(self):
        result = self.evaluate(snapshot(table(
            "t", chain("a", priority=0), chain("b", priority=0)
        )))
        self.assertEqual(result.applicability, FirewallRuleApplicability.INCOMPLETE)
        self.assertEqual(result.evaluated_policy_disposition,
                         EvaluatedPolicyDisposition.NOT_ESTABLISHED)

    def test_unknown_base_policy_does_not_establish_disposition(self):
        result = self.evaluate(snapshot(table(
            "unknown", chain("input", policy=LinuxChainPolicy.UNKNOWN)
        )))
        self.assertEqual(result.applicability,
                         FirewallRuleApplicability.INCOMPLETE)
        self.assertEqual(result.evaluated_policy_disposition,
                         EvaluatedPolicyDisposition.NOT_ESTABLISHED)

    def test_inet_ipv4_ipv6_family_and_tcp_udp_port_ranges(self):
        family_cases = (
            (LinuxFirewallFamily.INET, subject(), FirewallRuleApplicability.MATCHING_ALLOW),
            (LinuxFirewallFamily.IPV4, subject(), FirewallRuleApplicability.MATCHING_ALLOW),
            (LinuxFirewallFamily.IPV6, subject(local_address="::"), FirewallRuleApplicability.MATCHING_ALLOW),
        )
        for family, current, expected in family_cases:
            with self.subTest(family=family):
                result = self.evaluate(snapshot(table(
                    family.value, chain(f"chain-{family.value}", rule(
                        f"rule-{family.value}", LinuxVerdict.ACCEPT,
                        predicate(LinuxPredicateKind.FAMILY, family), TCP,
                        predicate(LinuxPredicateKind.DESTINATION_PORT,
                                  (FirewallPortRange(400, 500),)),
                    )), family=family
                )), current)
                self.assertEqual(result.applicability, expected)
        udp_result = self.evaluate(snapshot(table("udp-table", chain(
            "udp-chain", rule("udp-rule", LinuxVerdict.ACCEPT, UDP, PORT_443)
        ))), subject(protocol=NetworkProtocol.UDP))
        self.assertEqual(udp_result.applicability, FirewallRuleApplicability.MATCHING_ALLOW)

    def test_source_interface_and_ct_uncertainty_are_predicate_local(self):
        uncertain = (
            predicate(LinuxPredicateKind.SOURCE_ADDRESS,
                      (FirewallAddressCondition(AddressConditionKind.CIDR, "192.0.2.0/24"),)),
            predicate(LinuxPredicateKind.INBOUND_INTERFACE,
                      FirewallInterfaceCondition(InterfaceConditionKind.LAN)),
            predicate(LinuxPredicateKind.CT_STATE, LinuxCtState.NEW),
        )
        for index, expression in enumerate(uncertain):
            with self.subTest(expression=expression.kind):
                relevant = self.evaluate(snapshot(table(f"t{index}", chain(
                    f"c{index}", rule(f"r{index}", LinuxVerdict.DROP, expression)
                ))))
                irrelevant = self.evaluate(snapshot(table(f"ti{index}", chain(
                    f"ci{index}", rule(f"ri{index}", LinuxVerdict.DROP, UDP, expression)
                ))))
                self.assertEqual(relevant.applicability, FirewallRuleApplicability.INCOMPLETE)
                self.assertEqual(irrelevant.applicability, FirewallRuleApplicability.NO_MATCH)

    def test_known_destination_and_interface_can_be_evaluated(self):
        address = predicate(LinuxPredicateKind.DESTINATION_ADDRESS,
                            (FirewallAddressCondition(AddressConditionKind.CIDR, "0.0.0.0/0"),))
        interface = predicate(LinuxPredicateKind.INBOUND_INTERFACE,
                              FirewallInterfaceCondition(InterfaceConditionKind.LAN))
        result = self.evaluate(snapshot(table("t", chain(
            "c", rule("r", LinuxVerdict.ACCEPT, address, interface)
        ))), subject(interface=InterfaceConditionKind.LAN))
        self.assertEqual(result.applicability, FirewallRuleApplicability.MATCHING_ALLOW)

    def test_wildcard_destination_is_not_treated_as_literal_address(self):
        ipv4 = predicate(
            LinuxPredicateKind.DESTINATION_ADDRESS,
            (FirewallAddressCondition(AddressConditionKind.CIDR,
                                      "192.0.2.0/24"),),
        )
        ipv6 = predicate(
            LinuxPredicateKind.DESTINATION_ADDRESS,
            (FirewallAddressCondition(AddressConditionKind.CIDR,
                                      "2001:db8::/64"),),
        )
        cases = (
            (subject(local_address="0.0.0.0"), ipv4),
            (subject(local_address="::"), ipv6),
        )
        for current, expression in cases:
            with self.subTest(address=current.local_address):
                result = self.evaluate(snapshot(table(
                    "wildcard", chain(
                        "input", rule("drop", LinuxVerdict.DROP, expression)
                    )
                )), current)
                self.assertEqual(result.applicability,
                                 FirewallRuleApplicability.INCOMPLETE)
                self.assertEqual(
                    result.evaluated_policy_disposition,
                    EvaluatedPolicyDisposition.NOT_ESTABLISHED,
                )

    def test_concrete_destination_match_and_mismatch_for_both_families(self):
        cases = (
            ("192.0.2.4", "192.0.2.0/24", "198.51.100.0/24",
             LinuxFirewallFamily.IPV4),
            ("2001:db8::4", "2001:db8::/64", "2001:db9::/64",
             LinuxFirewallFamily.IPV6),
        )
        for address, matching, nonmatching, family in cases:
            with self.subTest(address=address):
                def result_for(network):
                    expression = predicate(
                        LinuxPredicateKind.DESTINATION_ADDRESS,
                        (FirewallAddressCondition(AddressConditionKind.CIDR,
                                                  network),),
                    )
                    return self.evaluate(snapshot(table(
                        "destination", chain(
                            "input", rule("drop", LinuxVerdict.DROP, expression)
                        ), family=family,
                    )), subject(local_address=address))

                self.assertEqual(
                    result_for(matching).evaluated_policy_disposition,
                    EvaluatedPolicyDisposition.BLOCK,
                )
                self.assertEqual(
                    result_for(nonmatching).evaluated_policy_disposition,
                    EvaluatedPolicyDisposition.ALLOW,
                )

    def test_unsupported_expression_is_ignored_only_when_rule_or_flow_is_irrelevant(self):
        after_terminal = self.evaluate(snapshot(table("t", chain(
            "c", rule("allow", LinuxVerdict.ACCEPT),
            rule("unsupported", LinuxVerdict.DROP, UNSUPPORTED),
        ))))
        protocol_irrelevant = self.evaluate(snapshot(table("t2", chain(
            "c2", rule("unsupported-udp", LinuxVerdict.DROP, UDP, UNSUPPORTED)
        ))))
        relevant = self.evaluate(snapshot(table("t3", chain(
            "c3", rule("unsupported-relevant", LinuxVerdict.DROP, TCP, UNSUPPORTED)
        ))))
        self.assertEqual(after_terminal.applicability, FirewallRuleApplicability.MATCHING_ALLOW)
        self.assertEqual(protocol_irrelevant.applicability, FirewallRuleApplicability.NO_MATCH)
        self.assertEqual(relevant.applicability, FirewallRuleApplicability.INCOMPLETE)

    def test_irrelevant_hooks_do_not_poison_and_unknown_input_family_is_unsupported(self):
        irrelevant = chain("forward", rule("bad", LinuxVerdict.DROP, UNSUPPORTED),
                           hook=LinuxFirewallHook.FORWARD)
        result = self.evaluate(snapshot(table("t", irrelevant)))
        self.assertEqual(result.applicability, FirewallRuleApplicability.NO_MATCH)
        unsupported = self.evaluate(snapshot(table(
            "unknown", chain("input"), family=LinuxFirewallFamily.UNKNOWN
        )))
        self.assertEqual(unsupported.applicability, FirewallRuleApplicability.UNSUPPORTED)
        self.assertEqual(unsupported.collection_coverage, CoverageState.COMPLETE)

    def test_opposite_family_address_range_is_a_known_nonmatch(self):
        ipv6_range = predicate(
            LinuxPredicateKind.DESTINATION_ADDRESS,
            (FirewallAddressCondition(
                AddressConditionKind.IPV6_RANGE,
                FirewallIPv6AddressRange(
                    ipaddress.IPv6Address("2001:db8::1"),
                    ipaddress.IPv6Address("2001:db8::ffff"),
                ),
            ),),
        )
        result = self.evaluate(snapshot(table("t", chain(
            "c", rule("r", LinuxVerdict.DROP, ipv6_range),
            policy=LinuxChainPolicy.ACCEPT,
        ))))
        self.assertEqual(result.applicability, FirewallRuleApplicability.NO_MATCH)
        self.assertEqual(result.default_policy_context, FirewallDefaultPolicyContext.ALLOW)

    def test_owner_cgroup_set_and_map_features_remain_incomplete(self):
        features = (
            LinuxFirewallUnsupportedFeature.UID_GID_OR_OWNER,
            LinuxFirewallUnsupportedFeature.CGROUP,
            LinuxFirewallUnsupportedFeature.UNRESOLVED_NAMED_SET,
            LinuxFirewallUnsupportedFeature.DYNAMIC_SET,
            LinuxFirewallUnsupportedFeature.MAP,
            LinuxFirewallUnsupportedFeature.VERDICT_MAP,
        )
        for index, feature in enumerate(features):
            with self.subTest(feature=feature):
                result = self.evaluate(snapshot(table(f"t{index}", chain(
                    f"c{index}", rule(f"r{index}", LinuxVerdict.ACCEPT,
                        predicate(LinuxPredicateKind.UNSUPPORTED, feature))
                ))))
                self.assertEqual(result.applicability, FirewallRuleApplicability.INCOMPLETE)

    def test_unknown_namespace_is_incomplete_and_aligned_namespace_evaluates(self):
        unknown = self.evaluate(snapshot(alignment=LinuxNamespaceAlignment.UNKNOWN))
        aligned = self.evaluate(snapshot())
        self.assertEqual(unknown.applicability, FirewallRuleApplicability.INCOMPLETE)
        self.assertEqual(aligned.applicability, FirewallRuleApplicability.NO_MATCH)

    def test_repeated_evaluation_is_deterministic_and_never_conflicting(self):
        value = snapshot(table("t", chain("c", rule("r", LinuxVerdict.ACCEPT, TCP))))
        first = self.evaluate(value)
        self.assertEqual(first, self.evaluate(value))
        self.assertNotEqual(first.applicability, FirewallRuleApplicability.CONFLICTING)
        self.assertNotIn("CONFIRMED_REACHABLE", repr(first))

    def test_linux_policy_never_confirms_reachability(self):
        policies = (
            self.evaluate(snapshot(table(
                "allow", chain("input", policy=LinuxChainPolicy.ACCEPT)
            ))),
            self.evaluate(snapshot(table(
                "block", chain("input", policy=LinuxChainPolicy.DROP)
            ))),
        )
        for policy in policies:
            with self.subTest(disposition=policy.evaluated_policy_disposition):
                reachability = assess_listener_reachability(
                    BindExposure.ALL_INTERFACES,
                    policy_assessment=policy,
                )
                self.assertNotEqual(
                    reachability.state,
                    RemoteReachabilityState.CONFIRMED_REACHABLE,
                )


if __name__ == "__main__":
    unittest.main()
