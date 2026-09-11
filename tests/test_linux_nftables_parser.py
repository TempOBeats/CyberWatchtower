import json
import unittest

from cyberwatchtower.firewall_policy import (
    AddressConditionKind,
    EvaluatedPolicyDisposition,
    FirewallDefaultPolicyContext,
    FirewallRuleApplicability,
    InterfaceConditionKind,
    ListenerPolicySubject,
)
from cyberwatchtower.platform.linux.firewall_contracts import (
    LinuxChainKind,
    LinuxChainPolicy,
    LinuxCtState,
    LinuxFirewallFamily,
    LinuxFirewallHook,
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
from cyberwatchtower.platform.linux.firewall_evaluator import (
    evaluate_linux_listener_policy,
)
from cyberwatchtower.platform.linux.nftables_contracts import (
    MAX_NFT_JSON_BYTES,
    NftObjectClassification,
    NftParseStatus,
)
from cyberwatchtower.platform.linux import nftables_parser
from cyberwatchtower.platform.linux.nftables_parser import parse_nftables_json
from cyberwatchtower.platform.models import BindExposure, FirewallProfile, NetworkProtocol


def document(*objects):
    return json.dumps({"nftables": list(objects)}, separators=(",", ":"))


def table(name="filter", family="inet", **extra):
    return {"table": {"family": family, "name": name, **extra}}


def chain(name="input", table_name="filter", family="inet", *, hook="input",
          priority=0, policy="accept", chain_type="filter", **extra):
    value = {"family": family, "table": table_name, "name": name, **extra}
    if hook is not None:
        value.update({"type": chain_type, "hook": hook, "prio": priority, "policy": policy})
    return {"chain": value}


def rule(*expressions, chain_name="input", table_name="filter", family="inet", **extra):
    return {"rule": {
        "family": family, "table": table_name, "chain": chain_name,
        "expr": list(expressions), **extra,
    }}


def match(protocol, field, right):
    return {"match": {
        "op": "==",
        "left": {"payload": {"protocol": protocol, "field": field}},
        "right": right,
    }}


def verdict(name, target=None):
    return {name: None if target is None else {"target": target}}


def subject(address="0.0.0.0", protocol=NetworkProtocol.TCP, port=443):
    return ListenerPolicySubject(
        protocol, port, BindExposure.ALL_INTERFACES, address,
        (FirewallProfile.DEFAULT,),
    )


class NftablesParserContractTests(unittest.TestCase):
    def test_closed_contract_and_frozen_bounds(self):
        self.assertEqual(MAX_NFT_JSON_BYTES, 8 * 1024 * 1024)
        self.assertEqual((
            MAX_LINUX_FIREWALL_TABLES, MAX_LINUX_FIREWALL_CHAINS,
            MAX_LINUX_FIREWALL_RULES, MAX_LINUX_EXPRESSIONS_PER_RULE,
            MAX_LINUX_INLINE_SET_VALUES, MAX_LINUX_NORMALIZED_TOKEN_LENGTH,
        ), (256, 8192, 8192, 64, 256, 256))
        self.assertEqual(
            {item.value for item in NftObjectClassification},
            {"SUPPORTED_POLICY_OBJECT", "IGNORABLE_METADATA",
             "UNSUPPORTED_POLICY_OBJECT", "INVALID_OBJECT"},
        )
        self.assertEqual(
            {item.value for item in NftParseStatus},
            {"SUCCESS", "INPUT_TOO_LARGE", "INVALID_JSON", "INVALID_ROOT",
             "STRUCTURAL_LIMIT_EXCEEDED", "INVALID_VALUE",
             "UNSUPPORTED_SEMANTICS", "INCOMPLETE_SEMANTICS"},
        )

    def test_valid_root_and_known_metadata(self):
        result = parse_nftables_json(document(
            {"metainfo": {"version": "1.0.9", "release_name": "fixture"}},
            table(), chain(),
        ))
        self.assertEqual(result.status, NftParseStatus.SUCCESS)
        self.assertEqual(len(result.snapshot.tables), 1)

    def test_size_bound_precedes_decode_for_bytes_and_text(self):
        for value in (b"x" * (MAX_NFT_JSON_BYTES + 1), "x" * (MAX_NFT_JSON_BYTES + 1)):
            with self.subTest(kind=type(value).__name__):
                self.assertEqual(
                    parse_nftables_json(value).status,
                    NftParseStatus.INPUT_TOO_LARGE,
                )

    def test_exact_size_invalid_bytes_and_multibyte_text_use_byte_precedence(self):
        valid = b'{"nftables":[]}'
        exact = valid + b" " * (MAX_NFT_JSON_BYTES - len(valid))
        self.assertEqual(parse_nftables_json(exact).status, NftParseStatus.SUCCESS)
        self.assertEqual(
            parse_nftables_json(b"\xff" * (MAX_NFT_JSON_BYTES + 1)).status,
            NftParseStatus.INPUT_TOO_LARGE,
        )
        multibyte = "é" * (MAX_NFT_JSON_BYTES // 2 + 1)
        self.assertLessEqual(len(multibyte), MAX_NFT_JSON_BYTES)
        self.assertEqual(
            parse_nftables_json(multibyte).status,
            NftParseStatus.INPUT_TOO_LARGE,
        )

    def test_invalid_json_and_root_shapes_fail_closed(self):
        cases = (
            ("{", NftParseStatus.INVALID_JSON),
            ("[]", NftParseStatus.INVALID_ROOT),
            ("{}", NftParseStatus.INVALID_ROOT),
            ('{"nftables":{}}', NftParseStatus.INVALID_ROOT),
            ('{"nftables":[],"extra":true}', NftParseStatus.INVALID_ROOT),
        )
        for value, expected in cases:
            with self.subTest(value=value):
                result = parse_nftables_json(value)
                self.assertEqual(result.status, expected)
                self.assertIsNone(result.snapshot)

    def test_table_chain_and_rule_global_limits_fail_closed(self):
        cases = (
            [table(str(index)) for index in range(MAX_LINUX_FIREWALL_TABLES + 1)],
            [table()] + [chain(str(index), hook=None) for index in range(MAX_LINUX_FIREWALL_CHAINS + 1)],
            [table(), chain()] + [rule(chain_name="input") for _ in range(MAX_LINUX_FIREWALL_RULES + 1)],
        )
        for objects in cases:
            with self.subTest(size=len(objects)):
                self.assertEqual(
                    parse_nftables_json(document(*objects)).status,
                    NftParseStatus.STRUCTURAL_LIMIT_EXCEEDED,
                )

    def test_expression_inline_set_and_token_limits_fail_closed(self):
        too_many_expressions = rule(*({"counter": {}} for _ in range(MAX_LINUX_EXPRESSIONS_PER_RULE + 1)))
        too_many_values = rule(
            match("tcp", "dport", {"set": list(range(MAX_LINUX_INLINE_SET_VALUES + 1))})
        )
        too_long = table("x" * (MAX_LINUX_NORMALIZED_TOKEN_LENGTH + 1))
        for value in (too_many_expressions, too_many_values, too_long):
            with self.subTest(value=next(iter(value))):
                self.assertEqual(
                    parse_nftables_json(document(table(), chain(), value)).status,
                    NftParseStatus.STRUCTURAL_LIMIT_EXCEEDED,
                )
        unicode_token = "é" * 129
        self.assertLessEqual(len(unicode_token), MAX_LINUX_NORMALIZED_TOKEN_LENGTH)
        self.assertEqual(
            parse_nftables_json(document(table(unicode_token))).status,
            NftParseStatus.STRUCTURAL_LIMIT_EXCEEDED,
        )

    def test_malformed_family_priority_ports_and_cidr_fail_closed(self):
        malformed = (
            document(table(family="future")),
            document(table(), chain(priority="filter")),
            document(table(), chain(), rule(match("tcp", "dport", -1))),
            document(table(), chain(), rule(match("tcp", "dport", 65536))),
            document(table(), chain(), rule(match("tcp", "dport", {"range": [90, 80]}))),
            document(table(), chain(), rule(match("ip", "daddr", "not-a-network"))),
        )
        expected = (
            NftParseStatus.INVALID_VALUE, NftParseStatus.INCOMPLETE_SEMANTICS,
            NftParseStatus.INVALID_VALUE, NftParseStatus.INVALID_VALUE,
            NftParseStatus.INVALID_VALUE, NftParseStatus.INVALID_VALUE,
        )
        for value, status in zip(malformed, expected):
            with self.subTest(status=status):
                self.assertEqual(parse_nftables_json(value).status, status)

    def test_bool_mixed_set_and_address_family_mismatches_fail_closed(self):
        cases = [
            match("tcp", "dport", True),
            match("tcp", "dport", False),
            match("tcp", "dport", {"set": [443, "https"]}),
            match("ip", "saddr", "2001:db8::/64"),
            match("ip", "daddr", "2001:db8::/64"),
            match("ip6", "saddr", "192.0.2.0/24"),
            match("ip6", "daddr", "192.0.2.0/24"),
        ]
        for expression in cases:
            with self.subTest(expression=expression):
                self.assertEqual(
                    parse_nftables_json(
                        document(table(), chain(), rule(expression, verdict("accept")))
                    ).status,
                    NftParseStatus.INVALID_VALUE,
                )

    def test_raw_duplicate_inline_set_limit_precedes_deduplication(self):
        accepted = match(
            "tcp", "dport", {"set": [80] * MAX_LINUX_INLINE_SET_VALUES}
        )
        rejected = match(
            "tcp", "dport", {"set": [80] * (MAX_LINUX_INLINE_SET_VALUES + 1)}
        )

        self.assertEqual(
            parse_nftables_json(
                document(table(), chain(), rule(accepted, verdict("accept")))
            ).status,
            NftParseStatus.SUCCESS,
        )
        self.assertEqual(
            parse_nftables_json(
                document(table(), chain(), rule(rejected, verdict("accept")))
            ).status,
            NftParseStatus.STRUCTURAL_LIMIT_EXCEEDED,
        )

    def test_unsupported_hook_declarations_are_counted_before_filtering(self):
        accepted = [table()] + [
            chain(str(index), hook="future-hook")
            for index in range(MAX_LINUX_FIREWALL_CHAINS)
        ]
        rejected = [*accepted, chain("overflow", hook="future-hook")]
        self.assertEqual(
            parse_nftables_json(document(*accepted)).status,
            NftParseStatus.UNSUPPORTED_SEMANTICS,
        )
        self.assertEqual(
            parse_nftables_json(document(*rejected)).status,
            NftParseStatus.STRUCTURAL_LIMIT_EXCEEDED,
        )

    def test_fatal_later_object_overrides_earlier_valid_structure(self):
        result = parse_nftables_json(document(table(), chain(), {"rule": None}))
        self.assertEqual(result.status, NftParseStatus.INVALID_VALUE)
        self.assertIsNone(result.snapshot)


class NftablesParserNormalizationTests(unittest.TestCase):
    def parse(self, *objects):
        result = parse_nftables_json(document(*objects))
        self.assertIsNotNone(result.snapshot)
        return result

    def test_supported_families_input_base_chain_and_priority(self):
        for actual in ("inet", "ip", "ip6"):
            with self.subTest(family=actual):
                result = self.parse(table(family=actual), chain(family=actual, priority=-20))
                current = result.snapshot.tables[0]
                self.assertEqual(current.family, LinuxFirewallFamily(actual))
                self.assertEqual(current.chains[0].hook, LinuxFirewallHook.INPUT)
                self.assertEqual(current.chains[0].priority, -20)

    def test_regular_chains_and_non_input_hooks_are_preserved_for_l2_filtering(self):
        result = self.parse(
            table(), chain("regular", hook=None), chain("output", hook="output", priority=4)
        )
        regular, output = result.snapshot.tables[0].chains
        self.assertEqual(regular.kind, LinuxChainKind.REGULAR)
        self.assertEqual(output.hook, LinuxFirewallHook.OUTPUT)

    def test_recognized_non_input_family_is_retained_as_unsupported(self):
        result = self.parse(
            table(family="bridge"), chain(family="bridge", hook="input")
        )
        self.assertEqual(result.status, NftParseStatus.UNSUPPORTED_SEMANTICS)
        self.assertEqual(result.snapshot.tables[0].family, LinuxFirewallFamily.BRIDGE)

    def test_base_policies_and_rule_order_are_preserved(self):
        for policy, expected in (("accept", LinuxChainPolicy.ACCEPT), ("drop", LinuxChainPolicy.DROP)):
            with self.subTest(policy=policy):
                parsed = self.parse(
                    table(), chain(policy=policy),
                    rule(verdict("accept")), rule(verdict("drop")),
                ).snapshot.tables[0].chains[0]
                self.assertEqual(parsed.policy, expected)
                self.assertEqual(
                    tuple(item.verdict for item in parsed.rules),
                    (LinuxVerdict.ACCEPT, LinuxVerdict.DROP),
                )

    def test_all_supported_verdicts_and_distinct_jump_goto_targets(self):
        objects = [table(), chain(), chain("child", hook=None)]
        names = ("accept", "drop", "reject", "return")
        objects.extend(rule(verdict(name)) for name in names)
        objects.extend((rule(verdict("jump", "child")), rule(verdict("goto", "child"))))
        rules = self.parse(*objects).snapshot.tables[0].chains[0].rules
        self.assertEqual(
            tuple(item.verdict for item in rules),
            (LinuxVerdict.ACCEPT, LinuxVerdict.DROP, LinuxVerdict.REJECT,
             LinuxVerdict.RETURN, LinuxVerdict.JUMP, LinuxVerdict.GOTO),
        )
        self.assertEqual(rules[-2].target_chain_id, rules[-1].target_chain_id)

    def test_tcp_udp_single_range_and_inline_port_set(self):
        expressions = (
            match("tcp", "dport", 443),
            match("udp", "dport", {"range": [500, 510]}),
            match("tcp", "dport", {"set": [80, {"range": [8000, 8002]}]}),
        )
        parsed = self.parse(
            table(), chain(), *(rule(item, verdict("accept")) for item in expressions)
        ).snapshot.tables[0].chains[0].rules
        self.assertEqual(parsed[0].expressions[0].value, NetworkProtocol.TCP)
        self.assertEqual(parsed[1].expressions[0].value, NetworkProtocol.UDP)
        self.assertEqual((parsed[1].expressions[1].value[0].start,
                          parsed[1].expressions[1].value[0].end), (500, 510))
        self.assertEqual(len(parsed[2].expressions[1].value), 2)

    def test_ipv4_ipv6_source_and_destination_cidrs(self):
        cases = (
            ("ip", "saddr", LinuxPredicateKind.SOURCE_ADDRESS, "192.0.2.0/24"),
            ("ip", "daddr", LinuxPredicateKind.DESTINATION_ADDRESS, "198.51.100.0/24"),
            ("ip6", "saddr", LinuxPredicateKind.SOURCE_ADDRESS, "2001:db8::/64"),
            ("ip6", "daddr", LinuxPredicateKind.DESTINATION_ADDRESS, "2001:db9::/64"),
        )
        for protocol, field, expected, network in cases:
            with self.subTest(protocol=protocol, field=field):
                expressions = self.parse(
                    table(), chain(), rule(match(protocol, field, network), verdict("accept"))
                ).snapshot.tables[0].chains[0].rules[0].expressions
                parsed = expressions[1]
                self.assertEqual(expressions[0].kind, LinuxPredicateKind.FAMILY)
                self.assertEqual(parsed.kind, expected)
                self.assertEqual(parsed.value[0].kind, AddressConditionKind.CIDR)

    def test_ct_state_and_interface_are_normalized_without_raw_name(self):
        ct = {"match": {"op": "==", "left": {"ct": {"key": "state"}}, "right": "new"}}
        interface = {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "private-lan0"}}
        result = self.parse(table(), chain(), rule(ct, interface, verdict("accept")))
        expressions = result.snapshot.tables[0].chains[0].rules[0].expressions
        self.assertEqual(expressions[0].value, LinuxCtState.NEW)
        self.assertEqual(expressions[1].value.kind, InterfaceConditionKind.INTERFACE_DIGEST)
        self.assertEqual(len(expressions[1].value.value), 64)
        self.assertNotIn("private-lan0", repr(result.snapshot))

    def test_counter_comment_and_handle_do_not_change_semantics_or_identity(self):
        plain = self.parse(table(), chain(), rule(verdict("accept"))).snapshot
        decorated = self.parse(
            table(handle=9, comment="table comment"),
            chain(handle=10, comment="chain comment"),
            rule({"counter": {"packets": 4, "bytes": 80}},
                 {"comment": "rule comment"}, verdict("accept"),
                 handle=11, comment="outer comment"),
        ).snapshot
        self.assertEqual(plain, decorated)
        self.assertNotIn("comment", repr(decorated).casefold())

    def test_unknown_object_downgrades_retained_snapshot_authority(self):
        result = self.parse(table(), chain(), {"future-policy-object": {"value": 1}})
        self.assertEqual(result.status, NftParseStatus.UNSUPPORTED_SEMANTICS)
        self.assertEqual(result.snapshot.namespace_alignment, LinuxNamespaceAlignment.UNKNOWN)

    def test_unknown_expression_verdict_and_named_set_are_unsupported(self):
        cases = (
            {"future": {"value": 1}},
            {"queue": None},
            match("tcp", "dport", {"set_ref": "web-ports"}),
        )
        for expression in cases:
            with self.subTest(expression=expression):
                result = self.parse(table(), chain(), rule(expression, verdict("accept")))
                self.assertEqual(result.status, NftParseStatus.UNSUPPORTED_SEMANTICS)
                predicates = result.snapshot.tables[0].chains[0].rules[0].expressions
                self.assertTrue(any(item.kind == LinuxPredicateKind.UNSUPPORTED for item in predicates))

    def test_unknown_rule_field_and_base_chain_type_poison_l2_proof(self):
        cases = (
            (chain(), rule(verdict("drop"), future_semantic=True)),
            (chain(chain_type="nat"), rule(verdict("drop"))),
        )
        for chain_object, rule_object in cases:
            with self.subTest(chain=chain_object):
                result = self.parse(table(), chain_object, rule_object)
                assessment = evaluate_linux_listener_policy(subject(), result.snapshot)
                self.assertEqual(result.status, NftParseStatus.UNSUPPORTED_SEMANTICS)
                self.assertEqual(assessment.applicability, FirewallRuleApplicability.INCOMPLETE)
                self.assertEqual(
                    assessment.evaluated_policy_disposition,
                    EvaluatedPolicyDisposition.NOT_ESTABLISHED,
                )

    def test_unknown_ct_state_and_unknown_policy_cannot_prove_policy(self):
        ct = {"match": {
            "op": "==", "left": {"ct": {"key": "state"}}, "right": "future",
        }}
        cases = (
            (chain(), rule(ct, verdict("drop"))),
            (chain(policy="queue"),),
        )
        for policy_objects in cases:
            with self.subTest(policy_objects=policy_objects):
                result = parse_nftables_json(
                    document(table(), *policy_objects),
                    namespace_alignment=LinuxNamespaceAlignment.SAME_CURRENT_NAMESPACE,
                )
                self.assertEqual(result.status, NftParseStatus.UNSUPPORTED_SEMANTICS)
                assessment = evaluate_linux_listener_policy(subject(), result.snapshot)
                self.assertEqual(
                    assessment.evaluated_policy_disposition,
                    EvaluatedPolicyDisposition.NOT_ESTABLISHED,
                )

    def test_raw_structural_names_are_not_retained_and_output_is_deterministic(self):
        raw = document(
            table("private-table"), chain("private-chain", "private-table"),
            rule(verdict("accept"), chain_name="private-chain", table_name="private-table"),
        )
        first = parse_nftables_json(raw)
        self.assertEqual(first, parse_nftables_json(raw))
        rendered = repr(first.snapshot)
        self.assertNotIn("private-table", rendered)
        self.assertNotIn("private-chain", rendered)
        current = first.snapshot.tables[0]
        self.assertEqual(len(current.semantic_table_id), 64)
        self.assertEqual(len(current.chains[0].semantic_chain_id), 64)
        self.assertEqual(len(current.chains[0].rules[0].semantic_rule_id), 64)

    def test_identity_is_parent_scoped_through_parser_construction(self):
        result = self.parse(
            table("same", "ip"), chain("same-chain", "same", "ip"),
            rule(verdict("accept"), chain_name="same-chain", table_name="same", family="ip"),
            table("same", "ip6"), chain("same-chain", "same", "ip6"),
            rule(verdict("accept"), chain_name="same-chain", table_name="same", family="ip6"),
            table("other", "ip"), chain("same-chain", "other", "ip"),
            rule(verdict("accept"), chain_name="same-chain", table_name="other", family="ip"),
        ).snapshot
        first, second, third = result.tables
        self.assertNotEqual(first.semantic_table_id, second.semantic_table_id)
        self.assertNotEqual(first.chains[0].semantic_chain_id, third.chains[0].semantic_chain_id)
        self.assertNotEqual(
            first.chains[0].rules[0].semantic_rule_id,
            third.chains[0].rules[0].semantic_rule_id,
        )

    def test_interface_domain_is_distinct_from_structural_identity_domains(self):
        interface = {"match": {
            "op": "==", "left": {"meta": {"key": "iifname"}}, "right": "same",
        }}
        snapshot = self.parse(
            table(), chain("same"),
            rule(interface, verdict("accept"), chain_name="same")
        ).snapshot
        table_value = snapshot.tables[0]
        chain_value = table_value.chains[0]
        interface_id = chain_value.rules[0].expressions[0].value.value
        self.assertEqual(len({
            interface_id, table_value.semantic_table_id,
            chain_value.semantic_chain_id, chain_value.rules[0].semantic_rule_id,
        }), 4)
        self.assertNotIn("same", repr(snapshot))

    def test_interface_hash_primitive_has_exact_separate_domain(self):
        material = "same-normalized-material"
        interface_domain = "cyberwatchtower:linux-firewall-interface:v1"
        structural_domains = (
            "cyberwatchtower:linux-firewall-table:v1",
            "cyberwatchtower:linux-firewall-chain:v1",
            "cyberwatchtower:linux-firewall-rule:v1",
        )

        self.assertEqual(nftables_parser._INTERFACE_IDENTITY_DOMAIN, interface_domain)
        interface_digest = nftables_parser._digest(interface_domain, material)
        self.assertEqual(
            interface_digest,
            nftables_parser._digest(
                nftables_parser._INTERFACE_IDENTITY_DOMAIN, material
            ),
        )
        for structural_domain in structural_domains:
            with self.subTest(structural_domain=structural_domain):
                self.assertNotEqual(
                    interface_digest,
                    nftables_parser._digest(structural_domain, material),
                )

    def test_canonical_semantics_stabilize_rule_identity(self):
        def rule_id(expression):
            return self.parse(
                table(), chain(), rule(expression, verdict("accept"))
            ).snapshot.tables[0].chains[0].rules[0].semantic_rule_id

        self.assertEqual(
            rule_id(match("tcp", "dport", {"set": [80, 443]})),
            rule_id(match("tcp", "dport", {"set": [443, 80, 80]})),
        )
        self.assertEqual(
            rule_id(match("ip", "daddr", "192.168.1.1/24")),
            rule_id(match("ip", "daddr", "192.168.1.0/24")),
        )

    def test_harmless_json_key_order_does_not_change_identity(self):
        left = {"payload": {"protocol": "tcp", "field": "dport"}}
        first = {"match": {"op": "==", "left": left, "right": 443}}
        second = {"match": {"right": 443, "left": left, "op": "=="}}
        first_id = self.parse(
            table(), chain(), rule(first, verdict("accept"))
        ).snapshot.tables[0].chains[0].rules[0].semantic_rule_id
        second_id = self.parse(
            table(), chain(), rule(second, verdict("accept"))
        ).snapshot.tables[0].chains[0].rules[0].semantic_rule_id
        self.assertEqual(first_id, second_id)


class NftablesParserL2IntegrationTests(unittest.TestCase):
    def evaluate(self, *objects, current_subject=None):
        parsed = parse_nftables_json(
            document(*objects),
            namespace_alignment=LinuxNamespaceAlignment.SAME_CURRENT_NAMESPACE,
        )
        self.assertIsNotNone(parsed.snapshot)
        return parsed, evaluate_linux_listener_policy(
            current_subject or subject(), parsed.snapshot
        )

    def test_base_drop_and_accept_flow_to_frozen_l2(self):
        blocked = self.evaluate(table(), chain(policy="drop"))[1]
        allowed = self.evaluate(table(), chain(policy="accept"))[1]
        self.assertEqual(
            (blocked.applicability, blocked.default_policy_context,
             blocked.evaluated_policy_disposition, blocked.matches),
            (FirewallRuleApplicability.NO_MATCH, FirewallDefaultPolicyContext.BLOCK,
             EvaluatedPolicyDisposition.BLOCK, ()),
        )
        self.assertEqual(
            (allowed.applicability, allowed.default_policy_context,
             allowed.evaluated_policy_disposition),
            (FirewallRuleApplicability.NO_MATCH, FirewallDefaultPolicyContext.ALLOW,
             EvaluatedPolicyDisposition.ALLOW),
        )

    def test_parser_default_provenance_never_establishes_base_policy(self):
        for policy in ("drop", "accept"):
            with self.subTest(policy=policy):
                parsed = parse_nftables_json(document(table(), chain(policy=policy)))
                self.assertEqual(parsed.status, NftParseStatus.SUCCESS)
                self.assertEqual(
                    parsed.snapshot.namespace_alignment,
                    LinuxNamespaceAlignment.UNKNOWN,
                )
                assessment = evaluate_linux_listener_policy(subject(), parsed.snapshot)
                self.assertEqual(
                    assessment.evaluated_policy_disposition,
                    EvaluatedPolicyDisposition.NOT_ESTABLISHED,
                )

    def test_explicit_drop_and_accept_then_later_base_drop(self):
        explicit = self.evaluate(table(), chain(), rule(verdict("drop")))[1]
        later = self.evaluate(
            table(), chain("early", priority=-10), chain("late", priority=10, policy="drop"),
            rule(verdict("accept"), chain_name="early"),
        )[1]
        self.assertEqual(
            (explicit.applicability, explicit.evaluated_policy_disposition),
            (FirewallRuleApplicability.MATCHING_BLOCK, EvaluatedPolicyDisposition.BLOCK),
        )
        self.assertEqual(
            (later.applicability, later.evaluated_policy_disposition),
            (FirewallRuleApplicability.MATCHING_ALLOW, EvaluatedPolicyDisposition.BLOCK),
        )

    def test_unsupported_relevant_expression_cannot_establish_disposition(self):
        parsed, assessment = self.evaluate(
            table(), chain(), rule({"future": {}}, verdict("drop"))
        )
        self.assertEqual(parsed.status, NftParseStatus.UNSUPPORTED_SEMANTICS)
        self.assertEqual(assessment.applicability, FirewallRuleApplicability.INCOMPLETE)
        self.assertEqual(
            assessment.evaluated_policy_disposition,
            EvaluatedPolicyDisposition.NOT_ESTABLISHED,
        )

    def test_missing_jump_and_goto_targets_remain_incomplete(self):
        for name in ("jump", "goto"):
            with self.subTest(verdict=name):
                assessment = self.evaluate(
                    table(), chain(), rule(verdict(name, "missing"))
                )[1]
                self.assertEqual(assessment.applicability, FirewallRuleApplicability.INCOMPLETE)
                self.assertEqual(
                    assessment.evaluated_policy_disposition,
                    EvaluatedPolicyDisposition.NOT_ESTABLISHED,
                )

    def test_cross_table_and_cross_family_targets_do_not_resolve(self):
        cases = (
            (table("local"), chain(table_name="local"),
             rule(verdict("jump", "child"), table_name="local"),
             table("foreign"), chain("child", "foreign", hook=None)),
            (table("local", "ip"), chain(table_name="local", family="ip"),
             rule(verdict("jump", "child"), table_name="local", family="ip"),
             table("foreign", "ip6"), chain("child", "foreign", family="ip6", hook=None)),
        )
        for objects in cases:
            with self.subTest(objects=objects[-2]):
                assessment = self.evaluate(*objects)[1]
                self.assertEqual(assessment.applicability, FirewallRuleApplicability.INCOMPLETE)

    def test_jump_and_goto_preserve_distinct_l2_control_flow(self):
        common = (table(), chain(), chain("child", hook=None))
        jumped = self.evaluate(
            *common, rule(verdict("jump", "child")), rule(verdict("drop"))
        )[1]
        gone = self.evaluate(
            *common, rule(verdict("goto", "child")), rule(verdict("drop"))
        )[1]
        self.assertEqual(jumped.evaluated_policy_disposition, EvaluatedPolicyDisposition.BLOCK)
        self.assertEqual(gone.evaluated_policy_disposition, EvaluatedPolicyDisposition.ALLOW)

    def test_wildcard_ipv4_and_ipv6_destination_remain_conservative(self):
        cases = (
            ("ip", "192.0.2.0/24", subject("0.0.0.0")),
            ("ip6", "2001:db8::/64", subject("::")),
        )
        for protocol, network, current in cases:
            with self.subTest(protocol=protocol):
                assessment = self.evaluate(
                    table(), chain(), rule(match(protocol, "daddr", network), verdict("drop")),
                    current_subject=current,
                )[1]
                self.assertEqual(assessment.applicability, FirewallRuleApplicability.INCOMPLETE)
                self.assertEqual(
                    assessment.evaluated_policy_disposition,
                    EvaluatedPolicyDisposition.NOT_ESTABLISHED,
                )

    def test_unknown_namespace_alignment_never_establishes_strong_disposition(self):
        parsed = parse_nftables_json(
            document(table(), chain(policy="drop"), {"future-policy-object": {}}),
            namespace_alignment=LinuxNamespaceAlignment.SAME_CURRENT_NAMESPACE,
        )
        assessment = evaluate_linux_listener_policy(subject(), parsed.snapshot)
        self.assertEqual(parsed.snapshot.namespace_alignment, LinuxNamespaceAlignment.UNKNOWN)
        self.assertEqual(
            assessment.evaluated_policy_disposition,
            EvaluatedPolicyDisposition.NOT_ESTABLISHED,
        )

    def test_family_qualified_universal_addresses_do_not_cross_match(self):
        cases = (
            ("ip", "daddr", "0.0.0.0/0", subject("192.0.2.4"), EvaluatedPolicyDisposition.BLOCK),
            ("ip", "daddr", "0.0.0.0/0", subject("2001:db8::4"), EvaluatedPolicyDisposition.ALLOW),
            ("ip6", "daddr", "::/0", subject("2001:db8::4"), EvaluatedPolicyDisposition.BLOCK),
            ("ip6", "daddr", "::/0", subject("192.0.2.4"), EvaluatedPolicyDisposition.ALLOW),
        )
        for protocol, field, network, current, expected in cases:
            with self.subTest(protocol=protocol, address=current.local_address):
                assessment = self.evaluate(
                    table(), chain(), rule(match(protocol, field, network), verdict("drop")),
                    current_subject=current,
                )[1]
                self.assertEqual(assessment.evaluated_policy_disposition, expected)

    def test_source_universal_addresses_retain_family_predicate(self):
        for protocol, network, family in (
            ("ip", "0.0.0.0/0", LinuxFirewallFamily.IPV4),
            ("ip6", "::/0", LinuxFirewallFamily.IPV6),
        ):
            with self.subTest(protocol=protocol):
                parsed = parse_nftables_json(document(
                    table(), chain(), rule(match(protocol, "saddr", network), verdict("drop"))
                ))
                expressions = parsed.snapshot.tables[0].chains[0].rules[0].expressions
                self.assertEqual(expressions[0].value, family)
                self.assertEqual(expressions[1].value[0].kind, AddressConditionKind.ANY)


if __name__ == "__main__":
    unittest.main()
