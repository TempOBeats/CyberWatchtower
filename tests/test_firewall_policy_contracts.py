import dataclasses
import unittest

from cyberwatchtower.firewall_policy import (
    MAX_CONDITIONS_PER_RULE,
    MAX_FIREWALL_RULES,
    MAX_MATCHED_RULE_DIGESTS_PER_LISTENER,
    MAX_NORMALIZED_TOKEN,
    MAX_VALUES_PER_CONDITION,
    AddressConditionKind,
    ApplicationConditionKind,
    FirewallAddressCondition,
    FirewallApplicationCondition,
    FirewallConditionMatch,
    FirewallDefaultPolicyContext,
    FirewallInterfaceCondition,
    FirewallPlatformTechnology,
    FirewallPortRange,
    FirewallRuleAction,
    FirewallRuleApplicability,
    FirewallRuleDirection,
    FirewallRuleEnabledState,
    FirewallRuleObservation,
    FirewallRuleUnsupportedFeature,
    InterfaceConditionKind,
    ListenerPolicySubject,
    evaluate_listener_policy,
    firewall_rule_applicability_coverage,
    normalize_firewall_rules,
    semantic_firewall_rule_id,
)
from cyberwatchtower.platform.models import (
    BindExposure,
    FirewallProfile,
    NetworkProtocol,
)
from cyberwatchtower.reachability import (
    ReachabilityEvidenceBasis,
    RemoteReachabilityState,
    assess_listener_reachability,
    reachability_coverage,
)
from cyberwatchtower.report_contracts import CoverageState


ANY_ADDRESS = (FirewallAddressCondition(AddressConditionKind.ANY),)
ANY_APPLICATION = FirewallApplicationCondition(ApplicationConditionKind.ANY)
ANY_INTERFACE = FirewallInterfaceCondition(InterfaceConditionKind.ANY)


def subject(**changes):
    values = {
        "protocol": NetworkProtocol.TCP,
        "local_port": 443,
        "bind_exposure": BindExposure.ALL_INTERFACES,
        "local_address": "0.0.0.0",
        "profiles": (FirewallProfile.PUBLIC,),
        "application_digest": "a" * 64,
        "service_identity": "windows-service:https",
        "interface": InterfaceConditionKind.LAN,
    }
    values.update(changes)
    return ListenerPolicySubject(**values)


def rule(**changes):
    values = {
        "technology": FirewallPlatformTechnology.WINDOWS_FIREWALL,
        "enabled": FirewallRuleEnabledState.ENABLED,
        "direction": FirewallRuleDirection.INBOUND,
        "action": FirewallRuleAction.ALLOW,
        "profiles": (FirewallProfile.PUBLIC,),
        "protocol": NetworkProtocol.TCP,
        "local_ports": (FirewallPortRange(443, 443),),
        "local_addresses": ANY_ADDRESS,
        "remote_addresses": ANY_ADDRESS,
        "application": ANY_APPLICATION,
        "interface": ANY_INTERFACE,
        "edge_traversal": False,
        "unsupported_features": (),
    }
    values.update(changes)
    identity = semantic_firewall_rule_id(**values)
    return FirewallRuleObservation(identity, **values)


class FirewallPolicyContractTests(unittest.TestCase):
    def test_contracts_are_immutable_slotted_and_bounds_are_frozen(self):
        self.assertEqual((
            MAX_FIREWALL_RULES, MAX_CONDITIONS_PER_RULE,
            MAX_VALUES_PER_CONDITION, MAX_NORMALIZED_TOKEN,
            MAX_MATCHED_RULE_DIGESTS_PER_LISTENER,
        ), (8192, 64, 256, 256, 16))
        value = rule()
        with self.assertRaises((dataclasses.FrozenInstanceError, AttributeError)):
            value.action = FirewallRuleAction.BLOCK
        self.assertFalse(hasattr(value, "__dict__"))

    def test_matching_allow_and_universal_block(self):
        allow = evaluate_listener_policy(subject(), (rule(),), CoverageState.COMPLETE)
        block = evaluate_listener_policy(subject(), (
            rule(action=FirewallRuleAction.BLOCK),
        ), CoverageState.COMPLETE)
        self.assertEqual(allow.applicability, FirewallRuleApplicability.MATCHING_ALLOW)
        self.assertEqual(block.applicability, FirewallRuleApplicability.MATCHING_BLOCK)
        self.assertTrue(block.matches[0].universally_applicable)

    def test_default_block_context_without_a_rule_is_no_match(self):
        result = evaluate_listener_policy(
            subject(), (), CoverageState.COMPLETE,
            FirewallDefaultPolicyContext.BLOCK,
        )
        self.assertEqual(result.applicability, FirewallRuleApplicability.NO_MATCH)
        self.assertEqual(
            result.default_policy_context, FirewallDefaultPolicyContext.BLOCK
        )

    def test_disabled_wrong_profile_protocol_and_port_do_not_match(self):
        cases = (
            rule(enabled=FirewallRuleEnabledState.DISABLED),
            rule(profiles=(FirewallProfile.DOMAIN,)),
            rule(protocol=NetworkProtocol.UDP),
            rule(local_ports=(FirewallPortRange(80, 80),)),
        )
        for value in cases:
            with self.subTest(rule=value):
                result = evaluate_listener_policy(
                    subject(), (value,), CoverageState.COMPLETE
                )
                self.assertEqual(result.applicability, FirewallRuleApplicability.NO_MATCH)

    def test_application_service_interface_and_any_port_conditions(self):
        cases = (
            rule(application=FirewallApplicationCondition(
                ApplicationConditionKind.APPLICATION_DIGEST, "a" * 64
            )),
            rule(application=FirewallApplicationCondition(
                ApplicationConditionKind.SERVICE_IDENTITY,
                "windows-service:https",
            )),
            rule(interface=FirewallInterfaceCondition(InterfaceConditionKind.LAN)),
            rule(local_ports=()),
        )
        for value in cases:
            with self.subTest(rule=value):
                self.assertEqual(
                    evaluate_listener_policy(
                        subject(), (value,), CoverageState.COMPLETE
                    ).applicability,
                    FirewallRuleApplicability.MATCHING_ALLOW,
                )

    def test_multiple_profiles_and_ipv4_ipv6_addresses_are_decidable(self):
        multi = rule(profiles=(FirewallProfile.DOMAIN, FirewallProfile.PUBLIC))
        self.assertEqual(
            evaluate_listener_policy(subject(), (multi,), CoverageState.COMPLETE)
            .applicability,
            FirewallRuleApplicability.MATCHING_ALLOW,
        )
        ipv6_rule = rule(local_addresses=(
            FirewallAddressCondition(AddressConditionKind.CIDR, "2001:db8::1/64"),
        ))
        ipv6_subject = subject(local_address="2001:db8::20")
        self.assertEqual(
            evaluate_listener_policy(
                ipv6_subject, (ipv6_rule,), CoverageState.COMPLETE
            ).applicability,
            FirewallRuleApplicability.MATCHING_ALLOW,
        )
        self.assertEqual(ipv6_rule.local_addresses[0].value, "2001:db8::/64")

    def test_missing_attribution_and_unsupported_predicate_are_incomplete(self):
        scoped = rule(application=FirewallApplicationCondition(
            ApplicationConditionKind.APPLICATION_DIGEST, "a" * 64
        ))
        unsupported = rule(unsupported_features=(
            FirewallRuleUnsupportedFeature.UNMODELED_PLATFORM_PREDICATE,
        ))
        for candidate, value in (
            (subject(application_digest=None), scoped),
            (subject(), unsupported),
        ):
            result = evaluate_listener_policy(candidate, (value,), CoverageState.COMPLETE)
            self.assertEqual(result.applicability, FirewallRuleApplicability.INCOMPLETE)
            self.assertEqual(result.matches[0].condition_match,
                             FirewallConditionMatch.INDETERMINATE)

    def test_restricted_remote_address_is_conditional_not_universal(self):
        restricted = rule(remote_addresses=(
            FirewallAddressCondition(AddressConditionKind.CIDR, "192.0.2.0/24"),
        ))
        result = evaluate_listener_policy(
            subject(), (restricted,), CoverageState.COMPLETE
        )
        self.assertEqual(result.applicability, FirewallRuleApplicability.INCOMPLETE)
        self.assertFalse(result.matches[0].universally_applicable)

    def test_conflicting_allow_and_block_remain_distinct(self):
        rules = tuple(sorted((
            rule(), rule(action=FirewallRuleAction.BLOCK),
        ), key=lambda value: value.semantic_rule_id))
        result = evaluate_listener_policy(subject(), rules, CoverageState.COMPLETE)
        self.assertEqual(result.applicability, FirewallRuleApplicability.CONFLICTING)
        self.assertEqual({value.action for value in result.matches}, {
            FirewallRuleAction.ALLOW, FirewallRuleAction.BLOCK,
        })

    def test_collection_states_and_applicability_coverage_fail_closed(self):
        incomplete = evaluate_listener_policy(subject(), (), CoverageState.INCOMPLETE)
        unsupported = evaluate_listener_policy(subject(), (), CoverageState.UNKNOWN)
        self.assertEqual(incomplete.applicability, FirewallRuleApplicability.INCOMPLETE)
        self.assertEqual(unsupported.applicability, FirewallRuleApplicability.UNSUPPORTED)
        self.assertEqual(
            firewall_rule_applicability_coverage(
                CoverageState.COMPLETE, (incomplete,)
            ), CoverageState.INCOMPLETE,
        )
        self.assertEqual(
            firewall_rule_applicability_coverage(CoverageState.UNKNOWN, ()),
            CoverageState.UNKNOWN,
        )

    def test_semantic_digest_is_deterministic_and_permutation_invariant(self):
        first = rule()
        second = rule()
        self.assertEqual(first.semantic_rule_id, second.semantic_rule_id)
        values = (rule(action=FirewallRuleAction.BLOCK), first)
        results = {
            evaluate_listener_policy(subject(), ordering, CoverageState.COMPLETE)
            for ordering in (values, tuple(reversed(values)))
        }
        self.assertEqual(len(results), 1)
        with self.assertRaises(ValueError):
            dataclasses.replace(first, semantic_rule_id="0" * 64)

    def test_exact_duplicates_deduplicate_only_after_validation(self):
        value = rule()
        self.assertEqual(normalize_firewall_rules((value, value)), (value,))
        with self.assertRaises(ValueError):
            evaluate_listener_policy(subject(), (value, value), CoverageState.COMPLETE)

    def test_invalid_values_and_privacy_fields_fail_closed(self):
        for invalid in (
            "C:\\Users\\private\\tool.exe", "user@example.test",
            "native error: access denied", "\x00secret",
        ):
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                FirewallApplicationCondition(
                    ApplicationConditionKind.APPLICATION_DIGEST, invalid
                )
        for invalid in ("user@example.test", "DOMAIN\\user", "arbitrary text"):
            with self.subTest(service=invalid), self.assertRaises(ValueError):
                FirewallApplicationCondition(
                    ApplicationConditionKind.SERVICE_IDENTITY, invalid
                )
        field_names = {field.name for field in dataclasses.fields(FirewallRuleObservation)}
        for prohibited in (
            "name", "description", "path", "username", "domain", "pid",
            "native_error", "command_output", "provider_text",
        ):
            self.assertNotIn(prohibited, field_names)

    def test_snapshot_and_condition_bounds_fail_closed(self):
        value = rule()
        with self.assertRaises(ValueError):
            normalize_firewall_rules((value,) * (MAX_FIREWALL_RULES + 1))
        with self.assertRaises(ValueError):
            rule(local_ports=tuple(
                FirewallPortRange(port, port)
                for port in range(MAX_VALUES_PER_CONDITION + 1)
            ))


class PolicyReachabilityTests(unittest.TestCase):
    def test_loopback_is_never_remotely_bound(self):
        policy = evaluate_listener_policy(
            subject(bind_exposure=BindExposure.LOOPBACK,
                    local_address="127.0.0.1"),
            (rule(action=FirewallRuleAction.ALLOW),), CoverageState.COMPLETE,
        )
        assessment = assess_listener_reachability(
            BindExposure.LOOPBACK, policy_assessment=policy
        )
        self.assertEqual(assessment.state, RemoteReachabilityState.NOT_REMOTELY_BOUND)

    def test_policy_mapping_is_conservative(self):
        cases = (
            (rule(action=FirewallRuleAction.BLOCK),
             RemoteReachabilityState.BLOCKED_BY_OBSERVED_POLICY,
             ReachabilityEvidenceBasis.HOST_POLICY_EXPLICIT_BLOCK),
            (rule(), RemoteReachabilityState.POTENTIALLY_REACHABLE,
             ReachabilityEvidenceBasis.HOST_POLICY_EXPLICIT_ALLOW),
        )
        for policy_rule, state, basis in cases:
            policy = evaluate_listener_policy(
                subject(), (policy_rule,), CoverageState.COMPLETE
            )
            assessment = assess_listener_reachability(
                BindExposure.ALL_INTERFACES, policy_assessment=policy
            )
            self.assertEqual(assessment.state, state)
            self.assertIn(basis, assessment.evidence_basis)

    def test_no_match_and_incomplete_stay_potential(self):
        for coverage in (CoverageState.COMPLETE, CoverageState.INCOMPLETE,
                         CoverageState.UNKNOWN):
            policy = evaluate_listener_policy(subject(), (), coverage)
            assessment = assess_listener_reachability(
                BindExposure.INTERFACE, policy_assessment=policy
            )
            self.assertEqual(
                assessment.state, RemoteReachabilityState.POTENTIALLY_REACHABLE
            )

    def test_blocked_and_not_bound_can_complete_reachability(self):
        policy = evaluate_listener_policy(
            subject(), (rule(action=FirewallRuleAction.BLOCK),),
            CoverageState.COMPLETE,
        )
        blocked = assess_listener_reachability(
            BindExposure.ALL_INTERFACES, policy_assessment=policy
        )
        self.assertEqual(
            reachability_coverage(CoverageState.COMPLETE, (blocked,)),
            CoverageState.COMPLETE,
        )


if __name__ == "__main__":
    unittest.main()
