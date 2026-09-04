import ipaddress
import unittest

from cyberwatchtower.firewall_policy import (
    MAX_POLICY_DIAGNOSTIC_LISTENERS,
    AddressConditionKind,
    ApplicationConditionKind,
    FirewallAddressCondition,
    FirewallApplicationCondition,
    FirewallDefaultPolicyContext,
    FirewallIPv4AddressRange,
    FirewallInterfaceCondition,
    FirewallPlatformTechnology,
    FirewallPolicyDiagnosticStatus,
    FirewallPolicyIndeterminateCause,
    FirewallRemoteUncertaintyShape,
    FirewallPortRange,
    FirewallRuleAction,
    FirewallRuleApplicability,
    FirewallRuleDirection,
    FirewallRuleEnabledState,
    FirewallRuleObservation,
    FirewallRuleUnsupportedFeature,
    FirewallUnsupportedFeatureDiagnosticSubtype,
    FirewallUnmodeledPlatformProvenance,
    InterfaceConditionKind,
    ListenerPolicyDiagnostic,
    ListenerPolicySubject,
    aggregate_listener_policy_diagnostics,
    diagnose_listener_policy,
    evaluate_listener_policy,
    semantic_firewall_rule_id,
)
from cyberwatchtower.platform.models import (
    BindExposure,
    FirewallProfile,
    NetworkProtocol,
)
from cyberwatchtower.report_contracts import CoverageState


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
        "local_addresses": (),
        "remote_addresses": (),
        "application": ANY_APPLICATION,
        "interface": ANY_INTERFACE,
        "edge_traversal": False,
        "unsupported_features": (),
    }
    values.update(changes)
    provenance = values.pop("unmodeled_platform_provenance", ())
    return FirewallRuleObservation(
        semantic_firewall_rule_id(**values), **values,
        unmodeled_platform_provenance=provenance,
    )


def diagnose(candidate, rules):
    return diagnose_listener_policy(candidate, tuple(sorted(
        rules, key=lambda value: value.semantic_rule_id
    )), CoverageState.COMPLETE, FirewallDefaultPolicyContext.BLOCK)


class FirewallPolicyDiagnosticCauseTests(unittest.TestCase):
    def test_each_normalized_unsupported_marker_has_a_closed_subtype(self):
        for feature in FirewallRuleUnsupportedFeature:
            with self.subTest(feature=feature):
                diagnostic = diagnose(subject(), (rule(
                    unsupported_features=(feature,),
                ),))
                self.assertEqual(diagnostic.unsupported_feature_subtypes, (
                    FirewallUnsupportedFeatureDiagnosticSubtype(feature.value),
                ))
                self.assertEqual(
                    diagnostic.assessment.applicability,
                    FirewallRuleApplicability.INCOMPLETE,
                )

    def test_potentially_relevant_unsupported_feature_is_closed(self):
        diagnostic = diagnose(subject(), (rule(unsupported_features=(
            FirewallRuleUnsupportedFeature.UNMODELED_PLATFORM_PREDICATE,
        )),))
        self.assertEqual(
            diagnostic.assessment.applicability,
            FirewallRuleApplicability.INCOMPLETE,
        )
        self.assertEqual(diagnostic.causes, (
            FirewallPolicyIndeterminateCause.UNSUPPORTED_FEATURE,
        ))

    def test_irrelevant_unsupported_feature_has_no_diagnostic_effect(self):
        diagnostic = diagnose(subject(), (rule(
            protocol=NetworkProtocol.UDP,
            unsupported_features=(
                FirewallRuleUnsupportedFeature.UNMODELED_PLATFORM_PREDICATE,
            ),
        ),))
        self.assertEqual(
            diagnostic.assessment.applicability,
            FirewallRuleApplicability.NO_MATCH,
        )
        self.assertEqual(diagnostic.causes, ())
        self.assertEqual(diagnostic.unsupported_feature_subtypes, ())

    def test_remote_any_and_supported_restriction_shapes_are_closed(self):
        any_remote = diagnose(subject(), (rule(remote_addresses=(
            FirewallAddressCondition(AddressConditionKind.ANY),
        )),))
        local_subnet = diagnose(subject(), (rule(remote_addresses=(
            FirewallAddressCondition(
                AddressConditionKind.SUPPORTED_SPECIAL_SCOPE, "LOCAL_SUBNET"
            ),
        )),))
        explicit = diagnose(subject(), (rule(remote_addresses=(
            FirewallAddressCondition(AddressConditionKind.CIDR, "198.51.100.0/24"),
        )),))
        mixed_conditions = tuple(sorted((
            FirewallAddressCondition(
                AddressConditionKind.SUPPORTED_SPECIAL_SCOPE, "LOCAL_SUBNET"
            ),
            FirewallAddressCondition(AddressConditionKind.EXACT, "198.51.100.8"),
        ), key=repr))
        mixed = diagnose(subject(), (rule(remote_addresses=mixed_conditions),))
        self.assertEqual(any_remote.remote_uncertainty_shapes, ())
        self.assertEqual(local_subnet.remote_uncertainty_shapes, (
            FirewallRemoteUncertaintyShape.LOCAL_SUBNET,
        ))
        self.assertEqual(explicit.remote_uncertainty_shapes, (
            FirewallRemoteUncertaintyShape.EXPLICIT_RESTRICTION,
        ))
        self.assertEqual(mixed.remote_uncertainty_shapes, (
            FirewallRemoteUncertaintyShape.MIXED_SUPPORTED_RESTRICTION,
        ))

    def test_irrelevant_protocol_and_port_short_circuit_remote_diagnostics(self):
        remote = (FirewallAddressCondition(
            AddressConditionKind.CIDR, "198.51.100.0/24"
        ),)
        cases = (
            rule(protocol=NetworkProtocol.UDP, remote_addresses=remote),
            rule(local_ports=(FirewallPortRange(8443, 8443),),
                 remote_addresses=remote),
        )
        for candidate in cases:
            with self.subTest(rule_id=candidate.semantic_rule_id):
                diagnostic = diagnose(subject(), (candidate,))
                self.assertEqual(diagnostic.causes, ())
                self.assertEqual(diagnostic.remote_uncertainty_shapes, ())

    def test_supported_remote_restriction_marker_is_discriminated_twice(self):
        diagnostic = diagnose(subject(), (rule(
            remote_addresses=(FirewallAddressCondition(
                AddressConditionKind.CIDR, "198.51.100.0/24"
            ),),
            unsupported_features=(
                FirewallRuleUnsupportedFeature.REMOTE_ADDRESS_RESTRICTED,
            ),
        ),))
        self.assertEqual(diagnostic.unsupported_feature_subtypes, (
            FirewallUnsupportedFeatureDiagnosticSubtype.REMOTE_ADDRESS_RESTRICTED,
        ))
        self.assertEqual(diagnostic.remote_uncertainty_shapes, (
            FirewallRemoteUncertaintyShape.EXPLICIT_RESTRICTION,
        ))

    def test_remote_and_interface_uncertainty_are_distinct(self):
        remote = diagnose(subject(), (rule(remote_addresses=(
            FirewallAddressCondition(
                AddressConditionKind.CIDR, "198.51.100.0/24"
            ),
        )),))
        interface = diagnose(subject(interface=None), (rule(
            interface=FirewallInterfaceCondition(InterfaceConditionKind.LAN),
        ),))
        self.assertIn(
            FirewallPolicyIndeterminateCause.REMOTE_ADDRESS_UNCERTAINTY,
            remote.causes,
        )
        self.assertEqual(interface.causes, (
            FirewallPolicyIndeterminateCause.INTERFACE_UNCERTAINTY,
        ))

    def test_missing_application_and_service_are_distinct(self):
        application = diagnose(subject(application_digest=None), (rule(
            application=FirewallApplicationCondition(
                ApplicationConditionKind.APPLICATION_DIGEST, "a" * 64
            ),
        ),))
        service = diagnose(subject(service_identity=None), (rule(
            application=FirewallApplicationCondition(
                ApplicationConditionKind.SERVICE_IDENTITY,
                "windows-service:https",
            ),
        ),))
        self.assertEqual(application.causes, (
            FirewallPolicyIndeterminateCause.MISSING_APPLICATION_IDENTITY,
        ))
        self.assertEqual(service.causes, (
            FirewallPolicyIndeterminateCause.MISSING_SERVICE_IDENTITY,
        ))

    def test_known_application_and_service_mismatches_do_not_report_missing(self):
        values = (
            diagnose(subject(application_digest="b" * 64), (rule(
                application=FirewallApplicationCondition(
                    ApplicationConditionKind.APPLICATION_DIGEST, "a" * 64
                ),
            ),)),
            diagnose(subject(service_identity="windows-service:other"), (rule(
                application=FirewallApplicationCondition(
                    ApplicationConditionKind.SERVICE_IDENTITY,
                    "windows-service:https",
                ),
            ),)),
        )
        for diagnostic in values:
            self.assertEqual(
                diagnostic.assessment.applicability,
                FirewallRuleApplicability.NO_MATCH,
            )
            self.assertEqual(diagnostic.causes, ())

    def test_multiple_causes_are_unique_and_deterministically_ordered(self):
        diagnostic = diagnose(subject(interface=None), (rule(
            interface=FirewallInterfaceCondition(InterfaceConditionKind.LAN),
            remote_addresses=(FirewallAddressCondition(
                AddressConditionKind.CIDR, "198.51.100.0/24"
            ),),
            unsupported_features=(
                FirewallRuleUnsupportedFeature.UNMODELED_PLATFORM_PREDICATE,
            ),
        ),))
        self.assertEqual(diagnostic.causes, tuple(sorted((
            FirewallPolicyIndeterminateCause.INTERFACE_UNCERTAINTY,
            FirewallPolicyIndeterminateCause.REMOTE_ADDRESS_UNCERTAINTY,
            FirewallPolicyIndeterminateCause.UNSUPPORTED_FEATURE,
        ), key=lambda value: value.value)))

    def test_typed_range_profile_and_unknown_state_are_closed(self):
        address_range = FirewallIPv4AddressRange(
            ipaddress.IPv4Address("192.0.2.1"),
            ipaddress.IPv4Address("192.0.2.10"),
        )
        typed_range = diagnose(subject(), (rule(local_addresses=(
            FirewallAddressCondition(AddressConditionKind.IPV4_RANGE, address_range),
        )),))
        profile = diagnose(subject(profiles=()), (rule(),))
        unknown = diagnose(subject(), (rule(
            enabled=FirewallRuleEnabledState.UNKNOWN,
        ),))
        self.assertIn(
            FirewallPolicyIndeterminateCause.TYPED_RANGE_OR_PARSE_UNCERTAINTY,
            typed_range.causes,
        )
        self.assertEqual(profile.causes, (
            FirewallPolicyIndeterminateCause.PROFILE_UNCERTAINTY,
        ))
        self.assertEqual(unknown.causes, (
            FirewallPolicyIndeterminateCause.UNKNOWN_ENABLEMENT_OR_STATE,
        ))


class FirewallPolicyDiagnosticIndependenceTests(unittest.TestCase):
    def test_complete_allow_block_and_conflict_have_no_causes(self):
        allow = rule()
        block = rule(action=FirewallRuleAction.BLOCK)
        cases = (
            ((allow,), FirewallRuleApplicability.MATCHING_ALLOW),
            ((block,), FirewallRuleApplicability.MATCHING_BLOCK),
            ((allow, block), FirewallRuleApplicability.CONFLICTING),
        )
        for rules, expected in cases:
            with self.subTest(expected=expected):
                diagnostic = diagnose(subject(), rules)
                self.assertEqual(diagnostic.assessment.applicability, expected)
                self.assertEqual(diagnostic.causes, ())

    def test_diagnostic_assessment_is_exactly_the_frozen_evaluator_result(self):
        cases = (
            (subject(), (rule(),)),
            (subject(), (rule(action=FirewallRuleAction.BLOCK),)),
            (subject(application_digest=None), (rule(
                application=FirewallApplicationCondition(
                    ApplicationConditionKind.APPLICATION_DIGEST, "a" * 64
                ),
            ),)),
            (subject(), (rule(protocol=NetworkProtocol.UDP),)),
        )
        for candidate, rules in cases:
            ordered = tuple(sorted(rules, key=lambda value: value.semantic_rule_id))
            expected = evaluate_listener_policy(
                candidate, ordered, CoverageState.COMPLETE,
                FirewallDefaultPolicyContext.BLOCK,
            )
            self.assertEqual(
                diagnose_listener_policy(
                    candidate, ordered, CoverageState.COMPLETE,
                    FirewallDefaultPolicyContext.BLOCK,
                ).assessment,
                expected,
            )

    def test_noncomplete_collection_diagnostic_does_not_reinterpret_policy(self):
        diagnostic = diagnose_listener_policy(
            subject(), (), CoverageState.INCOMPLETE
        )
        self.assertEqual(
            diagnostic.assessment.applicability,
            FirewallRuleApplicability.INCOMPLETE,
        )
        self.assertEqual(diagnostic.causes, ())


class FirewallPolicyDiagnosticAggregateTests(unittest.TestCase):
    def test_aggregate_counts_listeners_not_rule_or_listener_identities(self):
        missing = rule(application=FirewallApplicationCondition(
            ApplicationConditionKind.APPLICATION_DIGEST, "a" * 64
        ))
        diagnostics = tuple(
            diagnose(subject(application_digest=None), (missing,))
            for _ in range(35)
        )
        summary = aggregate_listener_policy_diagnostics(diagnostics)
        self.assertEqual(summary.status, FirewallPolicyDiagnosticStatus.COMPLETE)
        self.assertEqual(summary.total_listener_assessments, 35)
        self.assertEqual(summary.incomplete_listener_assessments, 35)
        self.assertEqual(summary.category_counts, ((
            FirewallPolicyIndeterminateCause.MISSING_APPLICATION_IDENTITY, 35
        ),))

    def test_aggregate_multi_listener_multi_category_is_deterministic(self):
        multi_cause = diagnose(subject(interface=None), (rule(
            interface=FirewallInterfaceCondition(InterfaceConditionKind.LAN),
            remote_addresses=(FirewallAddressCondition(
                AddressConditionKind.CIDR, "198.51.100.0/24"
            ),),
            unsupported_features=(
                FirewallRuleUnsupportedFeature.UNMODELED_PLATFORM_PREDICATE,
            ),
        ),))
        diagnostics = (
            diagnose(subject(application_digest=None), (rule(
                application=FirewallApplicationCondition(
                    ApplicationConditionKind.APPLICATION_DIGEST, "a" * 64
                ),
            ),)),
            diagnose(subject(interface=None), (rule(
                interface=FirewallInterfaceCondition(InterfaceConditionKind.LAN),
            ),)),
            diagnose(subject(), (rule(),)),
            multi_cause,
        )
        first = aggregate_listener_policy_diagnostics(diagnostics)
        second = aggregate_listener_policy_diagnostics(diagnostics)
        self.assertEqual(first, second)
        self.assertEqual(first.total_listener_assessments, 4)
        self.assertEqual(first.incomplete_listener_assessments, 3)
        self.assertEqual(first.category_counts, tuple(sorted(
            first.category_counts, key=lambda item: item[0].value
        )))

    def test_subtype_aggregation_is_listener_counted_and_deterministic(self):
        features = tuple(sorted((
            FirewallRuleUnsupportedFeature.REMOTE_PORT_RESTRICTED,
            FirewallRuleUnsupportedFeature.USER_OR_PACKAGE_SCOPE,
        ), key=lambda value: value.value))
        candidate = diagnose(subject(), (rule(
            remote_addresses=(FirewallAddressCondition(
                AddressConditionKind.CIDR, "198.51.100.0/24"
            ),),
            unsupported_features=features,
        ),))
        summary = aggregate_listener_policy_diagnostics((candidate, candidate))
        self.assertEqual(
            summary.unsupported_feature_subtype_listener_counts,
            tuple(sorted((
                (FirewallUnsupportedFeatureDiagnosticSubtype.REMOTE_PORT_RESTRICTED, 2),
                (FirewallUnsupportedFeatureDiagnosticSubtype.USER_OR_PACKAGE_SCOPE, 2),
            ), key=lambda item: item[0].value)),
        )
        self.assertEqual(summary.remote_uncertainty_shape_listener_counts, ((
            FirewallRemoteUncertaintyShape.EXPLICIT_RESTRICTION, 2
        ),))
        self.assertEqual(summary, aggregate_listener_policy_diagnostics(
            (candidate, candidate)
        ))

    def test_refined_provenance_is_listener_counted_and_short_circuited(self):
        origins = tuple(sorted((
            FirewallUnmodeledPlatformProvenance.RECOVERED_LOCAL_PORTS,
            FirewallUnmodeledPlatformProvenance.RULE3_UNAVAILABLE,
        ), key=lambda item: item.value))
        relevant = diagnose(subject(), (rule(
            unsupported_features=(
                FirewallRuleUnsupportedFeature.UNMODELED_PLATFORM_PREDICATE,
            ),
            unmodeled_platform_provenance=origins,
        ),))
        irrelevant = tuple(diagnose(subject(), (rule(
            **changes,
            unsupported_features=(
                FirewallRuleUnsupportedFeature.UNMODELED_PLATFORM_PREDICATE,
            ),
            unmodeled_platform_provenance=origins,
        ),)) for changes in (
            {"protocol": NetworkProtocol.UDP},
            {"local_ports": (FirewallPortRange(8443, 8443),)},
        ))
        summary = aggregate_listener_policy_diagnostics((relevant, relevant))
        self.assertEqual(relevant.unmodeled_platform_provenance, origins)
        self.assertTrue(all(
            value.unmodeled_platform_provenance == () for value in irrelevant
        ))
        self.assertEqual(
            summary.unmodeled_platform_provenance_listener_counts,
            tuple((origin, 2) for origin in origins),
        )

    def test_88_listener_shape_discriminates_overlapping_subtypes(self):
        remote = (FirewallAddressCondition(
            AddressConditionKind.CIDR, "198.51.100.0/24"
        ),)
        diagnostics = []
        for index in range(88):
            application = ANY_APPLICATION
            candidate = subject()
            if index < 6:
                application = FirewallApplicationCondition(
                    ApplicationConditionKind.APPLICATION_DIGEST, "a" * 64
                )
                candidate = subject(application_digest=None)
            elif index < 51:
                application = FirewallApplicationCondition(
                    ApplicationConditionKind.SERVICE_IDENTITY,
                    "windows-service:https",
                )
                candidate = subject(service_identity=None)
            diagnostics.append(diagnose(candidate, (rule(
                remote_addresses=remote,
                application=application,
                unsupported_features=(
                    FirewallRuleUnsupportedFeature.REMOTE_ADDRESS_RESTRICTED,
                    FirewallRuleUnsupportedFeature.UNMODELED_PLATFORM_PREDICATE,
                    FirewallRuleUnsupportedFeature.USER_OR_PACKAGE_SCOPE,
                ),
                unmodeled_platform_provenance=(
                    FirewallUnmodeledPlatformProvenance.RECOVERED_LOCAL_PORTS
                    if index < 44 else
                    FirewallUnmodeledPlatformProvenance.RULE3_UNAVAILABLE,
                ),
            ),)))
        summary = aggregate_listener_policy_diagnostics(tuple(diagnostics))
        self.assertEqual(summary.total_listener_assessments, 88)
        self.assertEqual(summary.incomplete_listener_assessments, 88)
        self.assertEqual(dict(summary.category_counts), {
            FirewallPolicyIndeterminateCause.MISSING_APPLICATION_IDENTITY: 6,
            FirewallPolicyIndeterminateCause.MISSING_SERVICE_IDENTITY: 45,
            FirewallPolicyIndeterminateCause.REMOTE_ADDRESS_UNCERTAINTY: 88,
            FirewallPolicyIndeterminateCause.UNSUPPORTED_FEATURE: 88,
        })
        self.assertEqual(
            summary.unsupported_feature_subtype_listener_counts,
            tuple(sorted((
                (FirewallUnsupportedFeatureDiagnosticSubtype.REMOTE_ADDRESS_RESTRICTED,
                 88),
                (FirewallUnsupportedFeatureDiagnosticSubtype.UNMODELED_PLATFORM_PREDICATE,
                 88),
                (FirewallUnsupportedFeatureDiagnosticSubtype.USER_OR_PACKAGE_SCOPE,
                 88),
            ), key=lambda item: item[0].value)),
        )
        self.assertEqual(summary.remote_uncertainty_shape_listener_counts, ((
            FirewallRemoteUncertaintyShape.EXPLICIT_RESTRICTION, 88
        ),))
        self.assertEqual(
            summary.unmodeled_platform_provenance_listener_counts,
            tuple(sorted((
                (FirewallUnmodeledPlatformProvenance.RECOVERED_LOCAL_PORTS, 44),
                (FirewallUnmodeledPlatformProvenance.RULE3_UNAVAILABLE, 44),
            ), key=lambda item: item[0].value)),
        )

    def test_bounds_and_invalid_input_fail_only_the_diagnostic_closed(self):
        diagnostic = diagnose(subject(), (rule(),))
        limited = aggregate_listener_policy_diagnostics(
            (diagnostic,) * (MAX_POLICY_DIAGNOSTIC_LISTENERS + 1)
        )
        invalid = aggregate_listener_policy_diagnostics((object(),))
        self.assertEqual(
            limited.status, FirewallPolicyDiagnosticStatus.LIMIT_EXCEEDED
        )
        self.assertEqual(
            invalid.status, FirewallPolicyDiagnosticStatus.INVALID_RESULT
        )
        for summary in (limited, invalid):
            self.assertEqual(summary.total_listener_assessments, 0)
            self.assertEqual(summary.incomplete_listener_assessments, 0)
            self.assertEqual(summary.category_counts, ())
            self.assertEqual(
                summary.unsupported_feature_subtype_listener_counts, ()
            )
            self.assertEqual(summary.remote_uncertainty_shape_listener_counts, ())
            self.assertEqual(
                summary.unmodeled_platform_provenance_listener_counts, ()
            )
        self.assertEqual(
            diagnostic.assessment.applicability,
            FirewallRuleApplicability.MATCHING_ALLOW,
        )

    def test_safe_mapping_contains_only_closed_categories_and_counts(self):
        canaries = (
            r"C:\private\application.exe",
            "private-service-name",
            "private-interface-identity",
            "private-native-value",
            "198.51.100.0/24",
        )
        summary = aggregate_listener_policy_diagnostics((
            diagnose(subject(application_digest=None), (rule(
                application=FirewallApplicationCondition(
                    ApplicationConditionKind.APPLICATION_DIGEST, "a" * 64
                ),
            ),)),
        ))
        mapping = summary.to_safe_mapping()
        rendered = repr(mapping)
        self.assertEqual(tuple(mapping), (
            "status", "total_listener_assessments",
            "incomplete_listener_assessments", "category_counts",
            "unsupported_feature_subtype_listener_counts",
            "remote_uncertainty_shape_listener_counts",
            "unmodeled_platform_provenance_listener_counts",
        ))
        self.assertTrue(all(value not in rendered for value in canaries))
        self.assertNotIn("semantic_rule_id", rendered)
        self.assertNotIn("application_digest", rendered)
        self.assertNotIn("service_identity", rendered)


if __name__ == "__main__":
    unittest.main()
