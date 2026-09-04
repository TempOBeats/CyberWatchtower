import dataclasses
from pathlib import Path
import unittest
from unittest.mock import patch

from cyberwatchtower.firewall_policy import (
    ApplicationConditionKind,
    FirewallApplicationCondition,
    FirewallConditionMatch,
    FirewallDefaultPolicyContext,
    FirewallPolicyDiagnosticStatus,
    FirewallPolicyIndeterminateCause,
    FirewallRuleAction,
    FirewallRuleApplicability,
    FirewallRuleMatch,
)
from cyberwatchtower.platform.models import (
    BindExposure,
    CollectionFailure,
    CollectionResult,
    FailureCategory,
    FailureCode,
    FirewallEnablement,
    FirewallInboundAction,
    FirewallInboundPostureObservation,
    FirewallProfile,
    FirewallProfileObservation,
    FirewallProfileState,
    ListenerObservation,
    NetworkProtocol,
    ObservationDomain,
)
from cyberwatchtower.platform.windows.firewall_policy_integration import (
    WindowsFirewallPolicyProviderProtocol,
    WindowsListenerPolicyIntegrationResult,
    collect_windows_listener_policy_diagnostics,
    collect_windows_listener_policy,
    windows_firewall_profile_context,
    windows_listener_policy_subject,
)
from cyberwatchtower.platform.windows.firewall_rule_models import (
    RawWindowsApplicationPath,
    RawWindowsFirewallRule,
    WindowsFirewallPolicyView,
    WindowsFirewallRuleCollectionResult,
    WindowsFirewallRuleResultCode,
    WindowsRawFirewallRuleAction,
    WindowsRawFirewallRuleDirection,
    WindowsRawFirewallInterfaceType,
    WindowsRawFirewallUnsupportedFeature,
)
from cyberwatchtower.platform.windows.firewall_rules import (
    WindowsFirewallRuleNormalizationResult,
    normalize_windows_firewall_rules,
    windows_application_identity,
)
from cyberwatchtower.report_contracts import CoverageState


VIEW = WindowsFirewallPolicyView.CURRENT_POLICY_VIEW
EXACT_PATH = r"C:\Program Files\Synthetic\listener.exe"
EXACT_DIGEST = windows_application_identity(RawWindowsApplicationPath(EXACT_PATH))


class FakeNormalizedPolicyProvider:
    def __init__(self, result):
        self.result = result
        self.calls = 0

    def collect_normalized_firewall_policy(self):
        self.calls += 1
        return self.result


class WindowsFirewallPolicyDiagnosticIntegrationTests(unittest.TestCase):
    def test_safe_aggregate_collects_provider_once_for_35_listeners(self):
        provider = FakeNormalizedPolicyProvider(complete_policy(raw_rule(
            application_path=RawWindowsApplicationPath(EXACT_PATH)
        )))
        listeners = tuple(listener(
            pid=100 + index,
            application=None,
            application_name=None,
            application_digest=None,
        ) for index in range(35))

        summary = collect_windows_listener_policy_diagnostics(
            provider,
            listeners,
            CoverageState.COMPLETE,
            posture(profile()),
        )

        self.assertEqual(provider.calls, 1)
        self.assertEqual(summary.status, FirewallPolicyDiagnosticStatus.COMPLETE)
        self.assertEqual(summary.total_listener_assessments, 35)
        self.assertEqual(summary.incomplete_listener_assessments, 35)
        self.assertEqual(summary.category_counts, ((
            FirewallPolicyIndeterminateCause.MISSING_APPLICATION_IDENTITY, 35
        ),))
        rendered = repr(summary.to_safe_mapping())
        self.assertNotIn(EXACT_PATH, rendered)
        self.assertNotIn(EXACT_DIGEST, rendered)

    def test_diagnostic_provider_failure_is_closed_and_has_no_partial_output(self):
        class RaisingProvider:
            def collect_normalized_firewall_policy(self):
                raise RuntimeError("private diagnostic canary")

        summary = collect_windows_listener_policy_diagnostics(
            RaisingProvider(),
            (listener(),),
            CoverageState.COMPLETE,
            posture(profile()),
        )

        self.assertEqual(
            summary.status, FirewallPolicyDiagnosticStatus.INVALID_RESULT
        )
        self.assertEqual(summary.total_listener_assessments, 0)
        self.assertEqual(summary.incomplete_listener_assessments, 0)
        self.assertEqual(summary.category_counts, ())
        self.assertNotIn("private diagnostic canary", repr(summary))


def raw_rule(**changes):
    values = {
        "policy_view": VIEW,
        "enabled": True,
        "direction": WindowsRawFirewallRuleDirection.INBOUND,
        "action": WindowsRawFirewallRuleAction.ALLOW,
        "profile_mask": 4,
        "protocol": 6,
        "local_ports": ("443",),
        "local_addresses": ("*",),
    }
    values.update(changes)
    return RawWindowsFirewallRule(**values)


def complete_policy(*rules):
    return normalize_windows_firewall_rules(WindowsFirewallRuleCollectionResult(
        WindowsFirewallRuleResultCode.COMPLETE, VIEW, tuple(rules)
    ))


def failed_policy(state, *, rules=()):
    coverage = (
        CoverageState.UNKNOWN
        if state in {
            WindowsFirewallRuleResultCode.API_UNAVAILABLE,
            WindowsFirewallRuleResultCode.UNSUPPORTED,
        }
        else CoverageState.INCOMPLETE
    )
    return WindowsFirewallRuleNormalizationResult(
        VIEW, coverage, tuple(rules), state
    )


def listener(**changes):
    values = {
        "protocol": NetworkProtocol.TCP,
        "state": "LISTEN",
        "address": "0.0.0.0",
        "port": 443,
        "exposure": BindExposure.ALL_INTERFACES,
        "process": "listener.exe",
        "pid": 100,
        "application": EXACT_DIGEST,
        "application_name": "listener.exe",
        "known_application": False,
        "application_digest": EXACT_DIGEST,
    }
    values.update(changes)
    return ListenerObservation(**values)


def profile(
    name=FirewallProfile.PUBLIC,
    *,
    state=FirewallProfileState.ACTIVE,
    enablement=FirewallEnablement.ENABLED,
    action=FirewallInboundAction.BLOCK,
    block_all=False,
):
    return FirewallProfileObservation(
        name, state, enablement, action, block_all
    )


def posture(*profiles, coverage=CoverageState.COMPLETE):
    observations = (
        (FirewallInboundPostureObservation("windows-firewall", tuple(profiles)),)
        if profiles else ()
    )
    failure = None
    if coverage != CoverageState.COMPLETE:
        failure = CollectionFailure(
            FailureCategory.PARTIAL,
            FailureCode.COLLECTOR_PARTIAL,
            "Windows profile posture is incomplete.",
        )
    return CollectionResult(
        ObservationDomain.FIREWALL_INBOUND_POLICY,
        coverage,
        observations,
        failure,
    )


def integrate(policy, listeners=(listener(),), *, socket=CoverageState.COMPLETE,
              profile_result=None):
    provider = FakeNormalizedPolicyProvider(policy)
    result = collect_windows_listener_policy(
        provider,
        listeners,
        socket,
        profile_result or posture(profile()),
    )
    return provider, result


class WindowsFirewallPolicyFailureMatrixTests(unittest.TestCase):
    def test_provider_protocol_is_normalized_and_narrow(self):
        provider = FakeNormalizedPolicyProvider(complete_policy())
        self.assertIsInstance(provider, WindowsFirewallPolicyProviderProtocol)
        self.assertEqual(
            {
                name for name in dir(WindowsFirewallPolicyProviderProtocol)
                if not name.startswith("_")
            },
            {"collect_normalized_firewall_policy"},
        )

    def test_complete_collection_evaluates_rules(self):
        provider, result = integrate(complete_policy(raw_rule()))
        self.assertEqual(provider.calls, 1)
        self.assertEqual(result.collection_coverage, CoverageState.COMPLETE)
        self.assertEqual(result.applicability_coverage, CoverageState.COMPLETE)
        self.assertEqual(
            result.assessments[0].applicability,
            FirewallRuleApplicability.MATCHING_ALLOW,
        )

    def test_every_noncomplete_collection_bypasses_the_evaluator(self):
        cases = tuple(
            state for state in WindowsFirewallRuleResultCode
            if state != WindowsFirewallRuleResultCode.COMPLETE
        )
        tempting = complete_policy(raw_rule()).rules[0]
        for state in cases:
            rules = (
                (tempting,)
                if state == WindowsFirewallRuleResultCode.COLLECTION_INCOMPLETE
                else ()
            )
            with self.subTest(state=state), patch(
                "cyberwatchtower.platform.windows.firewall_policy_integration."
                "evaluate_listener_policy"
            ) as evaluator:
                _, result = integrate(failed_policy(state, rules=rules))
                evaluator.assert_not_called()
                expected_coverage = (
                    CoverageState.UNKNOWN
                    if state in {
                        WindowsFirewallRuleResultCode.API_UNAVAILABLE,
                        WindowsFirewallRuleResultCode.UNSUPPORTED,
                    }
                    else CoverageState.INCOMPLETE
                )
                expected_applicability = (
                    FirewallRuleApplicability.UNSUPPORTED
                    if expected_coverage == CoverageState.UNKNOWN
                    else FirewallRuleApplicability.INCOMPLETE
                )
                self.assertEqual(result.collection_coverage, expected_coverage)
                self.assertEqual(
                    result.assessments[0].applicability,
                    expected_applicability,
                )
                self.assertEqual(result.assessments[0].matches, ())

    def test_invalid_provider_output_and_exception_fail_closed(self):
        for value in (object(), RuntimeError("PRIVATE_PATH_CANARY")):
            provider = FakeNormalizedPolicyProvider(value)
            if isinstance(value, Exception):
                provider.collect_normalized_firewall_policy = lambda: (_ for _ in ()).throw(value)
            with self.subTest(value=type(value).__name__), patch(
                "cyberwatchtower.platform.windows.firewall_policy_integration."
                "evaluate_listener_policy"
            ) as evaluator:
                result = collect_windows_listener_policy(
                    provider, (listener(),), CoverageState.COMPLETE,
                    posture(profile()),
                )
                evaluator.assert_not_called()
                self.assertIsNone(result.policy_view)
                self.assertEqual(
                    result.collection_failure,
                    WindowsFirewallRuleResultCode.INVALID_RESULT,
                )
                self.assertNotIn("PRIVATE_PATH_CANARY", repr(result))

    def test_unexpected_authority_fails_closed_without_evaluation(self):
        malformed = object.__new__(WindowsFirewallRuleNormalizationResult)
        object.__setattr__(malformed, "policy_view", "FUTURE_AUTHORITY")
        object.__setattr__(malformed, "coverage", CoverageState.COMPLETE)
        object.__setattr__(malformed, "rules", complete_policy(raw_rule()).rules)
        object.__setattr__(malformed, "failure", None)
        with patch(
            "cyberwatchtower.platform.windows.firewall_policy_integration."
            "evaluate_listener_policy"
        ) as evaluator:
            _, result = integrate(malformed)
            evaluator.assert_not_called()
        self.assertIsNone(result.policy_view)
        self.assertEqual(
            result.collection_failure,
            WindowsFirewallRuleResultCode.INVALID_RESULT,
        )


class WindowsFirewallSubjectAndProfileTests(unittest.TestCase):
    def test_subject_preserves_protocol_address_port_bind_and_profiles(self):
        cases = (
            listener(),
            listener(address="192.0.2.4", exposure=BindExposure.INTERFACE),
            listener(protocol=NetworkProtocol.UDP, address="::", port=5353,
                     exposure=BindExposure.ALL_INTERFACES),
            listener(address="2001:db8::4", exposure=BindExposure.INTERFACE),
            listener(address="127.0.0.1", exposure=BindExposure.LOOPBACK),
        )
        for value in cases:
            with self.subTest(listener=value):
                subject = windows_listener_policy_subject(
                    value, (FirewallProfile.PUBLIC,)
                )
                self.assertEqual(subject.protocol, value.protocol)
                self.assertEqual(subject.local_port, value.port)
                self.assertEqual(subject.local_address, value.address)
                self.assertEqual(subject.bind_exposure, value.exposure)
                self.assertEqual(subject.profiles, (FirewallProfile.PUBLIC,))
                self.assertIsNone(subject.interface)
                self.assertIsNone(subject.interface_digest)

    def test_application_and_service_are_closed_attribution_forms(self):
        application = windows_listener_policy_subject(
            listener(application_digest=EXACT_DIGEST), (FirewallProfile.PUBLIC,)
        )
        service = windows_listener_policy_subject(
            listener(
                application="windows-service:synthetic",
                service_identity="windows-service:synthetic",
            ),
            (FirewallProfile.PUBLIC,),
        )
        missing = windows_listener_policy_subject(
            listener(
                application=None, application_name=None,
                application_digest=None, service_identity=None,
            ),
            (FirewallProfile.PUBLIC,),
        )
        self.assertEqual(application.application_digest, EXACT_DIGEST)
        self.assertIsNone(application.service_identity)
        self.assertEqual(service.service_identity, "windows-service:synthetic")
        self.assertEqual(service.application_digest, EXACT_DIGEST)
        self.assertIsNone(missing.application_digest)
        self.assertIsNone(missing.service_identity)

    def test_profile_context_is_conservative(self):
        allow = windows_firewall_profile_context(posture(profile(
            action=FirewallInboundAction.ALLOW
        )))
        block = windows_firewall_profile_context(posture(profile()))
        mixed = windows_firewall_profile_context(posture(
            profile(FirewallProfile.PRIVATE, action=FirewallInboundAction.ALLOW),
            profile(FirewallProfile.PUBLIC, action=FirewallInboundAction.BLOCK),
        ))
        disabled = windows_firewall_profile_context(posture(profile(
            enablement=FirewallEnablement.DISABLED
        )))
        incomplete = windows_firewall_profile_context(posture(
            profile(), coverage=CoverageState.INCOMPLETE
        ))
        self.assertEqual(allow.default_policy_context, FirewallDefaultPolicyContext.ALLOW)
        self.assertEqual(block.default_policy_context, FirewallDefaultPolicyContext.BLOCK)
        self.assertEqual(mixed.default_policy_context, FirewallDefaultPolicyContext.UNKNOWN)
        self.assertTrue(mixed.evaluation_permitted)
        self.assertFalse(disabled.evaluation_permitted)
        self.assertFalse(incomplete.evaluation_permitted)
        self.assertEqual(incomplete.profiles, ())

    def test_disabled_or_incomplete_profiles_prevent_confident_rule_verdict(self):
        policy = complete_policy(raw_rule(action=WindowsRawFirewallRuleAction.BLOCK))
        for profile_result in (
            posture(profile(enablement=FirewallEnablement.DISABLED)),
            posture(profile(), coverage=CoverageState.INCOMPLETE),
        ):
            with self.subTest(profile_result=profile_result), patch(
                "cyberwatchtower.platform.windows.firewall_policy_integration."
                "evaluate_listener_policy"
            ) as evaluator:
                _, result = integrate(policy, profile_result=profile_result)
                evaluator.assert_not_called()
                self.assertEqual(result.collection_coverage, CoverageState.COMPLETE)
                self.assertEqual(result.applicability_coverage, CoverageState.INCOMPLETE)
                self.assertEqual(
                    result.assessments[0].applicability,
                    FirewallRuleApplicability.INCOMPLETE,
                )


class WindowsFirewallApplicabilityIntegrationTests(unittest.TestCase):
    def test_allow_block_no_match_conflict_and_incomplete(self):
        allow = raw_rule()
        block = raw_rule(action=WindowsRawFirewallRuleAction.BLOCK)
        no_match = raw_rule(local_ports=("80",))
        unsupported = raw_rule(unsupported_features=(
            WindowsRawFirewallUnsupportedFeature.UNMODELED_NATIVE_PREDICATE,
        ))
        cases = (
            ((allow,), FirewallRuleApplicability.MATCHING_ALLOW),
            ((block,), FirewallRuleApplicability.MATCHING_BLOCK),
            ((no_match,), FirewallRuleApplicability.NO_MATCH),
            ((allow, block), FirewallRuleApplicability.CONFLICTING),
            ((unsupported,), FirewallRuleApplicability.INCOMPLETE),
        )
        for rules, expected in cases:
            with self.subTest(expected=expected):
                _, result = integrate(complete_policy(*rules))
                self.assertEqual(result.assessments[0].applicability, expected)

    def test_frozen_ambiguous_aggregation_state_remains_supported(self):
        policy = complete_policy(
            raw_rule(action=WindowsRawFirewallRuleAction.BLOCK)
        )
        synthetic_nonuniversal_match = FirewallRuleMatch(
            policy.rules[0].semantic_rule_id,
            FirewallRuleAction.BLOCK,
            FirewallConditionMatch.MATCH,
            False,
        )
        with patch(
            "cyberwatchtower.firewall_policy._rule_match",
            return_value=synthetic_nonuniversal_match,
        ):
            _, result = integrate(policy)
        self.assertEqual(
            result.assessments[0].applicability,
            FirewallRuleApplicability.AMBIGUOUS,
        )

    def test_application_and_service_exact_or_missing(self):
        application_rule = raw_rule(
            application_path=RawWindowsApplicationPath(EXACT_PATH)
        )
        service_rule = raw_rule(service_name="Synthetic")
        cases = (
            (application_rule, listener(application_digest=EXACT_DIGEST),
             FirewallRuleApplicability.MATCHING_ALLOW),
            (application_rule, listener(application_digest="f" * 64),
             FirewallRuleApplicability.NO_MATCH),
            (application_rule, listener(
                application=None, application_name=None, application_digest=None
            ),
             FirewallRuleApplicability.INCOMPLETE),
            (service_rule, listener(
                application="windows-service:synthetic",
                service_identity="windows-service:synthetic",
            ),
             FirewallRuleApplicability.MATCHING_ALLOW),
            (service_rule, listener(
                application=None, application_name=None, service_identity=None
            ),
             FirewallRuleApplicability.INCOMPLETE),
        )
        for rule, value, expected in cases:
            with self.subTest(expected=expected):
                _, result = integrate(complete_policy(rule), (value,))
                self.assertEqual(result.assessments[0].applicability, expected)

    def test_address_interface_remote_protocol_and_port_conditions(self):
        cases = (
            (raw_rule(local_addresses=("192.0.2.1-192.0.2.10",)),
             listener(address="192.0.2.4", exposure=BindExposure.INTERFACE),
             FirewallRuleApplicability.INCOMPLETE),
            (raw_rule(local_addresses=("2001:db8::1-2001:db8::10",)),
             listener(address="2001:db8::4", exposure=BindExposure.INTERFACE),
             FirewallRuleApplicability.INCOMPLETE),
            (raw_rule(remote_addresses=("198.51.100.0/24",)), listener(),
             FirewallRuleApplicability.INCOMPLETE),
            (raw_rule(remote_ports=("8443",)), listener(),
             FirewallRuleApplicability.INCOMPLETE),
            (raw_rule(interface_types=(WindowsRawFirewallInterfaceType.LAN,)),
             listener(), FirewallRuleApplicability.INCOMPLETE),
            (raw_rule(protocol=17), listener(),
             FirewallRuleApplicability.NO_MATCH),
            (raw_rule(local_ports=("80",)), listener(),
             FirewallRuleApplicability.NO_MATCH),
        )
        for rule, value, expected in cases:
            with self.subTest(expected=expected, rule=rule):
                _, result = integrate(complete_policy(rule), (value,))
                self.assertEqual(result.assessments[0].applicability, expected)

    def test_collection_and_socket_coverage_are_independent(self):
        policy = complete_policy(raw_rule())
        for socket, expected in (
            (CoverageState.UNKNOWN, CoverageState.UNKNOWN),
            (CoverageState.INCOMPLETE, CoverageState.INCOMPLETE),
            (CoverageState.COMPLETE, CoverageState.COMPLETE),
        ):
            with self.subTest(socket=socket):
                _, result = integrate(policy, socket=socket)
                self.assertEqual(result.collection_coverage, CoverageState.COMPLETE)
                self.assertEqual(result.applicability_coverage, expected)

    def test_zero_listeners_is_vacuously_complete(self):
        _, result = integrate(complete_policy(), ())
        self.assertEqual(result.assessments, ())
        self.assertEqual(result.applicability_coverage, CoverageState.COMPLETE)

    def test_pid_distinct_tcp_and_udp_occurrences_remain_aligned(self):
        listeners = (
            listener(pid=10),
            listener(pid=11),
            listener(protocol=NetworkProtocol.UDP, state="UNCONN", pid=12),
        )
        _, result = integrate(complete_policy(raw_rule()), listeners)
        self.assertEqual(len(result.assessments), len(listeners))
        self.assertEqual(
            tuple(value.applicability for value in result.assessments),
            (
                FirewallRuleApplicability.MATCHING_ALLOW,
                FirewallRuleApplicability.MATCHING_ALLOW,
                FirewallRuleApplicability.NO_MATCH,
            ),
        )

    def test_result_is_immutable_slotted_and_contains_no_raw_values(self):
        _, result = integrate(complete_policy())
        self.assertIsInstance(result, WindowsListenerPolicyIntegrationResult)
        self.assertFalse(hasattr(result, "__dict__"))
        with self.assertRaises((dataclasses.FrozenInstanceError, AttributeError)):
            result.collection_coverage = CoverageState.UNKNOWN
        fields = {field.name for field in dataclasses.fields(result)}
        self.assertEqual(fields, {
            "policy_view", "collection_coverage", "applicability_coverage",
            "assessments", "collection_failure",
        })


class WindowsFirewallIntegrationContainmentTests(unittest.TestCase):
    def test_imports_do_not_load_native_firewall_or_launch_subprocess(self):
        with patch("subprocess.Popen") as popen:
            __import__("cyberwatchtower.scanner")
            __import__("cyberwatchtower.platform.windows.adapter")
            __import__(
                "cyberwatchtower.platform.windows.firewall_policy_integration"
            )
            popen.assert_not_called()
        root = Path(__file__).parents[1] / "src" / "cyberwatchtower"
        for relative in (
            "scanner.py",
            "platform/windows/adapter.py",
            "platform/windows/firewall_policy_integration.py",
        ):
            source = (root / relative).read_text(encoding="utf-8").casefold()
            self.assertNotIn("firewall_rule_native", source)
            self.assertNotIn("coinitialize", source)

    def test_private_canaries_do_not_cross_integration_state(self):
        canary = r"C:\Users\Private\SECRET_POLICY_CANARY\listener.exe"
        digest = windows_application_identity(RawWindowsApplicationPath(canary))
        value = listener(
            application_digest=digest, application_name="listener.exe"
        )
        _, result = integrate(complete_policy(), (value,))
        rendered = repr(result)
        self.assertNotIn("SECRET_POLICY_CANARY", rendered)
        self.assertNotIn("Users\\Private", rendered)


if __name__ == "__main__":
    unittest.main()
