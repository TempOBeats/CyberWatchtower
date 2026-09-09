import dataclasses
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cyberwatchtower.firewall_policy import (
    FirewallConditionMatch,
    FirewallRuleAction,
    FirewallRuleApplicability,
    FirewallRuleMatch,
)
from cyberwatchtower.history import compare_reports
from cyberwatchtower.memory.normalizers import normalize_report
from cyberwatchtower.scoring_projection import canonical_finding_id
from cyberwatchtower.platform.models import NetworkProtocol
from cyberwatchtower.platform.windows import (
    FakeWindowsApi,
    RawProcessInfo,
    RawTcpEndpoint,
    RawUdpEndpoint,
    WindowsAddressFamily,
    WindowsApiResult,
    WindowsPlatformAdapter,
    WindowsTcpState,
)
from cyberwatchtower.platform.windows.firewall_policy_integration import (
    ClosedWindowsFirewallPolicyProvider,
    WindowsListenerPolicyIntegrationResult,
)
from cyberwatchtower.platform.windows.firewall_rule_models import (
    RawWindowsApplicationPath,
    RawWindowsFirewallRule,
    WindowsFirewallPolicyView,
    WindowsFirewallRuleCollectionResult,
    WindowsFirewallRuleResultCode,
    WindowsRawFirewallRuleAction,
    WindowsRawFirewallRuleDirection,
    WindowsRawFirewallUnsupportedFeature,
)
from cyberwatchtower.platform.windows.firewall_rules import (
    WindowsFirewallRuleNormalizationResult,
    normalize_windows_firewall_rules,
    windows_application_identity,
)
from cyberwatchtower.reachability import (
    RemoteReachabilityState,
    reachability_from_report,
)
from cyberwatchtower.report_contracts import CoverageState
from cyberwatchtower.reporting import finding_to_dict, save_json_report
from cyberwatchtower.scanner import run_scan

from tests.test_windows_platform_integration import fixture, ok


VIEW = WindowsFirewallPolicyView.CURRENT_POLICY_VIEW


class StaticNormalizedPolicyProvider:
    def __init__(self, result):
        self.result = result
        self.calls = 0

    def collect_normalized_firewall_policy(self):
        self.calls += 1
        return self.result


def raw_rule(**changes):
    values = {
        "policy_view": VIEW,
        "enabled": True,
        "direction": WindowsRawFirewallRuleDirection.INBOUND,
        "action": WindowsRawFirewallRuleAction.ALLOW,
        "profile_mask": 2,
        "protocol": 6,
        "local_ports": ("8080",),
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


def scan(policy=None, *, api_fixture=None):
    provider = (
        ClosedWindowsFirewallPolicyProvider()
        if policy is None
        else StaticNormalizedPolicyProvider(policy)
    )
    adapter = WindowsPlatformAdapter(
        FakeWindowsApi(api_fixture or fixture()), provider
    )
    return provider, run_scan(adapter)


def network_finding(result):
    return next(item for item in result["findings"] if item.source == "network")


def report_mapping(result):
    return {
        "schema_version": "1.6",
        "generated_at": "2026-01-01T00:00:00+00:00",
        "system": result["system"],
        "assessment_domains": result["assessment_domains"],
        "coverage": result["coverage"],
        "assessment_assurance": result["assessment_assurance"],
        "security_score": result["score"],
        "findings": [finding_to_dict(item) for item in result["findings"]],
    }


class WindowsFirewallScannerFailureRoutingTests(unittest.TestCase):
    def test_all_collection_states_route_closed_coverage_and_assessments(self):
        tempting = complete_policy(raw_rule()).rules[0]
        for state in WindowsFirewallRuleResultCode:
            rules = (
                (tempting,)
                if state == WindowsFirewallRuleResultCode.COLLECTION_INCOMPLETE
                else ()
            )
            policy = (
                complete_policy(raw_rule())
                if state == WindowsFirewallRuleResultCode.COMPLETE
                else failed_policy(state, rules=rules)
            )
            with self.subTest(state=state):
                provider, result = scan(policy)
                finding = network_finding(result)
                context = finding.network_context
                assessment = context["policy_assessment"]
                expected_collection = (
                    CoverageState.COMPLETE
                    if state == WindowsFirewallRuleResultCode.COMPLETE
                    else CoverageState.UNKNOWN
                    if state in {
                        WindowsFirewallRuleResultCode.API_UNAVAILABLE,
                        WindowsFirewallRuleResultCode.UNSUPPORTED,
                    }
                    else CoverageState.INCOMPLETE
                )
                expected_applicability = (
                    FirewallRuleApplicability.MATCHING_ALLOW
                    if state == WindowsFirewallRuleResultCode.COMPLETE
                    else FirewallRuleApplicability.UNSUPPORTED
                    if expected_collection == CoverageState.UNKNOWN
                    else FirewallRuleApplicability.INCOMPLETE
                )
                self.assertEqual(provider.calls, 1)
                self.assertEqual(
                    result["coverage"]["network_socket_inspection"], "COMPLETE"
                )
                self.assertEqual(
                    result["coverage"]["host_firewall_rule_collection"],
                    expected_collection.value,
                )
                self.assertEqual(
                    assessment["applicability"], expected_applicability.value
                )
                if state != WindowsFirewallRuleResultCode.COMPLETE:
                    self.assertEqual(assessment["matching_rule_digests"], [])
                    self.assertEqual(
                        context["reachability_state"],
                        RemoteReachabilityState.POTENTIALLY_REACHABLE.value,
                    )
                self.assertNotEqual(
                    context["reachability_state"],
                    RemoteReachabilityState.CONFIRMED_REACHABLE.value,
                )

    def test_default_adapter_policy_is_inert_and_unsupported(self):
        provider, result = scan(None)
        self.assertIsInstance(provider, ClosedWindowsFirewallPolicyProvider)
        self.assertEqual(
            result["coverage"]["host_firewall_rule_collection"], "UNKNOWN"
        )
        self.assertEqual(
            network_finding(result).network_context["policy_assessment"][
                "applicability"
            ],
            FirewallRuleApplicability.UNSUPPORTED.value,
        )

    def test_alignment_failure_preserves_listener_and_fails_policy_closed(self):
        adapter = WindowsPlatformAdapter(
            FakeWindowsApi(fixture()),
            StaticNormalizedPolicyProvider(complete_policy(raw_rule())),
        )
        malformed = WindowsListenerPolicyIntegrationResult(
            VIEW, CoverageState.COMPLETE, CoverageState.COMPLETE, ()
        )
        with patch.object(
            adapter, "collect_listener_firewall_policy", return_value=malformed
        ):
            result = run_scan(adapter)
        finding = network_finding(result)
        self.assertEqual(
            result["coverage"]["host_firewall_rule_collection"], "INCOMPLETE"
        )
        self.assertEqual(
            finding.network_context["policy_assessment"]["applicability"],
            FirewallRuleApplicability.INCOMPLETE.value,
        )
        self.assertIn("8080", "\n".join(finding.evidence))

    def test_extra_assessment_also_fails_alignment_closed(self):
        adapter = WindowsPlatformAdapter(
            FakeWindowsApi(fixture()),
            StaticNormalizedPolicyProvider(complete_policy(raw_rule())),
        )
        valid = adapter.collect_listener_firewall_policy(
            adapter.collect_network().observations,
            CoverageState.COMPLETE,
            adapter.collect_firewall_inbound_policy(),
        )
        malformed = dataclasses.replace(
            valid, assessments=valid.assessments + valid.assessments[:1]
        )
        with patch.object(
            adapter, "collect_listener_firewall_policy", return_value=malformed
        ):
            result = run_scan(adapter)
        self.assertEqual(
            result["coverage"]["host_firewall_rule_collection"], "INCOMPLETE"
        )
        self.assertEqual(
            network_finding(result).network_context["policy_assessment"][
                "applicability"
            ],
            FirewallRuleApplicability.INCOMPLETE.value,
        )


class WindowsFirewallScannerPolicyRoutingTests(unittest.TestCase):
    def assert_policy(self, policy, applicability, reachability, *, match=None):
        with match or _null_context():
            _, result = scan(policy)
        finding = network_finding(result)
        context = finding.network_context
        self.assertEqual(
            context["policy_assessment"]["applicability"], applicability.value
        )
        self.assertEqual(context["reachability_state"], reachability.value)
        self.assertNotEqual(
            context["reachability_state"],
            RemoteReachabilityState.CONFIRMED_REACHABLE.value,
        )
        return result

    def test_complete_policy_outcomes_reach_network_context(self):
        allow = raw_rule()
        block = raw_rule(action=WindowsRawFirewallRuleAction.BLOCK)
        no_match = raw_rule(local_ports=("80",))
        unsupported = raw_rule(unsupported_features=(
            WindowsRawFirewallUnsupportedFeature.UNMODELED_NATIVE_PREDICATE,
        ))
        cases = (
            (complete_policy(allow), FirewallRuleApplicability.MATCHING_ALLOW,
             RemoteReachabilityState.POTENTIALLY_REACHABLE),
            (complete_policy(block), FirewallRuleApplicability.MATCHING_BLOCK,
             RemoteReachabilityState.BLOCKED_BY_OBSERVED_POLICY),
            (complete_policy(no_match), FirewallRuleApplicability.NO_MATCH,
             RemoteReachabilityState.POTENTIALLY_REACHABLE),
            (complete_policy(allow, block), FirewallRuleApplicability.CONFLICTING,
             RemoteReachabilityState.POTENTIALLY_REACHABLE),
            (complete_policy(unsupported), FirewallRuleApplicability.INCOMPLETE,
             RemoteReachabilityState.POTENTIALLY_REACHABLE),
        )
        for policy, applicability, reachability in cases:
            with self.subTest(applicability=applicability):
                self.assert_policy(policy, applicability, reachability)

    def test_ambiguous_frozen_aggregation_reaches_network_context(self):
        policy = complete_policy(
            raw_rule(action=WindowsRawFirewallRuleAction.BLOCK)
        )
        match = FirewallRuleMatch(
            policy.rules[0].semantic_rule_id,
            FirewallRuleAction.BLOCK,
            FirewallConditionMatch.MATCH,
            False,
        )
        self.assert_policy(
            policy,
            FirewallRuleApplicability.AMBIGUOUS,
            RemoteReachabilityState.POTENTIALLY_REACHABLE,
            match=patch("cyberwatchtower.firewall_policy._rule_match",
                        return_value=match),
        )

    def test_unsupported_collection_reaches_network_context(self):
        self.assert_policy(
            failed_policy(WindowsFirewallRuleResultCode.UNSUPPORTED),
            FirewallRuleApplicability.UNSUPPORTED,
            RemoteReachabilityState.POTENTIALLY_REACHABLE,
        )

    def test_matching_allow_does_not_add_scoring_or_coverage_findings(self):
        _, allow = scan(complete_policy(raw_rule()))
        _, no_match = scan(complete_policy(raw_rule(local_ports=("80",))))
        self.assertEqual(allow["score"]["scoring_version"], "2")
        self.assertEqual(allow["score"]["score"], no_match["score"]["score"])
        self.assertFalse(any(
            item.source == "host_firewall_policy" for item in allow["findings"]
        ))


class _null_context:
    def __enter__(self):
        return None

    def __exit__(self, exc_type, exc_value, traceback):
        return False


class WindowsFirewallReportHistoryTests(unittest.TestCase):
    def test_report_16_round_trip_and_memory_normalization(self):
        _, result = scan(complete_policy(raw_rule()))
        report = report_mapping(result)
        parsed = reachability_from_report(
            next(item for item in report["findings"] if item["source"] == "network")[
                "network_context"
            ],
            report_schema_version="1.6",
        )
        normalized, omitted = normalize_report(report)
        self.assertEqual(
            parsed.policy_assessment.applicability,
            FirewallRuleApplicability.MATCHING_ALLOW,
        )
        self.assertEqual(normalized.schema_version, "1.6")
        self.assertEqual(omitted, 3)

        with tempfile.TemporaryDirectory() as directory:
            path = save_json_report(result, directory)
            serialized = json.loads(Path(path).read_text(encoding="utf-8"))
        encoded = json.dumps(serialized)
        self.assertEqual(serialized["schema_version"], "1.6")
        self.assertIn("policy_assessment", encoded)
        self.assertNotIn("canary-secret", encoded.casefold())

    def test_policy_transitions_keep_finding_identity_stable(self):
        policies = (
            complete_policy(raw_rule()),
            complete_policy(raw_rule(action=WindowsRawFirewallRuleAction.BLOCK)),
            complete_policy(raw_rule(unsupported_features=(
                WindowsRawFirewallUnsupportedFeature.UNMODELED_NATIVE_PREDICATE,
            ))),
            failed_policy(WindowsFirewallRuleResultCode.TIMEOUT),
        )
        reports = tuple(report_mapping(scan(value)[1]) for value in policies)
        identities = tuple(
            next(item["finding_id"] for item in report["findings"]
                 if item["source"] == "network")
            for report in reports
        )
        self.assertEqual(len(set(identities)), 1)
        for previous, current in zip(reports, reports[1:]):
            comparison = compare_reports(previous, current)
            self.assertFalse(any(
                item["source"] == "network"
                for item in comparison["new_findings"]
            ))
            self.assertFalse(any(
                item["source"] == "network"
                for item in comparison["resolved_findings"]
            ))

    def test_listener_resolution_still_uses_socket_coverage_only(self):
        _, present = scan(complete_policy(raw_rule()))
        empty_fixture = dataclasses.replace(
            fixture(),
            tcp_endpoints=ok(()),
            udp_endpoints=ok(()),
        )
        _, absent = scan(
            failed_policy(WindowsFirewallRuleResultCode.TIMEOUT),
            api_fixture=empty_fixture,
        )
        comparison = compare_reports(
            report_mapping(present), report_mapping(absent)
        )
        self.assertTrue(any(
            item["source"] == "network"
            for item in comparison["resolved_findings"]
        ))


class WindowsFirewallMultiplicityAndContainmentTests(unittest.TestCase):
    def test_pid_distinct_same_policy_aggregates_only_runtime_multiplicity(self):
        path = r"C:\Program Files\Synthetic\same.exe"
        base = fixture()
        multi = dataclasses.replace(
            base,
            tcp_endpoints=ok((
                RawTcpEndpoint(WindowsAddressFamily.IPV4, "0.0.0.0", 8080,
                               200, WindowsTcpState.LISTEN),
                RawTcpEndpoint(WindowsAddressFamily.IPV4, "0.0.0.0", 8080,
                               201, WindowsTcpState.LISTEN),
            )),
            udp_endpoints=ok(()),
            processes=(
                (200, ok(RawProcessInfo(200, "same.exe", path))),
                (201, ok(RawProcessInfo(201, "same.exe", path))),
            ),
            services=ok(()),
        )
        _, result = scan(complete_policy(raw_rule()), api_fixture=multi)
        finding = network_finding(result)
        self.assertEqual(finding.runtime_instance_count, 2)

    def test_pid_distinct_application_policy_differences_do_not_collide(self):
        first_path = r"C:\Program Files\Synthetic\one\same.exe"
        second_path = r"C:\Program Files\Synthetic\two\same.exe"
        base = fixture()
        multi = dataclasses.replace(
            base,
            tcp_endpoints=ok((
                RawTcpEndpoint(WindowsAddressFamily.IPV4, "0.0.0.0", 8080,
                               200, WindowsTcpState.LISTEN),
                RawTcpEndpoint(WindowsAddressFamily.IPV4, "0.0.0.0", 8080,
                               201, WindowsTcpState.LISTEN),
            )),
            udp_endpoints=ok(()),
            processes=(
                (200, ok(RawProcessInfo(200, "same.exe", first_path))),
                (201, ok(RawProcessInfo(201, "same.exe", second_path))),
            ),
            services=ok(()),
        )
        policy = complete_policy(raw_rule(
            application_path=RawWindowsApplicationPath(first_path)
        ))
        _, result = scan(policy, api_fixture=multi)
        findings = [item for item in result["findings"] if item.source == "network"]
        self.assertEqual(len(findings), 2)
        self.assertEqual(len({canonical_finding_id(item) for item in findings}), 2)
        states = {
            item.network_context["policy_assessment"]["applicability"]
            for item in findings
        }
        self.assertEqual(states, {"MATCHING_ALLOW", "NO_MATCH"})

    def test_udp_wildcard_policy_routing_preserves_one_finding(self):
        path = r"C:\Program Files\Synthetic\udp.exe"
        base = fixture()
        udp = dataclasses.replace(
            base,
            tcp_endpoints=ok(()),
            udp_endpoints=ok((RawUdpEndpoint(
                WindowsAddressFamily.IPV6, "::", 5353, 300
            ),)),
            processes=((300, ok(RawProcessInfo(300, "udp.exe", path))),),
            services=ok(()),
        )
        policy = complete_policy(raw_rule(protocol=17, local_ports=("5353",)))
        _, result = scan(policy, api_fixture=udp)
        findings = [item for item in result["findings"] if item.source == "network"]
        self.assertEqual(len(findings), 1)
        self.assertIn("Protocol: udp", findings[0].evidence)
        self.assertEqual(
            findings[0].network_context["policy_assessment"]["applicability"],
            "MATCHING_ALLOW",
        )

    def test_scanner_and_adapter_have_no_helper_or_native_dependency(self):
        root = Path(__file__).parents[1] / "src" / "cyberwatchtower"
        for relative in (
            "scanner.py", "network.py", "platform/windows/adapter.py",
            "platform/windows/firewall_policy_integration.py",
        ):
            source = (root / relative).read_text(encoding="utf-8").casefold()
            for prohibited in (
                "firewall_rule_native", "windowsfirewallsubprocesslauncher",
                "run_isolated_windows_firewall_helper", "coinitialize",
            ):
                self.assertNotIn(prohibited, source)


if __name__ == "__main__":
    unittest.main()
