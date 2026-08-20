import copy
import dataclasses
import unittest

from cyberwatchtower.advisor.context import build_advisor_context
from cyberwatchtower.advisor.deterministic import build_deterministic_advisory
from cyberwatchtower.advisor.service import build_provider_request
from cyberwatchtower.advisor.providers.base import ProviderAction, ProviderFinding
from cyberwatchtower.briefing.builder import build_security_briefing
from cyberwatchtower.core.evidence import EpistemicRole, EvidenceSource
from cyberwatchtower.core.grounding import validate_grounding
from cyberwatchtower.platform import BindExposure
from cyberwatchtower.reachability import (
    ReachabilityEvidenceBasis,
    RemoteReachabilityState,
    assess_listener_reachability,
    reachability_coverage,
)
from cyberwatchtower.report_contracts import CoverageState
from cyberwatchtower.reporting import finding_to_dict
from cyberwatchtower.models import Finding, FindingKind, Severity, AssessmentState
from cyberwatchtower.presentation import group_findings
from cyberwatchtower.history import compare_reports
from cyberwatchtower.intelligence import analyze_history
from cyberwatchtower.scanner import _linux_policy_basis, run_scan
from tests.test_windows_platform_integration import (
    fixture,
    ok,
    profiles,
)
from cyberwatchtower.platform.windows import FakeWindowsApi, WindowsPlatformAdapter
from cyberwatchtower.platform import (
    FirewallEnablement,
    FirewallInboundAction,
    FirewallProfile,
)


class ReachabilityContractTests(unittest.TestCase):
    def test_loopback_and_interface_bind_are_distinct(self):
        loopback = assess_listener_reachability(BindExposure.LOOPBACK)
        interface = assess_listener_reachability(BindExposure.INTERFACE)
        wildcard = assess_listener_reachability(BindExposure.ALL_INTERFACES)

        self.assertEqual(
            loopback.state, RemoteReachabilityState.NOT_REMOTELY_BOUND
        )
        self.assertEqual(
            interface.state, RemoteReachabilityState.POTENTIALLY_REACHABLE
        )
        self.assertEqual(
            wildcard.state, RemoteReachabilityState.POTENTIALLY_REACHABLE
        )
        self.assertNotEqual(interface.bind_exposure, wildcard.bind_exposure)

    def test_socket_and_reachability_coverage_are_independent(self):
        wildcard = assess_listener_reachability(BindExposure.ALL_INTERFACES)
        loopback = assess_listener_reachability(BindExposure.LOOPBACK)
        self.assertEqual(
            reachability_coverage(CoverageState.COMPLETE, (wildcard,)),
            CoverageState.INCOMPLETE,
        )
        self.assertEqual(
            reachability_coverage(CoverageState.COMPLETE, (loopback,)),
            CoverageState.COMPLETE,
        )
        self.assertEqual(
            reachability_coverage(CoverageState.INCOMPLETE, (loopback,)),
            CoverageState.INCOMPLETE,
        )

    def test_linux_default_policies_are_context_not_reachability_proof(self):
        for policy, expected_basis in (
            ("ACCEPT", ReachabilityEvidenceBasis.LINUX_INPUT_ACCEPT),
            ("DROP", ReachabilityEvidenceBasis.LINUX_INPUT_DROP),
        ):
            with self.subTest(policy=policy):
                basis = _linux_policy_basis({"policies": {"INPUT": policy}})
                assessment = assess_listener_reachability(
                    BindExposure.ALL_INTERFACES, basis
                )
                self.assertEqual(
                    assessment.state,
                    RemoteReachabilityState.POTENTIALLY_REACHABLE,
                )
                self.assertIn(expected_basis, assessment.evidence_basis)

    def test_same_listener_id_is_not_resolved_when_metadata_becomes_explicit(self):
        finding = {
            "finding_id": "listener:stable", "title": "Listener bound broadly",
            "severity": "MEDIUM", "source": "network", "kind": "RISK",
            "assessment_state": "CONFIRMED", "evidence": [],
        }
        previous = {
            "security_score": {"score": 90}, "findings": [finding],
            "coverage": {"network_socket_inspection": "COMPLETE"},
        }
        current_finding = dict(finding)
        current_finding["assessment_state"] = "POTENTIAL"
        current_finding["network_context"] = {
            "bind_exposure": "all_interfaces",
            "bind_epistemic_role": "OBSERVED_FACT",
            "reachability_state": "POTENTIALLY_REACHABLE",
            "reachability_epistemic_role": "DETERMINISTIC_DERIVATION",
            "evidence_basis": ["SOCKET_WILDCARD_BIND"],
        }
        current = {
            "security_score": {"score": 90}, "findings": [current_finding],
            "assessment_domains": [
                "network_socket_inspection", "network_reachability",
            ],
            "coverage": {
                "network_socket_inspection": "COMPLETE",
                "network_reachability": "INCOMPLETE",
            },
        }
        comparison = compare_reports(previous, current)
        self.assertEqual(comparison["new_findings"], [])
        self.assertEqual(comparison["resolved_findings"], [])
        self.assertEqual(comparison["uncertain_findings"], [])


class WindowsReachabilityIntegrationTests(unittest.TestCase):
    def scan(self, **kwargs):
        return run_scan(WindowsPlatformAdapter(FakeWindowsApi(fixture(**kwargs))))

    def network_finding(self, result):
        return next(item for item in result["findings"] if item.source == "network")

    def test_default_block_is_restrictive_context_not_blocking_proof(self):
        result = self.scan()
        finding = self.network_finding(result)
        context = finding.network_context
        self.assertEqual(finding.assessment_state.value, "POTENTIAL")
        self.assertEqual(context["reachability_state"], "POTENTIALLY_REACHABLE")
        self.assertIn("WINDOWS_RESTRICTIVE_DEFAULT", context["evidence_basis"])
        self.assertNotEqual(context["reachability_state"], "BLOCKED_BY_OBSERVED_POLICY")

    def test_allow_disabled_and_multi_profile_are_permissive_context_only(self):
        cases = (
            ok(profiles(
                FirewallProfile.PUBLIC,
                public_action=FirewallInboundAction.ALLOW,
            )),
            ok(profiles(
                FirewallProfile.PUBLIC,
                disabled=FirewallProfile.PUBLIC,
            )),
            ok(profiles(
                FirewallProfile.PRIVATE,
                FirewallProfile.PUBLIC,
                public_action=FirewallInboundAction.ALLOW,
            )),
        )
        expected = (
            "WINDOWS_PERMISSIVE_DEFAULT",
            "WINDOWS_FIREWALL_DISABLED",
            "WINDOWS_PERMISSIVE_DEFAULT",
        )
        for firewall, basis in zip(cases, expected):
            with self.subTest(basis=basis):
                result = self.scan(firewall=firewall)
                finding = self.network_finding(result)
                self.assertEqual(
                    finding.network_context["reachability_state"],
                    "POTENTIALLY_REACHABLE",
                )
                self.assertIn(basis, finding.network_context["evidence_basis"])
                self.assertTrue(any(
                    item.source == "firewall_inbound_policy"
                    and item.assessment_state.value == "CONFIRMED"
                    for item in result["findings"]
                ) if basis == "WINDOWS_FIREWALL_DISABLED" else True)
                if basis == "WINDOWS_PERMISSIVE_DEFAULT":
                    self.assertTrue(any(
                        "allows inbound traffic by default" in item.title
                        for item in result["findings"]
                    ))

    def test_listener_identity_and_score_are_preserved(self):
        finding = self.network_finding(self.scan())
        serialized = finding_to_dict(finding)
        self.assertEqual(serialized["finding_id"], (
            "type=alternate http service listening on all interfaces|"
            "address=0.0.0.0|application=windows-service:demosvc|port=8080|"
            "process=python.exe|protocol=tcp"
        ))
        self.assertEqual(self.scan()["score"]["score"], 96)

    def test_partial_endpoint_coverage_is_separate_from_reachability(self):
        from cyberwatchtower.platform.windows import WindowsFailureCode

        result = self.scan(tcp_failure=WindowsFailureCode.PARTIAL_RESULT)
        self.assertEqual(
            result["coverage"]["network_socket_inspection"], "INCOMPLETE"
        )
        self.assertEqual(
            result["coverage"]["network_reachability"], "INCOMPLETE"
        )
        self.assertIn("firewall_inbound_policy", result["coverage"])


class ReachabilityPresentationTests(unittest.TestCase):
    def _report(self):
        result = run_scan(WindowsPlatformAdapter(FakeWindowsApi(fixture())))
        first = finding_to_dict(next(
            item for item in result["findings"] if item.source == "network"
        ))
        second = copy.deepcopy(first)
        second["finding_id"] = first["finding_id"] + "|family=ipv6"
        second["evidence"] = [
            "Address: ::" if item == "Address: 0.0.0.0" else item
            for item in second["evidence"]
        ]
        return {
            "schema_version": "1.3",
            "system": {"hostname": "WIN", "system_id": "system:test"},
            "assessment_domains": [
                "firewall_technology", "firewall_inbound_policy",
                "network_socket_inspection", "network_reachability",
            ],
            "coverage": {
                "firewall_technology": "COMPLETE",
                "firewall_inbound_policy": "COMPLETE",
                "network_socket_inspection": "COMPLETE",
                "network_reachability": "INCOMPLETE",
            },
            "security_score": {
                "score": 80, "risk_level": "MODERATE",
                "counts": {"MEDIUM": 2},
            },
            "findings": [first, second],
        }

    def test_grouping_preserves_atomic_ids_and_groups_advisor_action(self):
        report = self._report()
        context = build_advisor_context(report, None, None)
        advisory = build_deterministic_advisory(context)
        expected_ids = tuple(sorted(item["finding_id"] for item in report["findings"]))
        self.assertEqual(advisory.actions[0].finding_ids, expected_ids)
        self.assertEqual(advisory.finding_groups[0].finding_ids, expected_ids)
        self.assertEqual(len(context.findings), 2)
        self.assertEqual(report["security_score"]["score"], 80)
        provider = build_provider_request(context, advisory)
        self.assertEqual(
            {item.name for item in dataclasses.fields(ProviderFinding)},
            {
                "finding_id", "severity", "kind", "assessment_state",
                "is_new", "is_recurring", "service_name", "process", "port",
            },
        )
        self.assertEqual(
            {item.name for item in dataclasses.fields(ProviderAction)},
            {"action_id", "finding_ids", "deterministic_priority"},
        )
        self.assertNotIn("network_context", repr(provider))
        self.assertNotIn("evidence_basis", repr(provider))
        self.assertTrue(all(
            "presentation_group_id" not in item for item in report["findings"]
        ))

    def test_cli_projection_groups_without_mutating_atomic_findings(self):
        first = Finding(
            "Listener", "Observed", Severity.MEDIUM, "Review",
            finding_id="listener:v4", source="network", kind=FindingKind.RISK,
            assessment_state=AssessmentState.POTENTIAL,
            presentation_group_id="presentation:group",
        )
        second = Finding(
            "Listener", "Observed", Severity.MEDIUM, "Review",
            finding_id="listener:v6", source="network", kind=FindingKind.RISK,
            assessment_state=AssessmentState.POTENTIAL,
            presentation_group_id="presentation:group",
        )
        findings = [first, second]
        groups = group_findings(findings)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].findings, (first, second))
        self.assertEqual(
            [item.finding_id for item in findings],
            ["listener:v4", "listener:v6"],
        )

    def test_recurring_projection_has_shared_group_without_changing_ids(self):
        report = self._report()
        second_scan = copy.deepcopy(report)
        intelligence = analyze_history([report, second_scan])
        records = intelligence["findings"]
        self.assertEqual(len(records), 2)
        self.assertEqual({item["occurrences"] for item in records}, {2})
        self.assertEqual(len({item["presentation_group_id"] for item in records}), 1)
        self.assertEqual(
            {item["finding_id"] for item in records},
            {item["finding_id"] for item in report["findings"]},
        )

    def test_briefing_separates_observation_and_derivation_roles(self):
        briefing = build_security_briefing(self._report(), None, None)
        self.assertTrue(validate_grounding(briefing.response).valid)
        roles = {
            item.source: item.epistemic_role for item in briefing.response.evidence
        }
        self.assertEqual(
            roles[EvidenceSource.DETERMINISTIC_FINDING],
            EpistemicRole.OBSERVED_FACT,
        )
        self.assertEqual(
            roles[EvidenceSource.DETERMINISTIC_INTERPRETATION],
            EpistemicRole.DETERMINISTIC_DERIVATION,
        )


if __name__ == "__main__":
    unittest.main()
