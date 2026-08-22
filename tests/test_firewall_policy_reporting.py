import copy
import json
import tempfile
import unittest

from cyberwatchtower.history import compare_reports
from cyberwatchtower.memory.normalizers import normalize_report
from cyberwatchtower.models import AssessmentState, Finding, FindingKind, Severity
from cyberwatchtower.platform.models import BindExposure
from cyberwatchtower.reachability import (
    ReachabilityEvidenceBasis,
    RemoteReachabilityState,
    reachability_from_report,
)
from cyberwatchtower.reporting import finding_to_dict, save_json_report
from cyberwatchtower.scoring_projection import project_scoring_findings
from cyberwatchtower.scoring_v2 import calculate_security_score_v2


POLICY_DIGEST = "a" * 64


def policy_context(state="BLOCKED_BY_OBSERVED_POLICY"):
    return {
        "bind_exposure": "all_interfaces",
        "bind_epistemic_role": "OBSERVED_FACT",
        "reachability_state": state,
        "reachability_epistemic_role": "DETERMINISTIC_DERIVATION",
        "evidence_basis": [
            "SOCKET_WILDCARD_BIND",
            "HOST_POLICY_EXPLICIT_BLOCK" if state == "BLOCKED_BY_OBSERVED_POLICY"
            else "HOST_POLICY_INCOMPLETE",
        ],
        "policy_assessment": {
            "applicability": (
                "MATCHING_BLOCK" if state == "BLOCKED_BY_OBSERVED_POLICY"
                else "INCOMPLETE"
            ),
            "default_policy_context": "BLOCK",
            "evidence_basis": [
                "EXPLICIT_UNIVERSAL_BLOCK" if state == "BLOCKED_BY_OBSERVED_POLICY"
                else "POLICY_EVALUATION_INCOMPLETE"
            ],
            "matching_rule_digests": [POLICY_DIGEST],
            "rule_collection_coverage": "COMPLETE",
            "rule_applicability_coverage": (
                "COMPLETE" if state == "BLOCKED_BY_OBSERVED_POLICY"
                else "INCOMPLETE"
            ),
        },
    }


def network_finding(context=None):
    return Finding(
        "Service listening on all interfaces", "Observed bind", Severity.MEDIUM,
        "Review exposure", evidence=["Protocol: tcp", "Address: 0.0.0.0",
                                      "Port: 443", "Process: service.exe"],
        finding_id="listener:stable", source="network", kind=FindingKind.RISK,
        assessment_state=AssessmentState.POTENTIAL,
        network_context=context or policy_context(),
    )


def report_mapping(context=None):
    finding = network_finding(context)
    return {
        "schema_version": "1.6",
        "generated_at": "2026-08-21T00:00:00+00:00",
        "system": {"hostname": "host", "system_id": "system:test"},
        "assessment_domains": [
            "network_socket_inspection", "host_firewall_rule_collection",
            "host_firewall_rule_applicability", "network_reachability",
        ],
        "coverage": {
            "network_socket_inspection": "COMPLETE",
            "host_firewall_rule_collection": "COMPLETE",
            "host_firewall_rule_applicability": "COMPLETE",
            "network_reachability": "COMPLETE",
        },
        "security_score": {
            "scoring_version": "1", "score": 90, "risk_level": "LOW",
            "counts": {"MEDIUM": 1},
        },
        "findings": [finding_to_dict(finding)],
    }


class FirewallPolicyReportingTests(unittest.TestCase):
    def test_schema_16_round_trip_keeps_only_listener_policy_summary(self):
        report = report_mapping()
        normalized, omitted = normalize_report(report)
        self.assertEqual(normalized.schema_version, "1.6")
        self.assertEqual(omitted, 0)
        parsed = reachability_from_report(report["findings"][0]["network_context"])
        self.assertEqual(
            parsed.state, RemoteReachabilityState.BLOCKED_BY_OBSERVED_POLICY
        )
        self.assertEqual(parsed.policy_assessment.matches[0].semantic_rule_id,
                         POLICY_DIGEST)
        serialized = json.dumps(
            report["findings"][0]["network_context"]["policy_assessment"]
        )
        for prohibited in (
            "MachineGuid", "native error", "C:\\\\Users", "pid",
            "rule_name", "description", "provider",
        ):
            self.assertNotIn(prohibited, serialized)

    def test_new_reports_are_schema_16_without_claiming_unimplemented_domains(self):
        result = {
            "system": {"hostname": "host"},
            "assessment_domains": ["network_socket_inspection", "network_reachability"],
            "coverage": {
                "network_socket_inspection": "COMPLETE",
                "network_reachability": "INCOMPLETE",
            },
            "score": {"score": 100, "risk_level": "LOW", "counts": {}},
            "findings": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            saved = json.loads(save_json_report(result, directory).read_text())
        self.assertEqual(saved["schema_version"], "1.6")
        self.assertNotIn("host_firewall_rule_collection", saved["assessment_domains"])

    def test_schemas_10_through_15_remain_readable_without_policy_inference(self):
        base = report_mapping()
        base["findings"][0]["network_context"].pop("policy_assessment")
        base["findings"][0]["network_context"]["reachability_state"] = (
            "POTENTIALLY_REACHABLE"
        )
        base["findings"][0]["network_context"]["evidence_basis"] = [
            "SOCKET_WILDCARD_BIND"
        ]
        for version in ("1.0", "1.1", "1.2", "1.3", "1.4", "1.5"):
            report = copy.deepcopy(base)
            report["schema_version"] = version
            if version in {"1.0", "1.1"}:
                report.pop("assessment_domains")
            if version == "1.0":
                report["findings"][0].pop("kind")
                report["findings"][0].pop("assessment_state")
            if version in {"1.0", "1.1", "1.2"}:
                report["findings"][0].pop("network_context")
            if version != "1.5":
                report["findings"][0].pop("runtime_instance_count")
            if version in {"1.0", "1.1", "1.2", "1.3"}:
                report["security_score"].pop("scoring_version")
            normalized, _ = normalize_report(report)
            self.assertEqual(normalized.schema_version, version)

    def test_malformed_policy_summary_fails_closed(self):
        mutations = (
            ("applicability", "MODEL_SAYS_BLOCKED"),
            ("matching_rule_digests", ["not-a-digest"]),
            ("matching_rule_digests", [POLICY_DIGEST, POLICY_DIGEST]),
            ("rule_collection_coverage", "SUCCESS"),
            ("evidence_basis", ["native error: secret"]),
        )
        for key, value in mutations:
            report = report_mapping()
            report["findings"][0]["network_context"]["policy_assessment"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                normalize_report(report)

    def test_legacy_schema_cannot_claim_new_policy_semantics(self):
        report = report_mapping()
        report["schema_version"] = "1.5"
        with self.assertRaises(ValueError):
            normalize_report(report)

    def test_policy_state_changes_keep_identity_and_lifecycle(self):
        blocked = report_mapping()
        potential = report_mapping(policy_context("POTENTIALLY_REACHABLE"))
        comparison = compare_reports(blocked, potential)
        self.assertEqual(comparison["new_findings"], [])
        self.assertEqual(comparison["resolved_findings"], [])
        self.assertEqual(comparison["uncertain_findings"], [])
        self.assertEqual(
            blocked["findings"][0]["finding_id"],
            potential["findings"][0]["finding_id"],
        )

    def test_listener_resolution_uses_socket_not_policy_coverage(self):
        previous = report_mapping()
        current = report_mapping()
        current["findings"] = []
        current["coverage"]["network_socket_inspection"] = "INCOMPLETE"
        uncertain = compare_reports(previous, current)
        self.assertEqual(len(uncertain["uncertain_findings"]), 1)
        self.assertEqual(uncertain["resolved_findings"], [])

        current["coverage"]["network_socket_inspection"] = "COMPLETE"
        current["coverage"]["host_firewall_rule_collection"] = "INCOMPLETE"
        current["coverage"]["host_firewall_rule_applicability"] = "INCOMPLETE"
        resolved = compare_reports(previous, current)
        self.assertEqual(len(resolved["resolved_findings"]), 1)
        self.assertEqual(resolved["uncertain_findings"], [])

    def test_policy_metadata_does_not_change_scoring(self):
        plain = network_finding({
            "bind_exposure": BindExposure.ALL_INTERFACES.value,
            "bind_epistemic_role": "OBSERVED_FACT",
            "reachability_state": "POTENTIALLY_REACHABLE",
            "reachability_epistemic_role": "DETERMINISTIC_DERIVATION",
            "evidence_basis": [ReachabilityEvidenceBasis.SOCKET_WILDCARD_BIND.value],
        })
        policy = network_finding(policy_context("POTENTIALLY_REACHABLE"))
        plain_score = calculate_security_score_v2(project_scoring_findings((plain,), {}))
        policy_score = calculate_security_score_v2(project_scoring_findings((policy,), {}))
        self.assertEqual(plain_score, policy_score)


if __name__ == "__main__":
    unittest.main()
