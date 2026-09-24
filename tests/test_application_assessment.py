import copy
import re
import unittest
from dataclasses import FrozenInstanceError
from unittest.mock import patch

from cyberwatchtower.application import (
    ApplicationErrorCode,
    CurrentSystemAssessmentRequest,
    CyberWatchtowerApplication,
    CyberWatchtowerApplicationError,
    EvidenceProjectionState,
    SupportedPlatform,
)
from cyberwatchtower.firewall_policy import EvaluatedPolicyDisposition
from cyberwatchtower.models import AssessmentState, Finding, FindingKind, Severity
from cyberwatchtower.platform.errors import UnsupportedPlatformError
from cyberwatchtower.platform.models import BindExposure
from cyberwatchtower.reachability import RemoteReachabilityState
from cyberwatchtower.report_contracts import (
    AssessmentAssurance,
    CoverageState,
    assessment_assurance_summary,
)
from cyberwatchtower.scoring_contracts import (
    NetworkScoringIdentity,
    ScoringCategory,
    ScoringFinding,
    ScoringVersion,
)
from cyberwatchtower.scoring_report import serialize_scoring_result
from cyberwatchtower.scoring_v2 import calculate_security_score_v2


OPERATION_ID = re.compile(r"^assessment:[0-9a-f]{32}$")
FINDING_ID = "finding:listener:tcp:443"


def _policy_context():
    return {
        "bind_exposure": "all_interfaces",
        "bind_epistemic_role": "OBSERVED_FACT",
        "reachability_state": "POTENTIALLY_REACHABLE",
        "reachability_epistemic_role": "DETERMINISTIC_DERIVATION",
        "evidence_basis": ["SOCKET_WILDCARD_BIND", "HOST_POLICY_INCOMPLETE"],
        "policy_assessment": {
            "applicability": "NO_MATCH",
            "default_policy_context": "ALLOW",
            "evidence_basis": ["NO_APPLICABLE_RULE", "DEFAULT_POLICY_CONTEXT"],
            "matching_rule_digests": [],
            "rule_collection_coverage": "COMPLETE",
            "rule_applicability_coverage": "COMPLETE",
            "evaluated_policy_disposition": "ALLOW",
        },
    }


def _finding(*, finding_id=FINDING_ID, source="network", evidence=None):
    return Finding(
        title="Service listening on all interfaces",
        description="A TCP listener is bound broadly.",
        severity=Severity.MEDIUM,
        recommendation="Restrict exposure when unnecessary.",
        evidence=list(evidence or [
            "Protocol: tcp",
            "Address: 0.0.0.0",
            "Port: 443",
            "Process: service.exe",
            "Application: harmless-display-name",
            "PID: 123",
            "harmless legacy note",
        ]),
        confidence=91,
        technique_id="T1049",
        finding_id=finding_id,
        source=source,
        kind=FindingKind.RISK,
        assessment_state=AssessmentState.POTENTIAL,
        network_context=_policy_context(),
        presentation_group_id="presentation:listener:tcp:443",
        runtime_instance_count=2,
    )


def _score(finding_id=FINDING_ID):
    projected = ScoringFinding(
        finding_id=finding_id,
        severity=Severity.MEDIUM,
        kind=FindingKind.RISK,
        assessment_state=AssessmentState.POTENTIAL,
        source="network",
        category=ScoringCategory.NETWORK_EXPOSURE,
        network_identity=NetworkScoringIdentity(
            protocol="tcp",
            port=443,
            bind_exposure=BindExposure.ALL_INTERFACES,
            reachability_state=RemoteReachabilityState.POTENTIALLY_REACHABLE,
            process_basename="service.exe",
        ),
    )
    result = calculate_security_score_v2((projected,))
    return serialize_scoring_result(result, {finding_id})


def scanner_result(*, operating_system="Linux", finding_id=FINDING_ID):
    domains = [
        "firewall_technology",
        "iptables_input_policy",
        "network_socket_inspection",
        "network_reachability",
        "host_firewall_rule_collection",
        "host_firewall_rule_applicability",
    ]
    coverage = {domain: "COMPLETE" for domain in domains}
    coverage["network_reachability"] = "INCOMPLETE"
    return {
        "system": {
            "system_id": "system:test",
            "hostname": "test-host",
            "username": "test-user",
            "operating_system": operating_system,
            "os_version": "test-version",
            "architecture": "x86_64",
            "processor": "test-processor",
        },
        "firewall": {
            "detected_tools": ["nftables"],
            "tool_paths": {"nftables": "/usr/sbin/nft"},
        },
        "coverage": coverage,
        "assessment_domains": domains,
        "findings": [_finding(finding_id=finding_id)],
        "score": _score(finding_id),
        "assessment_assurance": assessment_assurance_summary(coverage, domains),
    }


def _assess(raw):
    with patch("cyberwatchtower.scanner.run_scan", return_value=raw) as scan:
        result = CyberWatchtowerApplication().assess_current_system(
            CurrentSystemAssessmentRequest()
        )
    return result, scan


def _failure(raw):
    with patch("cyberwatchtower.scanner.run_scan", return_value=raw) as scan:
        with unittest.TestCase().assertRaises(
            CyberWatchtowerApplicationError
        ) as caught:
            CyberWatchtowerApplication().assess_current_system(
                CurrentSystemAssessmentRequest()
            )
    return caught.exception.failure, scan


class CurrentSystemAssessmentTests(unittest.TestCase):
    def test_construction_is_zero_io_and_production_scanner_runs_once(self):
        raw = scanner_result()
        with patch("cyberwatchtower.scanner.run_scan", return_value=raw) as scan:
            application = CyberWatchtowerApplication()
            scan.assert_not_called()
            result = application.assess_current_system(
                CurrentSystemAssessmentRequest()
            )
        scan.assert_called_once_with()
        self.assertRegex(result.operation_id, OPERATION_ID)
        self.assertIsNotNone(result.completed_at.utcoffset())
        self.assertEqual(result.platform, SupportedPlatform.LINUX)

    def test_invalid_request_is_typed_and_does_not_scan(self):
        with patch("cyberwatchtower.scanner.run_scan") as scan:
            with self.assertRaises(CyberWatchtowerApplicationError) as caught:
                CyberWatchtowerApplication().assess_current_system(object())
        scan.assert_not_called()
        failure = caught.exception.failure
        self.assertEqual(failure.code, ApplicationErrorCode.INVALID_REQUEST)
        self.assertRegex(failure.operation_id, OPERATION_ID)
        self.assertFalse(failure.retryable)

    def test_platform_comes_only_from_exact_scanner_metadata(self):
        windows, _ = _assess(scanner_result(operating_system="Windows"))
        self.assertEqual(windows.platform, SupportedPlatform.WINDOWS)

        for value in ("linux", "Darwin", "", None, 7):
            with self.subTest(value=value):
                raw = scanner_result()
                raw["system"]["operating_system"] = value
                failure, scan = _failure(raw)
                self.assertEqual(
                    failure.code, ApplicationErrorCode.COMPATIBILITY_FAILURE
                )
                scan.assert_called_once_with()

        missing = scanner_result()
        missing["system"].pop("operating_system")
        failure, _ = _failure(missing)
        self.assertEqual(failure.code, ApplicationErrorCode.COMPATIBILITY_FAILURE)

    def test_platform_is_not_inferred_from_domain_signatures(self):
        linux_signature = scanner_result()
        linux_signature["system"].pop("operating_system")
        failure, _ = _failure(linux_signature)
        self.assertEqual(failure.code, ApplicationErrorCode.COMPATIBILITY_FAILURE)

        windows_signature = scanner_result()
        windows_signature["assessment_domains"][1] = "firewall_inbound_policy"
        windows_signature["coverage"].pop("iptables_input_policy")
        windows_signature["coverage"]["firewall_inbound_policy"] = "COMPLETE"
        windows_signature["system"]["operating_system"] = {"Windows": True}
        windows_signature["assessment_assurance"] = assessment_assurance_summary(
            windows_signature["coverage"], windows_signature["assessment_domains"]
        )
        failure, _ = _failure(windows_signature)
        self.assertEqual(failure.code, ApplicationErrorCode.COMPATIBILITY_FAILURE)

    def test_scanner_unsupported_platform_maps_without_retry(self):
        with patch(
            "cyberwatchtower.scanner.run_scan",
            side_effect=UnsupportedPlatformError("unsupported"),
        ) as scan:
            with self.assertRaises(CyberWatchtowerApplicationError) as caught:
                CyberWatchtowerApplication().assess_current_system(
                    CurrentSystemAssessmentRequest()
                )
        scan.assert_called_once_with()
        failure = caught.exception.failure
        self.assertEqual(failure.code, ApplicationErrorCode.UNSUPPORTED_PLATFORM)
        self.assertFalse(failure.retryable)

    def test_result_is_deeply_immutable_and_isolated_from_scanner_mutation(self):
        raw = scanner_result()
        result, _ = _assess(raw)
        raw["system"]["hostname"] = "mutated"
        raw["coverage"]["network_reachability"] = "COMPLETE"
        raw["findings"][0].title = "mutated"
        raw["findings"][0].evidence.append("Protocol: udp")
        raw["score"]["score"] = 1
        self.assertEqual(result.system.hostname, "test-host")
        self.assertEqual(result.findings[0].title, "Service listening on all interfaces")
        self.assertEqual(result.score.score, 96)
        self.assertEqual(
            dict((item.domain.value, item.state.value) for item in result.coverage)[
                "network_reachability"
            ],
            "INCOMPLETE",
        )
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            result.system = result.system
        self.assertIsInstance(result.findings, tuple)
        self.assertIsInstance(result.findings[0].evidence, tuple)
        self.assertIsInstance(result.score.breakdown.contributors, tuple)

    def test_finding_and_complete_scoring_v2_are_preserved_without_recalculation(self):
        raw = scanner_result()
        authoritative_score = copy.deepcopy(raw["score"])
        with patch(
            "cyberwatchtower.scoring_v2.calculate_security_score_v2",
            side_effect=AssertionError("score recalculation"),
        ), patch(
            "cyberwatchtower.application.assessment.canonical_finding_id",
            wraps=__import__(
                "cyberwatchtower.scoring_projection",
                fromlist=["canonical_finding_id"],
            ).canonical_finding_id,
        ) as identity:
            result, _ = _assess(raw)
        finding = result.findings[0]
        self.assertEqual(finding.finding_id, FINDING_ID)
        self.assertEqual(finding.severity, Severity.MEDIUM)
        self.assertEqual(finding.kind, FindingKind.RISK)
        self.assertEqual(finding.assessment_state, AssessmentState.POTENTIAL)
        self.assertEqual(finding.confidence, 91)
        self.assertEqual(finding.technique_id, "T1049")
        self.assertEqual(finding.runtime_instance_count, 2)
        self.assertEqual(finding.recommendation, "Restrict exposure when unnecessary.")
        self.assertEqual(result.score.scoring_version, ScoringVersion.V2)
        self.assertEqual(result.score.score, authoritative_score["score"])
        self.assertEqual(
            result.score.breakdown.total_effective_penalty,
            authoritative_score["breakdown"]["total_effective_penalty"],
        )
        self.assertEqual(
            result.score.breakdown.contributors[0].finding_ids, (FINDING_ID,)
        )
        identity.assert_called_once_with(raw["findings"][0])

    def test_duplicate_identity_and_bad_scoring_reference_fail_atomically(self):
        duplicate = scanner_result()
        duplicate["findings"].append(copy.deepcopy(duplicate["findings"][0]))
        failure, _ = _failure(duplicate)
        self.assertEqual(failure.code, ApplicationErrorCode.COMPATIBILITY_FAILURE)

        bad_reference = scanner_result()
        bad_reference["score"]["breakdown"]["contributors"][0][
            "finding_ids"
        ] = ["finding:not-present"]
        failure, _ = _failure(bad_reference)
        self.assertEqual(failure.code, ApplicationErrorCode.COMPATIBILITY_FAILURE)

    def test_coverage_order_unknown_incomplete_and_assurance_are_preserved(self):
        raw = scanner_result()
        raw["coverage"]["firewall_technology"] = "UNKNOWN"
        raw["assessment_assurance"] = assessment_assurance_summary(
            raw["coverage"], raw["assessment_domains"]
        )
        result, _ = _assess(raw)
        self.assertEqual(
            tuple(item.domain.value for item in result.coverage),
            tuple(raw["assessment_domains"]),
        )
        self.assertEqual(result.coverage[0].state, CoverageState.UNKNOWN)
        self.assertEqual(result.coverage[3].state, CoverageState.INCOMPLETE)
        self.assertEqual(result.assurance.level, AssessmentAssurance.PARTIAL)
        self.assertEqual(
            result.assurance.limitations,
            raw["assessment_assurance"]["limitations"],
        )

    def test_missing_extra_malformed_coverage_and_contradictory_assurance_fail(self):
        variants = []
        missing = scanner_result()
        missing["coverage"].pop("network_reachability")
        variants.append(missing)
        extra = scanner_result()
        extra["coverage"]["invented"] = "COMPLETE"
        variants.append(extra)
        malformed = scanner_result()
        malformed["coverage"]["network_reachability"] = "PERFECT"
        variants.append(malformed)
        contradictory = scanner_result()
        contradictory["assessment_assurance"] = {
            "level": "COMPLETE",
            "limitations": (),
        }
        variants.append(contradictory)
        for raw in variants:
            with self.subTest(raw=raw):
                failure, _ = _failure(raw)
                self.assertEqual(
                    failure.code, ApplicationErrorCode.COMPATIBILITY_FAILURE
                )

    def test_network_policy_is_preserved_and_allow_is_not_confirmed_reachable(self):
        with patch(
            "cyberwatchtower.reachability.assess_listener_reachability",
            side_effect=AssertionError("reachability recalculation"),
        ):
            result, _ = _assess(scanner_result())
        context = result.findings[0].network_context
        self.assertEqual(
            context.reachability_state,
            RemoteReachabilityState.POTENTIALLY_REACHABLE,
        )
        self.assertNotEqual(
            context.reachability_state,
            RemoteReachabilityState.CONFIRMED_REACHABLE,
        )
        self.assertEqual(
            context.firewall_policy.evaluated_policy_disposition,
            EvaluatedPolicyDisposition.ALLOW,
        )
        self.assertEqual(context.firewall_policy.matching_rule_digests, ())

    def test_missing_or_malformed_network_context_fails_conservatively(self):
        for mutation in ("missing", "malformed"):
            raw = scanner_result()
            if mutation == "missing":
                raw["findings"][0].network_context.pop("reachability_state")
            else:
                raw["findings"][0].network_context["policy_assessment"][
                    "evaluated_policy_disposition"
                ] = "MAGIC"
            failure, _ = _failure(raw)
            self.assertEqual(failure.code, ApplicationErrorCode.COMPATIBILITY_FAILURE)

    def test_privacy_is_structural_allowlist_first_and_redaction_is_exact(self):
        raw = scanner_result()
        result, _ = _assess(raw)
        finding = result.findings[0]
        self.assertEqual(
            tuple(item.category.value for item in finding.evidence),
            ("PROTOCOL", "ADDRESS", "PORT", "PROCESS"),
        )
        self.assertEqual(finding.evidence_projection_state, EvidenceProjectionState.REDACTED)
        self.assertEqual(finding.omitted_evidence_count, 3)
        self.assertEqual(result.projection_notices[0].omitted_count, 3)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.score.score, raw["score"]["score"])

        wrong_source = scanner_result()
        wrong_source["findings"][0].source = "unknown"
        result, _ = _assess(wrong_source)
        self.assertEqual(result.findings[0].evidence, ())
        self.assertEqual(result.findings[0].omitted_evidence_count, 7)

    def test_heuristics_can_reject_but_never_authorize_evidence(self):
        raw = scanner_result()
        raw["findings"][0].evidence = [
            "Protocol: tcp password",
            "Friendly: harmless value",
            "harmless unlabeled text",
            "Application: benign-name",
            "Protocol: udp",
        ]
        result, _ = _assess(raw)
        finding = result.findings[0]
        self.assertEqual(
            tuple((item.category.value, item.value) for item in finding.evidence),
            (("PROTOCOL", "udp"),),
        )
        self.assertEqual(finding.omitted_evidence_count, 4)
        self.assertEqual(finding.severity, Severity.MEDIUM)
        self.assertEqual(finding.runtime_instance_count, 2)

    def test_required_identity_privacy_failure_is_atomic(self):
        raw = scanner_result(finding_id="credential:secret-finding")
        failure, scan = _failure(raw)
        scan.assert_called_once_with()
        self.assertEqual(failure.code, ApplicationErrorCode.PRIVACY_POLICY_BLOCKED)

        raw = scanner_result()
        raw["findings"][0].description = "Captured password=/tmp/private"
        failure, _ = _failure(raw)
        self.assertEqual(failure.code, ApplicationErrorCode.PRIVACY_POLICY_BLOCKED)

    def test_malformed_finding_and_top_level_shapes_are_compatibility_failures(self):
        malformed_finding = scanner_result()
        malformed_finding["findings"][0].evidence = ("Protocol: tcp",)
        failure, _ = _failure(malformed_finding)
        self.assertEqual(failure.code, ApplicationErrorCode.COMPATIBILITY_FAILURE)

        formatted_finding = scanner_result()
        formatted_finding["findings"][0].title = "hidden\u200dformat"
        failure, _ = _failure(formatted_finding)
        self.assertEqual(failure.code, ApplicationErrorCode.COMPATIBILITY_FAILURE)

        extra = scanner_result()
        extra["invented"] = True
        failure, _ = _failure(extra)
        self.assertEqual(failure.code, ApplicationErrorCode.COMPATIBILITY_FAILURE)

    def test_internal_exception_is_bounded_and_does_not_leak_original_text(self):
        secret = "password=/tmp/private argv --token=secret"
        with patch(
            "cyberwatchtower.scanner.run_scan", side_effect=RuntimeError(secret)
        ) as scan:
            with self.assertRaises(CyberWatchtowerApplicationError) as caught:
                CyberWatchtowerApplication().assess_current_system(
                    CurrentSystemAssessmentRequest()
                )
        scan.assert_called_once_with()
        failure = caught.exception.failure
        self.assertEqual(failure.code, ApplicationErrorCode.INTERNAL_FAILURE)
        self.assertNotIn("password", str(caught.exception).casefold())
        self.assertNotIn("/tmp", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    def test_assessment_performs_no_report_or_memory_persistence(self):
        with patch("cyberwatchtower.reporting.save_json_report") as report_save, patch(
            "cyberwatchtower.memory.open_memory_database"
        ) as memory_open, patch(
            "cyberwatchtower.scanner.run_scan", return_value=scanner_result()
        ):
            CyberWatchtowerApplication().assess_current_system(
                CurrentSystemAssessmentRequest()
            )
        report_save.assert_not_called()
        memory_open.assert_not_called()


if __name__ == "__main__":
    unittest.main()
