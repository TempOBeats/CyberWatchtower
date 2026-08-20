import dataclasses
import inspect
import unittest

from cyberwatchtower.finding_identity import finding_identity
from cyberwatchtower.models import AssessmentState, Finding, FindingKind, Severity
from cyberwatchtower.platform import BindExposure
from cyberwatchtower.reachability import RemoteReachabilityState
from cyberwatchtower.scoring import calculate_security_score
from cyberwatchtower.scoring_contracts import (
    NetworkScoringIdentity,
    ScoringBasisCode,
    ScoringCategory,
    ScoringFinding,
    ScoringVersion,
)
from cyberwatchtower.scoring_v2 import (
    V1_CONFIRMED_WEIGHTS,
    V2_POTENTIAL_WEIGHTS,
    calculate_security_score_v2,
)


def scoring_finding(
    finding_id: str,
    *,
    severity: Severity = Severity.MEDIUM,
    kind: FindingKind = FindingKind.RISK,
    state: AssessmentState = AssessmentState.POTENTIAL,
    category: ScoringCategory = ScoringCategory.OTHER_DETERMINISTIC_RISK,
    source: str = "deterministic",
    network: NetworkScoringIdentity | None = None,
) -> ScoringFinding:
    return ScoringFinding(
        finding_id,
        severity,
        kind,
        state,
        source,
        category,
        network,
    )


def network_identity(
    *,
    application: str | None = "example-service",
    process: str | None = None,
    protocol: str = "tcp",
    port: int = 443,
) -> NetworkScoringIdentity:
    return NetworkScoringIdentity(
        protocol,
        port,
        BindExposure.ALL_INTERFACES,
        RemoteReachabilityState.POTENTIALLY_REACHABLE,
        application,
        process,
    )


class ScoringV2ContractTests(unittest.TestCase):
    def test_closed_contract_values_and_frozen_weights(self):
        self.assertEqual([item.value for item in ScoringVersion], ["1", "2"])
        self.assertEqual(
            [item.value for item in ScoringCategory],
            [
                "NETWORK_EXPOSURE",
                "FIREWALL_POSTURE",
                "OTHER_DETERMINISTIC_RISK",
            ],
        )
        self.assertEqual(
            set(ScoringBasisCode),
            {
                ScoringBasisCode.POTENTIAL_LISTENER_EXPOSURE,
                ScoringBasisCode.CONFIRMED_LISTENER_EXPOSURE,
                ScoringBasisCode.POTENTIAL_FIREWALL_POLICY_RISK,
                ScoringBasisCode.CONFIRMED_FIREWALL_POLICY_RISK,
                ScoringBasisCode.POTENTIAL_DETERMINISTIC_RISK,
                ScoringBasisCode.CONFIRMED_DETERMINISTIC_RISK,
            },
        )
        self.assertEqual(
            V1_CONFIRMED_WEIGHTS,
            {
                Severity.CRITICAL: 30,
                Severity.HIGH: 20,
                Severity.MEDIUM: 10,
                Severity.LOW: 5,
                Severity.INFO: 0,
            },
        )
        self.assertEqual(
            V2_POTENTIAL_WEIGHTS,
            {
                Severity.CRITICAL: 12,
                Severity.HIGH: 8,
                Severity.MEDIUM: 4,
                Severity.LOW: 2,
                Severity.INFO: 0,
            },
        )

    def test_input_and_result_contracts_are_immutable(self):
        item = scoring_finding("immutable")
        result = calculate_security_score_v2((item,))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            item.source = "changed"
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.score = 0
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.breakdown.total_penalty = 99

    def test_scorer_cannot_mutate_findings_or_finding_identity(self):
        canonical = Finding(
            "Stable finding", "Description", Severity.MEDIUM, "Review",
            evidence=["Protocol: tcp", "Port: 443"],
            finding_id="stable-finding-id",
            kind=FindingKind.RISK,
            assessment_state=AssessmentState.POTENTIAL,
        )
        before = finding_identity({
            "finding_id": canonical.finding_id,
            "title": canonical.title,
            "evidence": list(canonical.evidence),
        })
        snapshot = scoring_finding(canonical.finding_id)
        calculate_security_score_v2((snapshot,))
        after = finding_identity({
            "finding_id": canonical.finding_id,
            "title": canonical.title,
            "evidence": list(canonical.evidence),
        })
        self.assertEqual(before, after)
        self.assertEqual(canonical.assessment_state, AssessmentState.POTENTIAL)

    def test_scoring_input_has_no_private_or_free_form_evidence_surface(self):
        self.assertEqual(
            {field.name for field in dataclasses.fields(ScoringFinding)},
            {
                "finding_id", "severity", "kind", "assessment_state",
                "source", "category", "network_identity",
            },
        )
        self.assertEqual(
            {field.name for field in dataclasses.fields(NetworkScoringIdentity)},
            {
                "protocol", "port", "bind_exposure", "reachability_state",
                "application_identity", "process_basename",
            },
        )

    def test_only_confirmed_or_potential_risks_are_eligible(self):
        excluded = (
            scoring_finding(
                "observation",
                kind=FindingKind.OBSERVATION,
                state=AssessmentState.INFORMATIONAL,
                severity=Severity.CRITICAL,
            ),
            scoring_finding(
                "gap",
                kind=FindingKind.COVERAGE_GAP,
                state=AssessmentState.INCOMPLETE,
                severity=Severity.CRITICAL,
            ),
            scoring_finding(
                "risk-incomplete",
                state=AssessmentState.INCOMPLETE,
                severity=Severity.CRITICAL,
            ),
            scoring_finding(
                "risk-info",
                state=AssessmentState.INFORMATIONAL,
                severity=Severity.CRITICAL,
            ),
        )
        result = calculate_security_score_v2(excluded)
        self.assertEqual((result.score, result.risk_level), (100, "LOW"))
        self.assertEqual(result.breakdown.total_penalty, 0)
        self.assertEqual(result.breakdown.contributors, ())

    def test_potential_equivalent_never_exceeds_confirmed_penalty(self):
        for severity in Severity:
            with self.subTest(severity=severity):
                potential = calculate_security_score_v2((scoring_finding(
                    "potential", severity=severity,
                    state=AssessmentState.POTENTIAL,
                ),))
                confirmed = calculate_security_score_v2((scoring_finding(
                    "confirmed", severity=severity,
                    state=AssessmentState.CONFIRMED,
                ),))
                self.assertLessEqual(
                    potential.breakdown.total_penalty,
                    confirmed.breakdown.total_penalty,
                )

    def test_network_identity_is_closed_and_unknown_services_keep_port(self):
        with self.assertRaises(ValueError):
            network_identity(protocol="icmp")
        with self.assertRaises(ValueError):
            network_identity(port=65536)
        findings = (
            scoring_finding(
                "unknown-80", category=ScoringCategory.NETWORK_EXPOSURE,
                source="network", network=network_identity(application=None, port=80),
            ),
            scoring_finding(
                "unknown-443", category=ScoringCategory.NETWORK_EXPOSURE,
                source="network", network=network_identity(application=None, port=443),
            ),
        )
        result = calculate_security_score_v2(findings)
        self.assertEqual(len(result.breakdown.contributors), 2)
        self.assertEqual(result.breakdown.total_penalty, 8)

    def test_duplicate_input_ids_fail_closed_and_group_members_are_input_ids(self):
        duplicate = scoring_finding("duplicate")
        with self.assertRaises(ValueError):
            calculate_security_score_v2((duplicate, duplicate))
        findings = (
            scoring_finding("one"),
            scoring_finding("two", state=AssessmentState.CONFIRMED),
        )
        result = calculate_security_score_v2(findings)
        supplied = {item.finding_id for item in findings}
        referenced = {
            finding_id
            for group in result.breakdown.contributors
            for finding_id in group.finding_ids
        }
        self.assertEqual(referenced, supplied)
        self.assertTrue(all(
            len(group.finding_ids) == len(set(group.finding_ids))
            for group in result.breakdown.contributors
        ))

    def test_v1_callable_semantics_remain_exact(self):
        findings = [
            Finding("Critical", "", Severity.CRITICAL, ""),
            Finding("High", "", Severity.HIGH, ""),
            Finding("Medium", "", Severity.MEDIUM, ""),
            Finding("Low", "", Severity.LOW, ""),
            Finding("Info", "", Severity.INFO, ""),
        ]
        self.assertEqual(calculate_security_score(findings), {
            "score": 35,
            "risk_level": "CRITICAL",
            "counts": {
                "CRITICAL": 1,
                "HIGH": 1,
                "MEDIUM": 1,
                "LOW": 1,
                "INFO": 1,
            },
        })

    def test_scoring_modules_have_no_disallowed_boundaries(self):
        import cyberwatchtower.scoring_contracts as contracts
        import cyberwatchtower.scoring_v2 as engine

        source = inspect.getsource(contracts) + inspect.getsource(engine)
        for prohibited in (
            "presentation_group_id",
            "recommendation",
            "hostname",
            "pid",
            "provider",
            "model_gateway",
            "platform.windows",
            "platform.linux",
            "subprocess",
            "sqlite",
        ):
            self.assertNotIn(prohibited, source.casefold())


if __name__ == "__main__":
    unittest.main()
