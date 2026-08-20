import unittest

from cyberwatchtower.models import AssessmentState, FindingKind, Severity
from cyberwatchtower.platform import BindExposure
from cyberwatchtower.reachability import RemoteReachabilityState
from cyberwatchtower.scoring import calculate_security_score
from cyberwatchtower.scoring_contracts import (
    NetworkScoringIdentity,
    ScoringCategory,
    ScoringFinding,
)
from cyberwatchtower.scoring_v2 import calculate_security_score_v2


def other(
    finding_id: str,
    severity: Severity,
    state: AssessmentState,
    *,
    category: ScoringCategory = ScoringCategory.OTHER_DETERMINISTIC_RISK,
    kind: FindingKind = FindingKind.RISK,
) -> ScoringFinding:
    return ScoringFinding(
        finding_id,
        severity,
        kind,
        state,
        "firewall_inbound_policy" if category == ScoringCategory.FIREWALL_POSTURE
        else "deterministic",
        category,
    )


def listener(
    finding_id: str,
    application: str,
    port: int,
    *,
    severity: Severity = Severity.MEDIUM,
    state: AssessmentState = AssessmentState.POTENTIAL,
) -> ScoringFinding:
    return ScoringFinding(
        finding_id,
        severity,
        FindingKind.RISK,
        state,
        "network",
        ScoringCategory.NETWORK_EXPOSURE,
        NetworkScoringIdentity(
            "tcp",
            port,
            BindExposure.ALL_INTERFACES,
            (
                RemoteReachabilityState.POTENTIALLY_REACHABLE
                if state == AssessmentState.POTENTIAL
                else RemoteReachabilityState.CONFIRMED_REACHABLE
            ),
            application,
        ),
    )


def windows_style_findings() -> tuple[ScoringFinding, ...]:
    """Ten service families, two semantic ports, IPv4/IPv6 twin per port."""

    findings = []
    for service_number in range(10):
        application = f"windows-service:fixture-{service_number}"
        for port_offset in range(2):
            port = 20000 + service_number * 10 + port_offset
            for family in ("ipv4", "ipv6"):
                findings.append(listener(
                    f"{application}:{port}:{family}", application, port
                ))
    return tuple(findings)


class ScoringV2CalibrationTests(unittest.TestCase):
    def test_fixture_a_clean_host_is_100_low(self):
        result = calculate_security_score_v2(())
        self.assertEqual((result.score, result.risk_level), (100, "LOW"))

    def test_fixture_b_windows_style_host_is_82_moderate(self):
        result = calculate_security_score_v2(windows_style_findings())
        self.assertEqual((result.score, result.risk_level), (82, "MODERATE"))
        network = result.breakdown.categories[0]
        self.assertEqual(
            (network.raw_penalty, network.applied_penalty, network.saturated),
            (60, 18, True),
        )
        self.assertEqual(len(result.breakdown.contributors), 10)

    def test_fixture_c_confirmed_medium_firewall_is_89_moderate(self):
        result = calculate_security_score_v2((other(
            "firewall-medium",
            Severity.MEDIUM,
            AssessmentState.CONFIRMED,
            category=ScoringCategory.FIREWALL_POSTURE,
        ),))
        self.assertEqual((result.score, result.risk_level), (89, "MODERATE"))
        self.assertEqual(result.breakdown.total_penalty, 11)
        self.assertEqual(result.breakdown.categories[1].applied_penalty, 10)

    def test_fixture_d_potential_network_plus_confirmed_high_is_68_high(self):
        findings = tuple(
            listener(f"listener-{index}", f"service-{index}", 30000 + index)
            for index in range(3)
        ) + (other(
            "confirmed-high", Severity.HIGH, AssessmentState.CONFIRMED
        ),)
        result = calculate_security_score_v2(findings)
        self.assertEqual((result.score, result.risk_level), (68, "HIGH"))
        self.assertEqual(result.breakdown.total_penalty, 32)

    def test_fixture_e_two_confirmed_critical_groups_are_20_critical(self):
        findings = (
            other("critical-one", Severity.CRITICAL, AssessmentState.CONFIRMED),
            other("critical-two", Severity.CRITICAL, AssessmentState.CONFIRMED),
        )
        result = calculate_security_score_v2(findings)
        self.assertEqual((result.score, result.risk_level), (20, "CRITICAL"))
        self.assertEqual(result.breakdown.total_penalty, 80)
        self.assertEqual(result.breakdown.categories[2].applied_penalty, 60)

    def test_fixture_f_ipv4_ipv6_twins_score_once(self):
        single = (listener("ipv4", "twin-service", 8443),)
        twins = single + (listener("ipv6", "twin-service", 8443),)
        single_result = calculate_security_score_v2(single)
        twin_result = calculate_security_score_v2(twins)
        self.assertEqual((single_result.score, single_result.risk_level), (96, "LOW"))
        self.assertEqual(twin_result.score, single_result.score)
        self.assertEqual(
            twin_result.breakdown.contributors[0].finding_ids,
            ("ipv4", "ipv6"),
        )

    def test_fixture_g_assurance_is_not_a_scorer_input(self):
        result = calculate_security_score_v2(())
        self.assertEqual((result.score, result.risk_level), (100, "LOW"))
        self.assertNotIn("assurance", result.__dataclass_fields__)
        self.assertNotIn("coverage", result.__dataclass_fields__)

    def test_fixture_h_same_findings_are_v1_zero_and_v2_82(self):
        v2_findings = windows_style_findings()
        legacy_findings = tuple(type("LegacyFinding", (), {
            "severity": item.severity,
        })() for item in v2_findings)
        v1 = calculate_security_score(list(legacy_findings))
        v2 = calculate_security_score_v2(v2_findings)
        self.assertEqual((v1["score"], v1["risk_level"]), (0, "CRITICAL"))
        self.assertEqual((v2.score, v2.risk_level), (82, "MODERATE"))

    def test_permutation_invariance_and_deterministic_group_order(self):
        findings = windows_style_findings()[:12]
        forward = calculate_security_score_v2(findings)
        reverse = calculate_security_score_v2(tuple(reversed(findings)))
        self.assertEqual(forward, reverse)
        self.assertEqual(
            tuple(group.group_id for group in forward.breakdown.contributors),
            tuple(sorted(
                group.group_id for group in forward.breakdown.contributors
            )),
        )

    def test_related_family_diminishes_and_saturates_at_175_percent(self):
        findings = tuple(
            listener(f"port-{index}", "one-family", 40000 + index)
            for index in range(12)
        )
        result = calculate_security_score_v2(findings)
        group = result.breakdown.contributors[0]
        self.assertEqual(group.base_penalty, 4)
        self.assertEqual(group.raw_penalty, 7)
        self.assertEqual(group.applied_penalty, 7)
        expanded = calculate_security_score_v2(findings + (
            listener("additional-related", "one-family", 50000),
        ))
        self.assertEqual(expanded.score, result.score)

    def test_firewall_and_network_categories_score_independently(self):
        findings = (
            listener("network", "service", 8080),
            other(
                "firewall", Severity.MEDIUM, AssessmentState.CONFIRMED,
                category=ScoringCategory.FIREWALL_POSTURE,
            ),
        )
        result = calculate_security_score_v2(findings)
        categories = {
            item.category: item.applied_penalty
            for item in result.breakdown.categories
        }
        self.assertEqual(categories[ScoringCategory.NETWORK_EXPOSURE], 4)
        self.assertEqual(categories[ScoringCategory.FIREWALL_POSTURE], 10)
        self.assertEqual(result.score, 86)

    def test_potential_and_total_category_caps_are_exact(self):
        cases = (
            (
                tuple(
                    listener(f"network-{index}", f"service-{index}", 10000 + index,
                             severity=Severity.CRITICAL)
                    for index in range(10)
                ),
                ScoringCategory.NETWORK_EXPOSURE,
                18,
            ),
            (
                tuple(
                    other(
                        f"firewall-{index}", Severity.CRITICAL,
                        AssessmentState.POTENTIAL,
                        category=ScoringCategory.FIREWALL_POSTURE,
                    )
                    for index in range(10)
                ),
                ScoringCategory.FIREWALL_POSTURE,
                12,
            ),
            (
                tuple(
                    other(
                        f"other-{index}", Severity.CRITICAL,
                        AssessmentState.POTENTIAL,
                    )
                    for index in range(10)
                ),
                ScoringCategory.OTHER_DETERMINISTIC_RISK,
                25,
            ),
        )
        for findings, category, expected in cases:
            with self.subTest(category=category):
                result = calculate_security_score_v2(findings)
                breakdown = next(
                    item for item in result.breakdown.categories
                    if item.category == category
                )
                self.assertEqual(breakdown.applied_penalty, expected)
                self.assertTrue(breakdown.saturated)

        confirmed_firewall = tuple(
            other(
                f"confirmed-firewall-{index}", Severity.CRITICAL,
                AssessmentState.CONFIRMED,
                category=ScoringCategory.FIREWALL_POSTURE,
            )
            for index in range(3)
        )
        firewall_result = calculate_security_score_v2(confirmed_firewall)
        self.assertEqual(
            firewall_result.breakdown.categories[1].applied_penalty, 40
        )

        confirmed_other = tuple(
            other(
                f"confirmed-other-{index}", Severity.CRITICAL,
                AssessmentState.CONFIRMED,
            )
            for index in range(3)
        )
        other_result = calculate_security_score_v2(confirmed_other)
        self.assertEqual(
            other_result.breakdown.categories[2].applied_penalty, 70
        )

    def test_score_is_always_bounded(self):
        for count in (0, 1, 10, 100):
            findings = tuple(
                other(
                    f"critical-{index}", Severity.CRITICAL,
                    AssessmentState.CONFIRMED,
                )
                for index in range(count)
            )
            result = calculate_security_score_v2(findings)
            self.assertGreaterEqual(result.score, 0)
            self.assertLessEqual(result.score, 100)


if __name__ == "__main__":
    unittest.main()
