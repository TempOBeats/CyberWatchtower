import inspect
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from cyberwatchtower.advisor.context import build_advisor_context
from cyberwatchtower.advisor.deterministic import build_deterministic_advisory
from cyberwatchtower.advisor.rendering import render_advisory
from cyberwatchtower.advisor.service import build_provider_request
from cyberwatchtower.briefing.builder import build_security_briefing
from cyberwatchtower.briefing.rendering import render_grounded_response
from cyberwatchtower.cli import main
from cyberwatchtower.models import AssessmentState, FindingKind, Severity
from cyberwatchtower.score_explanation import (
    build_score_explanation,
    render_score_explanation,
)
from cyberwatchtower.scoring_contracts import ScoringCategory, ScoringFinding
from cyberwatchtower.scoring_contracts import NetworkScoringIdentity
from cyberwatchtower.scoring_report import serialize_scoring_result
from cyberwatchtower.scoring_v2 import calculate_security_score_v2
from cyberwatchtower.platform import BindExposure
from cyberwatchtower.reachability import RemoteReachabilityState


def _v2_report(*, firewall_only: bool = False):
    finding_ids = (
        ("finding:firewall",)
        if firewall_only
        else ("finding:firewall", "finding:listener:a", "finding:listener:b")
    )
    scoring_findings = (
        ScoringFinding(
            finding_ids[0], Severity.MEDIUM, FindingKind.RISK,
            AssessmentState.CONFIRMED, "firewall_inbound_policy",
            ScoringCategory.FIREWALL_POSTURE,
        ),
        *(() if firewall_only else (ScoringFinding(
            finding_ids[1], Severity.MEDIUM, FindingKind.RISK,
            AssessmentState.POTENTIAL, "network",
            ScoringCategory.NETWORK_EXPOSURE,
            NetworkScoringIdentity(
                "tcp", 443, BindExposure.ALL_INTERFACES,
                RemoteReachabilityState.POTENTIALLY_REACHABLE,
                application_identity="service:a",
            ),
        ),
        ScoringFinding(
            finding_ids[2], Severity.MEDIUM, FindingKind.RISK,
            AssessmentState.POTENTIAL, "network",
            ScoringCategory.NETWORK_EXPOSURE,
            NetworkScoringIdentity(
                "tcp", 8443, BindExposure.ALL_INTERFACES,
                RemoteReachabilityState.POTENTIALLY_REACHABLE,
                application_identity="service:b",
            ),
        ),)),
    )
    result = calculate_security_score_v2(scoring_findings)
    score = serialize_scoring_result(result, set(finding_ids))
    findings = [
        {
            "finding_id": finding_id,
            "title": f"Finding {index}",
            "description": "Deterministic finding.",
            "severity": "MEDIUM",
            "recommendation": "Review it.",
            "confidence": 100,
            "source": "firewall_inbound_policy" if index == 1 else "network",
            "kind": "RISK",
            "assessment_state": "CONFIRMED" if index == 1 else "POTENTIAL",
            "evidence": [],
        }
        for index, finding_id in enumerate(finding_ids, start=1)
    ]
    return {
        "schema_version": "1.4",
        "security_score": score,
        "findings": findings,
        "coverage": {"firewall_inbound_policy": "COMPLETE"},
        "assessment_domains": ["firewall_inbound_policy"],
    }


class ScoreExplanationTests(unittest.TestCase):
    def test_projection_and_rendering_exactly_copy_canonical_totals(self):
        report = _v2_report()
        breakdown = report["security_score"]["breakdown"]
        explanation = build_score_explanation(
            report["security_score"],
            report_finding_ids={item["finding_id"] for item in report["findings"]},
            schema_version="1.4",
        )
        self.assertIsNotNone(explanation)
        self.assertEqual(
            explanation.total_effective_penalty,
            breakdown["total_effective_penalty"],
        )
        self.assertEqual(
            [item.applied_penalty for item in explanation.categories],
            [item["applied_penalty"] for item in breakdown["categories"]],
        )
        self.assertEqual(
            explanation.guardrail.additional_guardrail_penalty,
            breakdown["guardrail"]["additional_guardrail_penalty"],
        )
        rendered = "\n".join(render_score_explanation(explanation, "PARTIAL"))
        self.assertIn("Assessment Assurance: PARTIAL", rendered)
        guardrail_report = _v2_report(firewall_only=True)
        guardrail_explanation = build_score_explanation(
            guardrail_report["security_score"],
            report_finding_ids={"finding:firewall"},
            schema_version="1.4",
        )
        guardrail_rendered = "\n".join(
            render_score_explanation(guardrail_explanation, "COMPLETE")
        )
        self.assertIn("Confirmed-risk guardrail adjustment: 1", guardrail_rendered)
        for contributor in breakdown["contributors"]:
            self.assertIn(contributor["group_id"], rendered)
            for finding_id in contributor["finding_ids"]:
                self.assertIn(finding_id, rendered)

    def test_advisor_and_briefing_share_canonical_projection(self):
        report = _v2_report()
        context = build_advisor_context(report, None, None)
        advisory = build_deterministic_advisory(context)
        advisor_text = render_advisory(advisory, context)
        briefing_text = render_grounded_response(
            build_security_briefing(report, None, None).response
        )
        canonical_total = report["security_score"]["breakdown"][
            "total_effective_penalty"
        ]
        self.assertIn(f"Effective deduction: {canonical_total}", advisor_text)
        self.assertIn(f"Effective deduction: {canonical_total}", briefing_text)
        for finding_id in ("finding:firewall", "finding:listener:a", "finding:listener:b"):
            self.assertIn(finding_id, advisor_text)
            self.assertIn(finding_id, briefing_text)

    def test_methodology_transition_is_not_called_improvement(self):
        report = _v2_report()
        context = build_advisor_context(report, {
            "previous_score": 0,
            "current_score": report["security_score"]["score"],
            "previous_scoring_version": "1",
            "current_scoring_version": "2",
            "change": None,
            "trend": "SCORING_VERSION_CHANGED",
            "new_findings": [],
            "resolved_findings": [],
        }, None)
        summary = build_deterministic_advisory(context).changes_summary
        self.assertIn("changed from v1 to v2", summary)
        self.assertNotIn("IMPROVED", summary)
        self.assertNotIn("+", summary)

    def test_v1_and_missing_breakdown_have_safe_fallback(self):
        report = {
            "security_score": {"score": 70, "risk_level": "HIGH", "counts": {}},
            "findings": [],
        }
        context = build_advisor_context(report, None, None)
        self.assertIsNotNone(context.score_explanation)
        rendered = "\n".join(render_score_explanation(
            context.score_explanation, context.assessment_assurance
        ))
        self.assertIn("Scoring v1", rendered)
        malformed = dict(report)
        malformed["security_score"] = {"scoring_version": "2", "score": 70}
        self.assertIsNone(build_advisor_context(malformed, None, None).score_explanation)

    def test_provider_request_is_unchanged_and_receives_no_score_breakdown(self):
        context = build_advisor_context(_v2_report(), None, None)
        request = build_provider_request(context, build_deterministic_advisory(context))
        self.assertFalse(hasattr(request, "score_explanation"))
        payload = repr(request).casefold()
        for prohibited in ("breakdown", "guardrail", "native", "machineguid"):
            self.assertNotIn(prohibited, payload)

    def test_presentation_modules_do_not_import_scorers(self):
        from cyberwatchtower import cli
        from cyberwatchtower.advisor import context
        from cyberwatchtower.briefing import builder

        for module in (cli, context, builder):
            source = inspect.getsource(module)
            self.assertNotIn("scoring_v2", source)
            self.assertNotIn("calculate_security_score", source)

    def test_saturated_category_is_rendered_from_canonical_flag(self):
        findings = tuple(
            ScoringFinding(
                f"finding:listener:{port}", Severity.MEDIUM, FindingKind.RISK,
                AssessmentState.POTENTIAL, "network",
                ScoringCategory.NETWORK_EXPOSURE,
                NetworkScoringIdentity(
                    "tcp", port, BindExposure.ALL_INTERFACES,
                    RemoteReachabilityState.POTENTIALLY_REACHABLE,
                    application_identity=f"service:{port}",
                ),
            )
            for port in range(8000, 8005)
        )
        score = serialize_scoring_result(
            calculate_security_score_v2(findings),
            {item.finding_id for item in findings},
        )
        explanation = build_score_explanation(
            score,
            report_finding_ids={item.finding_id for item in findings},
            schema_version="1.4",
        )
        rendered = "\n".join(render_score_explanation(explanation, "COMPLETE"))
        self.assertIn("Network exposure: 18-point applied penalty", rendered)
        self.assertIn("category saturated", rendered)

    def test_cli_renders_canonical_v2_breakdown_without_scorer_import(self):
        score = serialize_scoring_result(calculate_security_score_v2(()), set())
        results = {
            "system": {"hostname": "test-host"},
            "firewall": {},
            "findings": [],
            "score": score,
            "assessment_assurance": {"level": "PARTIAL", "limitations": []},
        }
        report = {
            "schema_version": "1.4",
            "system": results["system"],
            "findings": [],
            "security_score": score,
        }
        intelligence = {
            "total_scans": 1, "average_score": 100, "best_score": 100,
            "worst_score": 100, "overall_change": 0,
            "overall_trend": "UNCHANGED", "findings": [],
        }
        output = io.StringIO()
        with (
            patch("cyberwatchtower.cli.run_scan", return_value=results),
            patch("cyberwatchtower.cli.save_json_report", return_value="report.json"),
            patch("cyberwatchtower.cli.load_reports", return_value=[report]),
            patch("cyberwatchtower.cli.analyze_history", return_value=intelligence),
            patch("cyberwatchtower.cli._display_advisor"),
            patch("cyberwatchtower.cli._ingest_saved_report", return_value=None),
            redirect_stdout(output),
        ):
            main([])
        rendered = output.getvalue()
        self.assertIn("Scoring Method: v2", rendered)
        self.assertIn("Effective deduction: 0", rendered)
        self.assertIn("Assessment Assurance: PARTIAL", rendered)


if __name__ == "__main__":
    unittest.main()
