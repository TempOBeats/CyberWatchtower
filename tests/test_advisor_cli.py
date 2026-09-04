import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from cyberwatchtower.advisor.context import build_advisor_context
from cyberwatchtower.advisor.rendering import render_advisory
from cyberwatchtower.advisor.service import generate_advisory
from cyberwatchtower.cli import _display_advisor, main


def _report():
    return {
        "security_score": {"score": 90, "risk_level": "LOW", "counts": {}},
        "findings": [
            {
                "finding_id": "confirmed-risk",
                "title": "Confirmed service exposure",
                "description": "A service is exposed.",
                "severity": "MEDIUM",
                "recommendation": "Restrict the service exposure.",
                "confidence": 90,
                "source": "network",
                "kind": "RISK",
                "assessment_state": "CONFIRMED",
                "evidence": ["Port: 8080", "Exposure: all interfaces"],
            }
        ],
    }


class AdvisorRenderingTests(unittest.TestCase):
    def test_renderer_includes_required_deterministic_sections(self):
        context = build_advisor_context(_report(), None, None)
        advisory = generate_advisory(context)

        output = render_advisory(advisory, context)

        self.assertIn("CURRENT SECURITY POSTURE", output)
        self.assertIn("MOST IMPORTANT FINDINGS", output)
        self.assertIn("[MEDIUM/CONFIRMED]", output)
        self.assertIn("PRIORITIZED REMEDIATION", output)
        self.assertIn("Why it matters:", output)
        self.assertIn("WHAT SHOULD I DO NEXT?", output)

    def test_renderer_never_labels_legacy_potential_finding_as_confirmed(self):
        report = {
            "security_score": {"score": 95, "risk_level": "LOW", "counts": {}},
            "findings": [
                {
                    "finding_id": "legacy",
                    "title": "Legacy ambiguous finding",
                    "severity": "LOW",
                    "recommendation": "Verify this condition.",
                }
            ],
        }
        context = build_advisor_context(report, None, None)

        output = render_advisory(generate_advisory(context), context)

        self.assertIn("[LOW/POTENTIAL]", output)
        self.assertNotIn("[LOW/CONFIRMED]", output)
        self.assertIn("not a confirmed finding", output)

    def test_display_failure_is_contained_and_does_not_raise(self):
        output = io.StringIO()

        with (
            patch(
                "cyberwatchtower.advisor.context.build_advisor_context",
                side_effect=RuntimeError("advisor failed"),
            ),
            redirect_stdout(output),
        ):
            _display_advisor(_report(), None, {})

        self.assertIn("Advisor unavailable", output.getvalue())
        self.assertIn("deterministic scan and report remain complete", output.getvalue())

    def test_main_saves_report_before_containing_advisor_failure(self):
        report = _report()
        results = {
            "system": {"hostname": "test-host"},
            "firewall": {},
            "findings": [],
            "score": {
                "score": 100,
                "risk_level": "LOW",
                "counts": {
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "LOW": 0,
                    "INFO": 0,
                },
            },
        }
        intelligence = {
            "total_scans": 1,
            "average_score": 100,
            "best_score": 100,
            "worst_score": 100,
            "overall_change": 0,
            "overall_trend": "UNKNOWN",
            "findings": [],
        }
        output = io.StringIO()

        with (
            patch("cyberwatchtower.cli.run_scan", return_value=results),
            patch(
                "cyberwatchtower.cli.save_json_report",
                return_value="report.json",
            ) as save,
            patch("cyberwatchtower.cli.load_reports", return_value=[report]),
            patch("cyberwatchtower.cli.analyze_history", return_value=intelligence),
            patch(
                "cyberwatchtower.advisor.context.build_advisor_context",
                side_effect=RuntimeError("advisor failed"),
            ),
            redirect_stdout(output),
        ):
            main()

        save.assert_called_once_with(results)
        self.assertIn("Saved to: report.json", output.getvalue())
        self.assertIn("Advisor unavailable", output.getvalue())
        self.assertIn("scan complete", output.getvalue())

    def test_main_renders_scoring_methodology_transition_without_numeric_delta(self):
        counts = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
        }
        previous = {
            "generated_at": "2026-08-19T00:00:00+00:00",
            "system": {"hostname": "test-host"},
            "security_score": {
                "scoring_version": "1", "score": 0,
                "risk_level": "CRITICAL", "counts": counts,
            },
            "findings": [],
        }
        current = {
            "generated_at": "2026-08-20T00:00:00+00:00",
            "system": {"hostname": "test-host"},
            "security_score": {
                "scoring_version": "2", "score": 82,
                "risk_level": "MODERATE", "counts": counts,
            },
            "findings": [],
        }
        results = {
            "system": {"hostname": "test-host"}, "firewall": {},
            "findings": [], "score": current["security_score"],
        }
        output = io.StringIO()
        with (
            patch("cyberwatchtower.cli.run_scan", return_value=results),
            patch("cyberwatchtower.cli.save_json_report", return_value="report.json"),
            patch("cyberwatchtower.cli.load_reports", return_value=[previous, current]),
            patch("cyberwatchtower.cli._display_advisor"),
            patch("cyberwatchtower.cli._ingest_saved_report", return_value=None),
            redirect_stdout(output),
        ):
            main()
        rendered = output.getvalue()
        self.assertIn("Change: N/A", rendered)
        self.assertIn("Trend: SCORING_VERSION_CHANGED", rendered)
        self.assertNotIn("Change: +82", rendered)
        self.assertIn("Average Score: N/A", rendered)


class UnsupportedPlatformCliTests(unittest.TestCase):
    def _assert_contained_failure(self, system_name):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch(
                "cyberwatchtower.platform.selection.platform.system",
                return_value=system_name,
            ),
            patch(
                "cyberwatchtower.platform.linux.adapter."
                "LinuxPlatformAdapter.collect_system"
            ) as linux_collect,
            patch(
                "cyberwatchtower.platform.windows.adapter."
                "WindowsPlatformAdapter.collect_system"
            ) as windows_collect,
            patch("cyberwatchtower.cli.save_json_report") as save_report,
            patch("cyberwatchtower.cli.load_reports") as load_reports,
            patch("cyberwatchtower.cli._ingest_saved_report") as write_memory,
            redirect_stdout(stdout),
            redirect_stderr(stderr),
            self.assertRaises(SystemExit) as raised,
        ):
            main([])

        self.assertEqual(raised.exception.code, 2)
        self.assertIn(
            "CyberWatchtower currently supports Windows and Linux.",
            stdout.getvalue(),
        )
        self.assertNotIn(system_name, stdout.getvalue())
        self.assertNotIn("Traceback", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")
        linux_collect.assert_not_called()
        windows_collect.assert_not_called()
        save_report.assert_not_called()
        load_reports.assert_not_called()
        write_memory.assert_not_called()

    def test_darwin_failure_is_bounded_before_collection_or_persistence(self):
        self._assert_contained_failure("Darwin")

    def test_unknown_platform_failure_is_bounded_without_fallback(self):
        self._assert_contained_failure("SyntheticUnsupportedPlatform")

    def test_unrelated_internal_error_is_not_swallowed(self):
        with (
            patch(
                "cyberwatchtower.cli.run_scan",
                side_effect=RuntimeError("programmer error"),
            ),
            self.assertRaisesRegex(RuntimeError, "programmer error"),
        ):
            main([])


if __name__ == "__main__":
    unittest.main()
