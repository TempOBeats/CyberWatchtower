import copy
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from cyberwatchtower.cli import main
from cyberwatchtower.presentation import group_report_findings


def _listener(finding_id: str, address: str, port: str = "5353") -> dict:
    return {
        "finding_id": finding_id,
        "title": "Potentially reachable DNS listener",
        "description": "A listener has a broad bind.",
        "severity": "MEDIUM",
        "recommendation": "Verify DNS exposure.",
        "confidence": 100,
        "source": "network",
        "kind": "RISK",
        "assessment_state": "POTENTIAL",
        "evidence": [
            "Application: windows-service:dnscache",
            "Protocol: udp",
            f"Port: {port}",
            f"Address: {address}",
        ],
        "network_context": {
            "bind_exposure": "all_interfaces",
            "bind_epistemic_role": "OBSERVED_FACT",
            "reachability_state": "POTENTIALLY_REACHABLE",
            "reachability_epistemic_role": "DETERMINISTIC_DERIVATION",
            "evidence_basis": ["SOCKET_WILDCARD_BIND"],
        },
        "runtime_instance_count": 1,
    }


class PresentationPolishTests(unittest.TestCase):
    def test_report_grouping_retains_atomic_records_and_separates_unknown_ports(self):
        twins = [_listener("finding:v4", "0.0.0.0"), _listener("finding:v6", "::")]
        snapshot = copy.deepcopy(twins)

        groups = group_report_findings(twins)

        self.assertEqual(len(groups), 1)
        self.assertEqual(
            tuple(item["finding_id"] for item in groups[0].findings),
            ("finding:v4", "finding:v6"),
        )
        self.assertEqual(twins, snapshot)
        unknown_a = _listener("unknown:a", "0.0.0.0", "1000")
        unknown_b = _listener("unknown:b", "0.0.0.0", "1001")
        for item in (unknown_a, unknown_b):
            item["evidence"] = [
                entry
                for entry in item["evidence"]
                if not entry.startswith("Application:")
            ]
        self.assertEqual(len(group_report_findings([unknown_a, unknown_b])), 2)

    def test_new_and_recurring_findings_render_as_deterministic_blocks(self):
        first = _listener("finding:v4", "0.0.0.0")
        second = _listener("finding:v6", "::")
        second["runtime_instance_count"] = 2
        recurring = [
            {**first, "occurrences": 3},
            {**second, "occurrences": 2},
        ]
        recurring_snapshot = copy.deepcopy(recurring)
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 2, "LOW": 0, "INFO": 0}
        results = {
            "system": {"hostname": "host"}, "firewall": {}, "findings": [],
            "score": {
                "scoring_version": "1", "score": 90,
                "risk_level": "LOW", "counts": counts,
            },
        }
        reports = [
            {
                "system": {"hostname": "host"}, "findings": [],
                "security_score": results["score"],
            },
            {
                "system": {"hostname": "host"},
                "findings": [first, second],
                "security_score": results["score"],
            },
        ]
        comparison = {
            "previous_score": 90, "current_score": 90, "change": 0,
            "trend": "UNCHANGED", "new_findings": [second, first],
            "resolved_findings": [], "uncertain_findings": [],
        }
        intelligence = {
            "total_scans": 2, "average_score": 90, "best_score": 90,
            "worst_score": 90, "overall_change": 0,
            "overall_trend": "UNCHANGED", "findings": recurring,
        }
        output = io.StringIO()
        with (
            patch("cyberwatchtower.cli.run_scan", return_value=results),
            patch("cyberwatchtower.cli.save_json_report", return_value="report.json"),
            patch("cyberwatchtower.cli.load_reports", return_value=reports),
            patch("cyberwatchtower.cli.compare_reports", return_value=comparison),
            patch("cyberwatchtower.cli.analyze_history", return_value=intelligence),
            patch("cyberwatchtower.cli._display_advisor"),
            patch("cyberwatchtower.cli._ingest_saved_report", return_value=None),
            redirect_stdout(output),
        ):
            main([])

        rendered = output.getvalue()
        new_section = rendered.split("NEW FINDINGS", 1)[1].split(
            "SECURITY INTELLIGENCE", 1
        )[0]
        self.assertEqual(
            new_section.count("[MEDIUM] Potentially reachable DNS listener"), 1
        )
        self.assertIn("Related listener findings: 2", new_section)
        self.assertIn("Multiple runtime instances observed: 3", new_section)
        self.assertIn("Evidence:\n - Application:", new_section)
        recurring_section = rendered.split("RECURRING FINDINGS", 1)[1]
        self.assertIn("2 related listeners, 5 atomic occurrences", recurring_section)
        self.assertEqual(recurring, recurring_snapshot)
        self.assertEqual(
            {item["finding_id"]: item["occurrences"] for item in recurring},
            {"finding:v4": 3, "finding:v6": 2},
        )


if __name__ == "__main__":
    unittest.main()
