import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from cyberwatchtower.cli import main


def _write_report(directory: str) -> None:
    Path(directory, "report.json").write_text(json.dumps({
        "generated_at": "2026-08-13T00:00:00+00:00",
        "system": {"system_id": "cwt-test", "hostname": "host"},
        "security_score": {"score": 100, "risk_level": "LOW", "counts": {}},
        "findings": [],
    }), encoding="utf-8")


class IntelligenceCliTests(unittest.TestCase):
    def test_briefing_reads_saved_reports_without_running_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            _write_report(directory)
            output = io.StringIO()
            with patch("cyberwatchtower.cli.run_scan") as run_scan, redirect_stdout(output):
                main(["briefing", "--reports", directory])
        run_scan.assert_not_called()
        self.assertIn("CYBERWATCHTOWER SECURITY BRIEFING", output.getvalue())
        self.assertIn("100/100", output.getvalue())

    def test_supported_question_uses_saved_advisor_data(self):
        with tempfile.TemporaryDirectory() as directory:
            _write_report(directory)
            output = io.StringIO()
            with patch("cyberwatchtower.cli.run_scan") as run_scan, redirect_stdout(output):
                main(["ask", "What changed?", "--reports", directory])
        run_scan.assert_not_called()
        self.assertIn("No previous same-host scan", output.getvalue())

    def test_intelligence_failure_does_not_start_scanner(self):
        output = io.StringIO()
        with (
            patch("cyberwatchtower.core.orchestrator.IntelligenceOrchestrator.handle", side_effect=RuntimeError),
            patch("cyberwatchtower.cli.run_scan") as run_scan,
            redirect_stdout(output),
        ):
            main(["briefing"])
        run_scan.assert_not_called()
        self.assertIn("scanner remain unchanged", output.getvalue())


if __name__ == "__main__":
    unittest.main()
