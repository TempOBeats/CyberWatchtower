import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from cyberwatchtower.history import load_reports
from cyberwatchtower.models import Finding, Severity
from cyberwatchtower.reporting import save_json_report


def _write_report(path: Path, hostname: str, generated_at: str) -> None:
    path.write_text(
        json.dumps(
            {
                "generated_at": generated_at,
                "system": {"hostname": hostname},
                "security_score": {"score": 100},
                "findings": [],
            }
        ),
        encoding="utf-8",
    )


class ReportHistoryTests(unittest.TestCase):
    def test_reports_are_filtered_by_host_and_sorted_by_generated_time(self):
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory)
            _write_report(
                report_dir / "a.json",
                "host-a",
                "2026-08-13T12:00:00+00:00",
            )
            _write_report(
                report_dir / "z.json",
                "host-a",
                "2026-08-13T10:00:00+00:00",
            )
            _write_report(
                report_dir / "middle.json",
                "host-b",
                "2026-08-13T11:00:00+00:00",
            )

            reports = load_reports(report_dir, hostname="host-a")

        self.assertEqual(len(reports), 2)
        self.assertEqual(
            [report["generated_at"] for report in reports],
            [
                "2026-08-13T10:00:00+00:00",
                "2026-08-13T12:00:00+00:00",
            ],
        )

    def test_same_timestamp_creates_distinct_report_files(self):
        fixed_time = datetime(2026, 8, 13, 12, 30, tzinfo=timezone.utc)
        results = {
            "system": {"hostname": "test-host"},
            "score": {"score": 100, "risk_level": "LOW", "counts": {}},
            "findings": [
                Finding(
                    title="Example",
                    description="Example finding",
                    severity=Severity.INFO,
                    recommendation="None",
                )
            ],
        }

        with tempfile.TemporaryDirectory() as directory:
            with patch("cyberwatchtower.reporting.datetime") as mocked_datetime:
                mocked_datetime.now.return_value = fixed_time
                first = save_json_report(results, directory)
                second = save_json_report(results, directory)

            self.assertNotEqual(first, second)
            self.assertTrue(first.exists())
            self.assertTrue(second.exists())


if __name__ == "__main__":
    unittest.main()
