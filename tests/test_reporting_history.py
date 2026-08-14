import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from cyberwatchtower.history import load_reports
from cyberwatchtower.models import Finding, Severity
from cyberwatchtower.reporting import save_json_report
from cyberwatchtower.report_contracts import (
    LegacyIdentityResolution,
    LegacyIdentityState,
    LegacyLinkPolicy,
    canonical_report_digest,
)


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
    def test_system_id_isolates_hosts_even_when_hostnames_match(self):
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory)
            for filename, system_id in (("a.json", "cwt-a"), ("b.json", "cwt-b")):
                (report_dir / filename).write_text(
                    json.dumps(
                        {
                            "generated_at": "2026-08-13T12:00:00+00:00",
                            "system": {
                                "hostname": "same-hostname",
                                "system_id": system_id,
                            },
                            "security_score": {"score": 100},
                            "findings": [],
                        }
                    ),
                    encoding="utf-8",
                )

            reports = load_reports(
                report_dir,
                hostname="same-hostname",
                system_id="cwt-a",
            )

        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0]["system"]["system_id"], "cwt-a")

    def test_legacy_same_hostname_is_excluded_without_explicit_link(self):
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory)
            _write_report(
                report_dir / "legacy.json",
                "legacy-host",
                "2026-08-13T12:00:00+00:00",
            )

            reports = load_reports(
                report_dir,
                hostname="legacy-host",
                system_id="cwt-current",
            )

        self.assertEqual(reports, [])

    def test_explicit_unambiguous_legacy_link_is_admitted(self):
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory)
            path = report_dir / "legacy.json"
            _write_report(path, "legacy-host", "2026-08-13T12:00:00+00:00")
            raw = json.loads(path.read_text(encoding="utf-8"))
            digest = canonical_report_digest(raw)
            resolution = LegacyIdentityResolution(
                LegacyIdentityState.HOSTNAME_FALLBACK,
                "cwt-current",
                "legacy-host",
                LegacyLinkPolicy.ALLOW_EXPLICIT_HOSTNAME_FALLBACK,
                "Explicit same-system legacy association.",
            )
            reports = load_reports(
                report_dir,
                hostname="legacy-host",
                system_id="cwt-current",
                legacy_resolutions={digest: resolution},
            )

        self.assertEqual(len(reports), 1)
        self.assertNotIn("system_id", reports[0]["system"])

    def test_explicit_legacy_link_is_bound_to_digest_and_system(self):
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory)
            path = report_dir / "legacy.json"
            _write_report(path, "legacy-host", "2026-08-13T12:00:00+00:00")
            digest = canonical_report_digest(
                json.loads(path.read_text(encoding="utf-8"))
            )
            wrong_system = LegacyIdentityResolution(
                LegacyIdentityState.HOSTNAME_FALLBACK,
                "cwt-other",
                "legacy-host",
                LegacyLinkPolicy.ALLOW_EXPLICIT_HOSTNAME_FALLBACK,
                "Explicit link for a different system.",
            )
            wrong_digest = load_reports(
                report_dir, hostname="legacy-host", system_id="cwt-current",
                legacy_resolutions={"0" * 64: wrong_system},
            )
            wrong_target = load_reports(
                report_dir, hostname="legacy-host", system_id="cwt-current",
                legacy_resolutions={digest: wrong_system},
            )
        self.assertEqual(wrong_digest, [])
        self.assertEqual(wrong_target, [])

    def test_system_id_without_hostname_does_not_admit_legacy_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory)
            _write_report(
                report_dir / "legacy.json",
                "legacy-host",
                "2026-08-13T12:00:00+00:00",
            )

            reports = load_reports(report_dir, system_id="cwt-current")

        self.assertEqual(reports, [])

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
