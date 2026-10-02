import errno
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import cyberwatchtower.application.reports as report_boundary
import cyberwatchtower.reporting as reporting
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


def _report_results() -> dict[str, object]:
    return {
        "system": {"hostname": "test-host", "system_id": "system:test"},
        "score": {"score": 100, "risk_level": "LOW", "counts": {}},
        "findings": [],
    }


def _fixed_report_name(fixed_time: datetime, suffix: str = "") -> str:
    timestamp = fixed_time.astimezone().strftime("%Y%m%d_%H%M%S_%f")
    return f"cyberwatchtower_test-host_{timestamp}{suffix}.json"


class _RecordingStream:
    def __init__(self, stream, events, fail_on=None):
        self._stream = stream
        self._events = events
        self._fail_on = fail_on

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()
        return False

    def write(self, value):
        self._events.append("write")
        if self._fail_on == "write":
            raise OSError(errno.EIO, "controlled write failure")
        return self._stream.write(value)

    def flush(self):
        self._events.append("flush")
        if self._fail_on == "flush":
            raise OSError(errno.EIO, "controlled flush failure")
        return self._stream.flush()

    def fileno(self):
        return self._stream.fileno()

    def close(self):
        self._events.append("close")
        return self._stream.close()


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


class AtomicReportWriterTests(unittest.TestCase):
    def test_serialization_and_report_content_remain_canonical(self):
        fixed_time = datetime(2026, 8, 13, 12, 30, tzinfo=timezone.utc)
        generated = fixed_time.astimezone()
        expected = {
            "schema_version": "1.7",
            "generated_at": generated.isoformat(),
            "system": {
                "hostname": "test-host",
                "system_id": "system:test",
            },
            "assessment_domains": [
                "firewall_technology",
                "iptables_input_policy",
                "network_socket_inspection",
            ],
            "coverage": {
                "firewall_technology": "UNKNOWN",
                "iptables_input_policy": "UNKNOWN",
                "network_socket_inspection": "UNKNOWN",
            },
            "assessment_assurance": {
                "level": "INCOMPLETE",
                "limitations": [
                    "firewall technology detection was not completely assessed",
                    "iptables INPUT policy was not completely assessed",
                    "listening-service inspection was not completely assessed",
                ],
            },
            "security_score": {
                "score": 100,
                "risk_level": "LOW",
                "counts": {},
                "scoring_version": "1",
            },
            "findings": [],
        }
        with tempfile.TemporaryDirectory() as directory, patch(
            "cyberwatchtower.reporting.datetime"
        ) as mocked_datetime:
            mocked_datetime.now.return_value = fixed_time
            path = save_json_report(_report_results(), directory)
            content = path.read_text(encoding="utf-8")
        self.assertEqual(content, json.dumps(expected, indent=2))
        self.assertEqual(json.loads(content), expected)

    def test_write_flush_or_fsync_failure_never_creates_canonical_report(self):
        real_fdopen = os.fdopen
        real_fsync = os.fsync
        for failure_point in ("write", "flush", "fsync"):
            with self.subTest(
                failure_point=failure_point
            ), tempfile.TemporaryDirectory() as directory:
                events = []

                def recording_fdopen(descriptor, *args, **kwargs):
                    stream = real_fdopen(descriptor, *args, **kwargs)
                    return _RecordingStream(
                        stream,
                        events,
                        failure_point if failure_point != "fsync" else None,
                    )

                def controlled_fsync(descriptor):
                    events.append("fsync")
                    if failure_point == "fsync":
                        raise OSError(errno.EIO, "controlled fsync failure")
                    return real_fsync(descriptor)

                with patch.object(
                    reporting.os,
                    "fdopen",
                    side_effect=recording_fdopen,
                ), patch.object(
                    reporting.os,
                    "fsync",
                    side_effect=controlled_fsync,
                ):
                    with self.assertRaises(OSError):
                        save_json_report(_report_results(), directory)

                report_dir = Path(directory)
                self.assertEqual(tuple(report_dir.glob("*.json")), ())
                self.assertEqual(tuple(report_dir.glob("*.tmp")), ())

    def test_write_flush_fsync_close_precede_link_publication(self):
        events = []
        real_fdopen = os.fdopen
        real_fsync = os.fsync
        real_link = os.link

        def recording_fdopen(descriptor, *args, **kwargs):
            return _RecordingStream(
                real_fdopen(descriptor, *args, **kwargs),
                events,
            )

        def recording_fsync(descriptor):
            events.append("fsync")
            return real_fsync(descriptor)

        def recording_link(*args, **kwargs):
            events.append("link")
            return real_link(*args, **kwargs)

        with tempfile.TemporaryDirectory() as directory, patch.object(
            reporting.os,
            "fdopen",
            side_effect=recording_fdopen,
        ), patch.object(
            reporting.os,
            "fsync",
            side_effect=recording_fsync,
        ), patch.object(
            reporting.os,
            "link",
            side_effect=recording_link,
        ):
            path = save_json_report(_report_results(), directory)
            self.assertTrue(path.exists())

        self.assertEqual(events, ["write", "flush", "fsync", "close", "link"])

    def test_success_uses_link_cleans_temp_and_returns_published_path(self):
        real_link = os.link
        with tempfile.TemporaryDirectory() as directory, patch.object(
            reporting.os,
            "link",
            wraps=real_link,
        ) as link, patch.object(
            reporting.os,
            "replace",
        ) as replace, patch.object(
            reporting.os,
            "rename",
        ) as rename:
            path = save_json_report(_report_results(), directory)
            self.assertEqual(path.parent, Path(directory))
            self.assertTrue(path.exists())
            self.assertEqual(json.loads(path.read_text())["schema_version"], "1.7")
            self.assertEqual(tuple(Path(directory).glob("*.tmp")), ())
            self.assertEqual(link.call_count, 1)
            source_name, destination_name = link.call_args.args
            self.assertTrue(source_name.isdecimal())
            self.assertTrue(destination_name.endswith(".json"))
            self.assertNotEqual(
                link.call_args.kwargs["src_dir_fd"],
                link.call_args.kwargs["dst_dir_fd"],
            )
            self.assertTrue(link.call_args.kwargs["follow_symlinks"])
            replace.assert_not_called()
            rename.assert_not_called()

    def test_public_wrapper_closes_private_receipt_descriptor_once(self):
        close_calls = []
        real_close = reporting._PublicationReceipt.close

        def recording_close(receipt):
            close_calls.append(receipt)
            return real_close(receipt)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            published = root / "published.json"
            descriptor = os.open(root, os.O_RDONLY)
            receipt = reporting._PublicationReceipt(
                path=published,
                canonical_name=published.name,
                directory_descriptor=descriptor,
                directory_device=root.stat().st_dev,
                directory_inode=root.stat().st_ino,
                file_device=1,
                file_inode=1,
                file_size=0,
                content_sha256=b"\x00" * 32,
                resolved_directory=root,
            )
            with patch.object(
                reporting,
                "_save_json_report",
                return_value=receipt,
            ) as private_save, patch.object(
                reporting._PublicationReceipt,
                "close",
                new=recording_close,
            ):
                returned = save_json_report(_report_results(), root)

            self.assertEqual(returned, published)
            private_save.assert_called_once_with(
                _report_results(),
                root,
                retain_directory=False,
            )
            self.assertEqual(close_calls, [receipt])
            self.assertEqual(receipt.directory_descriptor, -1)
            with self.assertRaises(OSError) as caught:
                os.fstat(descriptor)
            self.assertEqual(caught.exception.errno, errno.EBADF)

    def test_collisions_never_modify_existing_reports(self):
        fixed_time = datetime(2026, 8, 13, 12, 30, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory)
            base = report_dir / _fixed_report_name(fixed_time)
            first_suffix = report_dir / _fixed_report_name(fixed_time, "_1")
            base.write_bytes(b"base sentinel")
            first_suffix.write_bytes(b"suffix sentinel")
            with patch("cyberwatchtower.reporting.datetime") as mocked_datetime:
                mocked_datetime.now.return_value = fixed_time
                published = save_json_report(_report_results(), report_dir)

            self.assertEqual(
                published,
                report_dir / _fixed_report_name(fixed_time, "_2"),
            )
            self.assertEqual(base.read_bytes(), b"base sentinel")
            self.assertEqual(first_suffix.read_bytes(), b"suffix sentinel")
            self.assertEqual(json.loads(published.read_text())["schema_version"], "1.7")

    def test_collision_exhaustion_attempts_exactly_base_through_999(self):
        attempted = []

        def occupied(_source, destination, **_kwargs):
            attempted.append(destination)
            raise FileExistsError(errno.EEXIST, "occupied")

        with tempfile.TemporaryDirectory() as directory, patch.object(
            reporting.os,
            "link",
            side_effect=occupied,
        ):
            with self.assertRaises(FileExistsError) as caught:
                save_json_report(_report_results(), directory)
            self.assertIs(
                type(caught.exception),
                reporting._CanonicalNameExhausted,
            )
            self.assertEqual(tuple(Path(directory).glob("*.json")), ())
            self.assertEqual(tuple(Path(directory).glob("*.tmp")), ())

        self.assertEqual(len(attempted), 1000)
        self.assertTrue(attempted[0].endswith(".json"))
        self.assertFalse(attempted[0].endswith("_1.json"))
        self.assertTrue(attempted[1].endswith("_1.json"))
        self.assertTrue(attempted[-1].endswith("_999.json"))
        self.assertFalse(any(name.endswith("_1000.json") for name in attempted))

    def test_noncollision_link_failure_has_no_fallback_or_canonical_file(self):
        fixed_time = datetime(2026, 8, 13, 12, 30, tzinfo=timezone.utc)
        publication_failure = OSError(errno.EIO, "controlled link failure")
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory)
            base = report_dir / _fixed_report_name(fixed_time)
            base.write_bytes(b"base sentinel")

            def fail_after_collision(_source, destination, **_kwargs):
                if destination == base.name:
                    raise FileExistsError(errno.EEXIST, "occupied")
                raise publication_failure

            with patch(
                "cyberwatchtower.reporting.datetime"
            ) as mocked_datetime, patch.object(
                reporting.os,
                "link",
                side_effect=fail_after_collision,
            ), patch.object(reporting.os, "replace") as replace, patch.object(
                reporting.os,
                "rename",
            ) as rename:
                mocked_datetime.now.return_value = fixed_time
                with self.assertRaises(OSError) as caught:
                    save_json_report(_report_results(), report_dir)

            self.assertIs(caught.exception, publication_failure)
            self.assertEqual(base.read_bytes(), b"base sentinel")
            self.assertFalse(
                (report_dir / _fixed_report_name(fixed_time, "_1")).exists()
            )
            self.assertEqual(tuple(report_dir.glob("*.json")), (base,))
            self.assertEqual(tuple(report_dir.glob("*.tmp")), ())
            replace.assert_not_called()
            rename.assert_not_called()

    def test_cleanup_failure_does_not_replace_publication_failure(self):
        publication_failure = OSError(errno.EIO, "controlled link failure")
        cleanup_failure = OSError(errno.EACCES, "controlled cleanup failure")
        with tempfile.TemporaryDirectory() as directory, patch.object(
            reporting.os,
            "link",
            side_effect=publication_failure,
        ), patch.object(
            reporting.os,
            "unlink",
            side_effect=cleanup_failure,
        ):
            with self.assertRaises(OSError) as caught:
                save_json_report(_report_results(), directory)
            self.assertIs(caught.exception, publication_failure)
            self.assertEqual(tuple(Path(directory).glob("*.json")), ())

    def test_crash_style_temp_artifact_is_ignored_by_read_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".cyberwatchtower-report-orphan.tmp").write_text(
                "partial",
                encoding="utf-8",
            )
            snapshot = report_boundary._FileReportRepository(
                root
            ).catalog_for_system("system:test")
            catalog = snapshot.public_catalog("reportop:" + "a" * 32)
        self.assertEqual(catalog.reports, ())
        self.assertEqual(catalog.omitted_count, 0)
        self.assertEqual(catalog.completeness.value, "COMPLETE")

    def test_absent_directory_is_created_and_used(self):
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory, "nested", "reports")
            path = save_json_report(_report_results(), report_dir)
            self.assertEqual(path.parent, report_dir)
            self.assertTrue(path.exists())
            self.assertEqual(tuple(report_dir.glob("*.tmp")), ())

    def test_regular_file_and_symlink_directories_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            regular = base / "regular"
            regular.write_text("not a directory", encoding="utf-8")
            real = base / "real"
            real.mkdir()
            symlink = base / "symlink"
            symlink.symlink_to(real, target_is_directory=True)
            for unsafe in (regular, symlink):
                with self.subTest(unsafe=unsafe.name), self.assertRaises(OSError):
                    save_json_report(_report_results(), unsafe)
            self.assertEqual(tuple(real.glob("*.json")), ())

    def test_directory_replacement_cannot_redirect_temp_or_publication(self):
        real_mkstemp = tempfile.mkstemp
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            report_dir = base / "reports"
            report_dir.mkdir()
            trusted = base / "trusted-root"

            def replace_before_temp(*args, **kwargs):
                report_dir.rename(trusted)
                report_dir.mkdir()
                return real_mkstemp(*args, **kwargs)

            with patch.object(
                reporting.tempfile,
                "mkstemp",
                side_effect=replace_before_temp,
            ), self.assertRaises(OSError):
                save_json_report(_report_results(), report_dir)

            self.assertEqual(tuple(report_dir.glob("*.json")), ())
            self.assertEqual(tuple(trusted.glob("*.json")), ())

    def test_temp_replacement_never_publishes_replacement_content(self):
        real_link = os.link
        replacement_payload = '{"attacker_replaced":true}'
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory)
            displaced = report_dir / "displaced-original.tmp"
            replacement_identity = None

            def replace_then_link(source, destination, **kwargs):
                nonlocal replacement_identity
                if replacement_identity is None:
                    temp_path, = report_dir.glob(".cyberwatchtower-report-*.tmp")
                    temp_path.rename(displaced)
                    temp_path.write_text(replacement_payload, encoding="utf-8")
                    replacement = temp_path.stat()
                    replacement_identity = (replacement.st_dev, replacement.st_ino)
                return real_link(source, destination, **kwargs)

            published = None
            with patch.object(
                reporting.os,
                "link",
                side_effect=replace_then_link,
            ):
                try:
                    published = save_json_report(_report_results(), report_dir)
                except OSError:
                    pass

            canonical = tuple(report_dir.glob("*.json"))
            self.assertIsNotNone(replacement_identity)
            self.assertFalse(
                any(
                    (path.stat().st_dev, path.stat().st_ino)
                    == replacement_identity
                    for path in canonical
                )
            )
            if published is None:
                self.assertEqual(canonical, ())
            else:
                self.assertEqual(canonical, (published,))
                self.assertEqual(
                    json.loads(published.read_text(encoding="utf-8"))[
                        "schema_version"
                    ],
                    "1.7",
                )
                self.assertEqual(
                    (published.stat().st_dev, published.stat().st_ino),
                    (displaced.stat().st_dev, displaced.stat().st_ino),
                )

    def test_temp_unlink_before_publication_never_redirects_source(self):
        real_link = os.link
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory)
            removed = False

            def unlink_then_link(source, destination, **kwargs):
                nonlocal removed
                if not removed:
                    temp_path, = report_dir.glob(".cyberwatchtower-report-*.tmp")
                    temp_path.unlink()
                    removed = True
                return real_link(source, destination, **kwargs)

            published = None
            with patch.object(
                reporting.os,
                "link",
                side_effect=unlink_then_link,
            ):
                try:
                    published = save_json_report(_report_results(), report_dir)
                except OSError:
                    pass

            canonical = tuple(report_dir.glob("*.json"))
            self.assertTrue(removed)
            if published is None:
                self.assertEqual(canonical, ())
            else:
                self.assertEqual(canonical, (published,))
                self.assertEqual(
                    json.loads(published.read_text(encoding="utf-8"))[
                        "schema_version"
                    ],
                    "1.7",
                )

    def test_temp_replacement_and_collision_never_publish_replacement(self):
        fixed_time = datetime(2026, 8, 13, 12, 30, tzinfo=timezone.utc)
        real_link = os.link
        replacement_payload = b'{"attacker_replaced":true}'
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory)
            base = report_dir / _fixed_report_name(fixed_time)
            base.write_bytes(b"base sentinel")
            displaced = report_dir / "displaced-original.tmp"
            replacement_identity = None

            def replace_then_link(source, destination, **kwargs):
                nonlocal replacement_identity
                if replacement_identity is None:
                    temp_path, = report_dir.glob(".cyberwatchtower-report-*.tmp")
                    temp_path.rename(displaced)
                    temp_path.write_bytes(replacement_payload)
                    replacement = temp_path.stat()
                    replacement_identity = (replacement.st_dev, replacement.st_ino)
                return real_link(source, destination, **kwargs)

            published = None
            with patch(
                "cyberwatchtower.reporting.datetime"
            ) as mocked_datetime, patch.object(
                reporting.os,
                "link",
                side_effect=replace_then_link,
            ):
                mocked_datetime.now.return_value = fixed_time
                try:
                    published = save_json_report(_report_results(), report_dir)
                except OSError:
                    pass

            self.assertEqual(base.read_bytes(), b"base sentinel")
            self.assertIsNotNone(replacement_identity)
            new_canonical = tuple(
                path for path in report_dir.glob("*.json") if path != base
            )
            self.assertFalse(
                any(
                    (path.stat().st_dev, path.stat().st_ino)
                    == replacement_identity
                    for path in new_canonical
                )
            )
            if published is None:
                self.assertEqual(new_canonical, ())
            else:
                self.assertEqual(
                    published,
                    report_dir / _fixed_report_name(fixed_time, "_1"),
                )
                self.assertEqual(new_canonical, (published,))
                self.assertEqual(
                    (published.stat().st_dev, published.stat().st_ino),
                    (displaced.stat().st_dev, displaced.stat().st_ino),
                )

    def test_multiple_collisions_reuse_one_authoritative_source_object(self):
        fixed_time = datetime(2026, 8, 13, 12, 30, tzinfo=timezone.utc)
        real_link = os.link
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory)
            for suffix in ("", "_1", "_2"):
                (report_dir / _fixed_report_name(fixed_time, suffix)).write_bytes(
                    f"sentinel{suffix}".encode("ascii")
                )
            source_names = []
            source_identities = []

            def record_source(source, destination, **kwargs):
                source_names.append(source)
                source_stat = os.stat(
                    source,
                    dir_fd=kwargs.get("src_dir_fd"),
                    follow_symlinks=kwargs.get("follow_symlinks", True),
                )
                source_identities.append((source_stat.st_dev, source_stat.st_ino))
                return real_link(source, destination, **kwargs)

            with patch(
                "cyberwatchtower.reporting.datetime"
            ) as mocked_datetime, patch.object(
                reporting.os,
                "link",
                side_effect=record_source,
            ):
                mocked_datetime.now.return_value = fixed_time
                published = save_json_report(_report_results(), report_dir)

            self.assertEqual(len(source_names), 4)
            self.assertTrue(all(name == source_names[0] for name in source_names))
            self.assertTrue(all(name.isdecimal() for name in source_names))
            self.assertEqual(len(set(source_identities)), 1)
            self.assertEqual(
                source_identities[0],
                (published.stat().st_dev, published.stat().st_ino),
            )
            self.assertEqual(
                published,
                report_dir / _fixed_report_name(fixed_time, "_3"),
            )

    def test_directory_close_error_does_not_mask_successful_publication(self):
        real_open_report_directory = reporting._open_report_directory
        real_close = os.close
        report_directory_descriptor = None

        def recording_open_report_directory(report_dir):
            nonlocal report_directory_descriptor
            descriptor, identity = real_open_report_directory(report_dir)
            report_directory_descriptor = descriptor
            return descriptor, identity

        def close_then_fail(descriptor):
            real_close(descriptor)
            if descriptor == report_directory_descriptor:
                raise OSError(errno.EIO, "controlled directory close failure")

        with tempfile.TemporaryDirectory() as directory, patch.object(
            reporting,
            "_open_report_directory",
            side_effect=recording_open_report_directory,
        ), patch.object(
            reporting.os,
            "close",
            side_effect=close_then_fail,
        ):
            published = save_json_report(_report_results(), directory)
            self.assertTrue(published.exists())
            self.assertEqual(
                json.loads(published.read_text(encoding="utf-8"))[
                    "schema_version"
                ],
                "1.7",
            )

    def test_unsupported_object_bound_publication_fails_before_temp_creation(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
            reporting,
            "_OBJECT_BOUND_PUBLICATION_SUPPORTED",
            False,
        ), patch.object(reporting.tempfile, "mkstemp") as mkstemp:
            with self.assertRaises(OSError) as caught:
                save_json_report(_report_results(), directory)
            self.assertEqual(caught.exception.errno, errno.ENOTSUP)
            mkstemp.assert_not_called()
            self.assertEqual(tuple(Path(directory).glob("*.json")), ())

    def test_unsupported_source_bound_publication_fails_before_temp_creation(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
            reporting,
            "_SOURCE_BOUND_PUBLICATION_SUPPORTED",
            False,
        ), patch.object(reporting.tempfile, "mkstemp") as mkstemp:
            with self.assertRaises(OSError) as caught:
                save_json_report(_report_results(), directory)
            self.assertEqual(caught.exception.errno, errno.ENOTSUP)
            mkstemp.assert_not_called()
            self.assertEqual(tuple(Path(directory).glob("*.json")), ())


if __name__ == "__main__":
    unittest.main()
