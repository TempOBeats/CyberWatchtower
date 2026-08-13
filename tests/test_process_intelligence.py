import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cyberwatchtower.network import (
    assess_network_exposure,
    enrich_process_intelligence,
)
from cyberwatchtower.process_intelligence import inspect_process_application


def _write_cmdline(proc_root: Path, pid: int, arguments: list[str]) -> None:
    process_dir = proc_root / str(pid)
    process_dir.mkdir()
    (process_dir / "cmdline").write_bytes(
        b"\0".join(argument.encode() for argument in arguments) + b"\0"
    )


class ProcessIntelligenceTests(unittest.TestCase):
    def test_python_script_identifies_known_wsdd_without_returning_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            proc_root = Path(directory)
            _write_cmdline(
                proc_root,
                123,
                ["python3", "/usr/bin/wsdd", "--password", "top-secret"],
            )

            result = inspect_process_application(123, "python3", proc_root)

        self.assertEqual(result["application"], "/usr/bin/wsdd")
        self.assertEqual(result["application_name"], "WSDD")
        self.assertTrue(result["known_application"])
        self.assertNotIn("top-secret", repr(result))
        self.assertNotIn("cmdline", result)

    def test_inline_python_code_is_never_returned_as_application(self):
        with tempfile.TemporaryDirectory() as directory:
            proc_root = Path(directory)
            _write_cmdline(
                proc_root,
                124,
                ["python3", "-c", "password = 'top-secret'"],
            )

            result = inspect_process_application(124, "python3", proc_root)

        self.assertIsNone(result["application"])
        self.assertNotIn("top-secret", repr(result))

    def test_python_module_is_identified_without_following_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            proc_root = Path(directory)
            _write_cmdline(
                proc_root,
                125,
                ["python3", "-m", "http.server", "--bind", "0.0.0.0"],
            )

            result = inspect_process_application(125, "python3", proc_root)

        self.assertEqual(result["application"], "http.server")
        self.assertNotIn("0.0.0.0", repr(result))

    def test_missing_process_is_a_safe_nonfatal_result(self):
        with tempfile.TemporaryDirectory() as directory:
            result = inspect_process_application(999, "python3", directory)

        self.assertFalse(result["inspected"])
        self.assertEqual(result["reason"], "process_not_found")

    def test_permission_denial_is_a_safe_nonfatal_result(self):
        with patch("pathlib.Path.open", side_effect=PermissionError):
            result = inspect_process_application(999, "python3")

        self.assertFalse(result["inspected"])
        self.assertEqual(result["reason"], "permission_denied")

    def test_oversized_cmdline_is_not_processed(self):
        with tempfile.TemporaryDirectory() as directory:
            proc_root = Path(directory)
            process_dir = proc_root / "132"
            process_dir.mkdir()
            (process_dir / "cmdline").write_bytes(b"python3\0/" + b"a" * 70000)

            result = inspect_process_application(132, "python3", proc_root)

        self.assertFalse(result["inspected"])
        self.assertEqual(result["reason"], "cmdline_too_large")

    def test_non_interpreter_process_does_not_read_proc(self):
        result = inspect_process_application(999, "sshd", "/does/not/exist")

        self.assertFalse(result["inspected"])
        self.assertEqual(result["reason"], "not_interpreter")

    def test_java_jar_and_shell_script_are_identified(self):
        with tempfile.TemporaryDirectory() as directory:
            proc_root = Path(directory)
            _write_cmdline(proc_root, 126, ["java", "-Xmx1g", "-jar", "/opt/app.jar"])
            _write_cmdline(proc_root, 127, ["bash", "/opt/start-service.sh", "secret"])

            java_result = inspect_process_application(126, "java", proc_root)
            shell_result = inspect_process_application(127, "bash", proc_root)

        self.assertEqual(java_result["application"], "/opt/app.jar")
        self.assertEqual(java_result["application_name"], "app")
        self.assertEqual(shell_result["application"], "/opt/start-service.sh")
        self.assertNotIn("secret", repr(shell_result))

    def test_options_with_values_are_not_mistaken_for_applications(self):
        with tempfile.TemporaryDirectory() as directory:
            proc_root = Path(directory)
            _write_cmdline(
                proc_root,
                129,
                ["node", "--require", "instrumentation", "/srv/server.js"],
            )
            _write_cmdline(
                proc_root,
                130,
                ["java", "-cp", "/opt/classes", "com.example.Server"],
            )

            node_result = inspect_process_application(129, "node", proc_root)
            java_result = inspect_process_application(130, "java", proc_root)

        self.assertEqual(node_result["application"], "/srv/server.js")
        self.assertEqual(java_result["application"], "com.example.Server")

    def test_pid_reuse_does_not_attribute_a_different_process(self):
        with tempfile.TemporaryDirectory() as directory:
            proc_root = Path(directory)
            _write_cmdline(proc_root, 131, ["sshd", "-D"])

            result = inspect_process_application(131, "python3", proc_root)

        self.assertFalse(result["inspected"])
        self.assertIsNone(result["application"])
        self.assertEqual(result["reason"], "process_changed")

    def test_supported_interpreter_families_identify_scripts(self):
        cases = [
            ("python3.13", ["python3.13", "/srv/app.py"], "/srv/app.py"),
            ("sh", ["sh", "/srv/app.sh"], "/srv/app.sh"),
            ("nodejs", ["nodejs", "/srv/app.js"], "/srv/app.js"),
            ("ruby", ["ruby", "/srv/app.rb"], "/srv/app.rb"),
            ("perl", ["perl", "/srv/app.pl"], "/srv/app.pl"),
        ]

        with tempfile.TemporaryDirectory() as directory:
            proc_root = Path(directory)

            for pid, (process, arguments, expected) in enumerate(cases, start=200):
                _write_cmdline(proc_root, pid, arguments)
                with self.subTest(process=process):
                    result = inspect_process_application(pid, process, proc_root)
                    self.assertEqual(result["application"], expected)

    def test_wsdd_enrichment_preserves_process_and_improves_finding(self):
        service = {
            "protocol": "udp",
            "state": "UNCONN",
            "address": "0.0.0.0",
            "port": "3702",
            "exposure": "all_interfaces",
            "process": "python3",
            "pid": 128,
        }

        with tempfile.TemporaryDirectory() as directory:
            proc_root = Path(directory)
            _write_cmdline(proc_root, 128, ["python3", "/usr/bin/wsdd"])
            enriched = enrich_process_intelligence([service], proc_root)

        findings = assess_network_exposure(enriched)

        self.assertEqual(enriched[0]["process"], "python3")
        self.assertEqual(enriched[0]["pid"], 128)
        self.assertEqual(enriched[0]["application"], "/usr/bin/wsdd")
        self.assertEqual(findings[0]["title"], "WSDD service listening on all interfaces")
        self.assertIn("WSDD", findings[0]["description"])
        self.assertNotIn("General-purpose runtime", findings[0]["description"])
        self.assertIn("Application: /usr/bin/wsdd", findings[0]["evidence"])
        self.assertIn("Service/Application: WSDD", findings[0]["evidence"])


if __name__ == "__main__":
    unittest.main()
