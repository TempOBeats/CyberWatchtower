import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import cyberwatchtower.scanner as scanner_module
from cyberwatchtower.firewall import assess_iptables
from cyberwatchtower.network import (
    SocketCompletenessCode,
    inspect_listening_services,
    parse_listening_services_checked,
)
from cyberwatchtower.scanner import run_scan
from cyberwatchtower.report_contracts import (
    CoverageState,
    ScanDomain,
    assessment_assurance_summary,
)
from cyberwatchtower.models import AssessmentState, Finding, FindingKind, Severity
from cyberwatchtower.scoring import calculate_security_score
from cyberwatchtower.reporting import save_json_report
from cyberwatchtower.advisor.context import build_advisor_context
from cyberwatchtower.advisor.service import build_provider_request, generate_advisory
from cyberwatchtower.core.orchestrator import IntelligenceOrchestrator
from cyberwatchtower.memory import open_memory_database
from cyberwatchtower.memory.ingestion import ingest_report
from cyberwatchtower.memory.ingestion_models import ReportIngestionRequest
from cyberwatchtower.platform.linux import LinuxPlatformAdapter


def _run_linux_fixture_scan():
    """Run patched Linux fixtures through an explicit hermetic adapter."""

    return run_scan(LinuxPlatformAdapter(
        system_collector=scanner_module.collect_system_information,
        firewall_collector=scanner_module.check_firewall,
        network_collector=scanner_module.inspect_listening_services,
        firewall_policy_collector=scanner_module.inspect_iptables,
        process_enricher=lambda services: services,
    ))


class SocketInspectionTests(unittest.TestCase):
    def test_linux_fixture_scan_is_host_independent_and_never_collects_windows(self):
        header = (
            "Netid State Recv-Q Send-Q Local Address:Port "
            "Peer Address:Port Process"
        )
        with (
            patch("cyberwatchtower.platform.selection.platform.system",
                  return_value="Windows"),
            patch("cyberwatchtower.platform.windows.NativeWindowsApi",
                  side_effect=AssertionError("native collection must not run")),
            patch("cyberwatchtower.scanner.collect_system_information",
                  return_value={}),
            patch("cyberwatchtower.scanner.check_firewall",
                  return_value={"detected_tools": ["nftables"]}),
            patch("cyberwatchtower.scanner.inspect_listening_services",
                  return_value={"accessible": True, "raw_output": header}),
        ):
            result = _run_linux_fixture_scan()

        self.assertIn("iptables_input_policy", result["assessment_domains"])
        self.assertNotIn("firewall_inbound_policy", result["assessment_domains"])

    def test_success_exit_with_netlink_error_is_inaccessible(self):
        command_result = {
            "success": True,
            "stdout": (
                "Netid State Recv-Q Send-Q Local Address:Port "
                "Peer Address:Port Process"
            ),
            "stderr_present": True,
            "returncode": 0,
            "failure_code": "SOCKET_COMMAND_FAILED",
        }

        with (
            patch("cyberwatchtower.network.shutil.which", return_value="/usr/bin/ss"),
            patch("cyberwatchtower.network._run_command", return_value=command_result),
        ):
            result = inspect_listening_services()

        self.assertFalse(result["accessible"])
        self.assertEqual(result["failure_code"], "SOCKET_COMMAND_FAILED")
        self.assertNotIn("error", result)

    def test_incomplete_inspection_prevents_perfect_score(self):
        network_result = {
            "available": True,
            "accessible": False,
            "message": "Socket inspection was incomplete.",
            "failure_code": "SOCKET_COMMAND_FAILED",
            "services": [],
        }

        with (
            patch(
                "cyberwatchtower.scanner.collect_system_information",
                return_value={"hostname": "privacy-host", "system_id": "cwt-privacy"},
            ),
            patch(
                "cyberwatchtower.scanner.check_firewall",
                return_value={"detected_tools": ["nftables"]},
            ),
            patch(
                "cyberwatchtower.scanner.inspect_listening_services",
                return_value=network_result,
            ),
        ):
            result = _run_linux_fixture_scan()

        self.assertLess(result["score"]["score"], 100)
        self.assertEqual(
            result["coverage"][ScanDomain.NETWORK_SOCKET_INSPECTION.value],
            CoverageState.INCOMPLETE.value,
        )
        self.assertTrue(
            any(
                finding.title == "Listening-service inspection incomplete"
                for finding in result["findings"]
            )
        )


class FirewallAssessmentTests(unittest.TestCase):
    def test_missing_input_policy_is_inconclusive(self):
        result = assess_iptables(
            {
                "available": True,
                "accessible": True,
                "policies": {},
            }
        )

        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["severity"], "INFO")

    def test_complete_network_and_iptables_checks_have_explicit_coverage(self):
        with (
            patch("cyberwatchtower.scanner.collect_system_information", return_value={}),
            patch(
                "cyberwatchtower.scanner.check_firewall",
                return_value={"detected_tools": ["iptables"]},
            ),
            patch(
                "cyberwatchtower.scanner.inspect_listening_services",
                return_value={
                    "accessible": True,
                    "raw_output": (
                        "Netid State Recv-Q Send-Q Local Address:Port "
                        "Peer Address:Port Process"
                    ),
                },
            ),
            patch("cyberwatchtower.scanner.enrich_process_intelligence", return_value=[]),
            patch("cyberwatchtower.scanner.inspect_iptables", return_value={
                "available": True,
                "accessible": True,
                "policies": {"INPUT": "DROP"},
            }),
        ):
            result = _run_linux_fixture_scan()

        self.assertEqual(
            result["coverage"][ScanDomain.NETWORK_SOCKET_INSPECTION.value],
            CoverageState.COMPLETE.value,
        )
        self.assertEqual(
            result["coverage"][ScanDomain.IPTABLES_INPUT_POLICY.value],
            CoverageState.COMPLETE.value,
        )

    def test_incomplete_iptables_is_reported_as_partial_assurance(self):
        header = (
            "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process"
        )
        with (
            patch("cyberwatchtower.scanner.collect_system_information", return_value={}),
            patch("cyberwatchtower.scanner.check_firewall",
                  return_value={"detected_tools": ["iptables"]}),
            patch("cyberwatchtower.scanner.inspect_listening_services",
                  return_value={"accessible": True, "raw_output": header}),
            patch("cyberwatchtower.scanner.inspect_iptables",
                  return_value={"accessible": False, "message": "not available"}),
        ):
            result = _run_linux_fixture_scan()
        self.assertEqual(result["score"]["score"], 100)
        self.assertEqual(result["assessment_assurance"]["level"], "PARTIAL")
        self.assertIn(
            "iptables INPUT policy was not completely assessed",
            result["assessment_assurance"]["limitations"],
        )

    def test_assurance_derivation_cannot_mutate_finding_or_score_authority(self):
        finding = Finding(
            title="Potential condition", description="Deterministic input.",
            severity=Severity.MEDIUM, recommendation="Review it.",
            kind=FindingKind.RISK, assessment_state=AssessmentState.POTENTIAL,
        )
        score = calculate_security_score([finding])
        authority_before = (
            score.copy(), finding.severity, finding.kind, finding.assessment_state,
        )
        assurance = assessment_assurance_summary({
            ScanDomain.FIREWALL_TECHNOLOGY.value: CoverageState.COMPLETE.value,
            ScanDomain.IPTABLES_INPUT_POLICY.value: CoverageState.UNKNOWN.value,
            ScanDomain.NETWORK_SOCKET_INSPECTION.value: CoverageState.COMPLETE.value,
        })
        self.assertEqual(assurance["level"], "PARTIAL")
        self.assertEqual(
            (score, finding.severity, finding.kind, finding.assessment_state),
            authority_before,
        )


class SocketOutputValidationTests(unittest.TestCase):
    SPACED_HEADER = (
        "Netid State Recv-Q Send-Q Local Address:Port "
        "Peer Address:Port Process"
    )
    COMPACT_HEADER = (
        "Netid State  Recv-Q Send-Q Local Address:Port "
        "Peer Address:PortProcess"
    )

    def test_valid_header_only_output_is_complete_empty_listener_set(self):
        for header in (self.SPACED_HEADER, self.COMPACT_HEADER):
            with self.subTest(header=header):
                result = parse_listening_services_checked(header)
                self.assertTrue(result.complete)
                self.assertEqual(result.services, ())

    def test_scoped_ipv6_and_missing_process_attribution_are_valid(self):
        row = "udp UNCONN 0 0 [fe80::1234]%wlan0:546 [::]:*"
        result = parse_listening_services_checked(f"{self.COMPACT_HEADER}\n{row}")

        self.assertTrue(result.complete)
        self.assertEqual(len(result.services), 1)
        self.assertEqual(result.services[0], {
            "protocol": "udp",
            "state": "UNCONN",
            "address": "[fe80::1234]%wlan0",
            "port": "546",
            "exposure": "interface",
            "process": "unknown",
            "pid": None,
        })

    def test_sanitized_real_world_rows_parse_completely_and_deterministically(self):
        raw = "\n".join((
            self.COMPACT_HEADER,
            'udp UNCONN 0 0 192.0.2.10:5353 0.0.0.0:* '
            'users:(("fixture-daemon",pid=42,fd=7))',
            'udp UNCONN 0 0 192.0.2.11:33441 0.0.0.0:* '
            'users:(("fixture-daemon",pid=42,fd=8))',
            'udp UNCONN 0 0 [2001:db8::10]%fixture0:42319 [::]:* '
            'users:(("fixture-daemon",pid=42,fd=9))',
            'udp UNCONN 0 0 [2001:db8::11]%fixture0:38372 [::]:* '
            'users:(("fixture-daemon",pid=42,fd=10))',
            'udp UNCONN 0 0 [2001:db8::12]%fixture0:42976 [::]:* '
            'users:(("fixture-daemon",pid=42,fd=11))',
            "udp UNCONN 0 0 [fe80::1234]%fixture0:546 [::]:*",
        ))

        first = parse_listening_services_checked(raw)
        second = parse_listening_services_checked(raw)

        self.assertTrue(first.complete)
        self.assertEqual(first, second)
        self.assertEqual(len(first.services), 6)
        self.assertEqual(first.services[0]["process"], "fixture-daemon")
        self.assertEqual(first.services[0]["pid"], 42)
        self.assertEqual(first.services[-1]["process"], "unknown")
        self.assertIsNone(first.services[-1]["pid"])

        collected = LinuxPlatformAdapter(
            network_collector=lambda: {"accessible": True, "raw_output": raw},
            process_enricher=lambda services: services,
        ).collect_network()
        self.assertEqual(collected.coverage, CoverageState.COMPLETE)
        self.assertEqual(len(collected.observations), 6)

    def test_malformed_truncated_and_partially_parseable_output_fail_closed(self):
        header = "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process"
        cases = (
            "",
            "unexpected header\ntcp LISTEN 0 1 0.0.0.0:22 0.0.0.0:*",
            f"{header}\ntcp LISTEN 0",
            f"{header}\ntcp LISTEN 0 1 0.0.0.0:22 0.0.0.0:*\ngarbage row",
            f"{header}\nraw unexpected diagnostic",
            f"{self.COMPACT_HEADER}\nraw unexpected diagnostic",
        )
        for raw in cases:
            with self.subTest(raw=raw):
                result = parse_listening_services_checked(raw)
                self.assertFalse(result.complete)
                self.assertEqual(result.code, SocketCompletenessCode.OUTPUT_MALFORMED)

    def test_raw_stderr_secret_canary_never_enters_findings(self):
        canary = "token=SECRET-CANARY"
        command_result = Mock(returncode=1, stdout="", stderr=canary)
        with (
            patch("cyberwatchtower.network.shutil.which", return_value="/usr/bin/ss"),
            patch("cyberwatchtower.network.subprocess.run", return_value=command_result),
            patch("cyberwatchtower.scanner.collect_system_information", return_value={}),
            patch("cyberwatchtower.scanner.check_firewall",
                  return_value={"detected_tools": ["nftables"]}),
        ):
            inspected = inspect_listening_services()
            self.assertNotIn(canary, repr(inspected))
            with patch("cyberwatchtower.scanner.inspect_listening_services",
                       return_value=inspected):
                scan = _run_linux_fixture_scan()
        self.assertNotIn(canary, repr(scan))
        self.assertIn("SOCKET_COMMAND_FAILED", repr(scan["findings"]))
        with tempfile.TemporaryDirectory() as directory:
            report_path = save_json_report(scan, directory)
            report = json.loads(Path(report_path).read_text(encoding="utf-8"))
            with open_memory_database(Path(directory, "memory", "memory.db")) as database:
                ingest_report(database, ReportIngestionRequest(Path(report_path)))
                durable_sql = "\n".join(database.connection.iterdump())
        context = build_advisor_context(report, None, None)
        provider_request = build_provider_request(context, generate_advisory(context))
        intelligence = IntelligenceOrchestrator().handle(
            "Give me my security briefing", reports=(report,)
        )
        with (
            patch("cyberwatchtower.cli.run_scan", return_value=scan),
            patch("cyberwatchtower.cli.save_json_report", return_value=Path(report_path)),
            patch("cyberwatchtower.cli.load_reports", return_value=[report]),
            patch("cyberwatchtower.cli._ingest_saved_report", return_value=None),
            patch("cyberwatchtower.cli._display_advisor"),
            patch("builtins.print") as rendered,
        ):
            from cyberwatchtower.cli import main
            main([])
        cli_output = "\n".join(" ".join(map(str, call.args)) for call in rendered.call_args_list)
        self.assertNotIn(canary, repr(report))
        self.assertNotIn(canary, repr(context))
        self.assertNotIn(canary, repr(intelligence))
        self.assertNotIn(canary, durable_sql)
        self.assertNotIn(canary, cli_output)
        self.assertNotIn(canary, repr(provider_request))


if __name__ == "__main__":
    unittest.main()
