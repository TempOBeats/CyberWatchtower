import copy
import inspect
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from cyberwatchtower.history import compare_reports
from cyberwatchtower.memory import open_memory_database
from cyberwatchtower.memory.history_models import ScoreTrendQuery
from cyberwatchtower.memory.ingestion import ingest_report
from cyberwatchtower.memory.ingestion_models import IngestionStatus, ReportIngestionRequest
from cyberwatchtower.memory.queries import score_trends_by_version
from cyberwatchtower.models import AssessmentState, Finding, FindingKind, Severity
from cyberwatchtower.platform import FirewallEnablement, FirewallInboundAction
from cyberwatchtower.platform import FirewallProfile, FirewallProfileState
from cyberwatchtower.platform.linux import LinuxPlatformAdapter
from cyberwatchtower.platform.windows import (
    FakeWindowsApi,
    RawFirewallProfile,
    RawMachineIdentity,
    RawProcessInfo,
    RawServiceInfo,
    RawTcpEndpoint,
    RawWindowsSystemInfo,
    WindowsAddressFamily,
    WindowsApiFixture,
    WindowsApiResult,
    WindowsPlatformAdapter,
    WindowsServiceState,
    WindowsTcpState,
)
from cyberwatchtower.reporting import finding_to_dict, save_json_report
from cyberwatchtower.scanner import run_scan
from cyberwatchtower.scoring import calculate_security_score
from cyberwatchtower.scoring_contracts import ScoringVersion
from cyberwatchtower.scoring_projection import project_scoring_findings


HEADER = "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process"
WILDCARD = (
    'tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* '
    'users:(("python3",pid=42,fd=3))'
)
SYSTEM = {
    "system_id": "cwt-linux-scoring-v2",
    "hostname": "fixture",
    "username": "user",
    "operating_system": "Linux",
    "os_version": "1",
    "architecture": "x86_64",
    "processor": "cpu",
}


def _ok(value):
    return WindowsApiResult(value=value)


def windows_style_fixture() -> WindowsApiFixture:
    endpoints = []
    processes = []
    services = []
    for service_number in range(10):
        pid = 1000 + service_number
        processes.append((pid, _ok(RawProcessInfo(
            pid, f"fixture-{service_number}.exe",
            rf"C:\private\canary-{service_number}\fixture.exe",
        ))))
        services.append(RawServiceInfo(
            f"FixtureSvc{service_number}", f"Fixture Service {service_number}",
            pid, WindowsServiceState.RUNNING,
        ))
        for port_offset in range(2):
            port = 20000 + service_number * 10 + port_offset
            endpoints.extend((
                RawTcpEndpoint(
                    WindowsAddressFamily.IPV4, "0.0.0.0", port, pid,
                    WindowsTcpState.LISTEN,
                ),
                RawTcpEndpoint(
                    WindowsAddressFamily.IPV6, "::", port, pid,
                    WindowsTcpState.LISTEN,
                ),
            ))
    profiles = tuple(RawFirewallProfile(
        profile,
        (FirewallProfileState.ACTIVE if profile == FirewallProfile.PUBLIC
         else FirewallProfileState.INACTIVE),
        FirewallEnablement.ENABLED,
        FirewallInboundAction.BLOCK,
        False,
    ) for profile in (
        FirewallProfile.DOMAIN, FirewallProfile.PRIVATE, FirewallProfile.PUBLIC,
    ))
    return WindowsApiFixture(
        system_info=_ok(RawWindowsSystemInfo(
            "WIN-SCORING-FIXTURE", "Windows", "11", "26100", "AMD64", "analyst",
        )),
        machine_identity=_ok(RawMachineIdentity("scoring-v2-fixture-identity")),
        tcp_endpoints=_ok(tuple(endpoints)),
        udp_endpoints=_ok(()),
        processes=tuple(processes),
        services=_ok(tuple(services)),
        firewall_profiles=_ok(profiles),
    )


def linux_adapter(*, output=HEADER, iptables=False, policy=None):
    firewall = (
        {"detected_tools": ["iptables"],
         "tool_paths": {"iptables": "/usr/sbin/iptables"}}
        if iptables else
        {"detected_tools": ["nftables"],
         "tool_paths": {"nftables": "/usr/sbin/nft", "iptables": None}}
    )
    return LinuxPlatformAdapter(
        system_collector=lambda: dict(SYSTEM),
        firewall_collector=lambda: firewall,
        network_collector=lambda: {"accessible": True, "raw_output": output},
        firewall_policy_collector=lambda: policy or {},
        process_enricher=lambda services: services,
    )


class ProductionScannerV2Tests(unittest.TestCase):
    def test_production_routes_only_to_v2_while_v1_remains_callable(self):
        import cyberwatchtower.scanner as scanner

        source = inspect.getsource(scanner)
        self.assertNotIn("calculate_security_score(findings)", source)
        self.assertIn("calculate_security_score_v2(scoring_findings)", source)
        with patch(
            "cyberwatchtower.scoring.calculate_security_score",
            side_effect=AssertionError("v1 production scorer called"),
        ) as legacy:
            result = run_scan(linux_adapter())
        legacy.assert_not_called()
        self.assertEqual(result["score"]["scoring_version"], ScoringVersion.V2.value)
        self.assertEqual(calculate_security_score([])["score"], 100)

    def test_windows_style_fixture_is_82_moderate_with_partial_assurance(self):
        result = run_scan(WindowsPlatformAdapter(FakeWindowsApi(
            windows_style_fixture()
        )))
        network = [item for item in result["findings"] if item.source == "network"]
        confirmed_network = [
            item for item in network
            if item.assessment_state == AssessmentState.CONFIRMED
        ]
        self.assertEqual(len(network), 40)
        self.assertTrue(all(item.severity == Severity.MEDIUM for item in network))
        self.assertEqual(confirmed_network, [])
        self.assertEqual(
            (result["score"]["score"], result["score"]["risk_level"]),
            (82, "MODERATE"),
        )
        self.assertEqual(result["assessment_assurance"]["level"], "PARTIAL")
        self.assertEqual(result["coverage"]["network_reachability"], "INCOMPLETE")
        network_breakdown = result["score"]["breakdown"]["categories"][0]
        self.assertEqual(
            (network_breakdown["raw_penalty"],
             network_breakdown["applied_penalty"],
             network_breakdown["saturated"]),
            (60, 18, True),
        )
        self.assertEqual(
            len(result["score"]["breakdown"]["contributors"]), 10
        )

    def test_report_history_and_memory_use_explicit_v2(self):
        result = run_scan(WindowsPlatformAdapter(FakeWindowsApi(
            windows_style_fixture()
        )))
        with tempfile.TemporaryDirectory() as directory:
            v2_path = save_json_report(result, Path(directory, "reports"))
            current = json.loads(v2_path.read_text(encoding="utf-8"))
            previous = copy.deepcopy(current)
            previous["generated_at"] = "2026-08-19T12:00:00+00:00"
            previous["security_score"] = {
                "scoring_version": "1",
                "score": 0,
                "risk_level": "CRITICAL",
                "counts": dict(current["security_score"]["counts"]),
            }
            previous_path = Path(directory, "previous.json")
            previous_path.write_text(json.dumps(previous), encoding="utf-8")
            comparison = compare_reports(previous, current)
            same_version = copy.deepcopy(current)
            same_version["security_score"]["score"] = 84
            v2_comparison = compare_reports(current, same_version)
            with open_memory_database(Path(directory, "memory.db")) as database:
                first = ingest_report(database, ReportIngestionRequest(previous_path))
                second = ingest_report(database, ReportIngestionRequest(v2_path))
                versions = [row[0] for row in database.connection.execute(
                    "SELECT scoring_version FROM score_history ORDER BY observed_at"
                )]
                series = score_trends_by_version(database, ScoreTrendQuery(
                    current["system"]["system_id"],
                    datetime(2026, 8, 1, tzinfo=timezone.utc),
                    datetime.now(timezone.utc),
                ))
        self.assertEqual(current["schema_version"], "1.6")
        self.assertEqual(current["security_score"]["scoring_version"], "2")
        self.assertIn("breakdown", current["security_score"])
        self.assertEqual((comparison["trend"], comparison["change"]),
                         ("SCORING_VERSION_CHANGED", None))
        self.assertEqual(comparison["new_findings"], [])
        self.assertEqual(comparison["resolved_findings"], [])
        self.assertEqual((v2_comparison["trend"], v2_comparison["change"]),
                         ("IMPROVED", 2))
        self.assertEqual((first.status, second.status),
                         (IngestionStatus.INGESTED, IngestionStatus.INGESTED))
        self.assertEqual(versions, ["1", "2"])
        self.assertEqual([item.scoring_version for item in series], ["1", "2"])

    def test_linux_v2_fixtures_freeze_score_without_changing_findings(self):
        listener = run_scan(linux_adapter(output=f"{HEADER}\n{WILDCARD}"))
        permissive = run_scan(linux_adapter(
            iptables=True,
            policy={"available": True, "accessible": True,
                    "policies": {"INPUT": "ACCEPT"}},
        ))
        incomplete = run_scan(linux_adapter(
            iptables=True,
            policy={"available": True, "accessible": False,
                    "message": "Firewall policy is unavailable."},
        ))
        self.assertEqual(
            (listener["score"]["score"], listener["score"]["risk_level"],
             listener["assessment_assurance"]["level"]),
            (96, "LOW", "PARTIAL"),
        )
        self.assertEqual(
            (permissive["score"]["score"], permissive["score"]["risk_level"]),
            (89, "MODERATE"),
        )
        self.assertEqual(incomplete["score"]["score"], 100)
        firewall = permissive["findings"][-1]
        self.assertEqual(
            (firewall.kind, firewall.assessment_state, firewall.severity),
            (FindingKind.RISK, AssessmentState.CONFIRMED, Severity.MEDIUM),
        )

    def test_projection_is_immutable_order_independent_and_uses_structured_network_data(self):
        result = run_scan(linux_adapter(output=f"{HEADER}\n{WILDCARD}"))
        findings = result["findings"]
        before = copy.deepcopy(findings)
        network = next(item for item in findings if item.source == "network")
        from cyberwatchtower.scoring_projection import (
            canonical_finding_id,
            network_scoring_identity,
        )
        identity = network_scoring_identity({
            "protocol": "tcp",
            "port": 8080,
            "bind_exposure": "all_interfaces",
            "reachability_state": "POTENTIALLY_REACHABLE",
            "application_identity": None,
            "process_basename": "python3",
        })
        identities = {canonical_finding_id(network): identity}
        forward = project_scoring_findings(findings, identities)
        reverse = project_scoring_findings(reversed(findings), identities)
        self.assertEqual(forward, reverse)
        self.assertEqual(findings, before)
        self.assertEqual(
            next(item for item in forward if item.source == "network").network_identity,
            identity,
        )

    def test_assurance_and_zero_weight_findings_do_not_change_score(self):
        complete = run_scan(linux_adapter())
        malformed = run_scan(linux_adapter(output=f"{HEADER}\nnot a socket row"))
        self.assertEqual(complete["score"]["score"], 100)
        self.assertEqual(malformed["score"]["score"], 100)
        self.assertNotEqual(
            complete["assessment_assurance"], malformed["assessment_assurance"]
        )
        self.assertTrue(any(
            item.kind == FindingKind.COVERAGE_GAP
            for item in malformed["findings"]
        ))


if __name__ == "__main__":
    unittest.main()
