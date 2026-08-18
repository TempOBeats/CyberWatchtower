import json
import platform
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cyberwatchtower.platform import (
    FirewallEnablement,
    FirewallInboundAction,
    FirewallProfile,
    FirewallProfileState,
)
from cyberwatchtower.platform.windows import (
    FakeWindowsApi,
    RawFirewallProfile,
    RawMachineIdentity,
    RawProcessInfo,
    RawServiceInfo,
    RawTcpEndpoint,
    RawUdpEndpoint,
    RawWindowsSystemInfo,
    WindowsAddressFamily,
    WindowsApiFixture,
    WindowsApiResult,
    WindowsFailureCode,
    WindowsPlatformAdapter,
    WindowsServiceState,
    WindowsTcpState,
)
from cyberwatchtower.reporting import finding_to_dict, save_json_report
from cyberwatchtower.scanner import run_scan
from cyberwatchtower.history import compare_reports
from cyberwatchtower.advisor.context import build_advisor_context
from cyberwatchtower.advisor.service import build_provider_request, generate_advisory
from cyberwatchtower.core.orchestrator import IntelligenceOrchestrator
from cyberwatchtower.memory import open_memory_database
from cyberwatchtower.memory.ingestion import ingest_report
from cyberwatchtower.memory.ingestion_models import (
    IngestionStatus,
    ReportIngestionRequest,
)


def ok(value):
    return WindowsApiResult(value=value)


def profiles(*active, public_action=FirewallInboundAction.BLOCK,
             disabled=None):
    rows = []
    for profile in (FirewallProfile.DOMAIN, FirewallProfile.PRIVATE,
                    FirewallProfile.PUBLIC):
        rows.append(RawFirewallProfile(
            profile,
            (FirewallProfileState.ACTIVE if profile in active
             else FirewallProfileState.INACTIVE),
            (FirewallEnablement.DISABLED if profile == disabled
             else FirewallEnablement.ENABLED),
            (public_action if profile == FirewallProfile.PUBLIC
             else FirewallInboundAction.BLOCK),
            False,
        ))
    return tuple(rows)


def fixture(*, firewall=None, tcp_failure=None, identity=True,
            shared_service=False):
    services = [RawServiceInfo(
        "DemoSvc", "Demo Service", 100, WindowsServiceState.RUNNING
    )]
    if shared_service:
        services.append(RawServiceInfo(
            "OtherSvc", "Other Service", 100, WindowsServiceState.RUNNING
        ))
    return WindowsApiFixture(
        system_info=ok(RawWindowsSystemInfo(
            "WIN-FIXTURE", "Windows", "11", "26100", "AMD64", "analyst"
        )),
        machine_identity=(ok(RawMachineIdentity("phase5-machine-guid"))
                          if identity else WindowsApiResult(
                              failure=WindowsFailureCode.ACCESS_DENIED)),
        tcp_endpoints=WindowsApiResult((
            RawTcpEndpoint(WindowsAddressFamily.IPV4, "0.0.0.0", 8080, 100,
                           WindowsTcpState.LISTEN),
            RawTcpEndpoint(WindowsAddressFamily.IPV4, "127.0.0.1", 9000, 101,
                           WindowsTcpState.LISTEN),
        ), tcp_failure),
        udp_endpoints=ok((RawUdpEndpoint(
            WindowsAddressFamily.IPV4, "192.0.2.10", 5353, 102
        ),)),
        processes=((100, ok(RawProcessInfo(
            100, "python.exe", r"C:\\private\\canary-secret\\python.exe"
        ))),),
        services=ok(tuple(services)),
        firewall_profiles=(firewall or ok(profiles(FirewallProfile.PRIVATE))),
    )


class WindowsPlatformIntegrationTests(unittest.TestCase):
    def scan(self, **kwargs):
        return run_scan(WindowsPlatformAdapter(FakeWindowsApi(fixture(**kwargs))))

    def test_complete_fixture_has_frozen_authoritative_results(self):
        result = self.scan()
        findings = [finding_to_dict(item) for item in result["findings"]]
        self.assertEqual(result["assessment_domains"], [
            "firewall_technology", "firewall_inbound_policy",
            "network_socket_inspection",
        ])
        self.assertNotIn("iptables_input_policy", result["coverage"])
        self.assertEqual(set(result["coverage"].values()), {"COMPLETE"})
        self.assertEqual(result["assessment_assurance"]["level"], "COMPLETE")
        self.assertEqual(result["score"], {
            "score": 90, "risk_level": "LOW",
            "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 1,
                       "LOW": 0, "INFO": 2},
        })
        self.assertEqual(
            [(item["title"], item["severity"], item["kind"],
              item["assessment_state"], item["confidence"])
             for item in findings],
            [
                ("Alternate HTTP service listening on all interfaces", "MEDIUM",
                 "RISK", "CONFIRMED", 90),
                ("Firewall technology detected", "INFO", "OBSERVATION",
                 "INFORMATIONAL", 95),
                ("Windows Firewall Private profile blocks inbound traffic by default",
                 "INFO", "OBSERVATION", "INFORMATIONAL", 95),
            ],
        )
        self.assertEqual(findings[0]["finding_id"],
            "type=alternate http service listening on all interfaces|address=0.0.0.0|application=windows-service:demosvc|port=8080|process=python.exe|protocol=tcp")
        self.assertNotIn("pid", findings[0]["finding_id"].casefold())
        self.assertFalse(any(
            "9000" in evidence
            for item in findings
            for evidence in item.get("evidence", ())
        ))
        self.assertEqual(findings[2]["finding_id"],
            "source=firewall_inbound_policy|profile=private|condition=default_inbound_block")

    def test_permissive_or_disabled_active_profile_is_confirmed_medium_risk(self):
        cases = (
            (ok(profiles(FirewallProfile.PUBLIC,
                         public_action=FirewallInboundAction.ALLOW)),
             "allows inbound traffic by default", "default_inbound_allow"),
            (ok(profiles(FirewallProfile.PUBLIC,
                         disabled=FirewallProfile.PUBLIC)),
             "profile is disabled", "disabled"),
        )
        for firewall, title, identity in cases:
            with self.subTest(title=title):
                result = self.scan(firewall=firewall)
                finding = next(item for item in result["findings"]
                               if title in item.title)
                self.assertEqual(finding.severity.value, "MEDIUM")
                self.assertEqual(finding.kind.value, "RISK")
                self.assertEqual(finding.assessment_state.value, "CONFIRMED")
                self.assertIn(identity, finding.finding_id)

    def test_multiple_profiles_and_incomplete_domains_fail_conservatively(self):
        result = self.scan(firewall=ok(profiles(
            FirewallProfile.PRIVATE, FirewallProfile.PUBLIC,
            public_action=FirewallInboundAction.ALLOW,
        )))
        titles = [item.title for item in result["findings"]]
        self.assertTrue(any("Private profile blocks" in item for item in titles))
        self.assertTrue(any("Public profile allows" in item for item in titles))

        partial = self.scan(tcp_failure=WindowsFailureCode.PARTIAL_RESULT)
        self.assertEqual(partial["coverage"]["network_socket_inspection"],
                         "INCOMPLETE")
        self.assertEqual(partial["assessment_assurance"]["level"], "PARTIAL")
        self.assertTrue(any("Alternate HTTP" in item.title
                            for item in partial["findings"]))

        incomplete_profiles = profiles(FirewallProfile.PUBLIC)
        incomplete_profiles = tuple(
            RawFirewallProfile(
                item.profile, item.state, item.enablement,
                (FirewallInboundAction.UNKNOWN
                 if item.profile == FirewallProfile.PUBLIC
                 else item.default_inbound_action),
                item.block_all_inbound,
            )
            for item in incomplete_profiles
        )
        incomplete = self.scan(firewall=ok(incomplete_profiles))
        self.assertEqual(incomplete["coverage"]["firewall_inbound_policy"],
                         "INCOMPLETE")
        self.assertTrue(any(item.kind.value == "COVERAGE_GAP"
                            and item.source == "firewall_inbound_policy"
                            for item in incomplete["findings"]))

    def test_identity_failure_does_not_fabricate_stable_identity(self):
        result = self.scan(identity=False)
        self.assertNotIn("system_id", result["system"])
        self.assertEqual(result["system"]["hostname"], "WIN-FIXTURE")

    def test_shared_service_is_not_selected_and_raw_path_never_serializes(self):
        result = self.scan(shared_service=True)
        finding = next(item for item in result["findings"]
                       if "Alternate HTTP" in item.title)
        self.assertFalse(any("windows-service:" in item
                             for item in finding.evidence))
        with tempfile.TemporaryDirectory() as directory:
            report_path = save_json_report(result, directory)
            report = json.loads(Path(report_path).read_text(encoding="utf-8"))
            with open_memory_database(Path(directory, "memory.db")) as database:
                ingested = ingest_report(database, ReportIngestionRequest(report_path))
                durable = "\n".join(database.connection.iterdump())
        encoded = json.dumps(report)
        context = build_advisor_context(report, None, None)
        provider = build_provider_request(context, generate_advisory(context))
        core = IntelligenceOrchestrator().handle(
            "Give me my security briefing", reports=(report,)
        )
        self.assertEqual(ingested.status, IngestionStatus.INGESTED)
        self.assertNotIn("phase5-machine-guid", encoded)
        self.assertNotIn("canary-secret", encoded)
        for boundary in (durable, repr(context), repr(provider), repr(core)):
            self.assertNotIn("phase5-machine-guid", boundary)
            self.assertNotIn("canary-secret", boundary)
        self.assertEqual(report["schema_version"], "1.2")
        self.assertEqual(report["assessment_domains"], result["assessment_domains"])

    def test_report_history_and_memory_use_existing_schema_and_coverage_rules(self):
        result = self.scan(firewall=ok(profiles(
            FirewallProfile.PUBLIC,
            public_action=FirewallInboundAction.ALLOW,
        )))
        with tempfile.TemporaryDirectory() as directory:
            first_path = save_json_report(result, directory)
            first = json.loads(Path(first_path).read_text(encoding="utf-8"))
            with open_memory_database(Path(directory, "memory.db")) as database:
                ingested = ingest_report(database, ReportIngestionRequest(first_path))
                report_domains = database.connection.execute(
                    "SELECT coverage_json FROM reports"
                ).fetchone()[0]
            current = dict(first)
            current["findings"] = [
                item for item in first["findings"]
                if item["source"] != "firewall_inbound_policy"
            ]
            comparison = compare_reports(first, current)
            incomplete = dict(current)
            incomplete["coverage"] = dict(current["coverage"])
            incomplete["coverage"]["firewall_inbound_policy"] = "INCOMPLETE"
            uncertain = compare_reports(first, incomplete)
        self.assertEqual(ingested.status, IngestionStatus.INGESTED)
        self.assertIn("firewall_inbound_policy", report_domains)
        self.assertTrue(any(item["source"] == "firewall_inbound_policy"
                            for item in comparison["resolved_findings"]))
        self.assertFalse(any(item["source"] == "firewall_inbound_policy"
                             for item in uncertain["resolved_findings"]))
        self.assertTrue(any(item["source"] == "firewall_inbound_policy"
                            for item in uncertain["uncertain_findings"]))

    @unittest.skipUnless(platform.system() == "Windows",
                         "native Windows adapter validation requires Windows")
    def test_native_windows_adapter_read_only_smoke(self):
        result = run_scan(WindowsPlatformAdapter())
        self.assertEqual(result["system"].get("operating_system"), "Windows")


if __name__ == "__main__":
    unittest.main()
