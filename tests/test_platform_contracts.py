import dataclasses
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cyberwatchtower.advisor.context import build_advisor_context
from cyberwatchtower.advisor.service import build_provider_request, generate_advisory
from cyberwatchtower.core.orchestrator import IntelligenceOrchestrator
from cyberwatchtower.memory import open_memory_database
from cyberwatchtower.memory.ingestion import ingest_report
from cyberwatchtower.memory.ingestion_models import ReportIngestionRequest
from cyberwatchtower.platform import (
    CollectionFailure,
    CollectionResult,
    FailureCategory,
    FailureCode,
    FirewallEnablement,
    FirewallInboundAction,
    FirewallInboundPostureObservation,
    ListenerObservation,
    ObservationDomain,
    FirewallProfile,
    FirewallProfileObservation,
    FirewallProfileState,
    UnsupportedPlatformError,
    select_platform_adapter,
)
from cyberwatchtower.platform.linux import LinuxPlatformAdapter
from cyberwatchtower.report_contracts import CoverageState
from cyberwatchtower.reporting import finding_to_dict, save_json_report
from cyberwatchtower.scanner import run_scan


HEADER = "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process"
EXPOSED = (
    'tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* '
    'users:(("python3",pid=42,fd=3))'
)
LOOPBACK = (
    'tcp LISTEN 0 128 127.0.0.1:8080 0.0.0.0:* '
    'users:(("python3",pid=42,fd=3))'
)
SYSTEM = {
    "system_id": "cwt-fixture",
    "hostname": "fixture",
    "username": "user",
    "operating_system": "Linux",
    "os_version": "1",
    "architecture": "x86_64",
    "processor": "cpu",
}
NFTABLES = {
    "detected_tools": ["nftables"],
    "tool_paths": {
        "ufw": None,
        "firewalld": None,
        "nftables": "/usr/sbin/nft",
        "iptables": None,
    },
}


def adapter(*, output=HEADER, firewall=NFTABLES, policy=None, enricher=None):
    return LinuxPlatformAdapter(
        system_collector=lambda: dict(SYSTEM),
        firewall_collector=lambda: firewall,
        network_collector=lambda: {"accessible": True, "raw_output": output},
        firewall_policy_collector=lambda: policy or {},
        process_enricher=enricher or (lambda services: services),
    )


def authoritative(result):
    return {
        "system": result["system"],
        "firewall": result["firewall"],
        "coverage": result["coverage"],
        "findings": [finding_to_dict(item) for item in result["findings"]],
        "score": result["score"],
        "assessment_assurance": result["assessment_assurance"],
    }


class ObservationContractTests(unittest.TestCase):
    def test_firewall_posture_is_closed_immutable_and_observation_only(self):
        profile = FirewallProfileObservation(
            FirewallProfile.DEFAULT,
            FirewallProfileState.ACTIVE,
            FirewallEnablement.ENABLED,
            FirewallInboundAction.BLOCK,
            block_all_inbound=False,
        )
        posture = FirewallInboundPostureObservation("iptables", (profile,))
        self.assertEqual(posture.technology_id, "iptables")
        self.assertFalse(hasattr(posture, "severity"))
        self.assertFalse(hasattr(posture, "score"))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            profile.block_all_inbound = True
        with self.assertRaises(ValueError):
            FirewallInboundPostureObservation("iptables", (profile, profile))

    def test_observations_are_immutable_closed_and_bounded(self):
        observation = ListenerObservation.from_mapping({
            "protocol": "tcp", "state": "LISTEN", "address": "127.0.0.1",
            "port": "8080", "exposure": "loopback", "process": "python3",
            "pid": 42,
        })
        with self.assertRaises(dataclasses.FrozenInstanceError):
            observation.port = 22
        with self.assertRaises(ValueError):
            ListenerObservation.from_mapping({
                "protocol": "icmp", "state": "LISTEN", "address": "127.0.0.1",
                "port": 80, "exposure": "loopback",
            })
        with self.assertRaises(ValueError):
            ListenerObservation.from_mapping({
                "protocol": "tcp", "state": "LISTEN", "address": "127.0.0.1",
                "port": 70000, "exposure": "loopback",
            })
        with self.assertRaises(ValueError):
            ListenerObservation.from_mapping({
                "protocol": "tcp", "state": "LISTEN", "address": "127.0.0.1",
                "port": 80, "exposure": "loopback", "arbitrary": "metadata",
            })

    def test_coverage_and_failure_contract_fails_closed(self):
        with self.assertRaises(ValueError):
            CollectionResult(
                ObservationDomain.NETWORK_LISTENERS,
                CoverageState.COMPLETE,
                failure=CollectionFailure(
                    FailureCategory.INTERNAL,
                    FailureCode.COLLECTOR_INTERNAL_FAILURE,
                    "Collection failed.",
                ),
            )
        with self.assertRaises(ValueError):
            CollectionResult(
                ObservationDomain.NETWORK_LISTENERS,
                CoverageState.UNKNOWN,
            )
        unknown = CollectionResult(
            ObservationDomain.NETWORK_LISTENERS,
            CoverageState.UNKNOWN,
            failure=CollectionFailure(
                FailureCategory.UNSUPPORTED,
                FailureCode.UNSUPPORTED_PLATFORM,
                "This observation domain is unsupported.",
            ),
        )
        self.assertEqual(unknown.coverage, CoverageState.UNKNOWN)
        with self.assertRaises(TypeError):
            CollectionResult(  # type: ignore[arg-type]
                ObservationDomain.NETWORK_LISTENERS, "COMPLETE", ()
            )

    def test_failure_contract_rejects_secrets_controls_and_unbounded_text(self):
        for message in ("token=SECRET-CANARY", "raw stderr secret", "bad\0value", "x" * 513):
            with self.subTest(message=message), self.assertRaises(ValueError):
                CollectionFailure(
                    FailureCategory.INTERNAL,
                    FailureCode.COLLECTOR_INTERNAL_FAILURE,
                    message,
                )

    def test_platform_selection_is_explicit_and_never_falls_back(self):
        linux = adapter()
        self.assertIs(
            select_platform_adapter(system_name="Linux", linux_adapter=linux), linux
        )
        self.assertIsInstance(
            select_platform_adapter(system_name="Linux"), LinuxPlatformAdapter
        )
        for unsupported in ("Windows", "Darwin", "Plan9"):
            with self.subTest(unsupported=unsupported), self.assertRaises(
                UnsupportedPlatformError
            ):
                select_platform_adapter(
                    system_name=unsupported, linux_adapter=linux
                )

    def test_system_observation_preserves_empty_legacy_platform_fields(self):
        linux = LinuxPlatformAdapter(
            system_collector=lambda: {**SYSTEM, "processor": ""},
            firewall_collector=lambda: NFTABLES,
            network_collector=lambda: {"accessible": True, "raw_output": HEADER},
        )
        result = run_scan(linux)
        self.assertIn("processor", result["system"])
        self.assertEqual(result["system"]["processor"], "")

    def test_scanner_does_not_collect_or_fall_back_on_unsupported_platform(self):
        with (
            patch("cyberwatchtower.platform.selection.platform.system",
                  return_value="Windows"),
            patch("cyberwatchtower.scanner.collect_system_information") as collect,
            self.assertRaises(UnsupportedPlatformError),
        ):
            run_scan()
        collect.assert_not_called()


class LinuxAdapterContractTests(unittest.TestCase):
    def test_valid_empty_and_loopback_fixtures_preserve_no_network_findings(self):
        for output in (HEADER, f"{HEADER}\n{LOOPBACK}"):
            with self.subTest(output=output):
                result = authoritative(run_scan(adapter(output=output)))
                self.assertEqual(
                    result["coverage"]["network_socket_inspection"], "COMPLETE"
                )
                self.assertEqual(
                    [item["finding_id"] for item in result["findings"]],
                    ["type=firewall technology detected"],
                )
                self.assertEqual(result["score"]["score"], 100)
                self.assertEqual(
                    result["coverage"]["iptables_input_policy"], "UNKNOWN"
                )

    def test_exposed_process_application_fixture_has_exact_authoritative_parity(self):
        def enrich(services):
            return [{
                **services[0],
                "application": "/usr/bin/wsdd",
                "application_name": "WSDD",
                "known_application": True,
            }]

        result = authoritative(run_scan(adapter(output=f"{HEADER}\n{EXPOSED}", enricher=enrich)))
        exposed = result["findings"][0]
        self.assertEqual(exposed, {
            "title": "Alternate HTTP service listening on all interfaces",
            "description": (
                "A TCP service on port 8080 is bound to all network interfaces. "
                "Port 8080 is commonly used for alternate HTTP or development web services."
            ),
            "severity": "MEDIUM",
            "recommendation": (
                "Verify the web service is expected and restrict network exposure "
                "if remote access is unnecessary."
            ),
            "evidence": [
                "Service: Alternate HTTP", "Protocol: tcp", "Address: 0.0.0.0",
                "Port: 8080", "Process: python3", "PID: 42",
                "Application: /usr/bin/wsdd", "Service/Application: WSDD",
                "Exposure: all interfaces",
            ],
            "confidence": 90,
            "technique_id": None,
            "source": "network",
            "kind": "RISK",
            "assessment_state": "CONFIRMED",
            "finding_id": (
                "type=alternate http service listening on all interfaces|"
                "address=0.0.0.0|application=/usr/bin/wsdd|port=8080|"
                "process=python3|protocol=tcp"
            ),
        })
        self.assertEqual(result["score"]["score"], 90)
        self.assertEqual(result["score"]["risk_level"], "LOW")
        self.assertEqual(result["assessment_assurance"]["level"], "PARTIAL")

    def test_firewall_and_iptables_fixtures_preserve_exact_classification(self):
        firewall = {
            "detected_tools": ["iptables"],
            "tool_paths": {"iptables": "/usr/sbin/iptables"},
        }
        cases = (
            ({"available": True, "accessible": True,
              "policies": {"INPUT": "ACCEPT", "FORWARD": "DROP", "OUTPUT": "ACCEPT"}},
             "COMPLETE", "MEDIUM", "RISK", "CONFIRMED", 90),
            ({"available": True, "accessible": True, "policies": {}},
             "INCOMPLETE", "INFO", "COVERAGE_GAP", "INCOMPLETE", 100),
            ({"available": True, "accessible": False,
              "message": "token=SECRET-CANARY raw stderr",
              "error": "token=SECRET-CANARY"},
             "INCOMPLETE", "INFO", "COVERAGE_GAP", "INCOMPLETE", 100),
        )
        for policy, coverage, severity, kind, state, score in cases:
            with self.subTest(policy=policy):
                result = authoritative(run_scan(adapter(firewall=firewall, policy=policy)))
                finding = result["findings"][-1]
                self.assertEqual(
                    result["coverage"]["iptables_input_policy"], coverage
                )
                self.assertEqual(
                    (finding["severity"], finding["kind"], finding["assessment_state"]),
                    (severity, kind, state),
                )
                self.assertEqual(result["score"]["score"], score)
                self.assertNotIn("SECRET-CANARY", repr(result))

    def test_neutral_inbound_posture_is_independent_of_legacy_domain(self):
        firewall = {
            "detected_tools": ["iptables"],
            "tool_paths": {"iptables": "/usr/sbin/iptables"},
        }
        linux = adapter(
            firewall=firewall,
            policy={"available": True, "accessible": True,
                    "policies": {"INPUT": "DROP"}},
        )
        neutral = linux.collect_firewall_inbound_policy()
        legacy = linux.collect_firewall_policy()
        self.assertEqual(neutral.domain, ObservationDomain.FIREWALL_INBOUND_POLICY)
        self.assertEqual(legacy.domain, ObservationDomain.FIREWALL_INPUT_POLICY)
        self.assertEqual(neutral.coverage, legacy.coverage)
        self.assertEqual(
            neutral.observations[0].profiles[0].default_inbound_action,
            FirewallInboundAction.BLOCK,
        )

    def test_malformed_partial_and_failed_socket_fixtures_fail_closed(self):
        partial = f"{HEADER}\n{EXPOSED}\nunexpected row"
        parsed = adapter(output=partial).collect_network()
        self.assertEqual(parsed.coverage, CoverageState.INCOMPLETE)
        self.assertEqual(len(parsed.observations), 1)
        self.assertEqual(parsed.failure.code, FailureCode.SOCKET_OUTPUT_MALFORMED)
        result = authoritative(run_scan(adapter(output=partial)))
        self.assertEqual(result["findings"][-2]["finding_id"],
                         "type=listening-service inspection incomplete")

        failed = LinuxPlatformAdapter(
            system_collector=lambda: dict(SYSTEM),
            firewall_collector=lambda: NFTABLES,
            network_collector=lambda: {
                "accessible": False,
                "failure_code": "SOCKET_COMMAND_FAILED",
                "message": "token=SECRET-CANARY raw stderr",
                "stderr": "token=SECRET-CANARY",
            },
        )
        failure = failed.collect_network()
        self.assertEqual(failure.coverage, CoverageState.INCOMPLETE)
        self.assertNotIn("SECRET-CANARY", repr(failure))
        self.assertNotIn("stderr", repr(failure).casefold())

    def test_identical_fixtures_produce_deterministic_order_and_observations(self):
        linux = adapter(output=f"{HEADER}\n{EXPOSED}\n{LOOPBACK}")
        first = linux.collect_network()
        second = linux.collect_network()
        self.assertEqual(first, second)
        self.assertEqual(
            [item.address for item in first.observations],
            ["0.0.0.0", "127.0.0.1"],
        )

    def test_secret_canary_cannot_cross_authoritative_pipeline(self):
        canary = "token=SECRET-CANARY"
        linux = LinuxPlatformAdapter(
            system_collector=lambda: dict(SYSTEM),
            firewall_collector=lambda: NFTABLES,
            network_collector=lambda: {
                "accessible": False,
                "failure_code": "SOCKET_COMMAND_FAILED",
                "message": canary,
                "stderr": canary,
            },
        )
        scan = run_scan(linux)
        with tempfile.TemporaryDirectory() as directory:
            report_path = save_json_report(scan, directory)
            report = json.loads(Path(report_path).read_text(encoding="utf-8"))
            with open_memory_database(Path(directory, "memory", "memory.db")) as database:
                ingest_report(database, ReportIngestionRequest(Path(report_path)))
                durable = "\n".join(database.connection.iterdump())
        context = build_advisor_context(report, None, None)
        provider = build_provider_request(context, generate_advisory(context))
        intelligence = IntelligenceOrchestrator().handle(
            "Give me my security briefing", reports=(report,)
        )
        for value in (scan, report, durable, context, provider, intelligence):
            self.assertNotIn(canary, repr(value))

    def test_platform_package_exposes_no_command_execution_abstraction(self):
        package = Path(__file__).parents[1] / "src" / "cyberwatchtower" / "platform"
        prohibited = ("subprocess", "shell=True", "os.system", "eval(", "exec(")
        for source in package.rglob("*.py"):
            text = source.read_text(encoding="utf-8")
            for marker in prohibited:
                with self.subTest(source=source.name, marker=marker):
                    self.assertNotIn(marker, text)
        linux = adapter()
        self.assertFalse(hasattr(linux, "run_command"))


if __name__ == "__main__":
    unittest.main()
