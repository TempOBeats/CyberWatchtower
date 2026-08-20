import unittest
from unittest.mock import patch

import cyberwatchtower.scanner as scanner_module
from cyberwatchtower.models import AssessmentState, Finding, FindingKind, Severity
from cyberwatchtower.platform.linux import LinuxPlatformAdapter
from cyberwatchtower.reporting import finding_to_dict
from cyberwatchtower.scanner import run_scan


def _run_linux_fixture_scan():
    """Run patched Linux collector fixtures without consulting the host OS."""

    return run_scan(LinuxPlatformAdapter(
        system_collector=scanner_module.collect_system_information,
        firewall_collector=scanner_module.check_firewall,
        network_collector=scanner_module.inspect_listening_services,
        firewall_policy_collector=scanner_module.inspect_iptables,
        process_enricher=lambda services: services,
    ))


class FindingMetadataTests(unittest.TestCase):
    def test_ambiguous_finding_defaults_to_potential_not_confirmed(self):
        finding = Finding("Legacy-style finding", "", Severity.LOW, "")

        self.assertEqual(finding.kind, FindingKind.RISK)
        self.assertEqual(finding.assessment_state, AssessmentState.POTENTIAL)

    def test_metadata_is_serialized_without_breaking_existing_fields(self):
        finding = Finding(
            "Observed",
            "Description",
            Severity.INFO,
            "Recommendation",
            source="firewall",
            kind=FindingKind.OBSERVATION,
            assessment_state=AssessmentState.INFORMATIONAL,
        )

        data = finding_to_dict(finding)

        self.assertEqual(data["source"], "firewall")
        self.assertEqual(data["kind"], "OBSERVATION")
        self.assertEqual(data["assessment_state"], "INFORMATIONAL")
        self.assertEqual(data["title"], "Observed")

    def test_exposed_service_and_firewall_detection_are_explicitly_classified(self):
        network_result = {
            "available": True,
            "accessible": True,
            "raw_output": "\n".join(
                [
                    "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process",
                    'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=10,fd=3))',
                ]
            ),
        }

        with (
            patch("cyberwatchtower.scanner.collect_system_information", return_value={}),
            patch(
                "cyberwatchtower.scanner.inspect_listening_services",
                return_value=network_result,
            ),
            patch(
                "cyberwatchtower.scanner.check_firewall",
                return_value={"detected_tools": ["nftables"]},
            ),
        ):
            result = _run_linux_fixture_scan()

        exposed = next(f for f in result["findings"] if "SSH" in f.title)
        firewall = next(
            f for f in result["findings"] if f.title == "Firewall technology detected"
        )
        self.assertEqual((exposed.kind, exposed.assessment_state), (
            FindingKind.RISK,
            AssessmentState.POTENTIAL,
        ))
        self.assertEqual((firewall.kind, firewall.assessment_state), (
            FindingKind.OBSERVATION,
            AssessmentState.INFORMATIONAL,
        ))

    def test_incomplete_socket_inspection_is_a_coverage_gap(self):
        with (
            patch("cyberwatchtower.scanner.collect_system_information", return_value={}),
            patch(
                "cyberwatchtower.scanner.inspect_listening_services",
                return_value={"available": False, "message": "ss unavailable"},
            ),
            patch(
                "cyberwatchtower.scanner.check_firewall",
                return_value={"detected_tools": ["nftables"]},
            ),
        ):
            result = _run_linux_fixture_scan()

        finding = next(
            f for f in result["findings"]
            if f.title == "Listening-service inspection incomplete"
        )
        self.assertEqual(finding.kind, FindingKind.COVERAGE_GAP)
        self.assertEqual(finding.assessment_state, AssessmentState.INCOMPLETE)

    def test_permissive_iptables_policy_is_confirmed_risk(self):
        with (
            patch("cyberwatchtower.scanner.collect_system_information", return_value={}),
            patch(
                "cyberwatchtower.scanner.inspect_listening_services",
                return_value={
                    "available": True,
                    "accessible": True,
                    "raw_output": "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process",
                },
            ),
            patch(
                "cyberwatchtower.scanner.check_firewall",
                return_value={"detected_tools": ["iptables"]},
            ),
            patch(
                "cyberwatchtower.scanner.inspect_iptables",
                return_value={
                    "available": True,
                    "accessible": True,
                    "policies": {
                        "INPUT": "ACCEPT",
                        "FORWARD": "ACCEPT",
                        "OUTPUT": "ACCEPT",
                    },
                },
            ),
        ):
            result = _run_linux_fixture_scan()

        finding = next(
            f for f in result["findings"] if f.title == "iptables firewall assessment"
        )
        self.assertEqual(finding.kind, FindingKind.RISK)
        self.assertEqual(finding.assessment_state, AssessmentState.CONFIRMED)

    def test_unknown_iptables_policy_is_an_incomplete_coverage_gap(self):
        with (
            patch("cyberwatchtower.scanner.collect_system_information", return_value={}),
            patch(
                "cyberwatchtower.scanner.inspect_listening_services",
                return_value={
                    "available": True,
                    "accessible": True,
                    "raw_output": "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process",
                },
            ),
            patch(
                "cyberwatchtower.scanner.check_firewall",
                return_value={"detected_tools": ["iptables"]},
            ),
            patch(
                "cyberwatchtower.scanner.inspect_iptables",
                return_value={
                    "available": True,
                    "accessible": True,
                    "policies": {},
                },
            ),
        ):
            result = _run_linux_fixture_scan()

        finding = next(
            f for f in result["findings"] if f.title == "iptables firewall assessment"
        )
        self.assertEqual(finding.kind, FindingKind.COVERAGE_GAP)
        self.assertEqual(finding.assessment_state, AssessmentState.INCOMPLETE)


if __name__ == "__main__":
    unittest.main()
