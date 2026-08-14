import unittest
from unittest.mock import patch

from cyberwatchtower.firewall import assess_iptables
from cyberwatchtower.network import inspect_listening_services
from cyberwatchtower.scanner import run_scan
from cyberwatchtower.report_contracts import CoverageState, ScanDomain


class SocketInspectionTests(unittest.TestCase):
    def test_success_exit_with_netlink_error_is_inaccessible(self):
        command_result = {
            "success": True,
            "stdout": (
                "Netid State Recv-Q Send-Q Local Address:Port "
                "Peer Address:Port Process"
            ),
            "stderr": "Cannot open netlink socket: Operation not permitted",
            "returncode": 0,
        }

        with (
            patch("cyberwatchtower.network.shutil.which", return_value="/usr/bin/ss"),
            patch("cyberwatchtower.network._run_command", return_value=command_result),
        ):
            result = inspect_listening_services()

        self.assertFalse(result["accessible"])
        self.assertIn("netlink", result["error"].lower())

    def test_incomplete_inspection_prevents_perfect_score(self):
        network_result = {
            "available": True,
            "accessible": False,
            "message": "Socket inspection was incomplete.",
            "error": "permission denied",
            "services": [],
        }

        with (
            patch("cyberwatchtower.scanner.collect_system_information", return_value={}),
            patch(
                "cyberwatchtower.scanner.check_firewall",
                return_value={"detected_tools": ["nftables"]},
            ),
            patch(
                "cyberwatchtower.scanner.inspect_listening_services",
                return_value=network_result,
            ),
        ):
            result = run_scan()

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
                return_value={"accessible": True, "raw_output": ""},
            ),
            patch("cyberwatchtower.scanner.parse_listening_services", return_value=[]),
            patch("cyberwatchtower.scanner.enrich_process_intelligence", return_value=[]),
            patch("cyberwatchtower.scanner.inspect_iptables", return_value={
                "available": True,
                "accessible": True,
                "policies": {"INPUT": "DROP"},
            }),
        ):
            result = run_scan()

        self.assertEqual(
            result["coverage"][ScanDomain.NETWORK_SOCKET_INSPECTION.value],
            CoverageState.COMPLETE.value,
        )
        self.assertEqual(
            result["coverage"][ScanDomain.IPTABLES_INPUT_POLICY.value],
            CoverageState.COMPLETE.value,
        )


if __name__ == "__main__":
    unittest.main()
