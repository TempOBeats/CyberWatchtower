import unittest
from unittest.mock import patch

from cyberwatchtower.firewall import assess_iptables
from cyberwatchtower.network import inspect_listening_services
from cyberwatchtower.scanner import run_scan


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


if __name__ == "__main__":
    unittest.main()
