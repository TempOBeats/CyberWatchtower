import subprocess
import unittest
from unittest.mock import patch

from cyberwatchtower.firewall import run_command
from cyberwatchtower.models import Finding, Severity
from cyberwatchtower.reporting import finding_to_dict


class ProjectHygieneTests(unittest.TestCase):
    def test_finding_serialization_preserves_technique_id(self):
        finding = Finding(
            title="Example",
            description="Example finding",
            severity=Severity.INFO,
            recommendation="None",
            technique_id="T1049",
        )

        serialized = finding_to_dict(finding)

        self.assertEqual(serialized["technique_id"], "T1049")
        self.assertTrue(serialized["finding_id"])

    def test_firewall_command_timeout_is_reported(self):
        with patch(
            "cyberwatchtower.firewall.subprocess.run",
            side_effect=subprocess.TimeoutExpired(["iptables"], timeout=10),
        ):
            result = run_command(["iptables", "-L", "-n"])

        self.assertEqual(result["returncode"], -1)
        self.assertIn("timed out", result["stderr"])


if __name__ == "__main__":
    unittest.main()
