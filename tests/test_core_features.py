import unittest

from cyberwatchtower.history import compare_reports
from cyberwatchtower.intelligence import analyze_history
from cyberwatchtower.models import Finding, Severity
from cyberwatchtower.network import (
    assess_network_exposure,
    parse_listening_services,
)
from cyberwatchtower.scoring import calculate_security_score
from cyberwatchtower.service_intelligence import lookup_service
from cyberwatchtower.system import collect_system_information


class NetworkParsingTests(unittest.TestCase):
    def test_tcp_udp_ipv4_ipv6_and_process_attribution(self):
        raw_output = "\n".join(
            [
                (
                    "Netid State Recv-Q Send-Q Local Address:Port "
                    "Peer Address:Port Process"
                ),
                (
                    'tcp LISTEN 0 128 127.0.0.1:8000 0.0.0.0:* '
                    'users:(("python3",pid=10,fd=3))'
                ),
                (
                    'udp UNCONN 0 0 [::]:53 [::]:* '
                    'users:(("named",pid=11,fd=4))'
                ),
            ]
        )

        services = parse_listening_services(raw_output)

        self.assertEqual(len(services), 2)
        self.assertEqual(services[0]["exposure"], "loopback")
        self.assertEqual(services[0]["process"], "python3")
        self.assertEqual(services[0]["pid"], 10)
        self.assertEqual(services[1]["address"], "[::]")
        self.assertEqual(services[1]["exposure"], "all_interfaces")

    def test_only_all_interface_services_create_exposure_findings(self):
        services = [
            {
                "protocol": "tcp",
                "address": "127.0.0.1",
                "port": "8000",
                "exposure": "loopback",
                "process": "python3",
                "pid": 10,
            },
            {
                "protocol": "tcp",
                "address": "0.0.0.0",
                "port": "22",
                "exposure": "all_interfaces",
                "process": "sshd",
                "pid": 11,
            },
        ]

        findings = assess_network_exposure(services)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "MEDIUM")
        self.assertIn("SSH", findings[0]["title"])


class IntelligenceAndScoringTests(unittest.TestCase):
    def test_service_database_known_alternate_and_unknown_ports(self):
        self.assertEqual(lookup_service("22")["name"], "SSH")
        self.assertEqual(lookup_service("8080")["name"], "Alternate HTTP")
        self.assertFalse(lookup_service("65000")["known"])

    def test_score_weights_counts_and_floor(self):
        findings = [
            Finding("Critical", "", Severity.CRITICAL, ""),
            Finding("High", "", Severity.HIGH, ""),
            Finding("Medium", "", Severity.MEDIUM, ""),
            Finding("Low", "", Severity.LOW, ""),
            Finding("Info", "", Severity.INFO, ""),
        ]

        result = calculate_security_score(findings)

        self.assertEqual(result["score"], 35)
        self.assertEqual(result["risk_level"], "CRITICAL")
        self.assertEqual(result["counts"], {
            "CRITICAL": 1,
            "HIGH": 1,
            "MEDIUM": 1,
            "LOW": 1,
            "INFO": 1,
        })
        self.assertEqual(calculate_security_score(findings * 10)["score"], 0)

    def test_comparison_and_long_term_score_trends(self):
        reports = [
            {
                "generated_at": "2026-08-12T10:00:00+00:00",
                "security_score": {"score": 70, "risk_level": "HIGH"},
                "findings": [{"title": "A", "severity": "LOW"}],
            },
            {
                "generated_at": "2026-08-13T10:00:00+00:00",
                "security_score": {"score": 90, "risk_level": "LOW"},
                "findings": [{"title": "A", "severity": "LOW"}],
            },
        ]

        comparison = compare_reports(reports[0], reports[1])
        intelligence = analyze_history(reports)

        self.assertEqual(comparison["trend"], "IMPROVED")
        self.assertEqual(comparison["change"], 20)
        self.assertEqual(intelligence["average_score"], 80)
        self.assertEqual(intelligence["overall_trend"], "IMPROVED")
        self.assertEqual(intelligence["findings"][0]["occurrences"], 2)


class SystemInformationTests(unittest.TestCase):
    def test_system_information_has_expected_fields(self):
        result = collect_system_information()

        self.assertEqual(
            set(result),
            {
                "hostname",
                "username",
                "operating_system",
                "os_version",
                "architecture",
                "processor",
            },
        )
        self.assertTrue(result["hostname"])


if __name__ == "__main__":
    unittest.main()
