from .models import Finding, Severity
from .system import collect_system_information
from .firewall import (
    check_firewall,
    inspect_iptables,
    assess_iptables,
)
from .network import (
    inspect_listening_services,
    parse_listening_services,
    assess_network_exposure,
)


def run_scan() -> dict:
    system = collect_system_information()
    firewall = check_firewall()

    findings = []

    network = inspect_listening_services()

    if network.get("accessible"):
        services = parse_listening_services(
            network.get("raw_output", "")
        )

        network_findings = assess_network_exposure(services)

        for network_finding in network_findings:
            findings.append(
                Finding(
                    title=network_finding["title"],
                    description=network_finding["description"],
                    severity=Severity[network_finding["severity"]],
                    recommendation=network_finding["recommendation"],
                    evidence=network_finding["evidence"],
                    confidence=90,
                )
            )

    detected_tools = firewall.get("detected_tools", [])

    if not detected_tools:
        findings.append(
            Finding(
                title="Firewall technology not detected",
                description=(
                    "CyberWatchtower could not detect a supported "
                    "Linux firewall technology."
                ),
                severity=Severity.LOW,
                recommendation=(
                    "Verify whether another firewall solution is "
                    "protecting this system."
                ),
                evidence=[
                    "No supported firewall tools were detected."
                ],
                confidence=70,
            )
        )

    else:
        findings.append(
            Finding(
                title="Firewall technology detected",
                description=(
                    "CyberWatchtower detected firewall technology "
                    "on this system."
                ),
                severity=Severity.INFO,
                recommendation=(
                    "Inspect the active firewall configuration to "
                    "verify that meaningful filtering is enabled."
                ),
                evidence=[
                    f"Detected tools: {', '.join(detected_tools)}"
                ],
                confidence=95,
            )
        )

    if "iptables" in detected_tools:
        iptables_data = inspect_iptables()

        if iptables_data.get("accessible"):
            assessment = assess_iptables(iptables_data)

            findings.append(
                Finding(
                    title="iptables firewall assessment",
                    description=assessment["message"],
                    severity=Severity[assessment["severity"]],
                    recommendation=assessment.get(
                        "recommendation",
                        "Review the firewall configuration.",
                    ),
                    evidence=assessment.get(
                        "evidence",
                        [],
                    ),
                    confidence=assessment["confidence"],
                )
            )

        else:
            findings.append(
                Finding(
                    title="iptables inspection requires elevated privileges",
                    description=iptables_data.get(
                        "message",
                        "CyberWatchtower could not inspect iptables.",
                    ),
                    severity=Severity.INFO,
                    recommendation=(
                        "Run CyberWatchtower with appropriate privileges "
                        "if a complete firewall assessment is required."
                    ),
                    evidence=[
                        "iptables detected",
                        "Firewall rules were not readable by the current user",
                    ],
                    confidence=100,
                )
            )

    return {
        "system": system,
        "firewall": firewall,
        "findings": findings,
    }
