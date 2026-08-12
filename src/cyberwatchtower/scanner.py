from .models import Finding, Severity
from .system import collect_system_information
from .firewall import check_firewall


def run_scan() -> dict:
    system = collect_system_information()
    firewall = check_firewall()

    findings = []

    if firewall["status"] == "inactive":
        findings.append(
            Finding(
                title="Firewall appears inactive",
                description=firewall["message"],
                severity=Severity.MEDIUM,
                recommendation="Review the host firewall configuration and enable filtering if appropriate.",
                evidence=[
                    f"Firewall technology: {firewall['tool']}",
                    f"Firewall status: {firewall['status']}",
                ],
                confidence=90,
            )
        )

    elif firewall["status"] == "unknown":
        findings.append(
            Finding(
                title="Firewall protection could not be verified",
                description=firewall["message"],
                severity=Severity.LOW,
                recommendation="Verify whether another firewall technology protects this system.",
                evidence=[
                    "CyberWatchtower could not identify a supported firewall technology."
                ],
                confidence=60,
            )
        )

    elif firewall["status"] == "available":
        findings.append(
            Finding(
                title="Firewall technology detected",
                description=firewall["message"],
                severity=Severity.INFO,
                recommendation="Inspect the firewall rules to determine whether meaningful filtering is configured.",
                evidence=[
                    f"Detected technology: {firewall['tool']}",
                ],
                confidence=95,
            )
        )

    return {
        "system": system,
        "firewall": firewall,
        "findings": findings,
    }
