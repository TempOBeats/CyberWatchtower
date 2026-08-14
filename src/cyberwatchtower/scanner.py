from .models import AssessmentState, Finding, FindingKind, Severity
from .system import collect_system_information
from .firewall import (
    check_firewall,
    inspect_iptables,
    assess_iptables,
)
from .network import (
    inspect_listening_services,
    parse_listening_services,
    enrich_process_intelligence,
    assess_network_exposure,
    classify_service_risk,
)
from .scoring import calculate_security_score
from .report_contracts import CoverageState, ScanDomain


def run_scan() -> dict:
    system = collect_system_information()
    firewall = check_firewall()

    findings = []
    coverage = {
        ScanDomain.FIREWALL_TECHNOLOGY.value: CoverageState.COMPLETE.value,
        ScanDomain.IPTABLES_INPUT_POLICY.value: CoverageState.UNKNOWN.value,
        ScanDomain.NETWORK_SOCKET_INSPECTION.value: CoverageState.UNKNOWN.value,
    }

    network = inspect_listening_services()

    if network.get("accessible"):
        coverage[ScanDomain.NETWORK_SOCKET_INSPECTION.value] = CoverageState.COMPLETE.value
        services = parse_listening_services(
            network.get("raw_output", "")
        )
        services = enrich_process_intelligence(services)

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
                    source="network",
                    kind=FindingKind.RISK,
                    assessment_state=AssessmentState.CONFIRMED,
                )
            )

    else:
        coverage[ScanDomain.NETWORK_SOCKET_INSPECTION.value] = CoverageState.INCOMPLETE.value
        error = network.get("error")
        evidence = [network.get("message", "Socket inspection was incomplete.")]

        if error:
            evidence.append(f"Inspection error: {error}")

        findings.append(
            Finding(
                title="Listening-service inspection incomplete",
                description=(
                    "CyberWatchtower could not complete listening-service "
                    "inspection, so network exposure may be underreported."
                ),
                severity=Severity.LOW,
                recommendation=(
                    "Verify that the ss utility is available and that the scan "
                    "has sufficient permission to inspect local sockets."
                ),
                evidence=evidence,
                confidence=100,
                source="network",
                kind=FindingKind.COVERAGE_GAP,
                assessment_state=AssessmentState.INCOMPLETE,
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
                source="firewall",
                kind=FindingKind.RISK,
                assessment_state=AssessmentState.POTENTIAL,
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
                source="firewall",
                kind=FindingKind.OBSERVATION,
                assessment_state=AssessmentState.INFORMATIONAL,
            )
        )

    if "iptables" in detected_tools:
        iptables_data = inspect_iptables()

        if iptables_data.get("accessible"):
            assessment = assess_iptables(iptables_data)

            coverage[ScanDomain.IPTABLES_INPUT_POLICY.value] = (
                CoverageState.COMPLETE.value
                if assessment["status"] in {"permissive", "configured"}
                else CoverageState.INCOMPLETE.value
            )

            if assessment["status"] == "permissive":
                finding_kind = FindingKind.RISK
                assessment_state = AssessmentState.CONFIRMED
            elif assessment["status"] == "inconclusive":
                finding_kind = FindingKind.COVERAGE_GAP
                assessment_state = AssessmentState.INCOMPLETE
            else:
                finding_kind = FindingKind.OBSERVATION
                assessment_state = AssessmentState.INFORMATIONAL

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
                    source="firewall",
                    kind=finding_kind,
                    assessment_state=assessment_state,
                )
            )

        else:
            coverage[ScanDomain.IPTABLES_INPUT_POLICY.value] = CoverageState.INCOMPLETE.value
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
                    source="firewall",
                    kind=FindingKind.COVERAGE_GAP,
                    assessment_state=AssessmentState.INCOMPLETE,
                )
            )

    score = calculate_security_score(findings)

    return {
        "system": system,
        "firewall": firewall,
        "coverage": coverage,
        "findings": findings,
        "score": score,
    }
