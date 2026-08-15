from .models import AssessmentState, Finding, FindingKind, Severity
from .system import collect_system_information
from .firewall import (
    check_firewall,
    inspect_iptables,
    assess_iptables,
)
from .network import (
    inspect_listening_services,
    enrich_process_intelligence,
    assess_network_exposure,
)
from .scoring import calculate_security_score
from .report_contracts import (
    CoverageState,
    ScanDomain,
    assessment_assurance_summary,
)
from .platform.contracts import PlatformAdapter
from .platform.linux import LinuxPlatformAdapter
from .platform.models import FailureCategory
from .platform.selection import select_platform_adapter


def _default_platform_adapter() -> PlatformAdapter:
    """Build the Linux adapter from existing seams to preserve patch compatibility."""

    return select_platform_adapter(linux_adapter=LinuxPlatformAdapter(
        system_collector=collect_system_information,
        firewall_collector=check_firewall,
        network_collector=inspect_listening_services,
        firewall_policy_collector=inspect_iptables,
        process_enricher=enrich_process_intelligence,
    ))


def run_scan(adapter: PlatformAdapter | None = None) -> dict:
    adapter = adapter or _default_platform_adapter()
    system_result = adapter.collect_system()
    system = (
        system_result.observations[0].to_mapping()
        if system_result.observations else {}
    )
    firewall_result = adapter.collect_firewall()
    firewall = (
        firewall_result.observations[0].to_mapping()
        if firewall_result.observations else {"detected_tools": [], "tool_paths": {}}
    )

    findings = []
    coverage = {
        ScanDomain.FIREWALL_TECHNOLOGY.value: firewall_result.coverage.value,
        ScanDomain.IPTABLES_INPUT_POLICY.value: CoverageState.UNKNOWN.value,
        ScanDomain.NETWORK_SOCKET_INSPECTION.value: CoverageState.UNKNOWN.value,
    }

    network_result = adapter.collect_network()
    coverage[ScanDomain.NETWORK_SOCKET_INSPECTION.value] = network_result.coverage.value
    services = [item.to_service_mapping() for item in network_result.observations]

    if (
        services
        or network_result.coverage == CoverageState.COMPLETE
        or network_result.failure.category in {
            FailureCategory.MALFORMED_OUTPUT,
            FailureCategory.PARTIAL,
        }
    ):
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

        if network_result.coverage != CoverageState.COMPLETE:
            failure = network_result.failure
            findings.append(
                Finding(
                    title="Listening-service inspection incomplete",
                    description=(
                        "CyberWatchtower could not validate all socket inspection "
                        "output, so network exposure may be underreported."
                    ),
                    severity=Severity.LOW,
                    recommendation=(
                        "Verify the local ss utility and repeat the assessment."
                    ),
                    evidence=[
                        f"Failure code: {failure.code.value}",
                        failure.message,
                    ],
                    confidence=100,
                    source="network",
                    kind=FindingKind.COVERAGE_GAP,
                    assessment_state=AssessmentState.INCOMPLETE,
                )
            )

    else:
        failure = network_result.failure
        evidence = [failure.message]
        evidence.append(f"Failure code: {failure.code.value}")

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
        policy_result = adapter.collect_firewall_policy()
        iptables_data = (
            policy_result.observations[0].to_assessment_mapping()
            if policy_result.observations else {}
        )

        if iptables_data.get("accessible"):
            assessment = assess_iptables(iptables_data)

            coverage[ScanDomain.IPTABLES_INPUT_POLICY.value] = policy_result.coverage.value

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
            coverage[ScanDomain.IPTABLES_INPUT_POLICY.value] = policy_result.coverage.value
            findings.append(
                Finding(
                    title="iptables inspection requires elevated privileges",
                    description=(
                        iptables_data.get("message")
                        or policy_result.failure.message
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
    assurance = assessment_assurance_summary(coverage)

    return {
        "system": system,
        "firewall": firewall,
        "coverage": coverage,
        "findings": findings,
        "score": score,
        "assessment_assurance": assurance,
    }
