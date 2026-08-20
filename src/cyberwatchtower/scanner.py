from typing import cast

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
    LEGACY_ASSESSMENT_DOMAINS,
    ScanDomain,
    assessment_assurance_summary,
)
from .platform.contracts import PlatformAdapter
from .platform.linux import LinuxPlatformAdapter
from .platform.linux.contracts import LinuxFirewallPolicyAdapter
from .platform.models import FailureCategory
from .platform.models import (
    BindExposure,
    FirewallEnablement,
    FirewallInboundAction,
    FirewallProfileState,
)
from .platform.errors import UnsupportedPlatformError
from .platform.selection import select_platform_adapter
from .windows_firewall import assess_windows_firewall
from .reachability import (
    ReachabilityEvidenceBasis,
    assess_listener_reachability,
    reachability_coverage,
)


WINDOWS_ASSESSMENT_DOMAINS = (
    ScanDomain.FIREWALL_TECHNOLOGY,
    ScanDomain.FIREWALL_INBOUND_POLICY,
    ScanDomain.NETWORK_SOCKET_INSPECTION,
    ScanDomain.NETWORK_REACHABILITY,
)

LINUX_ASSESSMENT_DOMAINS = (
    *LEGACY_ASSESSMENT_DOMAINS,
    ScanDomain.NETWORK_REACHABILITY,
)


def _windows_policy_basis(policy_result) -> tuple[ReachabilityEvidenceBasis, ...]:
    basis = []
    for posture in policy_result.observations:
        for profile in posture.profiles:
            if profile.state != FirewallProfileState.ACTIVE:
                continue
            if profile.enablement == FirewallEnablement.DISABLED:
                basis.append(ReachabilityEvidenceBasis.WINDOWS_FIREWALL_DISABLED)
            elif profile.default_inbound_action == FirewallInboundAction.ALLOW:
                basis.append(ReachabilityEvidenceBasis.WINDOWS_PERMISSIVE_DEFAULT)
            elif profile.default_inbound_action == FirewallInboundAction.BLOCK:
                basis.append(ReachabilityEvidenceBasis.WINDOWS_RESTRICTIVE_DEFAULT)
            else:
                basis.append(ReachabilityEvidenceBasis.FIREWALL_POLICY_UNKNOWN)
    if not basis:
        basis.append(ReachabilityEvidenceBasis.FIREWALL_POLICY_UNKNOWN)
    return tuple(dict.fromkeys(basis))


def _linux_policy_basis(iptables_data: dict) -> tuple[ReachabilityEvidenceBasis, ...]:
    policies = iptables_data.get("policies", {})
    policy = policies.get("INPUT") if isinstance(policies, dict) else None
    if policy == "ACCEPT":
        return (ReachabilityEvidenceBasis.LINUX_INPUT_ACCEPT,)
    if policy == "DROP":
        return (ReachabilityEvidenceBasis.LINUX_INPUT_DROP,)
    return (ReachabilityEvidenceBasis.FIREWALL_POLICY_UNKNOWN,)


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
    platform_name = adapter.platform_name.casefold()
    if platform_name == "linux":
        assessment_domains = LINUX_ASSESSMENT_DOMAINS
    elif platform_name == "windows":
        assessment_domains = WINDOWS_ASSESSMENT_DOMAINS
    else:
        raise UnsupportedPlatformError(
            "CyberWatchtower does not have deterministic interpretation for this platform."
        )
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
    detected_tools = firewall.get("detected_tools", [])

    policy_result = None
    iptables_data = {}
    policy_basis = (ReachabilityEvidenceBasis.FIREWALL_POLICY_UNKNOWN,)
    if platform_name == "linux" and "iptables" in detected_tools:
        linux_policy_adapter = cast(LinuxFirewallPolicyAdapter, adapter)
        policy_result = linux_policy_adapter.collect_firewall_policy()
        iptables_data = (
            policy_result.observations[0].to_assessment_mapping()
            if policy_result.observations else {}
        )
        policy_basis = _linux_policy_basis(iptables_data)
    elif platform_name == "windows":
        policy_result = adapter.collect_firewall_inbound_policy()
        policy_basis = _windows_policy_basis(policy_result)

    findings = []
    coverage = {
        domain.value: CoverageState.UNKNOWN.value
        for domain in assessment_domains
    }
    coverage[ScanDomain.FIREWALL_TECHNOLOGY.value] = firewall_result.coverage.value

    network_result = adapter.collect_network()
    coverage[ScanDomain.NETWORK_SOCKET_INSPECTION.value] = network_result.coverage.value
    services = [item.to_service_mapping() for item in network_result.observations]
    reachability_assessments = tuple(
        assess_listener_reachability(
            BindExposure(item["exposure"]), policy_basis
        )
        for item in services
    )
    coverage[ScanDomain.NETWORK_REACHABILITY.value] = reachability_coverage(
        network_result.coverage, reachability_assessments
    ).value

    if (
        services
        or network_result.coverage == CoverageState.COMPLETE
        or network_result.failure.category in {
            FailureCategory.MALFORMED_OUTPUT,
            FailureCategory.PARTIAL,
        }
    ):
        network_findings = assess_network_exposure(services, policy_basis)

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
                    assessment_state=AssessmentState.POTENTIAL,
                    network_context=network_finding["network_context"],
                    presentation_group_id=network_finding[
                        "presentation_group_id"
                    ],
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
                        if platform_name == "linux"
                        else "Repeat Windows endpoint collection and review its coverage."
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
                    (
                        "Verify that the ss utility is available and that the scan "
                        "has sufficient permission to inspect local sockets."
                        if platform_name == "linux"
                        else "Verify that Windows endpoint APIs are available and "
                        "repeat the assessment."
                    )
                ),
                evidence=evidence,
                confidence=100,
                source="network",
                kind=FindingKind.COVERAGE_GAP,
                assessment_state=AssessmentState.INCOMPLETE,
            )
        )

    if (
        platform_name == "windows"
        and not detected_tools
        and firewall_result.coverage != CoverageState.COMPLETE
    ):
        findings.append(
            Finding(
                title="Windows Firewall technology assessment incomplete",
                description=(
                    "CyberWatchtower could not completely determine Windows "
                    "Firewall technology availability."
                ),
                severity=Severity.LOW,
                recommendation=(
                    "Repeat the assessment with read access to Windows Firewall policy."
                ),
                evidence=[
                    f"Failure code: {firewall_result.failure.code.value}",
                    firewall_result.failure.message,
                ],
                confidence=100,
                finding_id=(
                    "source=firewall_technology|condition=coverage_incomplete"
                ),
                source="firewall_technology",
                kind=FindingKind.COVERAGE_GAP,
                assessment_state=AssessmentState.INCOMPLETE,
            )
        )
    elif not detected_tools:
        findings.append(
            Finding(
                title="Firewall technology not detected",
                description=(
                    "CyberWatchtower could not detect a supported Linux "
                    "firewall technology."
                    if platform_name == "linux"
                    else "CyberWatchtower could not detect supported Windows "
                    "firewall technology."
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
                source=(
                    "firewall" if platform_name == "linux"
                    else "firewall_technology"
                ),
                kind=FindingKind.RISK,
                assessment_state=AssessmentState.POTENTIAL,
            )
        )

    else:
        findings.append(
            Finding(
                title="Firewall technology detected",
                description=(
                    "CyberWatchtower detected firewall technology on this system."
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
                source=(
                    "firewall" if platform_name == "linux"
                    else "firewall_technology"
                ),
                kind=FindingKind.OBSERVATION,
                assessment_state=AssessmentState.INFORMATIONAL,
            )
        )

    if platform_name == "linux" and "iptables" in detected_tools:
        # The current deterministic interpretation is explicitly Linux-only.
        # Platform-neutral adapters expose inbound posture observations, while
        # this compatibility seam preserves exact legacy iptables evidence.
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

    if platform_name == "windows":
        coverage[ScanDomain.FIREWALL_INBOUND_POLICY.value] = (
            policy_result.coverage.value
        )
        findings.extend(assess_windows_firewall(policy_result))

    score = calculate_security_score(findings)
    assurance = assessment_assurance_summary(coverage, assessment_domains)

    return {
        "system": system,
        "firewall": firewall,
        "coverage": coverage,
        "assessment_domains": [
            domain.value for domain in assessment_domains
        ],
        "findings": findings,
        "score": score,
        "assessment_assurance": assurance,
    }
