"""Deterministic interpretation of normalized Windows Firewall posture."""

from __future__ import annotations

from .models import AssessmentState, Finding, FindingKind, Severity
from .platform.models import (
    CollectionResult,
    FirewallEnablement,
    FirewallInboundAction,
    FirewallInboundPostureObservation,
    FirewallProfileObservation,
    FirewallProfileState,
)
from .report_contracts import CoverageState


def _profile_name(profile: FirewallProfileObservation) -> str:
    return profile.profile.value.title()


def _evidence(profile: FirewallProfileObservation) -> list[str]:
    return [
        f"Profile: {profile.profile.value}",
        f"Firewall enabled: {profile.enablement.value}",
        f"Default inbound action: {profile.default_inbound_action.value}",
        "Block all inbound: " + (
            "UNKNOWN"
            if profile.block_all_inbound is None
            else str(profile.block_all_inbound).lower()
        ),
    ]


def _identity(profile: FirewallProfileObservation, condition: str) -> str:
    return (
        "source=firewall_inbound_policy"
        f"|profile={profile.profile.value.casefold()}"
        f"|condition={condition}"
    )


def _coverage_gap(
    profile: FirewallProfileObservation | None = None,
) -> Finding:
    profile_name = _profile_name(profile) if profile is not None else "Active"
    evidence = (
        _evidence(profile)
        if profile is not None
        else ["Firewall profile assessment: incomplete"]
    )
    finding_id = (
        _identity(profile, "coverage_incomplete")
        if profile is not None
        else "source=firewall_inbound_policy|profile=unknown|condition=coverage_incomplete"
    )
    return Finding(
        title=f"Windows Firewall {profile_name} profile assessment incomplete",
        description=(
            "CyberWatchtower could not completely determine the active Windows "
            "Firewall profile posture."
        ),
        severity=Severity.LOW,
        recommendation=(
            "Repeat the assessment with sufficient read access to Windows "
            "Firewall policy."
        ),
        evidence=evidence,
        confidence=100,
        finding_id=finding_id,
        source="firewall_inbound_policy",
        kind=FindingKind.COVERAGE_GAP,
        assessment_state=AssessmentState.INCOMPLETE,
    )


def _interpret_profile(profile: FirewallProfileObservation) -> list[Finding]:
    name = _profile_name(profile)
    evidence = _evidence(profile)
    if profile.enablement == FirewallEnablement.UNKNOWN:
        return [_coverage_gap(profile)]
    if profile.enablement == FirewallEnablement.DISABLED:
        return [Finding(
            title=f"Windows Firewall {name} profile is disabled",
            description=(
                f"The active Windows Firewall {name} profile is disabled, so "
                "that profile is not enforcing inbound firewall policy."
            ),
            severity=Severity.MEDIUM,
            recommendation=(
                f"Review why the Windows Firewall {name} profile is disabled "
                "and enable appropriate inbound protection."
            ),
            evidence=evidence,
            confidence=95,
            finding_id=_identity(profile, "disabled"),
            source="firewall_inbound_policy",
            kind=FindingKind.RISK,
            assessment_state=AssessmentState.CONFIRMED,
        )]
    if profile.default_inbound_action == FirewallInboundAction.UNKNOWN:
        return [_coverage_gap(profile)]

    findings = []
    if profile.default_inbound_action == FirewallInboundAction.ALLOW:
        findings.append(Finding(
            title=(
                f"Windows Firewall {name} profile allows inbound traffic by default"
            ),
            description=(
                f"The active Windows Firewall {name} profile permits inbound "
                "traffic by default unless another policy blocks it."
            ),
            severity=Severity.MEDIUM,
            recommendation=(
                f"Review the Windows Firewall {name} profile and determine "
                "whether a restrictive default inbound action is appropriate."
            ),
            evidence=evidence,
            confidence=90,
            finding_id=_identity(profile, "default_inbound_allow"),
            source="firewall_inbound_policy",
            kind=FindingKind.RISK,
            assessment_state=AssessmentState.CONFIRMED,
        ))
    else:
        findings.append(Finding(
            title=(
                f"Windows Firewall {name} profile blocks inbound traffic by default"
            ),
            description=(
                f"The active Windows Firewall {name} profile has a restrictive "
                "default inbound action."
            ),
            severity=Severity.INFO,
            recommendation=(
                f"Continue reviewing the Windows Firewall {name} profile as "
                "system requirements change."
            ),
            evidence=evidence,
            confidence=95,
            finding_id=_identity(profile, "default_inbound_block"),
            source="firewall_inbound_policy",
            kind=FindingKind.OBSERVATION,
            assessment_state=AssessmentState.INFORMATIONAL,
        ))

    if profile.block_all_inbound is True:
        findings.append(Finding(
            title=f"Windows Firewall {name} profile blocks all inbound traffic",
            description=(
                f"The active Windows Firewall {name} profile reports block-all-"
                "inbound mode in addition to its default inbound action."
            ),
            severity=Severity.INFO,
            recommendation=(
                f"Verify that block-all-inbound remains appropriate for the "
                f"Windows Firewall {name} profile."
            ),
            evidence=evidence,
            confidence=95,
            finding_id=_identity(profile, "block_all_inbound"),
            source="firewall_inbound_policy",
            kind=FindingKind.OBSERVATION,
            assessment_state=AssessmentState.INFORMATIONAL,
        ))
    return findings


def assess_windows_firewall(
    result: CollectionResult[FirewallInboundPostureObservation],
) -> list[Finding]:
    """Return findings derived only from typed Windows Firewall observations."""

    findings = []
    generated_gap = False
    for posture in result.observations:
        for profile in posture.profiles:
            if profile.state != FirewallProfileState.ACTIVE:
                continue
            profile_findings = _interpret_profile(profile)
            generated_gap = generated_gap or any(
                finding.kind == FindingKind.COVERAGE_GAP
                for finding in profile_findings
            )
            findings.extend(profile_findings)
    if result.coverage != CoverageState.COMPLETE and not generated_gap:
        findings.append(_coverage_gap())
    return findings
