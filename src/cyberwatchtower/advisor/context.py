from collections.abc import Mapping

from cyberwatchtower.finding_identity import finding_identity
from cyberwatchtower.models import AssessmentState, FindingKind
from cyberwatchtower.report_contracts import assessment_assurance_summary

from .models import AdvisoryFinding, AdvisorContext, ChangeFinding


SAFE_EVIDENCE_LABELS = {
    "address",
    "application",
    "exposure",
    "forward policy",
    "firewall enabled",
    "default inbound action",
    "block all inbound",
    "input policy",
    "output policy",
    "port",
    "process",
    "profile",
    "protocol",
    "service",
    "service/application",
}


def _enum_or_default(value, enum_type, default):
    try:
        return enum_type(value)
    except (TypeError, ValueError):
        return default


def _has_valid_metadata(finding: Mapping) -> bool:
    try:
        FindingKind(finding.get("kind"))
        AssessmentState(finding.get("assessment_state"))
    except (TypeError, ValueError):
        return False
    return True


def _safe_evidence(finding: Mapping) -> tuple[tuple[str, ...], dict[str, str]]:
    safe_items = []
    values = {}

    for item in finding.get("evidence", []):
        if not isinstance(item, str) or ":" not in item:
            continue

        label, value = item.split(":", 1)
        normalized_label = label.strip().casefold()

        if normalized_label not in SAFE_EVIDENCE_LABELS:
            continue

        clean_value = value.strip()
        if not clean_value:
            continue

        safe_items.append(f"{label.strip()}: {clean_value}")
        values[normalized_label] = clean_value

    return tuple(safe_items), values


def _change_finding(finding: Mapping) -> ChangeFinding:
    return ChangeFinding(
        finding_id=finding_identity(dict(finding)),
        title=str(finding.get("title", "Unknown finding")),
        severity=str(finding.get("severity", "UNKNOWN")),
    )


def build_advisor_context(
    current_report: Mapping,
    comparison: Mapping | None,
    intelligence: Mapping | None,
) -> AdvisorContext:
    """Normalize deterministic scan data into a read-only advisor snapshot."""

    comparison = comparison or {}
    intelligence = intelligence or {}
    new_ids = {
        finding_identity(dict(finding))
        for finding in comparison.get("new_findings", [])
    }
    occurrences = {
        str(item.get("finding_id")): int(item.get("occurrences", 0))
        for item in intelligence.get("findings", [])
        if item.get("finding_id")
    }
    findings = []

    for raw_finding in current_report.get("findings", []):
        finding_id = finding_identity(dict(raw_finding))
        safe_evidence, evidence_values = _safe_evidence(raw_finding)
        findings.append(
            AdvisoryFinding(
                finding_id=finding_id,
                title=str(raw_finding.get("title", "Unknown finding")),
                description=str(raw_finding.get("description", "")),
                severity=str(raw_finding.get("severity", "UNKNOWN")),
                recommendation=str(raw_finding.get("recommendation", "")),
                confidence=int(raw_finding.get("confidence", 0) or 0),
                source=str(raw_finding.get("source", "legacy")),
                kind=_enum_or_default(
                    raw_finding.get("kind"),
                    FindingKind,
                    FindingKind.RISK,
                ),
                assessment_state=_enum_or_default(
                    raw_finding.get("assessment_state"),
                    AssessmentState,
                    AssessmentState.POTENTIAL,
                ),
                evidence=safe_evidence,
                protocol=evidence_values.get("protocol"),
                address=evidence_values.get("address"),
                port=evidence_values.get("port"),
                process=evidence_values.get("process"),
                application=evidence_values.get("application"),
                application_name=evidence_values.get("service/application"),
                exposure=evidence_values.get("exposure"),
                is_new=finding_id in new_ids,
                occurrences=occurrences.get(finding_id, 0),
                metadata_inferred=not _has_valid_metadata(raw_finding),
            )
        )

    score_data = current_report.get("security_score", {})
    counts = score_data.get("counts", {})
    assurance = assessment_assurance_summary(
        current_report.get("coverage"), current_report.get("assessment_domains")
    )

    return AdvisorContext(
        schema_version="1.0",
        score=int(score_data.get("score", 0) or 0),
        risk_level=str(score_data.get("risk_level", "UNKNOWN")),
        severity_counts=tuple(
            (severity, int(counts.get(severity, 0) or 0))
            for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        ),
        findings=tuple(findings),
        previous_score=(
            int(comparison["previous_score"])
            if "previous_score" in comparison
            else None
        ),
        score_change=(
            int(comparison["change"])
            if "change" in comparison
            else None
        ),
        trend=str(comparison.get("trend", "UNKNOWN")),
        new_findings=tuple(
            _change_finding(finding)
            for finding in comparison.get("new_findings", [])
        ),
        resolved_findings=tuple(
            _change_finding(finding)
            for finding in comparison.get("resolved_findings", [])
        ),
        total_scans=int(intelligence.get("total_scans", 0) or 0),
        average_score=float(intelligence.get("average_score", 0) or 0),
        overall_trend=str(intelligence.get("overall_trend", "UNKNOWN")),
        assessment_assurance=str(assurance["level"]),
        coverage_limitations=tuple(assurance["limitations"]),
        uncertain_findings=tuple(
            _change_finding(finding)
            for finding in comparison.get("uncertain_findings", [])
        ),
    )
