"""Minimal current-system assessment use case over the existing scanner authority."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timezone
import unicodedata
from uuid import uuid4

from cyberwatchtower import scanner
from cyberwatchtower.core.evidence import EpistemicRole
from cyberwatchtower.firewall_policy import FirewallConditionMatch
from cyberwatchtower.memory.sanitization import (
    contains_sensitive_marker,
    sanitize_evidence,
)
from cyberwatchtower.models import AssessmentState, Finding, FindingKind, Severity
from cyberwatchtower.platform.errors import UnsupportedPlatformError
from cyberwatchtower.platform.models import FirewallObservation, SystemObservation
from cyberwatchtower.reachability import reachability_from_report
from cyberwatchtower.report_contracts import (
    CURRENT_REPORT_SCHEMA_VERSION,
    AssessmentAssurance,
    CoverageState,
    assessment_assurance_summary,
    normalize_assessment_domains,
)
from cyberwatchtower.scoring_contracts import (
    ScoringBasisCode,
    ScoringCategory,
    ScoringVersion,
)
from cyberwatchtower.scoring_projection import canonical_finding_id
from cyberwatchtower.scoring_report import validate_serialized_security_score

from .contracts import (
    ApplicationEvidence,
    ApplicationEvidenceCategory,
    ApplicationFinding,
    AssessmentAssuranceSummary,
    CurrentSystemAssessmentRequest,
    CurrentSystemAssessmentResult,
    DomainCoverage,
    EvidenceProjectionState,
    FirewallApplicabilitySummary,
    FirewallTechnologySummary,
    NetworkExposureContext,
    ProjectionNotice,
    ProjectionNoticeCode,
    ScoreCategoryBreakdown,
    ScoreContributor,
    ScoreGuardrail,
    SecurityRiskLevel,
    SecurityScore,
    SecurityScoreBreakdown,
    SeverityCount,
    SupportedPlatform,
    SystemSummary,
)
from .errors import (
    ApplicationComponent,
    ApplicationErrorCode,
    ApplicationFailure,
    CyberWatchtowerApplicationError,
)


_TOP_LEVEL_FIELDS = frozenset({
    "system", "firewall", "coverage", "assessment_domains", "findings",
    "score", "assessment_assurance",
})
_SYSTEM_FIELDS = frozenset({
    "system_id", "hostname", "username", "operating_system", "os_version",
    "architecture", "processor",
})
_COUNT_ORDER = (
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO,
)
_EVIDENCE_CATEGORIES = {
    "address": ApplicationEvidenceCategory.ADDRESS,
    "exposure": ApplicationEvidenceCategory.EXPOSURE,
    "forward policy": ApplicationEvidenceCategory.FORWARD_POLICY,
    "firewall enabled": ApplicationEvidenceCategory.FIREWALL_ENABLED,
    "default inbound action": ApplicationEvidenceCategory.DEFAULT_INBOUND_ACTION,
    "block all inbound": ApplicationEvidenceCategory.BLOCK_ALL_INBOUND,
    "input policy": ApplicationEvidenceCategory.INPUT_POLICY,
    "output policy": ApplicationEvidenceCategory.OUTPUT_POLICY,
    "port": ApplicationEvidenceCategory.PORT,
    "process": ApplicationEvidenceCategory.PROCESS,
    "profile": ApplicationEvidenceCategory.PROFILE,
    "protocol": ApplicationEvidenceCategory.PROTOCOL,
    "service": ApplicationEvidenceCategory.SERVICE,
    "service/application": ApplicationEvidenceCategory.SERVICE_APPLICATION,
}
_SOURCE_EVIDENCE = {
    "network": frozenset({
        ApplicationEvidenceCategory.ADDRESS,
        ApplicationEvidenceCategory.EXPOSURE,
        ApplicationEvidenceCategory.PORT,
        ApplicationEvidenceCategory.PROCESS,
        ApplicationEvidenceCategory.PROTOCOL,
        ApplicationEvidenceCategory.SERVICE,
        ApplicationEvidenceCategory.SERVICE_APPLICATION,
    }),
    "firewall": frozenset({
        ApplicationEvidenceCategory.INPUT_POLICY,
        ApplicationEvidenceCategory.FORWARD_POLICY,
        ApplicationEvidenceCategory.OUTPUT_POLICY,
    }),
    "firewall_inbound_policy": frozenset({
        ApplicationEvidenceCategory.PROFILE,
        ApplicationEvidenceCategory.FIREWALL_ENABLED,
        ApplicationEvidenceCategory.DEFAULT_INBOUND_ACTION,
        ApplicationEvidenceCategory.BLOCK_ALL_INBOUND,
    }),
}


class _ProjectionFailure(Exception):
    def __init__(
        self,
        code: ApplicationErrorCode,
        component: ApplicationComponent,
    ) -> None:
        self.code = code
        self.component = component
        super().__init__(code.value)


class _AssessmentRunner:
    """Private zero-argument scanner seam used only by the application use case."""

    __slots__ = ("_scanner_callable",)

    def __init__(self, scanner_callable: Callable[[], dict] | None = None) -> None:
        self._scanner_callable = scanner_callable

    def run(self) -> dict:
        if self._scanner_callable is not None:
            return self._scanner_callable()
        return scanner.run_scan()


def _operation_id() -> str:
    return f"assessment:{uuid4().hex}"


def _application_error(
    operation_id: str,
    code: ApplicationErrorCode,
    component: ApplicationComponent,
) -> CyberWatchtowerApplicationError:
    messages = {
        ApplicationErrorCode.INVALID_REQUEST: (
            "The assessment request does not match the supported local operation."
        ),
        ApplicationErrorCode.UNSUPPORTED_PLATFORM: (
            "The current platform is not supported for deterministic assessment."
        ),
        ApplicationErrorCode.PRIVACY_POLICY_BLOCKED: (
            "Required assessment data could not cross the application privacy boundary."
        ),
        ApplicationErrorCode.COMPATIBILITY_FAILURE: (
            "The deterministic assessment result did not match the application contract."
        ),
        ApplicationErrorCode.INTERNAL_FAILURE: (
            "The assessment could not be completed because of an internal failure."
        ),
    }
    return CyberWatchtowerApplicationError(ApplicationFailure(
        code=code,
        message=messages[code],
        retryable=False,
        component=component,
        operation_id=operation_id,
    ))


def _compatibility() -> None:
    raise _ProjectionFailure(
        ApplicationErrorCode.COMPATIBILITY_FAILURE,
        ApplicationComponent.PROJECTION,
    )


def _privacy() -> None:
    raise _ProjectionFailure(
        ApplicationErrorCode.PRIVACY_POLICY_BLOCKED,
        ApplicationComponent.PRIVACY,
    )


def _bounded_text(
    value: object,
    *,
    maximum: int = 4096,
    optional: bool = False,
) -> str | None:
    if value is None and optional:
        return None
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(
            unicodedata.category(character) in {"Cc", "Cf"}
            for character in value
        )
    ):
        _compatibility()
    return value


def _mapping(value: object, expected: frozenset[str] | None = None) -> Mapping:
    if not isinstance(value, Mapping):
        _compatibility()
    if expected is not None and set(value) != expected:
        _compatibility()
    return value


def _project_system(value: object) -> tuple[SupportedPlatform, SystemSummary]:
    system = _mapping(value)
    if set(system) - _SYSTEM_FIELDS:
        _compatibility()
    operating_system = system.get("operating_system")
    if operating_system == "Linux":
        platform = SupportedPlatform.LINUX
    elif operating_system == "Windows":
        platform = SupportedPlatform.WINDOWS
    else:
        _compatibility()
    try:
        observation = SystemObservation.from_mapping(system)
    except (TypeError, ValueError):
        _compatibility()
    return platform, SystemSummary(
        system_id=observation.system_id,
        hostname=observation.hostname,
        username=observation.username,
        operating_system=observation.operating_system,
        os_version=observation.os_version,
        architecture=observation.architecture,
        processor=observation.processor,
    )


def _project_firewall(value: object) -> FirewallTechnologySummary:
    try:
        observation = FirewallObservation.from_mapping(_mapping(value))
    except (TypeError, ValueError):
        _compatibility()
    return FirewallTechnologySummary(tuple(observation.detected_tools))


def _project_evidence(
    finding: Finding,
) -> tuple[tuple[ApplicationEvidence, ...], EvidenceProjectionState, int]:
    if not isinstance(finding.evidence, list) or not all(
        isinstance(item, str) for item in finding.evidence
    ):
        _compatibility()
    safe_items, omitted = sanitize_evidence(list(finding.evidence))
    approved = _SOURCE_EVIDENCE.get(finding.source, frozenset())
    evidence = []
    for item in safe_items:
        label, value = item.split(":", 1)
        category = _EVIDENCE_CATEGORIES.get(label.strip().casefold())
        if category is None or category not in approved:
            omitted += 1
            continue
        evidence.append(ApplicationEvidence(category, value.strip()))
    state = (
        EvidenceProjectionState.REDACTED
        if omitted
        else EvidenceProjectionState.COMPLETE
    )
    return tuple(evidence), state, omitted


def _project_network_context(value: object) -> NetworkExposureContext | None:
    if value is None:
        return None
    try:
        parsed = reachability_from_report(
            value,
            report_schema_version=CURRENT_REPORT_SCHEMA_VERSION,
        )
    except (TypeError, ValueError):
        _compatibility()
    if parsed is None:
        _compatibility()
    raw = _mapping(value)
    policy_summary = None
    if parsed.policy_assessment is not None:
        policy = parsed.policy_assessment
        policy_summary = FirewallApplicabilitySummary(
            applicability=policy.applicability,
            default_policy_context=policy.default_policy_context,
            evidence_basis=tuple(policy.evidence_basis),
            matching_rule_digests=tuple(
                match.semantic_rule_id
                for match in policy.matches
                if match.condition_match != FirewallConditionMatch.NO_MATCH
            ),
            collection_coverage=policy.collection_coverage,
            applicability_coverage=policy.applicability_coverage,
            evaluated_policy_disposition=policy.evaluated_policy_disposition,
        )
    return NetworkExposureContext(
        bind_exposure=parsed.bind_exposure,
        bind_epistemic_role=EpistemicRole(raw["bind_epistemic_role"]),
        reachability_state=parsed.state,
        reachability_epistemic_role=EpistemicRole(
            raw["reachability_epistemic_role"]
        ),
        evidence_basis=tuple(parsed.evidence_basis),
        firewall_policy=policy_summary,
    )


def _project_findings(
    value: object,
) -> tuple[tuple[ApplicationFinding, ...], tuple[ProjectionNotice, ...]]:
    if not isinstance(value, list):
        _compatibility()
    projected = []
    notices = []
    seen_ids = set()
    for finding in value:
        if not isinstance(finding, Finding):
            _compatibility()
        try:
            finding_id = canonical_finding_id(finding)
        except (TypeError, ValueError, AttributeError):
            _compatibility()
        finding_id = _bounded_text(finding_id, maximum=512)
        if contains_sensitive_marker(finding_id):
            _privacy()
        if finding_id in seen_ids:
            _compatibility()
        seen_ids.add(finding_id)
        title = _bounded_text(finding.title)
        description = _bounded_text(finding.description)
        recommendation = _bounded_text(finding.recommendation)
        source = _bounded_text(finding.source, maximum=256)
        technique_id = _bounded_text(
            finding.technique_id, maximum=256, optional=True
        )
        presentation_group_id = _bounded_text(
            finding.presentation_group_id, maximum=512, optional=True
        )
        required_text = (
            finding_id, title, description, recommendation, source,
            technique_id, presentation_group_id,
        )
        if any(
            value is not None and contains_sensitive_marker(value)
            for value in required_text
        ):
            _privacy()
        if not isinstance(finding.severity, Severity):
            _compatibility()
        if not isinstance(finding.kind, FindingKind):
            _compatibility()
        if not isinstance(finding.assessment_state, AssessmentState):
            _compatibility()
        if (
            isinstance(finding.confidence, bool)
            or not isinstance(finding.confidence, int)
            or not 0 <= finding.confidence <= 100
        ):
            _compatibility()
        evidence, evidence_state, omitted = _project_evidence(finding)
        network_context = _project_network_context(finding.network_context)
        application_finding = ApplicationFinding(
            finding_id=finding_id,
            title=title,
            description=description,
            severity=finding.severity,
            recommendation=recommendation,
            evidence=evidence,
            evidence_projection_state=evidence_state,
            omitted_evidence_count=omitted,
            confidence=finding.confidence,
            technique_id=technique_id,
            source=source,
            kind=finding.kind,
            assessment_state=finding.assessment_state,
            network_context=network_context,
            presentation_group_id=presentation_group_id,
            runtime_instance_count=finding.runtime_instance_count,
        )
        projected.append(application_finding)
        if omitted:
            notices.append(ProjectionNotice(
                ProjectionNoticeCode.EVIDENCE_REDACTED,
                finding_id,
                omitted,
            ))
    return tuple(projected), tuple(notices)


def _project_score(value: object, finding_ids: set[str]) -> SecurityScore:
    raw_score = _mapping(value)
    raw_counts = _mapping(raw_score.get("counts"))
    if set(raw_counts) != {severity.value for severity in Severity}:
        _compatibility()
    try:
        normalized = validate_serialized_security_score(
            raw_score,
            CURRENT_REPORT_SCHEMA_VERSION,
            finding_ids,
        )
    except (TypeError, ValueError):
        _compatibility()
    if normalized.get("scoring_version") != ScoringVersion.V2.value:
        _compatibility()
    breakdown = _mapping(normalized.get("breakdown"))
    categories = tuple(
        ScoreCategoryBreakdown(
            category=ScoringCategory(item["category"]),
            raw_penalty=item["raw_penalty"],
            applied_penalty=item["applied_penalty"],
            saturated=item["saturated"],
        )
        for item in breakdown["categories"]
    )
    contributors = tuple(
        ScoreContributor(
            group_id=item["group_id"],
            category=ScoringCategory(item["category"]),
            finding_ids=tuple(item["finding_ids"]),
            severity=Severity(item["severity"]),
            assessment_state=AssessmentState(item["assessment_state"]),
            atomic_penalties=tuple(item["atomic_penalties"]),
            base_penalty=item["base_penalty"],
            raw_penalty=item["raw_penalty"],
            applied_penalty=item["applied_penalty"],
            basis_code=ScoringBasisCode(item["basis_code"]),
        )
        for item in breakdown["contributors"]
    )
    raw_guardrail = _mapping(breakdown["guardrail"])
    highest = raw_guardrail["highest_confirmed_severity"]
    guardrail = ScoreGuardrail(
        highest_confirmed_severity=(Severity(highest) if highest is not None else None),
        category_applied_penalty_total=raw_guardrail[
            "category_applied_penalty_total"
        ],
        effective_penalty_total=raw_guardrail["effective_penalty_total"],
        additional_guardrail_penalty=raw_guardrail[
            "additional_guardrail_penalty"
        ],
        effective_score_ceiling=raw_guardrail["effective_score_ceiling"],
        applied=raw_guardrail["applied"],
    )
    normalized_counts = _mapping(normalized["counts"])
    return SecurityScore(
        scoring_version=ScoringVersion.V2,
        score=normalized["score"],
        risk_level=SecurityRiskLevel(normalized["risk_level"]),
        counts=tuple(
            SeverityCount(severity, normalized_counts[severity.value])
            for severity in _COUNT_ORDER
        ),
        breakdown=SecurityScoreBreakdown(
            total_effective_penalty=breakdown["total_effective_penalty"],
            categories=categories,
            contributors=contributors,
            guardrail=guardrail,
        ),
    )


def _project_coverage_and_assurance(
    raw_domains: object,
    raw_coverage: object,
    raw_assurance: object,
) -> tuple[tuple[DomainCoverage, ...], AssessmentAssuranceSummary]:
    if not isinstance(raw_domains, list) or not raw_domains:
        _compatibility()
    try:
        domains = normalize_assessment_domains(raw_domains)
    except (TypeError, ValueError):
        _compatibility()
    coverage = _mapping(raw_coverage)
    expected_keys = {domain.value for domain in domains}
    if set(coverage) != expected_keys:
        _compatibility()
    try:
        projected_coverage = tuple(
            DomainCoverage(domain, CoverageState(coverage[domain.value]))
            for domain in domains
        )
    except (TypeError, ValueError):
        _compatibility()
    assurance = _mapping(raw_assurance, frozenset({"level", "limitations"}))
    raw_limitations = assurance["limitations"]
    if not isinstance(raw_limitations, tuple) or not all(
        isinstance(item, str) for item in raw_limitations
    ):
        _compatibility()
    try:
        level = AssessmentAssurance(assurance["level"])
    except (TypeError, ValueError):
        _compatibility()
    expected_assurance = assessment_assurance_summary(coverage, raw_domains)
    if (
        assurance["level"] != expected_assurance["level"]
        or raw_limitations != expected_assurance["limitations"]
    ):
        _compatibility()
    return projected_coverage, AssessmentAssuranceSummary(
        level,
        tuple(raw_limitations),
    )


def _project_result(
    value: object,
    operation_id: str,
) -> CurrentSystemAssessmentResult:
    raw = _mapping(value, _TOP_LEVEL_FIELDS)
    platform, system = _project_system(raw["system"])
    firewall = _project_firewall(raw["firewall"])
    findings, notices = _project_findings(raw["findings"])
    finding_ids = {finding.finding_id for finding in findings}
    score = _project_score(raw["score"], finding_ids)
    coverage, assurance = _project_coverage_and_assurance(
        raw["assessment_domains"], raw["coverage"], raw["assessment_assurance"]
    )
    return CurrentSystemAssessmentResult(
        operation_id=operation_id,
        completed_at=datetime.now(timezone.utc),
        platform=platform,
        system=system,
        firewall=firewall,
        findings=findings,
        score=score,
        coverage=coverage,
        assurance=assurance,
        projection_notices=notices,
    )


class CyberWatchtowerApplication:
    """Single unprivileged facade for supported application use cases."""

    __slots__ = ()

    def __init__(self) -> None:
        pass

    def assess_current_system(
        self,
        request: CurrentSystemAssessmentRequest,
    ) -> CurrentSystemAssessmentResult:
        operation_id = _operation_id()
        if not isinstance(request, CurrentSystemAssessmentRequest):
            raise _application_error(
                operation_id,
                ApplicationErrorCode.INVALID_REQUEST,
                ApplicationComponent.APPLICATION,
            )
        try:
            raw = _AssessmentRunner().run()
        except UnsupportedPlatformError:
            raise _application_error(
                operation_id,
                ApplicationErrorCode.UNSUPPORTED_PLATFORM,
                ApplicationComponent.PLATFORM,
            ) from None
        except Exception:
            raise _application_error(
                operation_id,
                ApplicationErrorCode.INTERNAL_FAILURE,
                ApplicationComponent.ASSESSMENT,
            ) from None
        try:
            return _project_result(raw, operation_id)
        except _ProjectionFailure as failure:
            raise _application_error(
                operation_id,
                failure.code,
                failure.component,
            ) from None
        except (KeyError, TypeError, ValueError, AttributeError):
            raise _application_error(
                operation_id,
                ApplicationErrorCode.COMPATIBILITY_FAILURE,
                ApplicationComponent.PROJECTION,
            ) from None
        except Exception:
            raise _application_error(
                operation_id,
                ApplicationErrorCode.INTERNAL_FAILURE,
                ApplicationComponent.PROJECTION,
            ) from None
