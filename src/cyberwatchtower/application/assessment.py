"""Minimal current-system assessment use case over the existing scanner authority."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timezone
import unicodedata
from uuid import uuid4

from cyberwatchtower import scanner
from cyberwatchtower.models import AssessmentState, Finding, FindingKind, Severity
from cyberwatchtower.platform.errors import UnsupportedPlatformError
from cyberwatchtower.platform.models import FirewallObservation, SystemObservation
from cyberwatchtower.report_contracts import (
    CURRENT_REPORT_SCHEMA_VERSION,
    AssessmentAssurance,
    CoverageState,
    assessment_assurance_summary,
    normalize_assessment_domains,
)
from cyberwatchtower.scoring_contracts import ScoringVersion
from cyberwatchtower.scoring_projection import canonical_finding_id
from cyberwatchtower.scoring_report import validate_serialized_security_score

from .contracts import (
    ApplicationFinding,
    AssessmentAssuranceSummary,
    CurrentSystemAssessmentRequest,
    CurrentSystemAssessmentResult,
    DomainCoverage,
    FirewallTechnologySummary,
    GetLatestSavedReportRequest,
    GetSavedReportRequest,
    ListSavedReportsRequest,
    ProjectionNotice,
    ProjectionNoticeCode,
    ReportCatalogCompleteness,
    ReportId,
    SavedCurrentSystemAssessmentResult,
    SavedReportCatalog,
    SavedReportDetail,
    SecurityRiskLevel,
    SecurityScore,
    SeverityCount,
    SupportedPlatform,
    SystemSummary,
    _system_id,
)
from .errors import (
    ApplicationComponent,
    ApplicationErrorCode,
    ApplicationFailure,
    CyberWatchtowerApplicationError,
)
from ._privacy import _project_evidence, _required_text_is_sensitive
from . import reports as _reports


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


def _report_operation_id() -> str:
    return f"reportop:{uuid4().hex}"


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


def _report_application_error(
    operation_id: str,
    code: ApplicationErrorCode,
    component: ApplicationComponent,
) -> CyberWatchtowerApplicationError:
    messages = {
        ApplicationErrorCode.INVALID_REQUEST: (
            "The saved-report request does not match the supported operation."
        ),
        ApplicationErrorCode.NOT_FOUND: (
            "The requested saved report was not found."
        ),
        ApplicationErrorCode.CONFLICT: (
            "A canonical saved report name could not be reserved."
        ),
        ApplicationErrorCode.PERMISSION_DENIED: (
            "The saved-report store could not be read because access was denied."
        ),
        ApplicationErrorCode.COMPATIBILITY_FAILURE: (
            "A saved report did not match the supported compatibility contract."
        ),
        ApplicationErrorCode.INTEGRITY_FAILURE: (
            "Saved-report integrity could not be established."
        ),
        ApplicationErrorCode.STORAGE_FAILURE: (
            "The saved-report store could not be read."
        ),
        ApplicationErrorCode.PRIVACY_POLICY_BLOCKED: (
            "Required saved-report data could not cross the application privacy boundary."
        ),
        ApplicationErrorCode.INTERNAL_FAILURE: (
            "The saved-report operation could not be completed."
        ),
    }
    return CyberWatchtowerApplicationError(ApplicationFailure(
        code=code,
        message=messages[code],
        retryable=False,
        component=component,
        operation_id=operation_id,
    ))


def _valid_list_saved_reports_request(value: object) -> bool:
    if type(value) is not ListSavedReportsRequest:
        return False
    try:
        _system_id(value.system_id)
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def _valid_get_saved_report_request(value: object) -> bool:
    if type(value) is not GetSavedReportRequest:
        return False
    try:
        if type(value.report_id) is not ReportId:
            return False
        ReportId(value.report_id.value)
        _system_id(value.expected_system_id, "expected_system_id")
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def _valid_get_latest_saved_report_request(value: object) -> bool:
    if type(value) is not GetLatestSavedReportRequest:
        return False
    try:
        _system_id(value.system_id)
    except (AttributeError, TypeError, ValueError):
        return False
    return True


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
        if _required_text_is_sensitive(required_text):
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
        try:
            evidence, evidence_state, omitted = _project_evidence(
                finding.source,
                finding.evidence,
            )
        except (TypeError, ValueError):
            _compatibility()
        try:
            network_context = _reports._project_network_context(
                finding.network_context,
                report_schema_version=CURRENT_REPORT_SCHEMA_VERSION,
            )
        except _reports._ReportOperationFailure:
            _compatibility()
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
    normalized_counts = _mapping(normalized["counts"])
    try:
        breakdown = _reports._project_score_breakdown(normalized)
    except _reports._ReportOperationFailure:
        _compatibility()
    return SecurityScore(
        scoring_version=ScoringVersion.V2,
        score=normalized["score"],
        risk_level=SecurityRiskLevel(normalized["risk_level"]),
        counts=tuple(
            SeverityCount(severity, normalized_counts[severity.value])
            for severity in _COUNT_ORDER
        ),
        breakdown=breakdown,
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


def _run_current_system_assessment(
    request: CurrentSystemAssessmentRequest,
    operation_id: str,
) -> tuple[dict, CurrentSystemAssessmentResult]:
    if not isinstance(request, CurrentSystemAssessmentRequest):
        raise _application_error(
            operation_id,
            ApplicationErrorCode.INVALID_REQUEST,
            ApplicationComponent.APPLICATION,
        )
    try:
        raw = _AssessmentRunner().run()
    except UnsupportedPlatformError:
        public_error = _application_error(
            operation_id,
            ApplicationErrorCode.UNSUPPORTED_PLATFORM,
            ApplicationComponent.PLATFORM,
        )
    except Exception:
        public_error = _application_error(
            operation_id,
            ApplicationErrorCode.INTERNAL_FAILURE,
            ApplicationComponent.ASSESSMENT,
        )
    else:
        public_error = None
    if public_error is not None:
        raise public_error

    try:
        return raw, _project_result(raw, operation_id)
    except _ProjectionFailure as failure:
        public_error = _application_error(
            operation_id,
            failure.code,
            failure.component,
        )
    except (KeyError, TypeError, ValueError, AttributeError):
        public_error = _application_error(
            operation_id,
            ApplicationErrorCode.COMPATIBILITY_FAILURE,
            ApplicationComponent.PROJECTION,
        )
    except Exception:
        public_error = _application_error(
            operation_id,
            ApplicationErrorCode.INTERNAL_FAILURE,
            ApplicationComponent.PROJECTION,
        )
    raise public_error


def _authoritative_system_id(raw: object) -> str:
    try:
        system = _mapping(raw)["system"]
        system_id = _mapping(system)["system_id"]
        _system_id(system_id)
    except (KeyError, TypeError, ValueError, AttributeError):
        raise _ProjectionFailure(
            ApplicationErrorCode.COMPATIBILITY_FAILURE,
            ApplicationComponent.PROJECTION,
        ) from None
    return system_id


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
        _raw, result = _run_current_system_assessment(request, operation_id)
        return result

    def assess_and_save_current_system(
        self,
        request: CurrentSystemAssessmentRequest,
    ) -> SavedCurrentSystemAssessmentResult:
        operation_id = _operation_id()
        raw, assessment = _run_current_system_assessment(request, operation_id)
        try:
            expected_system_id = _authoritative_system_id(raw)
        except _ProjectionFailure as failure:
            public_error = _application_error(
                operation_id,
                failure.code,
                failure.component,
            )
        else:
            public_error = None
        if public_error is not None:
            raise public_error

        try:
            repository = _reports._default_report_repository()
            stored = repository.save_scanner_result(raw)
            if stored.summary.system_id != expected_system_id:
                raise _reports._ReportOperationFailure(
                    ApplicationErrorCode.INTEGRITY_FAILURE,
                    ApplicationComponent.STORAGE,
                )
            return SavedCurrentSystemAssessmentResult(
                assessment=assessment,
                report=stored.summary,
            )
        except _reports._ReportOperationFailure as failure:
            public_error = _report_application_error(
                operation_id,
                failure.code,
                failure.component,
            )
        except Exception:
            public_error = _report_application_error(
                operation_id,
                ApplicationErrorCode.INTERNAL_FAILURE,
                ApplicationComponent.STORAGE,
            )
        raise public_error

    def list_saved_reports(
        self,
        request: ListSavedReportsRequest,
    ) -> SavedReportCatalog:
        operation_id = _report_operation_id()
        if not _valid_list_saved_reports_request(request):
            raise _report_application_error(
                operation_id,
                ApplicationErrorCode.INVALID_REQUEST,
                ApplicationComponent.APPLICATION,
            )
        try:
            repository = _reports._default_report_repository()
            snapshot = repository.catalog_for_system(request.system_id)
            return snapshot.public_catalog(operation_id)
        except _reports._ReportOperationFailure as failure:
            public_error = _report_application_error(
                operation_id,
                failure.code,
                failure.component,
            )
        except Exception:
            public_error = _report_application_error(
                operation_id,
                ApplicationErrorCode.INTERNAL_FAILURE,
                ApplicationComponent.STORAGE,
            )
        raise public_error

    def get_saved_report(
        self,
        request: GetSavedReportRequest,
    ) -> SavedReportDetail:
        operation_id = _report_operation_id()
        if not _valid_get_saved_report_request(request):
            raise _report_application_error(
                operation_id,
                ApplicationErrorCode.INVALID_REQUEST,
                ApplicationComponent.APPLICATION,
            )
        try:
            repository = _reports._default_report_repository()
            snapshot = repository.catalog_for_system(request.expected_system_id)
            stored = snapshot.find(request.report_id)
            if stored is None:
                code = (
                    ApplicationErrorCode.INTEGRITY_FAILURE
                    if snapshot.completeness == ReportCatalogCompleteness.INCOMPLETE
                    else ApplicationErrorCode.NOT_FOUND
                )
                raise _reports._ReportOperationFailure(
                    code,
                    ApplicationComponent.STORAGE,
                )
            return repository.read_detail(
                stored,
                operation_id=operation_id,
                expected_system_id=request.expected_system_id,
            )
        except _reports._ReportOperationFailure as failure:
            public_error = _report_application_error(
                operation_id,
                failure.code,
                failure.component,
            )
        except Exception:
            public_error = _report_application_error(
                operation_id,
                ApplicationErrorCode.INTERNAL_FAILURE,
                ApplicationComponent.STORAGE,
            )
        raise public_error

    def get_latest_saved_report(
        self,
        request: GetLatestSavedReportRequest,
    ) -> SavedReportDetail | None:
        operation_id = _report_operation_id()
        if not _valid_get_latest_saved_report_request(request):
            raise _report_application_error(
                operation_id,
                ApplicationErrorCode.INVALID_REQUEST,
                ApplicationComponent.APPLICATION,
            )
        try:
            repository = _reports._default_report_repository()
            snapshot = repository.catalog_for_system(request.system_id)
            if snapshot.completeness == ReportCatalogCompleteness.INCOMPLETE:
                raise _reports._ReportOperationFailure(
                    ApplicationErrorCode.INTEGRITY_FAILURE,
                    ApplicationComponent.STORAGE,
                )
            if not snapshot.reports:
                return None
            return repository.read_detail(
                snapshot.reports[-1],
                operation_id=operation_id,
                expected_system_id=request.system_id,
            )
        except _reports._ReportOperationFailure as failure:
            public_error = _report_application_error(
                operation_id,
                failure.code,
                failure.component,
            )
        except Exception:
            public_error = _report_application_error(
                operation_id,
                ApplicationErrorCode.INTERNAL_FAILURE,
                ApplicationComponent.STORAGE,
            )
        raise public_error
