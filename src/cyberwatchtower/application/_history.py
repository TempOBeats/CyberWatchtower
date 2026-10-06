"""Private, I/O-free comparison and operation identity seam for WS1-E."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timezone
from uuid import uuid4

from cyberwatchtower.finding_identity import finding_identity
from cyberwatchtower.history import (
    _DuplicateFindingIdentity,
    _compare_report_semantics,
)
from cyberwatchtower.models import AssessmentState, FindingKind, Severity

from ._memory import _TrustedReportMaterial
from ._privacy import _required_text_is_sensitive
from .contracts import (
    CompareSavedReportsRequest,
    ComparisonFindingSummary,
    ReportId,
    SavedReportComparisonResult,
    SavedReportReference,
    ScoreTrendState,
    ScoringVersion,
    _system_id,
)
from .errors import ApplicationComponent, ApplicationErrorCode


class _HistoryOperationFailure(Exception):
    """Carry only a closed, privacy-safe application failure classification."""

    def __init__(
        self,
        code: ApplicationErrorCode,
        component: ApplicationComponent,
    ) -> None:
        self.code = code
        self.component = component
        super().__init__(code.value)


def _history_failure(
    code: ApplicationErrorCode,
    component: ApplicationComponent,
) -> None:
    raise _HistoryOperationFailure(code, component)


def _history_operation_id() -> str:
    """Create correlation identity before any future request validation."""

    return f"historyop:{uuid4().hex}"


def _start_history_operation(
    request: object,
    validator: Callable[[object], bool],
) -> tuple[str, bool]:
    """Freeze generation-before-validation ordering for future facade slices."""

    operation_id = _history_operation_id()
    return operation_id, validator(request)


def _valid_compare_saved_reports_request(value: object) -> bool:
    if type(value) is not CompareSavedReportsRequest:
        return False
    try:
        _system_id(value.system_id)
        if (
            type(value.previous_report_id) is not ReportId
            or type(value.current_report_id) is not ReportId
        ):
            return False
        ReportId(value.previous_report_id.value)
        ReportId(value.current_report_id.value)
        return value.previous_report_id != value.current_report_id
    except (AttributeError, TypeError, ValueError):
        return False


def _normalized_finding_identity(finding: object) -> str:
    try:
        return finding_identity({"finding_id": finding.finding_id})
    except (AttributeError, TypeError, ValueError):
        _history_failure(
            ApplicationErrorCode.COMPATIBILITY_FAILURE,
            ApplicationComponent.PROJECTION,
        )


def _normalized_finding_source(finding: object) -> object:
    try:
        return finding.source
    except AttributeError:
        _history_failure(
            ApplicationErrorCode.COMPATIBILITY_FAILURE,
            ApplicationComponent.PROJECTION,
        )


def _project_finding(finding: object) -> ComparisonFindingSummary:
    try:
        values = (finding.finding_id, finding.title, finding.source)
        if _required_text_is_sensitive(values):
            _history_failure(
                ApplicationErrorCode.PRIVACY_POLICY_BLOCKED,
                ApplicationComponent.PRIVACY,
            )
        return ComparisonFindingSummary(
            finding_id=finding.finding_id,
            title=finding.title,
            severity=Severity(finding.severity),
            source=finding.source,
            kind=FindingKind(finding.kind),
            assessment_state=AssessmentState(finding.assessment_state),
        )
    except _HistoryOperationFailure:
        raise
    except (AttributeError, TypeError, ValueError):
        _history_failure(
            ApplicationErrorCode.COMPATIBILITY_FAILURE,
            ApplicationComponent.PROJECTION,
        )


def _compare_trusted_reports(
    *,
    operation_id: str,
    system_id: str,
    previous: _TrustedReportMaterial,
    current: _TrustedReportMaterial,
) -> SavedReportComparisonResult:
    if (
        type(previous) is not _TrustedReportMaterial
        or type(current) is not _TrustedReportMaterial
        or previous.system_id != system_id
        or current.system_id != system_id
        or previous.normalized_report.native_system_id != system_id
        or current.normalized_report.native_system_id != system_id
    ):
        _history_failure(
            ApplicationErrorCode.INTEGRITY_FAILURE,
            ApplicationComponent.STORAGE,
        )
    previous_key = (
        previous.generated_at.astimezone(timezone.utc),
        previous.report_id.value,
    )
    current_key = (
        current.generated_at.astimezone(timezone.utc),
        current.report_id.value,
    )
    if previous_key >= current_key:
        _history_failure(
            ApplicationErrorCode.INVALID_REQUEST,
            ApplicationComponent.APPLICATION,
        )

    previous_report = previous.normalized_report
    current_report = current.normalized_report
    try:
        semantics = _compare_report_semantics(
            previous_score=previous_report.score.score,
            current_score=current_report.score.score,
            previous_scoring_version=previous_report.score.scoring_version,
            current_scoring_version=current_report.score.scoring_version,
            previous_risk=previous_report.score.risk_level,
            current_risk=current_report.score.risk_level,
            previous_findings=previous_report.findings,
            current_findings=current_report.findings,
            current_coverage=dict(current_report.coverage),
            current_assessment_domains=tuple(
                domain for domain, _state in current_report.coverage
            ),
            identity_of=_normalized_finding_identity,
            source_of=_normalized_finding_source,
            reject_duplicate_identities=True,
        )
    except _HistoryOperationFailure:
        raise
    except _DuplicateFindingIdentity:
        _history_failure(
            ApplicationErrorCode.INTEGRITY_FAILURE,
            ApplicationComponent.PROJECTION,
        )
    except (AttributeError, TypeError, ValueError):
        _history_failure(
            ApplicationErrorCode.COMPATIBILITY_FAILURE,
            ApplicationComponent.PROJECTION,
        )

    try:
        return SavedReportComparisonResult(
            operation_id=operation_id,
            system_id=system_id,
            previous_report=SavedReportReference(
                previous.report_id,
                previous.generated_at,
            ),
            current_report=SavedReportReference(
                current.report_id,
                current.generated_at,
            ),
            previous_score=semantics.previous_score,
            current_score=semantics.current_score,
            previous_risk=semantics.previous_risk,
            current_risk=semantics.current_risk,
            previous_scoring_version=ScoringVersion(
                semantics.previous_scoring_version
            ),
            current_scoring_version=ScoringVersion(
                semantics.current_scoring_version
            ),
            score_trend=ScoreTrendState(semantics.score_trend),
            score_change=semantics.score_change,
            added_findings=tuple(
                _project_finding(finding)
                for finding in semantics.added_findings
            ),
            resolved_findings=tuple(
                _project_finding(finding)
                for finding in semantics.resolved_findings
            ),
            uncertain_disappearances=tuple(
                _project_finding(finding)
                for finding in semantics.uncertain_findings
            ),
        )
    except _HistoryOperationFailure:
        raise
    except (AttributeError, TypeError, ValueError):
        _history_failure(
            ApplicationErrorCode.COMPATIBILITY_FAILURE,
            ApplicationComponent.PROJECTION,
        )
