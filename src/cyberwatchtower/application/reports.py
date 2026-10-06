"""Private bounded read boundary for canonical CyberWatchtower reports."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Protocol

import cyberwatchtower.reporting as reporting
from cyberwatchtower.core.evidence import EpistemicRole
from cyberwatchtower.firewall_policy import FirewallConditionMatch
from cyberwatchtower.memory.normalizers import (
    ReportValidationError,
    UnsupportedReportSchema,
    normalize_report,
)
from cyberwatchtower.models import AssessmentState, FindingKind, Severity
from cyberwatchtower.reachability import reachability_from_report
from cyberwatchtower.report_contracts import (
    CURRENT_REPORT_SCHEMA_VERSION,
    AssessmentAssurance,
    CoverageState,
    ScanDomain,
    assessment_assurance_summary,
    canonical_report_bytes,
    canonical_report_digest,
    normalize_assessment_domains,
)
from cyberwatchtower.scoring_contracts import (
    ScoringBasisCode,
    ScoringCategory,
    ScoringVersion,
)
from cyberwatchtower.scoring_report import validate_serialized_security_score

from ._privacy import _project_evidence, _required_text_is_sensitive
from ._memory import _TrustedReportMaterial
from .contracts import (
    AssessmentAssuranceSummary,
    DomainCoverage,
    FirewallApplicabilitySummary,
    NetworkExposureContext,
    ProjectionNotice,
    ProjectionNoticeCode,
    ReportCatalogCompleteness,
    ReportCompatibilityState,
    ReportId,
    SavedReportCatalog,
    SavedReportCatalogDiagnostics,
    SavedReportCompatibility,
    SavedReportDetail,
    SavedReportField,
    SavedReportFinding,
    SavedReportScore,
    SavedReportSummary,
    SavedReportSystemSummary,
    ScoreCategoryBreakdown,
    ScoreContributor,
    ScoreGuardrail,
    SecurityScoreBreakdown,
    SeverityCount,
    _system_id,
)
from .errors import ApplicationComponent, ApplicationErrorCode


MAX_REPORT_BYTES = 10 * 1024 * 1024
MAX_REPORT_CANDIDATES = 4096
_DEFAULT_REPORT_ROOT = Path("reports")
_NOFOLLOW_FLAG = getattr(os, "O_NOFOLLOW", 0)
_SCANDIR_SUPPORTS_FD = os.scandir in os.supports_fd
_RELATIVE_OPEN_SUPPORTED = os.open in os.supports_dir_fd
_RELATIVE_LSTAT_SUPPORTED = (
    os.stat in os.supports_dir_fd
    and os.stat in os.supports_follow_symlinks
)


def _race_safe_report_open_flags() -> int | None:
    """Return fail-closed flags for mutable report entries."""

    no_follow = getattr(os, "O_NOFOLLOW", None)
    nonblocking = getattr(os, "O_NONBLOCK", None)
    if (
        type(no_follow) is not int
        or no_follow <= 0
        or type(nonblocking) is not int
        or nonblocking <= 0
    ):
        return None
    flags = os.O_RDONLY | no_follow | nonblocking
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


class _ReportOperationFailure(Exception):
    """Carry only a closed safe failure classification to the facade."""

    def __init__(
        self,
        code: ApplicationErrorCode,
        component: ApplicationComponent,
    ) -> None:
        self.code = code
        self.component = component
        super().__init__(code.value)


class _CandidateIssue(str, Enum):
    MALFORMED = "malformed"
    UNSUPPORTED = "unsupported"
    OVERSIZED = "oversized"
    PERMISSION_DENIED = "permission_denied"
    IO_ERROR = "io_error"
    SYMLINK = "symlink"
    NONREGULAR = "nonregular"
    DISAPPEARED = "disappeared"
    UNRESOLVED_SYSTEM = "unresolved_system"


class _CandidateReadFailure(Exception):
    def __init__(self, issue: _CandidateIssue) -> None:
        self.issue = issue
        super().__init__(issue.value)


@dataclass(frozen=True, slots=True)
class _FileIdentity:
    device: int
    inode: int
    size: int


@dataclass(frozen=True, slots=True)
class _RootIdentity:
    device: int
    inode: int


@dataclass(frozen=True, slots=True)
class _TrustedRoot:
    resolved_path: Path
    identity: _RootIdentity


@dataclass(slots=True)
class _TrustedRootHandle:
    trusted_root: _TrustedRoot
    directory_descriptor: int

    def descriptor(self) -> int:
        if self.directory_descriptor < 0:
            _integrity_failure()
        return self.directory_descriptor

    def close(self) -> None:
        descriptor = self.directory_descriptor
        self.directory_descriptor = -1
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


@dataclass(frozen=True, slots=True)
class _AbsentRoot:
    anchor: Path
    resolved_anchor: Path
    anchor_identity: _RootIdentity
    relative_parts: tuple[str, ...]


_RootState = _TrustedRoot | _AbsentRoot


@dataclass(frozen=True, slots=True)
class _ValidatedCandidate:
    path: Path
    file_identity: _FileIdentity
    raw_report: Mapping[str, object]
    normalized_report: object
    report_id: ReportId
    canonical_bytes: bytes
    generated_at: datetime
    system_id: str
    compatibility: SavedReportCompatibility
    summary: SavedReportSummary


@dataclass(frozen=True, slots=True)
class _StoredReport:
    report_id: ReportId
    summary: SavedReportSummary
    canonical_bytes: bytes
    candidates: tuple[_ValidatedCandidate, ...]
    trusted_root: _TrustedRoot


@dataclass(frozen=True, slots=True)
class _ReportCatalogSnapshot:
    repository: _FileReportRepository
    root_state: _RootState
    stored_reports: tuple[_StoredReport, ...]
    catalog_completeness: ReportCatalogCompleteness
    catalog_omitted_count: int
    catalog_diagnostics: SavedReportCatalogDiagnostics

    def _revalidate(self) -> None:
        self.repository._revalidate_root_state(self.root_state)

    @property
    def reports(self) -> tuple[_StoredReport, ...]:
        self._revalidate()
        return self.stored_reports

    @property
    def completeness(self) -> ReportCatalogCompleteness:
        self._revalidate()
        return self.catalog_completeness

    @property
    def omitted_count(self) -> int:
        self._revalidate()
        return self.catalog_omitted_count

    @property
    def diagnostics(self) -> SavedReportCatalogDiagnostics:
        self._revalidate()
        return self.catalog_diagnostics

    def public_catalog(self, operation_id: str) -> SavedReportCatalog:
        self._revalidate()
        return SavedReportCatalog(
            operation_id=operation_id,
            reports=tuple(item.summary for item in self.stored_reports),
            completeness=self.catalog_completeness,
            omitted_count=self.catalog_omitted_count,
            diagnostics=self.catalog_diagnostics,
        )

    def find(self, report_id: ReportId) -> _StoredReport | None:
        self._revalidate()
        return next(
            (item for item in self.stored_reports if item.report_id == report_id),
            None,
        )


class _ReportRepositoryPort(Protocol):
    def save_scanner_result(self, scanner_result: dict) -> _StoredReport:
        ...

    def catalog_for_system(self, system_id: str) -> _ReportCatalogSnapshot:
        ...

    def read_detail(
        self,
        stored: _StoredReport,
        *,
        operation_id: str,
        expected_system_id: str,
    ) -> SavedReportDetail:
        ...

    def read_trusted_material(
        self,
        snapshot: _ReportCatalogSnapshot,
        *,
        report_id: ReportId,
        expected_system_id: str,
    ) -> _TrustedReportMaterial:
        """Return pathless material securely revalidated from one snapshot."""

        ...


class _DiagnosticCounts:
    __slots__ = ("_counts",)

    def __init__(self) -> None:
        self._counts = {issue: 0 for issue in _CandidateIssue}

    def add(self, issue: _CandidateIssue) -> None:
        self._counts[issue] += 1

    @property
    def omitted_count(self) -> int:
        return sum(self._counts.values())

    def public(self, duplicate_count: int) -> SavedReportCatalogDiagnostics:
        return SavedReportCatalogDiagnostics(
            malformed_count=self._counts[_CandidateIssue.MALFORMED],
            unsupported_count=self._counts[_CandidateIssue.UNSUPPORTED],
            oversized_count=self._counts[_CandidateIssue.OVERSIZED],
            permission_denied_count=self._counts[_CandidateIssue.PERMISSION_DENIED],
            io_error_count=self._counts[_CandidateIssue.IO_ERROR],
            symlink_count=self._counts[_CandidateIssue.SYMLINK],
            nonregular_count=self._counts[_CandidateIssue.NONREGULAR],
            disappeared_count=self._counts[_CandidateIssue.DISAPPEARED],
            unresolved_system_count=self._counts[
                _CandidateIssue.UNRESOLVED_SYSTEM
            ],
            duplicate_count=duplicate_count,
        )


def _integrity_failure() -> None:
    raise _ReportOperationFailure(
        ApplicationErrorCode.INTEGRITY_FAILURE,
        ApplicationComponent.STORAGE,
    )


def _storage_failure() -> None:
    raise _ReportOperationFailure(
        ApplicationErrorCode.STORAGE_FAILURE,
        ApplicationComponent.STORAGE,
    )


def _permission_failure() -> None:
    raise _ReportOperationFailure(
        ApplicationErrorCode.PERMISSION_DENIED,
        ApplicationComponent.STORAGE,
    )


def _not_found_failure() -> None:
    raise _ReportOperationFailure(
        ApplicationErrorCode.NOT_FOUND,
        ApplicationComponent.STORAGE,
    )


def _compatibility_failure() -> None:
    raise _ReportOperationFailure(
        ApplicationErrorCode.COMPATIBILITY_FAILURE,
        ApplicationComponent.PROJECTION,
    )


def _privacy_failure() -> None:
    raise _ReportOperationFailure(
        ApplicationErrorCode.PRIVACY_POLICY_BLOCKED,
        ApplicationComponent.PRIVACY,
    )


def _conflict_failure() -> None:
    raise _ReportOperationFailure(
        ApplicationErrorCode.CONFLICT,
        ApplicationComponent.STORAGE,
    )


def _publication_compatibility_failure() -> None:
    raise _ReportOperationFailure(
        ApplicationErrorCode.COMPATIBILITY_FAILURE,
        ApplicationComponent.STORAGE,
    )


def _utc_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError):
        raise _CandidateReadFailure(_CandidateIssue.MALFORMED) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise _CandidateReadFailure(_CandidateIssue.MALFORMED)
    return parsed.astimezone(timezone.utc)


def _project_coverage(normalized_report: object) -> tuple[DomainCoverage, ...]:
    try:
        return tuple(
            DomainCoverage(ScanDomain(domain), CoverageState(state))
            for domain, state in normalized_report.coverage
        )
    except (AttributeError, TypeError, ValueError):
        _compatibility_failure()


def _project_assurance(
    raw_report: Mapping[str, object],
    normalized_report: object,
) -> AssessmentAssuranceSummary | None:
    if "assessment_assurance" not in raw_report:
        return None
    raw_assurance = raw_report.get("assessment_assurance")
    if not isinstance(raw_assurance, Mapping) or set(raw_assurance) != {
        "level", "limitations",
    }:
        _compatibility_failure()
    limitations = raw_assurance.get("limitations")
    if not isinstance(limitations, (list, tuple)) or not all(
        isinstance(item, str) for item in limitations
    ):
        _compatibility_failure()
    try:
        level = AssessmentAssurance(raw_assurance.get("level"))
        domains = normalize_assessment_domains(raw_report.get("assessment_domains"))
        expected = assessment_assurance_summary(
            dict(normalized_report.coverage),
            domains,
        )
    except (AttributeError, TypeError, ValueError):
        _compatibility_failure()
    if (
        level.value != expected["level"]
        or tuple(limitations) != tuple(expected["limitations"])
    ):
        _compatibility_failure()
    try:
        return AssessmentAssuranceSummary(level, tuple(limitations))
    except (TypeError, ValueError):
        _compatibility_failure()


def _compatibility_metadata(
    raw_report: Mapping[str, object],
    normalized_report: object,
) -> SavedReportCompatibility:
    defaulted: set[SavedReportField] = set()
    unavailable: set[SavedReportField] = set()
    raw_coverage = raw_report.get("coverage")
    normalized_domains = {
        domain for domain, _state in normalized_report.coverage
    }
    if "assessment_domains" not in raw_report:
        defaulted.add(SavedReportField.ASSESSMENT_DOMAINS)
    if not isinstance(raw_coverage, Mapping) or set(raw_coverage) != normalized_domains:
        defaulted.add(SavedReportField.COVERAGE)
    raw_findings = raw_report.get("findings")
    if any(item.metadata_inferred for item in normalized_report.findings):
        defaulted.add(SavedReportField.FINDING_METADATA)
    if not isinstance(raw_findings, list) or any(
        not isinstance(item, Mapping) or "runtime_instance_count" not in item
        for item in raw_findings
    ):
        defaulted.add(SavedReportField.RUNTIME_MULTIPLICITY)
    raw_score = raw_report.get("security_score")
    if not isinstance(raw_score, Mapping):
        _compatibility_failure()
    if "scoring_version" not in raw_score:
        defaulted.add(SavedReportField.SCORING_VERSION)
    if "risk_level" not in raw_score:
        defaulted.add(SavedReportField.RISK_LEVEL)
    raw_counts = raw_score.get("counts")
    if not isinstance(raw_counts, Mapping) or set(raw_counts) != {
        severity.value for severity in Severity
    }:
        defaulted.add(SavedReportField.SEVERITY_COUNTS)
    if "assessment_assurance" not in raw_report:
        unavailable.add(SavedReportField.ASSURANCE)
    if normalized_report.score.scoring_version == ScoringVersion.V1.value:
        unavailable.add(SavedReportField.SCORING_BREAKDOWN)

    order = tuple(SavedReportField)
    return SavedReportCompatibility(
        state=(
            ReportCompatibilityState.CURRENT
            if normalized_report.schema_version == CURRENT_REPORT_SCHEMA_VERSION
            else ReportCompatibilityState.LEGACY_NORMALIZED
        ),
        defaulted_fields=tuple(item for item in order if item in defaulted),
        unavailable_fields=tuple(item for item in order if item in unavailable),
    )


def _project_score_breakdown(value: Mapping[str, object]) -> SecurityScoreBreakdown:
    try:
        raw_breakdown = value["breakdown"]
        categories = tuple(
            ScoreCategoryBreakdown(
                category=ScoringCategory(item["category"]),
                raw_penalty=item["raw_penalty"],
                applied_penalty=item["applied_penalty"],
                saturated=item["saturated"],
            )
            for item in raw_breakdown["categories"]
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
            for item in raw_breakdown["contributors"]
        )
        raw_guardrail = raw_breakdown["guardrail"]
        highest = raw_guardrail["highest_confirmed_severity"]
        guardrail = ScoreGuardrail(
            highest_confirmed_severity=(
                Severity(highest) if highest is not None else None
            ),
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
        return SecurityScoreBreakdown(
            total_effective_penalty=raw_breakdown["total_effective_penalty"],
            categories=categories,
            contributors=contributors,
            guardrail=guardrail,
        )
    except (KeyError, TypeError, ValueError):
        _compatibility_failure()


def _project_saved_score(
    raw_report: Mapping[str, object],
    normalized_report: object,
) -> SavedReportScore:
    try:
        version = ScoringVersion(normalized_report.score.scoring_version)
        counts = tuple(
            SeverityCount(Severity(severity), count)
            for severity, count in normalized_report.score.counts
        )
    except (AttributeError, TypeError, ValueError):
        _compatibility_failure()
    breakdown = None
    if version == ScoringVersion.V2:
        try:
            normalized_score = validate_serialized_security_score(
                raw_report.get("security_score"),
                normalized_report.schema_version,
                {finding.finding_id for finding in normalized_report.findings},
            )
        except (TypeError, ValueError):
            _compatibility_failure()
        breakdown = _project_score_breakdown(normalized_score)
    try:
        return SavedReportScore(
            scoring_version=version,
            score=normalized_report.score.score,
            risk_level=normalized_report.score.risk_level,
            counts=counts,
            breakdown=breakdown,
        )
    except (TypeError, ValueError):
        _compatibility_failure()


def _project_network_context(
    value: object,
    *,
    report_schema_version: str,
) -> NetworkExposureContext | None:
    if value is None:
        return None
    try:
        parsed = reachability_from_report(
            value,
            report_schema_version=report_schema_version,
        )
    except (TypeError, ValueError):
        _compatibility_failure()
    if parsed is None or not isinstance(value, Mapping):
        _compatibility_failure()
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
    try:
        return NetworkExposureContext(
            bind_exposure=parsed.bind_exposure,
            bind_epistemic_role=EpistemicRole(value["bind_epistemic_role"]),
            reachability_state=parsed.state,
            reachability_epistemic_role=EpistemicRole(
                value["reachability_epistemic_role"]
            ),
            evidence_basis=tuple(parsed.evidence_basis),
            firewall_policy=policy_summary,
        )
    except (KeyError, TypeError, ValueError):
        _compatibility_failure()


def _project_findings(
    raw_report: Mapping[str, object],
    normalized_report: object,
) -> tuple[tuple[SavedReportFinding, ...], tuple[ProjectionNotice, ...]]:
    raw_findings = raw_report.get("findings")
    if not isinstance(raw_findings, list) or len(raw_findings) != len(
        normalized_report.findings
    ):
        _compatibility_failure()
    projected = []
    notices = []
    for raw_finding, normalized in zip(raw_findings, normalized_report.findings):
        if not isinstance(raw_finding, Mapping):
            _compatibility_failure()
        description = normalized.description or None
        recommendation = normalized.recommendation or None
        required_text = (
            normalized.finding_id,
            normalized.title,
            description,
            recommendation,
            normalized.source,
            normalized.technique_id,
        )
        if _required_text_is_sensitive(required_text):
            _privacy_failure()
        try:
            evidence, evidence_state, omitted = _project_evidence(
                normalized.source,
                raw_finding.get("evidence", []),
            )
        except (TypeError, ValueError):
            _compatibility_failure()
        network_context = _project_network_context(
            raw_finding.get("network_context"),
            report_schema_version=normalized_report.schema_version,
        )
        try:
            finding = SavedReportFinding(
                finding_id=normalized.finding_id,
                title=normalized.title,
                description=description,
                severity=Severity(normalized.severity),
                recommendation=recommendation,
                evidence=evidence,
                evidence_projection_state=evidence_state,
                omitted_evidence_count=omitted,
                confidence=normalized.confidence,
                technique_id=normalized.technique_id,
                source=normalized.source,
                kind=FindingKind(normalized.kind),
                assessment_state=AssessmentState(normalized.assessment_state),
                metadata_inferred=normalized.metadata_inferred,
                network_context=network_context,
                runtime_instance_count=normalized.runtime_instance_count,
            )
        except (TypeError, ValueError):
            _compatibility_failure()
        projected.append(finding)
        if omitted:
            notices.append(ProjectionNotice(
                ProjectionNoticeCode.EVIDENCE_REDACTED,
                normalized.finding_id,
                omitted,
            ))
    return tuple(projected), tuple(notices)


def _project_summary(
    report_id: ReportId,
    generated_at: datetime,
    normalized_report: object,
    compatibility: SavedReportCompatibility,
    assurance: AssessmentAssuranceSummary | None,
) -> SavedReportSummary:
    try:
        return SavedReportSummary(
            report_id=report_id,
            generated_at=generated_at,
            schema_version=normalized_report.schema_version,
            system_id=normalized_report.native_system_id,
            scoring_version=ScoringVersion(
                normalized_report.score.scoring_version
            ),
            score=normalized_report.score.score,
            risk_level=normalized_report.score.risk_level,
            finding_count=len(normalized_report.findings),
            coverage=_project_coverage(normalized_report),
            assurance=assurance,
            compatibility=compatibility,
        )
    except (AttributeError, TypeError, ValueError):
        _compatibility_failure()


def _project_detail(
    candidate: _ValidatedCandidate,
    *,
    operation_id: str,
) -> SavedReportDetail:
    normalized = candidate.normalized_report
    if _required_text_is_sensitive((normalized.native_system_id, normalized.hostname)):
        _privacy_failure()
    findings, notices = _project_findings(candidate.raw_report, normalized)
    assurance = _project_assurance(candidate.raw_report, normalized)
    try:
        return SavedReportDetail(
            operation_id=operation_id,
            report_id=candidate.report_id,
            generated_at=candidate.generated_at,
            schema_version=normalized.schema_version,
            system=SavedReportSystemSummary(
                normalized.native_system_id,
                normalized.hostname,
            ),
            findings=findings,
            score=_project_saved_score(candidate.raw_report, normalized),
            coverage=_project_coverage(normalized),
            assurance=assurance,
            compatibility=candidate.compatibility,
            projection_notices=notices,
        )
    except (AttributeError, TypeError, ValueError):
        _compatibility_failure()


class _FileReportRepository:
    __slots__ = ("_root",)

    def __init__(self, root: Path) -> None:
        if not isinstance(root, Path):
            raise TypeError("private report root must be a Path.")
        self._root = root

    @staticmethod
    def _identity(value: os.stat_result) -> _RootIdentity:
        device = value.st_dev
        inode = value.st_ino
        if (
            not isinstance(device, int)
            or isinstance(device, bool)
            or device < 0
            or not isinstance(inode, int)
            or isinstance(inode, bool)
            or inode <= 0
        ):
            _integrity_failure()
        return _RootIdentity(device, inode)

    def _absent_root(self) -> _AbsentRoot:
        anchor = self._root.parent
        while True:
            try:
                resolved_anchor = anchor.resolve(strict=True)
                anchor_stat = anchor.stat()
                if not stat.S_ISDIR(anchor_stat.st_mode):
                    _integrity_failure()
                try:
                    relative_parts = self._root.relative_to(anchor).parts
                except ValueError:
                    _integrity_failure()
                if not relative_parts or any(
                    part in ("", ".", "..") for part in relative_parts
                ):
                    _integrity_failure()
                return _AbsentRoot(
                    anchor=anchor,
                    resolved_anchor=resolved_anchor,
                    anchor_identity=self._identity(anchor_stat),
                    relative_parts=relative_parts,
                )
            except FileNotFoundError:
                parent = anchor.parent
                if parent == anchor:
                    _integrity_failure()
                anchor = parent
            except PermissionError:
                _permission_failure()
            except OSError:
                _storage_failure()

    def _resolved_root(self, *, missing_is_empty: bool) -> _RootState:
        try:
            root_stat = self._root.lstat()
        except FileNotFoundError:
            if missing_is_empty:
                absent = self._absent_root()
                self._revalidate_absent_root(absent)
                return absent
            _integrity_failure()
        except PermissionError:
            _permission_failure()
        except OSError:
            _storage_failure()
        if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
            _integrity_failure()
        try:
            resolved_root = self._root.resolve(strict=True)
            current_stat = self._root.lstat()
        except FileNotFoundError:
            _integrity_failure()
        except PermissionError:
            _permission_failure()
        except OSError:
            _storage_failure()
        if (
            stat.S_ISLNK(current_stat.st_mode)
            or not stat.S_ISDIR(current_stat.st_mode)
            or (root_stat.st_dev, root_stat.st_ino)
            != (current_stat.st_dev, current_stat.st_ino)
        ):
            _integrity_failure()
        identity = self._identity(root_stat)
        if identity != self._identity(current_stat):
            _integrity_failure()
        return _TrustedRoot(resolved_root, identity)

    def _revalidate_absent_root(self, absent: _AbsentRoot) -> None:
        if not (_RELATIVE_OPEN_SUPPORTED and _RELATIVE_LSTAT_SUPPORTED):
            _integrity_failure()
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        flags |= _NOFOLLOW_FLAG
        descriptor = -1
        try:
            descriptor = os.open(absent.anchor, flags)
            opened_anchor = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(opened_anchor.st_mode)
                or self._identity(opened_anchor) != absent.anchor_identity
            ):
                _integrity_failure()
            for part in absent.relative_parts:
                try:
                    child_stat = os.stat(
                        part,
                        dir_fd=descriptor,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    return
                if (
                    stat.S_ISLNK(child_stat.st_mode)
                    or not stat.S_ISDIR(child_stat.st_mode)
                ):
                    _integrity_failure()
                child = -1
                try:
                    child = os.open(part, flags, dir_fd=descriptor)
                    opened_child = os.fstat(child)
                    if (
                        not stat.S_ISDIR(opened_child.st_mode)
                        or self._identity(opened_child)
                        != self._identity(child_stat)
                    ):
                        _integrity_failure()
                except (_ReportOperationFailure, OSError, TypeError):
                    try:
                        if child >= 0:
                            os.close(child)
                    except OSError:
                        pass
                    raise
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                descriptor = child
            _integrity_failure()
        except _ReportOperationFailure:
            raise
        except (FileNotFoundError, PermissionError, OSError, TypeError):
            _integrity_failure()
        finally:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def _revalidate_trusted_root(self, trusted: _TrustedRoot) -> None:
        try:
            current = self._root.lstat()
            resolved = self._root.resolve(strict=True)
            repeated = self._root.lstat()
        except (FileNotFoundError, PermissionError, OSError):
            _integrity_failure()
        if (
            stat.S_ISLNK(current.st_mode)
            or not stat.S_ISDIR(current.st_mode)
            or self._identity(current) != trusted.identity
            or self._identity(repeated) != trusted.identity
            or resolved != trusted.resolved_path
        ):
            _integrity_failure()

    def _revalidate_root_state(self, root_state: _RootState) -> None:
        if isinstance(root_state, _TrustedRoot):
            self._revalidate_trusted_root(root_state)
        else:
            self._revalidate_absent_root(root_state)

    @staticmethod
    def _candidate_name(name: object) -> bool:
        return (
            isinstance(name, str)
            and Path(name).parts == (name,)
            and not Path(name).is_absolute()
            and name.endswith(".json")
            and not name.endswith(".tmp")
        )

    def _open_trusted_root_handle(
        self,
        trusted: _TrustedRoot,
    ) -> _TrustedRootHandle:
        if not (
            _SCANDIR_SUPPORTS_FD
            and _RELATIVE_OPEN_SUPPORTED
            and _RELATIVE_LSTAT_SUPPORTED
            and hasattr(os, "O_NOFOLLOW")
        ):
            _integrity_failure()
        flags = os.O_RDONLY | os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        try:
            descriptor = os.open(self._root, flags)
        except FileNotFoundError:
            _integrity_failure()
        except PermissionError:
            _permission_failure()
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                _integrity_failure()
            _storage_failure()
        try:
            opened = os.fstat(descriptor)
        except OSError:
            try:
                os.close(descriptor)
            except OSError:
                pass
            _integrity_failure()
        if (
            not stat.S_ISDIR(opened.st_mode)
            or self._identity(opened) != trusted.identity
        ):
            try:
                os.close(descriptor)
            except OSError:
                pass
            _integrity_failure()
        return _TrustedRootHandle(trusted, descriptor)

    def _validated_root_descriptor(
        self,
        handle: _TrustedRootHandle,
    ) -> int:
        descriptor = handle.descriptor()
        try:
            opened = os.fstat(descriptor)
        except OSError:
            _integrity_failure()
        if (
            not stat.S_ISDIR(opened.st_mode)
            or self._identity(opened) != handle.trusted_root.identity
        ):
            _integrity_failure()
        return descriptor

    def _enumerate_candidate_paths(
        self,
        handle: _TrustedRootHandle,
    ) -> tuple[str, ...]:
        descriptor = self._validated_root_descriptor(handle)
        candidates: list[str] = []
        try:
            with os.scandir(descriptor) as entries:
                for entry in entries:
                    if not self._candidate_name(entry.name):
                        continue
                    if len(candidates) == MAX_REPORT_CANDIDATES:
                        _integrity_failure()
                    candidates.append(entry.name)
        except _ReportOperationFailure:
            raise
        except (TypeError, NotImplementedError):
            _integrity_failure()
        except FileNotFoundError:
            _integrity_failure()
        except PermissionError:
            _permission_failure()
        except OSError:
            _storage_failure()
        self._validated_root_descriptor(handle)
        self._revalidate_trusted_root(handle.trusted_root)
        candidates.sort()
        return tuple(candidates)

    def _root_candidates(
        self,
    ) -> tuple[_RootState, _TrustedRootHandle | None, tuple[str, ...]]:
        root_state = self._resolved_root(missing_is_empty=True)
        if isinstance(root_state, _AbsentRoot):
            self._revalidate_absent_root(root_state)
            return root_state, None, ()
        handle = self._open_trusted_root_handle(root_state)
        try:
            candidates = self._enumerate_candidate_paths(handle)
            self._revalidate_trusted_root(root_state)
            return root_state, handle, candidates
        except BaseException:
            handle.close()
            raise

    def _read_bytes(
        self,
        name: str,
        root_handle: _TrustedRootHandle,
    ) -> tuple[bytes, _FileIdentity]:
        if not self._candidate_name(name):
            _integrity_failure()
        root_descriptor = self._validated_root_descriptor(root_handle)
        try:
            before = os.stat(
                name,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            raise _CandidateReadFailure(_CandidateIssue.DISAPPEARED) from None
        except PermissionError:
            raise _CandidateReadFailure(_CandidateIssue.PERMISSION_DENIED) from None
        except (TypeError, NotImplementedError):
            _integrity_failure()
        except OSError:
            raise _CandidateReadFailure(_CandidateIssue.IO_ERROR) from None
        if stat.S_ISLNK(before.st_mode):
            raise _CandidateReadFailure(_CandidateIssue.SYMLINK)
        if not stat.S_ISREG(before.st_mode):
            raise _CandidateReadFailure(_CandidateIssue.NONREGULAR)

        flags = _race_safe_report_open_flags()
        if flags is None:
            _integrity_failure()
        try:
            descriptor = os.open(name, flags, dir_fd=root_descriptor)
        except FileNotFoundError:
            raise _CandidateReadFailure(_CandidateIssue.DISAPPEARED) from None
        except PermissionError:
            raise _CandidateReadFailure(_CandidateIssue.PERMISSION_DENIED) from None
        except (TypeError, NotImplementedError):
            _integrity_failure()
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise _CandidateReadFailure(_CandidateIssue.SYMLINK) from None
            raise _CandidateReadFailure(_CandidateIssue.IO_ERROR) from None

        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise _CandidateReadFailure(_CandidateIssue.NONREGULAR)
            if opened.st_size > MAX_REPORT_BYTES:
                raise _CandidateReadFailure(_CandidateIssue.OVERSIZED)
            with os.fdopen(descriptor, "rb", closefd=True) as file:
                descriptor = -1
                data = file.read(MAX_REPORT_BYTES + 1)
            if len(data) > MAX_REPORT_BYTES:
                raise _CandidateReadFailure(_CandidateIssue.OVERSIZED)
            try:
                after = os.stat(
                    name,
                    dir_fd=root_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                raise _CandidateReadFailure(_CandidateIssue.DISAPPEARED) from None
            except (TypeError, NotImplementedError):
                _integrity_failure()
            if (
                stat.S_ISLNK(after.st_mode)
                or not stat.S_ISREG(after.st_mode)
                or (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino)
            ):
                _integrity_failure()
            self._validated_root_descriptor(root_handle)
            return data, _FileIdentity(opened.st_dev, opened.st_ino, opened.st_size)
        except _CandidateReadFailure:
            raise
        except _ReportOperationFailure:
            raise
        except FileNotFoundError:
            raise _CandidateReadFailure(_CandidateIssue.DISAPPEARED) from None
        except PermissionError:
            raise _CandidateReadFailure(_CandidateIssue.PERMISSION_DENIED) from None
        except OSError:
            raise _CandidateReadFailure(_CandidateIssue.IO_ERROR) from None
        finally:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def _read_candidate(
        self,
        name: str,
        root_handle: _TrustedRootHandle,
    ) -> _ValidatedCandidate:
        data, file_identity = self._read_bytes(name, root_handle)
        return self._candidate_from_bytes(Path(name), data, file_identity)

    def _candidate_from_bytes(
        self,
        path: Path,
        data: bytes,
        file_identity: _FileIdentity,
    ) -> _ValidatedCandidate:
        try:
            decoded = data.decode("utf-8", errors="strict")
            raw_report = json.loads(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise _CandidateReadFailure(_CandidateIssue.MALFORMED) from None
        if not isinstance(raw_report, dict):
            raise _CandidateReadFailure(_CandidateIssue.MALFORMED)
        try:
            normalized, _omitted_evidence = normalize_report(raw_report)
        except UnsupportedReportSchema:
            raise _CandidateReadFailure(_CandidateIssue.UNSUPPORTED) from None
        except ReportValidationError:
            raise _CandidateReadFailure(_CandidateIssue.MALFORMED) from None
        try:
            digest = canonical_report_digest(raw_report)
            canonical = canonical_report_bytes(raw_report)
        except (TypeError, ValueError):
            raise _CandidateReadFailure(_CandidateIssue.MALFORMED) from None
        system = raw_report.get("system")
        raw_system_id = system.get("system_id") if isinstance(system, Mapping) else None
        if raw_system_id is None:
            raise _CandidateReadFailure(_CandidateIssue.UNRESOLVED_SYSTEM)
        try:
            _system_id(raw_system_id)
        except (TypeError, ValueError):
            raise _CandidateReadFailure(_CandidateIssue.MALFORMED) from None
        if raw_system_id != normalized.native_system_id:
            raise _CandidateReadFailure(_CandidateIssue.MALFORMED)
        generated_at = _utc_timestamp(normalized.generated_at)
        try:
            report_id = ReportId(f"report:{digest}")
            compatibility = _compatibility_metadata(raw_report, normalized)
            assurance = _project_assurance(raw_report, normalized)
            summary = _project_summary(
                report_id,
                generated_at,
                normalized,
                compatibility,
                assurance,
            )
        except _ReportOperationFailure:
            raise _CandidateReadFailure(_CandidateIssue.MALFORMED) from None
        return _ValidatedCandidate(
            path=path,
            file_identity=file_identity,
            raw_report=raw_report,
            normalized_report=normalized,
            report_id=report_id,
            canonical_bytes=canonical,
            generated_at=generated_at,
            system_id=raw_system_id,
            compatibility=compatibility,
            summary=summary,
        )

    def _read_published_bytes(
        self,
        receipt: reporting._PublicationReceipt,
    ) -> tuple[bytes, _FileIdentity]:
        if (
            type(receipt) is not reporting._PublicationReceipt
            or not _RELATIVE_OPEN_SUPPORTED
        ):
            _publication_compatibility_failure()
        flags = _race_safe_report_open_flags()
        if flags is None:
            _publication_compatibility_failure()

        expected_root = _RootIdentity(
            receipt.directory_device,
            receipt.directory_inode,
        )
        expected_file = _FileIdentity(
            receipt.file_device,
            receipt.file_inode,
            receipt.file_size,
        )
        descriptor = -1
        try:
            opened_root = os.fstat(receipt.directory_descriptor)
            if (
                not stat.S_ISDIR(opened_root.st_mode)
                or self._identity(opened_root) != expected_root
            ):
                _integrity_failure()

            descriptor = os.open(
                receipt.canonical_name,
                flags,
                dir_fd=receipt.directory_descriptor,
            )
            opened = os.fstat(descriptor)
            opened_identity = _FileIdentity(
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
            )
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened_identity != expected_file
            ):
                _integrity_failure()
            if opened.st_size > MAX_REPORT_BYTES:
                raise _CandidateReadFailure(_CandidateIssue.OVERSIZED)

            remaining = MAX_REPORT_BYTES + 1
            chunks = []
            while remaining:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) > MAX_REPORT_BYTES:
                raise _CandidateReadFailure(_CandidateIssue.OVERSIZED)

            repeated = os.fstat(descriptor)
            repeated_identity = _FileIdentity(
                repeated.st_dev,
                repeated.st_ino,
                repeated.st_size,
            )
            if (
                not stat.S_ISREG(repeated.st_mode)
                or repeated_identity != expected_file
                or hashlib.sha256(data).digest() != receipt.content_sha256
            ):
                _integrity_failure()
            current_entry = os.stat(
                receipt.canonical_name,
                dir_fd=receipt.directory_descriptor,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(current_entry.st_mode)
                or (current_entry.st_dev, current_entry.st_ino)
                != (receipt.file_device, receipt.file_inode)
            ):
                _integrity_failure()
            repeated_root = os.fstat(receipt.directory_descriptor)
            if (
                not stat.S_ISDIR(repeated_root.st_mode)
                or self._identity(repeated_root) != expected_root
            ):
                _integrity_failure()
            return data, opened_identity
        except _CandidateReadFailure:
            raise
        except _ReportOperationFailure:
            raise
        except FileNotFoundError:
            raise _CandidateReadFailure(_CandidateIssue.DISAPPEARED) from None
        except PermissionError:
            raise _CandidateReadFailure(_CandidateIssue.PERMISSION_DENIED) from None
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise _CandidateReadFailure(_CandidateIssue.SYMLINK) from None
            raise _CandidateReadFailure(_CandidateIssue.IO_ERROR) from None
        finally:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def _read_published_candidate(
        self,
        receipt: reporting._PublicationReceipt,
    ) -> _ValidatedCandidate:
        data, file_identity = self._read_published_bytes(receipt)
        return self._candidate_from_bytes(receipt.path, data, file_identity)

    def save_scanner_result(self, scanner_result: dict) -> _StoredReport:
        try:
            system = scanner_result["system"]
            expected_system_id = system["system_id"]
            _system_id(expected_system_id)
        except (KeyError, TypeError, ValueError):
            _compatibility_failure()

        receipt = None
        try:
            receipt = reporting._save_json_report_with_receipt(
                scanner_result,
                self._root,
            )
        except reporting._CanonicalNameExhausted:
            _conflict_failure()
        except PermissionError:
            _permission_failure()
        except OSError as exc:
            unsupported_errors = {
                errno.ENOTSUP,
                getattr(errno, "EOPNOTSUPP", errno.ENOTSUP),
                getattr(errno, "ENOSYS", errno.ENOTSUP),
            }
            if exc.errno in unsupported_errors:
                _publication_compatibility_failure()
            if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                _integrity_failure()
            _storage_failure()
        except (KeyError, TypeError, ValueError):
            _publication_compatibility_failure()

        try:
            if (
                type(receipt) is not reporting._PublicationReceipt
                or not isinstance(receipt.path, Path)
                or not self._candidate_name(receipt.canonical_name)
                or receipt.path.name != receipt.canonical_name
                or receipt.path != self._root / receipt.canonical_name
                or not isinstance(receipt.resolved_directory, Path)
            ):
                _integrity_failure()
            root_state = _TrustedRoot(
                receipt.resolved_directory,
                _RootIdentity(
                    receipt.directory_device,
                    receipt.directory_inode,
                ),
            )
            self._revalidate_trusted_root(root_state)
            try:
                candidate = self._read_published_candidate(receipt)
            except _CandidateReadFailure as failure:
                if failure.issue == _CandidateIssue.PERMISSION_DENIED:
                    _permission_failure()
                if failure.issue == _CandidateIssue.IO_ERROR:
                    _storage_failure()
                _integrity_failure()
            self._revalidate_trusted_root(root_state)
            if (
                candidate.system_id != expected_system_id
                or candidate.summary.system_id != expected_system_id
            ):
                _integrity_failure()
            return _StoredReport(
                report_id=candidate.report_id,
                summary=candidate.summary,
                canonical_bytes=candidate.canonical_bytes,
                candidates=(candidate,),
                trusted_root=root_state,
            )
        finally:
            if type(receipt) is reporting._PublicationReceipt:
                receipt.close()

    def catalog_for_system(self, system_id: str) -> _ReportCatalogSnapshot:
        root_state, root_handle, names = self._root_candidates()
        diagnostics = _DiagnosticCounts()
        identities: dict[str, tuple[bytes, str]] = {}
        groups: dict[str, list[_ValidatedCandidate]] = {}
        if isinstance(root_state, _AbsentRoot):
            self._revalidate_absent_root(root_state)
            return _ReportCatalogSnapshot(
                repository=self,
                root_state=root_state,
                stored_reports=(),
                catalog_completeness=ReportCatalogCompleteness.COMPLETE,
                catalog_omitted_count=0,
                catalog_diagnostics=diagnostics.public(0),
            )
        if root_handle is None:
            _integrity_failure()
        try:
            for name in names:
                self._revalidate_trusted_root(root_state)
                try:
                    candidate = self._read_candidate(name, root_handle)
                except _CandidateReadFailure as failure:
                    self._revalidate_trusted_root(root_state)
                    diagnostics.add(failure.issue)
                    continue
                self._revalidate_trusted_root(root_state)
                previous = identities.get(candidate.report_id.value)
                identity = (candidate.canonical_bytes, candidate.system_id)
                if previous is not None and previous != identity:
                    _integrity_failure()
                identities[candidate.report_id.value] = identity
                if candidate.system_id != system_id:
                    continue
                groups.setdefault(candidate.report_id.value, []).append(candidate)

            duplicate_count = sum(
                max(0, len(items) - 1) for items in groups.values()
            )
            stored = tuple(
                _StoredReport(
                    report_id=items[0].report_id,
                    summary=items[0].summary,
                    canonical_bytes=items[0].canonical_bytes,
                    candidates=tuple(items),
                    trusted_root=root_state,
                )
                for items in groups.values()
            )
            ordered = tuple(sorted(
                stored,
                key=lambda item: (
                    item.summary.generated_at.astimezone(timezone.utc),
                    item.report_id.value,
                ),
            ))
            omitted = diagnostics.omitted_count
            self._revalidate_trusted_root(root_state)
            return _ReportCatalogSnapshot(
                repository=self,
                root_state=root_state,
                stored_reports=ordered,
                catalog_completeness=(
                    ReportCatalogCompleteness.COMPLETE
                    if omitted == 0
                    else ReportCatalogCompleteness.INCOMPLETE
                ),
                catalog_omitted_count=omitted,
                catalog_diagnostics=diagnostics.public(duplicate_count),
            )
        finally:
            root_handle.close()

    def read_detail(
        self,
        stored: _StoredReport,
        *,
        operation_id: str,
        expected_system_id: str,
    ) -> SavedReportDetail:
        selected = self._reread_stored_report(
            stored,
            expected_system_id=expected_system_id,
        )
        return _project_detail(selected, operation_id=operation_id)

    def _reread_stored_report(
        self,
        stored: _StoredReport,
        *,
        expected_system_id: str,
    ) -> _ValidatedCandidate:
        root_state = self._resolved_root(missing_is_empty=False)
        if not isinstance(root_state, _TrustedRoot):
            _integrity_failure()
        if root_state != stored.trusted_root:
            _integrity_failure()
        self._revalidate_trusted_root(stored.trusted_root)
        root_handle = self._open_trusted_root_handle(stored.trusted_root)
        try:
            selected = None
            for original in stored.candidates:
                self._revalidate_trusted_root(stored.trusted_root)
                try:
                    current = self._read_candidate(
                        original.path.name,
                        root_handle,
                    )
                except _CandidateReadFailure as failure:
                    if failure.issue == _CandidateIssue.PERMISSION_DENIED:
                        _permission_failure()
                    if failure.issue == _CandidateIssue.IO_ERROR:
                        _storage_failure()
                    _integrity_failure()
                self._revalidate_trusted_root(stored.trusted_root)
                if (
                    current.file_identity != original.file_identity
                    or current.report_id != stored.report_id
                    or current.system_id != expected_system_id
                    or current.canonical_bytes != stored.canonical_bytes
                ):
                    _integrity_failure()
                if selected is None:
                    selected = current
            if selected is None:
                _integrity_failure()
            self._revalidate_trusted_root(stored.trusted_root)
            return selected
        finally:
            root_handle.close()

    def read_trusted_material(
        self,
        snapshot: _ReportCatalogSnapshot,
        *,
        report_id: ReportId,
        expected_system_id: str,
    ) -> _TrustedReportMaterial:
        if (
            type(snapshot) is not _ReportCatalogSnapshot
            or snapshot.repository is not self
            or type(report_id) is not ReportId
        ):
            _integrity_failure()
        try:
            _system_id(expected_system_id)
        except (TypeError, ValueError):
            _integrity_failure()
        if snapshot.completeness != ReportCatalogCompleteness.COMPLETE:
            _integrity_failure()
        stored = snapshot.find(report_id)
        if stored is None:
            _not_found_failure()
        candidate = self._reread_stored_report(
            stored,
            expected_system_id=expected_system_id,
        )
        digest = candidate.report_id.value.removeprefix("report:")
        if (
            candidate.report_id != report_id
            or candidate.system_id != expected_system_id
            or candidate.summary.system_id != expected_system_id
            or candidate.summary.report_id != candidate.report_id
            or candidate.summary.generated_at != candidate.generated_at
            or candidate.summary.schema_version
            != candidate.normalized_report.schema_version
            or hashlib.sha256(candidate.canonical_bytes).hexdigest() != digest
        ):
            _integrity_failure()
        try:
            return _TrustedReportMaterial(
                report_id=candidate.report_id,
                canonical_digest=digest,
                canonical_bytes=candidate.canonical_bytes,
                normalized_report=candidate.normalized_report,
                system_id=candidate.system_id,
                schema_version=candidate.normalized_report.schema_version,
                generated_at=candidate.generated_at,
            )
        except (TypeError, ValueError):
            _integrity_failure()


def _default_report_repository() -> _ReportRepositoryPort:
    return _FileReportRepository(_DEFAULT_REPORT_ROOT)
