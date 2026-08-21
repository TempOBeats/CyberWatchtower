from collections.abc import Mapping
from datetime import datetime, timezone
import unicodedata

from cyberwatchtower.finding_identity import finding_identity
from cyberwatchtower.models import (
    AssessmentState,
    FindingKind,
    MAX_RUNTIME_INSTANCE_COUNT,
    Severity,
)
from cyberwatchtower.report_contracts import (
    CURRENT_REPORT_SCHEMA_VERSION,
    APPLICABLE_DOMAINS_REPORT_SCHEMA_VERSION,
    CoverageState,
    LEGACY_REPORT_SCHEMA_VERSION,
    REACHABILITY_REPORT_SCHEMA_VERSION,
    SCORING_REPORT_SCHEMA_VERSION,
    STRUCTURED_FINDING_REPORT_SCHEMA_VERSION,
    ScanDomain,
    normalize_assessment_domains,
    normalize_coverage,
    report_schema_version,
)
from cyberwatchtower.reachability import reachability_from_report
from cyberwatchtower.scoring_report import (
    ScoringReportValidationError,
    validate_serialized_security_score,
)

from .ingestion_models import NormalizedFinding, NormalizedReport, NormalizedScore
from .sanitization import contains_sensitive_marker, sanitize_evidence


SUPPORTED_REPORT_SCHEMAS = frozenset({
    LEGACY_REPORT_SCHEMA_VERSION,
    STRUCTURED_FINDING_REPORT_SCHEMA_VERSION,
    APPLICABLE_DOMAINS_REPORT_SCHEMA_VERSION,
    REACHABILITY_REPORT_SCHEMA_VERSION,
    SCORING_REPORT_SCHEMA_VERSION,
    CURRENT_REPORT_SCHEMA_VERSION,
})
SEVERITIES = tuple(item.value for item in Severity)
KINDS = tuple(item.value for item in FindingKind)
ASSESSMENT_STATES = tuple(item.value for item in AssessmentState)
MAX_TITLE_LENGTH = 256
MAX_DESCRIPTION_LENGTH = 4_096
MAX_RECOMMENDATION_LENGTH = 4_096
MAX_SOURCE_LENGTH = 128
MAX_TECHNIQUE_ID_LENGTH = 128
MAX_FINDING_ID_LENGTH = 512


class ReportValidationError(ValueError):
    def __init__(self, code: str, message: str, field: str | None = None):
        super().__init__(message)
        self.code = code
        self.field = field


class UnsupportedReportSchema(ReportValidationError):
    pass


def _mapping(value, field: str) -> Mapping:
    if not isinstance(value, Mapping):
        raise ReportValidationError("INVALID_TYPE", f"{field} must be an object.", field)
    return value


def _text(value, field: str, *, default: str | None = None) -> str:
    if value is None and default is not None:
        return default
    if not isinstance(value, str) or not value.strip():
        raise ReportValidationError("INVALID_TEXT", f"{field} must be non-empty text.", field)
    return value.strip()


def _durable_text(
    value,
    field: str,
    *,
    maximum: int,
    default: str | None = None,
    allow_empty: bool = False,
) -> str:
    """Validate authoritative text without truncating or interpreting it."""

    if value is None and default is not None:
        value = default
    if not isinstance(value, str):
        raise ReportValidationError("INVALID_TEXT", f"{field} must be text.", field)
    if not allow_empty and not value.strip():
        raise ReportValidationError(
            "INVALID_TEXT", f"{field} must be non-empty text.", field
        )
    if len(value) > maximum:
        raise ReportValidationError(
            "TEXT_TOO_LONG",
            f"{field} exceeds its {maximum}-character limit.",
            field,
        )
    if any(unicodedata.category(char) in {"Cc", "Cf"} for char in value):
        raise ReportValidationError(
            "UNSAFE_CONTROL_CHARACTER",
            f"{field} contains a prohibited control character.",
            field,
        )
    return value


def _integer(value, field: str, minimum: int, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReportValidationError("INVALID_INTEGER", f"{field} must be an integer.", field)
    if value < minimum or (maximum is not None and value > maximum):
        raise ReportValidationError("OUT_OF_RANGE", f"{field} is out of range.", field)
    return value


def _timestamp(value, field: str) -> str:
    text = _text(value, field)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReportValidationError(
            "INVALID_TIMESTAMP", f"{field} must be an ISO-8601 timestamp.", field
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def _score(
    raw_score,
    schema_version: str,
    finding_ids: set[str],
) -> NormalizedScore:
    try:
        score_data = validate_serialized_security_score(
            raw_score, schema_version, finding_ids
        )
    except ScoringReportValidationError as exc:
        raise ReportValidationError(exc.code, str(exc), exc.field) from exc
    counts_data = score_data["counts"]
    counts = tuple(
        (severity, int(counts_data[severity])) for severity in SEVERITIES
    )
    return NormalizedScore(
        str(score_data["scoring_version"]),
        int(score_data["score"]),
        str(score_data["risk_level"]),
        counts,
    )


def _finding(raw_finding, index: int, schema_version: str) -> tuple[NormalizedFinding, int]:
    field = f"findings[{index}]"
    finding = _mapping(raw_finding, field)
    if schema_version == CURRENT_REPORT_SCHEMA_VERSION:
        if "runtime_instance_count" not in finding:
            raise ReportValidationError(
                "MISSING_RUNTIME_MULTIPLICITY",
                f"{field}.runtime_instance_count is required.",
                f"{field}.runtime_instance_count",
            )
        runtime_instance_count = _integer(
            finding.get("runtime_instance_count"),
            f"{field}.runtime_instance_count",
            1,
            MAX_RUNTIME_INSTANCE_COUNT,
        )
    else:
        runtime_instance_count = _integer(
            finding.get("runtime_instance_count", 1),
            f"{field}.runtime_instance_count",
            1,
            MAX_RUNTIME_INSTANCE_COUNT,
        )
    try:
        reachability_from_report(finding.get("network_context"))
    except ValueError as exc:
        raise ReportValidationError(
            "INVALID_NETWORK_CONTEXT",
            f"{field}.network_context is invalid.",
            f"{field}.network_context",
        ) from exc
    title = _durable_text(
        finding.get("title"), f"{field}.title", maximum=MAX_TITLE_LENGTH
    )
    severity = _text(finding.get("severity"), f"{field}.severity")
    if severity not in SEVERITIES:
        raise ReportValidationError(
            "INVALID_SEVERITY", f"{field}.severity is not recognized.", f"{field}.severity"
        )
    evidence_value = finding.get("evidence", [])
    if not isinstance(evidence_value, list) or not all(
        isinstance(item, str) for item in evidence_value
    ):
        raise ReportValidationError(
            "INVALID_EVIDENCE", f"{field}.evidence must be a list of strings.",
            f"{field}.evidence",
        )
    safe_evidence, omitted = sanitize_evidence(evidence_value)

    raw_kind = finding.get("kind")
    raw_assessment = finding.get("assessment_state")
    if schema_version != LEGACY_REPORT_SCHEMA_VERSION:
        if raw_kind not in KINDS:
            raise ReportValidationError(
                "INVALID_KIND", f"{field}.kind is not recognized.", f"{field}.kind"
            )
        if raw_assessment not in ASSESSMENT_STATES:
            raise ReportValidationError(
                "INVALID_ASSESSMENT_STATE",
                f"{field}.assessment_state is not recognized.",
                f"{field}.assessment_state",
            )
    metadata_inferred = raw_kind not in KINDS or raw_assessment not in ASSESSMENT_STATES
    kind = raw_kind if raw_kind in KINDS else FindingKind.RISK.value
    assessment = (
        raw_assessment
        if raw_assessment in ASSESSMENT_STATES
        else AssessmentState.POTENTIAL.value
    )
    confidence = _integer(finding.get("confidence", 0), f"{field}.confidence", 0, 100)
    source = _durable_text(
        finding.get("source"),
        f"{field}.source",
        maximum=MAX_SOURCE_LENGTH,
        default="legacy",
    )
    is_legacy = schema_version == LEGACY_REPORT_SCHEMA_VERSION
    description = _durable_text(
        finding.get("description"),
        f"{field}.description",
        maximum=MAX_DESCRIPTION_LENGTH,
        default="" if is_legacy else None,
        allow_empty=is_legacy,
    )
    recommendation = _durable_text(
        finding.get("recommendation"),
        f"{field}.recommendation",
        maximum=MAX_RECOMMENDATION_LENGTH,
        default="" if is_legacy else None,
        allow_empty=is_legacy,
    )
    technique_id = finding.get("technique_id")
    if technique_id is not None:
        technique_id = _durable_text(
            technique_id,
            f"{field}.technique_id",
            maximum=MAX_TECHNIQUE_ID_LENGTH,
        )
    stored_id = finding.get("finding_id")
    if stored_id is not None:
        stored_id = _durable_text(
            stored_id,
            f"{field}.finding_id",
            maximum=MAX_FINDING_ID_LENGTH,
        )
    if stored_id is not None and contains_sensitive_marker(stored_id):
        raise ReportValidationError(
            "UNSAFE_FINDING_ID",
            f"{field}.finding_id contains prohibited sensitive material.",
            f"{field}.finding_id",
        )
    identity_source = dict(finding)
    identity_source["evidence"] = list(safe_evidence)
    stable_id = finding_identity(identity_source)
    _durable_text(
        stable_id,
        f"{field}.finding_id",
        maximum=MAX_FINDING_ID_LENGTH,
    )
    if contains_sensitive_marker(stable_id):
        raise ReportValidationError(
            "UNSAFE_FINDING_ID",
            f"{field}.finding_id contains prohibited sensitive material.",
            f"{field}.finding_id",
        )
    return NormalizedFinding(
        stable_id,
        title,
        description,
        severity,
        recommendation,
        confidence,
        technique_id,
        source,
        kind,
        assessment,
        metadata_inferred,
        safe_evidence,
        runtime_instance_count,
    ), omitted


def normalize_report(raw_report: Mapping) -> tuple[NormalizedReport, int]:
    report = _mapping(raw_report, "report")
    schema_version = report_schema_version(report)
    if schema_version not in SUPPORTED_REPORT_SCHEMAS:
        raise UnsupportedReportSchema(
            "UNSUPPORTED_SCHEMA",
            f"Report schema {schema_version!r} is not supported.",
            "schema_version",
        )
    generated_at = _timestamp(report.get("generated_at"), "generated_at")
    system = _mapping(report.get("system"), "system")
    hostname = _text(system.get("hostname"), "system.hostname")
    native_system_id = system.get("system_id")
    if native_system_id is not None:
        native_system_id = _text(native_system_id, "system.system_id")

    raw_coverage = report.get("coverage")
    if raw_coverage is not None and not isinstance(raw_coverage, Mapping):
        raise ReportValidationError(
            "INVALID_COVERAGE", "coverage must be an object.", "coverage"
        )
    raw_domains = report.get("assessment_domains")
    if schema_version in {
        APPLICABLE_DOMAINS_REPORT_SCHEMA_VERSION,
        REACHABILITY_REPORT_SCHEMA_VERSION,
        SCORING_REPORT_SCHEMA_VERSION,
        CURRENT_REPORT_SCHEMA_VERSION,
    } and raw_domains is None:
        raise ReportValidationError(
            "MISSING_ASSESSMENT_DOMAINS",
            "assessment_domains is required for this report schema.",
            "assessment_domains",
        )
    try:
        assessment_domains = normalize_assessment_domains(raw_domains)
    except (TypeError, ValueError) as exc:
        raise ReportValidationError(
            "INVALID_ASSESSMENT_DOMAINS",
            "assessment_domains contains an invalid or duplicate domain.",
            "assessment_domains",
        ) from exc
    if raw_coverage is not None:
        known_domains = {domain.value for domain in ScanDomain}
        applicable = {domain.value for domain in assessment_domains}
        valid_states = {state.value for state in CoverageState}
        if set(raw_coverage) - known_domains or any(
            value not in valid_states for value in raw_coverage.values()
        ):
            raise ReportValidationError(
                "INVALID_COVERAGE",
                "coverage contains an unknown domain or state.",
                "coverage",
            )
        if schema_version in {
            APPLICABLE_DOMAINS_REPORT_SCHEMA_VERSION,
            REACHABILITY_REPORT_SCHEMA_VERSION,
            SCORING_REPORT_SCHEMA_VERSION,
            CURRENT_REPORT_SCHEMA_VERSION,
        } and set(raw_coverage) - applicable:
            raise ReportValidationError(
                "INAPPLICABLE_COVERAGE",
                "coverage contains a domain not declared applicable.",
                "coverage",
            )
    coverage = tuple(sorted(
        normalize_coverage(raw_coverage, assessment_domains).items()
    ))
    raw_findings = report.get("findings")
    if not isinstance(raw_findings, list):
        raise ReportValidationError(
            "INVALID_FINDINGS", "findings must be a list.", "findings"
        )
    findings = []
    omitted_evidence = 0
    finding_ids = set()
    for index, raw_finding in enumerate(raw_findings):
        finding, omitted = _finding(raw_finding, index, schema_version)
        if finding.finding_id in finding_ids:
            raise ReportValidationError(
                "DUPLICATE_FINDING", "A report cannot contain a duplicate finding identity.",
                f"findings[{index}].finding_id",
            )
        finding_ids.add(finding.finding_id)
        findings.append(finding)
        omitted_evidence += omitted
    score = _score(report.get("security_score"), schema_version, finding_ids)
    return NormalizedReport(
        schema_version,
        generated_at,
        native_system_id,
        hostname,
        coverage,
        score,
        tuple(findings),
    ), omitted_evidence
