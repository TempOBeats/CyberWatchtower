import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from cyberwatchtower.report_contracts import (
    LegacyIdentityResolution,
    LegacyIdentityState,
    LegacyLinkPolicy,
    canonical_report_digest,
)

from .database import MemoryDatabase
from .ingestion_models import (
    DiagnosticSeverity,
    IngestionDiagnostic,
    IngestionStatus,
    NormalizedFinding,
    NormalizedReport,
    ReportIngestionRequest,
    ReportIngestionResult,
)
from .normalizers import (
    ReportValidationError,
    UnsupportedReportSchema,
    normalize_report,
)
from .provenance import MemoryProvenance


MAX_REPORT_BYTES = 10 * 1024 * 1024


def _diagnostic(code, message, *, field=None, severity=DiagnosticSeverity.ERROR):
    return IngestionDiagnostic(code, message, severity, field)


def _result(
    status,
    *,
    report_id=None,
    system_id=None,
    digest=None,
    schema_version=None,
    resolution=None,
    diagnostics=(),
):
    return ReportIngestionResult(
        status,
        report_id,
        system_id,
        digest,
        schema_version,
        resolution,
        tuple(diagnostics),
    )


def _read_report(path: Path):
    try:
        if path.stat().st_size > MAX_REPORT_BYTES:
            raise ReportValidationError(
                "REPORT_TOO_LARGE", "Report exceeds the ingestion size limit."
            )
        with path.open("r", encoding="utf-8") as source:
            report = json.load(source)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReportValidationError(
            "INVALID_JSON", "Report could not be read as valid UTF-8 JSON."
        ) from exc
    if not isinstance(report, dict):
        raise ReportValidationError(
            "INVALID_REPORT", "The top-level report must be a JSON object."
        )
    return report


def _known_hostname_systems(connection, hostname: str) -> set[str]:
    rows = connection.execute(
        """SELECT system_id FROM systems WHERE display_hostname = ?
           UNION
           SELECT system_id FROM system_aliases
           WHERE alias_type = 'HOSTNAME' AND alias_value = ? AND valid_to IS NULL""",
        (hostname, hostname),
    )
    return {str(row[0]) for row in rows}


def _resolve_identity(
    connection: sqlite3.Connection,
    report: NormalizedReport,
    request: ReportIngestionRequest,
) -> LegacyIdentityResolution:
    if report.native_system_id:
        if (
            request.expected_system_id is not None
            and request.expected_system_id != report.native_system_id
        ):
            return LegacyIdentityResolution(
                LegacyIdentityState.UNRESOLVED,
                None,
                report.hostname,
                request.legacy_link_policy,
                "The report system_id conflicts with the explicitly scoped system_id.",
            )
        return LegacyIdentityResolution(
            LegacyIdentityState.NATIVE_SYSTEM_ID,
            report.native_system_id,
            report.hostname,
            request.legacy_link_policy,
            "The report contains an authoritative stable system_id.",
        )

    expected = request.expected_system_id
    if (
        request.legacy_link_policy
        != LegacyLinkPolicy.ALLOW_EXPLICIT_HOSTNAME_FALLBACK
        or not expected
    ):
        return LegacyIdentityResolution(
            LegacyIdentityState.UNRESOLVED,
            None,
            report.hostname,
            request.legacy_link_policy,
            "Legacy reports require an explicit scoped hostname-fallback policy.",
        )

    known_systems = _known_hostname_systems(connection, report.hostname)
    if len(known_systems) > 1 or (known_systems and expected not in known_systems):
        return LegacyIdentityResolution(
            LegacyIdentityState.UNRESOLVED,
            None,
            report.hostname,
            request.legacy_link_policy,
            "The legacy hostname is ambiguous or conflicts with known system aliases.",
        )
    return LegacyIdentityResolution(
        LegacyIdentityState.HOSTNAME_FALLBACK,
        expected,
        report.hostname,
        request.legacy_link_policy,
        "The caller explicitly scoped this unambiguous legacy hostname association.",
    )


def _opaque_id(prefix: str, *components: str) -> str:
    value = "\0".join(components).encode("utf-8")
    return f"{prefix}:{hashlib.sha256(value).hexdigest()}"


def _upsert_system(connection, report: NormalizedReport, resolution, now: str):
    system_id = resolution.system_id
    confidence = (
        "STABLE"
        if resolution.state == LegacyIdentityState.NATIVE_SYSTEM_ID
        else "LEGACY_LINKED"
    )
    connection.execute(
        """INSERT INTO systems
           (system_id, display_hostname, first_seen_at, last_seen_at,
            identity_version, identity_confidence, provenance, created_at, updated_at)
           VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?)
           ON CONFLICT(system_id) DO UPDATE SET
               display_hostname = excluded.display_hostname,
               first_seen_at = CASE
                   WHEN excluded.first_seen_at < systems.first_seen_at
                   THEN excluded.first_seen_at ELSE systems.first_seen_at END,
               last_seen_at = CASE
                   WHEN excluded.last_seen_at > systems.last_seen_at
                   THEN excluded.last_seen_at ELSE systems.last_seen_at END,
               updated_at = excluded.updated_at""",
        (
            system_id,
            report.hostname,
            report.generated_at,
            report.generated_at,
            confidence,
            MemoryProvenance.DETERMINISTIC_OBSERVATION.value,
            now,
            now,
        ),
    )
    alias_id = _opaque_id("alias", system_id, "HOSTNAME", report.hostname)
    connection.execute(
        """INSERT OR IGNORE INTO system_aliases
           (alias_id, system_id, alias_type, alias_value, valid_from, valid_to, provenance)
           VALUES (?, ?, 'HOSTNAME', ?, ?, NULL, ?)""",
        (
            alias_id,
            system_id,
            report.hostname,
            report.generated_at,
            MemoryProvenance.DETERMINISTIC_OBSERVATION.value,
        ),
    )


def _write_finding(
    connection,
    report: NormalizedReport,
    finding: NormalizedFinding,
    system_id: str,
    report_id: str,
    now: str,
):
    finding_pk = _opaque_id("finding", system_id, finding.finding_id)
    connection.execute(
        """INSERT INTO findings
           (finding_pk, system_id, finding_id, first_seen_at, last_seen_at,
            occurrence_count, active, lifecycle_state, recurring, reopened_count,
            last_resolved_at, latest_title, latest_severity, latest_kind,
            latest_assessment_state, latest_source, metadata_inferred,
            provenance, updated_at)
           VALUES (?, ?, ?, ?, ?, 1, 1, 'ACTIVE', 0, 0, NULL, ?, ?, ?, ?, ?, ?,
                   'DERIVED_HISTORY', ?)
           ON CONFLICT(system_id, finding_id) DO UPDATE SET
               last_seen_at = CASE
                   WHEN excluded.last_seen_at > findings.last_seen_at
                   THEN excluded.last_seen_at ELSE findings.last_seen_at END,
               occurrence_count = findings.occurrence_count + 1,
               active = 1,
               lifecycle_state = 'ACTIVE',
               recurring = 1,
               latest_title = excluded.latest_title,
               latest_severity = excluded.latest_severity,
               latest_kind = excluded.latest_kind,
               latest_assessment_state = excluded.latest_assessment_state,
               latest_source = excluded.latest_source,
               metadata_inferred = excluded.metadata_inferred,
               updated_at = excluded.updated_at""",
        (
            finding_pk,
            system_id,
            finding.finding_id,
            report.generated_at,
            report.generated_at,
            finding.title,
            finding.severity,
            finding.kind,
            finding.assessment_state,
            finding.source,
            int(finding.metadata_inferred),
            now,
        ),
    )
    occurrence_id = _opaque_id("occurrence", report_id, finding.finding_id)
    connection.execute(
        """INSERT INTO finding_occurrences
           (occurrence_id, finding_pk, report_id, system_id, observed_at, title,
            description, severity, recommendation, confidence, technique_id,
            source, kind, assessment_state, metadata_inferred, evidence_json, provenance,
            stable_finding_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            occurrence_id,
            finding_pk,
            report_id,
            system_id,
            report.generated_at,
            finding.title,
            finding.description,
            finding.severity,
            finding.recommendation,
            finding.confidence,
            finding.technique_id,
            finding.source,
            finding.kind,
            finding.assessment_state,
            int(finding.metadata_inferred),
            json.dumps(finding.evidence, ensure_ascii=False),
            MemoryProvenance.DETERMINISTIC_OBSERVATION.value,
            finding.finding_id,
        ),
    )


def ingest_report(
    database: MemoryDatabase,
    request: ReportIngestionRequest,
) -> ReportIngestionResult:
    """Validate and atomically ingest one report without modifying its source."""

    try:
        raw_report = _read_report(Path(request.path))
        digest = canonical_report_digest(raw_report)
        normalized, omitted_evidence = normalize_report(raw_report)
    except UnsupportedReportSchema as exc:
        return _result(
            IngestionStatus.UNSUPPORTED_SCHEMA,
            schema_version=(
                str(raw_report.get("schema_version"))
                if "raw_report" in locals() else None
            ),
            diagnostics=(_diagnostic(exc.code, str(exc), field=exc.field),),
        )
    except (ReportValidationError, TypeError, ValueError) as exc:
        return _result(
            IngestionStatus.INVALID,
            diagnostics=(
                _diagnostic(
                    getattr(exc, "code", "INVALID_REPORT"),
                    str(exc),
                    field=getattr(exc, "field", None),
                ),
            ),
        )

    connection = database.connection
    resolution = None
    try:
        connection.execute("BEGIN IMMEDIATE")
        resolution = _resolve_identity(connection, normalized, request)
        target_system_id = resolution.system_id or request.expected_system_id

        if target_system_id:
            digest_owner = connection.execute(
                "SELECT system_id, report_id FROM reports WHERE content_digest = ?",
                (digest,),
            ).fetchone()
            if digest_owner is not None and digest_owner["system_id"] != target_system_id:
                connection.rollback()
                return _result(
                    IngestionStatus.IDENTITY_CONFLICT,
                    system_id=target_system_id,
                    digest=digest,
                    schema_version=normalized.schema_version,
                    resolution=resolution,
                    diagnostics=(_diagnostic(
                        "DIGEST_SYSTEM_CONFLICT",
                        "This report digest is already associated with another system.",
                    ),),
                )

        if resolution.state == LegacyIdentityState.UNRESOLVED:
            connection.rollback()
            status = (
                IngestionStatus.IDENTITY_CONFLICT
                if normalized.native_system_id and request.expected_system_id
                else IngestionStatus.IDENTITY_UNRESOLVED
            )
            return _result(
                status,
                digest=digest,
                schema_version=normalized.schema_version,
                resolution=resolution,
                diagnostics=(_diagnostic("IDENTITY_UNRESOLVED", resolution.reason),),
            )

        system_id = resolution.system_id
        duplicate = connection.execute(
            "SELECT report_id FROM reports WHERE system_id = ? AND content_digest = ?",
            (system_id, digest),
        ).fetchone()
        if duplicate is not None:
            connection.rollback()
            return _result(
                IngestionStatus.DUPLICATE,
                report_id=duplicate["report_id"],
                system_id=system_id,
                digest=digest,
                schema_version=normalized.schema_version,
                resolution=resolution,
                diagnostics=(_diagnostic(
                    "DUPLICATE_REPORT",
                    "The same canonical report is already present for this system.",
                    severity=DiagnosticSeverity.INFO,
                ),),
            )

        now = datetime.now(timezone.utc).isoformat()
        report_id = _opaque_id("report", system_id, digest)
        _upsert_system(connection, normalized, resolution, now)
        connection.execute(
            """INSERT INTO reports
               (report_id, system_id, generated_at, ingested_at,
                report_schema_version, content_digest, source_path, source_filename,
                provenance, legacy_identity_state, ingestion_status, coverage_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'COMPLETE', ?)""",
            (
                report_id,
                system_id,
                normalized.generated_at,
                now,
                normalized.schema_version,
                digest,
                str(Path(request.path)),
                Path(request.path).name,
                MemoryProvenance.DETERMINISTIC_OBSERVATION.value,
                resolution.state.value,
                json.dumps(dict(normalized.coverage), sort_keys=True),
            ),
        )
        counts = dict(normalized.score.counts)
        connection.execute(
            """INSERT INTO score_history
               (report_id, system_id, score, risk_level, critical_count, high_count,
                medium_count, low_count, info_count, observed_at, provenance)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                report_id,
                system_id,
                normalized.score.score,
                normalized.score.risk_level,
                counts["CRITICAL"],
                counts["HIGH"],
                counts["MEDIUM"],
                counts["LOW"],
                counts["INFO"],
                normalized.generated_at,
                MemoryProvenance.DETERMINISTIC_OBSERVATION.value,
            ),
        )
        for finding in normalized.findings:
            _write_finding(
                connection, normalized, finding, system_id, report_id, now
            )
        connection.commit()
        diagnostics = []
        if omitted_evidence:
            diagnostics.append(_diagnostic(
                "EVIDENCE_OMITTED",
                f"{omitted_evidence} unsafe or unsupported evidence item(s) were not persisted.",
                severity=DiagnosticSeverity.WARNING,
            ))
        return _result(
            IngestionStatus.INGESTED,
            report_id=report_id,
            system_id=system_id,
            digest=digest,
            schema_version=normalized.schema_version,
            resolution=resolution,
            diagnostics=diagnostics,
        )
    except sqlite3.Error as exc:
        connection.rollback()
        return _result(
            IngestionStatus.FAILED,
            system_id=resolution.system_id if resolution else None,
            digest=digest,
            schema_version=normalized.schema_version,
            resolution=resolution,
            diagnostics=(_diagnostic(
                "TRANSACTION_FAILED",
                "The report transaction failed and was rolled back.",
            ),),
        )
    except Exception:
        connection.rollback()
        return _result(
            IngestionStatus.FAILED,
            system_id=resolution.system_id if resolution else None,
            digest=digest,
            schema_version=normalized.schema_version,
            resolution=resolution,
            diagnostics=(_diagnostic(
                "TRANSACTION_FAILED",
                "The report transaction failed and was rolled back.",
            ),),
        )
