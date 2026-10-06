"""Read-only integrity, canonical report, and operational diagnostics."""

from __future__ import annotations

import errno
import json
import os
import sqlite3
import stat
from datetime import datetime, timezone
from pathlib import Path

from cyberwatchtower.report_contracts import canonical_report_digest

from .database import (
    MemoryDatabase,
    REQUIRED_INDEXES,
    REQUIRED_TABLES,
    validate_memory_database,
)
from .ingestion import MAX_REPORT_BYTES
from .integrity_models import (
    DiagnosticCategory, DiagnosticSeverity, IntegrityDiagnostic, IntegrityReport,
    MemoryStatus, ReportVerification, ReportVerificationStatus,
)
from .migrations import discover_migrations
from .models import CURRENT_MEMORY_SCHEMA_VERSION
from .retention import plan_retention
from .retention_models import RetentionPolicy


REQUIRED_TRIGGERS = frozenset({
    "trg_decision_meaning_immutable", "trg_decision_no_delete",
    "trg_exception_meaning_immutable", "trg_exception_no_delete",
    "trg_approved_baseline_immutable", "trg_baseline_no_delete",
    "trg_investigation_meaning_immutable", "trg_investigation_no_delete",
    "trg_capability_identity_immutable", "trg_capability_event_no_delete",
    "trg_retention_authorization_immutable", "trg_retention_authorization_no_delete",
    "trg_retention_execution_immutable", "trg_retention_execution_no_delete",
    "trg_capability_authorization_immutable",
    "trg_capability_authorization_no_delete",
})
MAX_INTEGRITY_DIAGNOSTIC_ROWS = 1000
# Application health is synchronous, so cap the total SQLite virtual-machine
# work for its complete inspection rather than using a wall-clock timeout.
# Two million steps accommodates the schema-8 checks and the existing bounded
# source probes on ordinary local databases while remaining finite regardless
# of database size. The callback interval limits overshoot to under 1,000 VM
# instructions and avoids invoking Python for every SQLite instruction.
_APPLICATION_HEALTH_PROGRESS_INTERVAL = 1000
_APPLICATION_HEALTH_MAX_VM_STEPS = 2_000_000
_APPLICATION_HEALTH_BUDGET_CODE = "APPLICATION_HEALTH_BUDGET_EXHAUSTED"


def _diagnostic(severity, category, code, summary, count=1):
    return IntegrityDiagnostic(severity, category, code, summary, int(count))


def _source_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    """Return fields that must remain stable throughout one source read."""

    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _source_open_failure(error: OSError) -> ReportVerificationStatus:
    if error.errno in (errno.ENOENT, errno.ENOTDIR):
        return ReportVerificationStatus.SOURCE_MISSING
    if error.errno == errno.ELOOP:
        return ReportVerificationStatus.INVALID_SOURCE
    return ReportVerificationStatus.SOURCE_INACCESSIBLE


def _bounded_source_bytes(path: Path) -> tuple[bytes | None, ReportVerificationStatus | None]:
    """Read one stable regular legacy source without following links.

    The read limit reuses the report-ingestion authority. Platforms without
    no-follow and nonblocking open primitives fail verification rather than
    falling back to a pathname reopen that could race, follow a link, or block
    on a nonregular object substituted after the initial classification.
    """

    try:
        before = os.lstat(path)
    except FileNotFoundError:
        return None, ReportVerificationStatus.SOURCE_MISSING
    except PermissionError:
        return None, ReportVerificationStatus.SOURCE_INACCESSIBLE
    except (OSError, TypeError, ValueError):
        return None, ReportVerificationStatus.SOURCE_INACCESSIBLE
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        return None, ReportVerificationStatus.INVALID_SOURCE
    if before.st_size > MAX_REPORT_BYTES:
        return None, ReportVerificationStatus.INVALID_SOURCE

    no_follow = getattr(os, "O_NOFOLLOW", None)
    nonblocking = getattr(os, "O_NONBLOCK", None)
    if no_follow is None or nonblocking is None:
        return None, ReportVerificationStatus.INVALID_SOURCE
    flags = os.O_RDONLY | no_follow | nonblocking
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY

    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        return None, _source_open_failure(error)

    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _source_identity(opened) != _source_identity(before)
            or opened.st_size > MAX_REPORT_BYTES
        ):
            return None, ReportVerificationStatus.INVALID_SOURCE

        remaining = MAX_REPORT_BYTES + 1
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > MAX_REPORT_BYTES:
            return None, ReportVerificationStatus.INVALID_SOURCE

        after_read = os.fstat(descriptor)
        if (
            not stat.S_ISREG(after_read.st_mode)
            or _source_identity(after_read) != _source_identity(opened)
        ):
            return None, ReportVerificationStatus.INVALID_SOURCE
    except PermissionError:
        return None, ReportVerificationStatus.SOURCE_INACCESSIBLE
    except OSError:
        return None, ReportVerificationStatus.SOURCE_INACCESSIBLE
    finally:
        os.close(descriptor)

    try:
        after_path = os.lstat(path)
    except FileNotFoundError:
        return None, ReportVerificationStatus.SOURCE_MISSING
    except PermissionError:
        return None, ReportVerificationStatus.SOURCE_INACCESSIBLE
    except (OSError, TypeError, ValueError):
        return None, ReportVerificationStatus.SOURCE_INACCESSIBLE
    if (
        stat.S_ISLNK(after_path.st_mode)
        or not stat.S_ISREG(after_path.st_mode)
        or _source_identity(after_path) != _source_identity(opened)
    ):
        return None, ReportVerificationStatus.INVALID_SOURCE
    return data, None


def _verify_canonical_report_bounded(
    database: MemoryDatabase,
    *,
    system_id: str,
    report_id: str,
) -> ReportVerification:
    """Bounded legacy-source verification for application health only."""

    row = database.connection.execute(
        """SELECT content_digest,source_path,source_filename FROM reports
        WHERE system_id=? AND report_id=?""",
        (system_id, report_id),
    ).fetchone()
    if row is None:
        return ReportVerification(report_id, ReportVerificationStatus.REPORT_NOT_FOUND)
    if row["source_path"] is None and row["source_filename"] is None:
        return ReportVerification(
            report_id,
            ReportVerificationStatus.NOT_APPLICABLE_PATHLESS_SOURCE,
        )
    if not row["source_path"]:
        return ReportVerification(report_id, ReportVerificationStatus.SOURCE_MISSING)

    try:
        path = Path(row["source_path"])
    except (TypeError, ValueError):
        return ReportVerification(report_id, ReportVerificationStatus.INVALID_SOURCE)
    data, failure = _bounded_source_bytes(path)
    if failure is not None:
        return ReportVerification(report_id, failure)

    try:
        raw = json.loads(data.decode("utf-8", errors="strict"))
        if not isinstance(raw, dict):
            return ReportVerification(report_id, ReportVerificationStatus.INVALID_SOURCE)
        digest = canonical_report_digest(raw)
    except UnicodeError:
        return ReportVerification(report_id, ReportVerificationStatus.INVALID_SOURCE)
    except (json.JSONDecodeError, TypeError, ValueError):
        return ReportVerification(report_id, ReportVerificationStatus.INVALID_SOURCE)
    status = (
        ReportVerificationStatus.VERIFIED
        if digest == row["content_digest"]
        else ReportVerificationStatus.DIGEST_MISMATCH
    )
    return ReportVerification(report_id, status)


def _run_integrity_checks(
    database: MemoryDatabase,
    *,
    at: datetime | None,
    diagnostics: list[IntegrityDiagnostic],
    report_verifier=None,
) -> int:
    """Run the existing deep checks, retaining diagnostics if interrupted."""

    c = database.connection
    now = (at or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()
    quick = c.execute("PRAGMA quick_check").fetchone()[0]
    if quick != "ok":
        diagnostics.append(_diagnostic(DiagnosticSeverity.ERROR, DiagnosticCategory.SQLITE,
            "SQLITE_QUICK_CHECK_FAILED", "SQLite quick_check reported corruption."))
    fk = c.execute("PRAGMA foreign_key_check").fetchall()
    if fk:
        diagnostics.append(_diagnostic(DiagnosticSeverity.ERROR, DiagnosticCategory.RELATIONSHIP,
            "FOREIGN_KEY_VIOLATION", "Foreign-key integrity violations exist.", len(fk)))
    version = int(c.execute("PRAGMA user_version").fetchone()[0])
    migrations = discover_migrations()
    applied = {row["version"]: row for row in c.execute(
        "SELECT version,name,checksum FROM schema_migrations")}
    if version != CURRENT_MEMORY_SCHEMA_VERSION or max(applied, default=0) != version:
        diagnostics.append(_diagnostic(DiagnosticSeverity.ERROR, DiagnosticCategory.MIGRATION,
            "MIGRATION_VERSION_MISMATCH", "Schema and migration versions are inconsistent."))
    for migration in migrations:
        row = applied.get(migration.version)
        if row is None or row["name"] != migration.name or row["checksum"] != migration.checksum:
            diagnostics.append(_diagnostic(DiagnosticSeverity.ERROR, DiagnosticCategory.MIGRATION,
                "MIGRATION_CHECKSUM_MISMATCH", "Checksummed migration history is invalid."))
            break
    objects = {(row["type"], row["name"]) for row in c.execute(
        "SELECT type,name FROM sqlite_master WHERE type IN ('table','index','trigger')")}
    missing = (
        {name for name in REQUIRED_TABLES if ("table", name) not in objects}
        | {name for name in REQUIRED_INDEXES if ("index", name) not in objects}
        | {name for name in REQUIRED_TRIGGERS if ("trigger", name) not in objects}
    )
    if missing:
        diagnostics.append(_diagnostic(DiagnosticSeverity.ERROR, DiagnosticCategory.SCHEMA,
            "REQUIRED_SCHEMA_OBJECT_MISSING", "Required schema objects are missing.", len(missing)))
    lifecycle = c.execute("""SELECT COUNT(*) FROM findings WHERE occurrence_count<1
        OR reopened_count<0 OR (active=1 AND lifecycle_state='RESOLVED')
        OR (active=0 AND lifecycle_state='ACTIVE')""").fetchone()[0]
    if lifecycle:
        diagnostics.append(_diagnostic(DiagnosticSeverity.ERROR, DiagnosticCategory.LIFECYCLE,
            "IMPOSSIBLE_LIFECYCLE_STATE", "Impossible finding lifecycle states exist.", lifecycle))
    expired = c.execute("""SELECT COUNT(*) FROM exceptions
        WHERE status='ACTIVE' AND expires_at<=?""", (now,)).fetchone()[0]
    if expired:
        diagnostics.append(_diagnostic(DiagnosticSeverity.WARNING, DiagnosticCategory.DECISION,
            "EXPIRED_EXCEPTION_STORED_ACTIVE", "Expired exceptions remain stored as ACTIVE but fail closed at query time.", expired))
    baseline = c.execute("""SELECT COUNT(*) FROM (SELECT system_id,baseline_type
        FROM baselines WHERE state='APPROVED' GROUP BY system_id,baseline_type HAVING COUNT(*)>1)""").fetchone()[0]
    if baseline:
        diagnostics.append(_diagnostic(DiagnosticSeverity.ERROR, DiagnosticCategory.DECISION,
            "MULTIPLE_CURRENT_BASELINES", "Multiple current approved baseline versions exist.", baseline))
    invalid_auth = c.execute("""SELECT COUNT(*) FROM retention_authorizations a
        LEFT JOIN user_decisions d ON d.decision_id=a.decision_id AND d.system_id=a.system_id
        WHERE d.decision_id IS NULL""").fetchone()[0]
    if invalid_auth:
        diagnostics.append(_diagnostic(DiagnosticSeverity.ERROR, DiagnosticCategory.RELATIONSHIP,
            "INVALID_RETENTION_AUTHORIZATION", "Retention authorization linkage is invalid.", invalid_auth))
    verification_counts = {}
    report_rows = c.execute("""SELECT report_id,system_id FROM reports
        ORDER BY generated_at DESC,report_id LIMIT ?""",
        (MAX_INTEGRITY_DIAGNOSTIC_ROWS + 1,)).fetchall()
    verification_truncated = len(report_rows) > MAX_INTEGRITY_DIAGNOSTIC_ROWS
    verify_report = report_verifier or verify_canonical_report
    for report_row in report_rows[:MAX_INTEGRITY_DIAGNOSTIC_ROWS]:
        verification = verify_report(
            database, system_id=report_row["system_id"],
            report_id=report_row["report_id"],
        )
        verification_counts[verification.status] = verification_counts.get(verification.status, 0) + 1
    if verification_truncated:
        diagnostics.append(_diagnostic(
            DiagnosticSeverity.WARNING,
            DiagnosticCategory.REPORT,
            "REPORT_VERIFICATION_BOUNDED",
            "Canonical source verification was limited to the newest bounded set.",
            MAX_INTEGRITY_DIAGNOSTIC_ROWS,
        ))
    if verification_counts.get(ReportVerificationStatus.DIGEST_MISMATCH):
        diagnostics.append(_diagnostic(DiagnosticSeverity.ERROR, DiagnosticCategory.REPORT,
            "REPORT_DIGEST_MISMATCH", "Canonical report digest mismatches exist.",
            verification_counts[ReportVerificationStatus.DIGEST_MISMATCH]))
    unavailable_sources = sum(verification_counts.get(status, 0) for status in (
        ReportVerificationStatus.SOURCE_MISSING,
        ReportVerificationStatus.SOURCE_INACCESSIBLE,
        ReportVerificationStatus.INVALID_SOURCE,
    ))
    if unavailable_sources:
        diagnostics.append(_diagnostic(DiagnosticSeverity.WARNING, DiagnosticCategory.REPORT,
            "REPORT_SOURCE_UNVERIFIED", "Some canonical report sources could not be verified.",
            unavailable_sources))
    return version


def _integrity_report(
    version: int,
    diagnostics: list[IntegrityDiagnostic],
) -> IntegrityReport:
    health = (
        "HEALTHY"
        if not any(item.severity == DiagnosticSeverity.ERROR for item in diagnostics)
        else "DEGRADED"
    )
    return IntegrityReport(health, version, tuple(diagnostics))


def check_integrity(database: MemoryDatabase, *, at: datetime | None = None) -> IntegrityReport:
    """Inspect invariants without modifying or repairing storage."""

    diagnostics: list[IntegrityDiagnostic] = []
    try:
        version = _run_integrity_checks(
            database,
            at=at,
            diagnostics=diagnostics,
        )
        return _integrity_report(version, diagnostics)
    except (sqlite3.DatabaseError, KeyError, TypeError, ValueError):
        return IntegrityReport("UNAVAILABLE", None, (
            _diagnostic(DiagnosticSeverity.ERROR, DiagnosticCategory.SQLITE,
                        "INTEGRITY_CHECK_UNAVAILABLE", "Memory integrity could not be checked safely."),
        ))


def _bounded_application_health(
    database: MemoryDatabase,
    *,
    at: datetime | None = None,
) -> IntegrityReport:
    """Run application health under one cumulative SQLite VM-step budget."""

    interval = _APPLICATION_HEALTH_PROGRESS_INTERVAL
    maximum = _APPLICATION_HEALTH_MAX_VM_STEPS
    if (
        isinstance(interval, bool)
        or not isinstance(interval, int)
        or interval < 1
        or isinstance(maximum, bool)
        or not isinstance(maximum, int)
        or maximum < interval
    ):
        raise RuntimeError("Application health work budget is invalid.")

    callbacks_allowed = maximum // interval
    callbacks = 0
    exhausted = False
    diagnostics: list[IntegrityDiagnostic] = []

    def progress() -> int:
        nonlocal callbacks, exhausted
        callbacks += 1
        if callbacks >= callbacks_allowed:
            exhausted = True
            return 1
        return 0

    connection = database.connection
    connection.set_progress_handler(progress, interval)
    try:
        try:
            validate_memory_database(connection)
            version = _run_integrity_checks(
                database,
                at=at,
                diagnostics=diagnostics,
                report_verifier=_verify_canonical_report_bounded,
            )
            return _integrity_report(version, diagnostics)
        except Exception:
            if not exhausted:
                raise
            diagnostics.append(_diagnostic(
                DiagnosticSeverity.WARNING,
                DiagnosticCategory.SQLITE,
                _APPLICATION_HEALTH_BUDGET_CODE,
                "Bounded application health inspection did not complete.",
            ))
            return _integrity_report(database.info.schema_version, diagnostics)
    finally:
        connection.set_progress_handler(None, 0)


def verify_canonical_report(database: MemoryDatabase, *, system_id: str,
                            report_id: str) -> ReportVerification:
    row = database.connection.execute("""SELECT content_digest,source_path,source_filename FROM reports
        WHERE system_id=? AND report_id=?""", (system_id, report_id)).fetchone()
    if row is None:
        return ReportVerification(report_id, ReportVerificationStatus.REPORT_NOT_FOUND)
    if row["source_path"] is None and row["source_filename"] is None:
        return ReportVerification(
            report_id,
            ReportVerificationStatus.NOT_APPLICABLE_PATHLESS_SOURCE,
        )
    if not row["source_path"]:
        return ReportVerification(report_id, ReportVerificationStatus.SOURCE_MISSING)
    path = Path(row["source_path"])
    if not path.exists():
        return ReportVerification(report_id, ReportVerificationStatus.SOURCE_MISSING)
    try:
        with path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
        digest = canonical_report_digest(raw)
    except PermissionError:
        return ReportVerification(report_id, ReportVerificationStatus.SOURCE_INACCESSIBLE)
    except (OSError, UnicodeError):
        return ReportVerification(report_id, ReportVerificationStatus.SOURCE_INACCESSIBLE)
    except (json.JSONDecodeError, TypeError, ValueError):
        return ReportVerification(report_id, ReportVerificationStatus.INVALID_SOURCE)
    status = (ReportVerificationStatus.VERIFIED if digest == row["content_digest"]
              else ReportVerificationStatus.DIGEST_MISMATCH)
    return ReportVerification(report_id, status)


def memory_status(database: MemoryDatabase, *, system_id: str,
                  at: datetime | None = None,
                  policy: RetentionPolicy | None = None) -> MemoryStatus:
    now = at or datetime.now(timezone.utc)
    c = database.connection
    latest = c.execute("SELECT MAX(generated_at) FROM reports WHERE system_id=?",
                       (system_id,)).fetchone()[0]
    safe_tables = {
        "reports": "reports", "findings": "findings",
        "investigations": "investigations", "decisions": "user_decisions",
        "baselines": "baselines", "retention_audits": "retention_executions",
    }
    counts = tuple((label, int(c.execute(
        f"SELECT COUNT(*) FROM {table} WHERE system_id=?" if table != "retention_executions"
        else "SELECT COUNT(*) FROM retention_executions", (system_id,) if table != "retention_executions" else ()
    ).fetchone()[0])) for label, table in safe_tables.items())
    current = now.astimezone(timezone.utc).isoformat()
    active = c.execute("""SELECT COUNT(*) FROM exceptions WHERE system_id=?
        AND status='ACTIVE' AND starts_at<=? AND expires_at>?""",
        (system_id, current, current)).fetchone()[0]
    pending = c.execute("""SELECT COUNT(*) FROM exceptions WHERE system_id=?
        AND status='ACTIVE' AND starts_at>?""", (system_id, current)).fetchone()[0]
    expired = c.execute("""SELECT COUNT(*) FROM exceptions WHERE system_id=?
        AND expires_at<=?""", (system_id, current)).fetchone()[0]
    integrity = check_integrity(database, at=now)
    diagnostic_counts = {}
    for item in integrity.diagnostics:
        diagnostic_counts[item.severity.value] = diagnostic_counts.get(item.severity.value, 0) + item.count
    plan = plan_retention(database, system_id=system_id, at=now, policy=policy)
    return MemoryStatus(integrity.health, database.info.schema_version, latest, counts,
                        int(active), int(pending), int(expired), len(plan.selected_items),
                        tuple(sorted(diagnostic_counts.items())))


def diagnose_memory_path(path: str | Path) -> IntegrityReport:
    """Read-only best-effort diagnostics for a database that may not open normally."""
    connection = None
    try:
        uri = Path(path).resolve().as_uri() + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True)
        quick = connection.execute("PRAGMA quick_check").fetchone()[0]
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if quick == "ok":
            severity, health, code = DiagnosticSeverity.INFO, "READABLE", "SQLITE_READABLE"
        else:
            severity, health, code = DiagnosticSeverity.ERROR, "DEGRADED", "SQLITE_QUICK_CHECK_FAILED"
        return IntegrityReport(health, version, (
            _diagnostic(severity, DiagnosticCategory.SQLITE, code,
                        "Memory database was inspected read-only."),
        ))
    except Exception:
        return IntegrityReport("UNAVAILABLE", None, (
            _diagnostic(DiagnosticSeverity.ERROR, DiagnosticCategory.SQLITE,
                        "DATABASE_UNAVAILABLE", "Memory database is unavailable; preserve it for manual inspection."),
        ))
    finally:
        if connection is not None:
            connection.close()
