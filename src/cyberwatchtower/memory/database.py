import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from .errors import (
    MemoryCorrupt,
    MemoryIntegrityError,
    MemoryLocked,
    MemoryUnavailable,
    MemoryErrorBase,
)
from .migrations import apply_migrations
from .models import CURRENT_MEMORY_SCHEMA_VERSION, MemoryDatabaseInfo


DEFAULT_BUSY_TIMEOUT_MS = 2_000
REQUIRED_TABLES = frozenset({
    "schema_migrations",
    "systems",
    "system_aliases",
    "reports",
    "score_history",
    "findings",
    "finding_occurrences",
    "finding_lifecycle_events",
    "user_decisions",
    "exceptions",
    "baselines",
    "baseline_entries",
    "recommendations_shown",
    "action_responses",
    "investigations",
    "investigation_status_events",
    "investigation_findings",
    "investigation_scopes",
    "investigation_evidence",
    "investigation_questions",
    "capability_executions",
    "capability_execution_events",
    "investigation_recommendations",
    "conversation_references",
    "retention_guard",
    "retention_authorizations",
    "retention_executions",
})
REQUIRED_INDEXES = frozenset({
    "idx_system_aliases_lookup",
    "idx_reports_system_generated",
    "idx_score_history_system_observed",
    "idx_findings_system_active_recurring",
    "idx_occurrences_finding_observed",
    "idx_occurrences_system_finding_observed",
    "idx_lifecycle_finding_occurred",
    "idx_decisions_scope",
    "idx_exceptions_active",
    "idx_exceptions_scope",
    "idx_baselines_history",
    "idx_baseline_entries_order",
    "idx_recommendations_action",
    "idx_action_responses_history",
    "idx_investigations_open",
    "idx_investigation_status_time",
    "idx_investigation_findings_lookup",
    "idx_investigation_scopes_lookup",
    "idx_investigation_evidence_time",
    "idx_investigation_questions_time",
    "idx_capability_investigation",
    "idx_capability_event_time",
    "idx_conversation_references_active",
    "idx_retention_authorizations_plan",
    "idx_retention_executions_time",
})


@dataclass
class MemoryDatabase:
    path: Path
    connection: sqlite3.Connection
    info: MemoryDatabaseInfo
    readonly: bool = False

    def close(self) -> None:
        self.connection.close()
        if not self.readonly:
            _private_companion_files(self.path)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()


def _private_path(path: Path) -> None:
    if path.is_symlink():
        raise MemoryUnavailable("Persistent Security Memory path must not be a symlink.")
    current = path.parent
    while current != current.parent:
        if current.exists() and current.is_symlink():
            raise MemoryUnavailable("Persistent Security Memory directory must not be a symlink.")
        current = current.parent
    parent_existed = path.parent.exists()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        if parent_existed:
            mode = path.parent.stat().st_mode & 0o777
            if mode & 0o077:
                raise MemoryUnavailable(
                    "Persistent Security Memory requires an existing private directory."
                )
        else:
            path.parent.chmod(0o700)


def _private_companion_files(path: Path) -> None:
    if os.name != "posix":
        return
    for suffix in ("-wal", "-shm"):
        companion = Path(f"{path}{suffix}")
        if companion.exists() and not companion.is_symlink():
            companion.chmod(0o600)


def _connect(path: Path, busy_timeout_ms: int) -> sqlite3.Connection:
    try:
        connection = sqlite3.connect(path, timeout=busy_timeout_ms / 1000)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {int(busy_timeout_ms)}")
        if hasattr(connection, "enable_load_extension"):
            connection.enable_load_extension(False)
        if os.name == "posix":
            path.chmod(0o600)
            _private_companion_files(path)
        return connection
    except sqlite3.OperationalError as exc:
        if "locked" in str(exc).casefold():
            raise MemoryLocked("Persistent Security Memory is locked.") from exc
        raise MemoryUnavailable("Persistent Security Memory is unavailable.") from exc
    except OSError as exc:
        raise MemoryUnavailable("Persistent Security Memory path is unavailable.") from exc


def validate_memory_database(connection: sqlite3.Connection) -> None:
    try:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version != CURRENT_MEMORY_SCHEMA_VERSION:
            raise MemoryIntegrityError(
                f"Expected schema {CURRENT_MEMORY_SCHEMA_VERSION}, found {version}."
            )
        foreign_keys = int(connection.execute("PRAGMA foreign_keys").fetchone()[0])
        if foreign_keys != 1:
            raise MemoryIntegrityError("SQLite foreign-key enforcement is disabled.")
        objects = {
            row["name"]: row["type"]
            for row in connection.execute(
                "SELECT name, type FROM sqlite_master WHERE type IN ('table', 'index')"
            )
        }
        missing_tables = REQUIRED_TABLES - objects.keys()
        missing_indexes = REQUIRED_INDEXES - objects.keys()
        if missing_tables or missing_indexes:
            raise MemoryIntegrityError(
                f"Memory schema is incomplete; missing tables={sorted(missing_tables)}, "
                f"indexes={sorted(missing_indexes)}."
            )
        violations = connection.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise MemoryIntegrityError("Memory schema contains foreign-key violations.")
        missing_occurrence_ids = connection.execute(
            """SELECT COUNT(*) FROM finding_occurrences
               WHERE stable_finding_id IS NULL OR length(stable_finding_id) = 0"""
        ).fetchone()[0]
        if missing_occurrence_ids:
            raise MemoryIntegrityError(
                "Memory schema contains occurrences without immutable finding identities."
            )
        quick_check = connection.execute("PRAGMA quick_check").fetchone()[0]
        if quick_check != "ok":
            raise MemoryIntegrityError("SQLite quick_check did not return ok.")
    except sqlite3.DatabaseError as exc:
        raise MemoryCorrupt("Persistent Security Memory failed integrity validation.") from exc


def open_memory_database(
    path: str | Path,
    *,
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
    migration_directory: Path | None = None,
) -> MemoryDatabase:
    """Securely open, migrate, and validate a local memory database."""

    database_path = Path(path)
    _private_path(database_path)
    connection = _connect(database_path, busy_timeout_ms)
    try:
        apply_migrations(connection, migration_directory)
        validate_memory_database(connection)
        migration_count = int(
            connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0]
        )
        info = MemoryDatabaseInfo(
            database_path,
            CURRENT_MEMORY_SCHEMA_VERSION,
            migration_count,
            True,
            int(connection.execute("PRAGMA busy_timeout").fetchone()[0]),
        )
        return MemoryDatabase(database_path, connection, info)
    except MemoryErrorBase:
        connection.close()
        raise
    except sqlite3.DatabaseError as exc:
        connection.close()
        raise MemoryCorrupt("Persistent Security Memory is not a valid database.") from exc
    except Exception:
        connection.close()
        raise


def open_memory_database_readonly(path: str | Path) -> MemoryDatabase:
    """Open an existing current-schema database without migrations or writes."""
    database_path = Path(path)
    if database_path.is_symlink() or not database_path.is_file():
        raise MemoryUnavailable("Persistent Security Memory is unavailable.")
    try:
        connection = sqlite3.connect(database_path.resolve().as_uri() + "?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {DEFAULT_BUSY_TIMEOUT_MS}")
        if hasattr(connection, "enable_load_extension"):
            connection.enable_load_extension(False)
        validate_memory_database(connection)
        migration_count = int(connection.execute(
            "SELECT COUNT(*) FROM schema_migrations").fetchone()[0])
        return MemoryDatabase(database_path, connection, MemoryDatabaseInfo(
            database_path, CURRENT_MEMORY_SCHEMA_VERSION, migration_count, True,
            DEFAULT_BUSY_TIMEOUT_MS,
        ), True)
    except MemoryErrorBase:
        if "connection" in locals():
            connection.close()
        raise
    except sqlite3.DatabaseError as exc:
        if "connection" in locals():
            connection.close()
        raise MemoryCorrupt("Persistent Security Memory is not readable.") from exc
