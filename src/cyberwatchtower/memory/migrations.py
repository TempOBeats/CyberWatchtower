import hashlib
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path

from .errors import (
    MemoryIncompatibleVersion,
    MemoryMigrationChecksumMismatch,
    MemoryMigrationFailed,
)
from .models import CURRENT_MEMORY_SCHEMA_VERSION


APPLICATION_SCHEMA_VERSION = "memory-v0.2"
_MIGRATION_NAME = re.compile(r"^(?P<version>\d{4})_(?P<name>[a-z0-9_]+)\.sql$")


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    sql: str
    checksum: str


def _migration(sql_path) -> Migration:
    match = _MIGRATION_NAME.match(sql_path.name)
    if match is None:
        raise MemoryMigrationFailed(f"Invalid migration filename: {sql_path.name}")
    sql = sql_path.read_text(encoding="utf-8")
    return Migration(
        int(match.group("version")),
        match.group("name"),
        sql,
        hashlib.sha256(sql.encode("utf-8")).hexdigest(),
    )


def discover_migrations(directory: Path | None = None) -> tuple[Migration, ...]:
    root = Path(directory) if directory else files("cyberwatchtower.memory.schema")
    migrations = tuple(
        sorted(
            (_migration(item) for item in root.iterdir() if item.name.endswith(".sql")),
            key=lambda item: item.version,
        )
    )
    expected = tuple(range(1, len(migrations) + 1))
    versions = tuple(item.version for item in migrations)
    if versions != expected:
        raise MemoryMigrationFailed(
            f"Migration versions must be contiguous from 1; found {versions}."
        )
    return migrations


def _statements(sql: str):
    buffer = ""
    for line in sql.splitlines(keepends=True):
        buffer += line
        if sqlite3.complete_statement(buffer):
            statement = buffer.strip()
            buffer = ""
            if statement:
                yield statement
    if buffer.strip():
        raise MemoryMigrationFailed("Migration ends with an incomplete SQL statement.")


def _has_migration_table(connection: sqlite3.Connection) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        ("schema_migrations",),
    ).fetchone()
    return row is not None


def _applied_migrations(connection: sqlite3.Connection) -> dict[int, sqlite3.Row]:
    if not _has_migration_table(connection):
        return {}
    return {
        int(row["version"]): row
        for row in connection.execute(
            "SELECT version, name, checksum FROM schema_migrations ORDER BY version"
        )
    }


def apply_migrations(
    connection: sqlite3.Connection,
    migration_directory: Path | None = None,
) -> None:
    migrations = discover_migrations(migration_directory)
    if not migrations or migrations[-1].version != CURRENT_MEMORY_SCHEMA_VERSION:
        raise MemoryMigrationFailed(
            "Packaged migrations do not match CURRENT_MEMORY_SCHEMA_VERSION."
        )

    database_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    if database_version > CURRENT_MEMORY_SCHEMA_VERSION:
        raise MemoryIncompatibleVersion(
            f"Database schema {database_version} is newer than supported schema "
            f"{CURRENT_MEMORY_SCHEMA_VERSION}."
        )

    applied = _applied_migrations(connection)
    if database_version and not applied:
        raise MemoryIncompatibleVersion(
            "Database has a schema version but no checksummed migration history."
        )
    if applied:
        latest_applied = max(applied)
        if latest_applied > CURRENT_MEMORY_SCHEMA_VERSION:
            raise MemoryIncompatibleVersion(
                f"Migration history {latest_applied} is newer than supported schema "
                f"{CURRENT_MEMORY_SCHEMA_VERSION}."
            )
        if latest_applied != database_version:
            raise MemoryIncompatibleVersion(
                "PRAGMA user_version does not match the checksummed migration history."
            )

    for migration in migrations:
        record = applied.get(migration.version)
        if record is None:
            continue
        if record["name"] != migration.name or record["checksum"] != migration.checksum:
            raise MemoryMigrationChecksumMismatch(
                f"Migration {migration.version:04d}_{migration.name} checksum mismatch."
            )

    pending = [item for item in migrations if item.version not in applied]
    for migration in pending:
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    checksum TEXT NOT NULL,
                    applied_at TEXT NOT NULL,
                    application_version TEXT NOT NULL
                )"""
            )
            for statement in _statements(migration.sql):
                connection.execute(statement)
            connection.execute(
                """INSERT INTO schema_migrations
                   (version, name, checksum, applied_at, application_version)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    migration.version,
                    migration.name,
                    migration.checksum,
                    datetime.now(timezone.utc).isoformat(),
                    APPLICATION_SCHEMA_VERSION,
                ),
            )
            connection.execute(f"PRAGMA user_version = {migration.version}")
            connection.commit()
        except (sqlite3.Error, MemoryMigrationFailed) as exc:
            connection.rollback()
            if isinstance(exc, MemoryMigrationFailed):
                raise
            raise MemoryMigrationFailed(
                f"Migration {migration.version:04d}_{migration.name} failed."
            ) from exc
