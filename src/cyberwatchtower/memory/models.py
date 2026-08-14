from dataclasses import dataclass
from pathlib import Path

from .provenance import MemoryProvenance


CURRENT_MEMORY_SCHEMA_VERSION = 3


@dataclass(frozen=True)
class MigrationRecord:
    version: int
    name: str
    checksum: str
    applied_at: str
    application_version: str


@dataclass(frozen=True)
class MemoryDatabaseInfo:
    path: Path
    schema_version: int
    migration_count: int
    foreign_keys_enabled: bool
    busy_timeout_ms: int


@dataclass(frozen=True)
class SystemRecord:
    system_id: str
    display_hostname: str | None
    identity_confidence: str
    provenance: MemoryProvenance


@dataclass(frozen=True)
class ReportRecord:
    report_id: str
    system_id: str
    generated_at: str
    report_schema_version: str
    content_digest: str
    provenance: MemoryProvenance
