"""Versioned, backward-compatible contracts for deterministic JSON reports."""

import copy
import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Mapping


CURRENT_REPORT_SCHEMA_VERSION = "1.1"
LEGACY_REPORT_SCHEMA_VERSION = "1.0"


class CoverageState(str, Enum):
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    UNKNOWN = "UNKNOWN"


class ScanDomain(str, Enum):
    FIREWALL_TECHNOLOGY = "firewall_technology"
    IPTABLES_INPUT_POLICY = "iptables_input_policy"
    NETWORK_SOCKET_INSPECTION = "network_socket_inspection"


class LegacyIdentityState(str, Enum):
    NATIVE_SYSTEM_ID = "NATIVE_SYSTEM_ID"
    HOSTNAME_FALLBACK = "HOSTNAME_FALLBACK"
    USER_LINKED = "USER_LINKED"
    UNRESOLVED = "UNRESOLVED"


class LegacyLinkPolicy(str, Enum):
    REQUIRE_NATIVE_SYSTEM_ID = "REQUIRE_NATIVE_SYSTEM_ID"
    ALLOW_EXPLICIT_HOSTNAME_FALLBACK = "ALLOW_EXPLICIT_HOSTNAME_FALLBACK"
    REQUIRE_USER_LINK = "REQUIRE_USER_LINK"


@dataclass(frozen=True)
class LegacyIdentityResolution:
    state: LegacyIdentityState
    system_id: str | None
    legacy_hostname: str | None
    policy: LegacyLinkPolicy
    reason: str


def report_schema_version(report: Mapping) -> str:
    """Return the explicit schema version or the legacy version for old reports."""

    value = report.get("schema_version")
    return str(value) if value else LEGACY_REPORT_SCHEMA_VERSION


def normalize_coverage(coverage: Mapping | None) -> dict[str, str]:
    """Return every known scan domain, conservatively defaulting to UNKNOWN."""

    coverage = coverage or {}
    normalized = {}
    for domain in ScanDomain:
        try:
            state = CoverageState(coverage.get(domain.value, CoverageState.UNKNOWN))
        except (TypeError, ValueError):
            state = CoverageState.UNKNOWN
        normalized[domain.value] = state.value
    return normalized


_INGESTION_ONLY_KEYS = frozenset({
    "_report_path",
    "ingested_at",
    "ingestion_timestamp",
    "source_path",
    "source_filename",
})


def canonical_report_bytes(report: Mapping) -> bytes:
    """Canonicalize report content for digesting.

    Object key order and JSON whitespace are normalized. Ingestion-only metadata
    is excluded at every object level. Finding fields and finding identities are
    otherwise preserved exactly; list order remains significant.
    """

    def sanitized(value):
        if isinstance(value, Mapping):
            return {
                str(key): sanitized(item)
                for key, item in value.items()
                if str(key) not in _INGESTION_ONLY_KEYS
            }
        if isinstance(value, (list, tuple)):
            return [sanitized(item) for item in value]
        return copy.deepcopy(value)

    return json.dumps(
        sanitized(report),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_report_digest(report: Mapping) -> str:
    """Return a deterministic SHA-256 digest of canonical report content."""

    return hashlib.sha256(canonical_report_bytes(report)).hexdigest()
