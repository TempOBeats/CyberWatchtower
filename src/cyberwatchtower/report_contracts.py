"""Versioned, backward-compatible contracts for deterministic JSON reports."""

import copy
import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Mapping


CURRENT_REPORT_SCHEMA_VERSION = "1.5"
SCORING_REPORT_SCHEMA_VERSION = "1.4"
REACHABILITY_REPORT_SCHEMA_VERSION = "1.3"
APPLICABLE_DOMAINS_REPORT_SCHEMA_VERSION = "1.2"
STRUCTURED_FINDING_REPORT_SCHEMA_VERSION = "1.1"
LEGACY_REPORT_SCHEMA_VERSION = "1.0"


class CoverageState(str, Enum):
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    UNKNOWN = "UNKNOWN"


class AssessmentAssurance(str, Enum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    INCOMPLETE = "INCOMPLETE"


class ScanDomain(str, Enum):
    FIREWALL_TECHNOLOGY = "firewall_technology"
    IPTABLES_INPUT_POLICY = "iptables_input_policy"
    FIREWALL_INBOUND_POLICY = "firewall_inbound_policy"
    NETWORK_SOCKET_INSPECTION = "network_socket_inspection"
    NETWORK_REACHABILITY = "network_reachability"


LEGACY_ASSESSMENT_DOMAINS: tuple[ScanDomain, ...] = (
    ScanDomain.FIREWALL_TECHNOLOGY,
    ScanDomain.IPTABLES_INPUT_POLICY,
    ScanDomain.NETWORK_SOCKET_INSPECTION,
)


SOURCE_COVERAGE_REQUIREMENTS: dict[str, tuple[ScanDomain, ...]] = {
    "network": (ScanDomain.NETWORK_SOCKET_INSPECTION,),
    "firewall_technology": (ScanDomain.FIREWALL_TECHNOLOGY,),
    # Current firewall findings share one source value. Requiring both domains
    # is conservative and avoids guessing from finding titles.
    "firewall": (
        ScanDomain.FIREWALL_TECHNOLOGY,
        ScanDomain.IPTABLES_INPUT_POLICY,
    ),
    "firewall_inbound_policy": (ScanDomain.FIREWALL_INBOUND_POLICY,),
}


COVERAGE_LIMITATION_MESSAGES: dict[ScanDomain, str] = {
    ScanDomain.FIREWALL_TECHNOLOGY: (
        "firewall technology detection was not completely assessed"
    ),
    ScanDomain.IPTABLES_INPUT_POLICY: (
        "iptables INPUT policy was not completely assessed"
    ),
    ScanDomain.FIREWALL_INBOUND_POLICY: (
        "inbound firewall policy was not completely assessed"
    ),
    ScanDomain.NETWORK_SOCKET_INSPECTION: (
        "listening-service inspection was not completely assessed"
    ),
    ScanDomain.NETWORK_REACHABILITY: (
        "listener reachability was not completely assessed"
    ),
}


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


def legacy_resolution_authorizes(
    resolution: LegacyIdentityResolution | None,
    *,
    system_id: str,
    hostname: str | None,
) -> bool:
    """Validate an explicit legacy link without assigning identity to the report."""

    if not isinstance(resolution, LegacyIdentityResolution):
        return False
    valid_state_policy = (
        resolution.state == LegacyIdentityState.HOSTNAME_FALLBACK
        and resolution.policy == LegacyLinkPolicy.ALLOW_EXPLICIT_HOSTNAME_FALLBACK
    ) or (
        resolution.state == LegacyIdentityState.USER_LINKED
        and resolution.policy == LegacyLinkPolicy.REQUIRE_USER_LINK
    )
    return bool(
        valid_state_policy
        and resolution.system_id == system_id
        and hostname
        and resolution.legacy_hostname == hostname
    )


def report_schema_version(report: Mapping) -> str:
    """Return the explicit schema version or the legacy version for old reports."""

    value = report.get("schema_version")
    return str(value) if value else LEGACY_REPORT_SCHEMA_VERSION


def normalize_assessment_domains(
    domains: object | None,
) -> tuple[ScanDomain, ...]:
    """Validate applicable domains, retaining the legacy set when omitted."""

    if domains is None:
        return LEGACY_ASSESSMENT_DOMAINS
    if not isinstance(domains, (list, tuple)) or not domains:
        raise TypeError("assessment_domains must be a non-empty list.")
    try:
        normalized = tuple(
            item if isinstance(item, ScanDomain) else ScanDomain(item)
            for item in domains
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("assessment_domains contains an unknown domain.") from exc
    if len(set(normalized)) != len(normalized):
        raise ValueError("assessment_domains cannot contain duplicates.")
    return normalized


def report_assessment_domains(report: Mapping) -> tuple[ScanDomain, ...]:
    """Return explicitly applicable domains or conservative legacy semantics."""

    return normalize_assessment_domains(report.get("assessment_domains"))


def normalize_coverage(
    coverage: Mapping | None,
    assessment_domains: object | None = None,
) -> dict[str, str]:
    """Normalize applicable domains, conservatively defaulting states to UNKNOWN."""

    coverage = coverage if isinstance(coverage, Mapping) else {}
    normalized = {}
    for domain in normalize_assessment_domains(assessment_domains):
        try:
            state = CoverageState(coverage.get(domain.value, CoverageState.UNKNOWN))
        except (TypeError, ValueError):
            state = CoverageState.UNKNOWN
        normalized[domain.value] = state.value
    return normalized


def coverage_complete_for_source(
    source: object,
    coverage: Mapping | None,
    assessment_domains: object | None = None,
) -> bool:
    """Return whether structured coverage can prove a source-domain absence."""

    requirements = SOURCE_COVERAGE_REQUIREMENTS.get(str(source).casefold())
    if not requirements:
        return False
    try:
        applicable = normalize_assessment_domains(assessment_domains)
    except (TypeError, ValueError):
        return False
    if not set(requirements).issubset(applicable):
        return False
    normalized = normalize_coverage(coverage, applicable)
    return all(
        normalized[domain.value] == CoverageState.COMPLETE.value
        for domain in requirements
    )


def assessment_assurance_summary(
    coverage: Mapping | None,
    assessment_domains: object | None = None,
) -> dict[str, object]:
    """Derive assurance separately from the deterministic severity score."""

    applicable = normalize_assessment_domains(assessment_domains)
    normalized = normalize_coverage(coverage, applicable)
    complete_count = sum(
        state == CoverageState.COMPLETE.value for state in normalized.values()
    )
    if complete_count == len(normalized):
        level = AssessmentAssurance.COMPLETE
    elif complete_count == 0:
        level = AssessmentAssurance.INCOMPLETE
    else:
        level = AssessmentAssurance.PARTIAL
    limitations = tuple(
        COVERAGE_LIMITATION_MESSAGES[domain]
        for domain in applicable
        if normalized[domain.value] != CoverageState.COMPLETE.value
    )
    return {"level": level.value, "limitations": limitations}


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
