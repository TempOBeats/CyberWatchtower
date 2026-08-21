"""Read-only grouping projections over authoritative atomic findings."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .models import Finding
from .reachability import ReachabilityAssessment
from .reachability import reachability_from_report


@dataclass(frozen=True, slots=True)
class FindingPresentationGroup:
    group_id: str
    findings: tuple[Finding, ...]


@dataclass(frozen=True, slots=True)
class ReportFindingPresentationGroup:
    """Read-only presentation group retaining every authoritative report item."""

    group_id: str
    findings: tuple[dict, ...]


def listener_group_id(
    service: dict,
    reachability: ReachabilityAssessment,
    recommendation: str,
) -> str:
    subject = (
        service.get("application")
        or service.get("application_name")
        or service.get("process")
        or "unknown"
    )
    return listener_group_id_from_values(
        str(subject),
        str(service.get("protocol", "unknown")),
        str(service.get("port", "unknown")),
        reachability.bind_exposure.value,
        reachability.state.value,
        recommendation,
    )


def listener_group_id_from_values(
    subject: str,
    protocol: str,
    port: str,
    bind_exposure: str,
    reachability_state: str,
    recommendation: str,
) -> str:
    components = (
        "network-listener",
        subject.casefold(),
        protocol.casefold(),
        port,
        bind_exposure,
        reachability_state,
        recommendation,
    )
    return "presentation:" + hashlib.sha256("\0".join(components).encode()).hexdigest()


def group_findings(
    findings: list[Finding],
) -> tuple[FindingPresentationGroup, ...]:
    grouped: dict[str, list[Finding]] = {}
    order = []
    for index, finding in enumerate(findings):
        key = finding.presentation_group_id or f"atomic:{index}"
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        grouped[key].append(finding)
    return tuple(
        FindingPresentationGroup(key, tuple(grouped[key])) for key in order
    )


def report_listener_group_id(finding: dict) -> str | None:
    """Derive a transient group from structured fields, never from a title."""

    try:
        reachability = reachability_from_report(finding.get("network_context"))
    except ValueError:
        return None
    if reachability is None:
        return None
    values = {}
    for item in finding.get("evidence", ()):
        if not isinstance(item, str) or ":" not in item:
            continue
        label, value = item.split(":", 1)
        key = label.strip().casefold()
        if key in {
            "application", "service/application", "process", "protocol", "port"
        }:
            values[key] = value.strip()
    subject = (
        values.get("application")
        or values.get("service/application")
        or values.get("process")
        or "unknown"
    )
    return listener_group_id_from_values(
        subject,
        values.get("protocol", "unknown"),
        values.get("port", "unknown"),
        reachability.bind_exposure.value,
        reachability.state.value,
        str(finding.get("recommendation", "")),
    )


def group_report_findings(
    findings: list[dict],
) -> tuple[ReportFindingPresentationGroup, ...]:
    """Group report findings for display without changing their stored records."""

    grouped: dict[str, list[dict]] = {}
    order: list[str] = []
    for index, finding in enumerate(findings):
        key = (
            finding.get("presentation_group_id")
            or report_listener_group_id(finding)
            or f"atomic:{finding.get('finding_id', index)}"
        )
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        grouped[key].append(finding)
    return tuple(
        ReportFindingPresentationGroup(
            key,
            tuple(sorted(
                grouped[key],
                key=lambda item: str(item.get("finding_id", "")),
            )),
        )
        for key in order
    )
