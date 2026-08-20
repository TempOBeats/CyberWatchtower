"""Deterministic projection from canonical findings into Scoring v2 inputs."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from .models import Finding
from .platform.models import BindExposure
from .reachability import RemoteReachabilityState
from .reporting import finding_to_dict
from .scoring_contracts import (
    NetworkScoringIdentity,
    ScoringCategory,
    ScoringFinding,
)


_FIREWALL_SOURCES = frozenset({
    "firewall",
    "firewall_inbound_policy",
    "firewall_technology",
})
_NETWORK_IDENTITY_KEYS = frozenset({
    "protocol",
    "port",
    "bind_exposure",
    "reachability_state",
    "application_identity",
    "process_basename",
})


def canonical_finding_id(finding: Finding) -> str:
    """Use the report identity boundary without mutating the finding."""

    return str(finding_to_dict(finding)["finding_id"])


def network_scoring_identity(value: Mapping[str, object]) -> NetworkScoringIdentity:
    """Validate the closed, transient listener projection from the interpreter."""

    if not isinstance(value, Mapping) or set(value) != _NETWORK_IDENTITY_KEYS:
        raise ValueError("Network scoring identity has an invalid structure.")
    application = value["application_identity"]
    process = value["process_basename"]
    if application is not None and not isinstance(application, str):
        raise TypeError("application_identity must be text or None.")
    if process is not None and not isinstance(process, str):
        raise TypeError("process_basename must be text or None.")
    return NetworkScoringIdentity(
        protocol=value["protocol"],
        port=value["port"],
        bind_exposure=BindExposure(value["bind_exposure"]),
        reachability_state=RemoteReachabilityState(value["reachability_state"]),
        application_identity=application,
        process_basename=process,
    )


def project_scoring_findings(
    findings: Iterable[Finding],
    network_identities: Mapping[str, NetworkScoringIdentity],
) -> tuple[ScoringFinding, ...]:
    """Create immutable scoring snapshots from authoritative structured fields."""

    snapshots = []
    seen_ids = set()
    for finding in findings:
        if not isinstance(finding, Finding):
            raise TypeError("Scoring projection accepts only Finding values.")
        finding_id = canonical_finding_id(finding)
        if finding_id in seen_ids:
            raise ValueError("Canonical findings contain a duplicate finding ID.")
        seen_ids.add(finding_id)
        network_identity = network_identities.get(finding_id)
        if finding.source == "network" and network_identity is not None:
            category = ScoringCategory.NETWORK_EXPOSURE
        elif finding.source in _FIREWALL_SOURCES:
            category = ScoringCategory.FIREWALL_POSTURE
        else:
            category = ScoringCategory.OTHER_DETERMINISTIC_RISK
        snapshots.append(ScoringFinding(
            finding_id=finding_id,
            severity=finding.severity,
            kind=finding.kind,
            assessment_state=finding.assessment_state,
            source=finding.source,
            category=category,
            network_identity=network_identity,
        ))
    if not set(network_identities).issubset(seen_ids):
        raise ValueError("Network scoring identity references an absent finding.")
    return tuple(sorted(snapshots, key=lambda item: item.finding_id))
