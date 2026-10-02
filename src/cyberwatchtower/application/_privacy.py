"""Shared structural privacy policy for application evidence projection."""

from __future__ import annotations

from collections.abc import Iterable

from cyberwatchtower.memory.sanitization import (
    contains_sensitive_marker,
    sanitize_evidence,
)

from .contracts import (
    ApplicationEvidence,
    ApplicationEvidenceCategory,
    EvidenceProjectionState,
)


_EVIDENCE_CATEGORIES = {
    "address": ApplicationEvidenceCategory.ADDRESS,
    "exposure": ApplicationEvidenceCategory.EXPOSURE,
    "forward policy": ApplicationEvidenceCategory.FORWARD_POLICY,
    "firewall enabled": ApplicationEvidenceCategory.FIREWALL_ENABLED,
    "default inbound action": ApplicationEvidenceCategory.DEFAULT_INBOUND_ACTION,
    "block all inbound": ApplicationEvidenceCategory.BLOCK_ALL_INBOUND,
    "input policy": ApplicationEvidenceCategory.INPUT_POLICY,
    "output policy": ApplicationEvidenceCategory.OUTPUT_POLICY,
    "port": ApplicationEvidenceCategory.PORT,
    "process": ApplicationEvidenceCategory.PROCESS,
    "profile": ApplicationEvidenceCategory.PROFILE,
    "protocol": ApplicationEvidenceCategory.PROTOCOL,
    "service": ApplicationEvidenceCategory.SERVICE,
    "service/application": ApplicationEvidenceCategory.SERVICE_APPLICATION,
}
_SOURCE_EVIDENCE = {
    "network": frozenset({
        ApplicationEvidenceCategory.ADDRESS,
        ApplicationEvidenceCategory.EXPOSURE,
        ApplicationEvidenceCategory.PORT,
        ApplicationEvidenceCategory.PROCESS,
        ApplicationEvidenceCategory.PROTOCOL,
        ApplicationEvidenceCategory.SERVICE,
        ApplicationEvidenceCategory.SERVICE_APPLICATION,
    }),
    "firewall": frozenset({
        ApplicationEvidenceCategory.INPUT_POLICY,
        ApplicationEvidenceCategory.FORWARD_POLICY,
        ApplicationEvidenceCategory.OUTPUT_POLICY,
    }),
    "firewall_inbound_policy": frozenset({
        ApplicationEvidenceCategory.PROFILE,
        ApplicationEvidenceCategory.FIREWALL_ENABLED,
        ApplicationEvidenceCategory.DEFAULT_INBOUND_ACTION,
        ApplicationEvidenceCategory.BLOCK_ALL_INBOUND,
    }),
}


def _required_text_is_sensitive(values: Iterable[str | None]) -> bool:
    return any(
        value is not None and contains_sensitive_marker(value)
        for value in values
    )


def _project_evidence(
    source: str,
    evidence: object,
) -> tuple[tuple[ApplicationEvidence, ...], EvidenceProjectionState, int]:
    if not isinstance(evidence, list) or not all(
        isinstance(item, str) for item in evidence
    ):
        raise TypeError("application evidence must use the scanner list shape.")

    safe_items, omitted = sanitize_evidence(list(evidence))
    approved = _SOURCE_EVIDENCE.get(source, frozenset())
    projected = []
    for item in safe_items:
        label, value = item.split(":", 1)
        category = _EVIDENCE_CATEGORIES.get(label.strip().casefold())
        if category is None or category not in approved:
            omitted += 1
            continue
        projected.append(ApplicationEvidence(category, value.strip()))

    state = (
        EvidenceProjectionState.REDACTED
        if omitted
        else EvidenceProjectionState.COMPLETE
    )
    return tuple(projected), state, omitted
