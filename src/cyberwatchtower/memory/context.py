"""Conservative, validated presentation context derived from memory records."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from cyberwatchtower.core.evidence import (
    EpistemicRole, EvidenceRef, EvidenceSource, make_evidence_ref,
)
from cyberwatchtower.advisor.models import AdvisoryFinding

from .decision_models import (
    ApplicationScope, BaselineType, FindingScope, ListenerScope, ServiceScope,
)
from .history_models import FindingHistoryQuery
from .investigation_models import ReferenceType
from .service import SecurityMemory


@dataclass(frozen=True)
class FindingMemoryContext:
    finding_id: str
    occurrence_count: int
    first_seen_at: str
    last_seen_at: str
    lifecycle_state: str
    reopened_count: int
    exception_id: str | None = None
    exception_expires_at: str | None = None
    approved_baseline_id: str | None = None
    previous_investigation_id: str | None = None


@dataclass(frozen=True)
class ActionMemoryContext:
    action_id: str
    response_id: str
    response_type: str
    recorded_at: str


@dataclass(frozen=True)
class MemoryContext:
    system_id: str
    findings: tuple[FindingMemoryContext, ...]
    evidence: tuple[EvidenceRef, ...]
    actions: tuple[ActionMemoryContext, ...] = ()
    limitation: str | None = None


def _memory_evidence(evidence_id, source, source_id, role, label):
    return make_evidence_ref(evidence_id, source, source_id, role, label)


def build_memory_context(
    memory: SecurityMemory,
    *,
    system_id: str,
    finding_ids: tuple[str, ...],
    findings: tuple[AdvisoryFinding, ...] = (),
    action_ids: tuple[str, ...] = (),
    at: datetime | None = None,
) -> MemoryContext:
    """Read only exact current-finding context; malformed results fail closed."""

    now = at or datetime.now(timezone.utc)
    try:
        exceptions = memory.active_exceptions(system_id=system_id, at=now)
        if any(item.system_id != system_id for item in exceptions):
            raise ValueError("cross-system exception result")
        details = {item.finding_id: item for item in findings}

        def matches_scope(scope, finding_id):
            finding = details.get(finding_id)
            if isinstance(scope, FindingScope):
                return scope.finding_id == finding_id
            if finding is None:
                return False
            try:
                port = int(finding.port) if finding.port else None
            except ValueError:
                return False
            if isinstance(scope, ListenerScope):
                application = finding.application or finding.process or "unknown"
                return all((
                    finding.protocol == scope.protocol, finding.address == scope.address,
                    (finding.exposure or "").casefold() == scope.exposure,
                    port == scope.port, application == scope.application,
                ))
            if isinstance(scope, ServiceScope):
                return all((finding.application_name == scope.service,
                            finding.protocol == scope.protocol, port == scope.port))
            if isinstance(scope, ApplicationScope):
                return (finding.application or finding.process) == scope.application
            return False

        exception_by_finding = {
            finding_id: next((item for item in exceptions
                              if matches_scope(item.scope, finding_id)), None)
            for finding_id in finding_ids
        }
        baselines = tuple(
            item for item in (
                memory.current_baseline(system_id=system_id, baseline_type=kind)
                for kind in BaselineType
            ) if item is not None
        )
        if any(item.system_id != system_id for item in baselines):
            raise ValueError("cross-system baseline result")
        baseline_by_finding = {}
        for baseline in baselines:
            for entry in baseline.entries:
                if entry.key == "finding_id" and entry.value in finding_ids:
                    baseline_by_finding[entry.value] = baseline
                for finding_id, finding in details.items():
                    endpoint = (
                        f"{finding.protocol}/{finding.port}"
                        if finding.protocol and finding.port else None
                    )
                    if baseline.baseline_type == BaselineType.APPROVED_LISTENERS:
                        try:
                            listener_scope = ListenerScope(
                                finding.protocol,
                                finding.address,
                                (finding.exposure or "").casefold(),
                                int(finding.port),
                                finding.application or finding.process or "unknown",
                            )
                        except (TypeError, ValueError):
                            listener_scope = None
                        if listener_scope is not None and (
                            entry.key == (
                                f"scope:{listener_scope.scope_type.value}:"
                                f"{listener_scope.digest()}"
                            )
                            and entry.value == listener_scope.canonical_json()
                        ):
                            baseline_by_finding[finding_id] = baseline
                    if (baseline.baseline_type == BaselineType.EXPECTED_SERVICES
                            and entry.key == f"service:{finding.application_name}"
                            and entry.value == endpoint):
                        baseline_by_finding[finding_id] = baseline
                    application = finding.application or finding.process
                    if (baseline.baseline_type == BaselineType.EXPECTED_APPLICATIONS
                            and entry.key == "application" and entry.value == application):
                        baseline_by_finding[finding_id] = baseline

        contexts, evidence = [], []
        for finding_id in finding_ids:
            timeline = memory.finding_timeline(FindingHistoryQuery(system_id, finding_id))
            if timeline is None:
                continue
            if timeline.summary.finding_id != finding_id:
                raise ValueError("memory finding identity mismatch")
            summary = timeline.summary
            if summary.occurrence_count < 1:
                raise ValueError("invalid occurrence count")
            exception = exception_by_finding.get(finding_id)
            baseline = baseline_by_finding.get(finding_id)
            investigation = memory.previous_investigation_for_finding(
                system_id=system_id, finding_id=finding_id
            )
            if investigation is not None and investigation.system_id != system_id:
                raise ValueError("cross-system investigation result")
            contexts.append(FindingMemoryContext(
                finding_id, summary.occurrence_count, summary.first_seen_at,
                summary.last_seen_at, summary.lifecycle_state, summary.reopened_count,
                exception.exception_id if exception else None,
                exception.expires_at if exception else None,
                baseline.baseline_id if baseline else None,
                investigation.investigation_id if investigation else None,
            ))
            evidence.append(_memory_evidence(
                f"memory:lifecycle:{finding_id}", EvidenceSource.MEMORY_HISTORY,
                finding_id, EpistemicRole.DETERMINISTIC_DERIVATION,
                "Persistent deterministic finding lifecycle",
            ))
            if exception:
                evidence.append(_memory_evidence(
                    f"memory:exception:{exception.exception_id}", EvidenceSource.MEMORY_DECISION,
                    exception.exception_id, EpistemicRole.USER_DECISION,
                    "Active presentation exception",
                ))
            if baseline:
                evidence.append(_memory_evidence(
                    f"memory:baseline:{baseline.baseline_id}", EvidenceSource.MEMORY_DECISION,
                    baseline.baseline_id, EpistemicRole.USER_DECISION,
                    "Approved baseline context",
                ))
            if investigation:
                evidence.append(_memory_evidence(
                    f"memory:investigation:{investigation.investigation_id}",
                    EvidenceSource.MEMORY_AUDIT, investigation.investigation_id,
                    EpistemicRole.USER_DECISION, "Previous completed investigation",
                ))
        actions = []
        for action_id in action_ids:
            history = memory.action_history(system_id=system_id, action_id=action_id)
            if not history:
                continue
            latest = history[-1]
            if latest.system_id != system_id or latest.action_id != action_id:
                raise ValueError("memory action identity mismatch")
            actions.append(ActionMemoryContext(
                action_id, latest.response_id, latest.response_type.value,
                latest.recorded_at,
            ))
            evidence.append(_memory_evidence(
                f"memory:action-response:{latest.response_id}",
                EvidenceSource.MEMORY_DECISION, latest.response_id,
                EpistemicRole.USER_DECISION, "Previous user action response",
            ))
        return MemoryContext(system_id, tuple(contexts), tuple(evidence), tuple(actions))
    except Exception:
        return MemoryContext(
            system_id, (), (), (),
            "Persistent memory context is unavailable; using saved JSON history.",
        )


def persisted_finding_candidates(
    memory: SecurityMemory,
    *,
    system_id: str,
    session_id: str,
    known_finding_ids: set[str],
    at: datetime | None = None,
) -> tuple[str, ...]:
    """Return unique, unexpired, same-system finding candidates only."""

    try:
        references = memory.active_references(
            system_id=system_id, session_id=session_id,
            at=at or datetime.now(timezone.utc),
        )
        return tuple(sorted({
            item.target_id for item in references
            if item.reference_type == ReferenceType.FINDING
            and item.system_id == system_id
            and item.target_id in known_finding_ids
        }))
    except Exception:
        return ()
