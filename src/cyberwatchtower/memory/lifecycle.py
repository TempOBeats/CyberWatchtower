"""Deterministic, coverage-aware finding lifecycle derivation."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass

from cyberwatchtower.report_contracts import CoverageState, ScanDomain, normalize_coverage

from .database import MemoryDatabase
from .errors import MemoryCorrupt, MemoryLifecycleError, MemoryLocked


SOURCE_COVERAGE_REQUIREMENTS: dict[str, tuple[ScanDomain, ...]] = {
    "network": (ScanDomain.NETWORK_SOCKET_INSPECTION,),
    # Current reports use one source value for both firewall technology and
    # INPUT-policy findings. Requiring both domains is conservative and avoids
    # a prose/title-based classification or a false confirmed resolution.
    "firewall": (
        ScanDomain.FIREWALL_TECHNOLOGY,
        ScanDomain.IPTABLES_INPUT_POLICY,
    ),
}


@dataclass
class _State:
    finding_pk: str
    finding_id: str
    first_seen_at: str
    last_seen_at: str
    occurrence_count: int
    lifecycle_state: str
    reopened_count: int
    last_resolved_at: str | None
    title: str
    severity: str
    kind: str
    assessment_state: str
    source: str
    metadata_inferred: int


def _event_id(system_id: str, report_id: str, finding_id: str, event_type: str) -> str:
    raw = "\0".join((system_id, report_id, finding_id, event_type)).encode()
    return "event:" + hashlib.sha256(raw).hexdigest()


def _coverage_complete(source: str, coverage_json: str) -> bool:
    requirements = SOURCE_COVERAGE_REQUIREMENTS.get(source.casefold())
    if not requirements:
        return False
    try:
        raw = json.loads(coverage_json)
    except (TypeError, json.JSONDecodeError):
        return False
    coverage = normalize_coverage(raw if isinstance(raw, dict) else None)
    return all(coverage[domain.value] == CoverageState.COMPLETE.value for domain in requirements)


def _derive(connection: sqlite3.Connection, system_id: str):
    reports = connection.execute(
        """SELECT report_id, generated_at, coverage_json FROM reports
           WHERE system_id = ? ORDER BY generated_at, report_id""",
        (system_id,),
    ).fetchall()
    states: dict[str, _State] = {}
    events: list[tuple] = []
    for report in reports:
        occurrences = connection.execute(
            """SELECT o.* FROM finding_occurrences o
               WHERE o.system_id = ? AND o.report_id = ?
               ORDER BY o.stable_finding_id, o.occurrence_id""",
            (system_id, report["report_id"]),
        ).fetchall()
        present = {row["stable_finding_id"] for row in occurrences}
        for row in occurrences:
            prior = states.get(row["stable_finding_id"])
            if prior is None:
                state = _State(
                    row["finding_pk"], row["stable_finding_id"], row["observed_at"],
                    row["observed_at"], 1, "ACTIVE", 0, None, row["title"],
                    row["severity"], row["kind"], row["assessment_state"],
                    row["source"], row["metadata_inferred"],
                )
                events.append((state, "FIRST_SEEN", None, None))
                states[state.finding_id] = state
                continue
            event_type = "REOPENED" if prior.lifecycle_state == "RESOLVED" else "SEEN"
            if event_type == "REOPENED":
                prior.reopened_count += 1
            events.append((prior, event_type, None, None))
            for event, old, new in (
                ("SEVERITY_CHANGED", prior.severity, row["severity"]),
                ("ASSESSMENT_STATE_CHANGED", prior.assessment_state, row["assessment_state"]),
                ("KIND_CHANGED", prior.kind, row["kind"]),
            ):
                if old != new:
                    events.append((prior, event, old, new))
            prior.last_seen_at = row["observed_at"]
            prior.occurrence_count += 1
            prior.lifecycle_state = "ACTIVE"
            prior.title = row["title"]
            prior.severity = row["severity"]
            prior.kind = row["kind"]
            prior.assessment_state = row["assessment_state"]
            prior.source = row["source"]
            prior.metadata_inferred = row["metadata_inferred"]
        for finding_id, state in sorted(states.items()):
            if finding_id in present or state.lifecycle_state == "RESOLVED":
                continue
            if _coverage_complete(state.source, report["coverage_json"]):
                previous_state = state.lifecycle_state
                state.lifecycle_state = "RESOLVED"
                state.last_resolved_at = report["generated_at"]
                events.append((state, "RESOLVED", previous_state, "RESOLVED"))
            else:
                state.lifecycle_state = "RESOLUTION_UNCERTAIN"
        for index in range(len(events)):
            item = events[index]
            if len(item) == 4:
                state, event_type, previous, current = item
                if event_type in {"FIRST_SEEN", "SEEN", "REOPENED"} or (
                    event_type.endswith("_CHANGED") and state.finding_id in present
                ):
                    events[index] = (*item, report["report_id"], report["generated_at"])
                elif event_type == "RESOLVED" and len(item) == 4:
                    events[index] = (*item, report["report_id"], report["generated_at"])
    return states, events


def _apply(connection: sqlite3.Connection, system_id: str) -> None:
    states, events = _derive(connection, system_id)
    derived_at = connection.execute(
        "SELECT MAX(ingested_at) FROM reports WHERE system_id = ?", (system_id,)
    ).fetchone()[0]
    if derived_at is None:
        return
    connection.execute("DELETE FROM finding_lifecycle_events WHERE system_id = ?", (system_id,))
    for state in states.values():
        connection.execute(
            """UPDATE findings SET first_seen_at=?, last_seen_at=?, occurrence_count=?,
               active=?, lifecycle_state=?, recurring=?, reopened_count=?, last_resolved_at=?,
               latest_title=?, latest_severity=?, latest_kind=?, latest_assessment_state=?,
               latest_source=?, metadata_inferred=?, provenance='DERIVED_HISTORY', updated_at=?
               WHERE system_id=? AND finding_id=?""",
            (state.first_seen_at, state.last_seen_at, state.occurrence_count,
             int(state.lifecycle_state == "ACTIVE"), state.lifecycle_state,
             int(state.occurrence_count >= 2), state.reopened_count,
             state.last_resolved_at, state.title, state.severity, state.kind,
             state.assessment_state, state.source, state.metadata_inferred, derived_at,
             system_id, state.finding_id),
        )
    for state, event_type, previous, current, report_id, occurred_at in events:
        connection.execute(
            """INSERT INTO finding_lifecycle_events
               (event_id, finding_pk, system_id, report_id, event_type, occurred_at,
                previous_value, current_value, provenance)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'DERIVED_HISTORY')""",
            (_event_id(system_id, report_id, state.finding_id, event_type), state.finding_pk,
             system_id, report_id, event_type, occurred_at, previous, current),
        )


def rebuild_system_lifecycle(database: MemoryDatabase, system_id: str) -> None:
    """Atomically rebuild one system's summaries and events from immutable facts."""
    if not isinstance(system_id, str) or not system_id:
        raise MemoryLifecycleError("A non-empty system_id is required.")
    try:
        database.connection.execute("BEGIN IMMEDIATE")
        _apply(database.connection, system_id)
        database.connection.commit()
    except sqlite3.OperationalError as exc:
        database.connection.rollback()
        if "locked" in str(exc).casefold():
            raise MemoryLocked("Persistent Security Memory is locked.") from exc
        raise MemoryLifecycleError("Lifecycle rebuild failed and was rolled back.") from exc
    except sqlite3.IntegrityError as exc:
        database.connection.rollback()
        raise MemoryLifecycleError("Lifecycle rebuild failed and was rolled back.") from exc
    except sqlite3.DatabaseError as exc:
        database.connection.rollback()
        raise MemoryCorrupt("Lifecycle storage is corrupt.") from exc
    except Exception as exc:
        database.connection.rollback()
        raise MemoryLifecycleError("Lifecycle rebuild failed and was rolled back.") from exc


rebuild_lifecycle_in_transaction = _apply
