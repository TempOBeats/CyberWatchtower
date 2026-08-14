"""Transactional storage APIs for presentation-only security decisions."""

from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timezone

from .database import MemoryDatabase
from .decision_models import (
    ActionResponseRecord, ActionResponseType, BaselineEntry, BaselineRecord,
    BaselineState, BaselineType, DecisionRecord, DecisionStatus, DecisionType,
    ExceptionRecord, ExceptionStatus, RecommendationShownRecord, Scope,
    safe_text, scope_from_storage, utc_text, MAX_ACTOR_LENGTH, MAX_IDENTIFIER_LENGTH,
    MAX_RATIONALE_LENGTH, TypedScope, MAX_FINDING_ID_LENGTH,
)
from .errors import MemoryCorrupt, MemoryDecisionError, MemoryLocked


def _id(prefix: str) -> str:
    return f"{prefix}:{uuid.uuid4().hex}"


def _system_id(value: str) -> str:
    return safe_text(value, "system_id", MAX_IDENTIFIER_LENGTH)


def _identifier(value: str, name: str) -> str:
    return safe_text(value, name, MAX_IDENTIFIER_LENGTH)


def _scope(value) -> TypedScope:
    if not isinstance(value, TypedScope):
        raise MemoryDecisionError("scope must be a supported typed scope.")
    return value


def _enum(enum_type, value, name: str):
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise MemoryDecisionError(f"{name} is not recognized.") from exc


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _translate(exc: sqlite3.Error, operation: str):
    if "locked" in str(exc).casefold():
        return MemoryLocked("Persistent Security Memory is locked.")
    if isinstance(exc, sqlite3.IntegrityError):
        return MemoryDecisionError(f"{operation} violates a memory decision invariant.")
    return MemoryCorrupt(f"{operation} failed because memory storage is invalid.")


def _transaction(database: MemoryDatabase, operation, label: str):
    try:
        database.connection.execute("BEGIN IMMEDIATE")
        result = operation(database.connection)
        database.connection.commit()
        return result
    except sqlite3.Error as exc:
        database.connection.rollback()
        raise _translate(exc, label) from exc
    except Exception:
        database.connection.rollback()
        raise


def _decision(row) -> DecisionRecord:
    return DecisionRecord(
        row["decision_id"], row["system_id"], DecisionType(row["decision_type"]),
        scope_from_storage(row["scope_type"], row["scope_json"]), row["actor"],
        row["rationale"], row["effective_at"], row["expires_at"],
        DecisionStatus(row["status"]), row["supersedes_id"],
    )


def create_decision(database: MemoryDatabase, *, system_id: str,
                    decision_type: DecisionType, scope: Scope, actor: str,
                    effective_at: datetime, rationale: str | None = None,
                    expires_at: datetime | None = None,
                    supersedes_id: str | None = None) -> DecisionRecord:
    system_id = _system_id(system_id)
    decision_type, scope = _enum(DecisionType, decision_type, "decision_type"), _scope(scope)
    actor = safe_text(actor, "actor", MAX_ACTOR_LENGTH)
    rationale = safe_text(rationale, "rationale", MAX_RATIONALE_LENGTH, optional=True)
    effective = utc_text(effective_at, "effective_at")
    expiry = utc_text(expires_at, "expires_at") if expires_at else None
    if expiry is not None and expiry <= effective:
        raise MemoryDecisionError("expires_at must follow effective_at.")
    if supersedes_id is not None:
        supersedes_id = _identifier(supersedes_id, "supersedes_id")
    decision_id = _id("decision")

    def write(connection):
        if supersedes_id:
            prior = connection.execute(
                "SELECT status FROM user_decisions WHERE system_id=? AND decision_id=?",
                (system_id, supersedes_id),
            ).fetchone()
            if prior is None or prior["status"] != DecisionStatus.ACTIVE.value:
                raise MemoryDecisionError("Only an active same-system decision may be superseded.")
            connection.execute(
                "UPDATE user_decisions SET status='SUPERSEDED' WHERE system_id=? AND decision_id=?",
                (system_id, supersedes_id),
            )
        created = _now().isoformat()
        connection.execute(
            """INSERT INTO user_decisions
               (decision_id, system_id, decision_type, scope_type, scope_json, scope_digest,
                actor, rationale, effective_at, expires_at, status, supersedes_id,
                presentation_only, provenance, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, 1, 'USER_DECISION', ?)""",
            (decision_id, system_id, decision_type.value, scope.scope_type.value,
             scope.canonical_json(), scope.digest(), actor, rationale, effective, expiry,
             supersedes_id, created),
        )
        return _decision(connection.execute(
            "SELECT * FROM user_decisions WHERE decision_id=?", (decision_id,)).fetchone())
    return _transaction(database, write, "Decision creation")


def supersede_decision(database: MemoryDatabase, *, system_id: str,
                       decision_id: str, decision_type: DecisionType, scope: Scope,
                       actor: str, effective_at: datetime,
                       rationale: str | None = None,
                       expires_at: datetime | None = None) -> DecisionRecord:
    return create_decision(
        database, system_id=system_id, decision_type=decision_type, scope=scope,
        actor=actor, effective_at=effective_at, rationale=rationale,
        expires_at=expires_at, supersedes_id=decision_id,
    )


def revoke_decision(database: MemoryDatabase, *, system_id: str, decision_id: str) -> DecisionRecord:
    system_id, decision_id = _system_id(system_id), _identifier(decision_id, "decision_id")
    def write(connection):
        changed = connection.execute(
            "UPDATE user_decisions SET status='REVOKED' WHERE system_id=? AND decision_id=? AND status='ACTIVE'",
            (system_id, decision_id),
        ).rowcount
        if changed != 1:
            raise MemoryDecisionError("Only an active same-system decision may be revoked.")
        return _decision(connection.execute(
            "SELECT * FROM user_decisions WHERE decision_id=?", (decision_id,)).fetchone())
    return _transaction(database, write, "Decision revocation")


def decisions_for_scope(database: MemoryDatabase, *, system_id: str, scope: Scope):
    system_id, scope = _system_id(system_id), _scope(scope)
    try:
        rows = database.connection.execute(
            """SELECT * FROM user_decisions WHERE system_id=? AND scope_digest=?
               ORDER BY effective_at, decision_id""", (system_id, scope.digest())).fetchall()
        return tuple(_decision(row) for row in rows)
    except sqlite3.Error as exc:
        raise _translate(exc, "Decision query") from exc


def _exception(row, at: datetime | None = None) -> ExceptionRecord:
    status = ExceptionStatus(row["status"])
    if at is not None and status == ExceptionStatus.ACTIVE:
        current = utc_text(at, "at")
        if current < row["starts_at"] or current >= row["expires_at"]:
            status = ExceptionStatus.EXPIRED
    return ExceptionRecord(
        row["exception_id"], row["system_id"],
        scope_from_storage(row["scope_type"], row["scope_json"]), row["approver"],
        row["rationale"], row["starts_at"], row["expires_at"], status,
        row["supersedes_id"],
    )


def create_exception(database: MemoryDatabase, *, system_id: str, scope: Scope,
                     approver: str, starts_at: datetime, expires_at: datetime,
                     rationale: str | None = None,
                     supersedes_id: str | None = None) -> ExceptionRecord:
    system_id = _system_id(system_id)
    scope = _scope(scope)
    approver = safe_text(approver, "approver", MAX_ACTOR_LENGTH)
    rationale = safe_text(rationale, "rationale", MAX_RATIONALE_LENGTH, optional=True)
    starts, expires = utc_text(starts_at, "starts_at"), utc_text(expires_at, "expires_at")
    if expires <= starts:
        raise MemoryDecisionError("expires_at must follow starts_at.")
    if supersedes_id:
        supersedes_id = _identifier(supersedes_id, "supersedes_id")
    exception_id = _id("exception")
    def write(connection):
        if supersedes_id:
            changed = connection.execute(
                "UPDATE exceptions SET status='SUPERSEDED' WHERE system_id=? AND exception_id=? AND status='ACTIVE'",
                (system_id, supersedes_id),
            ).rowcount
            if changed != 1:
                raise MemoryDecisionError("Only an active same-system exception may be superseded.")
        connection.execute(
            """INSERT INTO exceptions
               (exception_id, system_id, scope_type, scope_json, scope_digest, approver,
                rationale, starts_at, expires_at, status, supersedes_id,
                presentation_only, provenance, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, 1, 'USER_DECISION', ?)""",
            (exception_id, system_id, scope.scope_type.value, scope.canonical_json(),
             scope.digest(), approver, rationale, starts, expires, supersedes_id,
             _now().isoformat()),
        )
        return _exception(connection.execute(
            "SELECT * FROM exceptions WHERE exception_id=?", (exception_id,)).fetchone())
    return _transaction(database, write, "Exception creation")


def revoke_exception(database: MemoryDatabase, *, system_id: str, exception_id: str) -> ExceptionRecord:
    system_id, exception_id = _system_id(system_id), _identifier(exception_id, "exception_id")
    def write(connection):
        changed = connection.execute(
            "UPDATE exceptions SET status='REVOKED' WHERE system_id=? AND exception_id=? AND status='ACTIVE'",
            (system_id, exception_id),
        ).rowcount
        if changed != 1:
            raise MemoryDecisionError("Only an active same-system exception may be revoked.")
        return _exception(connection.execute(
            "SELECT * FROM exceptions WHERE exception_id=?", (exception_id,)).fetchone())
    return _transaction(database, write, "Exception revocation")


def supersede_exception(database: MemoryDatabase, *, system_id: str,
                        exception_id: str, scope: Scope, approver: str,
                        starts_at: datetime, expires_at: datetime,
                        rationale: str | None = None) -> ExceptionRecord:
    return create_exception(
        database, system_id=system_id, scope=scope, approver=approver,
        starts_at=starts_at, expires_at=expires_at, rationale=rationale,
        supersedes_id=exception_id,
    )


def active_exceptions(database: MemoryDatabase, *, system_id: str, at: datetime):
    system_id, current = _system_id(system_id), utc_text(at, "at")
    try:
        rows = database.connection.execute(
            """SELECT * FROM exceptions WHERE system_id=? AND status='ACTIVE'
               AND starts_at<=? AND expires_at>? ORDER BY starts_at, exception_id""",
            (system_id, current, current),
        ).fetchall()
        return tuple(_exception(row, at) for row in rows)
    except sqlite3.Error as exc:
        raise _translate(exc, "Exception query") from exc


def exceptions_for_scope(database: MemoryDatabase, *, system_id: str,
                         scope: Scope, at: datetime | None = None):
    system_id, scope = _system_id(system_id), _scope(scope)
    try:
        rows = database.connection.execute(
            """SELECT * FROM exceptions WHERE system_id=? AND scope_digest=?
               ORDER BY starts_at, created_at, exception_id""", (system_id, scope.digest())).fetchall()
        return tuple(_exception(row, at) for row in rows)
    except sqlite3.Error as exc:
        raise _translate(exc, "Exception query") from exc


def _baseline(connection, row) -> BaselineRecord:
    entries = connection.execute(
        """SELECT entry_key, entry_value FROM baseline_entries WHERE system_id=?
           AND baseline_id=? ORDER BY ordinal, entry_key""",
        (row["system_id"], row["baseline_id"]),
    ).fetchall()
    return BaselineRecord(
        row["baseline_id"], row["system_id"], BaselineType(row["baseline_type"]),
        row["version"], BaselineState(row["state"]),
        tuple(BaselineEntry(item["entry_key"], item["entry_value"]) for item in entries),
        row["approver"], row["approved_at"], row["rationale"],
        row["previous_baseline_id"],
    )


def create_draft_baseline(database: MemoryDatabase, *, system_id: str,
                          baseline_type: BaselineType,
                          entries: tuple[BaselineEntry, ...],
                          rationale: str | None = None,
                          previous_baseline_id: str | None = None) -> BaselineRecord:
    system_id = _system_id(system_id)
    baseline_type = _enum(BaselineType, baseline_type, "baseline_type")
    if not isinstance(entries, tuple) or not entries or not all(isinstance(x, BaselineEntry) for x in entries):
        raise MemoryDecisionError("entries must be a non-empty tuple of BaselineEntry values.")
    if len({entry.key for entry in entries}) != len(entries):
        raise MemoryDecisionError("baseline entry keys must be unique.")
    rationale = safe_text(rationale, "rationale", MAX_RATIONALE_LENGTH, optional=True)
    if previous_baseline_id:
        previous_baseline_id = _identifier(previous_baseline_id, "previous_baseline_id")
    baseline_id = _id("baseline")
    def write(connection):
        latest = connection.execute(
            "SELECT MAX(version) FROM baselines WHERE system_id=? AND baseline_type=?",
            (system_id, baseline_type.value),
        ).fetchone()[0]
        version = int(latest or 0) + 1
        if previous_baseline_id:
            previous = connection.execute(
                """SELECT state, baseline_type FROM baselines
                   WHERE system_id=? AND baseline_id=?""",
                (system_id, previous_baseline_id),
            ).fetchone()
            if previous is None or previous["state"] != "APPROVED" or previous["baseline_type"] != baseline_type.value:
                raise MemoryDecisionError("Previous baseline must be approved, same-system, and same-type.")
        connection.execute(
            """INSERT INTO baselines
               (baseline_id, system_id, baseline_type, version, state, approver,
                approved_at, rationale, previous_baseline_id, provenance, created_at)
               VALUES (?, ?, ?, ?, 'DRAFT', NULL, NULL, ?, ?, 'USER_DECISION', ?)""",
            (baseline_id, system_id, baseline_type.value, version, rationale,
             previous_baseline_id, _now().isoformat()),
        )
        for ordinal, entry in enumerate(entries):
            connection.execute(
                """INSERT INTO baseline_entries
                   (baseline_id, system_id, entry_key, entry_value, ordinal, provenance)
                   VALUES (?, ?, ?, ?, ?, 'USER_DECISION')""",
                (baseline_id, system_id, entry.key, entry.value, ordinal),
            )
        row = connection.execute("SELECT * FROM baselines WHERE baseline_id=?", (baseline_id,)).fetchone()
        return _baseline(connection, row)
    return _transaction(database, write, "Baseline draft creation")


def create_next_baseline_version(database: MemoryDatabase, *, system_id: str,
                                 baseline_type: BaselineType,
                                 entries: tuple[BaselineEntry, ...],
                                 rationale: str | None = None) -> BaselineRecord:
    current = current_approved_baseline(database, system_id=system_id, baseline_type=baseline_type)
    if current is None:
        raise MemoryDecisionError("A current approved baseline is required.")
    return create_draft_baseline(
        database, system_id=system_id, baseline_type=baseline_type, entries=entries,
        rationale=rationale, previous_baseline_id=current.baseline_id,
    )


def approve_baseline(database: MemoryDatabase, *, system_id: str, baseline_id: str,
                     approver: str, approved_at: datetime) -> BaselineRecord:
    system_id, baseline_id = _system_id(system_id), _identifier(baseline_id, "baseline_id")
    approver, approved = safe_text(approver, "approver", MAX_ACTOR_LENGTH), utc_text(approved_at, "approved_at")
    def write(connection):
        row = connection.execute(
            "SELECT * FROM baselines WHERE system_id=? AND baseline_id=?",
            (system_id, baseline_id),
        ).fetchone()
        if row is None or row["state"] != "DRAFT":
            raise MemoryDecisionError("Only a same-system draft baseline may be approved.")
        connection.execute(
            """UPDATE baselines SET state='SUPERSEDED'
               WHERE system_id=? AND baseline_type=? AND state='APPROVED'""",
            (system_id, row["baseline_type"]),
        )
        connection.execute(
            """UPDATE baselines SET state='APPROVED', approver=?, approved_at=?
               WHERE system_id=? AND baseline_id=?""",
            (approver, approved, system_id, baseline_id),
        )
        return _baseline(connection, connection.execute(
            "SELECT * FROM baselines WHERE baseline_id=?", (baseline_id,)).fetchone())
    return _transaction(database, write, "Baseline approval")


def current_approved_baseline(database: MemoryDatabase, *, system_id: str,
                              baseline_type: BaselineType):
    system_id = _system_id(system_id)
    baseline_type = _enum(BaselineType, baseline_type, "baseline_type")
    try:
        row = database.connection.execute(
            """SELECT * FROM baselines WHERE system_id=? AND baseline_type=?
               AND state='APPROVED' ORDER BY version DESC, baseline_id DESC LIMIT 1""",
            (system_id, baseline_type.value),
        ).fetchone()
        return _baseline(database.connection, row) if row else None
    except sqlite3.Error as exc:
        raise _translate(exc, "Baseline query") from exc


def baseline_history(database: MemoryDatabase, *, system_id: str,
                     baseline_type: BaselineType):
    system_id = _system_id(system_id)
    baseline_type = _enum(BaselineType, baseline_type, "baseline_type")
    try:
        rows = database.connection.execute(
            """SELECT * FROM baselines WHERE system_id=? AND baseline_type=?
               ORDER BY version, baseline_id""", (system_id, baseline_type.value)).fetchall()
        return tuple(_baseline(database.connection, row) for row in rows)
    except sqlite3.Error as exc:
        raise _translate(exc, "Baseline query") from exc


def record_recommendation_shown(database: MemoryDatabase, *, system_id: str,
                                action_id: str, trusted_text_hash: str,
                                shown_at: datetime,
                                finding_id: str | None = None) -> RecommendationShownRecord:
    system_id, action_id = _system_id(system_id), _identifier(action_id, "action_id")
    if finding_id is not None:
        finding_id = safe_text(finding_id, "finding_id", MAX_FINDING_ID_LENGTH)
    if not isinstance(trusted_text_hash, str) or len(trusted_text_hash) != 64:
        raise MemoryDecisionError("trusted_text_hash must be a SHA-256 hex digest.")
    try:
        int(trusted_text_hash, 16)
    except ValueError as exc:
        raise MemoryDecisionError("trusted_text_hash must be a SHA-256 hex digest.") from exc
    shown = utc_text(shown_at, "shown_at")
    event_id = _id("recommendation")
    def write(connection):
        connection.execute(
            """INSERT INTO recommendations_shown
               VALUES (?, ?, ?, ?, ?, ?, 'DERIVED_HISTORY')""",
            (event_id, system_id, finding_id, action_id, trusted_text_hash.lower(), shown),
        )
        return RecommendationShownRecord(event_id, system_id, finding_id, action_id,
                                         trusted_text_hash.lower(), shown)
    return _transaction(database, write, "Recommendation recording")


def record_action_response(database: MemoryDatabase, *, system_id: str,
                           recommendation_event_id: str, action_id: str,
                           response_type: ActionResponseType, actor: str,
                           recorded_at: datetime, rationale: str | None = None,
                           defer_until: datetime | None = None) -> ActionResponseRecord:
    system_id = _system_id(system_id)
    recommendation_event_id = _identifier(recommendation_event_id, "recommendation_event_id")
    action_id = _identifier(action_id, "action_id")
    response_type = _enum(ActionResponseType, response_type, "response_type")
    actor = safe_text(actor, "actor", MAX_ACTOR_LENGTH)
    rationale = safe_text(rationale, "rationale", MAX_RATIONALE_LENGTH, optional=True)
    recorded = utc_text(recorded_at, "recorded_at")
    deferred = utc_text(defer_until, "defer_until") if defer_until else None
    if response_type == ActionResponseType.DEFERRED and deferred is None:
        raise MemoryDecisionError("DEFERRED requires defer_until.")
    if deferred is not None and deferred <= recorded:
        raise MemoryDecisionError("defer_until must follow recorded_at.")
    if response_type != ActionResponseType.DEFERRED and deferred is not None:
        raise MemoryDecisionError("defer_until is only valid for DEFERRED.")
    response_id = _id("response")
    def write(connection):
        recommendation = connection.execute(
            """SELECT action_id FROM recommendations_shown
               WHERE system_id=? AND recommendation_event_id=?""",
            (system_id, recommendation_event_id),
        ).fetchone()
        if recommendation is None or recommendation["action_id"] != action_id:
            raise MemoryDecisionError("Action response must reference the same-system deterministic action.")
        connection.execute(
            """INSERT INTO action_responses VALUES
               (?, ?, ?, ?, ?, ?, ?, ?, ?, 'USER_DECISION')""",
            (response_id, system_id, recommendation_event_id, action_id,
             response_type.value, actor, rationale, recorded, deferred),
        )
        return ActionResponseRecord(response_id, system_id, recommendation_event_id,
                                    action_id, response_type, actor, rationale, recorded, deferred)
    return _transaction(database, write, "Action response recording")


def action_response_history(database: MemoryDatabase, *, system_id: str, action_id: str):
    system_id, action_id = _system_id(system_id), _identifier(action_id, "action_id")
    try:
        rows = database.connection.execute(
            """SELECT * FROM action_responses WHERE system_id=? AND action_id=?
               ORDER BY recorded_at, response_id""", (system_id, action_id)).fetchall()
        return tuple(ActionResponseRecord(
            row["response_id"], row["system_id"], row["recommendation_event_id"],
            row["action_id"], ActionResponseType(row["response_type"]), row["actor"],
            row["rationale"], row["recorded_at"], row["defer_until"],
        ) for row in rows)
    except sqlite3.Error as exc:
        raise _translate(exc, "Action response query") from exc
