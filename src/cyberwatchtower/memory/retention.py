"""Deterministic retention planning and exact-plan transactional execution."""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone

from .database import MemoryDatabase
from .errors import (
    MemoryCorrupt, MemoryLocked, MemoryRetentionApprovalError, MemoryRetentionError,
)
from .retention_models import (
    RetentionAuthorization, RetentionExecution, RetentionItem, RetentionOutcome,
    RetentionPlan, RetentionPolicy, RetentionRecordType, canonical_plan_digest, utc,
)


def _identifier(value, name):
    if not isinstance(value, str) or not value or len(value) > 512 or any(ord(c) < 32 for c in value):
        raise MemoryRetentionError(f"{name} is invalid.")
    return value


def _iso(value):
    return value.astimezone(timezone.utc).isoformat()


def _rows(connection, sql, parameters):
    return connection.execute(sql, parameters).fetchall()


def _item(kind, row, record_id, eligible_at, reason, blocker=None, parent_id=None):
    return RetentionItem(kind, str(row[record_id]), str(row["system_id"]),
                         str(eligible_at), reason, blocker, parent_id)


def plan_retention(database: MemoryDatabase, *, system_id: str,
                   at: datetime, policy: RetentionPolicy | None = None,
                   plan_ttl: timedelta = timedelta(hours=1)) -> RetentionPlan:
    """Create a bounded deterministic plan without mutating the database."""
    system_id = _identifier(system_id, "system_id")
    now, policy = utc(at, "at"), policy or RetentionPolicy()
    if not timedelta(minutes=1) <= plan_ttl <= timedelta(days=1):
        raise MemoryRetentionError("plan_ttl must be between one minute and one day.")
    c = database.connection
    items = []

    def add_simple(kind, table, id_col, time_col, age, extra="1=1"):
        cutoff = _iso(now - age)
        sql = (f"SELECT system_id,{id_col},{time_col} FROM {table} "
               f"WHERE system_id=? AND {time_col}<=? AND {extra} ORDER BY {time_col},{id_col}")
        for row in _rows(c, sql, (system_id, cutoff)):
            items.append(_item(kind, row, id_col, cutoff,
                               f"{time_col} is at or before the policy cutoff"))

    # Query-time expiry is authoritative; stored ACTIVE is still expired here.
    exception_cutoff = _iso(now - policy.expired_exceptions)
    for row in _rows(c, """SELECT system_id,exception_id,expires_at FROM exceptions
        WHERE system_id=? AND expires_at<=? ORDER BY expires_at,exception_id""",
                     (system_id, exception_cutoff)):
        dependent = c.execute(
            "SELECT 1 FROM exceptions WHERE system_id=? AND supersedes_id=? LIMIT 1",
            (system_id, row["exception_id"]),).fetchone()
        items.append(_item(RetentionRecordType.EXPIRED_EXCEPTION, row, "exception_id",
                           exception_cutoff, "expired beyond exception retention",
                           "referenced by a retained exception" if dependent else None))

    add_simple(RetentionRecordType.ACTION_RESPONSE, "action_responses", "response_id",
               "recorded_at", policy.action_responses)
    add_simple(RetentionRecordType.CONVERSATION_REFERENCE, "conversation_references",
               "reference_id", "created_at", policy.conversation_references)

    recommendation_cutoff = _iso(now - policy.recommendation_events)
    for row in _rows(c, """SELECT system_id,recommendation_event_id,shown_at
        FROM recommendations_shown WHERE system_id=? AND shown_at<=?
        ORDER BY shown_at,recommendation_event_id""", (system_id, recommendation_cutoff)):
        dependency = c.execute("""SELECT 1 FROM action_responses WHERE system_id=?
            AND recommendation_event_id=? UNION ALL SELECT 1 FROM investigation_recommendations
            WHERE system_id=? AND recommendation_event_id=? LIMIT 1""",
            (system_id, row["recommendation_event_id"], system_id,
             row["recommendation_event_id"])).fetchone()
        items.append(_item(RetentionRecordType.RECOMMENDATION_EVENT, row,
                           "recommendation_event_id", recommendation_cutoff,
                           "shown beyond recommendation retention",
                           "referenced by retained action or investigation" if dependency else None))

    capability_cutoff = _iso(now - policy.capability_executions)
    for row in _rows(c, """SELECT system_id,execution_id,
        COALESCE(completed_at,requested_at) AS retention_time,investigation_id
        FROM capability_executions WHERE system_id=? AND status!='PROPOSED'
        AND COALESCE(completed_at,requested_at)<=?
        ORDER BY COALESCE(completed_at,requested_at),execution_id""",
                     (system_id, capability_cutoff)):
        evidence = c.execute("""SELECT 1 FROM investigation_evidence WHERE system_id=?
            AND evidence_type='CAPABILITY_RESULT' AND source_record_id=? LIMIT 1""",
            (system_id, row["execution_id"])).fetchone()
        blocker = "required by retained investigation evidence" if evidence or row["investigation_id"] else None
        items.append(_item(RetentionRecordType.CAPABILITY_EXECUTION, row, "execution_id",
                           capability_cutoff, "completed beyond capability audit retention", blocker))
        if blocker is None:
            for event in _rows(c, """SELECT system_id,event_id,occurred_at FROM
                capability_execution_events WHERE system_id=? AND execution_id=?
                ORDER BY occurred_at,event_id""", (system_id, row["execution_id"])):
                items.append(_item(RetentionRecordType.CAPABILITY_EXECUTION_EVENT, event,
                                   "event_id", capability_cutoff,
                                   "child of eligible capability execution"))

    investigation_cutoff = _iso(now - policy.investigations)
    for row in _rows(c, """SELECT system_id,investigation_id,closed_at FROM investigations
        WHERE system_id=? AND status IN ('COMPLETED','CANCELLED') AND closed_at<=?
        ORDER BY closed_at,investigation_id""", (system_id, investigation_cutoff)):
        iid = row["investigation_id"]
        child_specs = (
            (RetentionRecordType.INVESTIGATION_STATUS_EVENT, "investigation_status_events", "event_id", "occurred_at"),
            (RetentionRecordType.INVESTIGATION_FINDING, "investigation_findings", "finding_id", "attached_at"),
            (RetentionRecordType.INVESTIGATION_SCOPE, "investigation_scopes", "scope_digest", "attached_at"),
            (RetentionRecordType.INVESTIGATION_EVIDENCE, "investigation_evidence", "evidence_id", "consulted_at"),
            (RetentionRecordType.INVESTIGATION_QUESTION, "investigation_questions", "question_id", "recorded_at"),
            (RetentionRecordType.INVESTIGATION_RECOMMENDATION, "investigation_recommendations", "recommendation_event_id", "linked_at"),
        )
        for kind, table, id_col, time_col in child_specs:
            extra_column = ",relationship" if kind == RetentionRecordType.INVESTIGATION_FINDING else ""
            for child in _rows(c, f"SELECT system_id,{id_col},{time_col}{extra_column} FROM {table} WHERE system_id=? AND investigation_id=? ORDER BY {time_col},{id_col}", (system_id, iid)):
                stored_child = dict(child)
                if kind == RetentionRecordType.INVESTIGATION_FINDING:
                    stored_child[id_col] = json.dumps(
                        (child[id_col], child["relationship"]), separators=(",", ":")
                    )
                items.append(_item(kind, stored_child, id_col, investigation_cutoff,
                                   "child of eligible investigation", parent_id=iid))
        for capability in _rows(c, """SELECT system_id,execution_id,requested_at
            FROM capability_executions WHERE system_id=? AND investigation_id=?
            ORDER BY requested_at,execution_id""", (system_id, iid)):
            for event in _rows(c, """SELECT system_id,event_id,occurred_at FROM
                capability_execution_events WHERE system_id=? AND execution_id=?
                ORDER BY occurred_at,event_id""", (system_id, capability["execution_id"])):
                items.append(_item(RetentionRecordType.CAPABILITY_EXECUTION_EVENT,
                    event, "event_id", investigation_cutoff,
                    "child of eligible investigation"))
            items.append(_item(RetentionRecordType.CAPABILITY_EXECUTION, capability,
                "execution_id", investigation_cutoff,
                "child of eligible investigation"))
        items.append(_item(RetentionRecordType.INVESTIGATION, row, "investigation_id",
                           investigation_cutoff, "closed beyond investigation retention"))

    # Prefer an unblocked parent-retention selection over a separately blocked age rule.
    deduplicated = {}
    for item in items:
        key = (item.record_type, item.record_id)
        previous = deduplicated.get(key)
        if previous is None or (previous.blocker is not None and item.blocker is None):
            deduplicated[key] = item
    items = sorted(deduplicated.values(), key=lambda item: (item.record_type.value, item.record_id))
    if len(items) > policy.maximum_items:
        items = items[:policy.maximum_items]
    selected_counts = Counter(item.record_type.value for item in items if item.blocker is None)
    digest = canonical_plan_digest(system_id, policy.version, tuple(items))
    generated = _iso(now)
    plan_id = f"retention-plan:{digest[:24]}:{int(now.timestamp())}"
    return RetentionPlan(plan_id, digest, generated, _iso(now + plan_ttl),
                         policy.version, system_id, tuple(items),
                         tuple(sorted(selected_counts.items())))


def authorize_retention_plan(database: MemoryDatabase, *, plan: RetentionPlan,
                             decision_id: str, at: datetime,
                             expires_at: datetime) -> RetentionAuthorization:
    now, expiry = utc(at, "at"), utc(expires_at, "expires_at")
    if expiry <= now or expiry > now + timedelta(days=1):
        raise MemoryRetentionApprovalError("Retention approval expiry is invalid.")
    expected = canonical_plan_digest(plan.system_id, plan.policy_version, plan.items)
    if expected != plan.plan_digest or now.isoformat() >= plan.expires_at:
        raise MemoryRetentionApprovalError("Retention plan is modified or expired.")
    row = database.connection.execute("""SELECT * FROM user_decisions
        WHERE system_id=? AND decision_id=?""", (plan.system_id, decision_id)).fetchone()
    if row is None or row["status"] != "ACTIVE" or row["effective_at"] > now.isoformat() or (
            row["expires_at"] is not None and row["expires_at"] <= now.isoformat()):
        raise MemoryRetentionApprovalError("A valid same-system user decision is required.")
    authorization_id = f"retention-authorization:{uuid.uuid4().hex}"
    try:
        database.connection.execute("BEGIN IMMEDIATE")
        database.connection.execute("""INSERT INTO retention_authorizations
            VALUES (?,?,?,?,?,?,?,?,'USER_DECISION')""", (
            authorization_id, plan.plan_id, plan.plan_digest, plan.system_id,
            decision_id, now.isoformat(), expiry.isoformat(),
            len(plan.selected_items),
        ))
        database.connection.commit()
    except sqlite3.Error as exc:
        database.connection.rollback()
        raise MemoryRetentionApprovalError("Retention authorization could not be recorded.") from exc
    return RetentionAuthorization(authorization_id, plan.plan_id, plan.plan_digest,
                                  plan.system_id, decision_id, now.isoformat(),
                                  expiry.isoformat(), len(plan.selected_items))


_DELETE = {
    RetentionRecordType.EXPIRED_EXCEPTION: ("exceptions", "exception_id"),
    RetentionRecordType.ACTION_RESPONSE: ("action_responses", "response_id"),
    RetentionRecordType.RECOMMENDATION_EVENT: ("recommendations_shown", "recommendation_event_id"),
    RetentionRecordType.CONVERSATION_REFERENCE: ("conversation_references", "reference_id"),
    RetentionRecordType.CAPABILITY_EXECUTION_EVENT: ("capability_execution_events", "event_id"),
    RetentionRecordType.CAPABILITY_EXECUTION: ("capability_executions", "execution_id"),
    RetentionRecordType.INVESTIGATION_STATUS_EVENT: ("investigation_status_events", "event_id"),
    RetentionRecordType.INVESTIGATION_QUESTION: ("investigation_questions", "question_id"),
    RetentionRecordType.INVESTIGATION: ("investigations", "investigation_id"),
}


def _delete_item(connection, item):
    if item.record_type in _DELETE:
        table, column = _DELETE[item.record_type]
        return connection.execute(f"DELETE FROM {table} WHERE system_id=? AND {column}=?",
                                  (item.system_id, item.record_id)).rowcount
    mapping = {
        RetentionRecordType.INVESTIGATION_FINDING: ("investigation_findings", "finding_id"),
        RetentionRecordType.INVESTIGATION_SCOPE: ("investigation_scopes", "scope_digest"),
        RetentionRecordType.INVESTIGATION_EVIDENCE: ("investigation_evidence", "evidence_id"),
        RetentionRecordType.INVESTIGATION_RECOMMENDATION: ("investigation_recommendations", "recommendation_event_id"),
    }
    table, column = mapping[item.record_type]
    if item.record_type == RetentionRecordType.INVESTIGATION_FINDING:
        finding_id, relationship = json.loads(item.record_id)
        return connection.execute(
            """DELETE FROM investigation_findings WHERE system_id=?
               AND investigation_id=? AND finding_id=? AND relationship=?""",
            (item.system_id, item.parent_id, finding_id, relationship)).rowcount
    return connection.execute(
        f"DELETE FROM {table} WHERE system_id=? AND investigation_id=? AND {column}=?",
        (item.system_id, item.parent_id, item.record_id)).rowcount


def _audit(connection, execution):
    connection.execute("""INSERT INTO retention_executions VALUES
        (?,?,?,?,?,?,?,?,?,?,?,'DERIVED_HISTORY')""", (
        execution.execution_id, execution.plan_id, execution.plan_digest,
        execution.policy_version, execution.authorization_id,
        execution.started_at, execution.completed_at,
        json.dumps(dict(execution.selected_counts), sort_keys=True),
        json.dumps(dict(execution.deleted_counts), sort_keys=True),
        execution.outcome.value, execution.failure_code,
    ))


def execute_retention_plan(database: MemoryDatabase, *, plan: RetentionPlan,
                           authorization_id: str, at: datetime) -> RetentionExecution:
    now = utc(at, "at")
    expected = canonical_plan_digest(plan.system_id, plan.policy_version, plan.items)
    if expected != plan.plan_digest or now.isoformat() >= plan.expires_at:
        raise MemoryRetentionApprovalError("Retention plan is stale, modified, or expired.")
    try:
        auth = database.connection.execute("""SELECT a.*,d.status AS decision_status,
            d.effective_at AS decision_effective_at,d.expires_at AS decision_expires_at
            FROM retention_authorizations a JOIN user_decisions d
            ON d.decision_id=a.decision_id AND d.system_id=a.system_id
            WHERE a.authorization_id=? AND a.plan_id=? AND a.plan_digest=? AND a.system_id=?""",
            (authorization_id, plan.plan_id, plan.plan_digest, plan.system_id)).fetchone()
    except sqlite3.Error as exc:
        raise MemoryRetentionError("Retention authorization could not be verified.") from exc
    if (auth is None or auth["expires_at"] <= now.isoformat()
            or auth["selected_count"] != len(plan.selected_items)
            or auth["decision_status"] != "ACTIVE"
            or auth["decision_effective_at"] > now.isoformat()
            or (auth["decision_expires_at"] is not None
                and auth["decision_expires_at"] <= now.isoformat())):
        raise MemoryRetentionApprovalError("Exact unexpired retention authorization is required.")
    execution_id = f"retention-execution:{uuid.uuid4().hex}"
    selected = Counter(item.record_type.value for item in plan.selected_items)
    deleted = Counter()
    started = now.isoformat()
    try:
        database.connection.execute("BEGIN IMMEDIATE")
        database.connection.execute("UPDATE retention_guard SET enabled=1 WHERE singleton=1")
        delete_priority = {
            RetentionRecordType.ACTION_RESPONSE: 10,
            RetentionRecordType.INVESTIGATION_RECOMMENDATION: 10,
            RetentionRecordType.INVESTIGATION_EVIDENCE: 10,
            RetentionRecordType.INVESTIGATION_FINDING: 10,
            RetentionRecordType.INVESTIGATION_SCOPE: 10,
            RetentionRecordType.INVESTIGATION_QUESTION: 10,
            RetentionRecordType.CAPABILITY_EXECUTION_EVENT: 10,
            RetentionRecordType.INVESTIGATION_STATUS_EVENT: 10,
            RetentionRecordType.CAPABILITY_EXECUTION: 20,
            RetentionRecordType.RECOMMENDATION_EVENT: 20,
            RetentionRecordType.INVESTIGATION: 30,
        }
        order = sorted(plan.selected_items, key=lambda item: (
            delete_priority.get(item.record_type, 15), item.record_type.value,
            item.record_id))
        for item in order:
            count = _delete_item(database.connection, item)
            if count != 1:
                raise MemoryRetentionError("Approved retention record is missing or changed.")
            deleted[item.record_type.value] += count
        database.connection.execute("UPDATE retention_guard SET enabled=0 WHERE singleton=1")
        completed = datetime.now(timezone.utc).isoformat()
        result = RetentionExecution(execution_id, plan.plan_id, plan.plan_digest,
            plan.policy_version, authorization_id, started, completed,
            tuple(sorted(selected.items())), tuple(sorted(deleted.items())),
            RetentionOutcome.SUCCEEDED, None)
        _audit(database.connection, result)
        database.connection.commit()
        return result
    except Exception as exc:
        database.connection.rollback()
        code = "LOCKED" if "locked" in str(exc).casefold() else "TRANSACTION_FAILED"
        completed = datetime.now(timezone.utc).isoformat()
        result = RetentionExecution(execution_id, plan.plan_id, plan.plan_digest,
            plan.policy_version, authorization_id, started, completed,
            tuple(sorted(selected.items())), (), RetentionOutcome.FAILED, code)
        try:
            database.connection.execute("BEGIN IMMEDIATE")
            _audit(database.connection, result)
            database.connection.commit()
        except sqlite3.Error:
            database.connection.rollback()
        raise MemoryRetentionError("Retention transaction failed and was rolled back.") from exc
