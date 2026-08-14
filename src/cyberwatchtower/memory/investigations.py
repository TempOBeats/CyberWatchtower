"""Transactional, host-isolated investigation and capability audit APIs."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone

from cyberwatchtower.capabilities.registry import PermissionClass
from cyberwatchtower.core.evidence import EpistemicRole

from .database import MemoryDatabase
from .decision_models import (
    ListenerScope, ServiceScope, TypedScope, safe_text, scope_from_storage, utc_text,
    MAX_ACTOR_LENGTH, MAX_FINDING_ID_LENGTH, MAX_IDENTIFIER_LENGTH,
)
from .errors import MemoryCorrupt, MemoryDecisionError, MemoryInvestigationError, MemoryLocked
from .investigation_models import (
    CapabilityExecutionRecord, CapabilityExecutionStatus, ConversationReferenceRecord,
    EvidenceType, FindingRelationship, InvestigationDisposition,
    InvestigationEvidenceRecord, InvestigationFindingRecord, InvestigationIntent,
    InvestigationQuestionRecord, InvestigationRecord, InvestigationStatus,
    InvestigationTimeline, InvestigationTimelineEntry, ReferenceState, ReferenceType,
    SubjectType,
)


MAX_TITLE_LENGTH = 256
MAX_DISPOSITION_LENGTH = 128
MAX_SUMMARY_VALUE_LENGTH = 256
MAX_SUMMARY_ITEMS = 32

PARAMETER_ALLOWLISTS = {
    "load_reports": frozenset({"system_id", "report_limit"}),
    "compare_scans": frozenset({"report_ids"}),
    "explain_finding": frozenset({"finding_id"}),
    "scan_host": frozenset({"system_id"}),
    "inspect_process": frozenset({"finding_id", "application"}),
    "inspect_service": frozenset({"protocol", "address", "port", "application"}),
}
RESULT_ALLOWLISTS = {
    "load_reports": frozenset({"report_ids", "count"}),
    "compare_scans": frozenset({"report_ids", "new_finding_ids", "resolved_finding_ids"}),
    "explain_finding": frozenset({"finding_id"}),
    "scan_host": frozenset({"report_id"}),
    "inspect_process": frozenset({"finding_id", "application"}),
    "inspect_service": frozenset({"finding_id", "service"}),
}


def _id(prefix):
    return f"{prefix}:{uuid.uuid4().hex}"


def _text(value, name, maximum=MAX_IDENTIFIER_LENGTH):
    try:
        return safe_text(value, name, maximum)
    except MemoryDecisionError as exc:
        raise MemoryInvestigationError(str(exc)) from exc


def _enum(kind, value, name):
    try:
        return kind(value)
    except (TypeError, ValueError) as exc:
        raise MemoryInvestigationError(f"{name} is not recognized.") from exc


def _utc(value, name):
    try:
        return utc_text(value, name)
    except MemoryDecisionError as exc:
        raise MemoryInvestigationError(str(exc)) from exc


def _translate(exc, label):
    if "locked" in str(exc).casefold():
        return MemoryLocked("Persistent Security Memory is locked.")
    if isinstance(exc, sqlite3.IntegrityError):
        return MemoryInvestigationError(f"{label} violates an investigation invariant.")
    return MemoryCorrupt(f"{label} failed because memory storage is invalid.")


def _transaction(database, operation, label):
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


def _investigation(row):
    disposition = (InvestigationDisposition(row["final_disposition"])
                   if row["final_disposition"] else None)
    return InvestigationRecord(
        row["investigation_id"], row["system_id"], InvestigationStatus(row["status"]),
        row["title"], row["actor"], row["opened_at"], row["closed_at"], disposition,
    )


def create_investigation(database: MemoryDatabase, *, system_id: str, title: str,
                         actor: str, opened_at: datetime) -> InvestigationRecord:
    system_id = _text(system_id, "system_id")
    title = _text(title, "title", MAX_TITLE_LENGTH)
    actor = _text(actor, "actor", MAX_ACTOR_LENGTH)
    opened = _utc(opened_at, "opened_at")
    investigation_id = _id("investigation")
    def write(connection):
        connection.execute(
            """INSERT INTO investigations VALUES
               (?,?,'OPEN',?,?,?,NULL,NULL,'USER_DECISION',?)""",
            (investigation_id, system_id, title, actor, opened,
             datetime.now(timezone.utc).isoformat()),
        )
        connection.execute(
            "INSERT INTO investigation_status_events VALUES (?,?,?,?,?,'USER_DECISION')",
            (_id("investigation-event"), investigation_id, system_id, "OPEN", opened),
        )
        return _investigation(connection.execute(
            "SELECT * FROM investigations WHERE investigation_id=?",
            (investigation_id,)).fetchone())
    return _transaction(database, write, "Investigation creation")


def _change_status(database, system_id, investigation_id, expected, status,
                   closed_at=None, disposition=None):
    system_id = _text(system_id, "system_id")
    investigation_id = _text(investigation_id, "investigation_id")
    def write(connection):
        current = connection.execute(
            "SELECT opened_at FROM investigations WHERE system_id=? AND investigation_id=?",
            (system_id, investigation_id),
        ).fetchone()
        if current is None or (closed_at is not None and closed_at < current["opened_at"]):
            raise MemoryInvestigationError("Investigation closure cannot precede opening.")
        expected_values = [item.value for item in expected]
        if len(expected_values) == 1:
            expected_values.append(expected_values[0])
        parameters = [status.value, closed_at, disposition.value if disposition else None,
                      system_id, investigation_id, *expected_values]
        changed = connection.execute(
            """UPDATE investigations SET status=?,closed_at=?,final_disposition=?
               WHERE system_id=? AND investigation_id=? AND status IN (?,?)""",
            parameters,
        ).rowcount
        if changed != 1:
            raise MemoryInvestigationError("Investigation transition is not allowed.")
        occurred_at = closed_at or datetime.now(timezone.utc).isoformat()
        connection.execute(
            "INSERT INTO investigation_status_events VALUES (?,?,?,?,?,'USER_DECISION')",
            (_id("investigation-event"), investigation_id, system_id,
             status.value, occurred_at),
        )
        return _investigation(connection.execute(
            "SELECT * FROM investigations WHERE investigation_id=?",
            (investigation_id,)).fetchone())
    return _transaction(database, write, "Investigation transition")


def pause_investigation(database, *, system_id, investigation_id):
    return _change_status(database, system_id, investigation_id,
                          (InvestigationStatus.OPEN,), InvestigationStatus.PAUSED)


def resume_investigation(database, *, system_id, investigation_id):
    return _change_status(database, system_id, investigation_id,
                          (InvestigationStatus.PAUSED,), InvestigationStatus.OPEN)


def complete_investigation(database, *, system_id, investigation_id,
                           closed_at: datetime, disposition: InvestigationDisposition):
    disposition = _enum(InvestigationDisposition, disposition, "disposition")
    if disposition == InvestigationDisposition.CANCELLED:
        raise MemoryInvestigationError("Use cancel_investigation for cancellation.")
    return _change_status(
        database, system_id, investigation_id,
        (InvestigationStatus.OPEN, InvestigationStatus.PAUSED),
        InvestigationStatus.COMPLETED, _utc(closed_at, "closed_at"), disposition)


def cancel_investigation(database, *, system_id, investigation_id, closed_at: datetime):
    return _change_status(
        database, system_id, investigation_id,
        (InvestigationStatus.OPEN, InvestigationStatus.PAUSED),
        InvestigationStatus.CANCELLED, _utc(closed_at, "closed_at"),
        InvestigationDisposition.CANCELLED)


def _require_mutable(connection, system_id, investigation_id):
    row = connection.execute(
        "SELECT status FROM investigations WHERE system_id=? AND investigation_id=?",
        (system_id, investigation_id),
    ).fetchone()
    if row is None or row["status"] not in {"OPEN", "PAUSED"}:
        raise MemoryInvestigationError("Investigation must be open or paused.")


def attach_finding(database, *, system_id: str, investigation_id: str,
                   finding_id: str, relationship: FindingRelationship,
                   attached_at: datetime) -> InvestigationFindingRecord:
    system_id = _text(system_id, "system_id")
    investigation_id = _text(investigation_id, "investigation_id")
    finding_id = _text(finding_id, "finding_id", MAX_FINDING_ID_LENGTH)
    relationship = _enum(FindingRelationship, relationship, "relationship")
    attached = _utc(attached_at, "attached_at")
    def write(connection):
        _require_mutable(connection, system_id, investigation_id)
        connection.execute(
            """INSERT INTO investigation_findings VALUES
               (?,?,?,?,?,'USER_DECISION')""",
            (investigation_id, system_id, finding_id, relationship.value, attached),
        )
        return InvestigationFindingRecord(finding_id, relationship, attached)
    return _transaction(database, write, "Finding attachment")


def attach_subject_finding(database, **kwargs):
    return attach_finding(database, relationship=FindingRelationship.SUBJECT, **kwargs)


def attach_related_finding(database, **kwargs):
    return attach_finding(database, relationship=FindingRelationship.RELATED, **kwargs)


def attach_subject_scope(database, *, system_id: str, investigation_id: str,
                         scope: TypedScope, attached_at: datetime):
    if not isinstance(scope, (ServiceScope, ListenerScope)):
        raise MemoryInvestigationError("Only service and listener subject scopes are supported.")
    system_id = _text(system_id, "system_id")
    investigation_id = _text(investigation_id, "investigation_id")
    attached = _utc(attached_at, "attached_at")
    def write(connection):
        _require_mutable(connection, system_id, investigation_id)
        connection.execute(
            """INSERT INTO investigation_scopes VALUES
               (?,?,?,?,?,?,'USER_DECISION')""",
            (investigation_id, system_id, scope.scope_type.value,
             scope.canonical_json(), scope.digest(), attached),
        )
        return scope
    return _transaction(database, write, "Subject scope attachment")


def _source_exists(connection, system_id, investigation_id, evidence_type, source_id):
    queries = {
        EvidenceType.REPORT: ("SELECT 1 FROM reports WHERE system_id=? AND report_id=?", (system_id, source_id)),
        EvidenceType.FINDING: ("SELECT 1 FROM findings WHERE system_id=? AND finding_id=?", (system_id, source_id)),
        EvidenceType.OCCURRENCE: ("SELECT 1 FROM finding_occurrences WHERE system_id=? AND occurrence_id=?", (system_id, source_id)),
        EvidenceType.LIFECYCLE_EVENT: ("SELECT 1 FROM finding_lifecycle_events WHERE system_id=? AND event_id=?", (system_id, source_id)),
        EvidenceType.RECOMMENDATION: ("SELECT 1 FROM recommendations_shown WHERE system_id=? AND recommendation_event_id=?", (system_id, source_id)),
        EvidenceType.USER_DECISION: ("SELECT 1 FROM user_decisions WHERE system_id=? AND decision_id=?", (system_id, source_id)),
        EvidenceType.CAPABILITY_RESULT: (
            """SELECT 1 FROM capability_executions WHERE system_id=? AND execution_id=?
               AND status='SUCCEEDED' AND (investigation_id IS NULL OR investigation_id=?)""",
            (system_id, source_id, investigation_id)),
    }
    sql, parameters = queries[evidence_type]
    return connection.execute(sql, parameters).fetchone() is not None


def record_evidence_consulted(database, *, system_id: str, investigation_id: str,
                              evidence_id: str, evidence_type: EvidenceType,
                              source_record_id: str, epistemic_role: EpistemicRole,
                              consulted_at: datetime) -> InvestigationEvidenceRecord:
    system_id = _text(system_id, "system_id")
    investigation_id = _text(investigation_id, "investigation_id")
    evidence_id = _text(evidence_id, "evidence_id")
    source_record_id = _text(source_record_id, "source_record_id", MAX_FINDING_ID_LENGTH)
    evidence_type = _enum(EvidenceType, evidence_type, "evidence_type")
    epistemic_role = _enum(EpistemicRole, epistemic_role, "epistemic_role")
    required_roles = {
        EvidenceType.REPORT: EpistemicRole.OBSERVED_FACT,
        EvidenceType.FINDING: EpistemicRole.OBSERVED_FACT,
        EvidenceType.OCCURRENCE: EpistemicRole.OBSERVED_FACT,
        EvidenceType.LIFECYCLE_EVENT: EpistemicRole.DETERMINISTIC_DERIVATION,
        EvidenceType.RECOMMENDATION: EpistemicRole.DETERMINISTIC_DERIVATION,
        EvidenceType.CAPABILITY_RESULT: EpistemicRole.DETERMINISTIC_DERIVATION,
        EvidenceType.USER_DECISION: EpistemicRole.USER_DECISION,
    }
    if epistemic_role != required_roles[evidence_type]:
        raise MemoryInvestigationError(
            "Epistemic role is incompatible with the referenced evidence type.")
    consulted = _utc(consulted_at, "consulted_at")
    def write(connection):
        _require_mutable(connection, system_id, investigation_id)
        if not _source_exists(connection, system_id, investigation_id,
                              evidence_type, source_record_id):
            raise MemoryInvestigationError("Evidence source does not exist in the same system.")
        connection.execute(
            """INSERT INTO investigation_evidence VALUES
               (?,?,?,?,?,?,?,'DERIVED_HISTORY')""",
            (investigation_id, system_id, evidence_id, evidence_type.value,
             source_record_id, epistemic_role.value, consulted),
        )
        return InvestigationEvidenceRecord(
            evidence_id, evidence_type, source_record_id, epistemic_role, consulted)
    return _transaction(database, write, "Evidence recording")


def record_question(database, *, system_id: str, investigation_id: str,
                    intent: InvestigationIntent, subject_type: SubjectType,
                    subject_id: str, recorded_at: datetime) -> InvestigationQuestionRecord:
    system_id = _text(system_id, "system_id")
    investigation_id = _text(investigation_id, "investigation_id")
    intent = _enum(InvestigationIntent, intent, "intent")
    subject_type = _enum(SubjectType, subject_type, "subject_type")
    subject_id = _text(subject_id, "subject_id", MAX_FINDING_ID_LENGTH)
    recorded = _utc(recorded_at, "recorded_at")
    question_id = _id("question")
    def write(connection):
        _require_mutable(connection, system_id, investigation_id)
        connection.execute(
            "INSERT INTO investigation_questions VALUES (?,?,?,?,?,?,?,'DERIVED_HISTORY')",
            (question_id, investigation_id, system_id, intent.value,
             subject_type.value, subject_id, recorded),
        )
        return InvestigationQuestionRecord(
            question_id, intent, subject_type, subject_id, recorded)
    return _transaction(database, write, "Question recording")


def _safe_summary(capability_id, summary, allowlists, name):
    capability_id = _text(capability_id, "capability_id")
    allowed = allowlists.get(capability_id)
    if allowed is None or not isinstance(summary, dict) or set(summary) - allowed:
        raise MemoryInvestigationError(f"{name} contains unsupported capability fields.")
    if len(summary) > MAX_SUMMARY_ITEMS:
        raise MemoryInvestigationError(f"{name} contains too many fields.")
    normalized = {}
    for key, value in summary.items():
        if isinstance(value, bool) or isinstance(value, int):
            normalized[key] = value
        elif isinstance(value, str):
            normalized[key] = _text(value, f"{name}.{key}", MAX_SUMMARY_VALUE_LENGTH)
        elif isinstance(value, (tuple, list)) and len(value) <= MAX_SUMMARY_ITEMS:
            normalized[key] = [_text(item, f"{name}.{key}", MAX_SUMMARY_VALUE_LENGTH)
                               for item in value]
        else:
            raise MemoryInvestigationError(f"{name}.{key} has an unsupported value type.")
    return normalized


def _capability(row):
    result = json.loads(row["result_summary_json"]) if row["result_summary_json"] else None
    parameters = json.loads(row["parameter_summary_json"])
    return CapabilityExecutionRecord(
        row["execution_id"], row["system_id"], row["investigation_id"],
        row["capability_id"], PermissionClass(row["permission_class"]),
        CapabilityExecutionStatus(row["status"]), row["requested_at"],
        row["authorization_decision_id"], row["started_at"], row["completed_at"],
        tuple(sorted(parameters.items())), tuple(sorted(result.items())) if result else None,
        row["error_code"],
    )


def record_capability_proposal(database, *, system_id: str, capability_id: str,
                               permission_class: PermissionClass, requested_at: datetime,
                               parameter_summary: dict,
                               investigation_id: str | None = None) -> CapabilityExecutionRecord:
    system_id = _text(system_id, "system_id")
    capability_id = _text(capability_id, "capability_id")
    permission_class = _enum(PermissionClass, permission_class, "permission_class")
    requested = _utc(requested_at, "requested_at")
    parameters = _safe_summary(capability_id, parameter_summary,
                               PARAMETER_ALLOWLISTS, "parameter_summary")
    if investigation_id:
        investigation_id = _text(investigation_id, "investigation_id")
    status = {PermissionClass.USER_APPROVAL_REQUIRED: CapabilityExecutionStatus.APPROVAL_REQUIRED,
              PermissionClass.PROHIBITED: CapabilityExecutionStatus.DENIED}.get(
                  permission_class, CapabilityExecutionStatus.PROPOSED)
    execution_id = _id("execution")
    def write(connection):
        if investigation_id:
            _require_mutable(connection, system_id, investigation_id)
        connection.execute(
            """INSERT INTO capability_executions
               (execution_id,system_id,investigation_id,capability_id,permission_class,status,
                requested_at,authorization_decision_id,started_at,completed_at,
                parameter_summary_json,result_summary_json,error_code,provenance)
               VALUES (?,?,?,?,?,?,?,NULL,NULL,NULL,?,NULL,NULL,'DERIVED_HISTORY')""",
            (execution_id, system_id, investigation_id, capability_id,
             permission_class.value, status.value, requested,
             json.dumps(parameters, sort_keys=True, separators=(",", ":"))),
        )
        connection.execute(
            "INSERT INTO capability_execution_events VALUES (?,?,?,?,?,'DERIVED_HISTORY')",
            (_id("capability-event"), execution_id, system_id, status.value, requested),
        )
        return _capability(connection.execute(
            "SELECT * FROM capability_executions WHERE execution_id=?",
            (execution_id,)).fetchone())
    return _transaction(database, write, "Capability proposal")


def record_capability_outcome(database, *, system_id: str, execution_id: str,
                              status: CapabilityExecutionStatus,
                              completed_at: datetime,
                              started_at: datetime | None = None,
                              authorization_decision_id: str | None = None,
                              result_summary: dict | None = None,
                              error_code: str | None = None) -> CapabilityExecutionRecord:
    system_id = _text(system_id, "system_id")
    execution_id = _text(execution_id, "execution_id")
    status = _enum(CapabilityExecutionStatus, status, "status")
    if status not in {CapabilityExecutionStatus.DENIED,
                      CapabilityExecutionStatus.SUCCEEDED,
                      CapabilityExecutionStatus.FAILED}:
        raise MemoryInvestigationError("Outcome must be DENIED, SUCCEEDED, or FAILED.")
    completed = _utc(completed_at, "completed_at")
    started = _utc(started_at, "started_at") if started_at else None
    if authorization_decision_id:
        authorization_decision_id = _text(
            authorization_decision_id, "authorization_decision_id")
    if error_code:
        error_code = _text(error_code, "error_code", 128)
    def write(connection):
        row = connection.execute(
            "SELECT * FROM capability_executions WHERE system_id=? AND execution_id=?",
            (system_id, execution_id),
        ).fetchone()
        if row is None or row["status"] not in {"PROPOSED", "APPROVAL_REQUIRED"}:
            raise MemoryInvestigationError("Capability execution cannot transition from its current state.")
        if completed < row["requested_at"] or (started is not None and
                                                (started < row["requested_at"] or completed < started)):
            raise MemoryInvestigationError("Capability timestamps are not chronological.")
        permission = PermissionClass(row["permission_class"])
        if authorization_decision_id and permission != PermissionClass.USER_APPROVAL_REQUIRED:
            raise MemoryInvestigationError(
                "Authorization links are only valid for approval-required capabilities.")
        if status == CapabilityExecutionStatus.DENIED and authorization_decision_id:
            raise MemoryInvestigationError("Denied outcomes cannot claim authorization.")
        if authorization_decision_id:
            approval = connection.execute(
                """SELECT decision_type,scope_type,scope_json FROM user_decisions
                   WHERE system_id=? AND decision_id=?
                   AND status='ACTIVE' AND provenance='USER_DECISION'
                   AND effective_at<=? AND (expires_at IS NULL OR expires_at>?)""",
                (system_id, authorization_decision_id, row["requested_at"],
                 row["requested_at"]),
            ).fetchone()
            expected_scope = json.dumps(
                {"application": f"capability:{row['capability_id']}"},
                sort_keys=True, separators=(",", ":"))
            if (approval is None or approval["decision_type"] != "CUSTOM"
                    or approval["scope_type"] != "APPLICATION"
                    or approval["scope_json"] != expected_scope):
                raise MemoryInvestigationError("Authorization decision is invalid or cross-system.")
        result = None
        if status == CapabilityExecutionStatus.SUCCEEDED:
            if started is None or result_summary is None or error_code is not None:
                raise MemoryInvestigationError("Successful outcomes require times and an allowlisted result.")
            result = _safe_summary(row["capability_id"], result_summary,
                                   RESULT_ALLOWLISTS, "result_summary")
            if permission == PermissionClass.USER_APPROVAL_REQUIRED:
                if not authorization_decision_id:
                    raise MemoryInvestigationError("Approval-required success needs a user decision.")
        elif status == CapabilityExecutionStatus.FAILED:
            if started is None or not error_code or result_summary is not None:
                raise MemoryInvestigationError("Failed outcomes require an error code and no result summary.")
        else:
            if started is not None or result_summary is not None:
                raise MemoryInvestigationError("Denied outcomes cannot contain execution results.")
        connection.execute(
            """UPDATE capability_executions SET status=?,authorization_decision_id=?,
               started_at=?,completed_at=?,result_summary_json=?,error_code=?
               WHERE system_id=? AND execution_id=?""",
            (status.value, authorization_decision_id, started, completed,
             json.dumps(result, sort_keys=True, separators=(",", ":")) if result is not None else None,
             error_code, system_id, execution_id),
        )
        connection.execute(
            "INSERT INTO capability_execution_events VALUES (?,?,?,?,?,'DERIVED_HISTORY')",
            (_id("capability-event"), execution_id, system_id, status.value, completed),
        )
        return _capability(connection.execute(
            "SELECT * FROM capability_executions WHERE execution_id=?",
            (execution_id,)).fetchone())
    return _transaction(database, write, "Capability outcome")


def link_recommendation(database, *, system_id, investigation_id,
                        recommendation_event_id, linked_at):
    system_id = _text(system_id, "system_id")
    investigation_id = _text(investigation_id, "investigation_id")
    recommendation_event_id = _text(recommendation_event_id, "recommendation_event_id")
    linked = _utc(linked_at, "linked_at")
    def write(connection):
        _require_mutable(connection, system_id, investigation_id)
        connection.execute(
            "INSERT INTO investigation_recommendations VALUES (?,?,?,?,'DERIVED_HISTORY')",
            (investigation_id, system_id, recommendation_event_id, linked))
    _transaction(database, write, "Recommendation linkage")


def create_conversation_reference(database, *, system_id: str, session_id: str,
                                  reference_type: ReferenceType, target_id: str,
                                  reference_state: ReferenceState, created_at: datetime,
                                  expires_at: datetime) -> ConversationReferenceRecord:
    system_id = _text(system_id, "system_id")
    session_id = _text(session_id, "session_id")
    reference_type = _enum(ReferenceType, reference_type, "reference_type")
    target_id = _text(target_id, "target_id", MAX_FINDING_ID_LENGTH)
    reference_state = _enum(ReferenceState, reference_state, "reference_state")
    created, expires = _utc(created_at, "created_at"), _utc(expires_at, "expires_at")
    if expires <= created:
        raise MemoryInvestigationError("expires_at must follow created_at.")
    reference_id = _id("reference")
    def write(connection):
        queries = {
            ReferenceType.FINDING: ("SELECT 1 FROM findings WHERE system_id=? AND finding_id=?", (system_id,target_id)),
            ReferenceType.INVESTIGATION: ("SELECT 1 FROM investigations WHERE system_id=? AND investigation_id=?", (system_id,target_id)),
            ReferenceType.REPORT: ("SELECT 1 FROM reports WHERE system_id=? AND report_id=?", (system_id,target_id)),
            ReferenceType.ACTION: ("SELECT 1 FROM recommendations_shown WHERE system_id=? AND action_id=?", (system_id,target_id)),
        }
        query, parameters = queries[reference_type]
        if connection.execute(query, parameters).fetchone() is None:
            raise MemoryInvestigationError("Reference target does not exist in the same system.")
        connection.execute(
            "INSERT INTO conversation_references VALUES (?,?,?,?,?,?,?,?, 'DERIVED_HISTORY')",
            (reference_id, system_id, session_id, reference_type.value, target_id,
             reference_state.value, created, expires),
        )
        return ConversationReferenceRecord(
            reference_id, system_id, session_id, reference_type, target_id,
            reference_state, created, expires)
    return _transaction(database, write, "Conversation reference")


def open_investigations(database, *, system_id: str):
    system_id = _text(system_id, "system_id")
    rows = database.connection.execute(
        """SELECT * FROM investigations WHERE system_id=? AND status IN ('OPEN','PAUSED')
           ORDER BY opened_at,investigation_id""", (system_id,)).fetchall()
    return tuple(_investigation(row) for row in rows)


def investigation_by_id(database, *, system_id: str, investigation_id: str):
    row = database.connection.execute(
        "SELECT * FROM investigations WHERE system_id=? AND investigation_id=?",
        (_text(system_id,"system_id"), _text(investigation_id,"investigation_id")),
    ).fetchone()
    return _investigation(row) if row else None


def evidence_for_investigation(database, *, system_id: str, investigation_id: str):
    rows = database.connection.execute(
        """SELECT * FROM investigation_evidence WHERE system_id=? AND investigation_id=?
           ORDER BY consulted_at,evidence_id""",
        (_text(system_id,"system_id"), _text(investigation_id,"investigation_id")),
    ).fetchall()
    return tuple(InvestigationEvidenceRecord(
        row["evidence_id"], EvidenceType(row["evidence_type"]), row["source_record_id"],
        EpistemicRole(row["epistemic_role"]), row["consulted_at"]) for row in rows)


def capability_history(database, *, system_id: str, investigation_id: str):
    rows = database.connection.execute(
        """SELECT * FROM capability_executions WHERE system_id=? AND investigation_id=?
           ORDER BY requested_at,execution_id""",
        (_text(system_id,"system_id"), _text(investigation_id,"investigation_id")),
    ).fetchall()
    return tuple(_capability(row) for row in rows)


def latest_completed_for_finding(database, *, system_id: str, finding_id: str):
    row = database.connection.execute(
        """SELECT i.* FROM investigations i JOIN investigation_findings f
           ON f.investigation_id=i.investigation_id AND f.system_id=i.system_id
           WHERE i.system_id=? AND f.finding_id=? AND i.status='COMPLETED'
           ORDER BY i.closed_at DESC,i.investigation_id DESC LIMIT 1""",
        (_text(system_id,"system_id"), _text(finding_id,"finding_id",MAX_FINDING_ID_LENGTH)),
    ).fetchone()
    return _investigation(row) if row else None


def latest_completed_for_scope(database, *, system_id: str, scope: TypedScope):
    if not isinstance(scope, (ServiceScope, ListenerScope)):
        raise MemoryInvestigationError("Only service and listener scopes are supported.")
    row = database.connection.execute(
        """SELECT i.* FROM investigations i JOIN investigation_scopes s
           ON s.investigation_id=i.investigation_id AND s.system_id=i.system_id
           WHERE i.system_id=? AND s.scope_digest=? AND i.status='COMPLETED'
           ORDER BY i.closed_at DESC,i.investigation_id DESC LIMIT 1""",
        (_text(system_id,"system_id"), scope.digest()),
    ).fetchone()
    return _investigation(row) if row else None


def active_conversation_references(database, *, system_id: str, session_id: str,
                                   at: datetime):
    current = _utc(at,"at")
    rows = database.connection.execute(
        """SELECT * FROM conversation_references WHERE system_id=? AND session_id=?
           AND created_at<=? AND expires_at>? ORDER BY created_at,reference_id""",
        (_text(system_id,"system_id"), _text(session_id,"session_id"), current,current),
    ).fetchall()
    return tuple(ConversationReferenceRecord(
        row["reference_id"],row["system_id"],row["session_id"],
        ReferenceType(row["reference_type"]),row["target_id"],
        ReferenceState(row["reference_state"]),row["created_at"],row["expires_at"])
        for row in rows)


def investigation_timeline(database, *, system_id: str,
                           investigation_id: str) -> InvestigationTimeline | None:
    investigation = investigation_by_id(
        database, system_id=system_id, investigation_id=investigation_id)
    if investigation is None:
        return None
    system_id, investigation_id = investigation.system_id, investigation.investigation_id
    entries = []
    unions = (
        ("SELECT occurred_at,event_id FROM investigation_status_events WHERE system_id=? AND investigation_id=?","INVESTIGATION_STATUS"),
        ("SELECT attached_at,finding_id FROM investigation_findings WHERE system_id=? AND investigation_id=?","FINDING_ATTACHED"),
        ("SELECT attached_at,scope_digest FROM investigation_scopes WHERE system_id=? AND investigation_id=?","SCOPE_ATTACHED"),
        ("SELECT consulted_at,evidence_id FROM investigation_evidence WHERE system_id=? AND investigation_id=?","EVIDENCE_CONSULTED"),
        ("SELECT recorded_at,question_id FROM investigation_questions WHERE system_id=? AND investigation_id=?","QUESTION_RECORDED"),
        ("SELECT requested_at,execution_id FROM capability_executions WHERE system_id=? AND investigation_id=?","CAPABILITY_RECORDED"),
        ("SELECT linked_at,recommendation_event_id FROM investigation_recommendations WHERE system_id=? AND investigation_id=?","RECOMMENDATION_LINKED"),
    )
    for sql, kind in unions:
        entries.extend(InvestigationTimelineEntry(row[0],kind,row[1]) for row in
                       database.connection.execute(sql,(system_id,investigation_id)))
    entries.extend(InvestigationTimelineEntry(row[0],"CAPABILITY_STATUS",row[1]) for row in
        database.connection.execute(
            """SELECT e.occurred_at,e.event_id FROM capability_execution_events e
               JOIN capability_executions c ON c.execution_id=e.execution_id AND c.system_id=e.system_id
               WHERE c.system_id=? AND c.investigation_id=?""",(system_id,investigation_id)))
    entries.extend(InvestigationTimelineEntry(row[0],"ACTION_RESPONSE",row[1]) for row in
        database.connection.execute(
            """SELECT a.recorded_at,a.response_id FROM action_responses a
               JOIN investigation_recommendations r
               ON r.recommendation_event_id=a.recommendation_event_id AND r.system_id=a.system_id
               WHERE r.system_id=? AND r.investigation_id=?""",(system_id,investigation_id)))
    return InvestigationTimeline(investigation, tuple(sorted(
        entries,key=lambda item:(item.occurred_at,item.entry_type,item.record_id))))
