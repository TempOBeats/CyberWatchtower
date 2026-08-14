"""Transactional persistence and exact validation for authorization envelopes."""

from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime

from .authorization_models import (
    CapabilityAuthorizationEnvelope,
    CapabilityAuthorizationRequest,
    bounded_identifier,
    canonical_parameter_digest,
    utc_text,
)
from .database import MemoryDatabase
from .decision_models import TypedScope, safe_text, MAX_IDENTIFIER_LENGTH
from .errors import (
    MemoryAuthorizationError, MemoryCorrupt, MemoryDecisionError, MemoryLocked,
)


def _text(value: object, name: str) -> str:
    try:
        return safe_text(value, name, MAX_IDENTIFIER_LENGTH)
    except MemoryDecisionError as exc:
        raise MemoryAuthorizationError(f"{name} is invalid.") from exc


def _record(row) -> CapabilityAuthorizationEnvelope:
    from .decision_models import scope_from_storage
    return CapabilityAuthorizationEnvelope(
        row["authorization_id"], row["system_id"], row["capability_id"],
        scope_from_storage(row["target_scope_type"], row["target_scope_json"]),
        row["parameter_digest"], row["proposal_id"], row["decision_id"],
        row["actor"], row["issued_at"], row["expires_at"],
    )


def _translate(exc: sqlite3.Error):
    if "locked" in str(exc).casefold():
        return MemoryLocked("Persistent Security Memory is locked.")
    if isinstance(exc, sqlite3.IntegrityError):
        return MemoryAuthorizationError("Authorization violates a memory invariant.")
    return MemoryCorrupt("Authorization storage is invalid.")


def create_capability_authorization(
    database: MemoryDatabase,
    *,
    system_id: str,
    capability_id: str,
    target_scope: TypedScope,
    parameters,
    proposal_id: str,
    decision_id: str,
    issued_at: datetime,
    expires_at: datetime,
) -> CapabilityAuthorizationEnvelope:
    system_id = _text(system_id, "system_id")
    capability_id = _text(capability_id, "capability_id")
    proposal_id = _text(proposal_id, "proposal_id")
    decision_id = _text(decision_id, "decision_id")
    if not isinstance(target_scope, TypedScope):
        raise MemoryAuthorizationError("target_scope must be typed.")
    parameter_digest = canonical_parameter_digest(capability_id, parameters)
    issued, expiry = utc_text(issued_at, "issued_at"), utc_text(expires_at, "expires_at")
    if expiry <= issued:
        raise MemoryAuthorizationError("Authorization expiration must follow issuance.")
    authorization_id = f"capability-authorization:{uuid.uuid4().hex}"
    try:
        database.connection.execute("BEGIN IMMEDIATE")
        decision = database.connection.execute(
            """SELECT actor,scope_digest,status,effective_at,expires_at,provenance
               FROM user_decisions WHERE system_id=? AND decision_id=?""",
            (system_id, decision_id),
        ).fetchone()
        if (
            decision is None or decision["status"] != "ACTIVE"
            or decision["provenance"] != "USER_DECISION"
            or decision["scope_digest"] != target_scope.digest()
            or decision["effective_at"] > issued
            or (decision["expires_at"] is not None and decision["expires_at"] <= issued)
            or (decision["expires_at"] is not None and expiry > decision["expires_at"])
        ):
            raise MemoryAuthorizationError(
                "A matching active same-system user decision is required."
            )
        database.connection.execute(
            """INSERT INTO capability_authorizations
               (authorization_id,system_id,capability_id,target_scope_type,
                target_scope_json,target_scope_digest,parameter_digest,proposal_id,
                decision_id,actor,issued_at,expires_at,provenance)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,'USER_DECISION')""",
            (authorization_id, system_id, capability_id, target_scope.scope_type.value,
             target_scope.canonical_json(), target_scope.digest(), parameter_digest,
             proposal_id, decision_id, decision["actor"], issued, expiry),
        )
        row = database.connection.execute(
            "SELECT * FROM capability_authorizations WHERE authorization_id=?",
            (authorization_id,),
        ).fetchone()
        database.connection.commit()
        return _record(row)
    except sqlite3.Error as exc:
        database.connection.rollback()
        raise _translate(exc) from exc
    except Exception:
        database.connection.rollback()
        raise


def validate_capability_authorization(
    database: MemoryDatabase,
    request: CapabilityAuthorizationRequest,
) -> CapabilityAuthorizationEnvelope:
    """Validate the exact envelope at execution/start time; execute nothing."""

    if not isinstance(request, CapabilityAuthorizationRequest):
        raise MemoryAuthorizationError("A typed authorization request is required.")
    if not isinstance(request.target_scope, TypedScope):
        raise MemoryAuthorizationError("target_scope must be typed.")
    bounded_identifier(request.authorization_id, "authorization_id")
    bounded_identifier(request.system_id, "system_id")
    bounded_identifier(request.capability_id, "capability_id")
    bounded_identifier(request.proposal_id, "proposal_id")
    execution = utc_text(request.execution_at, "execution_at")
    expected_digest = canonical_parameter_digest(
        request.capability_id, request.parameters
    )
    try:
        row = database.connection.execute(
            """SELECT a.*,d.status decision_status,d.effective_at decision_effective_at,
               d.expires_at decision_expires_at,d.scope_digest decision_scope_digest
               FROM capability_authorizations a JOIN user_decisions d
               ON d.decision_id=a.decision_id AND d.system_id=a.system_id
               WHERE a.authorization_id=?""",
            (request.authorization_id,),
        ).fetchone()
    except sqlite3.Error as exc:
        raise _translate(exc) from exc
    if (
        row is None
        or row["system_id"] != request.system_id
        or row["capability_id"] != request.capability_id
        or row["proposal_id"] != request.proposal_id
        or row["target_scope_digest"] != request.target_scope.digest()
        or row["target_scope_json"] != request.target_scope.canonical_json()
        or row["parameter_digest"] != expected_digest
        or row["issued_at"] > execution
        or row["expires_at"] <= execution
        or row["decision_status"] != "ACTIVE"
        or row["decision_effective_at"] > execution
        or (row["decision_expires_at"] is not None
            and row["decision_expires_at"] <= execution)
        or row["decision_scope_digest"] != row["target_scope_digest"]
    ):
        raise MemoryAuthorizationError(
            "Exact unexpired user authorization is required at execution time."
        )
    return _record(row)
