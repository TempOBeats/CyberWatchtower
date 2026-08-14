"""Closed contracts for plan-first, explicitly authorized retention."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum

from .errors import MemoryRetentionError


RETENTION_POLICY_VERSION = "memory-v0.2-retention-1"
MAX_RETENTION_ITEMS = 10_000


class RetentionRecordType(str, Enum):
    INVESTIGATION = "INVESTIGATION"
    INVESTIGATION_STATUS_EVENT = "INVESTIGATION_STATUS_EVENT"
    INVESTIGATION_FINDING = "INVESTIGATION_FINDING"
    INVESTIGATION_SCOPE = "INVESTIGATION_SCOPE"
    INVESTIGATION_EVIDENCE = "INVESTIGATION_EVIDENCE"
    INVESTIGATION_QUESTION = "INVESTIGATION_QUESTION"
    INVESTIGATION_RECOMMENDATION = "INVESTIGATION_RECOMMENDATION"
    EXPIRED_EXCEPTION = "EXPIRED_EXCEPTION"
    RECOMMENDATION_EVENT = "RECOMMENDATION_EVENT"
    ACTION_RESPONSE = "ACTION_RESPONSE"
    CONVERSATION_REFERENCE = "CONVERSATION_REFERENCE"
    CAPABILITY_EXECUTION = "CAPABILITY_EXECUTION"
    CAPABILITY_EXECUTION_EVENT = "CAPABILITY_EXECUTION_EVENT"


class RetentionOutcome(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


@dataclass(frozen=True)
class RetentionPolicy:
    version: str = RETENTION_POLICY_VERSION
    investigations: timedelta = timedelta(days=730)
    expired_exceptions: timedelta = timedelta(days=365)
    recommendation_events: timedelta = timedelta(days=365)
    action_responses: timedelta = timedelta(days=730)
    conversation_references: timedelta = timedelta(days=30)
    capability_executions: timedelta = timedelta(days=180)
    model_interpretations: timedelta = timedelta(days=30)
    maximum_items: int = MAX_RETENTION_ITEMS

    def __post_init__(self):
        durations = tuple(value for key, value in vars(self).items() if isinstance(value, timedelta))
        if any(value <= timedelta(0) for value in durations):
            raise MemoryRetentionError("Retention durations must be positive.")
        if not isinstance(self.maximum_items, int) or not 1 <= self.maximum_items <= MAX_RETENTION_ITEMS:
            raise MemoryRetentionError("maximum_items is outside the safe bound.")


@dataclass(frozen=True)
class RetentionItem:
    record_type: RetentionRecordType
    record_id: str
    system_id: str
    eligible_at: str
    reason: str
    blocker: str | None = None
    parent_id: str | None = None


@dataclass(frozen=True)
class RetentionPlan:
    plan_id: str
    plan_digest: str
    generated_at: str
    expires_at: str
    policy_version: str
    system_id: str
    items: tuple[RetentionItem, ...]
    counts: tuple[tuple[str, int], ...]

    @property
    def selected_items(self):
        return tuple(item for item in self.items if item.blocker is None)


@dataclass(frozen=True)
class RetentionAuthorization:
    authorization_id: str
    plan_id: str
    plan_digest: str
    system_id: str
    decision_id: str
    authorized_at: str
    expires_at: str
    selected_count: int


@dataclass(frozen=True)
class RetentionExecution:
    execution_id: str
    plan_id: str
    plan_digest: str
    policy_version: str
    authorization_id: str
    started_at: str
    completed_at: str
    selected_counts: tuple[tuple[str, int], ...]
    deleted_counts: tuple[tuple[str, int], ...]
    outcome: RetentionOutcome
    failure_code: str | None


def canonical_plan_digest(system_id: str, policy_version: str,
                          items: tuple[RetentionItem, ...]) -> str:
    payload = {
        "system_id": system_id,
        "policy_version": policy_version,
        "items": [{
            "record_type": item.record_type.value,
            "record_id": item.record_id,
            "system_id": item.system_id,
            "eligible_at": item.eligible_at,
            "reason": item.reason,
            "blocker": item.blocker,
            "parent_id": item.parent_id,
        } for item in items],
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def utc(value: datetime, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise MemoryRetentionError(f"{name} must be timezone-aware.")
    return value.astimezone(timezone.utc)
