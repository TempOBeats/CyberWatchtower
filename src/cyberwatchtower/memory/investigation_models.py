"""Closed contracts for persistent investigations and capability audit history."""

from dataclasses import dataclass
from enum import Enum

from cyberwatchtower.capabilities.registry import PermissionClass
from cyberwatchtower.core.evidence import EpistemicRole

from .provenance import MemoryProvenance


class InvestigationStatus(str, Enum):
    OPEN = "OPEN"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"


class InvestigationDisposition(str, Enum):
    RESOLVED_BY_EVIDENCE = "RESOLVED_BY_EVIDENCE"
    NO_ACTION = "NO_ACTION"
    ESCALATED = "ESCALATED"
    INCONCLUSIVE = "INCONCLUSIVE"
    CANCELLED = "CANCELLED"


class FindingRelationship(str, Enum):
    SUBJECT = "SUBJECT"
    RELATED = "RELATED"


class EvidenceType(str, Enum):
    REPORT = "REPORT"
    FINDING = "FINDING"
    OCCURRENCE = "OCCURRENCE"
    LIFECYCLE_EVENT = "LIFECYCLE_EVENT"
    RECOMMENDATION = "RECOMMENDATION"
    CAPABILITY_RESULT = "CAPABILITY_RESULT"
    USER_DECISION = "USER_DECISION"


class InvestigationIntent(str, Enum):
    WHY_DANGEROUS = "WHY_DANGEROUS"
    WHAT_CHANGED = "WHAT_CHANGED"
    FIX_FIRST = "FIX_FIRST"
    SECURITY_BRIEFING = "SECURITY_BRIEFING"
    INVESTIGATE_FINDING = "INVESTIGATE_FINDING"
    INVESTIGATE_SERVICE = "INVESTIGATE_SERVICE"


class SubjectType(str, Enum):
    FINDING = "FINDING"
    SERVICE = "SERVICE"
    LISTENER = "LISTENER"
    REPORT = "REPORT"
    INVESTIGATION = "INVESTIGATION"


class CapabilityExecutionStatus(str, Enum):
    PROPOSED = "PROPOSED"
    DENIED = "DENIED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class ReferenceType(str, Enum):
    FINDING = "FINDING"
    ACTION = "ACTION"
    INVESTIGATION = "INVESTIGATION"
    REPORT = "REPORT"


class ReferenceState(str, Enum):
    FOCUSED = "FOCUSED"
    RECENTLY_MENTIONED = "RECENTLY_MENTIONED"


@dataclass(frozen=True)
class InvestigationRecord:
    investigation_id: str
    system_id: str
    status: InvestigationStatus
    title: str
    actor: str
    opened_at: str
    closed_at: str | None
    final_disposition: InvestigationDisposition | None
    provenance: MemoryProvenance = MemoryProvenance.USER_DECISION


@dataclass(frozen=True)
class InvestigationFindingRecord:
    finding_id: str
    relationship: FindingRelationship
    attached_at: str


@dataclass(frozen=True)
class InvestigationEvidenceRecord:
    evidence_id: str
    evidence_type: EvidenceType
    source_record_id: str
    epistemic_role: EpistemicRole
    consulted_at: str
    provenance: MemoryProvenance = MemoryProvenance.DERIVED_HISTORY


@dataclass(frozen=True)
class InvestigationQuestionRecord:
    question_id: str
    intent: InvestigationIntent
    subject_type: SubjectType
    subject_id: str
    recorded_at: str


@dataclass(frozen=True)
class CapabilityExecutionRecord:
    execution_id: str
    system_id: str
    investigation_id: str | None
    capability_id: str
    permission_class: PermissionClass
    status: CapabilityExecutionStatus
    requested_at: str
    authorization_decision_id: str | None
    started_at: str | None
    completed_at: str | None
    parameter_summary: tuple[tuple[str, object], ...]
    result_summary: tuple[tuple[str, object], ...] | None
    error_code: str | None
    provenance: MemoryProvenance = MemoryProvenance.DERIVED_HISTORY


@dataclass(frozen=True)
class ConversationReferenceRecord:
    reference_id: str
    system_id: str
    session_id: str
    reference_type: ReferenceType
    target_id: str
    reference_state: ReferenceState
    created_at: str
    expires_at: str
    provenance: MemoryProvenance = MemoryProvenance.DERIVED_HISTORY


@dataclass(frozen=True)
class InvestigationTimelineEntry:
    occurred_at: str
    entry_type: str
    record_id: str


@dataclass(frozen=True)
class InvestigationTimeline:
    investigation: InvestigationRecord
    entries: tuple[InvestigationTimelineEntry, ...]
