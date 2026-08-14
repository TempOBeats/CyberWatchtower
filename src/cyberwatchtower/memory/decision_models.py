"""Closed contracts for auditable, presentation-only security decisions."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from .errors import MemoryDecisionError
from .provenance import MemoryProvenance
from .sanitization import contains_sensitive_marker


MAX_ACTOR_LENGTH = 128
MAX_RATIONALE_LENGTH = 1024
MAX_SCOPE_VALUE_LENGTH = 256
MAX_BASELINE_ENTRY_LENGTH = 512
MAX_IDENTIFIER_LENGTH = 256
MAX_FINDING_ID_LENGTH = 512
PROHIBITED_DURABLE_TEXT = (
    "argv", "environment variable", "env=", "raw log", "shell command",
    "bash -c", "sh -c", "powershell", "sudo ",
)


class DecisionType(str, Enum):
    ACCEPTED_RISK = "ACCEPTED_RISK"
    REVIEWED = "REVIEWED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    CUSTOM = "CUSTOM"


class DecisionStatus(str, Enum):
    ACTIVE = "ACTIVE"
    SUPERSEDED = "SUPERSEDED"
    REVOKED = "REVOKED"


class ScopeType(str, Enum):
    FINDING = "FINDING"
    LISTENER = "LISTENER"
    SERVICE = "SERVICE"
    APPLICATION = "APPLICATION"
    FIREWALL_STATE = "FIREWALL_STATE"


class ExceptionStatus(str, Enum):
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    SUPERSEDED = "SUPERSEDED"


class BaselineType(str, Enum):
    EXPECTED_SERVICES = "EXPECTED_SERVICES"
    EXPECTED_APPLICATIONS = "EXPECTED_APPLICATIONS"
    EXPECTED_FIREWALL_STATE = "EXPECTED_FIREWALL_STATE"
    APPROVED_LISTENERS = "APPROVED_LISTENERS"
    SYSTEM_POSTURE = "SYSTEM_POSTURE"


class BaselineState(str, Enum):
    DRAFT = "DRAFT"
    APPROVED = "APPROVED"
    SUPERSEDED = "SUPERSEDED"


class ActionResponseType(str, Enum):
    ACKNOWLEDGED = "ACKNOWLEDGED"
    DEFERRED = "DEFERRED"
    DECLINED = "DECLINED"
    COMPLETED = "COMPLETED"


def safe_text(value, name: str, maximum: int, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str):
        raise MemoryDecisionError(f"{name} must be text.")
    normalized = unicodedata.normalize("NFC", value).strip()
    if not normalized or len(normalized) > maximum:
        raise MemoryDecisionError(f"{name} must contain 1-{maximum} characters.")
    if any(unicodedata.category(char) in {"Cc", "Cf"} for char in normalized):
        raise MemoryDecisionError(f"{name} contains prohibited control characters.")
    lowered = normalized.casefold()
    if (contains_sensitive_marker(normalized)
            or any(marker in lowered for marker in PROHIBITED_DURABLE_TEXT)
            or normalized.startswith(("$ ", "> "))):
        raise MemoryDecisionError(f"{name} contains prohibited sensitive or command data.")
    return normalized


def utc_text(value: datetime, name: str) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise MemoryDecisionError(f"{name} must be a timezone-aware datetime.")
    return value.astimezone(timezone.utc).isoformat()


class TypedScope:
    scope_type: ScopeType

    def fields(self) -> dict[str, object]:
        raise NotImplementedError

    def canonical_json(self) -> str:
        return json.dumps(self.fields(), sort_keys=True, separators=(",", ":"))

    def digest(self) -> str:
        return hashlib.sha256(
            f"{self.scope_type.value}\0{self.canonical_json()}".encode()
        ).hexdigest()


@dataclass(frozen=True)
class FindingScope(TypedScope):
    finding_id: str
    scope_type = ScopeType.FINDING

    def __post_init__(self):
        object.__setattr__(self, "finding_id", safe_text(self.finding_id, "finding_id", MAX_FINDING_ID_LENGTH))

    def fields(self):
        return {"finding_id": self.finding_id}


@dataclass(frozen=True)
class ListenerScope(TypedScope):
    protocol: str
    address: str
    exposure: str
    port: int
    application: str
    scope_type = ScopeType.LISTENER

    def __post_init__(self):
        protocol = safe_text(self.protocol, "protocol", 16).casefold()
        if protocol not in {"tcp", "udp"}:
            raise MemoryDecisionError("protocol must be tcp or udp.")
        if isinstance(self.port, bool) or not isinstance(self.port, int) or not 1 <= self.port <= 65535:
            raise MemoryDecisionError("port must be between 1 and 65535.")
        object.__setattr__(self, "protocol", protocol)
        object.__setattr__(self, "address", safe_text(self.address, "address", 128))
        object.__setattr__(self, "exposure", safe_text(self.exposure, "exposure", 64).casefold())
        object.__setattr__(self, "application", safe_text(self.application, "application", MAX_SCOPE_VALUE_LENGTH))

    def fields(self):
        return {"address": self.address, "application": self.application,
                "exposure": self.exposure, "port": self.port, "protocol": self.protocol}


@dataclass(frozen=True)
class ServiceScope(TypedScope):
    service: str
    protocol: str
    port: int
    scope_type = ScopeType.SERVICE

    def __post_init__(self):
        protocol = safe_text(self.protocol, "protocol", 16).casefold()
        if protocol not in {"tcp", "udp"}:
            raise MemoryDecisionError("protocol must be tcp or udp.")
        if isinstance(self.port, bool) or not isinstance(self.port, int) or not 1 <= self.port <= 65535:
            raise MemoryDecisionError("port must be between 1 and 65535.")
        object.__setattr__(self, "service", safe_text(self.service, "service", MAX_SCOPE_VALUE_LENGTH))
        object.__setattr__(self, "protocol", protocol)

    def fields(self):
        return {"port": self.port, "protocol": self.protocol, "service": self.service}


@dataclass(frozen=True)
class ApplicationScope(TypedScope):
    application: str
    scope_type = ScopeType.APPLICATION

    def __post_init__(self):
        object.__setattr__(self, "application", safe_text(self.application, "application", MAX_SCOPE_VALUE_LENGTH))

    def fields(self):
        return {"application": self.application}


@dataclass(frozen=True)
class FirewallStateScope(TypedScope):
    technology: str
    input_policy: str
    scope_type = ScopeType.FIREWALL_STATE

    def __post_init__(self):
        object.__setattr__(self, "technology", safe_text(self.technology, "technology", 64).casefold())
        object.__setattr__(self, "input_policy", safe_text(self.input_policy, "input_policy", 64).upper())

    def fields(self):
        return {"input_policy": self.input_policy, "technology": self.technology}


Scope = FindingScope | ListenerScope | ServiceScope | ApplicationScope | FirewallStateScope


def scope_from_storage(scope_type: str, scope_json: str) -> Scope:
    try:
        data = json.loads(scope_json)
        kind = ScopeType(scope_type)
        constructors = {
            ScopeType.FINDING: FindingScope,
            ScopeType.LISTENER: ListenerScope,
            ScopeType.SERVICE: ServiceScope,
            ScopeType.APPLICATION: ApplicationScope,
            ScopeType.FIREWALL_STATE: FirewallStateScope,
        }
        if not isinstance(data, dict):
            raise TypeError
        return constructors[kind](**data)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise MemoryDecisionError("Stored typed scope is invalid.") from exc


@dataclass(frozen=True)
class DecisionRecord:
    decision_id: str
    system_id: str
    decision_type: DecisionType
    scope: Scope
    actor: str
    rationale: str | None
    effective_at: str
    expires_at: str | None
    status: DecisionStatus
    supersedes_id: str | None
    presentation_only: bool = True
    provenance: MemoryProvenance = MemoryProvenance.USER_DECISION


@dataclass(frozen=True)
class ExceptionRecord:
    exception_id: str
    system_id: str
    scope: Scope
    approver: str
    rationale: str | None
    starts_at: str
    expires_at: str
    status: ExceptionStatus
    supersedes_id: str | None
    presentation_only: bool = True
    provenance: MemoryProvenance = MemoryProvenance.USER_DECISION


@dataclass(frozen=True)
class BaselineEntry:
    key: str
    value: str

    def __post_init__(self):
        object.__setattr__(self, "key", safe_text(self.key, "baseline entry key", 128))
        object.__setattr__(self, "value", safe_text(self.value, "baseline entry value", MAX_BASELINE_ENTRY_LENGTH))


@dataclass(frozen=True)
class BaselineRecord:
    baseline_id: str
    system_id: str
    baseline_type: BaselineType
    version: int
    state: BaselineState
    entries: tuple[BaselineEntry, ...]
    approver: str | None
    approved_at: str | None
    rationale: str | None
    previous_baseline_id: str | None
    provenance: MemoryProvenance = MemoryProvenance.USER_DECISION


@dataclass(frozen=True)
class RecommendationShownRecord:
    recommendation_event_id: str
    system_id: str
    finding_id: str | None
    action_id: str
    trusted_text_hash: str
    shown_at: str
    provenance: MemoryProvenance = MemoryProvenance.DERIVED_HISTORY


@dataclass(frozen=True)
class ActionResponseRecord:
    response_id: str
    system_id: str
    recommendation_event_id: str
    action_id: str
    response_type: ActionResponseType
    actor: str
    rationale: str | None
    recorded_at: str
    defer_until: str | None
    provenance: MemoryProvenance = MemoryProvenance.USER_DECISION
