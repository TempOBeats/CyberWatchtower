"""Execution-grade, non-executing capability authorization contracts."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping

from .decision_models import Scope
from .errors import MemoryAuthorizationError
from .provenance import MemoryProvenance


APPROVAL_REQUIRED_PARAMETER_FIELDS = {
    "scan_host": frozenset({"system_id"}),
    "inspect_process": frozenset({"finding_id", "application"}),
    "inspect_service": frozenset({"protocol", "address", "port", "application"}),
}
MAX_PARAMETER_VALUE_LENGTH = 512


def bounded_identifier(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise MemoryAuthorizationError(f"{name} must be text.")
    normalized = unicodedata.normalize("NFC", value).strip()
    if not normalized or len(normalized) > MAX_PARAMETER_VALUE_LENGTH:
        raise MemoryAuthorizationError(f"{name} is outside the safe bound.")
    if any(unicodedata.category(char) in {"Cc", "Cf"} for char in normalized):
        raise MemoryAuthorizationError(f"{name} contains prohibited characters.")
    return normalized


def canonical_parameter_digest(
    capability_id: str, parameters: Mapping[str, object]
) -> str:
    """Digest an exact, bounded parameter set without persisting raw values."""

    capability_id = bounded_identifier(capability_id, "capability_id")
    allowed = APPROVAL_REQUIRED_PARAMETER_FIELDS.get(capability_id)
    if allowed is None or not isinstance(parameters, Mapping):
        raise MemoryAuthorizationError("Capability parameters are not supported.")
    if set(parameters) != allowed:
        raise MemoryAuthorizationError("Capability parameters must exactly match the contract.")
    normalized: dict[str, object] = {}
    for key in sorted(allowed):
        value = parameters[key]
        if key == "port":
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
                raise MemoryAuthorizationError("port is invalid.")
            normalized[key] = value
        else:
            normalized[key] = bounded_identifier(value, key)
    canonical = json.dumps(
        {"capability_id": capability_id, "parameters": normalized},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def utc_text(value: datetime, name: str) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise MemoryAuthorizationError(f"{name} must be timezone-aware.")
    return value.astimezone(timezone.utc).isoformat()


@dataclass(frozen=True)
class CapabilityAuthorizationEnvelope:
    authorization_id: str
    system_id: str
    capability_id: str
    target_scope: Scope
    parameter_digest: str
    proposal_id: str
    decision_id: str
    actor: str
    issued_at: str
    expires_at: str
    provenance: MemoryProvenance = MemoryProvenance.USER_DECISION


@dataclass(frozen=True)
class CapabilityAuthorizationRequest:
    authorization_id: str
    system_id: str
    capability_id: str
    target_scope: Scope
    parameters: Mapping[str, object]
    proposal_id: str
    execution_at: datetime
