from dataclasses import dataclass
from enum import Enum
from typing import Protocol


class ProviderEmphasis(str, Enum):
    BALANCED = "BALANCED"
    URGENT_RISKS = "URGENT_RISKS"
    RECENT_CHANGES = "RECENT_CHANGES"
    RECURRING_PROBLEMS = "RECURRING_PROBLEMS"


@dataclass(frozen=True)
class ProviderFinding:
    finding_id: str
    severity: str
    kind: str
    assessment_state: str
    is_new: bool
    is_recurring: bool
    service_name: str | None
    process: str | None
    port: str | None


@dataclass(frozen=True)
class ProviderAction:
    action_id: str
    finding_ids: tuple[str, ...]
    deterministic_priority: int


@dataclass(frozen=True)
class ProviderRequest:
    findings: tuple[ProviderFinding, ...]
    actions: tuple[ProviderAction, ...]
    allowed_emphases: tuple[ProviderEmphasis, ...]


@dataclass(frozen=True)
class ProviderSelection:
    finding_ids: tuple[str, ...]
    action_ids: tuple[str, ...]
    emphasis: ProviderEmphasis = ProviderEmphasis.BALANCED


class AdvisorProvider(Protocol):
    name: str

    def select(self, request: ProviderRequest) -> ProviderSelection:
        """Select known IDs only; providers never return authoritative prose."""
        ...
