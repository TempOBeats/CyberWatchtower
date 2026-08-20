"""Typed read-only history query and result contracts."""

from dataclasses import dataclass
from datetime import datetime, timedelta

from .errors import MemoryQueryError


MAX_SCORE_TREND_RANGE = timedelta(days=366)


def _required(value: str, name: str) -> None:
    if not isinstance(value, str) or not value:
        raise MemoryQueryError(f"{name} must be a non-empty string.")


@dataclass(frozen=True)
class SystemHistoryQuery:
    system_id: str

    def __post_init__(self):
        _required(self.system_id, "system_id")


@dataclass(frozen=True)
class FindingHistoryQuery(SystemHistoryQuery):
    finding_id: str

    def __post_init__(self):
        super().__post_init__()
        _required(self.finding_id, "finding_id")


@dataclass(frozen=True)
class RecurringFindingsQuery(SystemHistoryQuery):
    active_only: bool = False


@dataclass(frozen=True)
class ScoreTrendQuery(SystemHistoryQuery):
    start_at: datetime
    end_at: datetime
    scoring_version: str | None = None

    def __post_init__(self):
        super().__post_init__()
        if self.start_at.tzinfo is None or self.end_at.tzinfo is None:
            raise MemoryQueryError("Score trend timestamps must be timezone-aware.")
        if self.start_at > self.end_at:
            raise MemoryQueryError("Score trend start_at must not follow end_at.")
        if self.end_at - self.start_at > MAX_SCORE_TREND_RANGE:
            raise MemoryQueryError("Score trend range exceeds 366 days.")
        if self.scoring_version not in (None, "1", "2"):
            raise MemoryQueryError("scoring_version must be '1', '2', or omitted.")


@dataclass(frozen=True)
class FindingLifecycleSummary:
    finding_id: str
    first_seen_at: str
    last_seen_at: str
    occurrence_count: int
    active: bool
    lifecycle_state: str
    recurring: bool
    reopened_count: int
    last_resolved_at: str | None
    latest_title: str
    latest_severity: str
    latest_kind: str
    latest_assessment_state: str
    latest_source: str
    metadata_inferred: bool


@dataclass(frozen=True)
class FindingOccurrence:
    occurrence_id: str
    report_id: str
    observed_at: str
    title: str
    severity: str
    kind: str
    assessment_state: str
    source: str
    metadata_inferred: bool


@dataclass(frozen=True)
class LifecycleEvent:
    event_id: str
    report_id: str
    event_type: str
    occurred_at: str
    previous_value: str | None
    current_value: str | None


@dataclass(frozen=True)
class FindingTimeline:
    summary: FindingLifecycleSummary
    occurrences: tuple[FindingOccurrence, ...]
    events: tuple[LifecycleEvent, ...]

    @property
    def reopened_history(self):
        return tuple(event for event in self.events if event.event_type == "REOPENED")

    @property
    def severity_changes(self):
        return tuple(event for event in self.events if event.event_type == "SEVERITY_CHANGED")

    @property
    def assessment_state_changes(self):
        return tuple(event for event in self.events if event.event_type == "ASSESSMENT_STATE_CHANGED")

    @property
    def kind_changes(self):
        return tuple(event for event in self.events if event.event_type == "KIND_CHANGED")


@dataclass(frozen=True)
class ScorePoint:
    report_id: str
    observed_at: str
    score: int
    risk_level: str
    scoring_version: str


@dataclass(frozen=True)
class VersionedScoreSeries:
    scoring_version: str
    points: tuple[ScorePoint, ...]
    average_score: float
    best_score: int
    worst_score: int
    overall_change: int
    trend: str


@dataclass(frozen=True)
class LatestReportSummary:
    report_id: str
    generated_at: str
    report_schema_version: str
    score: int
    risk_level: str
    finding_count: int
    coverage: tuple[tuple[str, str], ...]
