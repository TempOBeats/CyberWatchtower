from dataclasses import dataclass

from cyberwatchtower.models import AssessmentState, FindingKind
from cyberwatchtower.score_explanation import ScoreExplanation


@dataclass(frozen=True)
class AdvisoryFinding:
    finding_id: str
    title: str
    description: str
    severity: str
    recommendation: str
    confidence: int
    source: str
    kind: FindingKind
    assessment_state: AssessmentState
    evidence: tuple[str, ...]
    protocol: str | None = None
    address: str | None = None
    port: str | None = None
    process: str | None = None
    application: str | None = None
    application_name: str | None = None
    exposure: str | None = None
    is_new: bool = False
    occurrences: int = 0
    metadata_inferred: bool = False
    bind_exposure: str | None = None
    reachability_state: str | None = None
    reachability_basis: tuple[str, ...] = ()
    presentation_group_id: str | None = None

    @property
    def is_recurring(self) -> bool:
        return self.occurrences > 1


@dataclass(frozen=True)
class ChangeFinding:
    finding_id: str
    title: str
    severity: str


@dataclass(frozen=True)
class AdvisorContext:
    schema_version: str
    score: int
    risk_level: str
    severity_counts: tuple[tuple[str, int], ...]
    findings: tuple[AdvisoryFinding, ...]
    previous_score: int | None
    score_change: int | None
    trend: str
    new_findings: tuple[ChangeFinding, ...]
    resolved_findings: tuple[ChangeFinding, ...]
    total_scans: int
    average_score: float
    overall_trend: str
    assessment_assurance: str = "INCOMPLETE"
    coverage_limitations: tuple[str, ...] = ()
    uncertain_findings: tuple[ChangeFinding, ...] = ()
    score_explanation: ScoreExplanation | None = None
    previous_scoring_version: str | None = None
    current_scoring_version: str | None = None


@dataclass(frozen=True)
class AdvisoryAction:
    action_id: str
    priority: int
    finding_ids: tuple[str, ...]
    action: str
    rationale: str
    assessment_state: AssessmentState
    is_new: bool
    is_recurring: bool


@dataclass(frozen=True)
class AdvisoryFindingGroup:
    group_id: str
    finding_ids: tuple[str, ...]
    title: str
    severity: str
    assessment_state: AssessmentState


@dataclass(frozen=True)
class AdvisoryReport:
    mode: str
    posture_summary: str
    important_finding_ids: tuple[str, ...]
    actions: tuple[AdvisoryAction, ...]
    changes_summary: str
    recurring_summary: str
    next_steps: tuple[str, ...]
    coverage_warnings: tuple[str, ...]
    finding_groups: tuple[AdvisoryFindingGroup, ...]
    provider_warning: str | None = None
