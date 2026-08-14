from dataclasses import replace

from .deterministic import build_deterministic_advisory
from .models import AdvisoryAction, AdvisoryReport, AdvisorContext
from .providers.base import (
    AdvisorProvider,
    ProviderAction,
    ProviderEmphasis,
    ProviderFinding,
    ProviderRequest,
    ProviderSelection,
)


def build_provider_request(
    context: AdvisorContext,
    advisory: AdvisoryReport,
) -> ProviderRequest:
    """Create an allowlisted payload with no raw evidence or remediation prose."""

    findings = tuple(
        ProviderFinding(
            finding_id=finding.finding_id,
            severity=finding.severity,
            kind=finding.kind.value,
            assessment_state=finding.assessment_state.value,
            is_new=finding.is_new,
            is_recurring=finding.is_recurring,
            service_name=finding.application_name,
            process=finding.process,
            port=finding.port,
        )
        for finding in context.findings
    )
    actions = tuple(
        ProviderAction(
            action_id=action.action_id,
            finding_ids=action.finding_ids,
            deterministic_priority=action.priority,
        )
        for action in advisory.actions
    )
    return ProviderRequest(
        findings=findings,
        actions=actions,
        allowed_emphases=tuple(ProviderEmphasis),
    )


def _valid_unique_subset(values: tuple[str, ...], allowed: set[str]) -> bool:
    return (
        isinstance(values, tuple)
        and all(isinstance(value, str) for value in values)
        and len(values) <= len(allowed)
        and len(values) == len(set(values))
        and set(values).issubset(allowed)
    )


def _validate_selection(
    selection: ProviderSelection,
    request: ProviderRequest,
) -> bool:
    if not isinstance(selection, ProviderSelection):
        return False
    if not isinstance(selection.emphasis, ProviderEmphasis):
        return False
    finding_ids = {finding.finding_id for finding in request.findings}
    action_ids = {action.action_id for action in request.actions}
    return _valid_unique_subset(selection.finding_ids, finding_ids) and (
        _valid_unique_subset(selection.action_ids, action_ids)
    )


def _ordered_with_remainder(selected: tuple[str, ...], existing: tuple[str, ...]):
    selected_set = set(selected)
    return (*selected, *(item for item in existing if item not in selected_set))


def _reorder_actions(
    selected_ids: tuple[str, ...],
    actions: tuple[AdvisoryAction, ...],
) -> tuple[AdvisoryAction, ...]:
    actions_by_id = {action.action_id: action for action in actions}
    ordered_ids = _ordered_with_remainder(
        selected_ids,
        tuple(action.action_id for action in actions),
    )
    return tuple(
        replace(actions_by_id[action_id], priority=priority)
        for priority, action_id in enumerate(ordered_ids, start=1)
    )


def generate_advisory(
    context: AdvisorContext,
    provider: AdvisorProvider | None = None,
) -> AdvisoryReport:
    """Generate an advisory and fall back safely on any provider failure."""

    deterministic = build_deterministic_advisory(context)
    if provider is None:
        return deterministic

    request = build_provider_request(context, deterministic)

    try:
        selection = provider.select(request)
    except Exception:
        return replace(
            deterministic,
            provider_warning=(
                "The optional advisor provider failed; deterministic ordering was used."
            ),
        )

    if not _validate_selection(selection, request):
        return replace(
            deterministic,
            provider_warning=(
                "The optional advisor provider returned an invalid selection; "
                "deterministic ordering was used."
            ),
        )

    important_ids = _ordered_with_remainder(
        selection.finding_ids,
        deterministic.important_finding_ids,
    )[:5]
    actions = _reorder_actions(selection.action_ids, deterministic.actions)
    return replace(
        deterministic,
        mode=f"provider:{provider.name}",
        important_finding_ids=tuple(important_ids),
        actions=actions,
        next_steps=tuple(action.action for action in actions[:3]),
    )
