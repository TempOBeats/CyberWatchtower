"""Pure Windows listener-to-firewall-policy integration contracts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from cyberwatchtower.firewall_policy import (
    FirewallDefaultPolicyContext,
    FirewallRuleApplicability,
    ListenerPolicyAssessment,
    ListenerPolicyBasis,
    ListenerPolicySubject,
    evaluate_listener_policy,
    firewall_rule_applicability_coverage,
)
from cyberwatchtower.report_contracts import CoverageState

from ..models import (
    BindExposure,
    CollectionResult,
    FirewallEnablement,
    FirewallInboundAction,
    FirewallInboundPostureObservation,
    FirewallProfile,
    FirewallProfileState,
    ListenerObservation,
)
from .firewall_rule_models import (
    WindowsFirewallPolicyView,
    WindowsFirewallRuleResultCode,
)
from .firewall_rules import WindowsFirewallRuleNormalizationResult


@runtime_checkable
class WindowsFirewallPolicyProviderProtocol(Protocol):
    """Supply normalized policy without exposing transport or native details."""

    def collect_normalized_firewall_policy(
        self,
    ) -> WindowsFirewallRuleNormalizationResult: ...


@runtime_checkable
class WindowsListenerPolicyAdapterProtocol(Protocol):
    """Adapter capability consumed by scanner orchestration without native types."""

    def collect_listener_firewall_policy(
        self,
        listeners: tuple[ListenerObservation, ...],
        socket_coverage: CoverageState,
        posture: CollectionResult[FirewallInboundPostureObservation],
    ) -> "WindowsListenerPolicyIntegrationResult": ...


@dataclass(frozen=True, slots=True)
class ClosedWindowsFirewallPolicyProvider:
    """Return one closed unavailable/failure state without executing collection."""

    state: WindowsFirewallRuleResultCode = WindowsFirewallRuleResultCode.UNSUPPORTED

    def __post_init__(self) -> None:
        if not isinstance(self.state, WindowsFirewallRuleResultCode):
            raise TypeError("closed policy state must use the result enum.")
        if self.state == WindowsFirewallRuleResultCode.COMPLETE:
            raise ValueError("closed provider cannot claim complete collection.")

    def collect_normalized_firewall_policy(
        self,
    ) -> WindowsFirewallRuleNormalizationResult:
        coverage = (
            CoverageState.UNKNOWN
            if self.state in {
                WindowsFirewallRuleResultCode.API_UNAVAILABLE,
                WindowsFirewallRuleResultCode.UNSUPPORTED,
            }
            else CoverageState.INCOMPLETE
        )
        return WindowsFirewallRuleNormalizationResult(
            WindowsFirewallPolicyView.CURRENT_POLICY_VIEW,
            coverage,
            failure=self.state,
        )


def closed_windows_listener_policy(
    listeners: tuple[ListenerObservation, ...],
    socket_coverage: CoverageState,
    posture: CollectionResult[FirewallInboundPostureObservation],
    *,
    unsupported: bool = False,
) -> "WindowsListenerPolicyIntegrationResult":
    """Build aligned inert/failure policy state without exposing collector types."""

    state = (
        WindowsFirewallRuleResultCode.UNSUPPORTED
        if unsupported
        else WindowsFirewallRuleResultCode.INTERNAL_ERROR
    )
    return collect_windows_listener_policy(
        ClosedWindowsFirewallPolicyProvider(state),
        listeners,
        socket_coverage,
        posture,
    )


@dataclass(frozen=True, slots=True)
class WindowsFirewallProfileContext:
    """Trusted active-profile context used by the neutral rule evaluator."""

    profiles: tuple[FirewallProfile, ...]
    default_policy_context: FirewallDefaultPolicyContext
    evaluation_permitted: bool

    def __post_init__(self) -> None:
        if not isinstance(self.profiles, tuple) or not all(
            isinstance(profile, FirewallProfile) for profile in self.profiles
        ) or len(set(self.profiles)) != len(self.profiles):
            raise ValueError("active profiles must be a unique typed tuple.")
        if not isinstance(
            self.default_policy_context, FirewallDefaultPolicyContext
        ):
            raise TypeError("default policy context must use the closed enum.")
        if not isinstance(self.evaluation_permitted, bool):
            raise TypeError("profile evaluation gate must be boolean.")


@dataclass(frozen=True, slots=True)
class WindowsListenerPolicyIntegrationResult:
    """Aligned, domain-safe output from portable Windows policy integration."""

    policy_view: WindowsFirewallPolicyView | None
    collection_coverage: CoverageState
    applicability_coverage: CoverageState
    assessments: tuple[ListenerPolicyAssessment, ...]
    collection_failure: WindowsFirewallRuleResultCode | None = None

    def __post_init__(self) -> None:
        if self.policy_view is not None and not isinstance(
            self.policy_view, WindowsFirewallPolicyView
        ):
            raise TypeError("policy authority must use the closed enum.")
        if not isinstance(self.collection_coverage, CoverageState) or not isinstance(
            self.applicability_coverage, CoverageState
        ):
            raise TypeError("integration coverage must use the closed enum.")
        if not isinstance(self.assessments, tuple) or not all(
            isinstance(value, ListenerPolicyAssessment) for value in self.assessments
        ):
            raise TypeError("policy assessments must use an immutable typed tuple.")
        if self.collection_failure is not None and not isinstance(
            self.collection_failure, WindowsFirewallRuleResultCode
        ):
            raise TypeError("collection failure must use the closed enum.")
        if self.collection_coverage == CoverageState.COMPLETE:
            if self.collection_failure is not None:
                raise ValueError("complete collection cannot carry a failure.")
        elif self.collection_failure is None:
            raise ValueError("non-complete collection requires a closed failure.")


def windows_firewall_profile_context(
    posture: CollectionResult[FirewallInboundPostureObservation],
) -> WindowsFirewallProfileContext:
    """Derive profile context only from a complete, enforcing posture."""

    unknown = WindowsFirewallProfileContext(
        (), FirewallDefaultPolicyContext.UNKNOWN, False
    )
    if not isinstance(posture, CollectionResult):
        raise TypeError("firewall posture must use the typed collection result.")
    if posture.coverage != CoverageState.COMPLETE or len(posture.observations) != 1:
        return unknown
    observation = posture.observations[0]
    if not isinstance(observation, FirewallInboundPostureObservation):
        return unknown
    profiles = observation.profiles
    if not profiles or any(
        profile.state == FirewallProfileState.UNKNOWN for profile in profiles
    ):
        return unknown
    active = tuple(
        profile for profile in profiles
        if profile.state == FirewallProfileState.ACTIVE
    )
    if not active:
        return unknown
    active_profiles = tuple(profile.profile for profile in active)
    if any(
        profile.enablement != FirewallEnablement.ENABLED for profile in active
    ):
        return WindowsFirewallProfileContext(
            active_profiles, FirewallDefaultPolicyContext.UNKNOWN, False
        )
    actions = {profile.default_inbound_action for profile in active}
    if actions == {FirewallInboundAction.ALLOW}:
        default = FirewallDefaultPolicyContext.ALLOW
    elif actions == {FirewallInboundAction.BLOCK}:
        default = FirewallDefaultPolicyContext.BLOCK
    else:
        default = FirewallDefaultPolicyContext.UNKNOWN
    return WindowsFirewallProfileContext(active_profiles, default, True)


def windows_listener_policy_subject(
    listener: ListenerObservation,
    profiles: tuple[FirewallProfile, ...],
) -> ListenerPolicySubject:
    """Project one normalized Windows listener into the frozen policy subject."""

    if not isinstance(listener, ListenerObservation):
        raise TypeError("listener must use the normalized observation type.")
    return ListenerPolicySubject(
        protocol=listener.protocol,
        local_port=listener.port,
        bind_exposure=BindExposure(listener.exposure),
        local_address=listener.address,
        profiles=profiles,
        application_digest=listener.application_digest,
        service_identity=listener.service_identity,
    )


def _closed_assessment(
    collection_coverage: CoverageState,
    default_policy_context: FirewallDefaultPolicyContext,
) -> ListenerPolicyAssessment:
    if collection_coverage == CoverageState.UNKNOWN:
        return ListenerPolicyAssessment(
            FirewallRuleApplicability.UNSUPPORTED,
            default_policy_context,
            (),
            (ListenerPolicyBasis.POLICY_TECHNOLOGY_UNSUPPORTED,),
            CoverageState.UNKNOWN,
            CoverageState.UNKNOWN,
        )
    return ListenerPolicyAssessment(
        FirewallRuleApplicability.INCOMPLETE,
        default_policy_context,
        (),
        (ListenerPolicyBasis.POLICY_EVALUATION_INCOMPLETE,),
        collection_coverage,
        CoverageState.INCOMPLETE,
    )


def _aggregate_applicability_coverage(
    socket_coverage: CoverageState,
    collection_coverage: CoverageState,
    assessments: tuple[ListenerPolicyAssessment, ...],
) -> CoverageState:
    if collection_coverage == CoverageState.UNKNOWN:
        return CoverageState.UNKNOWN
    if collection_coverage != CoverageState.COMPLETE:
        return CoverageState.INCOMPLETE
    if socket_coverage == CoverageState.UNKNOWN:
        return CoverageState.UNKNOWN
    if socket_coverage != CoverageState.COMPLETE:
        return CoverageState.INCOMPLETE
    return firewall_rule_applicability_coverage(
        collection_coverage, assessments
    )


def collect_windows_listener_policy(
    provider: WindowsFirewallPolicyProviderProtocol,
    listeners: tuple[ListenerObservation, ...],
    socket_coverage: CoverageState,
    posture: CollectionResult[FirewallInboundPostureObservation],
) -> WindowsListenerPolicyIntegrationResult:
    """Evaluate an aligned listener tuple through a normalized fakeable provider."""

    if not isinstance(listeners, tuple) or not all(
        isinstance(listener, ListenerObservation) for listener in listeners
    ):
        raise TypeError("listeners must use an immutable normalized tuple.")
    if not isinstance(socket_coverage, CoverageState):
        raise TypeError("socket coverage must use the closed enum.")
    profile_context = windows_firewall_profile_context(posture)
    try:
        policy = provider.collect_normalized_firewall_policy()
    except Exception:
        policy = None
    if not isinstance(policy, WindowsFirewallRuleNormalizationResult) or (
        policy.policy_view != WindowsFirewallPolicyView.CURRENT_POLICY_VIEW
    ):
        coverage = CoverageState.INCOMPLETE
        failure = WindowsFirewallRuleResultCode.INVALID_RESULT
        assessments = tuple(
            _closed_assessment(coverage, profile_context.default_policy_context)
            for _ in listeners
        )
        return WindowsListenerPolicyIntegrationResult(
            None, coverage,
            _aggregate_applicability_coverage(
                socket_coverage, coverage, assessments
            ),
            assessments, failure,
        )

    collection_coverage = policy.coverage
    failure = policy.failure
    if collection_coverage != CoverageState.COMPLETE:
        assessments = tuple(
            _closed_assessment(
                collection_coverage, profile_context.default_policy_context
            )
            for _ in listeners
        )
    elif not profile_context.evaluation_permitted:
        assessments = tuple(
            _closed_assessment(
                CoverageState.COMPLETE,
                profile_context.default_policy_context,
            )
            for _ in listeners
        )
    else:
        assessments = tuple(
            evaluate_listener_policy(
                windows_listener_policy_subject(
                    listener, profile_context.profiles
                ),
                policy.rules,
                CoverageState.COMPLETE,
                profile_context.default_policy_context,
            )
            for listener in listeners
        )
    applicability_coverage = _aggregate_applicability_coverage(
        socket_coverage, collection_coverage, assessments
    )
    return WindowsListenerPolicyIntegrationResult(
        policy.policy_view,
        collection_coverage,
        applicability_coverage,
        assessments,
        failure,
    )
