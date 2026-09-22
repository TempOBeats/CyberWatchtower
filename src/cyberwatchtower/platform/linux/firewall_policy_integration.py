"""Normalized Linux listener policy in the current network namespace only.

This is a passive current-process namespace policy view, not host-global policy
or proof of effective network-path reachability. Native collection, parsing and
ordered policy semantics remain owned by the frozen Linux boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Protocol, runtime_checkable

from cyberwatchtower.firewall_policy import (
    FirewallDefaultPolicyContext,
    FirewallRuleApplicability,
    ListenerPolicyAssessment,
    ListenerPolicyBasis,
    ListenerPolicySubject,
)
from cyberwatchtower.report_contracts import CoverageState

from ..models import ListenerObservation
from .firewall_contracts import (
    LinuxFirewallPolicyAuthority,
    LinuxFirewallPolicySnapshot,
    LinuxNamespaceAlignment,
)
from .firewall_evaluator import evaluate_linux_listener_policy
from .nftables_contracts import NftParseResult, NftParseStatus
from .nftables_native import (
    NftablesNativeResult,
    NftablesNativeStatus,
    collect_nftables_ruleset,
)


class LinuxFirewallPolicyProviderProtocol(Protocol):
    def collect_firewall_policy(self) -> NftablesNativeResult: ...


@runtime_checkable
class LinuxListenerPolicyAdapterProtocol(Protocol):
    def collect_listener_firewall_policy(
        self,
        listeners: tuple[ListenerObservation, ...],
        socket_coverage: CoverageState,
    ) -> LinuxListenerPolicyIntegrationResult: ...


class NativeLinuxFirewallPolicyProvider:
    """Delegate solely to the fixed public native collector."""

    def collect_firewall_policy(self) -> NftablesNativeResult:
        return collect_nftables_ruleset()


@dataclass(frozen=True, slots=True)
class ClosedLinuxFirewallPolicyProvider:
    """Explicit inert provider for unavailable capabilities and portable fixtures."""

    status: NftablesNativeStatus = NftablesNativeStatus.UNAVAILABLE

    def __post_init__(self) -> None:
        if self.status not in {
            NftablesNativeStatus.UNAVAILABLE, NftablesNativeStatus.INTERNAL_ERROR,
        } or not isinstance(self.status, NftablesNativeStatus):
            raise ValueError("closed provider requires an unavailable/internal status")

    def collect_firewall_policy(self) -> NftablesNativeResult:
        return NftablesNativeResult(self.status)


@dataclass(frozen=True, slots=True)
class LinuxListenerPolicyBinding:
    """Keep one frozen L2 assessment attached to its evaluated subject."""

    subject: ListenerPolicySubject | None
    assessment: ListenerPolicyAssessment

    def __post_init__(self) -> None:
        if self.subject is not None and not isinstance(self.subject, ListenerPolicySubject):
            raise TypeError("binding subject must use the normalized contract")
        if not isinstance(self.assessment, ListenerPolicyAssessment):
            raise TypeError("binding assessment must use the frozen L2 contract")
        self.assessment.__post_init__()


@dataclass(frozen=True, slots=True)
class LinuxListenerPolicyIntegrationResult:
    """Carry ordered subject/assessment bindings across the scanner seam."""

    collection_coverage: CoverageState
    applicability_coverage: CoverageState
    bindings: tuple[LinuxListenerPolicyBinding, ...]
    native_status: NftablesNativeStatus
    parser_status: NftParseStatus | None = None
    authority: LinuxFirewallPolicyAuthority | None = None
    namespace_alignment: LinuxNamespaceAlignment = LinuxNamespaceAlignment.UNKNOWN
    _snapshot: LinuxFirewallPolicySnapshot | None = field(
        default=None, repr=False, compare=False,
    )

    def __post_init__(self) -> None:
        for value in (self.collection_coverage, self.applicability_coverage):
            if not isinstance(value, CoverageState):
                raise TypeError("coverage must use the closed enum")
        if not isinstance(self.native_status, NftablesNativeStatus) or (
            self.parser_status is not None and not isinstance(self.parser_status, NftParseStatus)
        ):
            raise TypeError("collection status must use closed enums")
        if not isinstance(self.namespace_alignment, LinuxNamespaceAlignment) or (
            self.authority is not None and not isinstance(self.authority, LinuxFirewallPolicyAuthority)
        ):
            raise TypeError("authority must use closed enums")
        if self._snapshot is not None and not isinstance(
            self._snapshot, LinuxFirewallPolicySnapshot
        ):
            raise TypeError("policy snapshot must use the frozen Linux contract")
        if not isinstance(self.bindings, tuple) or not all(
            isinstance(value, LinuxListenerPolicyBinding) for value in self.bindings
        ):
            raise TypeError("listener bindings must be an immutable typed tuple")
        for binding in self.bindings:
            binding.__post_init__()
        if self.collection_coverage == CoverageState.COMPLETE and (
            self.native_status != NftablesNativeStatus.COLLECTED
            or self.parser_status != NftParseStatus.SUCCESS
            or self.authority != LinuxFirewallPolicyAuthority.CURRENT_NETWORK_NAMESPACE_POLICY_VIEW
            or self._snapshot is None
        ):
            raise ValueError("complete collection requires successful trusted parsing")
        if self._snapshot is not None:
            self._snapshot.__post_init__()
            if (
                self.collection_coverage != CoverageState.COMPLETE
                or self._snapshot.authority != self.authority
                or self._snapshot.namespace_alignment != self.namespace_alignment
            ):
                raise ValueError("policy snapshot context is inconsistent")
        if self.collection_coverage == CoverageState.UNKNOWN and (
            self.native_status != NftablesNativeStatus.UNAVAILABLE
        ):
            raise ValueError("only genuine absence has unknown collection")
        if any(
            binding.assessment.collection_coverage != self.collection_coverage
            for binding in self.bindings
        ):
            raise ValueError("assessment collection coverage must agree")
        if self.applicability_coverage == CoverageState.COMPLETE and (
            not self.uses_nft_policy
            or self.namespace_alignment != LinuxNamespaceAlignment.SAME_CURRENT_NAMESPACE
            or any(binding.subject is None for binding in self.bindings)
            or any(
                binding.assessment.applicability_coverage != CoverageState.COMPLETE
                for binding in self.bindings
            )
        ):
            raise ValueError("complete applicability requires aligned complete assessments")

    @property
    def subjects(self) -> tuple[ListenerPolicySubject | None, ...]:
        return tuple(binding.subject for binding in self.bindings)

    @property
    def assessments(self) -> tuple[ListenerPolicyAssessment, ...]:
        return tuple(binding.assessment for binding in self.bindings)

    @property
    def uses_nft_policy(self) -> bool:
        """Select the structured backend independently of per-listener applicability."""
        return self.collection_coverage == CoverageState.COMPLETE


def linux_listener_policy_subject(listener: ListenerObservation) -> ListenerPolicySubject:
    """Do not derive firewall identities from process titles or command lines."""
    return ListenerPolicySubject(
        protocol=listener.protocol,
        local_port=listener.port,
        bind_exposure=listener.exposure,
        local_address=listener.address,
        profiles=(),
        application_digest=listener.application_digest,
        # The existing service identity contract is Windows-specific. Linux
        # listeners do not currently establish service or ingress identities.
    )


def _subjects(listeners: tuple[ListenerObservation, ...]) -> tuple[ListenerPolicySubject | None, ...]:
    subjects = []
    for listener in listeners:
        try:
            subjects.append(linux_listener_policy_subject(listener))
        except (TypeError, ValueError):
            subjects.append(None)
    return tuple(subjects)


def _closed_assessment(coverage: CoverageState) -> ListenerPolicyAssessment:
    unavailable = coverage == CoverageState.UNKNOWN
    return ListenerPolicyAssessment(
        FirewallRuleApplicability.UNSUPPORTED if unavailable else FirewallRuleApplicability.INCOMPLETE,
        FirewallDefaultPolicyContext.UNKNOWN,
        (),
        (ListenerPolicyBasis.POLICY_TECHNOLOGY_UNSUPPORTED if unavailable
         else ListenerPolicyBasis.POLICY_EVALUATION_INCOMPLETE,),
        coverage,
        CoverageState.UNKNOWN if unavailable else CoverageState.INCOMPLETE,
    )


def closed_linux_listener_policy(
    listeners: tuple[ListenerObservation, ...], *, unavailable: bool = False,
) -> LinuxListenerPolicyIntegrationResult:
    coverage = CoverageState.UNKNOWN if unavailable else CoverageState.INCOMPLETE
    subjects = _subjects(listeners)
    return LinuxListenerPolicyIntegrationResult(
        coverage, coverage,
        tuple(
            LinuxListenerPolicyBinding(subject, _closed_assessment(coverage))
            for subject in subjects
        ),
        NftablesNativeStatus.UNAVAILABLE if unavailable else NftablesNativeStatus.INTERNAL_ERROR,
    )


def _closed_applicability(
    value: LinuxListenerPolicyIntegrationResult,
    listeners: tuple[ListenerObservation, ...],
) -> LinuxListenerPolicyIntegrationResult:
    """Preserve trusted collection while discarding unproven applicability."""
    subjects = _subjects(listeners)
    return LinuxListenerPolicyIntegrationResult(
        value.collection_coverage,
        CoverageState.INCOMPLETE,
        tuple(
            LinuxListenerPolicyBinding(
                subject, _closed_assessment(value.collection_coverage),
            )
            for subject in subjects
        ),
        value.native_status,
        value.parser_status,
        value.authority,
        value.namespace_alignment,
        value._snapshot,
    )


def _applicability(
    collection: CoverageState,
    alignment: LinuxNamespaceAlignment,
    socket_coverage: CoverageState,
    bindings: tuple[LinuxListenerPolicyBinding, ...],
) -> CoverageState:
    if collection == CoverageState.UNKNOWN:
        return CoverageState.UNKNOWN
    if collection != CoverageState.COMPLETE or socket_coverage != CoverageState.COMPLETE \
            or alignment != LinuxNamespaceAlignment.SAME_CURRENT_NAMESPACE \
            or any(binding.subject is None for binding in bindings) \
            or any(
                binding.assessment.applicability_coverage != CoverageState.COMPLETE
                for binding in bindings
            ):
        return CoverageState.INCOMPLETE
    return CoverageState.COMPLETE


def collect_linux_listener_policy(
    provider: LinuxFirewallPolicyProviderProtocol,
    listeners: tuple[ListenerObservation, ...],
    socket_coverage: CoverageState,
) -> LinuxListenerPolicyIntegrationResult:
    """Collect once, inspect both success layers, then invoke the frozen evaluator."""
    if not isinstance(listeners, tuple) or not all(isinstance(value, ListenerObservation) for value in listeners):
        raise TypeError("listeners must use a normalized immutable tuple")
    if not isinstance(socket_coverage, CoverageState):
        raise TypeError("socket coverage must use the closed enum")
    try:
        native = provider.collect_firewall_policy()
        if not isinstance(native, NftablesNativeResult):
            raise ValueError("invalid provider result")
        native.__post_init__()
        subjects = _subjects(listeners)
        parser_status = None
        authority = None
        alignment = LinuxNamespaceAlignment.UNKNOWN
        snapshot = None
        collection = (CoverageState.UNKNOWN if native.status == NftablesNativeStatus.UNAVAILABLE
                      else CoverageState.INCOMPLETE)
        if native.status == NftablesNativeStatus.COLLECTED:
            parsed = native.parse_result
            if not isinstance(parsed, NftParseResult):
                raise ValueError("missing parser result")
            parsed.__post_init__()
            parser_status = parsed.status
            if parsed.status == NftParseStatus.SUCCESS:
                snapshot = parsed.snapshot
                if not isinstance(snapshot, LinuxFirewallPolicySnapshot):
                    raise ValueError("missing normalized snapshot")
                snapshot.__post_init__()
                if snapshot.authority != LinuxFirewallPolicyAuthority.CURRENT_NETWORK_NAMESPACE_POLICY_VIEW:
                    raise ValueError("inconsistent policy authority")
                authority = snapshot.authority
                alignment = snapshot.namespace_alignment
                collection = CoverageState.COMPLETE
    except Exception:
        return closed_linux_listener_policy(listeners)

    bindings = []
    for subject in subjects:
        assessment = _closed_assessment(collection)
        if collection == CoverageState.COMPLETE and subject is not None:
            try:
                evaluated = evaluate_linux_listener_policy(subject, snapshot)
                if not isinstance(evaluated, ListenerPolicyAssessment):
                    raise TypeError("invalid evaluator result")
                evaluated.__post_init__()
                assessment = evaluated
            except Exception:
                pass
        bindings.append(LinuxListenerPolicyBinding(subject, assessment))
    bindings = tuple(bindings)
    return LinuxListenerPolicyIntegrationResult(
        collection, _applicability(collection, alignment, socket_coverage, bindings),
        bindings, native.status, parser_status, authority, alignment, snapshot,
    )


def normalize_linux_listener_policy(
    value: object,
    listeners: tuple[ListenerObservation, ...],
    socket_coverage: CoverageState,
) -> LinuxListenerPolicyIntegrationResult:
    """Validate adapter output at the scanner seam, including listener order."""
    if not isinstance(value, LinuxListenerPolicyIntegrationResult):
        return closed_linux_listener_policy(listeners)
    trusted_collection = False
    try:
        if value.collection_coverage == CoverageState.COMPLETE:
            if not isinstance(value._snapshot, LinuxFirewallPolicySnapshot):
                raise ValueError("complete collection lost its policy snapshot")
            value._snapshot.__post_init__()
            if (
                value.native_status != NftablesNativeStatus.COLLECTED
                or value.parser_status != NftParseStatus.SUCCESS
                or value.authority
                != LinuxFirewallPolicyAuthority.CURRENT_NETWORK_NAMESPACE_POLICY_VIEW
                or value._snapshot.authority != value.authority
                or value._snapshot.namespace_alignment != value.namespace_alignment
            ):
                raise ValueError("complete collection context is inconsistent")
            trusted_collection = True
        value.__post_init__()
        expected_subjects = _subjects(listeners)
        if len(value.bindings) != len(expected_subjects) or value.subjects != expected_subjects:
            raise ValueError("policy subjects are not aligned with listeners")
        if trusted_collection:
            expected_assessments = []
            for subject in expected_subjects:
                if subject is None:
                    raise ValueError("listener subject could not be normalized")
                assessment = evaluate_linux_listener_policy(subject, value._snapshot)
                if not isinstance(assessment, ListenerPolicyAssessment):
                    raise TypeError("invalid evaluator result")
                assessment.__post_init__()
                expected_assessments.append(assessment)
            if value.assessments != tuple(expected_assessments):
                raise ValueError("listener assessments lack semantic provenance")
        return replace(value, applicability_coverage=_applicability(
            value.collection_coverage, value.namespace_alignment, socket_coverage,
            value.bindings,
        ))
    except Exception:
        if trusted_collection:
            return _closed_applicability(value, listeners)
        return closed_linux_listener_policy(listeners)
