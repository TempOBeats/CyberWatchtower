"""Deterministic listener reachability derivation from trusted observations."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .platform.models import BindExposure
from .firewall_policy import (
    FirewallRuleApplicability,
    ListenerPolicyAssessment,
)
from .report_contracts import CoverageState


class RemoteReachabilityState(str, Enum):
    NOT_REMOTELY_BOUND = "NOT_REMOTELY_BOUND"
    POTENTIALLY_REACHABLE = "POTENTIALLY_REACHABLE"
    CONFIRMED_REACHABLE = "CONFIRMED_REACHABLE"
    BLOCKED_BY_OBSERVED_POLICY = "BLOCKED_BY_OBSERVED_POLICY"
    UNKNOWN = "UNKNOWN"


class ReachabilityEvidenceBasis(str, Enum):
    SOCKET_LOOPBACK_BIND = "SOCKET_LOOPBACK_BIND"
    SOCKET_INTERFACE_BIND = "SOCKET_INTERFACE_BIND"
    SOCKET_WILDCARD_BIND = "SOCKET_WILDCARD_BIND"
    WINDOWS_RESTRICTIVE_DEFAULT = "WINDOWS_RESTRICTIVE_DEFAULT"
    WINDOWS_PERMISSIVE_DEFAULT = "WINDOWS_PERMISSIVE_DEFAULT"
    WINDOWS_FIREWALL_DISABLED = "WINDOWS_FIREWALL_DISABLED"
    LINUX_INPUT_ACCEPT = "LINUX_INPUT_ACCEPT"
    LINUX_INPUT_DROP = "LINUX_INPUT_DROP"
    FIREWALL_POLICY_UNKNOWN = "FIREWALL_POLICY_UNKNOWN"
    HOST_POLICY_EXPLICIT_BLOCK = "HOST_POLICY_EXPLICIT_BLOCK"
    HOST_POLICY_EXPLICIT_ALLOW = "HOST_POLICY_EXPLICIT_ALLOW"
    HOST_POLICY_DEFAULT_CONTEXT = "HOST_POLICY_DEFAULT_CONTEXT"
    HOST_POLICY_INCOMPLETE = "HOST_POLICY_INCOMPLETE"


@dataclass(frozen=True, slots=True)
class ReachabilityAssessment:
    bind_exposure: BindExposure
    state: RemoteReachabilityState
    evidence_basis: tuple[ReachabilityEvidenceBasis, ...]
    policy_assessment: ListenerPolicyAssessment | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.bind_exposure, BindExposure):
            raise TypeError("bind exposure must use the closed enum")
        if not isinstance(self.state, RemoteReachabilityState):
            raise TypeError("reachability state must use the closed enum")
        if (
            not isinstance(self.evidence_basis, tuple)
            or not self.evidence_basis
            or not all(
                isinstance(item, ReachabilityEvidenceBasis)
                for item in self.evidence_basis
            )
            or len(set(self.evidence_basis)) != len(self.evidence_basis)
        ):
            raise ValueError("reachability evidence must be a unique closed tuple")
        if self.policy_assessment is not None and not isinstance(
            self.policy_assessment, ListenerPolicyAssessment
        ):
            raise TypeError("policy assessment must use the typed contract")

    def to_report_mapping(self) -> dict[str, object]:
        result = {
            "bind_exposure": self.bind_exposure.value,
            "bind_epistemic_role": "OBSERVED_FACT",
            "reachability_state": self.state.value,
            "reachability_epistemic_role": "DETERMINISTIC_DERIVATION",
            "evidence_basis": [item.value for item in self.evidence_basis],
        }
        if self.policy_assessment is not None:
            result["policy_assessment"] = self.policy_assessment.to_report_mapping()
        return result


def assess_listener_reachability(
    exposure: BindExposure,
    policy_basis: tuple[ReachabilityEvidenceBasis, ...] = (),
    policy_assessment: ListenerPolicyAssessment | None = None,
) -> ReachabilityAssessment:
    """Classify reachability without treating a bind or default policy as proof."""

    if not isinstance(exposure, BindExposure):
        raise TypeError("bind exposure must use the closed enum")
    if not isinstance(policy_basis, tuple) or not all(
        isinstance(item, ReachabilityEvidenceBasis) for item in policy_basis
    ):
        raise TypeError("policy basis must use a closed immutable tuple")
    if policy_assessment is not None and not isinstance(
        policy_assessment, ListenerPolicyAssessment
    ):
        raise TypeError("policy assessment must use the typed contract")
    bind_basis = {
        BindExposure.LOOPBACK: ReachabilityEvidenceBasis.SOCKET_LOOPBACK_BIND,
        BindExposure.INTERFACE: ReachabilityEvidenceBasis.SOCKET_INTERFACE_BIND,
        BindExposure.ALL_INTERFACES: ReachabilityEvidenceBasis.SOCKET_WILDCARD_BIND,
    }[exposure]
    basis = tuple(dict.fromkeys((bind_basis, *policy_basis)))
    if exposure == BindExposure.LOOPBACK:
        state = RemoteReachabilityState.NOT_REMOTELY_BOUND
    elif policy_assessment is None:
        state = RemoteReachabilityState.POTENTIALLY_REACHABLE
    elif (
        policy_assessment.applicability
        == FirewallRuleApplicability.MATCHING_BLOCK
        and policy_assessment.applicability_coverage == CoverageState.COMPLETE
    ):
        state = RemoteReachabilityState.BLOCKED_BY_OBSERVED_POLICY
        basis = tuple(dict.fromkeys((
            *basis, ReachabilityEvidenceBasis.HOST_POLICY_EXPLICIT_BLOCK,
        )))
    else:
        state = RemoteReachabilityState.POTENTIALLY_REACHABLE
        policy_evidence = {
            FirewallRuleApplicability.MATCHING_ALLOW:
                ReachabilityEvidenceBasis.HOST_POLICY_EXPLICIT_ALLOW,
            FirewallRuleApplicability.NO_MATCH:
                ReachabilityEvidenceBasis.HOST_POLICY_DEFAULT_CONTEXT,
        }.get(
            policy_assessment.applicability,
            ReachabilityEvidenceBasis.HOST_POLICY_INCOMPLETE,
        )
        basis = tuple(dict.fromkeys((*basis, policy_evidence)))
    return ReachabilityAssessment(exposure, state, basis, policy_assessment)


def reachability_coverage(
    socket_coverage: CoverageState,
    assessments: tuple[ReachabilityAssessment, ...],
) -> CoverageState:
    """Keep enumeration coverage separate from effective reachability coverage."""

    if socket_coverage == CoverageState.UNKNOWN and not assessments:
        return CoverageState.UNKNOWN
    if socket_coverage != CoverageState.COMPLETE:
        return CoverageState.INCOMPLETE
    if all(
        item.state in {
            RemoteReachabilityState.NOT_REMOTELY_BOUND,
            RemoteReachabilityState.BLOCKED_BY_OBSERVED_POLICY,
            RemoteReachabilityState.CONFIRMED_REACHABLE,
        }
        for item in assessments
    ):
        return CoverageState.COMPLETE
    return CoverageState.INCOMPLETE


def reachability_from_report(value: object) -> ReachabilityAssessment | None:
    """Read only explicit new-report metadata; never infer legacy semantics."""

    if value is None:
        return None
    if not isinstance(value, dict) or set(value) not in ({
        "bind_exposure",
        "bind_epistemic_role",
        "reachability_state",
        "reachability_epistemic_role",
        "evidence_basis",
    }, {
        "bind_exposure",
        "bind_epistemic_role",
        "reachability_state",
        "reachability_epistemic_role",
        "evidence_basis",
        "policy_assessment",
    }):
        raise ValueError("network_context has an invalid structure")
    if value["bind_epistemic_role"] != "OBSERVED_FACT" or value[
        "reachability_epistemic_role"
    ] != "DETERMINISTIC_DERIVATION":
        raise ValueError("network_context has invalid epistemic roles")
    raw_basis = value["evidence_basis"]
    if not isinstance(raw_basis, list):
        raise ValueError("network_context evidence_basis must be a list")
    try:
        policy_assessment = None
        if "policy_assessment" in value:
            policy_assessment = policy_assessment_from_report(
                value["policy_assessment"]
            )
        return ReachabilityAssessment(
            BindExposure(value["bind_exposure"]),
            RemoteReachabilityState(value["reachability_state"]),
            tuple(ReachabilityEvidenceBasis(item) for item in raw_basis),
            policy_assessment,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("network_context contains an unknown value") from exc


def policy_assessment_from_report(value: object) -> ListenerPolicyAssessment:
    """Validate the bounded listener-level policy summary used by schema 1.6."""

    from .firewall_policy import (
        FirewallDefaultPolicyContext,
        FirewallConditionMatch,
        FirewallRuleAction,
        FirewallRuleMatch,
        ListenerPolicyBasis,
    )

    expected = {
        "applicability", "default_policy_context", "evidence_basis",
        "matching_rule_digests",
        "rule_collection_coverage", "rule_applicability_coverage",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("policy assessment has an invalid structure")
    digests = value["matching_rule_digests"]
    basis = value["evidence_basis"]
    if not isinstance(digests, list) or not isinstance(basis, list):
        raise ValueError("policy assessment collections must be lists")
    applicability = FirewallRuleApplicability(value["applicability"])
    action = (
        FirewallRuleAction.BLOCK
        if applicability == FirewallRuleApplicability.MATCHING_BLOCK
        else FirewallRuleAction.ALLOW
    )
    matches = tuple(sorted(
        FirewallRuleMatch(
            digest, action, FirewallConditionMatch.MATCH,
            applicability == FirewallRuleApplicability.MATCHING_BLOCK,
        )
        for digest in digests
    ))
    return ListenerPolicyAssessment(
        applicability,
        FirewallDefaultPolicyContext(value["default_policy_context"]),
        matches,
        tuple(ListenerPolicyBasis(item) for item in basis),
        CoverageState(value["rule_collection_coverage"]),
        CoverageState(value["rule_applicability_coverage"]),
    )
