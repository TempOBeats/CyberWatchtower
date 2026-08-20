"""Deterministic listener reachability derivation from trusted observations."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .platform.models import BindExposure
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


@dataclass(frozen=True, slots=True)
class ReachabilityAssessment:
    bind_exposure: BindExposure
    state: RemoteReachabilityState
    evidence_basis: tuple[ReachabilityEvidenceBasis, ...]

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

    def to_report_mapping(self) -> dict[str, object]:
        return {
            "bind_exposure": self.bind_exposure.value,
            "bind_epistemic_role": "OBSERVED_FACT",
            "reachability_state": self.state.value,
            "reachability_epistemic_role": "DETERMINISTIC_DERIVATION",
            "evidence_basis": [item.value for item in self.evidence_basis],
        }


def assess_listener_reachability(
    exposure: BindExposure,
    policy_basis: tuple[ReachabilityEvidenceBasis, ...] = (),
) -> ReachabilityAssessment:
    """Classify reachability without treating a bind or default policy as proof."""

    if not isinstance(exposure, BindExposure):
        raise TypeError("bind exposure must use the closed enum")
    if not isinstance(policy_basis, tuple) or not all(
        isinstance(item, ReachabilityEvidenceBasis) for item in policy_basis
    ):
        raise TypeError("policy basis must use a closed immutable tuple")
    bind_basis = {
        BindExposure.LOOPBACK: ReachabilityEvidenceBasis.SOCKET_LOOPBACK_BIND,
        BindExposure.INTERFACE: ReachabilityEvidenceBasis.SOCKET_INTERFACE_BIND,
        BindExposure.ALL_INTERFACES: ReachabilityEvidenceBasis.SOCKET_WILDCARD_BIND,
    }[exposure]
    basis = tuple(dict.fromkeys((bind_basis, *policy_basis)))
    state = (
        RemoteReachabilityState.NOT_REMOTELY_BOUND
        if exposure == BindExposure.LOOPBACK
        else RemoteReachabilityState.POTENTIALLY_REACHABLE
    )
    return ReachabilityAssessment(exposure, state, basis)


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
        item.state == RemoteReachabilityState.NOT_REMOTELY_BOUND
        for item in assessments
    ):
        return CoverageState.COMPLETE
    return CoverageState.INCOMPLETE


def reachability_from_report(value: object) -> ReachabilityAssessment | None:
    """Read only explicit new-report metadata; never infer legacy semantics."""

    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {
        "bind_exposure",
        "bind_epistemic_role",
        "reachability_state",
        "reachability_epistemic_role",
        "evidence_basis",
    }:
        raise ValueError("network_context has an invalid structure")
    if value["bind_epistemic_role"] != "OBSERVED_FACT" or value[
        "reachability_epistemic_role"
    ] != "DETERMINISTIC_DERIVATION":
        raise ValueError("network_context has invalid epistemic roles")
    raw_basis = value["evidence_basis"]
    if not isinstance(raw_basis, list):
        raise ValueError("network_context evidence_basis must be a list")
    try:
        return ReachabilityAssessment(
            BindExposure(value["bind_exposure"]),
            RemoteReachabilityState(value["reachability_state"]),
            tuple(ReachabilityEvidenceBasis(item) for item in raw_basis),
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("network_context contains an unknown value") from exc
