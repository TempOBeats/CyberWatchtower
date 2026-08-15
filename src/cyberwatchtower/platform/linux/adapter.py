"""Linux adapter wrapping CyberWatchtower's existing fixed-purpose collectors."""

from __future__ import annotations

from collections.abc import Callable, Mapping

from cyberwatchtower.firewall import check_firewall, inspect_iptables
from cyberwatchtower.network import (
    SocketCompletenessCode,
    enrich_process_intelligence,
    inspect_listening_services,
    parse_listening_services_checked,
)
from cyberwatchtower.report_contracts import CoverageState
from cyberwatchtower.system import collect_system_information

from ..models import (
    CollectionFailure,
    CollectionResult,
    FailureCategory,
    FailureCode,
    FirewallEnablement,
    FirewallInboundAction,
    FirewallInboundPostureObservation,
    FirewallObservation,
    FirewallProfile,
    FirewallProfileObservation,
    FirewallProfileState,
    ListenerObservation,
    ObservationDomain,
    SystemObservation,
)
from .models import FirewallPolicyObservation


_SOCKET_CODES = {
    SocketCompletenessCode.COMMAND_UNAVAILABLE.value: (
        FailureCategory.UNAVAILABLE, FailureCode.SOCKET_COMMAND_UNAVAILABLE,
    ),
    SocketCompletenessCode.COMMAND_TIMEOUT.value: (
        FailureCategory.INTERNAL, FailureCode.SOCKET_COMMAND_TIMEOUT,
    ),
    SocketCompletenessCode.COMMAND_FAILED.value: (
        FailureCategory.INTERNAL, FailureCode.SOCKET_COMMAND_FAILED,
    ),
    SocketCompletenessCode.OUTPUT_MALFORMED.value: (
        FailureCategory.MALFORMED_OUTPUT, FailureCode.SOCKET_OUTPUT_MALFORMED,
    ),
}

_SOCKET_MESSAGES = {
    FailureCode.SOCKET_COMMAND_UNAVAILABLE: "The ss utility could not be found.",
    FailureCode.SOCKET_COMMAND_FAILED: (
        "CyberWatchtower could not completely inspect listening services."
    ),
    FailureCode.SOCKET_COMMAND_TIMEOUT: (
        "CyberWatchtower could not completely inspect listening services."
    ),
}


def _internal_failure(domain: ObservationDomain, message: str):
    return CollectionResult(
        domain,
        CoverageState.INCOMPLETE,
        failure=CollectionFailure(
            FailureCategory.INTERNAL,
            FailureCode.COLLECTOR_INTERNAL_FAILURE,
            message,
        ),
    )


class LinuxPlatformAdapter:
    """Normalize existing Linux collection without making security conclusions."""

    platform_name = "linux"

    def __init__(
        self,
        *,
        system_collector: Callable[[], Mapping[str, object]] = collect_system_information,
        firewall_collector: Callable[[], Mapping[str, object]] = check_firewall,
        network_collector: Callable[[], Mapping[str, object]] = inspect_listening_services,
        firewall_policy_collector: Callable[[], Mapping[str, object]] = inspect_iptables,
        process_enricher: Callable[[list[dict]], list[dict]] = enrich_process_intelligence,
    ) -> None:
        self._system_collector = system_collector
        self._firewall_collector = firewall_collector
        self._network_collector = network_collector
        self._firewall_policy_collector = firewall_policy_collector
        self._process_enricher = process_enricher

    def collect_system(self) -> CollectionResult[SystemObservation]:
        try:
            observation = SystemObservation.from_mapping(self._system_collector())
        except Exception:
            return _internal_failure(
                ObservationDomain.SYSTEM_INFORMATION,
                "Linux system information collection failed.",
            )
        return CollectionResult(
            ObservationDomain.SYSTEM_INFORMATION,
            CoverageState.COMPLETE,
            (observation,),
        )

    def collect_firewall(self) -> CollectionResult[FirewallObservation]:
        try:
            observation = FirewallObservation.from_mapping(self._firewall_collector())
        except Exception:
            return _internal_failure(
                ObservationDomain.FIREWALL_TECHNOLOGY,
                "Linux firewall technology collection failed.",
            )
        return CollectionResult(
            ObservationDomain.FIREWALL_TECHNOLOGY,
            CoverageState.COMPLETE,
            (observation,),
        )

    def collect_network(self) -> CollectionResult[ListenerObservation]:
        try:
            raw = self._network_collector()
        except Exception:
            return _internal_failure(
                ObservationDomain.NETWORK_LISTENERS,
                "Linux listening-service collection failed.",
            )
        if not isinstance(raw, Mapping):
            return _internal_failure(
                ObservationDomain.NETWORK_LISTENERS,
                "Linux listening-service collection returned invalid data.",
            )
        if not raw.get("accessible"):
            raw_code = str(raw.get("failure_code", "SOCKET_COMMAND_FAILED"))
            category, code = _SOCKET_CODES.get(
                raw_code,
                (FailureCategory.INTERNAL, FailureCode.SOCKET_COMMAND_FAILED),
            )
            return CollectionResult(
                ObservationDomain.NETWORK_LISTENERS,
                CoverageState.INCOMPLETE,
                failure=CollectionFailure(
                    category,
                    code,
                    _SOCKET_MESSAGES[code],
                ),
            )
        parsed = parse_listening_services_checked(raw.get("raw_output", ""))
        try:
            enriched = self._process_enricher(list(parsed.services))
            observations = tuple(
                ListenerObservation.from_mapping(item) for item in enriched
            )
        except Exception:
            return _internal_failure(
                ObservationDomain.NETWORK_LISTENERS,
                "Linux listening-service normalization failed.",
            )
        if parsed.complete:
            return CollectionResult(
                ObservationDomain.NETWORK_LISTENERS,
                CoverageState.COMPLETE,
                observations,
            )
        return CollectionResult(
            ObservationDomain.NETWORK_LISTENERS,
            CoverageState.INCOMPLETE,
            observations,
            CollectionFailure(
                FailureCategory.MALFORMED_OUTPUT,
                FailureCode.SOCKET_OUTPUT_MALFORMED,
                parsed.message,
            ),
        )

    def collect_firewall_policy(self) -> CollectionResult[FirewallPolicyObservation]:
        try:
            raw = self._firewall_policy_collector()
            if not isinstance(raw, Mapping):
                raise TypeError("firewall policy collection must be a mapping")
            available = raw.get("available", False)
            accessible = raw.get("accessible", False)
            safe_message = None
            if isinstance(available, bool) and isinstance(accessible, bool) and not accessible:
                safe_message = (
                    "iptables exists, but CyberWatchtower could not read the rules."
                    if available else "iptables is not installed."
                )
            observation = FirewallPolicyObservation.from_mapping({
                "available": available,
                "accessible": accessible,
                "policies": raw.get("policies", {}),
                "message": safe_message,
            })
        except Exception:
            return _internal_failure(
                ObservationDomain.FIREWALL_INPUT_POLICY,
                "Linux firewall policy collection failed.",
            )
        if not observation.accessible:
            if observation.available:
                category = FailureCategory.PERMISSION_DENIED
                code = FailureCode.IPTABLES_PERMISSION_DENIED
                message = (
                    "iptables exists, but CyberWatchtower could not read the rules."
                )
            else:
                category = FailureCategory.UNAVAILABLE
                code = FailureCode.COLLECTOR_UNAVAILABLE
                message = "iptables is not installed."
            return CollectionResult(
                ObservationDomain.FIREWALL_INPUT_POLICY,
                CoverageState.INCOMPLETE,
                (observation,),
                CollectionFailure(
                    category,
                    code,
                    message,
                ),
            )
        input_policy = dict(observation.policies).get("INPUT")
        if input_policy not in {"ACCEPT", "DROP"}:
            return CollectionResult(
                ObservationDomain.FIREWALL_INPUT_POLICY,
                CoverageState.INCOMPLETE,
                (observation,),
                CollectionFailure(
                    FailureCategory.PARTIAL,
                    FailureCode.IPTABLES_POLICY_INCOMPLETE,
                    "Linux firewall INPUT policy could not be determined.",
                ),
            )
        return CollectionResult(
            ObservationDomain.FIREWALL_INPUT_POLICY,
            CoverageState.COMPLETE,
            (observation,),
        )

    def collect_firewall_inbound_policy(
        self,
    ) -> CollectionResult[FirewallInboundPostureObservation]:
        """Translate legacy iptables input state into the neutral posture contract.

        The deterministic Linux scanner intentionally continues consuming the
        legacy policy observation in v0.4 Phase 0 to preserve exact findings and
        evidence. This method establishes the future cross-platform collection
        seam without changing that authoritative path.
        """

        legacy = self.collect_firewall_policy()
        observations: tuple[FirewallInboundPostureObservation, ...] = ()
        if legacy.observations:
            policy = dict(legacy.observations[0].policies).get("INPUT")
            inbound_action = {
                "ACCEPT": FirewallInboundAction.ALLOW,
                "DROP": FirewallInboundAction.BLOCK,
            }.get(policy, FirewallInboundAction.UNKNOWN)
            profile = FirewallProfileObservation(
                FirewallProfile.DEFAULT,
                (
                    FirewallProfileState.ACTIVE
                    if legacy.observations[0].accessible
                    else FirewallProfileState.UNKNOWN
                ),
                FirewallEnablement.UNKNOWN,
                inbound_action,
            )
            observations = (
                FirewallInboundPostureObservation("iptables", (profile,)),
            )
        return CollectionResult(
            ObservationDomain.FIREWALL_INBOUND_POLICY,
            legacy.coverage,
            observations,
            legacy.failure,
        )
