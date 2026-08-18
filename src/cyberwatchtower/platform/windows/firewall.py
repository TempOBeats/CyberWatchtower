"""Normalize Windows Firewall facts without creating security conclusions."""

from __future__ import annotations

from cyberwatchtower.report_contracts import CoverageState

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
    ObservationDomain,
)
from .api import WindowsFirewallApiProtocol
from .errors import WindowsFailureCode
from .models import RawFirewallProfile, WindowsApiResult


WINDOWS_FIREWALL_TECHNOLOGY_ID = "windows-firewall"
_PROFILE_ORDER = {
    FirewallProfile.DOMAIN: 0,
    FirewallProfile.PRIVATE: 1,
    FirewallProfile.PUBLIC: 2,
}
_REQUIRED_PROFILES = frozenset(_PROFILE_ORDER)
_UNAVAILABLE = frozenset({
    WindowsFailureCode.API_UNAVAILABLE,
    WindowsFailureCode.UNSUPPORTED,
})


def _safe_failure(
    failure: WindowsFailureCode | None,
    *,
    unknown_without_data: bool,
) -> tuple[CoverageState, CollectionFailure]:
    if failure in _UNAVAILABLE and unknown_without_data:
        return CoverageState.UNKNOWN, CollectionFailure(
            FailureCategory.UNSUPPORTED,
            FailureCode.COLLECTOR_UNAVAILABLE,
            "Windows Firewall posture is unavailable on this system.",
        )
    if failure == WindowsFailureCode.ACCESS_DENIED:
        return CoverageState.INCOMPLETE, CollectionFailure(
            FailureCategory.PERMISSION_DENIED,
            FailureCode.COLLECTOR_PERMISSION_DENIED,
            "Windows Firewall posture could not be completely read.",
        )
    return CoverageState.INCOMPLETE, CollectionFailure(
        FailureCategory.PARTIAL,
        FailureCode.COLLECTOR_PARTIAL,
        "Windows Firewall posture did not completely validate.",
    )


def _read_profiles(api: WindowsFirewallApiProtocol):
    try:
        result = api.get_firewall_profiles()
    except Exception:
        return WindowsApiResult(failure=WindowsFailureCode.INTERNAL_ERROR)
    if not isinstance(result, WindowsApiResult):
        return WindowsApiResult(failure=WindowsFailureCode.INVALID_RESULT)
    if result.value is not None and (
        not isinstance(result.value, tuple)
        or not result.value
        or not all(isinstance(item, RawFirewallProfile) for item in result.value)
    ):
        return WindowsApiResult(failure=WindowsFailureCode.INVALID_RESULT)
    return result


def collect_windows_firewall_technology(
    api: WindowsFirewallApiProtocol,
) -> CollectionResult[FirewallObservation]:
    """Detect the supported Windows Firewall interface without interpreting risk."""

    result = _read_profiles(api)
    if result.value is not None:
        observation = FirewallObservation(
            (WINDOWS_FIREWALL_TECHNOLOGY_ID,),
            ((WINDOWS_FIREWALL_TECHNOLOGY_ID, None),),
        )
        return CollectionResult(
            ObservationDomain.FIREWALL_TECHNOLOGY,
            CoverageState.COMPLETE,
            (observation,),
        )
    coverage, safe_failure = _safe_failure(
        result.failure, unknown_without_data=True
    )
    return CollectionResult(
        ObservationDomain.FIREWALL_TECHNOLOGY,
        coverage,
        failure=safe_failure,
    )


def collect_windows_firewall_inbound_policy(
    api: WindowsFirewallApiProtocol,
) -> CollectionResult[FirewallInboundPostureObservation]:
    """Collect profile posture through the existing neutral observation contract."""

    result = _read_profiles(api)
    if result.value is None:
        coverage, safe_failure = _safe_failure(
            result.failure, unknown_without_data=True
        )
        return CollectionResult(
            ObservationDomain.FIREWALL_INBOUND_POLICY,
            coverage,
            failure=safe_failure,
        )

    try:
        raw_profiles = result.value
        profiles = tuple(sorted(
            (
                FirewallProfileObservation(
                    item.profile,
                    item.state,
                    item.enablement,
                    item.default_inbound_action,
                    item.block_all_inbound,
                )
                for item in raw_profiles
            ),
            key=lambda item: _PROFILE_ORDER[item.profile],
        ))
        profile_ids = tuple(item.profile for item in profiles)
        if len(set(profile_ids)) != len(profile_ids):
            raise ValueError("duplicate Windows Firewall profile")
        if set(profile_ids) != _REQUIRED_PROFILES:
            raise ValueError("Windows Firewall profile set is incomplete")
        active = tuple(
            item for item in profiles
            if item.state == FirewallProfileState.ACTIVE
        )
        if not active or any(
            item.state == FirewallProfileState.UNKNOWN for item in profiles
        ):
            raise ValueError("active Windows Firewall profiles are unknown")
        posture = FirewallInboundPostureObservation(
            WINDOWS_FIREWALL_TECHNOLOGY_ID,
            profiles,
        )
        active_complete = all(
            item.enablement != FirewallEnablement.UNKNOWN
            and item.default_inbound_action != FirewallInboundAction.UNKNOWN
            for item in active
        )
    except (KeyError, TypeError, ValueError):
        coverage, safe_failure = _safe_failure(
            WindowsFailureCode.INVALID_RESULT,
            unknown_without_data=False,
        )
        return CollectionResult(
            ObservationDomain.FIREWALL_INBOUND_POLICY,
            coverage,
            failure=safe_failure,
        )

    if result.failure is not None or not active_complete:
        coverage, safe_failure = _safe_failure(
            result.failure or WindowsFailureCode.PARTIAL_RESULT,
            unknown_without_data=False,
        )
        return CollectionResult(
            ObservationDomain.FIREWALL_INBOUND_POLICY,
            coverage,
            (posture,),
            safe_failure,
        )
    return CollectionResult(
        ObservationDomain.FIREWALL_INBOUND_POLICY,
        CoverageState.COMPLETE,
        (posture,),
    )
