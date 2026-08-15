"""Normalize Windows endpoint facts without creating security conclusions."""

from __future__ import annotations

from ipaddress import ip_address

from cyberwatchtower.report_contracts import CoverageState

from ..models import (
    CollectionFailure,
    CollectionResult,
    FailureCategory,
    FailureCode,
    ListenerExposure,
    ListenerObservation,
    NetworkProtocol,
    ObservationDomain,
)
from .api import WindowsNetworkApiProtocol
from .errors import WindowsFailureCode
from .models import RawServiceInfo, WindowsServiceState


_UNKNOWN_FAILURES = frozenset({
    WindowsFailureCode.API_UNAVAILABLE,
    WindowsFailureCode.UNSUPPORTED,
})


def _exposure(address: str) -> ListenerExposure:
    parsed = ip_address(address)
    if parsed.is_unspecified:
        return ListenerExposure.ALL_INTERFACES
    if parsed.is_loopback:
        return ListenerExposure.LOOPBACK
    return ListenerExposure.INTERFACE


def _services_by_pid(
    services: tuple[RawServiceInfo, ...],
) -> dict[int, tuple[RawServiceInfo, ...]]:
    grouped: dict[int, list[RawServiceInfo]] = {}
    for service in services:
        if service.state == WindowsServiceState.RUNNING:
            grouped.setdefault(service.pid, []).append(service)
    return {
        pid: tuple(sorted(items, key=lambda item: item.service_name.casefold()))
        for pid, items in grouped.items()
    }


def _failure(
    codes: tuple[WindowsFailureCode, ...],
    *,
    has_observations: bool,
) -> tuple[CoverageState, CollectionFailure]:
    if codes and all(code in _UNKNOWN_FAILURES for code in codes) and not has_observations:
        return CoverageState.UNKNOWN, CollectionFailure(
            FailureCategory.UNSUPPORTED,
            FailureCode.COLLECTOR_UNAVAILABLE,
            "Windows endpoint collection is unavailable on this system.",
        )
    if WindowsFailureCode.ACCESS_DENIED in codes:
        category = FailureCategory.PERMISSION_DENIED
        code = FailureCode.COLLECTOR_PERMISSION_DENIED
    else:
        category = FailureCategory.PARTIAL
        code = FailureCode.COLLECTOR_PARTIAL
    return CoverageState.INCOMPLETE, CollectionFailure(
        category,
        code,
        "Windows endpoint collection did not completely validate all required tables.",
    )


def collect_windows_network(
    api: WindowsNetworkApiProtocol,
) -> CollectionResult[ListenerObservation]:
    """Collect all endpoint tables and add best-effort process/service context."""

    try:
        tcp_result = api.get_tcp_endpoints()
        udp_result = api.get_udp_endpoints()
        raw_endpoints = tuple(
            (NetworkProtocol.TCP, item) for item in (tcp_result.value or ())
        ) + tuple(
            (NetworkProtocol.UDP, item) for item in (udp_result.value or ())
        )
        keys = tuple(
            (protocol.value, item.family.value, item.address, item.port, item.pid)
            for protocol, item in raw_endpoints
        )
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate Windows endpoint")

        try:
            service_result = api.list_services()
            services = _services_by_pid(service_result.value or ())
        except Exception:
            services = {}
        observations = []
        for protocol, endpoint in raw_endpoints:
            process_name = "unknown"
            try:
                process_result = api.get_process_image(endpoint.pid)
                if (
                    process_result.succeeded
                    and process_result.value is not None
                    and process_result.value.pid == endpoint.pid
                ):
                    process_name = process_result.value.image_name
            except Exception:
                pass

            values: dict[str, object] = {
                "protocol": protocol.value,
                "state": "LISTEN" if protocol == NetworkProtocol.TCP else "UNCONN",
                "address": endpoint.address,
                "port": endpoint.port,
                "exposure": _exposure(endpoint.address).value,
                "process": process_name,
                "pid": endpoint.pid,
            }
            matching_services = services.get(endpoint.pid, ())
            if len(matching_services) == 1:
                service = matching_services[0]
                values.update({
                    "application": (
                        f"windows-service:{service.service_name.casefold()}"
                    ),
                    "application_name": service.display_name,
                    "known_application": False,
                })
            observations.append(ListenerObservation.from_mapping(values))

        ordered = tuple(sorted(
            observations,
            key=lambda item: (
                item.protocol.value, item.address, item.port, item.pid or 0,
                item.process.casefold(), item.application or "",
            ),
        ))
    except Exception:
        return CollectionResult(
            ObservationDomain.NETWORK_LISTENERS,
            CoverageState.INCOMPLETE,
            failure=CollectionFailure(
                FailureCategory.PARTIAL,
                FailureCode.COLLECTOR_PARTIAL,
                "Windows endpoint data could not be normalized safely.",
            ),
        )

    failures = tuple(
        code for code in (tcp_result.failure, udp_result.failure) if code is not None
    )
    if failures:
        coverage, failure = _failure(failures, has_observations=bool(ordered))
        return CollectionResult(
            ObservationDomain.NETWORK_LISTENERS,
            coverage,
            ordered,
            failure,
        )
    return CollectionResult(
        ObservationDomain.NETWORK_LISTENERS,
        CoverageState.COMPLETE,
        ordered,
    )
