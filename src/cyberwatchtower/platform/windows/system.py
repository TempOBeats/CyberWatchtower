"""Normalize Windows system facts without creating security conclusions."""

from __future__ import annotations

from cyberwatchtower.system_identity import derive_system_id

from ..models import (
    CollectionFailure,
    CollectionResult,
    FailureCategory,
    FailureCode,
    ObservationDomain,
    SystemObservation,
)
from cyberwatchtower.report_contracts import CoverageState
from .api import WindowsSystemApiProtocol
from .errors import WindowsFailureCode


_ARCHITECTURES = {
    "amd64": "x86_64",
    "x64": "x86_64",
    "arm64": "arm64",
    "x86": "x86",
}
_UNKNOWN_FAILURES = frozenset({
    WindowsFailureCode.API_UNAVAILABLE,
    WindowsFailureCode.UNSUPPORTED,
})


def _collection_failure(
    code: WindowsFailureCode,
    message: str,
) -> tuple[CoverageState, CollectionFailure]:
    if code in _UNKNOWN_FAILURES:
        return CoverageState.UNKNOWN, CollectionFailure(
            FailureCategory.UNSUPPORTED,
            FailureCode.COLLECTOR_UNAVAILABLE,
            message,
        )
    if code == WindowsFailureCode.ACCESS_DENIED:
        return CoverageState.INCOMPLETE, CollectionFailure(
            FailureCategory.PERMISSION_DENIED,
            FailureCode.COLLECTOR_PERMISSION_DENIED,
            message,
        )
    if code in {WindowsFailureCode.INVALID_RESULT, WindowsFailureCode.PARTIAL_RESULT}:
        return CoverageState.INCOMPLETE, CollectionFailure(
            FailureCategory.PARTIAL,
            FailureCode.COLLECTOR_PARTIAL,
            message,
        )
    return CoverageState.INCOMPLETE, CollectionFailure(
        FailureCategory.INTERNAL,
        FailureCode.COLLECTOR_INTERNAL_FAILURE,
        message,
    )


def _system_observation(info, system_id: str | None, architecture: str | None):
    values = {
        "hostname": info.hostname,
        "operating_system": "Windows",
        "os_version": f"{info.version} (build {info.build})",
    }
    if system_id is not None:
        values["system_id"] = system_id
    if architecture is not None:
        values["architecture"] = architecture
    if info.user_label is not None:
        values["username"] = info.user_label
    return SystemObservation.from_mapping(values)


def collect_windows_system(
    api: WindowsSystemApiProtocol,
) -> CollectionResult[SystemObservation]:
    """Collect Windows display facts and immediately derive an opaque system ID."""

    system_result = api.get_system_info()
    if system_result.value is None:
        code = system_result.failure or WindowsFailureCode.INTERNAL_ERROR
        coverage, failure = _collection_failure(
            code, "Windows system information could not be collected."
        )
        return CollectionResult(
            ObservationDomain.SYSTEM_INFORMATION,
            coverage,
            failure=failure,
        )

    info = system_result.value
    architecture = _ARCHITECTURES.get(info.architecture.casefold())
    identity_result = api.get_machine_identity()
    if not identity_result.succeeded or identity_result.value is None:
        observation = _system_observation(info, None, architecture)
        code = identity_result.failure or WindowsFailureCode.INTERNAL_ERROR
        coverage, failure = _collection_failure(
            code, "Stable Windows system identity could not be established."
        )
        return CollectionResult(
            ObservationDomain.SYSTEM_INFORMATION,
            coverage,
            (observation,),
            failure,
        )

    raw_identity = identity_result.value
    try:
        raw_value = raw_identity.consume_for_derivation()
        system_id = derive_system_id(raw_value)
    except (TypeError, ValueError):
        observation = _system_observation(info, None, architecture)
        coverage, failure = _collection_failure(
            WindowsFailureCode.INVALID_RESULT,
            "Stable Windows system identity could not be established.",
        )
        return CollectionResult(
            ObservationDomain.SYSTEM_INFORMATION,
            coverage,
            (observation,),
            failure,
        )
    finally:
        if "raw_value" in locals():
            del raw_value
        del raw_identity

    observation = _system_observation(info, system_id, architecture)
    if architecture is None:
        return CollectionResult(
            ObservationDomain.SYSTEM_INFORMATION,
            CoverageState.UNKNOWN,
            (observation,),
            CollectionFailure(
                FailureCategory.UNSUPPORTED,
                FailureCode.COLLECTOR_UNAVAILABLE,
                "Windows native architecture could not be determined.",
            ),
        )
    if system_result.failure is not None:
        coverage, failure = _collection_failure(
            system_result.failure,
            "Windows system information was only partially collected.",
        )
        return CollectionResult(
            ObservationDomain.SYSTEM_INFORMATION,
            coverage,
            (observation,),
            failure,
        )
    return CollectionResult(
        ObservationDomain.SYSTEM_INFORMATION,
        CoverageState.COMPLETE,
        (observation,),
    )
