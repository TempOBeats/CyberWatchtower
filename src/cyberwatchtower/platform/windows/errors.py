"""Closed, sanitized failure contract for the internal Windows API boundary."""

from dataclasses import dataclass
from enum import Enum


class WindowsFailureCode(str, Enum):
    API_UNAVAILABLE = "API_UNAVAILABLE"
    ACCESS_DENIED = "ACCESS_DENIED"
    BUFFER_UNSTABLE = "BUFFER_UNSTABLE"
    PARTIAL_RESULT = "PARTIAL_RESULT"
    INVALID_RESULT = "INVALID_RESULT"
    TIMEOUT = "TIMEOUT"
    PROCESS_DISAPPEARED = "PROCESS_DISAPPEARED"
    UNSUPPORTED = "UNSUPPORTED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class WindowsEndpointTable(str, Enum):
    TCP_IPV4 = "TCP_IPV4"
    TCP_IPV6 = "TCP_IPV6"
    UDP_IPV4 = "UDP_IPV4"
    UDP_IPV6 = "UDP_IPV6"


class WindowsEndpointTableResultCode(str, Enum):
    COMPLETE = "COMPLETE"
    API_UNAVAILABLE = WindowsFailureCode.API_UNAVAILABLE.value
    ACCESS_DENIED = WindowsFailureCode.ACCESS_DENIED.value
    BUFFER_UNSTABLE = WindowsFailureCode.BUFFER_UNSTABLE.value
    INVALID_RESULT = WindowsFailureCode.INVALID_RESULT.value
    TIMEOUT = WindowsFailureCode.TIMEOUT.value
    UNSUPPORTED = WindowsFailureCode.UNSUPPORTED.value
    INTERNAL_ERROR = WindowsFailureCode.INTERNAL_ERROR.value


@dataclass(frozen=True, slots=True)
class WindowsEndpointTableDiagnostic:
    """Sanitized table outcome containing no endpoint or native error data."""

    table: WindowsEndpointTable
    result: WindowsEndpointTableResultCode

    def __post_init__(self) -> None:
        if not isinstance(self.table, WindowsEndpointTable):
            raise TypeError("endpoint diagnostic table must use the closed enum.")
        if not isinstance(self.result, WindowsEndpointTableResultCode):
            raise TypeError("endpoint diagnostic result must use the closed enum.")


_SAFE_MESSAGES = {
    WindowsFailureCode.API_UNAVAILABLE: "The required Windows API is unavailable.",
    WindowsFailureCode.ACCESS_DENIED: "The Windows API denied access.",
    WindowsFailureCode.BUFFER_UNSTABLE: (
        "The Windows API result changed during bounded collection."
    ),
    WindowsFailureCode.PARTIAL_RESULT: (
        "The Windows API returned only part of the requested data."
    ),
    WindowsFailureCode.INVALID_RESULT: (
        "The Windows API returned data outside the supported contract."
    ),
    WindowsFailureCode.TIMEOUT: "The Windows API operation exceeded its time limit.",
    WindowsFailureCode.PROCESS_DISAPPEARED: (
        "The process ended before its information could be collected."
    ),
    WindowsFailureCode.UNSUPPORTED: (
        "This Windows API operation is unsupported on the current system."
    ),
    WindowsFailureCode.INTERNAL_ERROR: (
        "The Windows API boundary encountered an internal failure."
    ),
}


def safe_windows_failure_message(code: WindowsFailureCode) -> str:
    if not isinstance(code, WindowsFailureCode):
        raise TypeError("Windows failures must use the closed error code enum.")
    return _SAFE_MESSAGES[code]
