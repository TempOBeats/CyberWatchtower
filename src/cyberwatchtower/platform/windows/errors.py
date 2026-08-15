"""Closed, sanitized failure contract for the internal Windows API boundary."""

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
