"""Privacy-safe typed errors for the application-service boundary."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
import unicodedata

from cyberwatchtower.report_contracts import ScanDomain


_OPERATION_ID = re.compile(r"^assessment:[0-9a-f]{32}$")


class ApplicationErrorCode(str, Enum):
    INVALID_REQUEST = "INVALID_REQUEST"
    NOT_FOUND = "NOT_FOUND"
    CONFLICT = "CONFLICT"
    UNSUPPORTED_PLATFORM = "UNSUPPORTED_PLATFORM"
    COMPONENT_UNAVAILABLE = "COMPONENT_UNAVAILABLE"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"
    AUTHORIZATION_REQUIRED = "AUTHORIZATION_REQUIRED"
    AUTHORIZATION_DENIED = "AUTHORIZATION_DENIED"
    AUTHORIZATION_EXPIRED = "AUTHORIZATION_EXPIRED"
    PRIVACY_POLICY_BLOCKED = "PRIVACY_POLICY_BLOCKED"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"
    STORAGE_FAILURE = "STORAGE_FAILURE"
    COMPATIBILITY_FAILURE = "COMPATIBILITY_FAILURE"
    INTERNAL_FAILURE = "INTERNAL_FAILURE"


class ApplicationComponent(str, Enum):
    APPLICATION = "APPLICATION"
    ASSESSMENT = "ASSESSMENT"
    PROJECTION = "PROJECTION"
    PLATFORM = "PLATFORM"
    PRIVACY = "PRIVACY"
    STORAGE = "STORAGE"
    AUTHORIZATION = "AUTHORIZATION"


@dataclass(frozen=True, slots=True)
class ApplicationFailure:
    code: ApplicationErrorCode
    message: str
    retryable: bool
    component: ApplicationComponent
    operation_id: str
    domain: ScanDomain | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.code, ApplicationErrorCode):
            raise TypeError("application failure code must use the closed enum.")
        if not isinstance(self.message, str) or not self.message or len(self.message) > 512:
            raise ValueError("application failure message must be bounded safe text.")
        if any(
            unicodedata.category(character) in {"Cc", "Cf"}
            for character in self.message
        ):
            raise ValueError("application failure message contains controls.")
        if not isinstance(self.retryable, bool):
            raise TypeError("application failure retryability must be boolean.")
        if not isinstance(self.component, ApplicationComponent):
            raise TypeError("application component must use the closed enum.")
        if _OPERATION_ID.fullmatch(self.operation_id) is None:
            raise ValueError("application failure operation id is invalid.")
        if self.domain is not None and not isinstance(self.domain, ScanDomain):
            raise TypeError("application failure domain must use the closed enum.")


class CyberWatchtowerApplicationError(RuntimeError):
    """Expose one bounded failure object without retaining an internal exception."""

    def __init__(self, failure: ApplicationFailure):
        if not isinstance(failure, ApplicationFailure):
            raise TypeError("application error requires ApplicationFailure.")
        self.failure = failure
        super().__init__(failure.message)
