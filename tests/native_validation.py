"""Closed opt-in gates for test-only native validation."""

import os
import platform
from collections.abc import Mapping


WINDOWS_NATIVE_VALIDATION_ENV = "CYBERWATCHTOWER_VALIDATE_NATIVE_WINDOWS"


def windows_native_validation_enabled(
    *,
    system_name: str | None = None,
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Return true only for Windows with the exact native-validation opt-in."""

    detected_system = platform.system() if system_name is None else system_name
    current_environment = os.environ if environment is None else environment
    return (
        detected_system == "Windows"
        and current_environment.get(WINDOWS_NATIVE_VALIDATION_ENV) == "1"
    )
