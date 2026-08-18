"""Deterministic platform adapter selection."""

import platform

from .contracts import PlatformAdapter
from .errors import UnsupportedPlatformError


def select_platform_adapter(
    *,
    system_name: str | None = None,
    linux_adapter: PlatformAdapter | None = None,
    windows_adapter: PlatformAdapter | None = None,
) -> PlatformAdapter:
    """Select only an explicitly supported adapter; never fall back by accident."""

    selected = system_name if system_name is not None else platform.system()
    if selected.casefold() == "linux":
        if linux_adapter is not None:
            return linux_adapter
        from .linux import LinuxPlatformAdapter
        return LinuxPlatformAdapter()
    if selected.casefold() == "windows":
        if windows_adapter is not None:
            return windows_adapter
        from .windows import WindowsPlatformAdapter
        return WindowsPlatformAdapter()
    raise UnsupportedPlatformError(
        "CyberWatchtower does not have a supported adapter for this platform."
    )
