"""Typed platform-boundary errors."""


class PlatformError(RuntimeError):
    """Base class for safe platform-boundary failures."""


class UnsupportedPlatformError(PlatformError):
    """Raised when no explicitly supported platform adapter exists."""
