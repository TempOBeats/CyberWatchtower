"""Platform-neutral host observation contracts and adapter selection."""

from .contracts import PlatformAdapter
from .errors import UnsupportedPlatformError
from .models import (
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
    ListenerExposure,
    ListenerObservation,
    NetworkProtocol,
    ObservationDomain,
    SystemObservation,
)
from .selection import select_platform_adapter

__all__ = [
    "CollectionFailure",
    "CollectionResult",
    "FailureCategory",
    "FailureCode",
    "FirewallEnablement",
    "FirewallInboundAction",
    "FirewallInboundPostureObservation",
    "FirewallObservation",
    "FirewallProfile",
    "FirewallProfileObservation",
    "FirewallProfileState",
    "ListenerExposure",
    "ListenerObservation",
    "NetworkProtocol",
    "ObservationDomain",
    "PlatformAdapter",
    "SystemObservation",
    "UnsupportedPlatformError",
    "select_platform_adapter",
]
