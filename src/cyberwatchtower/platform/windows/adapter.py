"""Concrete Windows observation adapter assembled from reviewed collectors."""

from __future__ import annotations

from ..models import (
    CollectionResult,
    FirewallInboundPostureObservation,
    FirewallObservation,
    ListenerObservation,
    SystemObservation,
)
from .api import WindowsApiProtocol
from .api_native import NativeWindowsApi
from .firewall import (
    collect_windows_firewall_inbound_policy,
    collect_windows_firewall_technology,
)
from .network import collect_windows_network
from .system import collect_windows_system


class WindowsPlatformAdapter:
    """Coordinate Windows observations without creating security conclusions."""

    platform_name = "windows"

    def __init__(self, api: WindowsApiProtocol | None = None) -> None:
        self._api = api or NativeWindowsApi()

    def collect_system(self) -> CollectionResult[SystemObservation]:
        return collect_windows_system(self._api)

    def collect_firewall(self) -> CollectionResult[FirewallObservation]:
        return collect_windows_firewall_technology(self._api)

    def collect_network(self) -> CollectionResult[ListenerObservation]:
        return collect_windows_network(self._api)

    def collect_firewall_inbound_policy(
        self,
    ) -> CollectionResult[FirewallInboundPostureObservation]:
        return collect_windows_firewall_inbound_policy(self._api)
