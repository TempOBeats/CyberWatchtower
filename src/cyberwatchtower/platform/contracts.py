"""Narrow host collection boundary consumed by the deterministic scanner."""

from typing import Protocol

from .models import (
    CollectionResult,
    FirewallInboundPostureObservation,
    FirewallObservation,
    ListenerObservation,
    SystemObservation,
)


class PlatformAdapter(Protocol):
    platform_name: str

    def collect_system(self) -> CollectionResult[SystemObservation]: ...

    def collect_firewall(self) -> CollectionResult[FirewallObservation]: ...

    def collect_network(self) -> CollectionResult[ListenerObservation]: ...

    def collect_firewall_inbound_policy(
        self,
    ) -> CollectionResult[FirewallInboundPostureObservation]: ...
