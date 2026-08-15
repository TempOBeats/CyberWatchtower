"""Fakeable protocol and bounded helpers for future Windows-native access."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .models import (
    RawFirewallProfile,
    RawMachineIdentity,
    RawProcessInfo,
    RawServiceInfo,
    RawTcpEndpoint,
    RawUdpEndpoint,
    RawWindowsSystemInfo,
    WindowsApiResult,
)


@runtime_checkable
class WindowsSystemApiProtocol(Protocol):
    def get_system_info(self) -> WindowsApiResult[RawWindowsSystemInfo]: ...

    def get_machine_identity(self) -> WindowsApiResult[RawMachineIdentity]: ...


@runtime_checkable
class WindowsApiProtocol(WindowsSystemApiProtocol, Protocol):

    def get_tcp_endpoints(
        self,
    ) -> WindowsApiResult[tuple[RawTcpEndpoint, ...]]: ...

    def get_udp_endpoints(
        self,
    ) -> WindowsApiResult[tuple[RawUdpEndpoint, ...]]: ...

    def get_process_image(self, pid: int) -> WindowsApiResult[RawProcessInfo]: ...

    def list_services(self) -> WindowsApiResult[tuple[RawServiceInfo, ...]]: ...

    def get_firewall_profiles(
        self,
    ) -> WindowsApiResult[tuple[RawFirewallProfile, ...]]: ...
