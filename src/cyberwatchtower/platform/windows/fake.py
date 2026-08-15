"""Explicit, non-executing Windows API fixtures for portable collector tests."""

from __future__ import annotations

from dataclasses import dataclass

from .errors import WindowsFailureCode
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


def _canonical_result(result, *, key, unique=True):
    if not isinstance(result, WindowsApiResult):
        raise TypeError("fixture values must use WindowsApiResult.")
    if result.value is None:
        return result
    if not isinstance(result.value, tuple):
        raise TypeError("fixture collection results must contain tuples.")
    ordered = tuple(sorted(result.value, key=key))
    if unique and any(item in ordered[:index] for index, item in enumerate(ordered)):
        raise ValueError("fixture collection contains duplicate native records.")
    return WindowsApiResult(ordered, result.failure)


@dataclass(frozen=True, slots=True)
class WindowsApiFixture:
    system_info: WindowsApiResult[RawWindowsSystemInfo]
    machine_identity: WindowsApiResult[RawMachineIdentity]
    tcp_endpoints: WindowsApiResult[tuple[RawTcpEndpoint, ...]]
    udp_endpoints: WindowsApiResult[tuple[RawUdpEndpoint, ...]]
    processes: tuple[tuple[int, WindowsApiResult[RawProcessInfo]], ...]
    services: WindowsApiResult[tuple[RawServiceInfo, ...]]
    firewall_profiles: WindowsApiResult[tuple[RawFirewallProfile, ...]]

    def __post_init__(self) -> None:
        if not isinstance(self.system_info, WindowsApiResult):
            raise TypeError("system fixture must use WindowsApiResult.")
        if not isinstance(self.machine_identity, WindowsApiResult):
            raise TypeError("identity fixture must use WindowsApiResult.")
        if not isinstance(self.processes, tuple):
            raise TypeError("process fixtures must be an immutable tuple.")
        process_ids = []
        for pid, result in self.processes:
            if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
                raise ValueError("process fixture PID is invalid.")
            if not isinstance(result, WindowsApiResult):
                raise TypeError("process fixture must use WindowsApiResult.")
            if result.value is not None and result.value.pid != pid:
                raise ValueError("process fixture PID does not match its result.")
            process_ids.append(pid)
        if len(set(process_ids)) != len(process_ids):
            raise ValueError("process fixture PIDs must be unique.")
        object.__setattr__(self, "processes", tuple(sorted(self.processes)))
        object.__setattr__(self, "tcp_endpoints", _canonical_result(
            self.tcp_endpoints,
            key=lambda item: (item.family.value, item.address, item.port, item.pid),
        ))
        object.__setattr__(self, "udp_endpoints", _canonical_result(
            self.udp_endpoints,
            key=lambda item: (item.family.value, item.address, item.port, item.pid),
        ))
        object.__setattr__(self, "services", _canonical_result(
            self.services,
            key=lambda item: (
                item.service_name.casefold(), item.display_name.casefold(), item.pid
            ),
        ))
        object.__setattr__(self, "firewall_profiles", _canonical_result(
            self.firewall_profiles,
            key=lambda item: item.profile.value,
        ))


class FakeWindowsApi:
    """Method-specific fake matching WindowsApiProtocol without native access."""

    __slots__ = ("_fixture",)

    def __init__(self, fixture: WindowsApiFixture) -> None:
        if not isinstance(fixture, WindowsApiFixture):
            raise TypeError("FakeWindowsApi requires a typed fixture.")
        self._fixture = fixture

    def get_system_info(self) -> WindowsApiResult[RawWindowsSystemInfo]:
        return self._fixture.system_info

    def get_machine_identity(self) -> WindowsApiResult[RawMachineIdentity]:
        return self._fixture.machine_identity

    def get_tcp_endpoints(self) -> WindowsApiResult[tuple[RawTcpEndpoint, ...]]:
        return self._fixture.tcp_endpoints

    def get_udp_endpoints(self) -> WindowsApiResult[tuple[RawUdpEndpoint, ...]]:
        return self._fixture.udp_endpoints

    def get_process_image(self, pid: int) -> WindowsApiResult[RawProcessInfo]:
        if isinstance(pid, bool) or not isinstance(pid, int) or pid < 0:
            return WindowsApiResult(failure=WindowsFailureCode.INVALID_RESULT)
        if pid == 0:
            return WindowsApiResult(failure=WindowsFailureCode.ACCESS_DENIED)
        for fixture_pid, result in self._fixture.processes:
            if fixture_pid == pid:
                return result
        return WindowsApiResult(failure=WindowsFailureCode.PROCESS_DISAPPEARED)

    def list_services(self) -> WindowsApiResult[tuple[RawServiceInfo, ...]]:
        return self._fixture.services

    def get_firewall_profiles(
        self,
    ) -> WindowsApiResult[tuple[RawFirewallProfile, ...]]:
        return self._fixture.firewall_profiles
