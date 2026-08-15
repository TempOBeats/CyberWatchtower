"""Pure-Python contracts for future Windows-native observation collection."""

from .api import WindowsApiProtocol
from .errors import WindowsFailureCode
from .models import (
    RawFirewallProfile,
    RawMachineIdentity,
    RawProcessInfo,
    RawServiceInfo,
    RawTcpEndpoint,
    RawUdpEndpoint,
    RawWindowsSystemInfo,
    WindowsAddressFamily,
    WindowsApiResult,
    WindowsFirewallAction,
    WindowsFirewallEnablement,
    WindowsFirewallProfile,
    WindowsProfileState,
    WindowsServiceState,
    WindowsTcpState,
)

__all__ = [
    "RawFirewallProfile",
    "RawMachineIdentity",
    "RawProcessInfo",
    "RawServiceInfo",
    "RawTcpEndpoint",
    "RawUdpEndpoint",
    "RawWindowsSystemInfo",
    "WindowsAddressFamily",
    "WindowsApiProtocol",
    "WindowsApiResult",
    "WindowsFailureCode",
    "WindowsFirewallAction",
    "WindowsFirewallEnablement",
    "WindowsFirewallProfile",
    "WindowsProfileState",
    "WindowsServiceState",
    "WindowsTcpState",
]
