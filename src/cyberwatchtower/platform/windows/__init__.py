"""Pure-Python contracts for future Windows-native observation collection."""

from .api import WindowsApiProtocol, WindowsSystemApiProtocol
from .api_native import NativeWindowsApi
from .buffer import NativeBufferRead, read_bounded_native_table
from .errors import WindowsFailureCode
from .fake import FakeWindowsApi, WindowsApiFixture
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
    "FakeWindowsApi",
    "NativeBufferRead",
    "NativeWindowsApi",
    "RawFirewallProfile",
    "RawMachineIdentity",
    "RawProcessInfo",
    "RawServiceInfo",
    "RawTcpEndpoint",
    "RawUdpEndpoint",
    "RawWindowsSystemInfo",
    "WindowsAddressFamily",
    "WindowsApiFixture",
    "WindowsApiProtocol",
    "WindowsApiResult",
    "WindowsFailureCode",
    "WindowsFirewallAction",
    "WindowsFirewallEnablement",
    "WindowsFirewallProfile",
    "WindowsProfileState",
    "WindowsServiceState",
    "WindowsSystemApiProtocol",
    "WindowsTcpState",
    "read_bounded_native_table",
]
