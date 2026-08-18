"""Pure-Python contracts for future Windows-native observation collection."""

from .api import (
    WindowsApiProtocol,
    WindowsFirewallApiProtocol,
    WindowsNetworkApiProtocol,
    WindowsSystemApiProtocol,
)
from .api_native import NativeWindowsApi
from .buffer import NativeBufferRead, read_bounded_native_table
from .errors import WindowsFailureCode
from .fake import FakeWindowsApi, WindowsApiFixture
from .system import collect_windows_system
from .network import collect_windows_network
from .firewall import (
    collect_windows_firewall_inbound_policy,
    collect_windows_firewall_technology,
)
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
    "WindowsNetworkApiProtocol",
    "WindowsApiResult",
    "WindowsFailureCode",
    "WindowsFirewallApiProtocol",
    "WindowsFirewallAction",
    "WindowsFirewallEnablement",
    "WindowsFirewallProfile",
    "WindowsProfileState",
    "WindowsServiceState",
    "WindowsSystemApiProtocol",
    "WindowsTcpState",
    "collect_windows_system",
    "collect_windows_network",
    "collect_windows_firewall_inbound_policy",
    "collect_windows_firewall_technology",
    "read_bounded_native_table",
]
