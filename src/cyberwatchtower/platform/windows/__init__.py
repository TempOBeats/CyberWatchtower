"""Pure-Python contracts for future Windows-native observation collection."""

from .api import (
    WindowsApiProtocol,
    WindowsFirewallApiProtocol,
    WindowsFirewallRulesApiProtocol,
    WindowsNetworkApiProtocol,
    WindowsSystemApiProtocol,
)
from .api_native import NativeWindowsApi
from .adapter import WindowsPlatformAdapter
from .buffer import NativeBufferRead, read_bounded_native_table
from .errors import (
    WindowsEndpointTable,
    WindowsEndpointTableDiagnostic,
    WindowsEndpointTableResultCode,
    WindowsEndpointValidationReason,
    WindowsFailureCode,
)
from .fake import FakeWindowsApi, WindowsApiFixture
from .system import collect_windows_system
from .network import collect_windows_network
from .firewall import (
    collect_windows_firewall_inbound_policy,
    collect_windows_firewall_technology,
)
from .firewall_rule_models import (
    RawWindowsApplicationPath,
    RawWindowsFirewallRule,
    RawWindowsInterfaceIdentity,
    WindowsFirewallPolicyView,
    WindowsFirewallRuleCollectionResult,
    WindowsFirewallRuleResultCode,
    WindowsRawFirewallInterfaceType,
    WindowsRawFirewallRuleAction,
    WindowsRawFirewallRuleDirection,
    WindowsRawFirewallUnsupportedFeature,
)
from .firewall_rules import (
    WINDOWS_FIREWALL_COM_ENUMERATION_CONTRACT,
    WindowsComGetterDeadlineGuarantee,
    WindowsComOwnershipRequirement,
    WindowsFirewallComEnumerationContract,
    WindowsFirewallRuleNormalizationResult,
    normalize_windows_firewall_rules,
    windows_application_identity,
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
    "RawWindowsApplicationPath",
    "RawWindowsFirewallRule",
    "RawWindowsInterfaceIdentity",
    "WindowsAddressFamily",
    "WindowsApiFixture",
    "WindowsApiProtocol",
    "WindowsNetworkApiProtocol",
    "WindowsPlatformAdapter",
    "WindowsApiResult",
    "WindowsFailureCode",
    "WindowsEndpointTable",
    "WindowsEndpointTableDiagnostic",
    "WindowsEndpointTableResultCode",
    "WindowsEndpointValidationReason",
    "WindowsFirewallApiProtocol",
    "WindowsFirewallRulesApiProtocol",
    "WindowsFirewallAction",
    "WindowsFirewallEnablement",
    "WindowsFirewallProfile",
    "WindowsProfileState",
    "WindowsFirewallPolicyView",
    "WindowsFirewallRuleCollectionResult",
    "WindowsFirewallRuleResultCode",
    "WindowsRawFirewallInterfaceType",
    "WindowsRawFirewallRuleAction",
    "WindowsRawFirewallRuleDirection",
    "WindowsRawFirewallUnsupportedFeature",
    "WINDOWS_FIREWALL_COM_ENUMERATION_CONTRACT",
    "WindowsComGetterDeadlineGuarantee",
    "WindowsComOwnershipRequirement",
    "WindowsFirewallComEnumerationContract",
    "WindowsFirewallRuleNormalizationResult",
    "WindowsServiceState",
    "WindowsSystemApiProtocol",
    "WindowsTcpState",
    "collect_windows_system",
    "collect_windows_network",
    "collect_windows_firewall_inbound_policy",
    "collect_windows_firewall_technology",
    "normalize_windows_firewall_rules",
    "windows_application_identity",
    "read_bounded_native_table",
]
