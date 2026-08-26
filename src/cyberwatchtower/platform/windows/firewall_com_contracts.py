"""Portable COM ABI and ownership contracts for future firewall rule reads.

This module deliberately performs no COM loading or native calls.  It freezes
the fixed read-only surface and provides mockable lifetime primitives for the
future isolated Windows helper.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
import unicodedata

from cyberwatchtower.firewall_policy import MAX_VALUES_PER_CONDITION


CLSID_NET_FW_POLICY2 = "e2b3c97f-6ae1-41ac-817a-f6f92166d7dd"
IID_IUNKNOWN = "00000000-0000-0000-c000-000000000046"
IID_IENUMVARIANT = "00020404-0000-0000-c000-000000000046"
IID_INET_FW_POLICY2 = "98325047-c671-4174-8d81-defcd3f03186"
IID_INET_FW_RULES = "9c4c6277-5027-441e-afae-ca1f542da009"
IID_INET_FW_RULE = "af230d27-baba-4e42-aced-f524f22cfce2"
IID_INET_FW_RULE2 = "9c27c8da-189b-4dde-89f7-8b39a316782c"
IID_INET_FW_RULE3 = "b21563ff-d696-4222-ab46-4e89b73ab34a"

COINIT_APARTMENTTHREADED = 0x2
COINIT_DISABLE_OLE1DDE = 0x4
WINDOWS_FIREWALL_COM_INIT_FLAGS = (
    COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE
)

MAX_PROPERTY_GETTERS_PER_RULE = 22
APPROVED_PROPERTY_GETTER_COUNT = 21
RESERVED_PROPERTY_GETTER_CAPACITY = 1


class WindowsComInterface(str, Enum):
    IUNKNOWN = "IUNKNOWN"
    IENUMVARIANT = "IENUMVARIANT"
    POLICY2 = "INET_FW_POLICY2"
    RULES = "INET_FW_RULES"
    RULE = "INET_FW_RULE"
    RULE2 = "INET_FW_RULE2"
    RULE3 = "INET_FW_RULE3"


class WindowsComMethodKind(str, Enum):
    LIFETIME = "LIFETIME"
    COLLECTION = "COLLECTION"
    ENUMERATION = "ENUMERATION"
    PROPERTY_GETTER = "PROPERTY_GETTER"


class WindowsFirewallPropertyGetter(str, Enum):
    ENABLED = "get_Enabled"
    DIRECTION = "get_Direction"
    ACTION = "get_Action"
    PROFILES = "get_Profiles"
    PROTOCOL = "get_Protocol"
    LOCAL_PORTS = "get_LocalPorts"
    REMOTE_PORTS = "get_RemotePorts"
    LOCAL_ADDRESSES = "get_LocalAddresses"
    REMOTE_ADDRESSES = "get_RemoteAddresses"
    APPLICATION_NAME = "get_ApplicationName"
    SERVICE_NAME = "get_ServiceName"
    INTERFACE_TYPES = "get_InterfaceTypes"
    INTERFACES = "get_Interfaces"
    ICMP_TYPES_AND_CODES = "get_IcmpTypesAndCodes"
    EDGE_TRAVERSAL_OPTIONS = "get_EdgeTraversalOptions"
    EDGE_TRAVERSAL = "get_EdgeTraversal"
    LOCAL_APP_PACKAGE_ID = "get_LocalAppPackageId"
    LOCAL_USER_AUTHORIZED_LIST = "get_LocalUserAuthorizedList"
    REMOTE_MACHINE_AUTHORIZED_LIST = "get_RemoteMachineAuthorizedList"
    REMOTE_USER_AUTHORIZED_LIST = "get_RemoteUserAuthorizedList"
    SECURE_FLAGS = "get_SecureFlags"


APPROVED_FIREWALL_PROPERTY_GETTERS = tuple(WindowsFirewallPropertyGetter)
PROHIBITED_FIREWALL_COM_MEMBERS = (
    "get_Name", "put_Name", "get_Description", "put_Description",
    "get_Grouping", "put_Grouping", "get_LocalUserOwner",
    "GetIDsOfNames", "Invoke", "Item", "Add", "Remove",
)


@dataclass(frozen=True, slots=True)
class WindowsFirewallRuleInterfacePlan:
    rule2_available: bool
    rule3_available: bool

    def __post_init__(self) -> None:
        if not isinstance(self.rule2_available, bool) \
                or not isinstance(self.rule3_available, bool):
            raise TypeError("COM interface availability must be boolean.")

    @property
    def edge_getter(self) -> WindowsFirewallPropertyGetter:
        return (
            WindowsFirewallPropertyGetter.EDGE_TRAVERSAL_OPTIONS
            if self.rule2_available
            else WindowsFirewallPropertyGetter.EDGE_TRAVERSAL
        )

    @property
    def rule3_presence_getters(self) -> tuple[WindowsFirewallPropertyGetter, ...]:
        if not self.rule3_available:
            return ()
        return (
            WindowsFirewallPropertyGetter.LOCAL_APP_PACKAGE_ID,
            WindowsFirewallPropertyGetter.LOCAL_USER_AUTHORIZED_LIST,
            WindowsFirewallPropertyGetter.REMOTE_MACHINE_AUTHORIZED_LIST,
            WindowsFirewallPropertyGetter.REMOTE_USER_AUTHORIZED_LIST,
            WindowsFirewallPropertyGetter.SECURE_FLAGS,
        )

    @property
    def rule3_predicates_decidable(self) -> bool:
        return self.rule3_available


@dataclass(frozen=True, slots=True)
class WindowsComMethod:
    interface: WindowsComInterface
    name: str
    vtable_index: int
    kind: WindowsComMethodKind

    def __post_init__(self) -> None:
        if not isinstance(self.interface, WindowsComInterface):
            raise TypeError("COM method interface must use the closed enum.")
        if not isinstance(self.kind, WindowsComMethodKind):
            raise TypeError("COM method kind must use the closed enum.")
        if not isinstance(self.name, str) or not self.name.startswith((
            "QueryInterface", "AddRef", "Release", "get_", "Next"
        )):
            raise ValueError("COM method is outside the fixed read-only surface.")
        if isinstance(self.vtable_index, bool) or not isinstance(
            self.vtable_index, int
        ) or self.vtable_index < 0:
            raise ValueError("COM vtable index is invalid.")
        lifecycle = {
            "QueryInterface": (WindowsComInterface.IUNKNOWN, 0,
                               WindowsComMethodKind.LIFETIME),
            "AddRef": (WindowsComInterface.IUNKNOWN, 1,
                       WindowsComMethodKind.LIFETIME),
            "Release": (WindowsComInterface.IUNKNOWN, 2,
                        WindowsComMethodKind.LIFETIME),
            "get_Rules": (WindowsComInterface.POLICY2, 18,
                          WindowsComMethodKind.COLLECTION),
            "get_Count": (WindowsComInterface.RULES, 7,
                          WindowsComMethodKind.COLLECTION),
            "get__NewEnum": (WindowsComInterface.RULES, 11,
                             WindowsComMethodKind.COLLECTION),
            "Next": (WindowsComInterface.IENUMVARIANT, 3,
                     WindowsComMethodKind.ENUMERATION),
        }
        getter_slots = {
            WindowsFirewallPropertyGetter.ENABLED: (WindowsComInterface.RULE, 33),
            WindowsFirewallPropertyGetter.DIRECTION: (WindowsComInterface.RULE, 27),
            WindowsFirewallPropertyGetter.ACTION: (WindowsComInterface.RULE, 41),
            WindowsFirewallPropertyGetter.PROFILES: (WindowsComInterface.RULE, 37),
            WindowsFirewallPropertyGetter.PROTOCOL: (WindowsComInterface.RULE, 15),
            WindowsFirewallPropertyGetter.LOCAL_PORTS: (WindowsComInterface.RULE, 17),
            WindowsFirewallPropertyGetter.REMOTE_PORTS: (WindowsComInterface.RULE, 19),
            WindowsFirewallPropertyGetter.LOCAL_ADDRESSES:
                (WindowsComInterface.RULE, 21),
            WindowsFirewallPropertyGetter.REMOTE_ADDRESSES:
                (WindowsComInterface.RULE, 23),
            WindowsFirewallPropertyGetter.APPLICATION_NAME:
                (WindowsComInterface.RULE, 11),
            WindowsFirewallPropertyGetter.SERVICE_NAME:
                (WindowsComInterface.RULE, 13),
            WindowsFirewallPropertyGetter.INTERFACE_TYPES:
                (WindowsComInterface.RULE, 31),
            WindowsFirewallPropertyGetter.INTERFACES:
                (WindowsComInterface.RULE, 29),
            WindowsFirewallPropertyGetter.ICMP_TYPES_AND_CODES:
                (WindowsComInterface.RULE, 25),
            WindowsFirewallPropertyGetter.EDGE_TRAVERSAL_OPTIONS:
                (WindowsComInterface.RULE2, 43),
            WindowsFirewallPropertyGetter.EDGE_TRAVERSAL:
                (WindowsComInterface.RULE, 39),
            WindowsFirewallPropertyGetter.LOCAL_APP_PACKAGE_ID:
                (WindowsComInterface.RULE3, 45),
            WindowsFirewallPropertyGetter.LOCAL_USER_AUTHORIZED_LIST:
                (WindowsComInterface.RULE3, 47),
            WindowsFirewallPropertyGetter.REMOTE_MACHINE_AUTHORIZED_LIST:
                (WindowsComInterface.RULE3, 53),
            WindowsFirewallPropertyGetter.REMOTE_USER_AUTHORIZED_LIST:
                (WindowsComInterface.RULE3, 51),
            WindowsFirewallPropertyGetter.SECURE_FLAGS:
                (WindowsComInterface.RULE3, 55),
        }
        if self.kind == WindowsComMethodKind.PROPERTY_GETTER:
            try:
                getter = WindowsFirewallPropertyGetter(self.name)
            except ValueError as exc:
                raise ValueError("COM property getter is not approved.") from exc
            if getter_slots[getter] != (self.interface, self.vtable_index):
                raise ValueError("COM property getter ABI does not match.")
        elif lifecycle.get(self.name) != (
            self.interface, self.vtable_index, self.kind
        ):
            raise ValueError("COM method is outside the fixed ABI.")


WINDOWS_FIREWALL_COM_METHODS = (
    WindowsComMethod(WindowsComInterface.IUNKNOWN, "QueryInterface", 0,
                     WindowsComMethodKind.LIFETIME),
    WindowsComMethod(WindowsComInterface.IUNKNOWN, "AddRef", 1,
                     WindowsComMethodKind.LIFETIME),
    WindowsComMethod(WindowsComInterface.IUNKNOWN, "Release", 2,
                     WindowsComMethodKind.LIFETIME),
    WindowsComMethod(WindowsComInterface.POLICY2, "get_Rules", 18,
                     WindowsComMethodKind.COLLECTION),
    WindowsComMethod(WindowsComInterface.RULES, "get_Count", 7,
                     WindowsComMethodKind.COLLECTION),
    WindowsComMethod(WindowsComInterface.RULES, "get__NewEnum", 11,
                     WindowsComMethodKind.COLLECTION),
    WindowsComMethod(WindowsComInterface.IENUMVARIANT, "Next", 3,
                     WindowsComMethodKind.ENUMERATION),
    WindowsComMethod(WindowsComInterface.RULE, "get_Enabled", 33,
                     WindowsComMethodKind.PROPERTY_GETTER),
    WindowsComMethod(WindowsComInterface.RULE, "get_Direction", 27,
                     WindowsComMethodKind.PROPERTY_GETTER),
    WindowsComMethod(WindowsComInterface.RULE, "get_Action", 41,
                     WindowsComMethodKind.PROPERTY_GETTER),
    WindowsComMethod(WindowsComInterface.RULE, "get_Profiles", 37,
                     WindowsComMethodKind.PROPERTY_GETTER),
    WindowsComMethod(WindowsComInterface.RULE, "get_Protocol", 15,
                     WindowsComMethodKind.PROPERTY_GETTER),
    WindowsComMethod(WindowsComInterface.RULE, "get_LocalPorts", 17,
                     WindowsComMethodKind.PROPERTY_GETTER),
    WindowsComMethod(WindowsComInterface.RULE, "get_RemotePorts", 19,
                     WindowsComMethodKind.PROPERTY_GETTER),
    WindowsComMethod(WindowsComInterface.RULE, "get_LocalAddresses", 21,
                     WindowsComMethodKind.PROPERTY_GETTER),
    WindowsComMethod(WindowsComInterface.RULE, "get_RemoteAddresses", 23,
                     WindowsComMethodKind.PROPERTY_GETTER),
    WindowsComMethod(WindowsComInterface.RULE, "get_ApplicationName", 11,
                     WindowsComMethodKind.PROPERTY_GETTER),
    WindowsComMethod(WindowsComInterface.RULE, "get_ServiceName", 13,
                     WindowsComMethodKind.PROPERTY_GETTER),
    WindowsComMethod(WindowsComInterface.RULE, "get_InterfaceTypes", 31,
                     WindowsComMethodKind.PROPERTY_GETTER),
    WindowsComMethod(WindowsComInterface.RULE, "get_Interfaces", 29,
                     WindowsComMethodKind.PROPERTY_GETTER),
    WindowsComMethod(WindowsComInterface.RULE, "get_IcmpTypesAndCodes", 25,
                     WindowsComMethodKind.PROPERTY_GETTER),
    WindowsComMethod(WindowsComInterface.RULE2, "get_EdgeTraversalOptions", 43,
                     WindowsComMethodKind.PROPERTY_GETTER),
    WindowsComMethod(WindowsComInterface.RULE, "get_EdgeTraversal", 39,
                     WindowsComMethodKind.PROPERTY_GETTER),
    WindowsComMethod(WindowsComInterface.RULE3, "get_LocalAppPackageId", 45,
                     WindowsComMethodKind.PROPERTY_GETTER),
    WindowsComMethod(WindowsComInterface.RULE3, "get_LocalUserAuthorizedList", 47,
                     WindowsComMethodKind.PROPERTY_GETTER),
    WindowsComMethod(WindowsComInterface.RULE3,
                     "get_RemoteMachineAuthorizedList", 53,
                     WindowsComMethodKind.PROPERTY_GETTER),
    WindowsComMethod(WindowsComInterface.RULE3,
                     "get_RemoteUserAuthorizedList", 51,
                     WindowsComMethodKind.PROPERTY_GETTER),
    WindowsComMethod(WindowsComInterface.RULE3, "get_SecureFlags", 55,
                     WindowsComMethodKind.PROPERTY_GETTER),
)


class WindowsComInitializationResult(str, Enum):
    S_OK = "S_OK"
    S_FALSE = "S_FALSE"
    RPC_E_CHANGED_MODE = "RPC_E_CHANGED_MODE"
    FAILURE = "FAILURE"


class WindowsComFailureCategory(str, Enum):
    API_UNAVAILABLE = "API_UNAVAILABLE"
    ACCESS_DENIED = "ACCESS_DENIED"
    COLLECTION_INCOMPLETE = "COLLECTION_INCOMPLETE"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    INVALID_RESULT = "INVALID_RESULT"
    TIMEOUT = "TIMEOUT"
    UNSUPPORTED = "UNSUPPORTED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class WindowsComContractError(RuntimeError):
    __slots__ = ("category",)

    def __init__(self, category: WindowsComFailureCategory) -> None:
        if not isinstance(category, WindowsComFailureCategory):
            raise TypeError("COM failure must use the closed category.")
        self.category = category
        super().__init__(category.value)


class WindowsComInitializationLease:
    """Exactly-once CoUninitialize ownership represented without native calls."""

    __slots__ = ("_owned", "_uninitialize")

    def __init__(
        self,
        result: WindowsComInitializationResult,
        uninitialize: Callable[[], None],
    ) -> None:
        if not isinstance(result, WindowsComInitializationResult):
            raise TypeError("COM initialization result must use the closed enum.")
        if not callable(uninitialize):
            raise TypeError("COM uninitializer must be callable.")
        if result == WindowsComInitializationResult.RPC_E_CHANGED_MODE:
            raise WindowsComContractError(WindowsComFailureCategory.INTERNAL_ERROR)
        if result == WindowsComInitializationResult.FAILURE:
            raise WindowsComContractError(WindowsComFailureCategory.INTERNAL_ERROR)
        self._owned = True
        self._uninitialize = uninitialize

    def close(self) -> None:
        if self._owned:
            self._owned = False
            _sanitized_cleanup(self._uninitialize)

    def __enter__(self) -> "WindowsComInitializationLease":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


class WindowsComResourceKind(str, Enum):
    POLICY2 = "POLICY2"
    RULES = "RULES"
    NEW_ENUM_UNKNOWN = "NEW_ENUM_UNKNOWN"
    ENUMVARIANT = "ENUMVARIANT"
    RULE = "RULE"
    RULE2 = "RULE2"
    RULE3 = "RULE3"
    BSTR = "BSTR"
    VARIANT = "VARIANT"


class WindowsComCleanupStack:
    """Explicit LIFO ownership for portable lifetime verification."""

    __slots__ = ("_resources", "_closed")

    def __init__(self) -> None:
        self._resources: list[tuple[WindowsComResourceKind, Callable[[], None]]] = []
        self._closed = False

    def own(
        self, kind: WindowsComResourceKind, cleanup: Callable[[], None]
    ) -> None:
        if self._closed:
            raise WindowsComContractError(WindowsComFailureCategory.INTERNAL_ERROR)
        if not isinstance(kind, WindowsComResourceKind) or not callable(cleanup):
            raise TypeError("COM ownership requires a closed kind and callback.")
        self._resources.append((kind, cleanup))

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        first_error: Exception | None = None
        while self._resources:
            _, cleanup = self._resources.pop()
            try:
                cleanup()
            except Exception as exc:  # cleanup continues; native text is discarded
                first_error = first_error or exc
        if first_error is not None:
            raise WindowsComContractError(
                WindowsComFailureCategory.INTERNAL_ERROR
            ) from None

    def __enter__(self) -> "WindowsComCleanupStack":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


class WindowsVariantType(str, Enum):
    EMPTY = "EMPTY"
    DISPATCH = "DISPATCH"
    UNKNOWN = "UNKNOWN"
    BSTR = "BSTR"
    I4 = "I4"
    BOOL = "BOOL"
    ARRAY_VARIANT = "ARRAY_VARIANT"
    BY_REFERENCE = "BY_REFERENCE"


class WindowsSafeArrayElementType(str, Enum):
    VARIANT = "VARIANT"
    BSTR = "BSTR"


@dataclass(frozen=True, slots=True)
class WindowsSafeArrayValue:
    dimensions: int
    element_type: WindowsSafeArrayElementType
    values: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.dimensions != 1:
            raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)
        if not isinstance(self.element_type, WindowsSafeArrayElementType):
            raise TypeError("SAFEARRAY element type must use the closed enum.")
        if not isinstance(self.values, tuple) \
                or len(self.values) > MAX_VALUES_PER_CONDITION \
                or not all(isinstance(item, str) for item in self.values):
            raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)


class WindowsOwnedBstr:
    __slots__ = ("_value", "_free", "_closed")

    def __init__(self, value: str, free: Callable[[], None]) -> None:
        if not isinstance(value, str) or not callable(free):
            raise TypeError("owned BSTR requires text and a cleanup callback.")
        self._value = value
        self._free = free
        self._closed = False

    def __repr__(self) -> str:
        return "WindowsOwnedBstr(<redacted>)"

    __str__ = __repr__

    def copy_bounded(self, maximum: int) -> str:
        if self._closed:
            raise WindowsComContractError(WindowsComFailureCategory.INTERNAL_ERROR)
        if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum <= 0:
            raise ValueError("BSTR bound is invalid.")
        if not self._value or len(self._value) > maximum or any(
            unicodedata.category(character) in {"Cc", "Cf"}
            for character in self._value
        ):
            raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)
        return self._value

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._value = ""
            _sanitized_cleanup(self._free)

    def __enter__(self) -> "WindowsOwnedBstr":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


class WindowsOwnedVariant:
    __slots__ = ("variant_type", "_value", "_clear", "_closed")

    def __init__(
        self,
        variant_type: WindowsVariantType,
        value: object,
        initialize: Callable[[], None],
        clear: Callable[[], None],
    ) -> None:
        if not isinstance(variant_type, WindowsVariantType):
            raise TypeError("VARIANT type must use the closed enum.")
        if not callable(initialize) or not callable(clear):
            raise TypeError("VARIANT lifecycle callbacks must be callable.")
        try:
            initialize()
        except Exception:
            raise WindowsComContractError(
                WindowsComFailureCategory.INTERNAL_ERROR
            ) from None
        self.variant_type = variant_type
        self._value = value
        self._clear = clear
        self._closed = False

    def __repr__(self) -> str:
        return f"WindowsOwnedVariant({self.variant_type.value}, <redacted>)"

    def extract(self, expected: WindowsVariantType) -> object:
        if self._closed or not isinstance(expected, WindowsVariantType):
            raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)
        if self.variant_type == WindowsVariantType.BY_REFERENCE \
                or self.variant_type != expected:
            raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)
        return self._value

    def extract_safearray(self) -> tuple[str, ...]:
        value = self.extract(WindowsVariantType.ARRAY_VARIANT)
        if not isinstance(value, WindowsSafeArrayValue):
            raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)
        return value.values

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._value = None
            _sanitized_cleanup(self._clear)

    def __enter__(self) -> "WindowsOwnedVariant":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


@dataclass(slots=True)
class WindowsComOperationAccounting:
    property_getters: int = 0
    query_interfaces: int = 0
    enumeration_operations: int = 0
    interface_releases: int = 0
    initialization_operations: int = 0
    cleanup_operations: int = 0

    def record_property_getter(self, getter: WindowsFirewallPropertyGetter) -> None:
        if not isinstance(getter, WindowsFirewallPropertyGetter):
            raise WindowsComContractError(WindowsComFailureCategory.UNSUPPORTED)
        if self.property_getters >= MAX_PROPERTY_GETTERS_PER_RULE:
            raise WindowsComContractError(WindowsComFailureCategory.LIMIT_EXCEEDED)
        self.property_getters += 1

    def record_query_interface(self) -> None:
        self.query_interfaces += 1

    def record_enumeration(self) -> None:
        self.enumeration_operations += 1

    def record_release(self) -> None:
        self.interface_releases += 1

    def record_initialization(self) -> None:
        self.initialization_operations += 1

    def record_cleanup(self) -> None:
        self.cleanup_operations += 1


def _sanitized_cleanup(callback: Callable[[], None]) -> None:
    try:
        callback()
    except Exception:
        raise WindowsComContractError(
            WindowsComFailureCategory.INTERNAL_ERROR
        ) from None


def _validate_contract() -> None:
    property_methods = tuple(
        method.name for method in WINDOWS_FIREWALL_COM_METHODS
        if method.kind == WindowsComMethodKind.PROPERTY_GETTER
    )
    if property_methods != tuple(value.value for value in APPROVED_FIREWALL_PROPERTY_GETTERS):
        raise RuntimeError("Windows Firewall COM getter ABI is not the approved allowlist.")
    if len(property_methods) != APPROVED_PROPERTY_GETTER_COUNT \
            or MAX_PROPERTY_GETTERS_PER_RULE - len(property_methods) \
            != RESERVED_PROPERTY_GETTER_CAPACITY:
        raise RuntimeError("Windows Firewall COM getter budget is inconsistent.")
    if set(property_methods) & set(PROHIBITED_FIREWALL_COM_MEMBERS):
        raise RuntimeError("Windows Firewall COM ABI exposes prohibited members.")


_validate_contract()
