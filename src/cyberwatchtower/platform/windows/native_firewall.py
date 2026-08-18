"""Lazy fixed-purpose read-only INetFwPolicy2 profile collection."""

from __future__ import annotations

from .errors import WindowsFailureCode
from .models import (
    RawFirewallProfile,
    WindowsApiResult,
    WindowsFirewallAction,
    WindowsFirewallEnablement,
    WindowsFirewallProfile,
    WindowsProfileState,
)


_COINIT_APARTMENTTHREADED = 0x2
_CLSCTX_INPROC_SERVER = 0x1
_S_OK = 0
_S_FALSE = 1
_RPC_E_CHANGED_MODE = 0x80010106
_E_ACCESSDENIED = 0x80070005
_REGDB_E_CLASSNOTREG = 0x80040154
_E_NOINTERFACE = 0x80004002

_NET_FW_PROFILE2_DOMAIN = 0x1
_NET_FW_PROFILE2_PRIVATE = 0x2
_NET_FW_PROFILE2_PUBLIC = 0x4
_VALID_CURRENT_PROFILE_MASK = 0x7
_NET_FW_ACTION_BLOCK = 0
_NET_FW_ACTION_ALLOW = 1

_VTABLE_RELEASE = 2
_VTABLE_CURRENT_PROFILE_TYPES = 7
_VTABLE_FIREWALL_ENABLED = 8
_VTABLE_BLOCK_ALL_INBOUND = 12
_VTABLE_DEFAULT_INBOUND_ACTION = 23

_CLSID_NET_FW_POLICY2 = "e2b3c97f-6ae1-41ac-817a-f6f92166d7dd"
_IID_NET_FW_POLICY2 = "98325047-c671-4174-8d81-defcd3f03186"

_PROFILE_ORDER = (
    (WindowsFirewallProfile.DOMAIN, _NET_FW_PROFILE2_DOMAIN),
    (WindowsFirewallProfile.PRIVATE, _NET_FW_PROFILE2_PRIVATE),
    (WindowsFirewallProfile.PUBLIC, _NET_FW_PROFILE2_PUBLIC),
)


class _NativeFailure(Exception):
    def __init__(self, code: WindowsFailureCode):
        super().__init__(code.value)
        self.code = code


def _hresult(value: int) -> int:
    return int(value) & 0xFFFFFFFF


def _failure_code(value: int) -> WindowsFailureCode:
    code = _hresult(value)
    if code == _E_ACCESSDENIED:
        return WindowsFailureCode.ACCESS_DENIED
    if code in {_REGDB_E_CLASSNOTREG, _E_NOINTERFACE}:
        return WindowsFailureCode.API_UNAVAILABLE
    return WindowsFailureCode.INTERNAL_ERROR


class _Policy2:
    """Owned fixed-purpose COM pointer with read-only semantic accessors."""

    __slots__ = ("_ctypes", "_interface", "_uninitialize")

    def __init__(self, ctypes_module, interface, *, uninitialize: bool) -> None:
        self._ctypes = ctypes_module
        self._interface = interface
        self._uninitialize = uninitialize

    def _address(self, index: int) -> int:
        ctypes = self._ctypes
        table = ctypes.cast(
            self._interface,
            ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)),
        ).contents
        address = table[index]
        if not address:
            raise _NativeFailure(WindowsFailureCode.API_UNAVAILABLE)
        return int(address)

    def _profile_long(self, index: int, profile: int) -> int:
        ctypes = self._ctypes
        prototype = ctypes.WINFUNCTYPE(
            ctypes.c_long,
            ctypes.c_void_p,
            ctypes.c_long,
            ctypes.POINTER(ctypes.c_long),
        )
        value = ctypes.c_long()
        result = prototype(self._address(index))(
            self._interface, profile, ctypes.byref(value)
        )
        if _hresult(result) != _S_OK:
            raise _NativeFailure(_failure_code(result))
        return int(value.value)

    def _profile_bool(self, index: int, profile: int) -> bool:
        ctypes = self._ctypes
        prototype = ctypes.WINFUNCTYPE(
            ctypes.c_long,
            ctypes.c_void_p,
            ctypes.c_long,
            ctypes.POINTER(ctypes.c_short),
        )
        value = ctypes.c_short()
        result = prototype(self._address(index))(
            self._interface, profile, ctypes.byref(value)
        )
        if _hresult(result) != _S_OK:
            raise _NativeFailure(_failure_code(result))
        return bool(value.value)

    def current_profile_mask(self) -> int:
        ctypes = self._ctypes
        prototype = ctypes.WINFUNCTYPE(
            ctypes.c_long, ctypes.c_void_p, ctypes.POINTER(ctypes.c_long)
        )
        value = ctypes.c_long()
        result = prototype(self._address(_VTABLE_CURRENT_PROFILE_TYPES))(
            self._interface, ctypes.byref(value)
        )
        if _hresult(result) != _S_OK:
            raise _NativeFailure(_failure_code(result))
        mask = int(value.value)
        if mask <= 0 or mask & ~_VALID_CURRENT_PROFILE_MASK:
            raise _NativeFailure(WindowsFailureCode.INVALID_RESULT)
        return mask

    def firewall_enabled(self, profile: int) -> bool:
        return self._profile_bool(_VTABLE_FIREWALL_ENABLED, profile)

    def block_all_inbound(self, profile: int) -> bool:
        return self._profile_bool(_VTABLE_BLOCK_ALL_INBOUND, profile)

    def default_inbound_action(self, profile: int) -> int:
        return self._profile_long(_VTABLE_DEFAULT_INBOUND_ACTION, profile)

    def close(self) -> None:
        ctypes = self._ctypes
        try:
            if self._interface:
                release = ctypes.WINFUNCTYPE(
                    ctypes.c_ulong, ctypes.c_void_p
                )(self._address(_VTABLE_RELEASE))
                release(self._interface)
        finally:
            self._interface = None
            if self._uninitialize:
                ctypes.WinDLL("ole32", use_last_error=True).CoUninitialize()
                self._uninitialize = False

    def __enter__(self) -> "_Policy2":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


def _guid(ctypes, value: str):
    import uuid

    class _Guid(ctypes.Structure):
        _fields_ = (
            ("data1", ctypes.c_uint32),
            ("data2", ctypes.c_uint16),
            ("data3", ctypes.c_uint16),
            ("data4", ctypes.c_ubyte * 8),
        )

    return _Guid.from_buffer_copy(uuid.UUID(value).bytes_le)


def _open_policy() -> _Policy2:
    import ctypes

    try:
        ole32 = ctypes.WinDLL("ole32", use_last_error=True)
    except (AttributeError, OSError) as exc:
        del exc
        raise _NativeFailure(WindowsFailureCode.API_UNAVAILABLE) from None
    ole32.CoInitializeEx.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    ole32.CoInitializeEx.restype = ctypes.c_long
    initialized = _hresult(ole32.CoInitializeEx(None, _COINIT_APARTMENTTHREADED))
    if initialized not in {_S_OK, _S_FALSE, _RPC_E_CHANGED_MODE}:
        raise _NativeFailure(_failure_code(initialized))
    should_uninitialize = initialized in {_S_OK, _S_FALSE}
    try:
        ole32.CoCreateInstance.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        ole32.CoCreateInstance.restype = ctypes.c_long
        clsid = _guid(ctypes, _CLSID_NET_FW_POLICY2)
        iid = _guid(ctypes, _IID_NET_FW_POLICY2)
        interface = ctypes.c_void_p()
        result = ole32.CoCreateInstance(
            ctypes.byref(clsid),
            None,
            _CLSCTX_INPROC_SERVER,
            ctypes.byref(iid),
            ctypes.byref(interface),
        )
        if _hresult(result) != _S_OK or not interface.value:
            raise _NativeFailure(_failure_code(result))
        return _Policy2(
            ctypes, interface, uninitialize=should_uninitialize
        )
    except Exception:
        if should_uninitialize:
            ole32.CoUninitialize()
        raise


def _action(value: int) -> WindowsFirewallAction:
    if value == _NET_FW_ACTION_ALLOW:
        return WindowsFirewallAction.ALLOW
    if value == _NET_FW_ACTION_BLOCK:
        return WindowsFirewallAction.BLOCK
    raise _NativeFailure(WindowsFailureCode.INVALID_RESULT)


def collect_firewall_profiles() -> WindowsApiResult[tuple[RawFirewallProfile, ...]]:
    """Read current Windows Firewall profile posture without modifying policy."""

    try:
        partial = False
        with _open_policy() as policy:
            active_mask = policy.current_profile_mask()
            profiles = []
            for profile, native_profile in _PROFILE_ORDER:
                state = (
                    WindowsProfileState.ACTIVE
                    if active_mask & native_profile
                    else WindowsProfileState.INACTIVE
                )
                try:
                    enabled = (
                        WindowsFirewallEnablement.ENABLED
                        if policy.firewall_enabled(native_profile)
                        else WindowsFirewallEnablement.DISABLED
                    )
                except _NativeFailure:
                    enabled = WindowsFirewallEnablement.UNKNOWN
                    partial = partial or state == WindowsProfileState.ACTIVE
                try:
                    inbound = _action(
                        policy.default_inbound_action(native_profile)
                    )
                except _NativeFailure:
                    inbound = WindowsFirewallAction.UNKNOWN
                    partial = partial or state == WindowsProfileState.ACTIVE
                try:
                    block_all = policy.block_all_inbound(native_profile)
                except _NativeFailure:
                    block_all = None
                profiles.append(RawFirewallProfile(
                    profile,
                    state,
                    enabled,
                    inbound,
                    block_all,
                ))
        return WindowsApiResult(
            tuple(profiles),
            WindowsFailureCode.PARTIAL_RESULT if partial else None,
        )
    except _NativeFailure as exc:
        code = exc.code
        del exc
        return WindowsApiResult(failure=code)
    except (AttributeError, OSError, OverflowError, TypeError, ValueError):
        return WindowsApiResult(failure=WindowsFailureCode.INTERNAL_ERROR)
