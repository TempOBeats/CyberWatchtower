"""Native Windows Firewall COM adapters confined to the isolated helper."""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
import sys
import uuid

from .firewall_com_contracts import (
    CLSID_NET_FW_POLICY2,
    IID_IENUMVARIANT,
    IID_INET_FW_POLICY2,
    IID_INET_FW_RULE,
    IID_INET_FW_RULE2,
    IID_INET_FW_RULE3,
    WINDOWS_FIREWALL_COM_INIT_FLAGS,
    WindowsComContractError,
    WindowsComFailureCategory,
    WindowsComInitializationLease,
    WindowsComInitializationResult,
    WindowsOwnedBstr,
    WindowsOwnedVariant,
    WindowsSafeArrayElementType,
    WindowsSafeArrayValue,
    WindowsVariantType,
)
from .firewall_rule_collection import (
    WindowsFirewallEnumerationState,
    WindowsFirewallEnumerationStep,
    collect_windows_firewall_rules_from_collection,
)
from .firewall_rule_models import (
    WindowsFirewallPolicyView,
    WindowsFirewallRuleCollectionResult,
    WindowsFirewallRuleResultCode,
)
from .firewall_rule_reader import (
    WindowsComInterfaceAvailability,
    WindowsFirewallRule2Query,
    WindowsFirewallRule3Query,
)
_S_OK = 0
_S_FALSE = 1
_RPC_E_CHANGED_MODE = 0x80010106
_E_ACCESSDENIED = 0x80070005
_E_NOINTERFACE = 0x80004002
_REGDB_E_CLASSNOTREG = 0x80040154
_CLSCTX_INPROC_SERVER = 0x1
_VT_EMPTY = 0
_VT_BSTR = 8
_VT_DISPATCH = 9
_VT_BOOL = 11
_VT_VARIANT = 12
_VT_ARRAY = 0x2000
_VARIANT_TRUE = -1


class _GUID(ctypes.Structure):
    _fields_ = [
        ("data1", ctypes.c_uint32), ("data2", ctypes.c_uint16),
        ("data3", ctypes.c_uint16), ("data4", ctypes.c_ubyte * 8),
    ]

    @classmethod
    def parse(cls, text: str) -> "_GUID":
        raw = uuid.UUID(text).bytes_le
        value = cls()
        ctypes.memmove(ctypes.byref(value), raw, 16)
        return value


class _VariantRecord(ctypes.Structure):
    _fields_ = [("record", ctypes.c_void_p), ("record_info", ctypes.c_void_p)]


class _VariantValue(ctypes.Union):
    _fields_ = [
        ("long_value", ctypes.c_int32), ("bool_value", ctypes.c_int16),
        ("bstr", ctypes.c_void_p), ("dispatch", ctypes.c_void_p),
        ("unknown", ctypes.c_void_p), ("array", ctypes.c_void_p),
        ("by_reference", ctypes.c_void_p), ("record", _VariantRecord),
    ]


class _VARIANT(ctypes.Structure):
    _anonymous_ = ("value",)
    _fields_ = [
        ("vt", ctypes.c_uint16), ("reserved1", ctypes.c_uint16),
        ("reserved2", ctypes.c_uint16), ("reserved3", ctypes.c_uint16),
        ("value", _VariantValue),
    ]


def collect_native_windows_firewall_rules(
    runtime: object | None = None,
) -> WindowsFirewallRuleCollectionResult:
    """Collect CURRENT_POLICY_VIEW through fixed native adapters inside helper."""

    native = runtime
    lease = None
    policy = None
    result = _failure(WindowsFirewallRuleResultCode.INTERNAL_ERROR)
    primary = None
    try:
        if native is None:
            native = _CtypesFirewallRuntime.create()
        lease = native.initialize()
        policy = native.activate_policy2()
        rules = policy.get_rules()
        result = collect_windows_firewall_rules_from_collection(rules)
    except WindowsComContractError as exc:
        primary = WindowsFirewallRuleResultCode(exc.category.value)
    except (TypeError, ValueError):
        primary = WindowsFirewallRuleResultCode.INVALID_RESULT
    except Exception:
        primary = WindowsFirewallRuleResultCode.INTERNAL_ERROR
    cleanup_failed = False
    if policy is not None:
        try:
            policy.release()
        except Exception:
            cleanup_failed = True
    if lease is not None:
        try:
            lease.close()
        except Exception:
            cleanup_failed = True
    if primary is not None:
        return _failure(primary)
    if cleanup_failed:
        return _failure(WindowsFirewallRuleResultCode.INTERNAL_ERROR)
    return result


@dataclass(slots=True)
class _CtypesFirewallRuntime:
    ole32: object
    oleaut32: object

    @classmethod
    def create(cls) -> "_CtypesFirewallRuntime":
        if sys.platform != "win32":
            raise WindowsComContractError(WindowsComFailureCategory.API_UNAVAILABLE)
        try:
            runtime = cls(ctypes.WinDLL("ole32"), ctypes.WinDLL("oleaut32"))
            runtime.ole32.CoUninitialize.argtypes = []
            runtime.ole32.CoUninitialize.restype = None
            runtime.oleaut32.SysStringLen.argtypes = [ctypes.c_void_p]
            runtime.oleaut32.SysStringLen.restype = ctypes.c_uint32
            runtime.oleaut32.SysFreeString.argtypes = [ctypes.c_void_p]
            runtime.oleaut32.SysFreeString.restype = None
            return runtime
        except (AttributeError, OSError):
            raise WindowsComContractError(
                WindowsComFailureCategory.API_UNAVAILABLE
            ) from None

    def initialize(self) -> WindowsComInitializationLease:
        function = self.ole32.CoInitializeEx
        function.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        function.restype = ctypes.c_int32
        hr = _unsigned(function(None, WINDOWS_FIREWALL_COM_INIT_FLAGS))
        result = {
            _S_OK: WindowsComInitializationResult.S_OK,
            _S_FALSE: WindowsComInitializationResult.S_FALSE,
            _RPC_E_CHANGED_MODE: WindowsComInitializationResult.RPC_E_CHANGED_MODE,
        }.get(hr, WindowsComInitializationResult.FAILURE)
        return WindowsComInitializationLease(result, self.ole32.CoUninitialize)

    def activate_policy2(self):
        function = self.ole32.CoCreateInstance
        function.argtypes = [ctypes.POINTER(_GUID), ctypes.c_void_p, ctypes.c_uint32,
                             ctypes.POINTER(_GUID), ctypes.POINTER(ctypes.c_void_p)]
        function.restype = ctypes.c_int32
        clsid = _GUID.parse(CLSID_NET_FW_POLICY2)
        iid = _GUID.parse(IID_INET_FW_POLICY2)
        output = ctypes.c_void_p()
        _check_hresult(function(ctypes.byref(clsid), None, _CLSCTX_INPROC_SERVER,
                                ctypes.byref(iid), ctypes.byref(output)))
        if not output.value:
            raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)
        return _NativePolicy2(output, self)

    def call(self, pointer, slot, restype, *arguments):
        if not pointer.value:
            raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)
        try:
            table = ctypes.cast(pointer, ctypes.POINTER(
                ctypes.POINTER(ctypes.c_void_p))).contents
            address = table[slot]
            argument_types = tuple(
                ctypes.c_uint32 if isinstance(argument, ctypes.c_uint32)
                else ctypes.c_void_p
                for argument in arguments
            )
            prototype = ctypes.WINFUNCTYPE(
                restype, ctypes.c_void_p, *argument_types)
            return prototype(address)(pointer, *arguments)
        except WindowsComContractError:
            raise
        except Exception:
            raise WindowsComContractError(
                WindowsComFailureCategory.INTERNAL_ERROR
            ) from None

    def query(self, pointer, iid_text):
        iid = _GUID.parse(iid_text)
        output = ctypes.c_void_p()
        hr = self.call(pointer, 0, ctypes.c_int32, ctypes.byref(iid),
                       ctypes.byref(output))
        if _unsigned(hr) == _E_NOINTERFACE:
            return None
        _check_hresult(hr)
        if not output.value:
            raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)
        return output

    def release(self, pointer):
        self.call(pointer, 2, ctypes.c_uint32)

    def bstr(self, pointer, slot):
        output = ctypes.c_void_p()
        _check_hresult(self.call(pointer, slot, ctypes.c_int32,
                                 ctypes.byref(output)))
        if not output.value:
            return None
        try:
            length = self.oleaut32.SysStringLen(output)
            text = ctypes.wstring_at(output.value, length)
        except Exception:
            self.oleaut32.SysFreeString(output)
            raise WindowsComContractError(
                WindowsComFailureCategory.INVALID_RESULT
            ) from None
        if not text:
            self.oleaut32.SysFreeString(output)
            return None
        return WindowsOwnedBstr(text, lambda: self.oleaut32.SysFreeString(output))

    def scalar(self, pointer, slot):
        output = ctypes.c_int32()
        _check_hresult(self.call(pointer, slot, ctypes.c_int32,
                                 ctypes.byref(output)))
        return int(output.value)

    def boolean(self, pointer, slot):
        output = ctypes.c_int16()
        _check_hresult(self.call(pointer, slot, ctypes.c_int32,
                                 ctypes.byref(output)))
        if output.value not in (0, _VARIANT_TRUE):
            raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)
        return output.value == _VARIANT_TRUE

    def initialize_variant(self, variant):
        self.oleaut32.VariantInit(ctypes.byref(variant))

    def clear_variant(self, variant):
        _check_hresult(self.oleaut32.VariantClear(ctypes.byref(variant)))

    def interface_variant(self, pointer, slot):
        variant = _VARIANT()
        self.initialize_variant(variant)
        try:
            _check_hresult(self.call(pointer, slot, ctypes.c_int32,
                                     ctypes.byref(variant)))
            values = self._safearray_strings(variant)
            return WindowsOwnedVariant(
                WindowsVariantType.ARRAY_VARIANT,
                WindowsSafeArrayValue(1, WindowsSafeArrayElementType.VARIANT,
                                      values),
                lambda: None, lambda: self.clear_variant(variant),
            )
        except Exception:
            try:
                self.clear_variant(variant)
            except Exception:
                pass
            raise

    def _safearray_strings(self, variant):
        if variant.vt == _VT_EMPTY:
            return ()
        if variant.vt not in (_VT_ARRAY | _VT_VARIANT, _VT_ARRAY | _VT_BSTR) \
                or not variant.array:
            raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)
        array = ctypes.c_void_p(variant.array)
        if self.oleaut32.SafeArrayGetDim(array) != 1:
            raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)
        lower, upper = ctypes.c_int32(), ctypes.c_int32()
        _check_hresult(self.oleaut32.SafeArrayGetLBound(array, 1,
                                                       ctypes.byref(lower)))
        _check_hresult(self.oleaut32.SafeArrayGetUBound(array, 1,
                                                       ctypes.byref(upper)))
        if upper.value < lower.value:
            return ()
        count = upper.value - lower.value + 1
        if count > 256:
            raise WindowsComContractError(WindowsComFailureCategory.LIMIT_EXCEEDED)
        values = []
        for index_value in range(lower.value, upper.value + 1):
            index = ctypes.c_int32(index_value)
            if variant.vt == (_VT_ARRAY | _VT_BSTR):
                text_pointer = ctypes.c_void_p()
                _check_hresult(self.oleaut32.SafeArrayGetElement(
                    array, ctypes.byref(index), ctypes.byref(text_pointer)))
                try:
                    length = self.oleaut32.SysStringLen(text_pointer)
                    values.append(ctypes.wstring_at(text_pointer.value, length))
                finally:
                    if text_pointer.value:
                        self.oleaut32.SysFreeString(text_pointer)
            else:
                item = _VARIANT()
                self.initialize_variant(item)
                try:
                    _check_hresult(self.oleaut32.SafeArrayGetElement(
                        array, ctypes.byref(index), ctypes.byref(item)))
                    if item.vt != _VT_BSTR or not item.bstr:
                        raise WindowsComContractError(
                            WindowsComFailureCategory.INVALID_RESULT)
                    length = self.oleaut32.SysStringLen(item.bstr)
                    values.append(ctypes.wstring_at(item.bstr, length))
                finally:
                    self.clear_variant(item)
        return tuple(values)


class _NativeInterface:
    def __init__(self, pointer, runtime):
        self._pointer, self._runtime, self._released = pointer, runtime, False

    def release(self):
        if self._released:
            raise WindowsComContractError(WindowsComFailureCategory.INTERNAL_ERROR)
        self._released = True
        self._runtime.release(self._pointer)


class _NativePolicy2(_NativeInterface):
    def get_rules(self):
        output = ctypes.c_void_p()
        _check_hresult(self._runtime.call(self._pointer, 18, ctypes.c_int32,
                                          ctypes.byref(output)))
        if not output.value:
            raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)
        return _NativeRules(output, self._runtime)


class _NativeRules(_NativeInterface):
    def get_count(self):
        return self._runtime.scalar(self._pointer, 7)
    def get_new_enum(self):
        output = ctypes.c_void_p()
        _check_hresult(self._runtime.call(self._pointer, 11, ctypes.c_int32,
                                          ctypes.byref(output)))
        if not output.value:
            raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)
        return _NativeNewEnum(output, self._runtime)


class _NativeNewEnum(_NativeInterface):
    def query_enum_variant(self):
        output = self._runtime.query(self._pointer, IID_IENUMVARIANT)
        if output is None:
            raise WindowsComContractError(WindowsComFailureCategory.UNSUPPORTED)
        return _NativeEnumVariant(output, self._runtime)


class _NativeEnumVariant(_NativeInterface):
    def next_one(self):
        variant, fetched = _VARIANT(), ctypes.c_uint32()
        self._runtime.initialize_variant(variant)
        hr = self._runtime.call(self._pointer, 3, ctypes.c_int32,
                                ctypes.c_uint32(1), ctypes.byref(variant),
                                ctypes.byref(fetched))
        if _unsigned(hr) == _S_FALSE and fetched.value == 0:
            self._runtime.clear_variant(variant)
            return WindowsFirewallEnumerationStep(
                WindowsFirewallEnumerationState.END, 0)
        try:
            _check_hresult(hr)
            if fetched.value != 1 or variant.vt != _VT_DISPATCH \
                    or not variant.dispatch:
                raise WindowsComContractError(
                    WindowsComFailureCategory.INVALID_RESULT)
            identity = int(variant.dispatch)
            element = _NativeRuleElement(
                ctypes.c_void_p(identity), self._runtime
            )
            owned = WindowsOwnedVariant(
                WindowsVariantType.DISPATCH, element, lambda: None,
                lambda: self._runtime.clear_variant(variant),
            )
            return WindowsFirewallEnumerationStep(
                WindowsFirewallEnumerationState.ITEM, 1, owned)
        except Exception:
            self._runtime.clear_variant(variant)
            raise


class _NativeRuleElement:
    def __init__(self, pointer, runtime): self._pointer, self._runtime = pointer, runtime
    def query_rule(self):
        output = self._runtime.query(self._pointer, IID_INET_FW_RULE)
        if output is None:
            raise WindowsComContractError(WindowsComFailureCategory.UNSUPPORTED)
        return _NativeRule(output, self._runtime)


class _NativeRule(_NativeInterface):
    def get_enabled(self):
        return self._runtime.boolean(self._pointer, 33)
    def get_direction(self): return self._runtime.scalar(self._pointer, 27)
    def get_action(self): return self._runtime.scalar(self._pointer, 41)
    def get_profiles(self): return self._runtime.scalar(self._pointer, 37)
    def get_protocol(self): return self._runtime.scalar(self._pointer, 15)
    def get_local_ports(self):
        return self._runtime.bstr(self._pointer, 17)
    def get_remote_ports(self):
        return self._runtime.bstr(self._pointer, 19)
    def get_local_addresses(self):
        return self._runtime.bstr(self._pointer, 21)
    def get_remote_addresses(self):
        return self._runtime.bstr(self._pointer, 23)
    def get_application_name(self):
        return self._runtime.bstr(self._pointer, 11)
    def get_service_name(self):
        return self._runtime.bstr(self._pointer, 13)
    def get_interface_types(self):
        return self._runtime.bstr(self._pointer, 31)
    def get_interfaces(self):
        return self._runtime.interface_variant(self._pointer, 29)
    def get_icmp_types_and_codes(self):
        return self._runtime.bstr(self._pointer, 25)
    def get_edge_traversal(self):
        return self._runtime.boolean(self._pointer, 39)
    def query_rule2(self):
        output = self._runtime.query(self._pointer, IID_INET_FW_RULE2)
        return WindowsFirewallRule2Query(
            WindowsComInterfaceAvailability.AVAILABLE if output else
            WindowsComInterfaceAvailability.UNAVAILABLE,
            _NativeRule2(output, self._runtime) if output else None)
    def query_rule3(self):
        output = self._runtime.query(self._pointer, IID_INET_FW_RULE3)
        return WindowsFirewallRule3Query(
            WindowsComInterfaceAvailability.AVAILABLE if output else
            WindowsComInterfaceAvailability.UNAVAILABLE,
            _NativeRule3(output, self._runtime) if output else None)


class _NativeRule2(_NativeInterface):
    def get_edge_traversal_options(self):
        return self._runtime.scalar(self._pointer, 43)


class _NativeRule3(_NativeInterface):
    def get_local_app_package_id(self):
        return self._runtime.bstr(self._pointer, 45)
    def get_local_user_authorized_list(self):
        return self._runtime.bstr(self._pointer, 47)
    def get_remote_user_authorized_list(self):
        return self._runtime.bstr(self._pointer, 51)
    def get_remote_machine_authorized_list(self):
        return self._runtime.bstr(self._pointer, 53)
    def get_secure_flags(self): return self._runtime.scalar(self._pointer, 55)


def _unsigned(value): return int(value) & 0xFFFFFFFF


def _check_hresult(value):
    code = _unsigned(value)
    if code in (_S_OK, _S_FALSE):
        return
    category = WindowsComFailureCategory.INTERNAL_ERROR
    if code == _E_ACCESSDENIED:
        category = WindowsComFailureCategory.ACCESS_DENIED
    elif code == _REGDB_E_CLASSNOTREG:
        category = WindowsComFailureCategory.API_UNAVAILABLE
    raise WindowsComContractError(category)


def _failure(state):
    return WindowsFirewallRuleCollectionResult(
        state, WindowsFirewallPolicyView.CURRENT_POLICY_VIEW)
