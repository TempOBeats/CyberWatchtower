"""Lazy, read-only Windows-native implementation for system facts and identity."""

from __future__ import annotations

import sys

from .errors import WindowsFailureCode
from .models import RawMachineIdentity, RawWindowsSystemInfo, WindowsApiResult


_MAX_HOSTNAME_CHARS = 256
_MAX_USER_CHARS = 257
_ERROR_ACCESS_DENIED = 5
_ERROR_CALL_NOT_IMPLEMENTED = 120
_ERROR_INSUFFICIENT_BUFFER = 122
_ERROR_MORE_DATA = 234


class _NativeFailure(Exception):
    def __init__(self, code: WindowsFailureCode):
        super().__init__(code.value)
        self.code = code


def _native_error_code(value: object) -> WindowsFailureCode:
    if value == _ERROR_ACCESS_DENIED:
        return WindowsFailureCode.ACCESS_DENIED
    if value == _ERROR_CALL_NOT_IMPLEMENTED:
        return WindowsFailureCode.UNSUPPORTED
    return WindowsFailureCode.INTERNAL_ERROR


def _kernel32():
    import ctypes

    try:
        return ctypes.WinDLL("kernel32", use_last_error=True)
    except (AttributeError, OSError) as exc:
        del exc
        raise _NativeFailure(WindowsFailureCode.API_UNAVAILABLE) from None


def _advapi32():
    import ctypes

    try:
        return ctypes.WinDLL("advapi32", use_last_error=True)
    except (AttributeError, OSError) as exc:
        del exc
        raise _NativeFailure(WindowsFailureCode.API_UNAVAILABLE) from None


def _computer_name() -> str:
    import ctypes

    function = _kernel32().GetComputerNameExW
    function.argtypes = [ctypes.c_int, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_ulong)]
    function.restype = ctypes.c_int
    size = ctypes.c_ulong(0)
    if function(1, None, ctypes.byref(size)):
        raise _NativeFailure(WindowsFailureCode.INVALID_RESULT)
    error = ctypes.get_last_error()
    if error != _ERROR_MORE_DATA:
        raise _NativeFailure(_native_error_code(error))
    if not 0 < size.value <= _MAX_HOSTNAME_CHARS:
        raise _NativeFailure(WindowsFailureCode.INVALID_RESULT)
    buffer = ctypes.create_unicode_buffer(size.value)
    if not function(1, buffer, ctypes.byref(size)):
        raise _NativeFailure(_native_error_code(ctypes.get_last_error()))
    return buffer.value


def _windows_version() -> tuple[str, str]:
    try:
        version = sys.getwindowsversion()
        major = int(version.major)
        minor = int(version.minor)
        build = int(version.build)
    except (AttributeError, TypeError, ValueError, OverflowError) as exc:
        del exc
        raise _NativeFailure(WindowsFailureCode.INVALID_RESULT) from None
    if major < 0 or minor < 0 or build <= 0:
        raise _NativeFailure(WindowsFailureCode.INVALID_RESULT)
    return f"{major}.{minor}", str(build)


def _native_architecture() -> str:
    import ctypes

    class _ProcessorInfo(ctypes.Structure):
        _fields_ = [
            ("architecture", ctypes.c_ushort),
            ("reserved", ctypes.c_ushort),
        ]

    class _SystemInfoUnion(ctypes.Union):
        _fields_ = [
            ("oem_id", ctypes.c_ulong),
            ("processor", _ProcessorInfo),
        ]

    class _SystemInfo(ctypes.Structure):
        _anonymous_ = ("identity",)
        _fields_ = [
            ("identity", _SystemInfoUnion),
            ("page_size", ctypes.c_ulong),
            ("minimum_address", ctypes.c_void_p),
            ("maximum_address", ctypes.c_void_p),
            ("active_processor_mask", ctypes.c_size_t),
            ("processor_count", ctypes.c_ulong),
            ("processor_type", ctypes.c_ulong),
            ("allocation_granularity", ctypes.c_ulong),
            ("processor_level", ctypes.c_ushort),
            ("processor_revision", ctypes.c_ushort),
        ]

    function = _kernel32().GetNativeSystemInfo
    function.argtypes = [ctypes.POINTER(_SystemInfo)]
    function.restype = None
    info = _SystemInfo()
    function(ctypes.byref(info))
    return {0: "x86", 9: "AMD64", 12: "ARM64"}.get(
        int(info.processor.architecture), "UNKNOWN"
    )


def _current_user_label() -> str | None:
    import ctypes

    try:
        function = _advapi32().GetUserNameW
        function.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_ulong)]
        function.restype = ctypes.c_int
        size = ctypes.c_ulong(0)
        if function(None, ctypes.byref(size)):
            return None
        if ctypes.get_last_error() != _ERROR_INSUFFICIENT_BUFFER:
            return None
        if not 0 < size.value <= _MAX_USER_CHARS:
            return None
        buffer = ctypes.create_unicode_buffer(size.value)
        if not function(buffer, ctypes.byref(size)):
            return None
        return buffer.value or None
    except (_NativeFailure, AttributeError, OSError):
        return None


class NativeWindowsApi:
    """Read-only native facade; DLL and registry access are lazy and Windows-only."""

    def get_system_info(self) -> WindowsApiResult[RawWindowsSystemInfo]:
        if sys.platform != "win32":
            return WindowsApiResult(failure=WindowsFailureCode.UNSUPPORTED)
        try:
            version, build = _windows_version()
            value = RawWindowsSystemInfo(
                hostname=_computer_name(),
                product_name="Windows",
                version=version,
                build=build,
                architecture=_native_architecture(),
                user_label=_current_user_label(),
            )
            return WindowsApiResult(value=value)
        except _NativeFailure as exc:
            code = exc.code
            del exc
            return WindowsApiResult(failure=code)
        except (AttributeError, OSError, TypeError, ValueError):
            return WindowsApiResult(failure=WindowsFailureCode.INTERNAL_ERROR)

    def get_machine_identity(self) -> WindowsApiResult[RawMachineIdentity]:
        if sys.platform != "win32":
            return WindowsApiResult(failure=WindowsFailureCode.UNSUPPORTED)
        try:
            import winreg

            access = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography",
                0,
                access,
            ) as key:
                value, value_type = winreg.QueryValueEx(key, "MachineGuid")
            if value_type != winreg.REG_SZ or not isinstance(value, str):
                return WindowsApiResult(failure=WindowsFailureCode.INVALID_RESULT)
            return WindowsApiResult(value=RawMachineIdentity(value))
        except PermissionError:
            return WindowsApiResult(failure=WindowsFailureCode.ACCESS_DENIED)
        except FileNotFoundError:
            return WindowsApiResult(failure=WindowsFailureCode.API_UNAVAILABLE)
        except OSError as exc:
            code = _native_error_code(getattr(exc, "winerror", None))
            del exc
            return WindowsApiResult(failure=code)
        except (TypeError, ValueError):
            return WindowsApiResult(failure=WindowsFailureCode.INVALID_RESULT)
