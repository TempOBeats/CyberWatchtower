"""Lazy fixed-purpose Win32 endpoint, process, and service reads."""

from __future__ import annotations

import ntpath
import struct
from ipaddress import ip_address

from .buffer import (
    MAX_ENDPOINTS,
    MAX_NATIVE_BUFFER_BYTES,
    NativeBufferRead,
    read_bounded_native_table,
)
from .errors import WindowsFailureCode
from .models import (
    RawProcessInfo,
    RawServiceInfo,
    RawTcpEndpoint,
    RawUdpEndpoint,
    WindowsAddressFamily,
    WindowsApiResult,
    WindowsServiceState,
    WindowsTcpState,
)


_AF_INET = 2
_AF_INET6 = 23
_NO_ERROR = 0
_ERROR_ACCESS_DENIED = 5
_ERROR_INSUFFICIENT_BUFFER = 122
_ERROR_MORE_DATA = 234
_TCP_TABLE_OWNER_PID_LISTENER = 3
_UDP_TABLE_OWNER_PID = 1
_MIB_TCP_STATE_LISTEN = 2
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_SC_MANAGER_ENUMERATE_SERVICE = 0x0004
_SC_ENUM_PROCESS_INFO = 0
_SERVICE_WIN32 = 0x0030
_SERVICE_ACTIVE = 0x0001
_SERVICE_RUNNING = 4
_MAX_NATIVE_ATTEMPTS = 3
_MAX_PROCESS_PATH_CHARS = 32_768
_MAX_SERVICE_NAME_CHARS = 1024


class _NativeFailure(Exception):
    def __init__(self, code: WindowsFailureCode):
        super().__init__(code.value)
        self.code = code


def _failure_code(native_code: int) -> WindowsFailureCode:
    if native_code == _ERROR_ACCESS_DENIED:
        return WindowsFailureCode.ACCESS_DENIED
    return WindowsFailureCode.INTERNAL_ERROR


def _iphlpapi():
    import ctypes

    try:
        return ctypes.WinDLL("iphlpapi", use_last_error=True)
    except (AttributeError, OSError) as exc:
        del exc
        raise _NativeFailure(WindowsFailureCode.API_UNAVAILABLE) from None


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


def _port(native_value: int) -> int:
    raw = native_value.to_bytes(4, "little", signed=False)
    return int.from_bytes(raw[:2], "big")


def _address_v4(native_value: int) -> str:
    return str(ip_address(native_value.to_bytes(4, "little", signed=False)))


def _address_v6(raw: bytes, scope_id: int) -> str:
    parsed = ip_address(raw)
    text = str(parsed)
    if scope_id and parsed.is_link_local:
        text = f"{text}%{scope_id}"
    return text


def decode_endpoint_table(
    data: bytes,
    family: WindowsAddressFamily,
    protocol: str,
) -> tuple[RawTcpEndpoint | RawUdpEndpoint, ...]:
    """Validate a native endpoint table snapshot and return bounded raw DTOs."""

    if not isinstance(data, bytes) or len(data) < 4:
        raise ValueError("native endpoint table is truncated")
    if not isinstance(family, WindowsAddressFamily) or protocol not in {"tcp", "udp"}:
        raise ValueError("native endpoint table type is invalid")
    formats = {
        ("tcp", WindowsAddressFamily.IPV4): "<6I",
        ("tcp", WindowsAddressFamily.IPV6): "<16sII16sIIII",
        ("udp", WindowsAddressFamily.IPV4): "<3I",
        ("udp", WindowsAddressFamily.IPV6): "<16sIII",
    }
    row_format = formats[(protocol, family)]
    row_size = struct.calcsize(row_format)
    count = struct.unpack_from("<I", data, 0)[0]
    if count > MAX_ENDPOINTS or 4 + count * row_size > len(data):
        raise ValueError("native endpoint table count exceeds its buffer")

    entries = []
    offset = 4
    for _ in range(count):
        values = struct.unpack_from(row_format, data, offset)
        offset += row_size
        if protocol == "tcp" and family == WindowsAddressFamily.IPV4:
            state, address, port, _remote, _remote_port, pid = values
            if state != _MIB_TCP_STATE_LISTEN:
                raise ValueError("non-listener appeared in listener table")
            entry = RawTcpEndpoint(
                family, _address_v4(address), _port(port), pid,
                WindowsTcpState.LISTEN,
            )
        elif protocol == "tcp":
            address, scope, port, _remote, _remote_scope, _remote_port, state, pid = values
            if state != _MIB_TCP_STATE_LISTEN:
                raise ValueError("non-listener appeared in listener table")
            entry = RawTcpEndpoint(
                family, _address_v6(address, scope), _port(port), pid,
                WindowsTcpState.LISTEN,
            )
        elif family == WindowsAddressFamily.IPV4:
            address, port, pid = values
            entry = RawUdpEndpoint(family, _address_v4(address), _port(port), pid)
        else:
            address, scope, port, pid = values
            entry = RawUdpEndpoint(
                family, _address_v6(address, scope), _port(port), pid
            )
        entries.append(entry)
    if len(set(entries)) != len(entries):
        raise ValueError("native endpoint table contains duplicate rows")
    return tuple(sorted(
        entries,
        key=lambda item: (item.family.value, item.address, item.port, item.pid),
    ))


def _read_endpoint_table(
    family: WindowsAddressFamily,
    protocol: str,
) -> WindowsApiResult[tuple[RawTcpEndpoint | RawUdpEndpoint, ...]]:
    import ctypes

    try:
        api = _iphlpapi()
    except _NativeFailure as exc:
        return WindowsApiResult(failure=exc.code)
    function = api.GetExtendedTcpTable if protocol == "tcp" else api.GetExtendedUdpTable
    function.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_int,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint32,
    ]
    function.restype = ctypes.c_uint32
    native_family = _AF_INET if family == WindowsAddressFamily.IPV4 else _AF_INET6
    table_class = (
        _TCP_TABLE_OWNER_PID_LISTENER
        if protocol == "tcp" else _UDP_TABLE_OWNER_PID
    )
    native_failure: WindowsFailureCode | None = None

    def size_query() -> int:
        nonlocal native_failure
        size = ctypes.c_uint32(0)
        result = function(
            None, ctypes.byref(size), False, native_family, table_class, 0
        )
        if result not in {_NO_ERROR, _ERROR_INSUFFICIENT_BUFFER}:
            native_failure = _failure_code(int(result))
            return 0
        return int(size.value)

    def reader(allocation: int):
        nonlocal native_failure
        buffer = ctypes.create_string_buffer(allocation)
        returned_size = ctypes.c_uint32(allocation)
        result = function(
            buffer, ctypes.byref(returned_size), False,
            native_family, table_class, 0,
        )
        if result == _ERROR_INSUFFICIENT_BUFFER:
            return NativeBufferRead(required_size=int(returned_size.value))
        if result != _NO_ERROR:
            native_failure = _failure_code(int(result))
            return NativeBufferRead(required_size=allocation)
        if not 4 <= returned_size.value <= allocation:
            native_failure = WindowsFailureCode.INVALID_RESULT
            return NativeBufferRead(required_size=allocation)
        try:
            entries = decode_endpoint_table(
                bytes(buffer.raw[:returned_size.value]), family, protocol
            )
        except (OverflowError, TypeError, ValueError):
            native_failure = WindowsFailureCode.INVALID_RESULT
            return NativeBufferRead(required_size=allocation)
        return NativeBufferRead(
            required_size=int(returned_size.value),
            entries=entries,
            complete=True,
        )

    bounded = read_bounded_native_table(
        size_query,
        reader,
        max_size=MAX_NATIVE_BUFFER_BYTES,
        max_attempts=_MAX_NATIVE_ATTEMPTS,
        max_entries=MAX_ENDPOINTS,
        sort_key=lambda item: (
            item.family.value, item.address, item.port, item.pid
        ),
    )
    if native_failure is not None:
        return WindowsApiResult(failure=native_failure)
    return bounded


def _combine_endpoint_results(
    results: tuple[WindowsApiResult[tuple], ...],
) -> WindowsApiResult[tuple]:
    entries = tuple(item for result in results for item in (result.value or ()))
    if len(set(entries)) != len(entries):
        return WindowsApiResult(failure=WindowsFailureCode.INVALID_RESULT)
    ordered = tuple(sorted(
        entries,
        key=lambda item: (item.family.value, item.address, item.port, item.pid),
    ))
    failures = tuple(result.failure for result in results if result.failure is not None)
    if failures:
        if ordered:
            return WindowsApiResult(ordered, WindowsFailureCode.PARTIAL_RESULT)
        return WindowsApiResult(failure=failures[0])
    return WindowsApiResult(value=ordered)


def collect_tcp_endpoints() -> WindowsApiResult[tuple[RawTcpEndpoint, ...]]:
    return _combine_endpoint_results((
        _read_endpoint_table(WindowsAddressFamily.IPV4, "tcp"),
        _read_endpoint_table(WindowsAddressFamily.IPV6, "tcp"),
    ))


def collect_udp_endpoints() -> WindowsApiResult[tuple[RawUdpEndpoint, ...]]:
    return _combine_endpoint_results((
        _read_endpoint_table(WindowsAddressFamily.IPV4, "udp"),
        _read_endpoint_table(WindowsAddressFamily.IPV6, "udp"),
    ))


def query_process_image(pid: int) -> WindowsApiResult[RawProcessInfo]:
    import ctypes

    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return WindowsApiResult(failure=WindowsFailureCode.ACCESS_DENIED)
    try:
        kernel32 = _kernel32()
    except _NativeFailure as exc:
        return WindowsApiResult(failure=exc.code)
    open_process = kernel32.OpenProcess
    open_process.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    open_process.restype = ctypes.c_void_p
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int
    query_image = kernel32.QueryFullProcessImageNameW
    query_image.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    query_image.restype = ctypes.c_int
    handle = open_process(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return WindowsApiResult(failure=_failure_code(ctypes.get_last_error()))
    try:
        buffer = ctypes.create_unicode_buffer(_MAX_PROCESS_PATH_CHARS)
        size = ctypes.c_uint32(_MAX_PROCESS_PATH_CHARS)
        if not query_image(handle, 0, buffer, ctypes.byref(size)):
            native = ctypes.get_last_error()
            code = (
                WindowsFailureCode.PROCESS_DISAPPEARED
                if native in {6, 87, 1168} else _failure_code(native)
            )
            return WindowsApiResult(failure=code)
        if not 0 < size.value < _MAX_PROCESS_PATH_CHARS:
            return WindowsApiResult(failure=WindowsFailureCode.INVALID_RESULT)
        path = buffer.value
        image_name = ntpath.basename(path)
        return WindowsApiResult(value=RawProcessInfo(pid, image_name, path))
    except (TypeError, ValueError):
        return WindowsApiResult(failure=WindowsFailureCode.INVALID_RESULT)
    finally:
        close_handle(handle)


def _read_utf16_from_buffer(buffer, pointer: int) -> str:
    import ctypes

    base = ctypes.addressof(buffer)
    end = base + len(buffer.raw)
    if not base <= pointer < end:
        raise ValueError("service string pointer is outside native buffer")
    raw = buffer.raw[pointer - base:]
    limit = min(len(raw), (_MAX_SERVICE_NAME_CHARS + 1) * 2)
    terminator = next(
        (index for index in range(0, limit - 1, 2)
         if raw[index:index + 2] == b"\0\0"),
        None,
    )
    if terminator is None:
        raise ValueError("service string is not bounded")
    return raw[:terminator].decode("utf-16-le")


def list_active_services() -> WindowsApiResult[tuple[RawServiceInfo, ...]]:
    import ctypes

    class _ServiceStatusProcess(ctypes.Structure):
        _fields_ = [
            ("service_type", ctypes.c_uint32),
            ("current_state", ctypes.c_uint32),
            ("controls_accepted", ctypes.c_uint32),
            ("win32_exit_code", ctypes.c_uint32),
            ("service_specific_exit_code", ctypes.c_uint32),
            ("check_point", ctypes.c_uint32),
            ("wait_hint", ctypes.c_uint32),
            ("process_id", ctypes.c_uint32),
            ("service_flags", ctypes.c_uint32),
        ]

    class _ServiceEntry(ctypes.Structure):
        _fields_ = [
            ("service_name", ctypes.c_void_p),
            ("display_name", ctypes.c_void_p),
            ("status", _ServiceStatusProcess),
        ]

    try:
        advapi = _advapi32()
    except _NativeFailure as exc:
        return WindowsApiResult(failure=exc.code)
    open_manager = advapi.OpenSCManagerW
    open_manager.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
    open_manager.restype = ctypes.c_void_p
    enum_services = advapi.EnumServicesStatusExW
    enum_services.argtypes = [
        ctypes.c_void_p, ctypes.c_int, ctypes.c_uint32, ctypes.c_uint32,
        ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_wchar_p,
    ]
    enum_services.restype = ctypes.c_int
    close_service = advapi.CloseServiceHandle
    close_service.argtypes = [ctypes.c_void_p]
    close_service.restype = ctypes.c_int
    manager = open_manager(None, None, _SC_MANAGER_ENUMERATE_SERVICE)
    if not manager:
        return WindowsApiResult(failure=_failure_code(ctypes.get_last_error()))
    try:
        allocation = 0
        for _ in range(_MAX_NATIVE_ATTEMPTS):
            if allocation > MAX_NATIVE_BUFFER_BYTES:
                return WindowsApiResult(failure=WindowsFailureCode.BUFFER_UNSTABLE)
            buffer = ctypes.create_string_buffer(allocation) if allocation else None
            needed = ctypes.c_uint32(0)
            returned = ctypes.c_uint32(0)
            resume = ctypes.c_uint32(0)
            succeeded = enum_services(
                manager, _SC_ENUM_PROCESS_INFO, _SERVICE_WIN32, _SERVICE_ACTIVE,
                buffer, allocation, ctypes.byref(needed), ctypes.byref(returned),
                ctypes.byref(resume), None,
            )
            if not succeeded:
                native = ctypes.get_last_error()
                if native == _ERROR_MORE_DATA and needed.value > 0:
                    candidate = (
                        int(needed.value)
                        if allocation == 0
                        else max(allocation * 2, allocation + int(needed.value))
                    )
                    if candidate <= allocation or candidate > MAX_NATIVE_BUFFER_BYTES:
                        return WindowsApiResult(
                            failure=WindowsFailureCode.BUFFER_UNSTABLE
                        )
                    allocation = candidate
                    continue
                return WindowsApiResult(failure=_failure_code(native))
            if returned.value > MAX_ENDPOINTS:
                return WindowsApiResult(failure=WindowsFailureCode.INVALID_RESULT)
            if returned.value == 0:
                return WindowsApiResult(value=())
            if buffer is None:
                return WindowsApiResult(failure=WindowsFailureCode.INVALID_RESULT)
            required = returned.value * ctypes.sizeof(_ServiceEntry)
            if required > allocation:
                return WindowsApiResult(failure=WindowsFailureCode.INVALID_RESULT)
            services = []
            for index in range(returned.value):
                entry = _ServiceEntry.from_buffer_copy(
                    buffer.raw, index * ctypes.sizeof(_ServiceEntry)
                )
                if entry.status.process_id <= 0:
                    continue
                service_name = _read_utf16_from_buffer(buffer, entry.service_name)
                display_name = _read_utf16_from_buffer(buffer, entry.display_name)
                state = (
                    WindowsServiceState.RUNNING
                    if entry.status.current_state == _SERVICE_RUNNING
                    else WindowsServiceState.OTHER
                )
                services.append(RawServiceInfo(
                    service_name, display_name, entry.status.process_id, state
                ))
            if len(set(services)) != len(services):
                return WindowsApiResult(failure=WindowsFailureCode.INVALID_RESULT)
            return WindowsApiResult(value=tuple(sorted(
                services,
                key=lambda item: (
                    item.pid, item.service_name.casefold(), item.display_name.casefold()
                ),
            )))
        return WindowsApiResult(failure=WindowsFailureCode.BUFFER_UNSTABLE)
    except (OverflowError, TypeError, UnicodeError, ValueError):
        return WindowsApiResult(failure=WindowsFailureCode.INVALID_RESULT)
    finally:
        close_service(manager)
