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
from .errors import (
    WindowsEndpointTable,
    WindowsEndpointTableDiagnostic,
    WindowsEndpointTableResultCode,
    WindowsEndpointValidationReason,
    WindowsFailureCode,
)
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


class _EndpointValidationFailure(ValueError):
    def __init__(self, reason: WindowsEndpointValidationReason):
        super().__init__(reason.value)
        self.reason = reason


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
        raise _EndpointValidationFailure(
            WindowsEndpointValidationReason.TABLE_HEADER_INVALID
        )
    if not isinstance(family, WindowsAddressFamily) or protocol not in {"tcp", "udp"}:
        raise _EndpointValidationFailure(
            WindowsEndpointValidationReason.TABLE_TYPE_INVALID
        )
    formats = {
        ("tcp", WindowsAddressFamily.IPV4): "<6I",
        ("tcp", WindowsAddressFamily.IPV6): "<16sII16sIIII",
        ("udp", WindowsAddressFamily.IPV4): "<3I",
        ("udp", WindowsAddressFamily.IPV6): "<16sIII",
    }
    row_format = formats[(protocol, family)]
    row_size = struct.calcsize(row_format)
    count = struct.unpack_from("<I", data, 0)[0]
    if count > MAX_ENDPOINTS:
        raise _EndpointValidationFailure(
            WindowsEndpointValidationReason.ENTRY_COUNT_INVALID
        )
    if 4 + count * row_size > len(data):
        raise _EndpointValidationFailure(
            WindowsEndpointValidationReason.BUFFER_SIZE_MISMATCH
        )

    entries = []
    offset = 4
    for _ in range(count):
        try:
            values = struct.unpack_from(row_format, data, offset)
        except struct.error:
            raise _EndpointValidationFailure(
                WindowsEndpointValidationReason.ROW_LAYOUT_INVALID
            ) from None
        offset += row_size
        if protocol == "tcp" and family == WindowsAddressFamily.IPV4:
            state, address, port, _remote, _remote_port, pid = values
            if state != _MIB_TCP_STATE_LISTEN:
                raise _EndpointValidationFailure(
                    WindowsEndpointValidationReason.ROW_LAYOUT_INVALID
                )
            entry = RawTcpEndpoint(
                family, _address_v4(address), _port(port), pid,
                WindowsTcpState.LISTEN,
            )
        elif protocol == "tcp":
            address, scope, port, _remote, _remote_scope, _remote_port, state, pid = values
            if state != _MIB_TCP_STATE_LISTEN:
                raise _EndpointValidationFailure(
                    WindowsEndpointValidationReason.ROW_LAYOUT_INVALID
                )
            entry = RawTcpEndpoint(
                family, _address_v6(address, scope), _port(port), pid,
                WindowsTcpState.LISTEN,
            )
        elif family == WindowsAddressFamily.IPV4:
            address, port, pid = values
            try:
                normalized_address = _address_v4(address)
            except ValueError:
                raise _EndpointValidationFailure(
                    WindowsEndpointValidationReason.ADDRESS_ENCODING_INVALID
                ) from None
            normalized_port = _port(port)
            if normalized_port == 0:
                raise _EndpointValidationFailure(
                    WindowsEndpointValidationReason.PORT_ENCODING_INVALID
                )
            entry = RawUdpEndpoint(
                family, normalized_address, normalized_port, pid
            )
        else:
            address, scope, port, pid = values
            try:
                normalized_address = _address_v6(address, scope)
            except ValueError:
                raise _EndpointValidationFailure(
                    WindowsEndpointValidationReason.ADDRESS_ENCODING_INVALID
                ) from None
            normalized_port = _port(port)
            if normalized_port == 0:
                raise _EndpointValidationFailure(
                    WindowsEndpointValidationReason.PORT_ENCODING_INVALID
                )
            entry = RawUdpEndpoint(
                family, normalized_address, normalized_port, pid
            )
        entries.append(entry)
    if len(set(entries)) != len(entries):
        raise _EndpointValidationFailure(
            WindowsEndpointValidationReason.DUPLICATE_ROWS
        )
    return tuple(sorted(
        entries,
        key=lambda item: (item.family.value, item.address, item.port, item.pid),
    ))


def _endpoint_table(
    family: WindowsAddressFamily,
    protocol: str,
) -> WindowsEndpointTable:
    return WindowsEndpointTable(f"{protocol.upper()}_{family.value}")


def _diagnosed_endpoint_result(
    table: WindowsEndpointTable,
    result: WindowsApiResult,
    reason: WindowsEndpointValidationReason | None = None,
) -> WindowsApiResult:
    table_result = (
        WindowsEndpointTableResultCode.COMPLETE
        if result.failure is None
        else WindowsEndpointTableResultCode(result.failure.value)
    )
    return WindowsApiResult(
        result.value,
        result.failure,
        (WindowsEndpointTableDiagnostic(table, table_result, reason),),
    )


def _read_endpoint_table(
    family: WindowsAddressFamily,
    protocol: str,
) -> WindowsApiResult[tuple[RawTcpEndpoint | RawUdpEndpoint, ...]]:
    import ctypes

    table = _endpoint_table(family, protocol)
    try:
        api = _iphlpapi()
    except _NativeFailure as exc:
        return _diagnosed_endpoint_result(
            table, WindowsApiResult(failure=exc.code)
        )
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
    validation_reason: WindowsEndpointValidationReason | None = None

    def size_query() -> int:
        nonlocal native_failure, validation_reason
        size = ctypes.c_uint32(0)
        result = function(
            None, ctypes.byref(size), False, native_family, table_class, 0
        )
        if result not in {_NO_ERROR, _ERROR_INSUFFICIENT_BUFFER}:
            native_failure = _failure_code(int(result))
            return 0
        if size.value <= 0:
            validation_reason = (
                WindowsEndpointValidationReason.BOUNDED_ACQUISITION_INVALID
            )
        return int(size.value)

    def reader(allocation: int):
        nonlocal native_failure, validation_reason
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
            validation_reason = (
                WindowsEndpointValidationReason.BUFFER_SIZE_MISMATCH
            )
            return NativeBufferRead(required_size=allocation)
        try:
            entries = decode_endpoint_table(
                bytes(buffer.raw[:returned_size.value]), family, protocol
            )
        except _EndpointValidationFailure as exc:
            native_failure = WindowsFailureCode.INVALID_RESULT
            validation_reason = exc.reason
            return NativeBufferRead(required_size=allocation)
        except (OverflowError, TypeError, ValueError):
            native_failure = WindowsFailureCode.INVALID_RESULT
            validation_reason = WindowsEndpointValidationReason.ROW_LAYOUT_INVALID
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
    result = (
        WindowsApiResult(failure=native_failure)
        if native_failure is not None else bounded
    )
    if (
        result.failure == WindowsFailureCode.INVALID_RESULT
        and validation_reason is None
    ):
        validation_reason = (
            WindowsEndpointValidationReason.BOUNDED_ACQUISITION_INVALID
        )
    return _diagnosed_endpoint_result(table, result, validation_reason)


def _combine_endpoint_results(
    results: tuple[WindowsApiResult[tuple], ...],
) -> WindowsApiResult[tuple]:
    entries = tuple(item for result in results for item in (result.value or ()))
    diagnostics = tuple(
        diagnostic
        for result in results
        for diagnostic in result.endpoint_diagnostics
    )
    diagnostic_tables = tuple(item.table for item in diagnostics)
    if len(set(diagnostic_tables)) != len(diagnostic_tables):
        return WindowsApiResult(failure=WindowsFailureCode.INVALID_RESULT)
    if len(set(entries)) != len(entries):
        return WindowsApiResult(
            failure=WindowsFailureCode.INVALID_RESULT,
            endpoint_diagnostics=diagnostics,
        )
    ordered = tuple(sorted(
        entries,
        key=lambda item: (item.family.value, item.address, item.port, item.pid),
    ))
    failures = tuple(result.failure for result in results if result.failure is not None)
    if failures:
        if ordered:
            return WindowsApiResult(
                ordered, WindowsFailureCode.PARTIAL_RESULT, diagnostics
            )
        return WindowsApiResult(
            failure=failures[0], endpoint_diagnostics=diagnostics
        )
    return WindowsApiResult(value=ordered, endpoint_diagnostics=diagnostics)


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
