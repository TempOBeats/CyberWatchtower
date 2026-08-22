import ast
import ctypes
import dataclasses
import inspect
import ipaddress
import json
import struct
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cyberwatchtower.network import assess_network_exposure
from cyberwatchtower.platform import ListenerExposure
from cyberwatchtower.platform.windows import (
    FakeWindowsApi,
    NativeWindowsApi,
    RawFirewallProfile,
    RawMachineIdentity,
    RawProcessInfo,
    RawServiceInfo,
    RawTcpEndpoint,
    RawUdpEndpoint,
    RawWindowsSystemInfo,
    WindowsAddressFamily,
    WindowsApiFixture,
    WindowsApiResult,
    WindowsEndpointTable,
    WindowsEndpointTableDiagnostic,
    WindowsEndpointTableResultCode,
    WindowsEndpointValidationReason,
    WindowsFailureCode,
    WindowsNetworkApiProtocol,
    WindowsServiceState,
    WindowsTcpState,
    collect_windows_network,
)
from cyberwatchtower.platform.windows.native_network import (
    _EndpointValidationFailure,
    _diagnosed_endpoint_result,
    _endpoint_table,
    _read_endpoint_table,
    collect_tcp_endpoints,
    collect_udp_endpoints,
    decode_endpoint_table,
)
from cyberwatchtower.report_contracts import CoverageState


def success(value):
    return WindowsApiResult(value=value)


def failure(code):
    return WindowsApiResult(failure=code)


def fixture_api(*, tcp=(), udp=(), processes=(), services=(), tcp_result=None,
                udp_result=None, service_result=None):
    fixture = WindowsApiFixture(
        system_info=success(RawWindowsSystemInfo(
            "WINDOWS-HOST", "Windows", "11", "26100", "AMD64"
        )),
        machine_identity=success(RawMachineIdentity("fixture-machine-guid")),
        tcp_endpoints=tcp_result or success(tuple(tcp)),
        udp_endpoints=udp_result or success(tuple(udp)),
        processes=tuple(processes),
        services=service_result or success(tuple(services)),
        firewall_profiles=success(tuple[RawFirewallProfile, ...]()),
    )
    return FakeWindowsApi(fixture)


class WindowsEndpointNormalizationTests(unittest.TestCase):
    def test_all_address_protocol_and_reserved_pid_variants_are_retained(self):
        tcp = (
            RawTcpEndpoint(WindowsAddressFamily.IPV4, "0.0.0.0", 80, 4,
                           WindowsTcpState.LISTEN),
            RawTcpEndpoint(WindowsAddressFamily.IPV4, "127.0.0.1", 81, 10,
                           WindowsTcpState.LISTEN),
            RawTcpEndpoint(WindowsAddressFamily.IPV6, "::", 82, 11,
                           WindowsTcpState.LISTEN),
            RawTcpEndpoint(WindowsAddressFamily.IPV6, "::1", 83, 12,
                           WindowsTcpState.LISTEN),
            RawTcpEndpoint(WindowsAddressFamily.IPV6, "fe80::1%12", 84, 0,
                           WindowsTcpState.LISTEN),
        )
        udp = (
            RawUdpEndpoint(WindowsAddressFamily.IPV4, "192.0.2.10", 5353, 13),
            RawUdpEndpoint(WindowsAddressFamily.IPV6, "2001:db8::1", 5354, 14),
        )
        processes = tuple(
            (pid, success(RawProcessInfo(pid, f"process{pid}.exe")))
            for pid in (4, 10, 11, 12, 13, 14)
        )
        api = fixture_api(tcp=tcp, udp=udp, processes=processes)

        first = collect_windows_network(api)
        second = collect_windows_network(api)

        self.assertEqual(first, second)
        self.assertEqual(first.coverage, CoverageState.COMPLETE)
        self.assertEqual(len(first.observations), 7)
        by_port = {item.port: item for item in first.observations}
        self.assertEqual(by_port[80].exposure, ListenerExposure.ALL_INTERFACES)
        self.assertEqual(by_port[81].exposure, ListenerExposure.LOOPBACK)
        self.assertEqual(by_port[82].exposure, ListenerExposure.ALL_INTERFACES)
        self.assertEqual(by_port[83].exposure, ListenerExposure.LOOPBACK)
        self.assertEqual(by_port[84].address, "fe80::1%12")
        self.assertEqual(by_port[84].pid, 0)
        self.assertEqual(by_port[84].process, "unknown")
        self.assertEqual(by_port[5353].state, "UNCONN")

    def test_process_failures_and_pid_reuse_mismatch_do_not_erase_endpoint(self):
        endpoints = tuple(
            RawUdpEndpoint(WindowsAddressFamily.IPV4, "127.0.0.1", port, pid)
            for port, pid in ((1001, 101), (1002, 102), (1003, 103))
        )
        api = fixture_api(
            udp=endpoints,
            processes=(
                (101, failure(WindowsFailureCode.ACCESS_DENIED)),
                (102, failure(WindowsFailureCode.PROCESS_DISAPPEARED)),
                (103, success(RawProcessInfo(103, "protected.exe"))),
            ),
        )
        original = api.get_process_image

        def lookup(pid):
            if pid == 103:
                return success(RawProcessInfo(999, "reused.exe"))
            return original(pid)

        with patch.object(FakeWindowsApi, "get_process_image", side_effect=lookup):
            result = collect_windows_network(api)

        self.assertEqual(result.coverage, CoverageState.COMPLETE)
        self.assertEqual(len(result.observations), 3)
        self.assertTrue(all(item.process == "unknown" for item in result.observations))
        self.assertEqual({item.pid for item in result.observations}, {101, 102, 103})

    def test_service_attribution_is_exact_and_ambiguity_never_selects_first(self):
        endpoints = (
            RawTcpEndpoint(WindowsAddressFamily.IPV4, "0.0.0.0", 8080, 200,
                           WindowsTcpState.LISTEN),
            RawTcpEndpoint(WindowsAddressFamily.IPV4, "0.0.0.0", 8081, 201,
                           WindowsTcpState.LISTEN),
            RawTcpEndpoint(WindowsAddressFamily.IPV4, "0.0.0.0", 8082, 202,
                           WindowsTcpState.LISTEN),
        )
        services = (
            RawServiceInfo("OnlySvc", "Only Service", 200,
                           WindowsServiceState.RUNNING),
            RawServiceInfo("SharedA", "Shared A", 201,
                           WindowsServiceState.RUNNING),
            RawServiceInfo("SharedB", "Shared B", 201,
                           WindowsServiceState.RUNNING),
        )
        result = collect_windows_network(fixture_api(tcp=endpoints, services=services))
        by_port = {item.port: item for item in result.observations}

        self.assertEqual(by_port[8080].application, "windows-service:onlysvc")
        self.assertEqual(by_port[8080].application_name, "Only Service")
        self.assertFalse(by_port[8080].known_application)
        self.assertIsNone(by_port[8081].application)
        self.assertIsNone(by_port[8082].application)
        self.assertEqual(result.coverage, CoverageState.COMPLETE)

    def test_enrichment_failure_does_not_change_endpoint_coverage(self):
        endpoint = RawUdpEndpoint(
            WindowsAddressFamily.IPV4, "0.0.0.0", 53, 4
        )
        api = fixture_api(
            udp=(endpoint,),
            service_result=failure(WindowsFailureCode.ACCESS_DENIED),
        )
        with patch.object(
            FakeWindowsApi, "get_process_image", side_effect=RuntimeError("secret")
        ):
            result = collect_windows_network(api)
        self.assertEqual(result.coverage, CoverageState.COMPLETE)
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(result.observations[0].process, "unknown")

    def test_partial_required_table_retains_data_but_never_becomes_complete(self):
        endpoint = RawTcpEndpoint(
            WindowsAddressFamily.IPV4, "127.0.0.1", 443, 20,
            WindowsTcpState.LISTEN,
        )
        result = collect_windows_network(fixture_api(
            tcp_result=WindowsApiResult(
                (endpoint,), WindowsFailureCode.PARTIAL_RESULT,
                (WindowsEndpointTableDiagnostic(
                    WindowsEndpointTable.TCP_IPV6,
                    WindowsEndpointTableResultCode.BUFFER_UNSTABLE,
                ),),
            ),
            udp_result=WindowsApiResult(
                failure=WindowsFailureCode.ACCESS_DENIED,
                endpoint_diagnostics=(WindowsEndpointTableDiagnostic(
                    WindowsEndpointTable.UDP_IPV4,
                    WindowsEndpointTableResultCode.ACCESS_DENIED,
                ),),
            ),
        ))
        self.assertEqual(result.coverage, CoverageState.INCOMPLETE)
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(result.failure.code.value, "COLLECTOR_PERMISSION_DENIED")
        self.assertNotIn("TCP_IPV6", repr(result))
        self.assertNotIn("UDP_IPV4", repr(result))

        unavailable = collect_windows_network(fixture_api(
            tcp_result=failure(WindowsFailureCode.UNSUPPORTED),
            udp_result=failure(WindowsFailureCode.API_UNAVAILABLE),
        ))
        self.assertEqual(unavailable.coverage, CoverageState.UNKNOWN)
        self.assertEqual(unavailable.observations, ())

    def test_normalized_observation_feeds_existing_deterministic_interpretation(self):
        endpoint = RawTcpEndpoint(
            WindowsAddressFamily.IPV4, "0.0.0.0", 8080, 300,
            WindowsTcpState.LISTEN,
        )
        result = collect_windows_network(fixture_api(
            tcp=(endpoint,),
            processes=((300, success(RawProcessInfo(300, "python.exe"))),),
        ))
        finding = assess_network_exposure([
            result.observations[0].to_service_mapping()
        ])[0]
        self.assertEqual(finding["severity"], "MEDIUM")
        self.assertEqual(finding["title"], "Alternate HTTP service listening on all interfaces")
        self.assertFalse(hasattr(result.observations[0], "finding"))
        self.assertFalse(hasattr(result.observations[0], "recommendation"))
        self.assertFalse(hasattr(result.observations[0], "severity"))
        self.assertFalse(hasattr(result.observations[0], "score"))


class WindowsNativeEndpointValidationTests(unittest.TestCase):
    @staticmethod
    def _native_port(port):
        return int.from_bytes(port.to_bytes(2, "big") + b"\0\0", "little")

    def test_portable_native_decoding_covers_all_four_table_shapes(self):
        v4 = int.from_bytes(ipaddress.ip_address("127.0.0.1").packed, "little")
        tcp4 = struct.pack("<I6I", 1, 2, v4, self._native_port(80), 0, 0, 4)
        udp4 = struct.pack("<I3I", 1, v4, self._native_port(53), 0)
        local6 = ipaddress.ip_address("fe80::1").packed
        remote6 = bytes(16)
        tcp6 = struct.pack(
            "<I16sII16sIIII", 1, local6, 12, self._native_port(443),
            remote6, 0, 0, 2, 40,
        )
        udp6 = struct.pack(
            "<I16sIII", 1, local6, 12, self._native_port(5353), 41
        )

        self.assertEqual(
            decode_endpoint_table(tcp4, WindowsAddressFamily.IPV4, "tcp")[0].port,
            80,
        )
        self.assertEqual(
            decode_endpoint_table(udp4, WindowsAddressFamily.IPV4, "udp")[0].pid,
            0,
        )
        self.assertEqual(
            decode_endpoint_table(tcp6, WindowsAddressFamily.IPV6, "tcp")[0].address,
            "fe80::1%12",
        )
        self.assertEqual(
            decode_endpoint_table(udp6, WindowsAddressFamily.IPV6, "udp")[0].port,
            5353,
        )

    def test_malformed_truncated_nonlistener_and_duplicate_tables_fail_closed(self):
        v4 = int.from_bytes(ipaddress.ip_address("0.0.0.0").packed, "little")
        row = struct.pack("<6I", 2, v4, self._native_port(80), 0, 0, 4)
        cases = (
            b"",
            struct.pack("<I", 1),
            struct.pack("<I", 2) + row,
            struct.pack("<I", 1) + struct.pack(
                "<6I", 5, v4, self._native_port(80), 0, 0, 4
            ),
            struct.pack("<I", 2) + row + row,
        )
        for data in cases:
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                decode_endpoint_table(data, WindowsAddressFamily.IPV4, "tcp")

    def test_udp4_layout_matches_fixed_width_windows_sdk_contract(self):
        class MibUdpRowOwnerPid(ctypes.Structure):
            _fields_ = (
                ("local_address", ctypes.c_uint32),
                ("local_port", ctypes.c_uint32),
                ("owning_pid", ctypes.c_uint32),
            )

        class MibUdpTableOwnerPid(ctypes.Structure):
            _fields_ = (
                ("entry_count", ctypes.c_uint32),
                ("table", MibUdpRowOwnerPid * 1),
            )

        self.assertEqual(ctypes.sizeof(MibUdpRowOwnerPid), 12)
        self.assertEqual(ctypes.alignment(MibUdpRowOwnerPid), 4)
        self.assertEqual(MibUdpTableOwnerPid.table.offset, 4)
        self.assertEqual(
            tuple(getattr(MibUdpRowOwnerPid, name).offset for name in (
                "local_address", "local_port", "owning_pid"
            )),
            (0, 4, 8),
        )

    def test_udp6_layout_matches_fixed_width_windows_sdk_contract(self):
        class MibUdp6RowOwnerPid(ctypes.Structure):
            _fields_ = (
                ("local_address", ctypes.c_ubyte * 16),
                ("local_scope_id", ctypes.c_uint32),
                ("local_port", ctypes.c_uint32),
                ("owning_pid", ctypes.c_uint32),
            )

        class MibUdp6TableOwnerPid(ctypes.Structure):
            _fields_ = (
                ("entry_count", ctypes.c_uint32),
                ("table", MibUdp6RowOwnerPid * 1),
            )

        self.assertEqual(ctypes.sizeof(MibUdp6RowOwnerPid), 28)
        self.assertEqual(ctypes.alignment(MibUdp6RowOwnerPid), 4)
        self.assertEqual(MibUdp6TableOwnerPid.table.offset, 4)
        self.assertEqual(
            tuple(getattr(MibUdp6RowOwnerPid, name).offset for name in (
                "local_address", "local_scope_id", "local_port", "owning_pid"
            )),
            (0, 16, 20, 24),
        )

    def test_udp4_validation_branches_have_closed_sanitized_reasons(self):
        zero_port_row = struct.pack("<3I", 0, 0, 4)
        cases = (
            (b"", WindowsEndpointValidationReason.TABLE_HEADER_INVALID),
            (
                struct.pack("<I", 65_537),
                WindowsEndpointValidationReason.ENTRY_COUNT_INVALID,
            ),
            (
                struct.pack("<I", 1),
                WindowsEndpointValidationReason.BUFFER_SIZE_MISMATCH,
            ),
            (
                struct.pack("<I", 1) + zero_port_row,
                WindowsEndpointValidationReason.PORT_ENCODING_INVALID,
            ),
        )
        for data, expected in cases:
            with self.subTest(reason=expected), self.assertRaises(
                _EndpointValidationFailure
            ) as raised:
                decode_endpoint_table(data, WindowsAddressFamily.IPV4, "udp")
            self.assertEqual(raised.exception.reason, expected)

    def test_udp4_duplicate_owner_rows_are_one_semantic_endpoint(self):
        row = struct.pack("<3I", 0, self._native_port(53), 4)
        payload = struct.pack("<I", 2) + row + row

        endpoints = decode_endpoint_table(
            payload, WindowsAddressFamily.IPV4, "udp"
        )

        self.assertEqual(endpoints, (
            RawUdpEndpoint(WindowsAddressFamily.IPV4, "0.0.0.0", 53, 4),
        ))

    def test_udp4_duplicate_owner_rows_keep_native_table_complete(self):
        row = struct.pack("<3I", 0, self._native_port(53), 4)
        payload = struct.pack("<I", 2) + row + row

        class FixedNativeTable:
            def __call__(self, buffer, size_pointer, *_args):
                size_pointer._obj.value = len(payload)
                if buffer is None:
                    return 122
                ctypes.memmove(buffer, payload, len(payload))
                return 0

        api = SimpleNamespace(GetExtendedUdpTable=FixedNativeTable())
        with patch(
            "cyberwatchtower.platform.windows.native_network._iphlpapi",
            return_value=api,
        ):
            result = _read_endpoint_table(WindowsAddressFamily.IPV4, "udp")

        self.assertEqual(result.value, (
            RawUdpEndpoint(WindowsAddressFamily.IPV4, "0.0.0.0", 53, 4),
        ))
        self.assertIsNone(result.failure)
        self.assertEqual(result.endpoint_diagnostics, (
            WindowsEndpointTableDiagnostic(
                WindowsEndpointTable.UDP_IPV4,
                WindowsEndpointTableResultCode.COMPLETE,
            ),
        ))
        normalized = collect_windows_network(fixture_api(udp_result=result))
        self.assertEqual(normalized.coverage, CoverageState.COMPLETE)
        self.assertEqual(len(normalized.observations), 1)

    def test_udp4_duplicate_prefix_does_not_hide_truncation(self):
        row = struct.pack("<3I", 0, self._native_port(53), 4)
        truncated = struct.pack("<I", 3) + row + row

        with self.assertRaises(_EndpointValidationFailure) as raised:
            decode_endpoint_table(
                truncated, WindowsAddressFamily.IPV4, "udp"
            )

        self.assertEqual(
            raised.exception.reason,
            WindowsEndpointValidationReason.BUFFER_SIZE_MISMATCH,
        )

    def test_udp6_duplicate_owner_rows_are_one_semantic_endpoint(self):
        row = struct.pack(
            "<16sIII", bytes.fromhex("fe800000000000000000000000000001"),
            12, self._native_port(5353), 40,
        )
        payload = struct.pack("<I", 2) + row + row

        first = decode_endpoint_table(
            payload, WindowsAddressFamily.IPV6, "udp"
        )
        second = decode_endpoint_table(
            payload, WindowsAddressFamily.IPV6, "udp"
        )

        expected = (
            RawUdpEndpoint(
                WindowsAddressFamily.IPV6, "fe80::1%12", 5353, 40
            ),
        )
        self.assertEqual(first, expected)
        self.assertEqual(second, expected)

    def test_udp6_duplicate_owner_rows_keep_udp_and_network_complete(self):
        row = struct.pack(
            "<16sIII", bytes.fromhex("00000000000000000000000000000000"),
            0, self._native_port(5353), 40,
        )
        payload = struct.pack("<I", 2) + row + row

        class FixedNativeTable:
            def __call__(self, buffer, size_pointer, *_args):
                size_pointer._obj.value = len(payload)
                if buffer is None:
                    return 122
                ctypes.memmove(buffer, payload, len(payload))
                return 0

        api = SimpleNamespace(GetExtendedUdpTable=FixedNativeTable())
        with patch(
            "cyberwatchtower.platform.windows.native_network._iphlpapi",
            return_value=api,
        ):
            ipv6 = _read_endpoint_table(WindowsAddressFamily.IPV6, "udp")

        ipv4_endpoint = RawUdpEndpoint(
            WindowsAddressFamily.IPV4, "0.0.0.0", 53, 4
        )
        ipv4 = WindowsApiResult(
            (ipv4_endpoint,), endpoint_diagnostics=(
                WindowsEndpointTableDiagnostic(
                    WindowsEndpointTable.UDP_IPV4,
                    WindowsEndpointTableResultCode.COMPLETE,
                ),
            ),
        )
        with patch(
            "cyberwatchtower.platform.windows.native_network._read_endpoint_table",
            side_effect=(ipv4, ipv6),
        ):
            combined = collect_udp_endpoints()

        self.assertIsNone(ipv6.failure)
        self.assertEqual(ipv6.endpoint_diagnostics, (
            WindowsEndpointTableDiagnostic(
                WindowsEndpointTable.UDP_IPV6,
                WindowsEndpointTableResultCode.COMPLETE,
            ),
        ))
        self.assertIsNone(combined.failure)
        self.assertEqual(len(combined.value), 2)
        normalized = collect_windows_network(fixture_api(udp_result=combined))
        self.assertEqual(normalized.coverage, CoverageState.COMPLETE)
        self.assertEqual(len(normalized.observations), 2)

    def test_udp6_duplicate_prefix_does_not_hide_invalid_rows(self):
        valid = struct.pack(
            "<16sIII", bytes(16), 0, self._native_port(5353), 40
        )
        truncated = struct.pack("<I", 3) + valid + valid
        zero_port = struct.pack("<16sIII", bytes(16), 0, 0, 40)

        for payload, reason in (
            (truncated, WindowsEndpointValidationReason.BUFFER_SIZE_MISMATCH),
            (
                struct.pack("<I", 2) + valid + zero_port,
                WindowsEndpointValidationReason.PORT_ENCODING_INVALID,
            ),
        ):
            with self.subTest(reason=reason), self.assertRaises(
                _EndpointValidationFailure
            ) as raised:
                decode_endpoint_table(
                    payload, WindowsAddressFamily.IPV6, "udp"
                )
            self.assertEqual(raised.exception.reason, reason)

        one_row = struct.pack(
            "<I16sIII", 1, bytes(16), 0, self._native_port(5353), 40
        )
        with (
            patch(
                "cyberwatchtower.platform.windows.native_network._address_v6",
                side_effect=ValueError,
            ),
            self.assertRaises(_EndpointValidationFailure) as raised,
        ):
            decode_endpoint_table(
                one_row, WindowsAddressFamily.IPV6, "udp"
            )
        self.assertEqual(
            raised.exception.reason,
            WindowsEndpointValidationReason.ADDRESS_ENCODING_INVALID,
        )

    def test_tcp_duplicate_rows_remain_invalid(self):
        row = struct.pack("<6I", 2, 0, self._native_port(80), 0, 0, 4)
        payload = struct.pack("<I", 2) + row + row

        with self.assertRaises(_EndpointValidationFailure) as raised:
            decode_endpoint_table(
                payload, WindowsAddressFamily.IPV4, "tcp"
            )

        self.assertEqual(
            raised.exception.reason,
            WindowsEndpointValidationReason.DUPLICATE_ROWS,
        )

    def test_udp4_native_invalid_result_retains_only_validation_category(self):
        payload = struct.pack("<I3I", 1, 0, 0, 4)

        class FixedNativeTable:
            def __call__(self, buffer, size_pointer, *_args):
                size_pointer._obj.value = len(payload)
                if buffer is None:
                    return 122
                ctypes.memmove(buffer, payload, len(payload))
                return 0

        native_call = FixedNativeTable()
        api = SimpleNamespace(GetExtendedUdpTable=native_call)
        with patch(
            "cyberwatchtower.platform.windows.native_network._iphlpapi",
            return_value=api,
        ):
            result = _read_endpoint_table(WindowsAddressFamily.IPV4, "udp")

        self.assertEqual(result.failure, WindowsFailureCode.INVALID_RESULT)
        self.assertEqual(result.endpoint_diagnostics, (
            WindowsEndpointTableDiagnostic(
                WindowsEndpointTable.UDP_IPV4,
                WindowsEndpointTableResultCode.INVALID_RESULT,
                WindowsEndpointValidationReason.PORT_ENCODING_INVALID,
            ),
        ))

    def test_one_family_failure_is_a_typed_partial_protocol_result(self):
        endpoint = RawTcpEndpoint(
            WindowsAddressFamily.IPV4, "0.0.0.0", 80, 4,
            WindowsTcpState.LISTEN,
        )
        with patch(
            "cyberwatchtower.platform.windows.native_network._read_endpoint_table",
            side_effect=(
                WindowsApiResult(
                    (endpoint,), endpoint_diagnostics=(
                        WindowsEndpointTableDiagnostic(
                            WindowsEndpointTable.TCP_IPV4,
                            WindowsEndpointTableResultCode.COMPLETE,
                        ),
                    ),
                ),
                WindowsApiResult(
                    failure=WindowsFailureCode.ACCESS_DENIED,
                    endpoint_diagnostics=(WindowsEndpointTableDiagnostic(
                        WindowsEndpointTable.TCP_IPV6,
                        WindowsEndpointTableResultCode.ACCESS_DENIED,
                    ),),
                ),
            ),
        ):
            result = collect_tcp_endpoints()
        self.assertEqual(result.failure, WindowsFailureCode.PARTIAL_RESULT)
        self.assertEqual(result.value, (endpoint,))
        self.assertEqual(result.endpoint_diagnostics, (
            WindowsEndpointTableDiagnostic(
                WindowsEndpointTable.TCP_IPV4,
                WindowsEndpointTableResultCode.COMPLETE,
            ),
            WindowsEndpointTableDiagnostic(
                WindowsEndpointTable.TCP_IPV6,
                WindowsEndpointTableResultCode.ACCESS_DENIED,
            ),
        ))

    def test_all_four_table_ids_and_sanitized_result_codes_are_closed(self):
        cases = (
            (WindowsAddressFamily.IPV4, "tcp", WindowsEndpointTable.TCP_IPV4),
            (WindowsAddressFamily.IPV6, "tcp", WindowsEndpointTable.TCP_IPV6),
            (WindowsAddressFamily.IPV4, "udp", WindowsEndpointTable.UDP_IPV4),
            (WindowsAddressFamily.IPV6, "udp", WindowsEndpointTable.UDP_IPV6),
        )
        for family, protocol, expected in cases:
            with self.subTest(table=expected):
                table = _endpoint_table(family, protocol)
                complete = _diagnosed_endpoint_result(table, success(()))
                failed = _diagnosed_endpoint_result(
                    table, failure(WindowsFailureCode.BUFFER_UNSTABLE)
                )
                self.assertEqual(complete.endpoint_diagnostics, (
                    WindowsEndpointTableDiagnostic(
                        expected, WindowsEndpointTableResultCode.COMPLETE
                    ),
                ))
                self.assertEqual(failed.endpoint_diagnostics, (
                    WindowsEndpointTableDiagnostic(
                        expected, WindowsEndpointTableResultCode.BUFFER_UNSTABLE
                    ),
                ))

    def test_endpoint_diagnostics_cannot_carry_native_text_or_endpoint_data(self):
        fields = {
            item.name for item in dataclasses.fields(
                WindowsEndpointTableDiagnostic
            )
        }
        self.assertEqual(fields, {"table", "result", "reason"})
        diagnostic = WindowsEndpointTableDiagnostic(
            WindowsEndpointTable.UDP_IPV6,
            WindowsEndpointTableResultCode.INVALID_RESULT,
            WindowsEndpointValidationReason.BUFFER_SIZE_MISMATCH,
        )
        rendered = repr(diagnostic)
        for canary in (
            "token=SECRET", "native error", "command line", "address", "pid"
        ):
            self.assertNotIn(canary.casefold(), rendered.casefold())


class WindowsNetworkPrivacyAndBoundaryTests(unittest.TestCase):
    def test_full_path_and_native_error_canaries_do_not_cross_normalization(self):
        path_canary = r"C:\Users\private\PATH-CANARY\service.exe"
        endpoint = RawTcpEndpoint(
            WindowsAddressFamily.IPV4, "127.0.0.1", 9000, 500,
            WindowsTcpState.LISTEN,
        )
        api = fixture_api(
            tcp=(endpoint,),
            processes=((500, success(RawProcessInfo(500, "service.exe", path_canary))),),
            service_result=failure(WindowsFailureCode.INTERNAL_ERROR),
        )
        result = collect_windows_network(api)
        serialized = json.dumps([
            item.to_service_mapping() for item in result.observations
        ])
        self.assertNotIn("PATH-CANARY", serialized)
        self.assertNotIn("private", repr(result).casefold())
        self.assertNotIn("error", repr(result.failure).casefold())

    def test_phase_three_boundary_has_no_prohibited_execution_or_authority_surface(self):
        package = Path(__file__).parents[1] / "src/cyberwatchtower/platform/windows"
        sources = "\n".join(
            Path(package, name).read_text(encoding="utf-8").casefold()
            for name in ("api.py", "api_native.py", "native_network.py", "network.py")
        )
        for marker in (
            "subprocess", "shell=true", "os.system", "powershell", "cmd.exe",
            "netstat", "process_vm_read", "process_all_access", "sedebugprivilege",
            "openprocesstoken", "cyberwatchtower.memory", "cyberwatchtower.advisor",
            "cyberwatchtower.core", "cyberwatchtower.model_gateway",
        ):
            with self.subTest(marker=marker):
                self.assertNotIn(marker, sources)
        self.assertIn("process_query_limited_information = 0x1000", sources)
        methods = {name.casefold() for name, _ in inspect.getmembers(
            WindowsNetworkApiProtocol
        )}
        self.assertTrue(methods.isdisjoint({
            "execute", "invoke", "powershell", "query", "run_command", "shell",
        }))
        tree = ast.parse(Path(package, "native_network.py").read_text(encoding="utf-8"))
        top_imports = {
            alias.name
            for node in tree.body
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        self.assertEqual(top_imports, {"ntpath", "struct"})

    def test_non_windows_native_facade_is_import_safe_and_unsupported(self):
        native = NativeWindowsApi()
        self.assertIsInstance(native, WindowsNetworkApiProtocol)
        if sys.platform != "win32":
            self.assertEqual(native.get_tcp_endpoints().failure,
                             WindowsFailureCode.UNSUPPORTED)
            self.assertEqual(native.get_udp_endpoints().failure,
                             WindowsFailureCode.UNSUPPORTED)
            self.assertEqual(native.get_process_image(4).failure,
                             WindowsFailureCode.UNSUPPORTED)
            self.assertEqual(native.list_services().failure,
                             WindowsFailureCode.UNSUPPORTED)

    @unittest.skipUnless(sys.platform == "win32", "requires a real Windows host")
    def test_read_only_native_endpoint_functions(self):
        native = NativeWindowsApi()
        tcp = native.get_tcp_endpoints()
        udp = native.get_udp_endpoints()
        self.assertTrue(tcp.succeeded, tcp.endpoint_diagnostics)
        self.assertTrue(udp.succeeded, udp.endpoint_diagnostics)
        self.assertEqual(
            {item.table for item in (*tcp.endpoint_diagnostics,
                                     *udp.endpoint_diagnostics)},
            set(WindowsEndpointTable),
        )
        self.assertIsNotNone(native.list_services())


if __name__ == "__main__":
    unittest.main()
