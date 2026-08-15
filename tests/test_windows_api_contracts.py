import dataclasses
import inspect
import json
import pkgutil
import unittest
from pathlib import Path

from cyberwatchtower.platform.windows import (
    FakeWindowsApi,
    RawFirewallProfile,
    RawMachineIdentity,
    RawProcessInfo,
    RawServiceInfo,
    RawTcpEndpoint,
    RawUdpEndpoint,
    RawWindowsSystemInfo,
    WindowsAddressFamily,
    WindowsApiFixture,
    WindowsApiProtocol,
    WindowsApiResult,
    WindowsFailureCode,
    WindowsFirewallAction,
    WindowsFirewallEnablement,
    WindowsFirewallProfile,
    WindowsProfileState,
    WindowsServiceState,
    WindowsTcpState,
    NativeBufferRead,
    read_bounded_native_table,
)


def success(value):
    return WindowsApiResult(value=value)


def failure(code):
    return WindowsApiResult(failure=code)


class WindowsRawModelTests(unittest.TestCase):
    def test_models_are_immutable_bounded_and_deterministic(self):
        tcp = RawTcpEndpoint(
            WindowsAddressFamily.IPV4, "0.0.0.0", 443, 100,
            WindowsTcpState.LISTEN,
        )
        udp = RawUdpEndpoint(WindowsAddressFamily.IPV6, "::1", 5353, 101)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            tcp.port = 80
        self.assertEqual(tcp, RawTcpEndpoint(
            WindowsAddressFamily.IPV4, "0.0.0.0", 443, 100,
            WindowsTcpState.LISTEN,
        ))
        self.assertEqual(udp.address, "::1")

    def test_endpoint_validation_fails_closed(self):
        valid = (WindowsAddressFamily.IPV4, "127.0.0.1", 80, 4)
        reserved = (WindowsAddressFamily.IPV4, "127.0.0.1", 80, 0)
        invalid = (
            ("IPX", "127.0.0.1", 80, 4),
            (WindowsAddressFamily.IPV4, "::1", 80, 4),
            (WindowsAddressFamily.IPV4, "127.0.0.1", -1, 4),
            (WindowsAddressFamily.IPV4, "127.0.0.1", 65536, 4),
            (WindowsAddressFamily.IPV4, "127.0.0.1", 80, -1),
        )
        RawTcpEndpoint(*valid, WindowsTcpState.LISTEN)
        RawTcpEndpoint(*reserved, WindowsTcpState.LISTEN)
        for family, address, port, pid in invalid:
            with self.subTest(value=(family, address, port, pid)), self.assertRaises(
                (TypeError, ValueError)
            ):
                RawTcpEndpoint(family, address, port, pid, WindowsTcpState.LISTEN)

    def test_system_process_service_and_firewall_validation(self):
        RawWindowsSystemInfo("host", "Windows", "11", "26100", "AMD64")
        RawProcessInfo(4, "System")
        RawServiceInfo("Dnscache", "DNS Client", 100, WindowsServiceState.RUNNING)
        RawFirewallProfile(
            WindowsFirewallProfile.PUBLIC,
            WindowsProfileState.ACTIVE,
            WindowsFirewallEnablement.ENABLED,
            WindowsFirewallAction.BLOCK,
            False,
        )
        invalid_factories = (
            lambda: RawWindowsSystemInfo("bad\0host", "Windows", "11", "1", "x64"),
            lambda: RawProcessInfo(-1, "bad"),
            lambda: RawProcessInfo(1, "x" * 1025),
            lambda: RawServiceInfo("same", "same", 8, "RUNNING"),
            lambda: RawFirewallProfile(
                "PUBLIC", WindowsProfileState.ACTIVE,
                WindowsFirewallEnablement.ENABLED, WindowsFirewallAction.BLOCK,
            ),
        )
        for factory in invalid_factories:
            with self.subTest(factory=factory), self.assertRaises((TypeError, ValueError)):
                factory()

    def test_identity_is_redacted_nonserializable_and_strongly_contained(self):
        identity = RawMachineIdentity("token=RAW-MACHINE-IDENTITY-CANARY")
        self.assertNotIn("CANARY", repr(identity))
        self.assertNotIn("CANARY", str(identity))
        self.assertFalse(hasattr(identity, "__dict__"))
        with self.assertRaises(TypeError):
            json.dumps(identity)
        self.assertEqual(
            identity.consume_for_derivation(),
            "token=RAW-MACHINE-IDENTITY-CANARY",
        )

    def test_sensitive_or_instruction_like_text_is_not_accepted_as_raw_fact(self):
        values = (
            "token=SECRET", "password=SECRET", "api_key=SECRET",
            "environment=SECRET", "command_line=do evil", "bad\nvalue",
        )
        for value in values:
            with self.subTest(value=value), self.assertRaises(ValueError):
                RawProcessInfo(4, value)

    def test_process_path_is_diagnostic_redacted_and_command_fields_do_not_exist(self):
        process = RawProcessInfo(4, "service.exe", r"C:\Users\private\service.exe")
        self.assertNotIn("private", repr(process).casefold())
        fields = {item.name for item in dataclasses.fields(RawProcessInfo)}
        self.assertTrue(fields.isdisjoint({"command_line", "argv", "environment"}))


class WindowsResultAndBufferTests(unittest.TestCase):
    def test_failure_messages_are_deterministic_and_cannot_accept_native_text(self):
        result = failure(WindowsFailureCode.ACCESS_DENIED)
        self.assertEqual(result.message, "The Windows API denied access.")
        self.assertNotIn("native", repr(result).casefold())
        with self.assertRaises(TypeError):
            WindowsApiResult(failure=WindowsFailureCode.ACCESS_DENIED,
                             message="token=SECRET raw HRESULT")
        with self.assertRaises(ValueError):
            WindowsApiResult()
        with self.assertRaises(ValueError):
            WindowsApiResult(value=(), failure=WindowsFailureCode.INTERNAL_ERROR)

    def test_bounded_two_call_reader_resizes_and_returns_sorted_entries(self):
        calls = []

        def read(size):
            calls.append(size)
            if size < 64:
                return NativeBufferRead(required_size=64)
            return NativeBufferRead(
                required_size=64,
                entries=(
                    RawUdpEndpoint(WindowsAddressFamily.IPV4, "0.0.0.0", 5353, 9),
                    RawUdpEndpoint(WindowsAddressFamily.IPV4, "127.0.0.1", 53, 8),
                ),
                complete=True,
            )

        result = read_bounded_native_table(lambda: 32, read, sort_key=lambda item: (
            item.port, item.address, item.pid
        ))
        self.assertEqual(calls, [32, 64])
        self.assertTrue(result.succeeded)
        self.assertEqual([item.port for item in result.value], [53, 5353])

    def test_buffer_limits_instability_and_callback_errors_fail_closed(self):
        cases = (
            (lambda: -1, lambda size: NativeBufferRead(complete=True)),
            (lambda: 0, lambda size: NativeBufferRead(complete=True)),
            (lambda: 2**31, lambda size: NativeBufferRead(complete=True)),
            (lambda: 8, lambda size: NativeBufferRead(required_size=size)),
            (lambda: 8, lambda size: (_ for _ in ()).throw(RuntimeError("token=SECRET"))),
        )
        for size_query, reader in cases:
            with self.subTest(size_query=size_query):
                result = read_bounded_native_table(size_query, reader, max_size=1024)
                self.assertFalse(result.succeeded)
                self.assertIn(result.failure, {
                    WindowsFailureCode.BUFFER_UNSTABLE,
                    WindowsFailureCode.INVALID_RESULT,
                    WindowsFailureCode.INTERNAL_ERROR,
                })
                self.assertNotIn("SECRET", repr(result))

    def test_retry_exhaustion_is_a_typed_unstable_buffer_failure(self):
        seen = []

        def reader(size):
            seen.append(size)
            return NativeBufferRead(required_size=size * 2)

        result = read_bounded_native_table(
            lambda: 8, reader, max_attempts=3, max_size=1024
        )
        self.assertEqual(seen, [8, 16, 32])
        self.assertEqual(result.failure, WindowsFailureCode.BUFFER_UNSTABLE)

    def test_excessive_duplicate_and_partial_entries_fail_closed(self):
        endpoint = RawUdpEndpoint(WindowsAddressFamily.IPV4, "127.0.0.1", 53, 8)
        duplicate = read_bounded_native_table(
            lambda: 8,
            lambda size: NativeBufferRead(8, (endpoint, endpoint), True),
        )
        excessive = read_bounded_native_table(
            lambda: 8,
            lambda size: NativeBufferRead(8, tuple(range(5)), True),
            max_entries=4,
        )
        partial = read_bounded_native_table(
            lambda: 8,
            lambda size: NativeBufferRead(16, (endpoint,), False),
        )
        self.assertEqual(duplicate.failure, WindowsFailureCode.INVALID_RESULT)
        self.assertEqual(excessive.failure, WindowsFailureCode.INVALID_RESULT)
        self.assertEqual(partial.failure, WindowsFailureCode.INVALID_RESULT)


class FakeWindowsApiTests(unittest.TestCase):
    def fixture(self):
        services = (
            RawServiceInfo("ServiceB", "Service B", 40, WindowsServiceState.RUNNING),
            RawServiceInfo("ServiceA", "Service A", 40, WindowsServiceState.RUNNING),
        )
        return WindowsApiFixture(
            system_info=success(RawWindowsSystemInfo(
                "fixture", "Windows", "11", "26100", "AMD64"
            )),
            machine_identity=success(RawMachineIdentity("fixture-machine-id")),
            tcp_endpoints=success((RawTcpEndpoint(
                WindowsAddressFamily.IPV4, "0.0.0.0", 443, 40,
                WindowsTcpState.LISTEN,
            ),)),
            udp_endpoints=success((RawUdpEndpoint(
                WindowsAddressFamily.IPV4, "127.0.0.1", 53, 41,
            ),)),
            processes=((40, success(RawProcessInfo(40, "service.exe"))),),
            services=success(services),
            firewall_profiles=success((RawFirewallProfile(
                WindowsFirewallProfile.PUBLIC,
                WindowsProfileState.ACTIVE,
                WindowsFirewallEnablement.ENABLED,
                WindowsFirewallAction.BLOCK,
                False,
            ),)),
        )

    def test_fake_satisfies_protocol_and_is_deterministic(self):
        first = FakeWindowsApi(self.fixture())
        second = FakeWindowsApi(self.fixture())
        self.assertIsInstance(first, WindowsApiProtocol)
        self.assertEqual(first.get_system_info(), second.get_system_info())
        self.assertEqual(first.get_tcp_endpoints(), second.get_tcp_endpoints())
        self.assertEqual(
            [item.service_name for item in first.list_services().value],
            ["ServiceA", "ServiceB"],
        )
        self.assertEqual(
            [item.pid for item in first.list_services().value],
            [40, 40],
        )

    def test_fake_models_access_denial_missing_api_and_process_disappearance(self):
        fixture = dataclasses.replace(
            self.fixture(),
            tcp_endpoints=failure(WindowsFailureCode.ACCESS_DENIED),
            firewall_profiles=failure(WindowsFailureCode.API_UNAVAILABLE),
        )
        fake = FakeWindowsApi(fixture)
        self.assertEqual(fake.get_tcp_endpoints().failure, WindowsFailureCode.ACCESS_DENIED)
        self.assertEqual(
            fake.get_firewall_profiles().failure,
            WindowsFailureCode.API_UNAVAILABLE,
        )
        self.assertEqual(
            fake.get_process_image(999).failure,
            WindowsFailureCode.PROCESS_DISAPPEARED,
        )

    def test_fixture_rejects_duplicate_endpoints_and_duplicate_process_keys(self):
        endpoint = RawUdpEndpoint(WindowsAddressFamily.IPV4, "127.0.0.1", 53, 8)
        with self.assertRaises(ValueError):
            dataclasses.replace(self.fixture(), udp_endpoints=success((endpoint, endpoint)))
        process = success(RawProcessInfo(4, "System"))
        with self.assertRaises(ValueError):
            dataclasses.replace(self.fixture(), processes=((4, process), (4, process)))


class WindowsBoundarySecurityTests(unittest.TestCase):
    def test_package_imports_on_non_windows_and_has_no_execution_surface(self):
        import cyberwatchtower.platform.windows as windows

        names = {name.casefold() for name, _ in inspect.getmembers(WindowsApiProtocol)}
        prohibited_names = {"run_command", "execute", "powershell", "subprocess",
                            "shell", "query", "invoke"}
        self.assertTrue(names.isdisjoint(prohibited_names))
        self.assertIs(windows.FakeWindowsApi, FakeWindowsApi)

    def test_package_has_no_prohibited_imports_or_calls(self):
        import cyberwatchtower.platform.windows as windows

        root = Path(windows.__file__).parent
        prohibited = (
            "subprocess", "shell=true", "os.system", "cmd.exe", "powershell",
            "win32", "psutil", "windll", "windll", "socket.socket", "urllib",
            "requests", "cyberwatchtower.scanner", "cyberwatchtower.advisor",
            "cyberwatchtower.core", "cyberwatchtower.memory", "cyberwatchtower.reporting",
            "cyberwatchtower.model_gateway", "cyberwatchtower.authorization",
            "ctypes", "winreg", "comtypes", "pythoncom", "importlib", "__import__",
        )
        phase_one_modules = {"api", "buffer", "errors", "fake", "models"}
        sources = "\n".join(
            Path(module.module_finder.path, f"{module.name}.py").read_text(encoding="utf-8")
            for module in pkgutil.iter_modules([str(root)])
            if module.name in phase_one_modules
        ).casefold()
        for marker in prohibited:
            with self.subTest(marker=marker):
                self.assertNotIn(marker.casefold(), sources)

    def test_windows_raw_dtos_do_not_become_neutral_observations(self):
        from cyberwatchtower.platform.models import SystemObservation

        raw = RawWindowsSystemInfo("host", "Windows", "11", "26100", "AMD64")
        self.assertNotIsInstance(raw, SystemObservation)
        self.assertFalse(hasattr(raw, "to_mapping"))


if __name__ == "__main__":
    unittest.main()
