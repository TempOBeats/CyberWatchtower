import ast
import inspect
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from cyberwatchtower.platform import ObservationDomain
from cyberwatchtower.platform.windows import (
    FakeWindowsApi,
    NativeWindowsApi,
    RawMachineIdentity,
    RawWindowsSystemInfo,
    WindowsApiFixture,
    WindowsApiResult,
    WindowsFailureCode,
    WindowsSystemApiProtocol,
    collect_windows_system,
)
from cyberwatchtower.report_contracts import CoverageState
from cyberwatchtower.system_identity import derive_system_id


def success(value):
    return WindowsApiResult(value=value)


def failure(code):
    return WindowsApiResult(failure=code)


def fake_api(
    *,
    identity="machine-guid-a",
    hostname="WINDOWS-HOST",
    user_label="Alice",
    version="11",
    build="26100",
    architecture="AMD64",
    identity_failure=None,
    system_failure=None,
    identity_partial=False,
):
    system = (
        failure(system_failure)
        if system_failure else success(RawWindowsSystemInfo(
            hostname, "Windows", version, build, architecture, user_label
        ))
    )
    machine = (
        failure(identity_failure)
        if identity_failure else success(RawMachineIdentity(identity))
    )
    if identity_partial:
        machine = WindowsApiResult(
            value=RawMachineIdentity(identity),
            failure=WindowsFailureCode.PARTIAL_RESULT,
        )
    unavailable = failure(WindowsFailureCode.UNSUPPORTED)
    return FakeWindowsApi(WindowsApiFixture(
        system_info=system,
        machine_identity=machine,
        tcp_endpoints=unavailable,
        udp_endpoints=unavailable,
        processes=(),
        services=unavailable,
        firewall_profiles=unavailable,
    ))


class WindowsSystemCollectorTests(unittest.TestCase):
    def test_success_normalizes_complete_system_observation(self):
        result = collect_windows_system(fake_api())
        self.assertEqual(result.domain, ObservationDomain.SYSTEM_INFORMATION)
        self.assertEqual(result.coverage, CoverageState.COMPLETE)
        self.assertIsNone(result.failure)
        self.assertEqual(result.observations[0].to_mapping(), {
            "system_id": derive_system_id("machine-guid-a"),
            "hostname": "WINDOWS-HOST",
            "username": "Alice",
            "operating_system": "Windows",
            "os_version": "11 (build 26100)",
            "architecture": "x86_64",
        })

    def test_identity_is_stable_and_independent_of_hostname_and_user(self):
        first = collect_windows_system(fake_api()).observations[0].system_id
        repeated = collect_windows_system(fake_api()).observations[0].system_id
        renamed = collect_windows_system(fake_api(
            hostname="RENAMED", user_label="Bob"
        )).observations[0].system_id
        different = collect_windows_system(fake_api(
            identity="machine-guid-b"
        )).observations[0].system_id
        self.assertEqual(first, repeated)
        self.assertEqual(first, renamed)
        self.assertNotEqual(first, different)

    def test_x64_arm64_and_x86_architectures_normalize(self):
        for raw, normalized in (
            ("AMD64", "x86_64"), ("ARM64", "arm64"), ("x86", "x86")
        ):
            with self.subTest(raw=raw):
                result = collect_windows_system(fake_api(architecture=raw))
                self.assertEqual(result.coverage, CoverageState.COMPLETE)
                self.assertEqual(result.observations[0].architecture, normalized)

    def test_unknown_architecture_is_unknown_not_complete(self):
        result = collect_windows_system(fake_api(architecture="UNKNOWN"))
        self.assertEqual(result.coverage, CoverageState.UNKNOWN)
        self.assertIsNone(result.observations[0].architecture)
        self.assertEqual(
            result.failure.message,
            "Windows native architecture could not be determined.",
        )

    def test_identity_failures_preserve_display_without_manufacturing_id(self):
        for failure_code, coverage in (
            (WindowsFailureCode.ACCESS_DENIED, CoverageState.INCOMPLETE),
            (WindowsFailureCode.INVALID_RESULT, CoverageState.INCOMPLETE),
            (WindowsFailureCode.API_UNAVAILABLE, CoverageState.UNKNOWN),
            (WindowsFailureCode.UNSUPPORTED, CoverageState.UNKNOWN),
        ):
            with self.subTest(failure=failure_code):
                result = collect_windows_system(fake_api(
                    identity_failure=failure_code
                ))
                self.assertEqual(result.coverage, coverage)
                mapping = result.observations[0].to_mapping()
                self.assertNotIn("system_id", mapping)
                self.assertEqual(mapping["hostname"], "WINDOWS-HOST")
                self.assertNotIn("machine-guid", repr(result))

        partial = collect_windows_system(fake_api(identity_partial=True))
        self.assertEqual(partial.coverage, CoverageState.INCOMPLETE)
        self.assertNotIn("system_id", partial.observations[0].to_mapping())

    def test_required_system_failure_has_no_partial_or_fabricated_observation(self):
        for code, coverage in (
            (WindowsFailureCode.ACCESS_DENIED, CoverageState.INCOMPLETE),
            (WindowsFailureCode.API_UNAVAILABLE, CoverageState.UNKNOWN),
        ):
            result = collect_windows_system(fake_api(system_failure=code))
            self.assertEqual(result.coverage, coverage)
            self.assertEqual(result.observations, ())

    def test_user_label_is_optional_for_complete_coverage(self):
        result = collect_windows_system(fake_api(user_label=None))
        self.assertEqual(result.coverage, CoverageState.COMPLETE)
        self.assertNotIn("username", result.observations[0].to_mapping())


class WindowsSystemValidationAndPrivacyTests(unittest.TestCase):
    def test_malformed_required_system_fields_fail_before_collection(self):
        cases = (
            ("", "Windows", "11", "26100", "AMD64", None),
            ("bad\0host", "Windows", "11", "26100", "AMD64", None),
            ("host", "", "11", "26100", "AMD64", None),
            ("host", "Windows", "", "26100", "AMD64", None),
            ("host", "Windows", "11", "", "AMD64", None),
        )
        for values in cases:
            with self.subTest(values=values), self.assertRaises(ValueError):
                RawWindowsSystemInfo(*values)

    def test_identity_rejects_empty_oversized_and_control_values(self):
        for value in ("", "x" * 257, "bad\0identity", "bad\u200bidentity"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                RawMachineIdentity(value)

    def test_identity_canary_is_only_transient_and_result_is_opaque(self):
        canary = "token=RAW-WINDOWS-IDENTITY-CANARY"
        result = collect_windows_system(fake_api(identity=canary))
        serialized = json.dumps(result.observations[0].to_mapping())
        self.assertNotIn(canary, serialized)
        self.assertNotIn("CANARY", repr(result))
        self.assertEqual(
            result.observations[0].system_id,
            derive_system_id(canary),
        )

    def test_sensitive_hostname_and_user_labels_fail_validation(self):
        for field in ("hostname", "user_label"):
            values = {
                "hostname": "host", "product_name": "Windows", "version": "11",
                "build": "26100", "architecture": "AMD64", "user_label": "user",
            }
            values[field] = "token=SECRET-CANARY"
            with self.subTest(field=field), self.assertRaises(ValueError):
                RawWindowsSystemInfo(**values)

    def test_phase_two_modules_have_no_downstream_authority_dependencies(self):
        import cyberwatchtower.platform.windows.system as system_module

        sources = "\n".join(
            Path(module.__file__).read_text(encoding="utf-8")
            for module in (system_module,)
        ).casefold()
        for marker in (
            "cyberwatchtower.scanner", "cyberwatchtower.reporting",
            "cyberwatchtower.memory", "cyberwatchtower.advisor",
            "cyberwatchtower.core", "cyberwatchtower.model_gateway",
        ):
            self.assertNotIn(marker, sources)


class NativeWindowsSystemBoundaryTests(unittest.TestCase):
    def test_native_facade_constructs_and_fails_safely_off_windows(self):
        native = NativeWindowsApi()
        self.assertIsInstance(native, WindowsSystemApiProtocol)
        if sys.platform != "win32":
            self.assertEqual(
                native.get_system_info().failure, WindowsFailureCode.UNSUPPORTED
            )
            self.assertEqual(
                native.get_machine_identity().failure,
                WindowsFailureCode.UNSUPPORTED,
            )

    def test_native_source_is_lazy_read_only_and_has_no_execution_surface(self):
        import cyberwatchtower.platform.windows.api_native as native_module

        source = Path(native_module.__file__).read_text(encoding="utf-8").casefold()
        tree = ast.parse(source)
        top_level_imports = {
            alias.name
            for node in tree.body
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        self.assertEqual(top_level_imports, {"sys"})
        for marker in (
            "subprocess", "shell=true", "os.system", "powershell", "cmd.exe",
            "socket.socket", "setvalue", "createkey", "deletekey", "savekey",
            "openprocess", "token", "sid", "formatmessage",
        ):
            with self.subTest(marker=marker):
                self.assertNotIn(marker, source)
        self.assertIn("openkey", source)
        self.assertIn("queryvalueex", source)
        self.assertNotIn("winreg", sys.modules if sys.platform != "win32" else {})
        protocol_names = {name for name, _ in inspect.getmembers(NativeWindowsApi)}
        self.assertTrue(protocol_names.isdisjoint({
            "run_command", "execute", "query", "invoke", "write_registry"
        }))

    def test_native_exception_text_is_replaced_by_typed_safe_failure(self):
        import cyberwatchtower.platform.windows.api_native as native_module

        canary = "token=NATIVE-ERROR-CANARY"
        with (
            patch.object(native_module.sys, "platform", "win32"),
            patch.object(native_module, "_windows_version", return_value=("11", "1")),
            patch.object(native_module, "_computer_name", side_effect=OSError(canary)),
        ):
            result = NativeWindowsApi().get_system_info()
        self.assertEqual(result.failure, WindowsFailureCode.INTERNAL_ERROR)
        self.assertNotIn(canary, repr(result))
        self.assertNotIn(canary, result.message)

    @unittest.skipUnless(sys.platform == "win32", "requires a real Windows host")
    def test_read_only_native_system_and_identity_sources(self):
        native = NativeWindowsApi()
        system = native.get_system_info()
        collected = collect_windows_system(native)
        self.assertTrue(system.succeeded)
        self.assertEqual(collected.coverage, CoverageState.COMPLETE)
        self.assertTrue(collected.observations[0].system_id.startswith("cwt-"))


if __name__ == "__main__":
    unittest.main()
