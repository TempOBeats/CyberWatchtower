import dataclasses
import hashlib
import inspect
import json
import pkgutil
import unittest
from pathlib import Path

from cyberwatchtower.firewall_policy import (
    AddressConditionKind,
    ApplicationConditionKind,
    FirewallPlatformTechnology,
    FirewallRuleAction,
    FirewallRuleDirection,
    FirewallRuleEnabledState,
    FirewallRuleUnsupportedFeature,
    InterfaceConditionKind,
    MAX_FIREWALL_RULES,
)
from cyberwatchtower.platform import (
    FirewallEnablement,
    FirewallInboundAction,
    FirewallProfile,
    FirewallProfileState,
)
from cyberwatchtower.platform.windows import (
    FakeWindowsApi,
    RawFirewallProfile,
    RawMachineIdentity,
    RawWindowsApplicationPath,
    RawWindowsFirewallRule,
    RawWindowsInterfaceIdentity,
    RawWindowsSystemInfo,
    WINDOWS_FIREWALL_COM_ENUMERATION_CONTRACT,
    WindowsApiFixture,
    WindowsApiResult,
    WindowsComGetterDeadlineGuarantee,
    WindowsComOwnershipRequirement,
    WindowsFailureCode,
    WindowsFirewallPolicyView,
    WindowsFirewallRuleCollectionResult,
    WindowsFirewallRuleResultCode,
    WindowsFirewallRulesApiProtocol,
    WindowsRawFirewallInterfaceType,
    WindowsRawFirewallRuleAction,
    WindowsRawFirewallRuleDirection,
    WindowsRawFirewallUnsupportedFeature,
    normalize_windows_firewall_rules,
    windows_application_identity,
)
from cyberwatchtower.report_contracts import CoverageState


VIEW = WindowsFirewallPolicyView.CURRENT_POLICY_VIEW


def raw_rule(**changes):
    values = {
        "policy_view": VIEW,
        "enabled": True,
        "direction": WindowsRawFirewallRuleDirection.INBOUND,
        "action": WindowsRawFirewallRuleAction.ALLOW,
        "profile_mask": 0x4,
        "protocol": 6,
        "local_ports": ("443",),
        "local_addresses": ("*",),
        "remote_addresses": ("*",),
    }
    values.update(changes)
    return RawWindowsFirewallRule(**values)


def raw_result(*rules, state=WindowsFirewallRuleResultCode.COMPLETE):
    return WindowsFirewallRuleCollectionResult(state, VIEW, tuple(rules))


def fixture(rule_result=None):
    return WindowsApiFixture(
        system_info=WindowsApiResult(value=RawWindowsSystemInfo(
            "fixture", "Windows", "11", "26100", "AMD64"
        )),
        machine_identity=WindowsApiResult(value=RawMachineIdentity("fixture-id")),
        tcp_endpoints=WindowsApiResult(value=()),
        udp_endpoints=WindowsApiResult(value=()),
        processes=(),
        services=WindowsApiResult(value=()),
        firewall_profiles=WindowsApiResult(value=(RawFirewallProfile(
            FirewallProfile.PUBLIC,
            FirewallProfileState.ACTIVE,
            FirewallEnablement.ENABLED,
            FirewallInboundAction.BLOCK,
            False,
        ),)),
        firewall_rules=rule_result or raw_result(),
    )


class WindowsFirewallRuleApiBoundaryTests(unittest.TestCase):
    def test_fake_satisfies_fixed_purpose_protocol_without_changing_master_api(self):
        fake = FakeWindowsApi(fixture(raw_result(raw_rule())))
        self.assertIsInstance(fake, WindowsFirewallRulesApiProtocol)
        self.assertEqual(fake.collect_firewall_rules(), raw_result(raw_rule()))
        methods = {
            name.casefold() for name, value in inspect.getmembers(
                WindowsFirewallRulesApiProtocol
            ) if callable(value) and not name.startswith("_")
        }
        self.assertEqual(methods, {"collect_firewall_rules"})
        for prohibited in (
            "dispatch", "invoke", "query", "execute", "create", "delete",
            "update", "enable", "disable", "set", "powershell", "netsh",
        ):
            self.assertNotIn(prohibited, methods)

    def test_non_windows_import_and_fake_have_no_native_or_execution_surface(self):
        import cyberwatchtower.platform.windows as windows

        root = Path(windows.__file__).parent
        sources = "\n".join(
            Path(module.module_finder.path, f"{module.name}.py").read_text(
                encoding="utf-8"
            )
            for module in pkgutil.iter_modules([str(root)])
            if module.name in {
                "api", "fake", "firewall_rule_models", "firewall_rules"
            }
        ).casefold()
        for prohibited in (
            "subprocess", "shell=true", "os.system", "powershell", "netsh",
            "winreg", "windll", "coinitializeex(", "cocreateinstance(",
            "idispatch", "ienumvariant", "socket.socket", "requests",
        ):
            with self.subTest(marker=prohibited):
                self.assertNotIn(prohibited, sources)

    def test_result_failures_are_closed_and_carry_no_diagnostics(self):
        fields = {field.name for field in dataclasses.fields(
            WindowsFirewallRuleCollectionResult
        )}
        self.assertEqual(fields, {"state", "policy_view", "rules"})
        for state in WindowsFirewallRuleResultCode:
            if state == WindowsFirewallRuleResultCode.COMPLETE:
                continue
            value = raw_result(state=state)
            self.assertNotIn("SECRET_NATIVE_ERROR", repr(value))
            self.assertFalse(hasattr(value, "message"))


class WindowsRawFirewallRuleTests(unittest.TestCase):
    def test_raw_contract_is_immutable_ordered_and_has_no_rule_prose_fields(self):
        first = raw_rule(local_ports=("8443", "443"))
        second = raw_rule(local_ports=("443", "8443"))
        self.assertEqual(first, second)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            first.enabled = False
        fields = {field.name for field in dataclasses.fields(first)}
        for prohibited in (
            "name", "rule_name", "description", "error", "metadata",
            "native_object", "provider_text",
        ):
            self.assertNotIn(prohibited, fields)

    def test_private_path_and_interface_are_redacted_and_not_serializable(self):
        path_canary = r"C:\Users\Private\SECRET_TOKEN\service.exe"
        interface_canary = "SECRET_PRIVATE_INTERFACE"
        path = RawWindowsApplicationPath(path_canary)
        interface = RawWindowsInterfaceIdentity(interface_canary)
        value = raw_rule(application_path=path, interfaces=(interface,))
        for rendered in (repr(path), str(path), repr(interface), str(interface),
                         repr(value)):
            self.assertNotIn("SECRET", rendered)
        for item in (path, interface, value):
            with self.assertRaises(TypeError):
                json.dumps(item)

    def test_invalid_raw_values_fail_closed(self):
        mutations = (
            {"enabled": 1}, {"profile_mask": 0}, {"profile_mask": 8},
            {"protocol": -1}, {"protocol": 257},
            {"local_ports": ("443-80",)}, {"local_ports": ("not-port",)},
            {"local_addresses": ("not-address",)},
            {"service_name": "DOMAIN\\user"},
            {"edge_traversal": 1},
        )
        for changes in mutations:
            with self.subTest(changes=changes), self.assertRaises(
                (TypeError, ValueError)
            ):
                raw_rule(**changes)

    def test_bounds_and_duplicate_raw_values_fail_closed(self):
        with self.assertRaises(ValueError):
            raw_rule(local_ports=tuple(str(value) for value in range(257)))
        with self.assertRaises(ValueError):
            raw_rule(local_ports=("443", "443"))
        maximum = raw_result(*(raw_rule() for _ in range(MAX_FIREWALL_RULES)))
        self.assertEqual(len(maximum.rules), MAX_FIREWALL_RULES)
        with self.assertRaises(ValueError):
            raw_result(*(raw_rule() for _ in range(MAX_FIREWALL_RULES + 1)))


class WindowsFirewallRuleNormalizationTests(unittest.TestCase):
    def normalized(self, value):
        result = normalize_windows_firewall_rules(raw_result(value))
        self.assertEqual(result.coverage, CoverageState.COMPLETE)
        self.assertIsNone(result.failure)
        self.assertEqual(len(result.rules), 1)
        return result.rules[0]

    def test_action_enablement_direction_profiles_and_edge_traversal(self):
        value = self.normalized(raw_rule(
            enabled=False,
            direction=WindowsRawFirewallRuleDirection.OUTBOUND,
            action=WindowsRawFirewallRuleAction.BLOCK,
            profile_mask=0x3,
            edge_traversal=True,
        ))
        self.assertEqual(value.technology, FirewallPlatformTechnology.WINDOWS_FIREWALL)
        self.assertEqual(value.enabled, FirewallRuleEnabledState.DISABLED)
        self.assertEqual(value.direction, FirewallRuleDirection.OUTBOUND)
        self.assertEqual(value.action, FirewallRuleAction.BLOCK)
        self.assertEqual(value.profiles, (
            FirewallProfile.DOMAIN, FirewallProfile.PRIVATE,
        ))
        self.assertTrue(value.edge_traversal)
        self.assertEqual(
            self.normalized(raw_rule(profile_mask=0x7FFFFFFF)).profiles, ()
        )

    def test_protocol_any_ports_ranges_and_unsupported_protocol(self):
        tcp = self.normalized(raw_rule(local_ports=("80-90", "443")))
        any_rule = self.normalized(raw_rule(protocol=256, local_ports=("*",)))
        unsupported = self.normalized(raw_rule(protocol=1))
        self.assertEqual(tcp.protocol.value, "tcp")
        self.assertEqual(
            {(value.start, value.end) for value in tcp.local_ports},
            {(80, 90), (443, 443)},
        )
        self.assertIsNone(any_rule.protocol)
        self.assertEqual(any_rule.local_ports, ())
        self.assertIn(
            FirewallRuleUnsupportedFeature.UNMODELED_PLATFORM_PREDICATE,
            unsupported.unsupported_features,
        )
        self.assertEqual(self.normalized(raw_rule(protocol=17)).protocol.value, "udp")

    def test_ipv4_ipv6_and_remote_restriction_normalize(self):
        value = self.normalized(raw_rule(
            local_addresses=("192.0.2.10", "2001:db8::1/64"),
            remote_addresses=("198.51.100.0/24",),
        ))
        self.assertEqual(
            {item.kind for item in value.local_addresses},
            {AddressConditionKind.EXACT, AddressConditionKind.CIDR},
        )
        self.assertIn("2001:db8::/64", {
            item.value for item in value.local_addresses
        })
        self.assertIn(
            FirewallRuleUnsupportedFeature.REMOTE_ADDRESS_RESTRICTED,
            value.unsupported_features,
        )
        self.assertEqual(
            self.normalized(raw_rule(local_addresses=("*",))).local_addresses,
            (),
        )
        special = self.normalized(raw_rule(local_addresses=("LocalSubnet",)))
        self.assertEqual(
            special.local_addresses[0].kind,
            AddressConditionKind.SUPPORTED_SPECIAL_SCOPE,
        )

    def test_application_service_interface_and_unsupported_features(self):
        application = self.normalized(raw_rule(
            application_path=RawWindowsApplicationPath(r"C:\Program Files\App\app.exe")
        ))
        service = self.normalized(raw_rule(service_name="Dnscache"))
        interface = self.normalized(raw_rule(interface_types=(
            WindowsRawFirewallInterfaceType.WIRELESS,
        )))
        unsupported = self.normalized(raw_rule(unsupported_features=(
            WindowsRawFirewallUnsupportedFeature.PACKAGE_SCOPE,
        )))
        self.assertEqual(
            application.application.kind, ApplicationConditionKind.APPLICATION_DIGEST
        )
        self.assertEqual(len(application.application.value), 64)
        self.assertEqual(service.application.value, "windows-service:dnscache")
        self.assertEqual(interface.interface.kind, InterfaceConditionKind.WIRELESS)
        self.assertIn(
            FirewallRuleUnsupportedFeature.USER_OR_PACKAGE_SCOPE,
            unsupported.unsupported_features,
        )

    def test_application_digest_is_private_namespaced_and_deterministic(self):
        first = RawWindowsApplicationPath(r"C:\Program Files\App\app.exe")
        equivalent = RawWindowsApplicationPath(r"c:/program files/app/APP.EXE")
        different = RawWindowsApplicationPath(r"C:\Other Directory\App\app.exe")
        self.assertEqual(
            windows_application_identity(first),
            windows_application_identity(equivalent),
        )
        self.assertNotEqual(
            windows_application_identity(first),
            windows_application_identity(different),
        )
        self.assertNotEqual(
            windows_application_identity(first),
            hashlib.sha256(
                r"c:\program files\app\app.exe".encode("utf-8")
            ).hexdigest(),
        )
        normalized = self.normalized(raw_rule(application_path=first))
        rendered = repr(normalized)
        self.assertNotIn("Program Files", rendered)
        self.assertNotIn("app.exe", rendered)

    def test_private_interface_identity_becomes_only_an_opaque_digest(self):
        canary = RawWindowsInterfaceIdentity("PRIVATE_INTERFACE_CANARY")
        value = self.normalized(raw_rule(interfaces=(canary,)))
        self.assertEqual(value.interface.kind, InterfaceConditionKind.INTERFACE_DIGEST)
        self.assertEqual(len(value.interface.value), 64)
        self.assertNotIn("PRIVATE_INTERFACE_CANARY", repr(value))

    def test_semantic_identity_permutation_duplicates_and_current_view(self):
        first = raw_rule(local_ports=("443", "8443"))
        second = raw_rule(local_ports=("8443", "443"))
        left = normalize_windows_firewall_rules(raw_result(first, second))
        right = normalize_windows_firewall_rules(raw_result(second, first))
        self.assertEqual(left, right)
        self.assertEqual(len(left.rules), 1)
        self.assertEqual(left.policy_view, WindowsFirewallPolicyView.CURRENT_POLICY_VIEW)
        self.assertEqual(len(left.rules[0].semantic_rule_id), 64)

    def test_partial_failure_limit_access_unavailable_and_invalid_results(self):
        cases = (
            (raw_result(raw_rule(), state=WindowsFirewallRuleResultCode.COLLECTION_INCOMPLETE),
             CoverageState.INCOMPLETE, WindowsFirewallRuleResultCode.COLLECTION_INCOMPLETE),
            (raw_result(state=WindowsFirewallRuleResultCode.LIMIT_EXCEEDED),
             CoverageState.INCOMPLETE, WindowsFirewallRuleResultCode.LIMIT_EXCEEDED),
            (raw_result(state=WindowsFirewallRuleResultCode.ACCESS_DENIED),
             CoverageState.INCOMPLETE, WindowsFirewallRuleResultCode.ACCESS_DENIED),
            (raw_result(state=WindowsFirewallRuleResultCode.API_UNAVAILABLE),
             CoverageState.UNKNOWN, WindowsFirewallRuleResultCode.API_UNAVAILABLE),
            (raw_result(state=WindowsFirewallRuleResultCode.INVALID_RESULT),
             CoverageState.INCOMPLETE, WindowsFirewallRuleResultCode.INVALID_RESULT),
        )
        for raw, coverage, failure in cases:
            with self.subTest(failure=failure):
                result = normalize_windows_firewall_rules(raw)
                self.assertEqual(result.coverage, coverage)
                self.assertEqual(result.failure, failure)


class WindowsFirewallRuleOwnershipAndPrivacyTests(unittest.TestCase):
    def test_phase_2b_com_ownership_and_nonpreemptible_getter_contract_is_frozen(self):
        contract = WINDOWS_FIREWALL_COM_ENUMERATION_CONTRACT
        self.assertEqual(contract.requirements, tuple(WindowsComOwnershipRequirement))
        self.assertEqual(contract.max_rules, 8192)
        self.assertEqual(
            contract.getter_deadline_guarantee,
            WindowsComGetterDeadlineGuarantee.NON_PREEMPTIBLE_IN_PROCESS,
        )
        self.assertGreater(contract.max_getter_operations_per_rule, 0)
        self.assertTrue(contract.acquisition_deadline_required)

    def test_production_adapter_and_native_facade_do_not_route_rule_collection(self):
        root = Path(__file__).parents[1] / "src" / "cyberwatchtower"
        for relative in (
            "scanner.py", "platform/windows/adapter.py",
            "platform/windows/api_native.py",
        ):
            source = (root / relative).read_text(encoding="utf-8")
            self.assertNotIn("collect_firewall_rules", source)
            self.assertNotIn("firewall_rule_models", source)

    def test_downstream_authority_modules_do_not_import_raw_rule_types(self):
        root = Path(__file__).parents[1] / "src" / "cyberwatchtower"
        prohibited = (
            "RawWindowsFirewallRule", "RawWindowsApplicationPath",
            "firewall_rule_models",
        )
        targets = (
            root / "reporting.py", root / "history.py", root / "scoring_projection.py",
            root / "advisor", root / "briefing", root / "memory", root / "core",
            root / "model_gateway",
        )
        for target in targets:
            paths = target.rglob("*.py") if target.is_dir() else (target,)
            source = "\n".join(path.read_text(encoding="utf-8") for path in paths)
            for marker in prohibited:
                with self.subTest(target=target, marker=marker):
                    self.assertNotIn(marker, source)


if __name__ == "__main__":
    unittest.main()
