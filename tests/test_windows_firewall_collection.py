import ast
import dataclasses
import inspect
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from cyberwatchtower.platform import (
    FirewallEnablement,
    FirewallInboundAction,
    FirewallProfile,
    FirewallProfileState,
    ObservationDomain,
)
from cyberwatchtower.platform.windows import (
    FakeWindowsApi,
    NativeWindowsApi,
    RawFirewallProfile,
    RawMachineIdentity,
    RawWindowsSystemInfo,
    WindowsApiFixture,
    WindowsApiResult,
    WindowsFailureCode,
    WindowsFirewallApiProtocol,
    collect_windows_firewall_inbound_policy,
    collect_windows_firewall_technology,
)
from cyberwatchtower.platform.windows.native_firewall import (
    collect_firewall_profiles,
)
from cyberwatchtower.report_contracts import CoverageState


def success(value):
    return WindowsApiResult(value=value)


def failure(code):
    return WindowsApiResult(failure=code)


def raw_profile(
    profile,
    *,
    active=False,
    enabled=FirewallEnablement.ENABLED,
    action=FirewallInboundAction.BLOCK,
    block_all=False,
):
    return RawFirewallProfile(
        profile,
        FirewallProfileState.ACTIVE if active else FirewallProfileState.INACTIVE,
        enabled,
        action,
        block_all,
    )


def profile_set(*active, overrides=None):
    overrides = overrides or {}
    return tuple(
        raw_profile(
            profile,
            active=profile in active,
            **overrides.get(profile, {}),
        )
        for profile in (
            FirewallProfile.DOMAIN,
            FirewallProfile.PRIVATE,
            FirewallProfile.PUBLIC,
        )
    )


def firewall_fixture(result):
    return WindowsApiFixture(
        system_info=success(RawWindowsSystemInfo(
            "WINDOWS-HOST", "Windows", "11", "26100", "AMD64"
        )),
        machine_identity=success(RawMachineIdentity("fixture-machine-guid")),
        tcp_endpoints=success(()),
        udp_endpoints=success(()),
        processes=(),
        services=success(()),
        firewall_profiles=result,
    )


def fixture_api(result):
    return FakeWindowsApi(firewall_fixture(result))


class WindowsFirewallNormalizationTests(unittest.TestCase):
    def test_single_and_multiple_active_profiles_are_retained_in_fixed_order(self):
        active_sets = (
            (FirewallProfile.DOMAIN,),
            (FirewallProfile.PRIVATE,),
            (FirewallProfile.PUBLIC,),
            (FirewallProfile.DOMAIN, FirewallProfile.PRIVATE),
            (FirewallProfile.PRIVATE, FirewallProfile.PUBLIC),
            (
                FirewallProfile.DOMAIN,
                FirewallProfile.PRIVATE,
                FirewallProfile.PUBLIC,
            ),
        )
        for active in active_sets:
            with self.subTest(active=active):
                api = fixture_api(success(profile_set(*active)))
                first = collect_windows_firewall_inbound_policy(api)
                second = collect_windows_firewall_inbound_policy(api)
                self.assertEqual(first, second)
                self.assertEqual(first.coverage, CoverageState.COMPLETE)
                profiles = first.observations[0].profiles
                self.assertEqual(
                    tuple(item.profile for item in profiles),
                    (
                        FirewallProfile.DOMAIN,
                        FirewallProfile.PRIVATE,
                        FirewallProfile.PUBLIC,
                    ),
                )
                self.assertEqual(
                    {item.profile for item in profiles
                     if item.state == FirewallProfileState.ACTIVE},
                    set(active),
                )

    def test_enabled_action_and_block_all_values_are_preserved_without_risk(self):
        profiles = profile_set(
            FirewallProfile.PUBLIC,
            overrides={
                FirewallProfile.DOMAIN: {
                    "enabled": FirewallEnablement.DISABLED,
                    "action": FirewallInboundAction.ALLOW,
                    "block_all": None,
                },
                FirewallProfile.PRIVATE: {
                    "action": FirewallInboundAction.ALLOW,
                    "block_all": False,
                },
                FirewallProfile.PUBLIC: {
                    "action": FirewallInboundAction.BLOCK,
                    "block_all": True,
                },
            },
        )
        result = collect_windows_firewall_inbound_policy(
            fixture_api(success(profiles))
        )
        by_profile = {
            item.profile: item for item in result.observations[0].profiles
        }
        self.assertEqual(result.coverage, CoverageState.COMPLETE)
        self.assertEqual(
            by_profile[FirewallProfile.DOMAIN].enablement,
            FirewallEnablement.DISABLED,
        )
        self.assertEqual(
            by_profile[FirewallProfile.PRIVATE].default_inbound_action,
            FirewallInboundAction.ALLOW,
        )
        self.assertIsNone(
            by_profile[FirewallProfile.DOMAIN].block_all_inbound
        )
        self.assertFalse(
            by_profile[FirewallProfile.PRIVATE].block_all_inbound
        )
        self.assertTrue(by_profile[FirewallProfile.PUBLIC].block_all_inbound)
        posture = result.observations[0]
        for field in (
            "approval", "finding", "model_evidence", "recommendation",
            "risk", "score", "severity",
        ):
            self.assertFalse(hasattr(posture, field))

    def test_permissive_active_profile_is_not_hidden_by_restrictive_profile(self):
        profiles = profile_set(
            FirewallProfile.DOMAIN,
            FirewallProfile.PUBLIC,
            overrides={
                FirewallProfile.DOMAIN: {
                    "action": FirewallInboundAction.BLOCK,
                },
                FirewallProfile.PUBLIC: {
                    "action": FirewallInboundAction.ALLOW,
                },
            },
        )
        result = collect_windows_firewall_inbound_policy(
            fixture_api(success(profiles))
        )
        active_actions = {
            item.profile: item.default_inbound_action
            for item in result.observations[0].profiles
            if item.state == FirewallProfileState.ACTIVE
        }
        self.assertEqual(result.coverage, CoverageState.COMPLETE)
        self.assertEqual(active_actions, {
            FirewallProfile.DOMAIN: FirewallInboundAction.BLOCK,
            FirewallProfile.PUBLIC: FirewallInboundAction.ALLOW,
        })

    def test_active_unknown_required_property_is_incomplete_but_preserved(self):
        cases = (
            {"enabled": FirewallEnablement.UNKNOWN},
            {"action": FirewallInboundAction.UNKNOWN},
        )
        for override in cases:
            with self.subTest(override=override):
                profiles = profile_set(
                    FirewallProfile.PUBLIC,
                    overrides={FirewallProfile.PUBLIC: override},
                )
                result = collect_windows_firewall_inbound_policy(
                    fixture_api(success(profiles))
                )
                self.assertEqual(result.coverage, CoverageState.INCOMPLETE)
                self.assertEqual(len(result.observations), 1)
                active = next(
                    item for item in result.observations[0].profiles
                    if item.profile == FirewallProfile.PUBLIC
                )
                if "action" in override:
                    self.assertEqual(
                        active.default_inbound_action,
                        FirewallInboundAction.UNKNOWN,
                    )

    def test_inactive_unknown_properties_do_not_hide_complete_active_profile(self):
        profiles = profile_set(
            FirewallProfile.PUBLIC,
            overrides={
                FirewallProfile.DOMAIN: {
                    "enabled": FirewallEnablement.UNKNOWN,
                    "action": FirewallInboundAction.UNKNOWN,
                    "block_all": None,
                }
            },
        )
        result = collect_windows_firewall_inbound_policy(
            fixture_api(success(profiles))
        )
        self.assertEqual(result.coverage, CoverageState.COMPLETE)

    def test_access_partial_and_unavailable_fail_conservatively(self):
        access = collect_windows_firewall_inbound_policy(
            fixture_api(failure(WindowsFailureCode.ACCESS_DENIED))
        )
        unavailable = collect_windows_firewall_inbound_policy(
            fixture_api(failure(WindowsFailureCode.API_UNAVAILABLE))
        )
        partial = collect_windows_firewall_inbound_policy(fixture_api(
            WindowsApiResult(
                profile_set(FirewallProfile.PUBLIC),
                WindowsFailureCode.PARTIAL_RESULT,
            )
        ))
        self.assertEqual(access.coverage, CoverageState.INCOMPLETE)
        self.assertEqual(unavailable.coverage, CoverageState.UNKNOWN)
        self.assertEqual(partial.coverage, CoverageState.INCOMPLETE)
        self.assertEqual(len(partial.observations), 1)

    def test_missing_duplicate_and_unknown_active_profile_state_fail_closed(self):
        missing = collect_windows_firewall_inbound_policy(fixture_api(success(
            profile_set(FirewallProfile.PUBLIC)[:2]
        )))

        class DuplicateApi:
            def get_firewall_profiles(self):
                profile = raw_profile(FirewallProfile.PUBLIC, active=True)
                return success((profile, profile))

        duplicate = collect_windows_firewall_inbound_policy(DuplicateApi())
        unknown = profile_set(
            overrides={
                FirewallProfile.PUBLIC: {}
            }
        )
        unknown = tuple(
            dataclasses.replace(item, state=FirewallProfileState.UNKNOWN)
            if item.profile == FirewallProfile.PUBLIC else item
            for item in unknown
        )
        unknown_result = collect_windows_firewall_inbound_policy(
            fixture_api(success(unknown))
        )
        for result in (missing, duplicate, unknown_result):
            self.assertEqual(result.coverage, CoverageState.INCOMPLETE)
            self.assertEqual(result.observations, ())

        profile = raw_profile(FirewallProfile.PUBLIC, active=True)
        original = firewall_fixture(success(profile_set(FirewallProfile.PUBLIC)))
        with self.assertRaises(ValueError):
            dataclasses.replace(
                original,
                firewall_profiles=success((profile, profile)),
            )

    def test_technology_detection_is_independent_from_policy_completeness(self):
        partial = WindowsApiResult(
            profile_set(FirewallProfile.PUBLIC),
            WindowsFailureCode.PARTIAL_RESULT,
        )
        detected = collect_windows_firewall_technology(fixture_api(partial))
        denied = collect_windows_firewall_technology(
            fixture_api(failure(WindowsFailureCode.ACCESS_DENIED))
        )
        unavailable = collect_windows_firewall_technology(
            fixture_api(failure(WindowsFailureCode.UNSUPPORTED))
        )
        self.assertEqual(detected.domain, ObservationDomain.FIREWALL_TECHNOLOGY)
        self.assertEqual(detected.coverage, CoverageState.COMPLETE)
        self.assertEqual(
            detected.observations[0].detected_tools, ("windows-firewall",)
        )
        self.assertEqual(denied.coverage, CoverageState.INCOMPLETE)
        self.assertEqual(unavailable.coverage, CoverageState.UNKNOWN)


class WindowsNativeFirewallTests(unittest.TestCase):
    def test_native_profile_mapping_uses_fixed_semantic_getters(self):
        class Policy:
            def __init__(self):
                self.closed = False

            def __enter__(self):
                return self

            def __exit__(self, *unused):
                self.closed = True

            def current_profile_mask(self):
                return 0x1 | 0x4

            def firewall_enabled(self, profile):
                return profile != 0x1

            def default_inbound_action(self, profile):
                return 1 if profile == 0x4 else 0

            def block_all_inbound(self, profile):
                return profile == 0x1

        policy = Policy()
        with patch(
            "cyberwatchtower.platform.windows.native_firewall._open_policy",
            return_value=policy,
        ):
            result = collect_firewall_profiles()
        self.assertTrue(result.succeeded)
        self.assertTrue(policy.closed)
        self.assertEqual(
            tuple(item.profile for item in result.value),
            (
                FirewallProfile.DOMAIN,
                FirewallProfile.PRIVATE,
                FirewallProfile.PUBLIC,
            ),
        )
        self.assertEqual(result.value[0].enablement, FirewallEnablement.DISABLED)
        self.assertEqual(
            result.value[2].default_inbound_action,
            FirewallInboundAction.ALLOW,
        )

    def test_native_active_property_failure_is_partial_and_inactive_failure_is_tolerated(self):
        class Policy:
            def __enter__(self):
                return self

            def __exit__(self, *unused):
                pass

            def current_profile_mask(self):
                return 0x4

            def firewall_enabled(self, profile):
                if profile in {0x1, 0x4}:
                    from cyberwatchtower.platform.windows.native_firewall import _NativeFailure
                    raise _NativeFailure(WindowsFailureCode.ACCESS_DENIED)
                return True

            def default_inbound_action(self, profile):
                return 0

            def block_all_inbound(self, profile):
                return False

        with patch(
            "cyberwatchtower.platform.windows.native_firewall._open_policy",
            return_value=Policy(),
        ):
            result = collect_firewall_profiles()
        self.assertEqual(result.failure, WindowsFailureCode.PARTIAL_RESULT)
        self.assertEqual(result.value[0].enablement, FirewallEnablement.UNKNOWN)
        self.assertEqual(result.value[2].enablement, FirewallEnablement.UNKNOWN)

        class InactiveOnlyPolicy(Policy):
            def firewall_enabled(self, profile):
                if profile == 0x1:
                    from cyberwatchtower.platform.windows.native_firewall import _NativeFailure
                    raise _NativeFailure(WindowsFailureCode.ACCESS_DENIED)
                return True

        with patch(
            "cyberwatchtower.platform.windows.native_firewall._open_policy",
            return_value=InactiveOnlyPolicy(),
        ):
            inactive_only = collect_firewall_profiles()
        self.assertTrue(inactive_only.succeeded)
        self.assertEqual(
            inactive_only.value[0].enablement,
            FirewallEnablement.UNKNOWN,
        )

    def test_native_error_and_policy_canaries_never_escape(self):
        class CanaryApi:
            def get_firewall_profiles(self):
                raise RuntimeError("HRESULT token=FIREWALL-SECRET-CANARY")

        result = collect_windows_firewall_inbound_policy(CanaryApi())
        rendered = json.dumps(dataclasses.asdict(result.failure))
        self.assertNotIn("CANARY", rendered)
        self.assertNotIn("HRESULT", rendered)
        self.assertNotIn("token", rendered.casefold())

    def test_boundary_is_read_only_fixed_purpose_and_import_safe(self):
        package = Path(__file__).parents[1] / "src/cyberwatchtower/platform/windows"
        source = Path(package, "native_firewall.py").read_text(encoding="utf-8")
        lowered = source.casefold()
        for marker in (
            "subprocess", "shell=true", "os.system", "powershell", "cmd.exe",
            "netsh", "create rule", "delete rule", "put_firewallenabled",
            "put_defaultinboundaction", "registry", "winreg", "service change",
            "cyberwatchtower.scanner", "cyberwatchtower.memory",
            "cyberwatchtower.advisor", "cyberwatchtower.core",
        ):
            with self.subTest(marker=marker):
                self.assertNotIn(marker, lowered)
        self.assertIn("inetfwpolicy2", lowered)
        self.assertIn("coinitializeex", lowered)
        self.assertIn("couninitialize", lowered)
        self.assertIn("_vtable_release", lowered)
        self.assertNotIn("idispatch", lowered)
        methods = {
            name.casefold() for name, _ in inspect.getmembers(
                WindowsFirewallApiProtocol
            )
        }
        self.assertTrue(methods.isdisjoint({
            "execute", "invoke", "query", "set", "update", "delete",
        }))
        tree = ast.parse(source)
        imports = {
            alias.name
            for node in tree.body
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        self.assertEqual(imports, set())
        native = NativeWindowsApi()
        if sys.platform != "win32":
            self.assertEqual(
                native.get_firewall_profiles().failure,
                WindowsFailureCode.UNSUPPORTED,
            )

    @unittest.skipUnless(sys.platform == "win32", "requires a real Windows host")
    def test_read_only_native_windows_firewall_profile_api(self):
        result = NativeWindowsApi().get_firewall_profiles()
        self.assertIsInstance(result, WindowsApiResult)
        if result.value is not None:
            self.assertTrue(all(
                isinstance(item, RawFirewallProfile) for item in result.value
            ))


if __name__ == "__main__":
    unittest.main()
