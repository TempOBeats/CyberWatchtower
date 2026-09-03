"""Production bridge to the isolated Windows Firewall helper."""

from __future__ import annotations

from dataclasses import dataclass

from .firewall_rule_ipc import (
    WindowsFirewallHelperLauncherProtocol,
    run_isolated_windows_firewall_helper,
)
from .firewall_rule_transport import WindowsFirewallSubprocessLauncher
from .firewall_rule_models import (
    WindowsFirewallPolicyView,
    WindowsFirewallRuleResultCode,
)
from .firewall_rules import (
    WindowsFirewallRuleNormalizationResult,
    normalize_windows_firewall_rules,
)
from cyberwatchtower.report_contracts import CoverageState


def _internal_error_result() -> WindowsFirewallRuleNormalizationResult:
    return WindowsFirewallRuleNormalizationResult(
        WindowsFirewallPolicyView.CURRENT_POLICY_VIEW,
        CoverageState.INCOMPLETE,
        failure=WindowsFirewallRuleResultCode.INTERNAL_ERROR,
    )


@dataclass(frozen=True, slots=True)
class IsolatedWindowsFirewallPolicyProvider:
    """Collect normalized current-policy rules through the fixed helper route."""

    launcher: WindowsFirewallHelperLauncherProtocol | None = None

    def __post_init__(self) -> None:
        if self.launcher is not None and not isinstance(
            self.launcher, WindowsFirewallHelperLauncherProtocol
        ):
            raise TypeError("policy provider launcher must use the fixed protocol.")

    def collect_normalized_firewall_policy(
        self,
    ) -> WindowsFirewallRuleNormalizationResult:
        try:
            launcher = self.launcher or WindowsFirewallSubprocessLauncher()
            result = normalize_windows_firewall_rules(
                run_isolated_windows_firewall_helper(launcher)
            )
        except Exception:
            return _internal_error_result()
        return (
            result
            if isinstance(result, WindowsFirewallRuleNormalizationResult)
            else _internal_error_result()
        )
