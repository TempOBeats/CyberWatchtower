"""Linux-specific observations retained for deterministic iptables parity."""

from dataclasses import dataclass
from typing import Mapping
import unicodedata

from ..models import MAX_FAILURE_MESSAGE


def _linux_policy_text(value: object, name: str, maximum: int) -> None:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"{name} is outside the supported bound.")
    if any(unicodedata.category(char) in {"Cc", "Cf"} for char in value):
        raise ValueError(f"{name} contains prohibited control characters.")


@dataclass(frozen=True)
class FirewallPolicyObservation:
    available: bool
    accessible: bool
    policies: tuple[tuple[str, str], ...] = ()
    message: str | None = None

    def __post_init__(self) -> None:
        if self.message is not None:
            _linux_policy_text(
                self.message, "firewall policy message", MAX_FAILURE_MESSAGE
            )
        for chain, policy in self.policies:
            _linux_policy_text(chain, "firewall chain", 128)
            _linux_policy_text(policy, "firewall policy", 128)

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "FirewallPolicyObservation":
        if not isinstance(value, Mapping):
            raise TypeError("firewall policy collection must be a mapping.")
        policies = value.get("policies", {})
        if not isinstance(policies, Mapping):
            raise TypeError("firewall policies must be a mapping.")
        available = value.get("available", False)
        accessible = value.get("accessible", False)
        if not isinstance(available, bool) or not isinstance(accessible, bool):
            raise TypeError("firewall availability fields must be boolean.")
        return cls(
            available,
            accessible,
            tuple((str(chain), str(policy)) for chain, policy in policies.items()),
            value.get("message"),
        )

    def to_assessment_mapping(self) -> dict[str, object]:
        result: dict[str, object] = {
            "available": self.available,
            "accessible": self.accessible,
            "policies": dict(self.policies),
        }
        if self.message is not None:
            result["message"] = self.message
        return result
