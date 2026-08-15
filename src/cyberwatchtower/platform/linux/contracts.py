"""Linux-only collection contract retained for exact iptables parity."""

from typing import Protocol

from ..models import CollectionResult
from .models import FirewallPolicyObservation


class LinuxFirewallPolicyAdapter(Protocol):
    """Expose legacy iptables detail only to the Linux deterministic path."""

    def collect_firewall_policy(
        self,
    ) -> CollectionResult[FirewallPolicyObservation]: ...
