"""Closed result contracts for pure, bounded nftables JSON normalization."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .firewall_contracts import LinuxFirewallPolicySnapshot


MAX_NFT_JSON_BYTES = 8 * 1024 * 1024


class NftObjectClassification(str, Enum):
    SUPPORTED_POLICY_OBJECT = "SUPPORTED_POLICY_OBJECT"
    IGNORABLE_METADATA = "IGNORABLE_METADATA"
    UNSUPPORTED_POLICY_OBJECT = "UNSUPPORTED_POLICY_OBJECT"
    INVALID_OBJECT = "INVALID_OBJECT"


class NftParseStatus(str, Enum):
    SUCCESS = "SUCCESS"
    INPUT_TOO_LARGE = "INPUT_TOO_LARGE"
    INVALID_JSON = "INVALID_JSON"
    INVALID_ROOT = "INVALID_ROOT"
    STRUCTURAL_LIMIT_EXCEEDED = "STRUCTURAL_LIMIT_EXCEEDED"
    INVALID_VALUE = "INVALID_VALUE"
    UNSUPPORTED_SEMANTICS = "UNSUPPORTED_SEMANTICS"
    INCOMPLETE_SEMANTICS = "INCOMPLETE_SEMANTICS"


@dataclass(frozen=True, slots=True)
class NftParseResult:
    status: NftParseStatus
    snapshot: LinuxFirewallPolicySnapshot | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, NftParseStatus):
            raise TypeError("nft parse status must use the closed enum.")
        if self.snapshot is not None and not isinstance(
            self.snapshot, LinuxFirewallPolicySnapshot
        ):
            raise TypeError("nft parse snapshot must use the frozen Linux contract.")
        if self.status == NftParseStatus.SUCCESS and self.snapshot is None:
            raise ValueError("successful nft parsing requires a snapshot.")


__all__ = [
    "MAX_NFT_JSON_BYTES",
    "NftObjectClassification",
    "NftParseResult",
    "NftParseStatus",
]
