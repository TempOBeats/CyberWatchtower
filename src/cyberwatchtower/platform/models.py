"""Immutable, platform-neutral observations produced by host adapters."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Generic, Mapping, TypeVar
import unicodedata

from cyberwatchtower.report_contracts import CoverageState, ScanDomain


MAX_OBSERVATION_TEXT = 4096
MAX_FAILURE_MESSAGE = 512
_SENSITIVE_FAILURE_MARKERS = (
    "api_key", "apikey", "authorization:", "bearer ", "credential",
    "environment=", "password", "raw argv", "stderr", "token=", "token:",
)
_SYSTEM_FIELDS = (
    "system_id", "hostname", "username", "operating_system", "os_version",
    "architecture", "processor",
)


def _text(value: object, name: str, maximum: int = MAX_OBSERVATION_TEXT) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be text.")
    if not value or len(value) > maximum:
        raise ValueError(f"{name} is outside the supported bound.")
    if any(unicodedata.category(char) in {"Cc", "Cf"} for char in value):
        raise ValueError(f"{name} contains prohibited control characters.")
    return value


class ObservationDomain(str, Enum):
    SYSTEM_INFORMATION = "system_information"
    FIREWALL_TECHNOLOGY = ScanDomain.FIREWALL_TECHNOLOGY.value
    FIREWALL_INPUT_POLICY = ScanDomain.IPTABLES_INPUT_POLICY.value
    FIREWALL_INBOUND_POLICY = ScanDomain.FIREWALL_INBOUND_POLICY.value
    NETWORK_LISTENERS = ScanDomain.NETWORK_SOCKET_INSPECTION.value


class FailureCategory(str, Enum):
    UNSUPPORTED = "UNSUPPORTED"
    UNAVAILABLE = "UNAVAILABLE"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    MALFORMED_OUTPUT = "MALFORMED_OUTPUT"
    PARTIAL = "PARTIAL"
    INTERNAL = "INTERNAL"


class FailureCode(str, Enum):
    UNSUPPORTED_PLATFORM = "UNSUPPORTED_PLATFORM"
    COLLECTOR_UNAVAILABLE = "COLLECTOR_UNAVAILABLE"
    COLLECTOR_PERMISSION_DENIED = "COLLECTOR_PERMISSION_DENIED"
    COLLECTOR_OUTPUT_MALFORMED = "COLLECTOR_OUTPUT_MALFORMED"
    COLLECTOR_PARTIAL = "COLLECTOR_PARTIAL"
    COLLECTOR_INTERNAL_FAILURE = "COLLECTOR_INTERNAL_FAILURE"
    SOCKET_COMMAND_UNAVAILABLE = "SOCKET_COMMAND_UNAVAILABLE"
    SOCKET_COMMAND_FAILED = "SOCKET_COMMAND_FAILED"
    SOCKET_COMMAND_TIMEOUT = "SOCKET_COMMAND_TIMEOUT"
    SOCKET_OUTPUT_MALFORMED = "SOCKET_OUTPUT_MALFORMED"
    IPTABLES_PERMISSION_DENIED = "IPTABLES_PERMISSION_DENIED"
    IPTABLES_POLICY_INCOMPLETE = "IPTABLES_POLICY_INCOMPLETE"


@dataclass(frozen=True)
class CollectionFailure:
    category: FailureCategory
    code: FailureCode
    message: str

    def __post_init__(self) -> None:
        if not isinstance(self.category, FailureCategory):
            raise TypeError("failure category must use the closed enum.")
        if not isinstance(self.code, FailureCode):
            raise TypeError("failure code must use the closed enum.")
        _text(self.message, "failure message", MAX_FAILURE_MESSAGE)
        if any(marker in self.message.casefold()
               for marker in _SENSITIVE_FAILURE_MARKERS):
            raise ValueError("failure message contains prohibited sensitive data.")


T = TypeVar("T")


@dataclass(frozen=True)
class CollectionResult(Generic[T]):
    domain: ObservationDomain
    coverage: CoverageState
    observations: tuple[T, ...] = ()
    failure: CollectionFailure | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.domain, ObservationDomain):
            raise TypeError("domain must use the closed observation enum.")
        if not isinstance(self.coverage, CoverageState):
            raise TypeError("coverage must use the closed coverage enum.")
        if self.failure is not None and not isinstance(self.failure, CollectionFailure):
            raise TypeError("failure must use the typed collection failure.")
        if not isinstance(self.observations, tuple):
            raise TypeError("observations must be an immutable tuple.")
        if self.coverage == CoverageState.COMPLETE and self.failure is not None:
            raise ValueError("complete coverage cannot carry a collection failure.")
        if self.coverage != CoverageState.COMPLETE and self.failure is None:
            raise ValueError("non-complete coverage requires a typed failure.")


@dataclass(frozen=True)
class SystemObservation:
    system_id: str | None = None
    hostname: str | None = None
    username: str | None = None
    operating_system: str | None = None
    os_version: str | None = None
    architecture: str | None = None
    processor: str | None = None
    present_fields: frozenset[str] = field(default_factory=frozenset, repr=False)

    def __post_init__(self) -> None:
        if not self.present_fields.issubset(_SYSTEM_FIELDS):
            raise ValueError("system observation contains unsupported fields.")
        for name in self.present_fields:
            value = getattr(self, name)
            if not isinstance(value, str) or len(value) > MAX_OBSERVATION_TEXT:
                raise ValueError(f"system {name} is outside the supported bound.")
            if any(unicodedata.category(char) in {"Cc", "Cf"} for char in value):
                raise ValueError(f"system {name} contains prohibited controls.")

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "SystemObservation":
        if not isinstance(value, Mapping):
            raise TypeError("system collection must be a mapping.")
        unsupported = set(value) - set(_SYSTEM_FIELDS)
        if unsupported:
            raise ValueError("system collection contains unsupported fields.")
        fields = {name: value[name] for name in _SYSTEM_FIELDS if name in value}
        return cls(**fields, present_fields=frozenset(fields))

    def to_mapping(self) -> dict[str, str]:
        return {name: getattr(self, name) for name in _SYSTEM_FIELDS
                if name in self.present_fields}


class NetworkProtocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"


class ListenerExposure(str, Enum):
    ALL_INTERFACES = "all_interfaces"
    LOOPBACK = "loopback"
    INTERFACE = "interface"


@dataclass(frozen=True)
class ListenerObservation:
    protocol: NetworkProtocol
    state: str
    address: str
    port: int
    exposure: ListenerExposure
    process: str = "unknown"
    pid: int | None = None
    application: str | None = None
    application_name: str | None = None
    known_application: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.protocol, NetworkProtocol):
            raise TypeError("listener protocol must use the closed enum.")
        if not isinstance(self.exposure, ListenerExposure):
            raise TypeError("listener exposure must use the closed enum.")
        _text(self.state, "listener state", 128)
        _text(self.address, "listener address", 1024)
        _text(self.process, "listener process", 1024)
        if isinstance(self.port, bool) or not isinstance(self.port, int) or not 0 <= self.port <= 65535:
            raise ValueError("listener port is invalid.")
        if self.pid is not None and (
            isinstance(self.pid, bool) or not isinstance(self.pid, int) or self.pid <= 0
        ):
            raise ValueError("listener pid is invalid.")
        if self.application is not None:
            _text(self.application, "listener application")
        if self.application_name is not None:
            _text(self.application_name, "listener application name", 1024)
        if not isinstance(self.known_application, bool):
            raise ValueError("known_application must be boolean.")

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "ListenerObservation":
        allowed = {
            "protocol", "state", "address", "port", "exposure", "process", "pid",
            "application", "application_name", "known_application",
        }
        if not isinstance(value, Mapping) or set(value) - allowed:
            raise ValueError("listener collection contains unsupported fields.")
        port = value.get("port")
        if isinstance(port, str) and port.isdigit():
            port = int(port)
        return cls(
            NetworkProtocol(value.get("protocol")),
            value.get("state"),
            value.get("address"),
            port,
            ListenerExposure(value.get("exposure")),
            value.get("process", "unknown"),
            value.get("pid"),
            value.get("application"),
            value.get("application_name"),
            value.get("known_application", False),
        )

    def to_service_mapping(self) -> dict[str, object]:
        result: dict[str, object] = {
            "protocol": self.protocol.value,
            "state": self.state,
            "address": self.address,
            "port": str(self.port),
            "exposure": self.exposure.value,
            "process": self.process,
            "pid": self.pid,
        }
        if self.application is not None:
            result.update({
                "application": self.application,
                "application_name": self.application_name,
                "known_application": self.known_application,
            })
        return result


@dataclass(frozen=True)
class FirewallObservation:
    detected_tools: tuple[str, ...]
    tool_paths: tuple[tuple[str, str | None], ...]

    def __post_init__(self) -> None:
        if len(set(self.detected_tools)) != len(self.detected_tools):
            raise ValueError("firewall tools must be unique.")
        for tool in self.detected_tools:
            _text(tool, "firewall tool", 128)
        path_keys = [name for name, _ in self.tool_paths]
        if len(set(path_keys)) != len(path_keys):
            raise ValueError("firewall tool paths must be unique.")
        for name, path in self.tool_paths:
            _text(name, "firewall path key", 128)
            if path is not None:
                _text(path, "firewall tool path")

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "FirewallObservation":
        if not isinstance(value, Mapping) or set(value) - {"detected_tools", "tool_paths"}:
            raise ValueError("firewall collection contains unsupported fields.")
        tools = value.get("detected_tools", [])
        paths = value.get("tool_paths", {})
        if not isinstance(tools, list) or not isinstance(paths, Mapping):
            raise TypeError("firewall collection has invalid structure.")
        return cls(tuple(tools), tuple((str(key), item) for key, item in paths.items()))

    def to_mapping(self) -> dict[str, object]:
        return {
            "detected_tools": list(self.detected_tools),
            "tool_paths": dict(self.tool_paths),
        }


class FirewallProfile(str, Enum):
    DEFAULT = "DEFAULT"
    DOMAIN = "DOMAIN"
    PRIVATE = "PRIVATE"
    PUBLIC = "PUBLIC"


class FirewallProfileState(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    UNKNOWN = "UNKNOWN"


class FirewallEnablement(str, Enum):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"
    UNKNOWN = "UNKNOWN"


class FirewallInboundAction(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class FirewallProfileObservation:
    profile: FirewallProfile
    state: FirewallProfileState
    enablement: FirewallEnablement
    default_inbound_action: FirewallInboundAction
    block_all_inbound: bool | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.profile, FirewallProfile):
            raise TypeError("firewall profile must use the closed enum.")
        if not isinstance(self.state, FirewallProfileState):
            raise TypeError("firewall profile state must use the closed enum.")
        if not isinstance(self.enablement, FirewallEnablement):
            raise TypeError("firewall enablement must use the closed enum.")
        if not isinstance(self.default_inbound_action, FirewallInboundAction):
            raise TypeError("inbound action must use the closed enum.")
        if self.block_all_inbound is not None and not isinstance(
            self.block_all_inbound, bool
        ):
            raise TypeError("block_all_inbound must be boolean or unknown.")


@dataclass(frozen=True)
class FirewallInboundPostureObservation:
    technology_id: str
    profiles: tuple[FirewallProfileObservation, ...]

    def __post_init__(self) -> None:
        _text(self.technology_id, "firewall technology identifier", 128)
        if not isinstance(self.profiles, tuple) or not self.profiles:
            raise ValueError("firewall posture requires an immutable profile tuple.")
        if not all(isinstance(item, FirewallProfileObservation) for item in self.profiles):
            raise TypeError("firewall posture contains an invalid profile.")
        profile_ids = tuple(item.profile for item in self.profiles)
        if len(set(profile_ids)) != len(profile_ids):
            raise ValueError("firewall posture profiles must be unique.")
