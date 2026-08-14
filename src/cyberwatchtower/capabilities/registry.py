from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from cyberwatchtower.finding_identity import finding_identity
from cyberwatchtower.history import compare_reports, load_reports


class PermissionClass(str, Enum):
    READ_ONLY = "READ_ONLY"
    USER_APPROVAL_REQUIRED = "USER_APPROVAL_REQUIRED"
    PROHIBITED = "PROHIBITED"


@dataclass(frozen=True)
class CapabilityRequest:
    capability_id: str
    parameters: Mapping[str, object]


@dataclass(frozen=True)
class CapabilityPlan:
    requests: tuple[CapabilityRequest, ...]


@dataclass(frozen=True)
class CapabilityContext:
    report_directory: str | Path = "reports"
    reports: tuple[dict, ...] = ()


@dataclass(frozen=True)
class CapabilityDefinition:
    capability_id: str
    permission: PermissionClass
    handler: Callable[[CapabilityRequest, CapabilityContext], object] | None = None


class CapabilityDenied(RuntimeError):
    pass


class ApprovalRequired(RuntimeError):
    pass


class CapabilityRegistry:
    def __init__(self) -> None:
        self._definitions: dict[str, CapabilityDefinition] = {}

    def register(self, definition: CapabilityDefinition) -> None:
        if definition.capability_id in self._definitions:
            raise ValueError(f"Duplicate capability: {definition.capability_id}")
        self._definitions[definition.capability_id] = definition

    def definition(self, capability_id: str) -> CapabilityDefinition:
        try:
            return self._definitions[capability_id]
        except KeyError as exc:
            raise CapabilityDenied(f"Capability is not allowlisted: {capability_id}") from exc

    def execute(
        self,
        request: CapabilityRequest,
        context: CapabilityContext,
    ) -> object:
        definition = self.definition(request.capability_id)
        if definition.permission == PermissionClass.PROHIBITED:
            raise CapabilityDenied(f"Capability is prohibited: {request.capability_id}")
        if definition.permission == PermissionClass.USER_APPROVAL_REQUIRED:
            raise ApprovalRequired(f"Explicit approval required: {request.capability_id}")
        if definition.handler is None:
            raise CapabilityDenied(
                f"Capability is not implemented in Intelligence Core v0.1: "
                f"{request.capability_id}"
            )
        return definition.handler(request, context)


def _load_reports(request: CapabilityRequest, context: CapabilityContext):
    return load_reports(
        context.report_directory,
        hostname=request.parameters.get("hostname"),
        system_id=request.parameters.get("system_id"),
    )


def _compare_scans(request: CapabilityRequest, context: CapabilityContext):
    if len(context.reports) < 2:
        return None
    return compare_reports(context.reports[-2], context.reports[-1])


def _explain_finding(request: CapabilityRequest, context: CapabilityContext):
    requested_id = request.parameters.get("finding_id")
    if not context.reports:
        return None
    return next(
        (
            finding
            for finding in context.reports[-1].get("findings", [])
            if finding_identity(finding) == requested_id
        ),
        None,
    )


def build_read_only_registry() -> CapabilityRegistry:
    registry = CapabilityRegistry()
    for capability_id, handler in (
        ("load_reports", _load_reports),
        ("compare_scans", _compare_scans),
        ("explain_finding", _explain_finding),
    ):
        registry.register(
            CapabilityDefinition(capability_id, PermissionClass.READ_ONLY, handler)
        )
    for capability_id in ("scan_host", "inspect_process", "inspect_service"):
        registry.register(CapabilityDefinition(
            capability_id,
            PermissionClass.USER_APPROVAL_REQUIRED,
        ))
    return registry
