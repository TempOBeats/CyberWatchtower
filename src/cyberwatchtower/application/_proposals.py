"""Private construction of inert, fully bound capability proposals."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from uuid import uuid4

from ._capabilities import (
    _capability_catalog,
    _lookup_capability,
    _parameter_digest,
    _target_digest,
)
from .contracts import (
    CapabilityAvailability,
    CapabilityMetadata,
    CapabilityParameterKind,
    CapabilityParameterSpec,
    CapabilityProposal,
    CapabilityTarget,
    CapabilityTargetKind,
    EffectClass,
    PermissionClass,
    ProposalParameter,
    ProposeCapabilityRequest,
    ReusePolicy,
)


_PROPOSAL_LIFETIME = timedelta(minutes=10)


class _ProposalFailureCode(str, Enum):
    UNKNOWN_CAPABILITY = "UNKNOWN_CAPABILITY"
    STALE_CAPABILITY_VERSION = "STALE_CAPABILITY_VERSION"
    UNAVAILABLE_CAPABILITY = "UNAVAILABLE_CAPABILITY"
    PROHIBITED_CAPABILITY = "PROHIBITED_CAPABILITY"
    INCOMPATIBLE_TARGET = "INCOMPATIBLE_TARGET"
    UNKNOWN_PARAMETER = "UNKNOWN_PARAMETER"
    DUPLICATE_PARAMETER = "DUPLICATE_PARAMETER"
    MISSING_REQUIRED_PARAMETER = "MISSING_REQUIRED_PARAMETER"
    WRONG_PARAMETER_KIND = "WRONG_PARAMETER_KIND"
    INVALID_PARAMETER_VALUE = "INVALID_PARAMETER_VALUE"


class _ProposalConstructionError(ValueError):
    """Bounded private failure signal for later application error translation."""

    def __init__(self, code: _ProposalFailureCode) -> None:
        self.code = code
        super().__init__(code.value)


@dataclass(frozen=True, slots=True)
class _ParameterPolicy:
    capability_id: str
    key: str
    default: ProposalParameter | None = None
    minimum: int | None = None
    maximum: int | None = None
    allowed_text: tuple[str, ...] = ()


def _default_parameter(
    key: str,
    kind: CapabilityParameterKind,
    value: str,
) -> ProposalParameter:
    return ProposalParameter(key=key, kind=kind, value=value)


_PARAMETER_POLICIES = (
    _ParameterPolicy(
        capability_id="cyberwatchtower.application.get_finding_timeline",
        key="limit",
        default=_default_parameter("limit", CapabilityParameterKind.INTEGER, "100"),
        minimum=1,
        maximum=500,
    ),
    _ParameterPolicy(
        capability_id="cyberwatchtower.application.get_score_history",
        key="end_at",
    ),
    _ParameterPolicy(
        capability_id="cyberwatchtower.application.get_score_history",
        key="limit",
        default=_default_parameter("limit", CapabilityParameterKind.INTEGER, "100"),
        minimum=1,
        maximum=500,
    ),
    _ParameterPolicy(
        capability_id="cyberwatchtower.application.get_score_history",
        key="scoring_version",
        allowed_text=("1", "2"),
    ),
    _ParameterPolicy(
        capability_id="cyberwatchtower.application.get_score_history",
        key="start_at",
    ),
    _ParameterPolicy(
        capability_id="cyberwatchtower.application.list_recurring_findings",
        key="active_only",
        default=_default_parameter(
            "active_only", CapabilityParameterKind.BOOLEAN, "false"
        ),
    ),
    _ParameterPolicy(
        capability_id="cyberwatchtower.application.list_recurring_findings",
        key="limit",
        default=_default_parameter("limit", CapabilityParameterKind.INTEGER, "50"),
        minimum=1,
        maximum=200,
    ),
)


_REPORT_CARDINALITIES = (
    ("cyberwatchtower.application.compare_saved_reports", 2),
    ("cyberwatchtower.application.get_saved_report", 1),
    ("cyberwatchtower.application.ingest_saved_report_into_memory", 1),
)


def _fail(code: _ProposalFailureCode) -> None:
    raise _ProposalConstructionError(code)


def _spec_for(
    metadata: CapabilityMetadata,
    key: str,
) -> CapabilityParameterSpec | None:
    for spec in metadata.parameters:
        if spec.key == key:
            return spec
    return None


def _policy_for(capability_id: str, key: str) -> _ParameterPolicy | None:
    for policy in _PARAMETER_POLICIES:
        if policy.capability_id == capability_id and policy.key == key:
            return policy
    return None


def _validate_parameter_policies() -> tuple[_ParameterPolicy, ...]:
    identities = tuple(
        (policy.capability_id, policy.key) for policy in _PARAMETER_POLICIES
    )
    if len(set(identities)) != len(identities) or identities != tuple(sorted(identities)):
        raise ValueError("proposal parameter policy must be unique and ordered.")
    catalog_specs = tuple(
        (metadata.capability_id, spec.key)
        for metadata in _capability_catalog()
        for spec in metadata.parameters
    )
    if identities != tuple(sorted(catalog_specs)):
        raise ValueError("proposal parameter policy must cover the frozen catalog exactly.")
    for policy in _PARAMETER_POLICIES:
        metadata = next(
            item
            for item in _capability_catalog()
            if item.capability_id == policy.capability_id
        )
        spec = _spec_for(metadata, policy.key)
        if spec is None:
            raise ValueError("proposal parameter policy references an unknown spec.")
        if policy.default is not None:
            if spec.required or (
                policy.default.key != spec.key or policy.default.kind != spec.kind
            ):
                raise ValueError("proposal parameter default conflicts with its spec.")
        if (policy.minimum is None) != (policy.maximum is None):
            raise ValueError("proposal integer ranges require both bounds.")
        if policy.minimum is not None and (
            spec.kind != CapabilityParameterKind.INTEGER
            or policy.minimum > policy.maximum
        ):
            raise ValueError("proposal parameter integer range is invalid.")
        if policy.allowed_text and spec.kind != CapabilityParameterKind.TEXT:
            raise ValueError("proposal text choices require a text parameter.")
    return _PARAMETER_POLICIES


_VALIDATED_PARAMETER_POLICIES = _validate_parameter_policies()


def _resolve_capability(
    capability_id: str,
    capability_version: str,
) -> CapabilityMetadata:
    metadata = _lookup_capability(capability_id, capability_version)
    if metadata is not None:
        return metadata
    if any(
        item.capability_id == capability_id for item in _capability_catalog()
    ):
        _fail(_ProposalFailureCode.STALE_CAPABILITY_VERSION)
    _fail(_ProposalFailureCode.UNKNOWN_CAPABILITY)


def _check_capability_policy(metadata: CapabilityMetadata) -> None:
    if (
        metadata.availability == CapabilityAvailability.PROHIBITED
        or metadata.permission_class == PermissionClass.PROHIBITED
        or metadata.effect_class == EffectClass.PROHIBITED
    ):
        _fail(_ProposalFailureCode.PROHIBITED_CAPABILITY)
    if metadata.availability == CapabilityAvailability.UNAVAILABLE:
        _fail(_ProposalFailureCode.UNAVAILABLE_CAPABILITY)


def _validate_target(
    metadata: CapabilityMetadata,
    request: ProposeCapabilityRequest,
) -> CapabilityTarget:
    target = request.target
    if request.system_id != target.system_id or target.kind not in metadata.target_kinds:
        _fail(_ProposalFailureCode.INCOMPATIBLE_TARGET)

    for capability_id, report_count in _REPORT_CARDINALITIES:
        if metadata.capability_id == capability_id and len(target.report_ids) != report_count:
            _fail(_ProposalFailureCode.INCOMPATIBLE_TARGET)
    if (
        metadata.capability_id
        == "cyberwatchtower.application.get_finding_timeline"
        and target.report_ids
    ):
        _fail(_ProposalFailureCode.INCOMPATIBLE_TARGET)
    return target


def _timestamp_value(parameter: ProposalParameter) -> datetime:
    try:
        return datetime.strptime(
            parameter.value, "%Y-%m-%dT%H:%M:%S.%fZ"
        ).replace(tzinfo=timezone.utc)
    except ValueError:
        _fail(_ProposalFailureCode.INVALID_PARAMETER_VALUE)


def _validate_effective_values(
    metadata: CapabilityMetadata,
    parameters: tuple[ProposalParameter, ...],
) -> None:
    for parameter in parameters:
        policy = _policy_for(metadata.capability_id, parameter.key)
        if policy is None:
            continue
        if policy.minimum is not None:
            value = int(parameter.value)
            if not policy.minimum <= value <= policy.maximum:
                _fail(_ProposalFailureCode.INVALID_PARAMETER_VALUE)
        if policy.allowed_text and parameter.value not in policy.allowed_text:
            _fail(_ProposalFailureCode.INVALID_PARAMETER_VALUE)

    if metadata.capability_id == "cyberwatchtower.application.get_score_history":
        by_key = {parameter.key: parameter for parameter in parameters}
        start_at = _timestamp_value(by_key["start_at"])
        end_at = _timestamp_value(by_key["end_at"])
        if end_at < start_at or end_at - start_at > timedelta(days=366):
            _fail(_ProposalFailureCode.INVALID_PARAMETER_VALUE)


def _materialize_parameters(
    metadata: CapabilityMetadata,
    parameters: tuple[ProposalParameter, ...],
) -> tuple[ProposalParameter, ...]:
    if not isinstance(parameters, tuple) or not all(
        isinstance(parameter, ProposalParameter) for parameter in parameters
    ):
        raise TypeError("parameters must be an immutable ProposalParameter tuple.")
    if len(parameters) > 32:
        _fail(_ProposalFailureCode.INVALID_PARAMETER_VALUE)
    keys = tuple(parameter.key for parameter in parameters)
    if len(set(keys)) != len(keys):
        _fail(_ProposalFailureCode.DUPLICATE_PARAMETER)
    if keys != tuple(sorted(keys)):
        _fail(_ProposalFailureCode.INVALID_PARAMETER_VALUE)

    supplied = []
    for parameter in parameters:
        spec = _spec_for(metadata, parameter.key)
        if spec is None:
            _fail(_ProposalFailureCode.UNKNOWN_PARAMETER)
        if parameter.kind != spec.kind:
            _fail(_ProposalFailureCode.WRONG_PARAMETER_KIND)
        supplied.append(parameter)

    supplied_keys = set(keys)
    effective = list(supplied)
    for spec in metadata.parameters:
        if spec.key in supplied_keys:
            continue
        if spec.required:
            _fail(_ProposalFailureCode.MISSING_REQUIRED_PARAMETER)
        policy = _policy_for(metadata.capability_id, spec.key)
        if policy is not None and policy.default is not None:
            effective.append(policy.default)

    result = tuple(sorted(effective, key=lambda parameter: parameter.key))
    _validate_effective_values(metadata, result)
    return result


def _new_proposal_id() -> str:
    """Generate one private UUID4 correlation identity."""

    return f"proposal:{uuid4().hex}"


def _construct_proposal_with_id(
    request: ProposeCapabilityRequest,
    issued_at: datetime,
    proposal_id: str,
) -> CapabilityProposal:
    """Construct a proposal with explicit entropy for deterministic testing."""

    if not isinstance(request, ProposeCapabilityRequest):
        raise TypeError("request must use the immutable proposal request contract.")
    metadata = _resolve_capability(
        request.capability_id,
        request.capability_version,
    )
    return _construct_proposal_from_metadata(
        request=request,
        metadata=metadata,
        issued_at=issued_at,
        proposal_id=proposal_id,
    )


def _construct_proposal_from_metadata(
    request: ProposeCapabilityRequest,
    metadata: CapabilityMetadata,
    issued_at: datetime,
    proposal_id: str | None,
) -> CapabilityProposal:
    """Private fixture seam that applies the same policy to supplied metadata."""

    if not isinstance(request, ProposeCapabilityRequest):
        raise TypeError("request must use the immutable proposal request contract.")
    if not isinstance(metadata, CapabilityMetadata):
        raise TypeError("metadata must use the immutable capability contract.")
    if (
        request.capability_id != metadata.capability_id
        or request.capability_version != metadata.capability_version
    ):
        _fail(_ProposalFailureCode.UNKNOWN_CAPABILITY)

    _check_capability_policy(metadata)
    target = _validate_target(metadata, request)
    effective_parameters = _materialize_parameters(metadata, request.parameters)
    target_digest = _target_digest(target)
    parameter_digest = _parameter_digest(effective_parameters)
    if proposal_id is None:
        proposal_id = _new_proposal_id()
    return CapabilityProposal(
        proposal_id=proposal_id,
        system_id=request.system_id,
        capability_id=metadata.capability_id,
        capability_version=metadata.capability_version,
        target=target,
        target_digest=target_digest,
        parameters=effective_parameters,
        parameter_digest=parameter_digest,
        effect_class=metadata.effect_class,
        permission_class=metadata.permission_class,
        privacy_class=metadata.privacy_class,
        expected_effects=metadata.expected_effects,
        issued_at=issued_at,
        expires_at=issued_at + _PROPOSAL_LIFETIME,
        reuse_policy=ReusePolicy.ONE_TIME,
    )


def _construct_proposal(
    request: ProposeCapabilityRequest,
    issued_at: datetime,
) -> CapabilityProposal:
    """Construct one inert proposal using private UUID4 entropy."""

    if not isinstance(request, ProposeCapabilityRequest):
        raise TypeError("request must use the immutable proposal request contract.")
    metadata = _resolve_capability(
        request.capability_id,
        request.capability_version,
    )
    return _construct_proposal_from_metadata(
        request=request,
        metadata=metadata,
        issued_at=issued_at,
        proposal_id=None,
    )
