"""Private deterministic capability metadata and proposal-binding primitives."""

from __future__ import annotations

from hashlib import sha256

from .contracts import (
    CapabilityAvailability,
    CapabilityExpectedEffect,
    CapabilityMetadata,
    CapabilityParameterKind,
    CapabilityParameterSpec,
    CapabilityTarget,
    CapabilityTargetKind,
    EffectClass,
    PermissionClass,
    PrivacyClass,
    ProposalParameter,
)


_PARAMETER_HEADER = b"CWT-PARAMETERS-V1\0"
_TARGET_HEADER = b"CWT-TARGET-V1\0"


def _effect(
    effect_id: str,
    effect_class: EffectClass,
    summary: str,
) -> CapabilityExpectedEffect:
    return CapabilityExpectedEffect(
        effect_id=effect_id,
        effect_class=effect_class,
        summary=summary,
    )


def _parameter(
    key: str,
    kind: CapabilityParameterKind,
    required: bool,
    privacy_class: PrivacyClass,
) -> CapabilityParameterSpec:
    return CapabilityParameterSpec(
        key=key,
        kind=kind,
        required=required,
        privacy_class=privacy_class,
    )


def _metadata(
    operation_name: str,
    title: str,
    summary: str,
    effect_class: EffectClass,
    permission_class: PermissionClass,
    privacy_class: PrivacyClass,
    expected_effects: tuple[CapabilityExpectedEffect, ...],
    target_kinds: tuple[CapabilityTargetKind, ...],
    parameters: tuple[CapabilityParameterSpec, ...] = (),
) -> CapabilityMetadata:
    return CapabilityMetadata(
        capability_id=f"cyberwatchtower.application.{operation_name}",
        capability_version="1",
        title=title,
        summary=summary,
        effect_class=effect_class,
        permission_class=permission_class,
        privacy_class=privacy_class,
        availability=CapabilityAvailability.AVAILABLE,
        expected_effects=expected_effects,
        target_kinds=target_kinds,
        parameters=parameters,
    )


def _validate_catalog(
    catalog: tuple[CapabilityMetadata, ...],
) -> tuple[CapabilityMetadata, ...]:
    if not isinstance(catalog, tuple) or not all(
        isinstance(item, CapabilityMetadata) for item in catalog
    ):
        raise TypeError("capability catalog must be an immutable metadata tuple.")
    if len(catalog) != 11 or len(catalog) > 64:
        raise ValueError("initial capability catalog must contain exactly eleven entries.")
    identities = tuple(
        (item.capability_id, item.capability_version) for item in catalog
    )
    if len(set(identities)) != len(identities):
        raise ValueError("capability catalog cannot contain duplicate identities.")
    expected = tuple(
        sorted(
            catalog,
            key=lambda item: (
                item.capability_id,
                int(item.capability_version),
            ),
        )
    )
    if expected != catalog:
        raise ValueError("capability catalog must use canonical ordering.")
    return catalog


_CAPABILITY_CATALOG = _validate_catalog((
    _metadata(
        operation_name="assess_and_save_current_system",
        title="Assess and save this system",
        summary=(
            "Run the frozen current-system assessment and create one canonical "
            "saved report."
        ),
        effect_class=EffectClass.LOCAL_AUTHORITATIVE_STATE_CHANGE,
        permission_class=PermissionClass.USER_APPROVAL_REQUIRED,
        privacy_class=PrivacyClass.SENSITIVE_LOCAL_DATA,
        expected_effects=(
            _effect(
                "observe_current_system",
                EffectClass.SYSTEM_OBSERVATION,
                "Observe the current local system through the frozen assessment boundary.",
            ),
            _effect(
                "write_canonical_report",
                EffectClass.LOCAL_AUTHORITATIVE_STATE_CHANGE,
                "Create one canonical saved assessment report.",
            ),
        ),
        target_kinds=(CapabilityTargetKind.SYSTEM,),
    ),
    _metadata(
        operation_name="assess_current_system",
        title="Assess this system",
        summary=(
            "Run the frozen read-only current-system assessment without "
            "persistence."
        ),
        effect_class=EffectClass.SYSTEM_OBSERVATION,
        permission_class=PermissionClass.READ_ONLY,
        privacy_class=PrivacyClass.SENSITIVE_LOCAL_DATA,
        expected_effects=(
            _effect(
                "observe_current_system",
                EffectClass.SYSTEM_OBSERVATION,
                "Observe the current local system through the frozen assessment boundary.",
            ),
        ),
        target_kinds=(CapabilityTargetKind.SYSTEM,),
    ),
    _metadata(
        operation_name="compare_saved_reports",
        title="Compare saved reports",
        summary=(
            "Compare two exact same-system canonical saved reports with frozen "
            "history semantics."
        ),
        effect_class=EffectClass.LOCAL_READ,
        permission_class=PermissionClass.READ_ONLY,
        privacy_class=PrivacyClass.SENSITIVE_LOCAL_DATA,
        expected_effects=(
            _effect(
                "read_canonical_reports",
                EffectClass.LOCAL_READ,
                "Read and compare two exact same-system canonical saved reports.",
            ),
        ),
        target_kinds=(CapabilityTargetKind.REPORT,),
    ),
    _metadata(
        operation_name="get_finding_timeline",
        title="Get finding timeline",
        summary=(
            "Read one bounded exact-system finding lifecycle timeline from "
            "SecurityMemory."
        ),
        effect_class=EffectClass.LOCAL_READ,
        permission_class=PermissionClass.READ_ONLY,
        privacy_class=PrivacyClass.SENSITIVE_LOCAL_DATA,
        expected_effects=(
            _effect(
                "read_derived_memory",
                EffectClass.LOCAL_READ,
                "Read a bounded exact-system finding timeline from SecurityMemory.",
            ),
        ),
        target_kinds=(CapabilityTargetKind.FINDING,),
        parameters=(
            _parameter(
                "limit",
                CapabilityParameterKind.INTEGER,
                False,
                PrivacyClass.PUBLIC_METADATA,
            ),
        ),
    ),
    _metadata(
        operation_name="get_latest_saved_report",
        title="Get latest saved report",
        summary="Read the latest canonical saved report for one exact system.",
        effect_class=EffectClass.LOCAL_READ,
        permission_class=PermissionClass.READ_ONLY,
        privacy_class=PrivacyClass.SENSITIVE_LOCAL_DATA,
        expected_effects=(
            _effect(
                "read_report_catalog",
                EffectClass.LOCAL_READ,
                "Read the latest canonical saved-report metadata and report for one exact system.",
            ),
        ),
        target_kinds=(CapabilityTargetKind.SYSTEM,),
    ),
    _metadata(
        operation_name="get_memory_health",
        title="Get Memory health",
        summary="Read bounded privacy-safe SecurityMemory health information.",
        effect_class=EffectClass.LOCAL_READ,
        permission_class=PermissionClass.READ_ONLY,
        privacy_class=PrivacyClass.LOCAL_SECURITY_DATA,
        expected_effects=(
            _effect(
                "read_memory_health",
                EffectClass.LOCAL_READ,
                "Read bounded privacy-safe SecurityMemory health state.",
            ),
        ),
        target_kinds=(CapabilityTargetKind.APPLICATION,),
    ),
    _metadata(
        operation_name="get_saved_report",
        title="Get saved report",
        summary="Read one exact canonical saved report.",
        effect_class=EffectClass.LOCAL_READ,
        permission_class=PermissionClass.READ_ONLY,
        privacy_class=PrivacyClass.SENSITIVE_LOCAL_DATA,
        expected_effects=(
            _effect(
                "read_canonical_report",
                EffectClass.LOCAL_READ,
                "Read one exact canonical saved report.",
            ),
        ),
        target_kinds=(CapabilityTargetKind.REPORT,),
    ),
    _metadata(
        operation_name="get_score_history",
        title="Get score history",
        summary="Read bounded score history for one exact system and time range.",
        effect_class=EffectClass.LOCAL_READ,
        permission_class=PermissionClass.READ_ONLY,
        privacy_class=PrivacyClass.LOCAL_SECURITY_DATA,
        expected_effects=(
            _effect(
                "read_derived_memory",
                EffectClass.LOCAL_READ,
                "Read bounded score-history series from SecurityMemory.",
            ),
        ),
        target_kinds=(CapabilityTargetKind.SYSTEM,),
        parameters=(
            _parameter(
                "end_at",
                CapabilityParameterKind.UTC_TIMESTAMP,
                True,
                PrivacyClass.LOCAL_SECURITY_DATA,
            ),
            _parameter(
                "limit",
                CapabilityParameterKind.INTEGER,
                False,
                PrivacyClass.PUBLIC_METADATA,
            ),
            _parameter(
                "scoring_version",
                CapabilityParameterKind.TEXT,
                False,
                PrivacyClass.PUBLIC_METADATA,
            ),
            _parameter(
                "start_at",
                CapabilityParameterKind.UTC_TIMESTAMP,
                True,
                PrivacyClass.LOCAL_SECURITY_DATA,
            ),
        ),
    ),
    _metadata(
        operation_name="ingest_saved_report_into_memory",
        title="Ingest report into Memory",
        summary=(
            "Idempotently derive SecurityMemory state from one trusted canonical "
            "report."
        ),
        effect_class=EffectClass.LOCAL_DERIVED_STATE_CHANGE,
        permission_class=PermissionClass.USER_APPROVAL_REQUIRED,
        privacy_class=PrivacyClass.SENSITIVE_LOCAL_DATA,
        expected_effects=(
            _effect(
                "read_canonical_report",
                EffectClass.LOCAL_READ,
                "Read one exact canonical saved report.",
            ),
            _effect(
                "write_derived_memory",
                EffectClass.LOCAL_DERIVED_STATE_CHANGE,
                "Idempotently derive SecurityMemory state from that report.",
            ),
        ),
        target_kinds=(CapabilityTargetKind.REPORT,),
    ),
    _metadata(
        operation_name="list_recurring_findings",
        title="List recurring findings",
        summary=(
            "Read a bounded recurring-finding view for one exact system from "
            "SecurityMemory."
        ),
        effect_class=EffectClass.LOCAL_READ,
        permission_class=PermissionClass.READ_ONLY,
        privacy_class=PrivacyClass.SENSITIVE_LOCAL_DATA,
        expected_effects=(
            _effect(
                "read_derived_memory",
                EffectClass.LOCAL_READ,
                "Read a bounded recurring-finding view from SecurityMemory.",
            ),
        ),
        target_kinds=(CapabilityTargetKind.SYSTEM,),
        parameters=(
            _parameter(
                "active_only",
                CapabilityParameterKind.BOOLEAN,
                False,
                PrivacyClass.LOCAL_SECURITY_DATA,
            ),
            _parameter(
                "limit",
                CapabilityParameterKind.INTEGER,
                False,
                PrivacyClass.PUBLIC_METADATA,
            ),
        ),
    ),
    _metadata(
        operation_name="list_saved_reports",
        title="List saved reports",
        summary="Read bounded canonical saved-report metadata for one exact system.",
        effect_class=EffectClass.LOCAL_READ,
        permission_class=PermissionClass.READ_ONLY,
        privacy_class=PrivacyClass.LOCAL_SECURITY_DATA,
        expected_effects=(
            _effect(
                "read_report_catalog",
                EffectClass.LOCAL_READ,
                "Read bounded canonical saved-report metadata for one exact system.",
            ),
        ),
        target_kinds=(CapabilityTargetKind.SYSTEM,),
    ),
))


def _capability_catalog() -> tuple[CapabilityMetadata, ...]:
    """Return the immutable, statically validated application catalog."""

    return _CAPABILITY_CATALOG


def _lookup_capability(
    capability_id: str,
    capability_version: str,
) -> CapabilityMetadata | None:
    """Return one exact catalog identity or the private not-found signal."""

    if not isinstance(capability_id, str) or not isinstance(
        capability_version, str
    ):
        return None
    for capability in _CAPABILITY_CATALOG:
        if (
            capability.capability_id == capability_id
            and capability.capability_version == capability_version
        ):
            return capability
    return None


def _parameter_kind_tag(kind: CapabilityParameterKind) -> bytes:
    if kind == CapabilityParameterKind.TEXT:
        return b"T"
    if kind == CapabilityParameterKind.INTEGER:
        return b"I"
    if kind == CapabilityParameterKind.BOOLEAN:
        return b"B"
    if kind == CapabilityParameterKind.UTC_TIMESTAMP:
        return b"D"
    raise TypeError("parameter kind must use the closed application enum.")


def _canonical_parameter_bytes(
    parameters: tuple[ProposalParameter, ...],
) -> bytes:
    """Encode an already-effective validated parameter tuple."""

    if not isinstance(parameters, tuple) or not all(
        isinstance(parameter, ProposalParameter) for parameter in parameters
    ):
        raise TypeError("parameters must be an immutable ProposalParameter tuple.")
    if len(parameters) > 32:
        raise ValueError("parameters exceed the supported bound.")
    keys = tuple(parameter.key for parameter in parameters)
    if keys != tuple(sorted(keys)) or len(set(keys)) != len(keys):
        raise ValueError("parameters must be uniquely ordered by key.")

    encoded = bytearray(_PARAMETER_HEADER)
    for parameter in parameters:
        key_bytes = parameter.key.encode("utf-8")
        value_bytes = parameter.value.encode("utf-8")
        encoded.extend(len(key_bytes).to_bytes(2, "big"))
        encoded.extend(key_bytes)
        encoded.extend(_parameter_kind_tag(parameter.kind))
        encoded.extend(len(value_bytes).to_bytes(4, "big"))
        encoded.extend(value_bytes)
    return bytes(encoded)


def _parameter_digest(parameters: tuple[ProposalParameter, ...]) -> str:
    """Return the lowercase SHA-256 binding for effective parameters."""

    return sha256(_canonical_parameter_bytes(parameters)).hexdigest()


def _target_kind_tag(kind: CapabilityTargetKind) -> bytes:
    if kind == CapabilityTargetKind.APPLICATION:
        return b"A"
    if kind == CapabilityTargetKind.SYSTEM:
        return b"S"
    if kind == CapabilityTargetKind.REPORT:
        return b"R"
    if kind == CapabilityTargetKind.FINDING:
        return b"F"
    raise TypeError("target kind must use the closed application enum.")


def _canonical_target_bytes(target: CapabilityTarget) -> bytes:
    """Encode one validated opaque target without resolving its identity."""

    if not isinstance(target, CapabilityTarget):
        raise TypeError("target must use the immutable CapabilityTarget contract.")

    system_bytes = target.system_id.encode("utf-8")
    encoded = bytearray(_TARGET_HEADER)
    encoded.extend(_target_kind_tag(target.kind))
    encoded.extend(len(system_bytes).to_bytes(4, "big"))
    encoded.extend(system_bytes)
    encoded.extend(len(target.report_ids).to_bytes(1, "big"))
    for report_id in target.report_ids:
        report_bytes = report_id.value.encode("utf-8")
        encoded.extend(len(report_bytes).to_bytes(2, "big"))
        encoded.extend(report_bytes)
    if target.finding_id is None:
        encoded.extend(b"\0")
    else:
        finding_bytes = target.finding_id.encode("utf-8")
        encoded.extend(b"\1")
        encoded.extend(len(finding_bytes).to_bytes(2, "big"))
        encoded.extend(finding_bytes)
    return bytes(encoded)


def _target_digest(target: CapabilityTarget) -> str:
    """Return the lowercase SHA-256 binding for one opaque target."""

    return sha256(_canonical_target_bytes(target)).hexdigest()
