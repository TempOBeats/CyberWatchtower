import ast
import dataclasses
import inspect
import unittest
import unicodedata
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import get_type_hints

import cyberwatchtower.application as application
from cyberwatchtower.application import (
    AssistantClaim, AssistantEvidenceReference, AssistantEvidenceRole,
    AssistantEvidenceSourceKind, AssistantGroundedResponse, AssistantIntent,
    AssistantQuestionRequest, AssistantQuestionResult, AssistantQuestionStatus,
    AssistantSection, AssistantSectionId, CapabilityAvailability,
    CapabilityCatalogResult, CapabilityExpectedEffect, CapabilityMetadata,
    CapabilityParameterKind, CapabilityParameterSpec, CapabilityProposal,
    CapabilityTarget, CapabilityTargetKind, CyberWatchtowerApplication,
    EffectClass, EpistemicState, ListCapabilitiesRequest, PermissionClass,
    PrivacyClass, ProposalParameter, ProposeCapabilityRequest,
    ProposeCapabilityResult, ReportId, ReusePolicy, SavedReportReference,
    SecurityBriefingRequest, SecurityBriefingResult,
)
from cyberwatchtower.capabilities.registry import PermissionClass as LegacyPermissionClass


ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "src" / "cyberwatchtower" / "application" / "contracts.py"
APPLICATION_INIT = ROOT / "src" / "cyberwatchtower" / "application" / "__init__.py"

F_ENUMS = {
    EffectClass: (
        "PURE", "LOCAL_READ", "LOCAL_DERIVED_STATE_CHANGE",
        "LOCAL_AUTHORITATIVE_STATE_CHANGE", "SYSTEM_OBSERVATION",
        "SYSTEM_STATE_CHANGE", "EXTERNAL_IO", "PROHIBITED",
    ),
    PermissionClass: ("READ_ONLY", "USER_APPROVAL_REQUIRED", "PROHIBITED"),
    PrivacyClass: (
        "PUBLIC_METADATA", "LOCAL_SECURITY_DATA", "SENSITIVE_LOCAL_DATA", "SECRET",
    ),
    CapabilityAvailability: ("AVAILABLE", "UNAVAILABLE", "PROHIBITED"),
    CapabilityParameterKind: ("TEXT", "INTEGER", "BOOLEAN", "UTC_TIMESTAMP"),
    CapabilityTargetKind: ("APPLICATION", "SYSTEM", "REPORT", "FINDING"),
    ReusePolicy: ("ONE_TIME",),
    EpistemicState: ("OBSERVED", "STRONGLY_SUPPORTED", "POSSIBLE", "UNKNOWN"),
    AssistantSectionId: (
        "posture", "changes", "priorities", "explanation", "coverage", "next_steps",
    ),
    AssistantEvidenceSourceKind: (
        "CANONICAL_REPORT", "REPORT_FINDING", "REPORT_COMPARISON",
        "DETERMINISTIC_ADVISOR",
    ),
    AssistantEvidenceRole: ("OBSERVED_FACT", "DETERMINISTIC_DERIVATION"),
    AssistantIntent: (
        "SUMMARY", "WHY_FINDING", "WHAT_CHANGED", "WHAT_TO_FIX_FIRST", "COVERAGE",
    ),
    AssistantQuestionStatus: (
        "ANSWERED", "UNSUPPORTED", "AMBIGUOUS", "MISSING_CONTEXT",
    ),
}

F_DTOS = (
    CapabilityExpectedEffect, CapabilityParameterSpec, CapabilityMetadata,
    ProposalParameter, CapabilityTarget, AssistantEvidenceReference,
    AssistantClaim, AssistantSection, AssistantGroundedResponse,
    SecurityBriefingRequest, AssistantQuestionRequest, SecurityBriefingResult,
    AssistantQuestionResult, ListCapabilitiesRequest, CapabilityCatalogResult,
    ProposeCapabilityRequest, CapabilityProposal, ProposeCapabilityResult,
)

EXPECTED_FIELDS = {
    CapabilityExpectedEffect: ("effect_id", "effect_class", "summary"),
    CapabilityParameterSpec: ("key", "kind", "required", "privacy_class"),
    CapabilityMetadata: (
        "capability_id", "capability_version", "title", "summary", "effect_class",
        "permission_class", "privacy_class", "availability", "expected_effects",
        "target_kinds", "parameters",
    ),
    ProposalParameter: ("key", "kind", "value"),
    CapabilityTarget: ("kind", "system_id", "report_ids", "finding_id"),
    AssistantEvidenceReference: (
        "evidence_id", "source_kind", "source_id", "evidence_role", "report_ids",
    ),
    AssistantClaim: ("claim_id", "text", "epistemic_state", "evidence_refs"),
    AssistantSection: ("section_id", "title", "claims", "omitted_item_count"),
    AssistantGroundedResponse: ("sections", "evidence"),
    SecurityBriefingRequest: ("system_id", "current_report_id", "previous_report_id"),
    AssistantQuestionRequest: (
        "system_id", "current_report_id", "previous_report_id", "question",
    ),
    SecurityBriefingResult: (
        "operation_id", "system_id", "current_report", "previous_report", "response",
    ),
    AssistantQuestionResult: (
        "operation_id", "system_id", "current_report", "previous_report", "status",
        "intent", "response",
    ),
    ListCapabilitiesRequest: (),
    CapabilityCatalogResult: ("operation_id", "capabilities", "returned_count"),
    ProposeCapabilityRequest: (
        "system_id", "capability_id", "capability_version", "target", "parameters",
    ),
    CapabilityProposal: (
        "proposal_id", "system_id", "capability_id", "capability_version", "target",
        "target_digest", "parameters", "parameter_digest", "effect_class",
        "permission_class", "privacy_class", "expected_effects", "issued_at",
        "expires_at", "reuse_policy",
    ),
    ProposeCapabilityResult: ("operation_id", "proposal"),
}


def _report_id(character="a"):
    return ReportId("report:" + character * 64)


def _effect(effect_id="read_report"):
    return CapabilityExpectedEffect(
        effect_id,
        EffectClass.LOCAL_READ,
        f"Perform the bounded {effect_id} application effect.",
    )


def _target(kind=CapabilityTargetKind.SYSTEM, report_ids=(), finding_id=None):
    return CapabilityTarget(kind, "system-1", report_ids, finding_id)


def _metadata(version="1", leaf="get_saved_report"):
    return CapabilityMetadata(
        f"cyberwatchtower.application.{leaf}", version, "Get saved report",
        "Read one bounded saved report.", EffectClass.LOCAL_READ,
        PermissionClass.READ_ONLY, PrivacyClass.SENSITIVE_LOCAL_DATA,
        CapabilityAvailability.AVAILABLE, (_effect(),),
        (CapabilityTargetKind.REPORT,), (),
    )


def _evidence(evidence_id="evidence.report"):
    report_id = _report_id()
    return AssistantEvidenceReference(
        evidence_id, AssistantEvidenceSourceKind.CANONICAL_REPORT, report_id.value,
        AssistantEvidenceRole.OBSERVED_FACT, (report_id,),
    )


def _claim(claim_id="claim.posture", evidence_id="evidence.report"):
    return AssistantClaim(
        claim_id, "The saved report records the current posture.",
        EpistemicState.OBSERVED, (evidence_id,),
    )


def _response():
    evidence = _evidence()
    section = AssistantSection(
        AssistantSectionId.POSTURE, "Posture",
        (_claim(evidence_id=evidence.evidence_id),), 0,
    )
    return AssistantGroundedResponse((section,), (evidence,))


def _proposal():
    issued = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return CapabilityProposal(
        "proposal:" + "a" * 32, "system-1",
        "cyberwatchtower.application.get_saved_report", "1",
        _target(CapabilityTargetKind.REPORT, (_report_id(),)), "a" * 64, (),
        "b" * 64, EffectClass.LOCAL_READ, PermissionClass.READ_ONLY,
        PrivacyClass.SENSITIVE_LOCAL_DATA, (_effect(),), issued,
        issued + timedelta(minutes=10), ReusePolicy.ONE_TIME,
    )


class ApplicationAssistantContractTests(unittest.TestCase):
    def test_exact_enum_vocabularies(self):
        for enum_type, values in F_ENUMS.items():
            with self.subTest(enum=enum_type.__name__):
                self.assertEqual(tuple(item.value for item in enum_type), values)

    def test_permission_class_is_application_owned(self):
        self.assertIsNot(PermissionClass, LegacyPermissionClass)
        self.assertEqual(PermissionClass.__module__, "cyberwatchtower.application.contracts")

    def test_exact_public_fields_and_exports(self):
        for dto, expected in EXPECTED_FIELDS.items():
            with self.subTest(dto=dto.__name__):
                self.assertEqual(tuple(field.name for field in dataclasses.fields(dto)), expected)
                self.assertIn(dto.__name__, application.__all__)
                self.assertIs(getattr(application, dto.__name__), dto)
        for enum_type in F_ENUMS:
            self.assertIn(enum_type.__name__, application.__all__)

    def test_all_f_dtos_are_frozen_and_slotted(self):
        for dto in F_DTOS:
            with self.subTest(dto=dto.__name__):
                self.assertTrue(dataclasses.is_dataclass(dto))
                self.assertTrue(dto.__dataclass_params__.frozen)
                self.assertIn("__slots__", dto.__dict__)
        request = ListCapabilitiesRequest()
        self.assertFalse(hasattr(request, "__dict__"))
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            request.value = "changed"

    def test_public_field_annotations_are_closed_and_immutable(self):
        prohibited = ("list", "dict", "set", "Mapping", "Any", "object", "Callable", "Path")
        for dto in F_DTOS:
            rendered = " ".join(str(value) for value in get_type_hints(dto).values())
            with self.subTest(dto=dto.__name__, annotations=rendered):
                for name in prohibited:
                    self.assertNotIn(name, rendered)

    def test_identifier_version_and_effect_validation(self):
        _metadata(version="99999999999999999999")
        for version in ("0", "01", "+1", "1.0", "1" * 21):
            with self.subTest(version=version), self.assertRaises(ValueError):
                _metadata(version=version)
        for leaf in ("BadName", "bad-name", "", "a" * 97):
            with self.subTest(leaf=leaf), self.assertRaises(ValueError):
                _metadata(leaf=leaf)
        with self.assertRaises(ValueError):
            CapabilityExpectedEffect("Bad", EffectClass.LOCAL_READ, "Summary")
        with self.assertRaises(ValueError):
            CapabilityExpectedEffect("read", EffectClass.LOCAL_READ, "x" * 513)

    def test_parameter_lexical_forms_and_privacy_rejection(self):
        valid = (
            ProposalParameter("text", CapabilityParameterKind.TEXT, "value"),
            ProposalParameter("integer", CapabilityParameterKind.INTEGER, "-42"),
            ProposalParameter("boolean", CapabilityParameterKind.BOOLEAN, "false"),
            ProposalParameter(
                "at", CapabilityParameterKind.UTC_TIMESTAMP,
                "2026-01-02T03:04:05.000006Z",
            ),
        )
        self.assertEqual(len(valid), 4)
        bad = (
            ("text", CapabilityParameterKind.TEXT, " value"),
            ("integer", CapabilityParameterKind.INTEGER, "01"),
            ("integer", CapabilityParameterKind.INTEGER, str(2**63)),
            ("boolean", CapabilityParameterKind.BOOLEAN, "True"),
            ("at", CapabilityParameterKind.UTC_TIMESTAMP, "2026-02-30T00:00:00.000000Z"),
            ("value", CapabilityParameterKind.TEXT, "/etc/passwd"),
            ("value", CapabilityParameterKind.TEXT, "bash -c whoami"),
            ("value", CapabilityParameterKind.TEXT, "token=secret"),
        )
        for key, kind, value in bad:
            with self.subTest(kind=kind, value=value), self.assertRaises(ValueError):
                ProposalParameter(key, kind, value)

    def test_parameter_tuples_require_order_and_unique_keys(self):
        first = ProposalParameter("a", CapabilityParameterKind.INTEGER, "1")
        second = ProposalParameter("b", CapabilityParameterKind.BOOLEAN, "true")
        ProposeCapabilityRequest(
            "system-1", "cyberwatchtower.application.get_score_history", "1",
            _target(), (first, second),
        )
        for parameters in ((second, first), (first, first), [first]):
            with self.subTest(parameters=parameters), self.assertRaises((TypeError, ValueError)):
                ProposeCapabilityRequest(
                    "system-1", "cyberwatchtower.application.get_score_history", "1",
                    _target(), parameters,
                )

    def test_target_shapes_and_injection_rejection(self):
        _target(CapabilityTargetKind.APPLICATION)
        _target(CapabilityTargetKind.SYSTEM)
        _target(CapabilityTargetKind.REPORT, (_report_id(),))
        _target(CapabilityTargetKind.REPORT, (_report_id("a"), _report_id("b")))
        _target(CapabilityTargetKind.FINDING, (), "finding-1")
        invalid = (
            (CapabilityTargetKind.APPLICATION, (_report_id(),), None),
            (CapabilityTargetKind.SYSTEM, (), "finding-1"),
            (CapabilityTargetKind.REPORT, (), None),
            (CapabilityTargetKind.REPORT, (_report_id(),), "finding-1"),
            (CapabilityTargetKind.FINDING, (), None),
        )
        for kind, report_ids, finding_id in invalid:
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                _target(kind, report_ids, finding_id)
        for system_id in ("/tmp/report", "https://example.test", "cmd.exe /c whoami"):
            with self.subTest(system_id=system_id), self.assertRaises(ValueError):
                CapabilityTarget(CapabilityTargetKind.SYSTEM, system_id, (), None)

    def test_propose_request_binds_exact_system(self):
        with self.assertRaises(ValueError):
            ProposeCapabilityRequest(
                "system-2", "cyberwatchtower.application.get_saved_report", "1",
                _target(), (),
            )

    def test_capability_metadata_ordering_and_secret_policy(self):
        effect_a = _effect("a")
        effect_b = _effect("b")
        base = dict(
            capability_id="cyberwatchtower.application.get_saved_report",
            capability_version="1", title="Get report",
            summary="Read a bounded report.", effect_class=EffectClass.LOCAL_READ,
            permission_class=PermissionClass.READ_ONLY,
            privacy_class=PrivacyClass.SENSITIVE_LOCAL_DATA,
            availability=CapabilityAvailability.AVAILABLE,
            target_kinds=(CapabilityTargetKind.SYSTEM, CapabilityTargetKind.REPORT),
        )
        CapabilityMetadata(expected_effects=(effect_a, effect_b), parameters=(), **base)
        with self.assertRaises(ValueError):
            CapabilityMetadata(expected_effects=(effect_b, effect_a), parameters=(), **base)
        with self.assertRaises(ValueError):
            CapabilityMetadata(expected_effects=(effect_a, effect_a), parameters=(), **base)
        secret = CapabilityParameterSpec(
            "secret", CapabilityParameterKind.TEXT, True, PrivacyClass.SECRET
        )
        with self.assertRaises(ValueError):
            CapabilityMetadata(expected_effects=(effect_a,), parameters=(secret,), **base)
        self.assertNotIn("handler", EXPECTED_FIELDS[CapabilityMetadata])
        self.assertNotIn("callable", EXPECTED_FIELDS[CapabilityMetadata])

    def test_catalog_bounds_uniqueness_and_numeric_order(self):
        two = _metadata(version="2")
        ten = _metadata(version="10")
        CapabilityCatalogResult("assistantop:" + "a" * 32, (two, ten), 2)
        with self.assertRaises(ValueError):
            CapabilityCatalogResult("assistantop:" + "a" * 32, (ten, two), 2)
        with self.assertRaises(ValueError):
            CapabilityCatalogResult("assistantop:" + "a" * 32, (two, two), 2)
        entries = tuple(_metadata(leaf=f"operation_{index:02d}") for index in range(65))
        with self.assertRaises(ValueError):
            CapabilityCatalogResult("assistantop:" + "a" * 32, entries, 65)

    def test_metadata_collection_and_text_ceilings(self):
        effects = tuple(_effect(f"effect_{index:02d}") for index in range(16))
        specs = tuple(
            CapabilityParameterSpec(
                f"parameter_{index:02d}",
                CapabilityParameterKind.TEXT,
                False,
                PrivacyClass.LOCAL_SECURITY_DATA,
            )
            for index in range(32)
        )
        base = dict(
            capability_id="cyberwatchtower.application.get_saved_report",
            capability_version="1",
            title="T" * 128,
            summary="S" * 1024,
            effect_class=EffectClass.LOCAL_READ,
            permission_class=PermissionClass.READ_ONLY,
            privacy_class=PrivacyClass.SENSITIVE_LOCAL_DATA,
            availability=CapabilityAvailability.AVAILABLE,
            target_kinds=(CapabilityTargetKind.REPORT,),
        )
        CapabilityMetadata(expected_effects=effects, parameters=specs, **base)
        with self.assertRaises(ValueError):
            CapabilityMetadata(
                expected_effects=effects + (_effect("effect_16"),),
                parameters=specs,
                **base,
            )
        extra_spec = CapabilityParameterSpec(
            "parameter_32",
            CapabilityParameterKind.TEXT,
            False,
            PrivacyClass.LOCAL_SECURITY_DATA,
        )
        with self.assertRaises(ValueError):
            CapabilityMetadata(
                expected_effects=effects,
                parameters=specs + (extra_spec,),
                **base,
            )
        for field, replacement in (("title", "T" * 129), ("summary", "S" * 1025)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                CapabilityMetadata(
                    expected_effects=effects,
                    parameters=specs,
                    **(base | {field: replacement}),
                )

    def test_response_claim_text_and_evidence_ceilings(self):
        evidence = _evidence()
        claims = tuple(
            AssistantClaim(
                f"claim.{index:02d}",
                "x" * 2048,
                EpistemicState.OBSERVED,
                (evidence.evidence_id,),
            )
            for index in range(32)
        )
        section = AssistantSection(AssistantSectionId.POSTURE, "Posture", claims, 0)
        AssistantGroundedResponse((section,), (evidence,))
        overflow_claim = AssistantClaim(
            "claim.32", "x" * 2048, EpistemicState.OBSERVED,
            (evidence.evidence_id,),
        )
        with self.assertRaises(ValueError):
            AssistantGroundedResponse(
                (AssistantSection(
                    AssistantSectionId.POSTURE,
                    "Posture",
                    claims + (overflow_claim,),
                    0,
                ),),
                (evidence,),
            )
        with self.assertRaises(ValueError):
            AssistantSection(
                AssistantSectionId.POSTURE,
                "Posture",
                tuple(
                    AssistantClaim(
                        f"claim.bound.{index:02d}",
                        "bounded",
                        EpistemicState.OBSERVED,
                        (evidence.evidence_id,),
                    )
                    for index in range(65)
                ),
                0,
            )
        with self.assertRaises(ValueError):
            AssistantClaim(
                "claim.references",
                "Too many references.",
                EpistemicState.OBSERVED,
                tuple(f"evidence.{index:02d}" for index in range(17)),
            )

        references = tuple(
            AssistantEvidenceReference(
                f"evidence.{index:03d}",
                AssistantEvidenceSourceKind.REPORT_FINDING,
                f"finding-{index:03d}",
                AssistantEvidenceRole.OBSERVED_FACT,
                (_report_id(),),
            )
            for index in range(128)
        )
        grouped_claims = tuple(
            AssistantClaim(
                f"claim.evidence.{index:02d}",
                "Bounded evidence group.",
                EpistemicState.OBSERVED,
                tuple(item.evidence_id for item in references[index * 16:(index + 1) * 16]),
            )
            for index in range(8)
        )
        AssistantGroundedResponse(
            (AssistantSection(
                AssistantSectionId.POSTURE,
                "Posture",
                grouped_claims,
                0,
            ),),
            references,
        )
        extra = AssistantEvidenceReference(
            "evidence.128",
            AssistantEvidenceSourceKind.REPORT_FINDING,
            "finding-128",
            AssistantEvidenceRole.OBSERVED_FACT,
            (_report_id(),),
        )
        with self.assertRaises(ValueError):
            AssistantGroundedResponse(
                (AssistantSection(
                    AssistantSectionId.POSTURE,
                    "Posture",
                    grouped_claims + (
                        AssistantClaim(
                            "claim.evidence.08",
                            "Overflow evidence group.",
                            EpistemicState.OBSERVED,
                            (extra.evidence_id,),
                        ),
                    ),
                    0,
                ),),
                references + (extra,),
            )

    def test_question_validation_bounds_nfc_and_controls(self):
        AssistantQuestionRequest("system-1", _report_id(), None, "x" * 4096)
        invalid = ("", "   ", "x" * 4097, "line\nbreak", "hidden\u200dtext")
        for question in invalid:
            with self.subTest(length=len(question)), self.assertRaises(ValueError):
                AssistantQuestionRequest("system-1", _report_id(), None, question)
        decomposed = "e\N{COMBINING ACUTE ACCENT}"
        self.assertNotEqual(decomposed, unicodedata.normalize("NFC", decomposed))
        with self.assertRaises(ValueError):
            AssistantQuestionRequest("system-1", _report_id(), None, decomposed)

    def test_report_selection_rejects_duplicate_ids(self):
        report_id = _report_id()
        with self.assertRaises(ValueError):
            SecurityBriefingRequest("system-1", report_id, report_id)

    def test_evidence_role_binding_and_duplicate_report_rejection(self):
        report = _report_id()
        AssistantEvidenceReference(
            "evidence.finding", AssistantEvidenceSourceKind.REPORT_FINDING,
            "finding-1", AssistantEvidenceRole.OBSERVED_FACT, (report,),
        )
        with self.assertRaises(ValueError):
            AssistantEvidenceReference(
                "evidence.bad-role", AssistantEvidenceSourceKind.REPORT_FINDING,
                "finding-1", AssistantEvidenceRole.DETERMINISTIC_DERIVATION, (report,),
            )
        with self.assertRaises(ValueError):
            AssistantEvidenceReference(
                "evidence.bad-report", AssistantEvidenceSourceKind.CANONICAL_REPORT,
                _report_id("b").value, AssistantEvidenceRole.OBSERVED_FACT, (report,),
            )
        with self.assertRaises(ValueError):
            AssistantEvidenceReference(
                "evidence.duplicate", AssistantEvidenceSourceKind.REPORT_COMPARISON,
                "comparison-1", AssistantEvidenceRole.DETERMINISTIC_DERIVATION,
                (report, report),
            )

    def test_claim_and_section_bounds(self):
        with self.assertRaises(ValueError):
            AssistantClaim("Bad", "Text", EpistemicState.OBSERVED, ("evidence.report",))
        with self.assertRaises(ValueError):
            AssistantClaim(
                "claim.text", "x" * 2049, EpistemicState.OBSERVED,
                ("evidence.report",),
            )
        with self.assertRaises(ValueError):
            AssistantClaim("claim.empty", "Text", EpistemicState.OBSERVED, ())
        AssistantSection(AssistantSectionId.PRIORITIES, "Priorities", (), 0)
        with self.assertRaises(ValueError):
            AssistantSection(AssistantSectionId.POSTURE, "Posture", (), 0)
        with self.assertRaises(ValueError):
            AssistantSection(
                AssistantSectionId.POSTURE, "Posture", (_claim(),), 65537,
            )

    def test_response_enforces_order_uniqueness_and_complete_grounding(self):
        response = _response()
        evidence = response.evidence[0]
        duplicate = AssistantEvidenceReference(
            "evidence.alias", evidence.source_kind, evidence.source_id,
            evidence.evidence_role, evidence.report_ids,
        )
        section = AssistantSection(
            AssistantSectionId.POSTURE, "Posture",
            (_claim("claim.two", evidence.evidence_id),), 0,
        )
        with self.assertRaises(ValueError):
            AssistantGroundedResponse((section,), (evidence, duplicate))
        with self.assertRaises(ValueError):
            AssistantGroundedResponse(
                (
                    AssistantSection(
                        AssistantSectionId.COVERAGE, "Coverage",
                        (_claim("claim.coverage"),), 0,
                    ),
                    AssistantSection(
                        AssistantSectionId.POSTURE, "Posture",
                        (_claim("claim.other"),), 0,
                    ),
                ),
                (evidence,),
            )
        missing = AssistantClaim(
            "claim.missing", "Missing evidence.", EpistemicState.OBSERVED,
            ("evidence.missing",),
        )
        with self.assertRaises(ValueError):
            AssistantGroundedResponse(
                (AssistantSection(AssistantSectionId.POSTURE, "Posture", (missing,), 0),),
                (evidence,),
            )

    def test_observed_and_strong_claim_support_rules(self):
        derived = AssistantEvidenceReference(
            "evidence.advisor", AssistantEvidenceSourceKind.DETERMINISTIC_ADVISOR,
            "advisor.rule", AssistantEvidenceRole.DETERMINISTIC_DERIVATION,
            (_report_id(),),
        )
        for state in (EpistemicState.OBSERVED, EpistemicState.STRONGLY_SUPPORTED):
            claim = AssistantClaim(
                "claim.rule", "A bounded rule result.", state, (derived.evidence_id,),
            )
            section = AssistantSection(
                AssistantSectionId.EXPLANATION, "Explanation", (claim,), 0,
            )
            with self.subTest(state=state), self.assertRaises(ValueError):
                AssistantGroundedResponse((section,), (derived,))

    def test_operation_and_proposal_id_digest_validation(self):
        with self.assertRaises(ValueError):
            CapabilityCatalogResult("assistantop:ABC", (), 0)
        proposal = _proposal()
        self.assertEqual(proposal.reuse_policy, ReusePolicy.ONE_TIME)
        values = {field.name: getattr(proposal, field.name) for field in dataclasses.fields(proposal)}
        for change in (
            {"proposal_id": "proposal:ABC"},
            {"target_digest": "A" * 64},
            {"parameter_digest": "a" * 63},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                CapabilityProposal(**(values | change))

    def test_proposal_requires_canonical_utc_and_exact_expiry(self):
        proposal = _proposal()
        values = {field.name: getattr(proposal, field.name) for field in dataclasses.fields(proposal)}
        with self.assertRaises(ValueError):
            CapabilityProposal(**(values | {"issued_at": proposal.issued_at.replace(tzinfo=None)}))
        with self.assertRaises(ValueError):
            CapabilityProposal(**(values | {"expires_at": proposal.expires_at + timedelta(seconds=1)}))
        plus_one = timezone(timedelta(hours=1))
        with self.assertRaises(ValueError):
            CapabilityProposal(**(values | {
                "issued_at": proposal.issued_at.astimezone(plus_one),
                "expires_at": proposal.expires_at.astimezone(plus_one),
            }))

    def test_proposal_is_non_executable_and_deeply_immutable(self):
        proposal = _proposal()
        for name in ("approval", "execute", "authorize"):
            self.assertFalse(hasattr(proposal, name))
        self.assertIsInstance(proposal.parameters, tuple)
        self.assertIsInstance(proposal.expected_effects, tuple)
        with self.assertRaises(FrozenInstanceError):
            proposal.system_id = "changed"
        result = ProposeCapabilityResult("assistantop:" + "a" * 32, proposal)
        self.assertIs(result.proposal, proposal)

    def test_question_result_status_shapes(self):
        current = SavedReportReference(
            _report_id(), datetime(2026, 1, 2, tzinfo=timezone.utc)
        )
        AssistantQuestionResult(
            "assistantop:" + "a" * 32, "system-1", current, None,
            AssistantQuestionStatus.ANSWERED, AssistantIntent.SUMMARY, _response(),
        )
        AssistantQuestionResult(
            "assistantop:" + "a" * 32, "system-1", current, None,
            AssistantQuestionStatus.MISSING_CONTEXT, AssistantIntent.WHAT_CHANGED, None,
        )
        with self.assertRaises(ValueError):
            AssistantQuestionResult(
                "assistantop:" + "a" * 32, "system-1", current, None,
                AssistantQuestionStatus.UNSUPPORTED, AssistantIntent.SUMMARY, None,
            )

    def test_briefing_result_requires_utc_chronology(self):
        previous = SavedReportReference(
            _report_id("a"), datetime(2026, 1, 1, tzinfo=timezone.utc)
        )
        current = SavedReportReference(
            _report_id("b"), datetime(2026, 1, 2, tzinfo=timezone.utc)
        )
        SecurityBriefingResult(
            "assistantop:" + "a" * 32, "system-1", current, previous, _response(),
        )
        with self.assertRaises(ValueError):
            SecurityBriefingResult(
                "assistantop:" + "a" * 32, "system-1", previous, current, _response(),
            )

    def test_contracts_add_no_runtime_or_io_surface(self):
        tree = ast.parse(CONTRACTS.read_text(encoding="utf-8"))
        imports = {
            node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
        }
        imports.update(
            alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
            for alias in node.names
        )
        for forbidden in (
            "sqlite3", "subprocess", "pathlib", "urllib", "requests",
            "cyberwatchtower.memory", "cyberwatchtower.reporting",
            "cyberwatchtower.capabilities", "cyberwatchtower.model_gateway",
        ):
            self.assertFalse(any(name.startswith(forbidden) for name in imports), forbidden)
        public = set(application.__all__)
        self.assertFalse(any("canonical" in name.casefold() for name in public))
        self.assertFalse(any("serialize" in name.casefold() for name in public))

    def test_facade_and_zero_argument_construction_are_unchanged(self):
        self.assertEqual(tuple(inspect.signature(CyberWatchtowerApplication).parameters), ())
        facade = CyberWatchtowerApplication()
        for method in (
            "get_security_briefing", "ask_assistant", "list_capabilities",
            "propose_capability",
        ):
            self.assertFalse(hasattr(facade, method))

    def test_application_init_only_reexports_contract_types(self):
        tree = ast.parse(APPLICATION_INIT.read_text(encoding="utf-8"))
        imports = {
            node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
        }
        self.assertEqual(imports, {"assessment", "contracts", "errors"})


if __name__ == "__main__":
    unittest.main()
