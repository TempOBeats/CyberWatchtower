from contextlib import ExitStack
from dataclasses import fields
from datetime import datetime, timedelta, timezone
import inspect
from pathlib import Path
from types import SimpleNamespace
from typing import get_type_hints
import unittest
from unittest.mock import patch

import cyberwatchtower.application as application
import cyberwatchtower.application.assessment as assessment_module
import cyberwatchtower.application._proposals as proposals_module
from cyberwatchtower.application import (
    ApplicationComponent,
    ApplicationErrorCode,
    CapabilityParameterKind,
    CapabilityTarget,
    CapabilityTargetKind,
    CurrentSystemAssessmentRequest,
    CyberWatchtowerApplication,
    CyberWatchtowerApplicationError,
    PermissionClass,
    ProposalParameter,
    ProposeCapabilityRequest,
    ProposeCapabilityResult,
    ReusePolicy,
)
from cyberwatchtower.application._capabilities import _lookup_capability
from cyberwatchtower.application._proposals import (
    _ProposalConstructionError,
    _ProposalFailureCode,
    _construct_proposal_with_id,
)


SYSTEM_ID = "system:alpha"
ISSUED_AT = datetime(2026, 1, 2, 3, 4, 5, 6, tzinfo=timezone.utc)
OPERATION_HEX = "a" * 12 + "4" + "b" * 3 + "8" + "c" * 15
OPERATION_ID = "assistantop:" + OPERATION_HEX
PROPOSAL_HEX = "d" * 12 + "4" + "e" * 3 + "9" + "f" * 15
PROPOSAL_ID = "proposal:" + PROPOSAL_HEX
ROOT = Path(__file__).resolve().parents[1]
ASSESSMENT_SOURCE = (
    ROOT / "src" / "cyberwatchtower" / "application" / "assessment.py"
)


def _capability_id(leaf: str) -> str:
    return f"cyberwatchtower.application.{leaf}"


def _target(
    kind: CapabilityTargetKind = CapabilityTargetKind.SYSTEM,
) -> CapabilityTarget:
    return CapabilityTarget(
        kind=kind,
        system_id=SYSTEM_ID,
        report_ids=(),
        finding_id=None,
    )


def _parameter(
    key: str,
    kind: CapabilityParameterKind,
    value: str,
) -> ProposalParameter:
    return ProposalParameter(key=key, kind=kind, value=value)


def _request(
    leaf: str = "assess_current_system",
    *,
    version: str = "1",
    target: CapabilityTarget | None = None,
    parameters: tuple[ProposalParameter, ...] = (),
) -> ProposeCapabilityRequest:
    return ProposeCapabilityRequest(
        system_id=SYSTEM_ID,
        capability_id=_capability_id(leaf),
        capability_version=version,
        target=target or _target(),
        parameters=parameters,
    )


class ProposeCapabilitySurfaceTests(unittest.TestCase):
    def test_public_method_has_exact_signature_and_types(self):
        method = CyberWatchtowerApplication.propose_capability
        signature = inspect.signature(method)
        self.assertEqual(tuple(signature.parameters), ("self", "request"))
        hints = get_type_hints(method)
        self.assertIs(hints["request"], ProposeCapabilityRequest)
        self.assertIs(hints["return"], ProposeCapabilityResult)

    def test_zero_argument_construction_is_clock_and_io_free(self):
        with patch.object(
            assessment_module,
            "_proposal_utc_now",
            side_effect=AssertionError("clock read during construction"),
            create=True,
        ) as clock, patch(
            "builtins.open",
            side_effect=AssertionError("I/O during construction"),
        ):
            facade = CyberWatchtowerApplication()
        self.assertIsInstance(facade, CyberWatchtowerApplication)
        clock.assert_not_called()
        self.assertEqual(tuple(inspect.signature(CyberWatchtowerApplication).parameters), ())

    def test_public_surface_adds_only_the_frozen_method(self):
        expected = {
            "assess_current_system",
            "assess_and_save_current_system",
            "compare_saved_reports",
            "ingest_saved_report_into_memory",
            "list_recurring_findings",
            "get_finding_timeline",
            "get_score_history",
            "get_memory_health",
            "list_saved_reports",
            "get_saved_report",
            "get_latest_saved_report",
            "propose_capability",
        }
        actual = {
            name
            for name, value in vars(CyberWatchtowerApplication).items()
            if not name.startswith("_") and callable(value)
        }
        self.assertEqual(actual, expected)
        self.assertNotIn("_construct_proposal", application.__all__)
        self.assertNotIn("_ProposalConstructionError", application.__all__)
        self.assertNotIn("_ProposalFailureCode", application.__all__)
        self.assertNotIn("_proposal_utc_now", application.__all__)


class ProposeCapabilitySuccessTests(unittest.TestCase):
    def test_success_matches_frozen_f5_defaults_bindings_and_metadata(self):
        request = _request("list_recurring_findings")
        expected = _construct_proposal_with_id(request, ISSUED_AT, PROPOSAL_ID)
        metadata = _lookup_capability(request.capability_id, request.capability_version)
        self.assertIsNotNone(metadata)

        with patch.object(
            assessment_module, "_assistant_operation_id", return_value=OPERATION_ID
        ), patch.object(
            assessment_module, "_proposal_utc_now", return_value=ISSUED_AT
        ) as clock, patch.object(
            proposals_module, "_new_proposal_id", return_value=PROPOSAL_ID
        ) as proposal_id:
            result = CyberWatchtowerApplication().propose_capability(request)

        self.assertIsInstance(result, ProposeCapabilityResult)
        self.assertEqual(result.operation_id, OPERATION_ID)
        self.assertEqual(result.proposal, expected)
        self.assertIs(result.proposal.target, request.target)
        self.assertEqual(result.proposal.capability_id, request.capability_id)
        self.assertEqual(result.proposal.capability_version, "1")
        self.assertEqual(
            result.proposal.parameters,
            (
                _parameter("active_only", CapabilityParameterKind.BOOLEAN, "false"),
                _parameter("limit", CapabilityParameterKind.INTEGER, "50"),
            ),
        )
        self.assertEqual(result.proposal.parameter_digest, expected.parameter_digest)
        self.assertEqual(result.proposal.target_digest, expected.target_digest)
        self.assertEqual(result.proposal.issued_at, ISSUED_AT)
        self.assertEqual(result.proposal.expires_at, ISSUED_AT + timedelta(minutes=10))
        self.assertEqual(result.proposal.reuse_policy, ReusePolicy.ONE_TIME)
        self.assertEqual(result.proposal.effect_class, metadata.effect_class)
        self.assertEqual(result.proposal.permission_class, metadata.permission_class)
        self.assertEqual(result.proposal.privacy_class, metadata.privacy_class)
        self.assertIs(result.proposal.expected_effects, metadata.expected_effects)
        clock.assert_called_once_with()
        proposal_id.assert_called_once_with()

    def test_facade_returns_the_exact_private_proposal_without_reconstruction(self):
        request = _request()
        proposal = _construct_proposal_with_id(request, ISSUED_AT, PROPOSAL_ID)
        with patch.object(
            assessment_module, "_assistant_operation_id", return_value=OPERATION_ID
        ), patch.object(
            assessment_module, "_proposal_utc_now", return_value=ISSUED_AT
        ), patch.object(
            proposals_module, "_construct_proposal", return_value=proposal
        ) as construct:
            result = CyberWatchtowerApplication().propose_capability(request)
        self.assertIs(result.proposal, proposal)
        construct.assert_called_once_with(request, ISSUED_AT)

    def test_returned_proposal_is_non_authorizing_metadata(self):
        request = _request("assess_and_save_current_system")
        metadata = _lookup_capability(request.capability_id, request.capability_version)
        self.assertIsNotNone(metadata)
        with patch.object(
            assessment_module, "_assistant_operation_id", return_value=OPERATION_ID
        ), patch.object(
            assessment_module, "_proposal_utc_now", return_value=ISSUED_AT
        ), patch.object(
            proposals_module, "_new_proposal_id", return_value=PROPOSAL_ID
        ):
            proposal = CyberWatchtowerApplication().propose_capability(request).proposal
        self.assertEqual(proposal.effect_class, metadata.effect_class)
        self.assertEqual(
            proposal.permission_class,
            PermissionClass.USER_APPROVAL_REQUIRED,
        )
        self.assertTrue(
            {field.name for field in fields(proposal)}.isdisjoint(
                {
                    "approval",
                    "approved",
                    "authorization",
                    "authorized",
                    "execute",
                    "handler",
                    "persistence",
                }
            )
        )


class ProposeCapabilityBoundaryTests(unittest.TestCase):
    def _assert_failure(
        self,
        request: object,
        expected: ApplicationErrorCode,
    ):
        with self.assertRaises(CyberWatchtowerApplicationError) as caught:
            CyberWatchtowerApplication().propose_capability(request)
        failure = caught.exception.failure
        self.assertEqual(failure.code, expected)
        self.assertEqual(failure.component, ApplicationComponent.APPLICATION)
        self.assertEqual(failure.operation_id, OPERATION_ID)
        self.assertFalse(failure.retryable)
        return caught.exception

    def test_assistant_operation_id_uses_one_uuid4_value_and_f5_owns_proposal_id(self):
        request = _request()
        with patch.object(
            assessment_module,
            "uuid4",
            return_value=SimpleNamespace(hex=OPERATION_HEX),
        ) as operation_entropy, patch.object(
            assessment_module, "_proposal_utc_now", return_value=ISSUED_AT
        ), patch.object(
            proposals_module, "_new_proposal_id", return_value=PROPOSAL_ID
        ) as proposal_entropy:
            result = CyberWatchtowerApplication().propose_capability(request)

        self.assertEqual(result.operation_id, OPERATION_ID)
        self.assertRegex(result.operation_id, r"^assistantop:[0-9a-f]{32}$")
        raw = result.operation_id.removeprefix("assistantop:")
        self.assertEqual(raw[12], "4")
        self.assertIn(raw[16], "89ab")
        self.assertEqual(result.proposal.proposal_id, PROPOSAL_ID)
        operation_entropy.assert_called_once_with()
        proposal_entropy.assert_called_once_with()
        method_source = inspect.getsource(CyberWatchtowerApplication.propose_capability)
        self.assertNotIn("proposal:", method_source)
        self.assertNotIn("_new_proposal_id", method_source)

    def test_operation_id_precedes_validation_and_wrong_request_skips_clock(self):
        events = []

        def operation_id():
            events.append("operation_id")
            return OPERATION_ID

        with patch.object(
            assessment_module, "_assistant_operation_id", side_effect=operation_id
        ) as generator, patch.object(
            assessment_module, "_proposal_utc_now"
        ) as clock:
            self._assert_failure(None, ApplicationErrorCode.INVALID_REQUEST)
        self.assertEqual(events, ["operation_id"])
        generator.assert_called_once_with()
        clock.assert_not_called()

    def test_valid_request_samples_exactly_one_utc_clock_value(self):
        with patch.object(
            assessment_module, "_assistant_operation_id", return_value=OPERATION_ID
        ), patch.object(
            assessment_module, "_proposal_utc_now", return_value=ISSUED_AT
        ) as clock, patch.object(
            proposals_module, "_new_proposal_id", return_value=PROPOSAL_ID
        ):
            result = CyberWatchtowerApplication().propose_capability(_request())
        clock.assert_called_once_with()
        self.assertIs(result.proposal.issued_at.tzinfo, timezone.utc)
        self.assertEqual(result.proposal.issued_at, ISSUED_AT)

    def test_wrong_public_request_types_map_to_invalid_request(self):
        for value in (None, {}, object(), CurrentSystemAssessmentRequest()):
            with self.subTest(type=type(value).__name__), patch.object(
                assessment_module, "_assistant_operation_id", return_value=OPERATION_ID
            ), patch.object(assessment_module, "_proposal_utc_now") as clock:
                error = self._assert_failure(
                    value,
                    ApplicationErrorCode.INVALID_REQUEST,
                )
                self.assertNotIn(repr(value), str(error))
                clock.assert_not_called()

    def test_frozen_private_failure_vocabulary_is_exact(self):
        self.assertEqual(
            {item.value for item in _ProposalFailureCode},
            {
                "UNKNOWN_CAPABILITY",
                "STALE_CAPABILITY_VERSION",
                "UNAVAILABLE_CAPABILITY",
                "PROHIBITED_CAPABILITY",
                "INCOMPATIBLE_TARGET",
                "UNKNOWN_PARAMETER",
                "DUPLICATE_PARAMETER",
                "MISSING_REQUIRED_PARAMETER",
                "WRONG_PARAMETER_KIND",
                "INVALID_PARAMETER_VALUE",
            },
        )

    def test_legitimate_f5_request_failures_translate_to_public_codes(self):
        cases = (
            (
                _request("not_present"),
                ApplicationErrorCode.AUTHORIZATION_DENIED,
            ),
            (
                _request("assess_current_system", version="2"),
                ApplicationErrorCode.AUTHORIZATION_DENIED,
            ),
            (
                _request("assess_current_system", target=_target(CapabilityTargetKind.APPLICATION)),
                ApplicationErrorCode.INVALID_REQUEST,
            ),
            (
                _request(
                    "assess_current_system",
                    parameters=(
                        _parameter("unexpected", CapabilityParameterKind.TEXT, "value"),
                    ),
                ),
                ApplicationErrorCode.INVALID_REQUEST,
            ),
            (
                _request("get_score_history"),
                ApplicationErrorCode.INVALID_REQUEST,
            ),
            (
                _request(
                    "list_recurring_findings",
                    parameters=(
                        _parameter("limit", CapabilityParameterKind.TEXT, "50"),
                    ),
                ),
                ApplicationErrorCode.INVALID_REQUEST,
            ),
            (
                _request(
                    "list_recurring_findings",
                    parameters=(
                        _parameter("limit", CapabilityParameterKind.INTEGER, "0"),
                    ),
                ),
                ApplicationErrorCode.INVALID_REQUEST,
            ),
        )
        for request, expected in cases:
            with self.subTest(capability=request.capability_id, expected=expected), patch.object(
                assessment_module, "_assistant_operation_id", return_value=OPERATION_ID
            ), patch.object(
                assessment_module, "_proposal_utc_now", return_value=ISSUED_AT
            ):
                error = self._assert_failure(request, expected)
                self.assertNotIn("_Proposal", str(error))

    def test_private_seam_only_failures_translate_without_catalog_mutation(self):
        cases = (
            (
                _ProposalFailureCode.PROHIBITED_CAPABILITY,
                ApplicationErrorCode.AUTHORIZATION_DENIED,
            ),
            (
                _ProposalFailureCode.UNAVAILABLE_CAPABILITY,
                ApplicationErrorCode.COMPONENT_UNAVAILABLE,
            ),
            (
                _ProposalFailureCode.DUPLICATE_PARAMETER,
                ApplicationErrorCode.INVALID_REQUEST,
            ),
        )
        for private_code, public_code in cases:
            with self.subTest(private=private_code), patch.object(
                assessment_module, "_assistant_operation_id", return_value=OPERATION_ID
            ), patch.object(
                assessment_module, "_proposal_utc_now", return_value=ISSUED_AT
            ), patch.object(
                proposals_module,
                "_construct_proposal",
                side_effect=_ProposalConstructionError(private_code),
            ):
                error = self._assert_failure(_request(), public_code)
                self.assertNotIn(private_code.value, str(error))

    def test_compatibility_and_internal_failures_are_sanitized(self):
        sensitive = "token=secret /private/path raw-command"
        cases = (
            (TypeError(sensitive), ApplicationErrorCode.COMPATIBILITY_FAILURE),
            (ValueError(sensitive), ApplicationErrorCode.COMPATIBILITY_FAILURE),
            (RuntimeError(sensitive), ApplicationErrorCode.INTERNAL_FAILURE),
        )
        for private_error, expected in cases:
            with self.subTest(expected=expected), patch.object(
                assessment_module, "_assistant_operation_id", return_value=OPERATION_ID
            ), patch.object(
                assessment_module, "_proposal_utc_now", return_value=ISSUED_AT
            ), patch.object(
                proposals_module,
                "_construct_proposal",
                side_effect=private_error,
            ):
                public_error = self._assert_failure(_request(), expected)
                self.assertNotIn(sensitive, str(public_error))
                self.assertNotIn(sensitive, public_error.failure.message)
                self.assertNotIn(type(private_error).__name__, str(public_error))

    def test_base_exceptions_are_not_caught(self):
        with patch.object(
            assessment_module, "_assistant_operation_id", return_value=OPERATION_ID
        ), patch.object(
            assessment_module, "_proposal_utc_now", return_value=ISSUED_AT
        ), patch.object(
            proposals_module,
            "_construct_proposal",
            side_effect=KeyboardInterrupt,
        ), self.assertRaises(KeyboardInterrupt):
            CyberWatchtowerApplication().propose_capability(_request())


class ProposeCapabilitySecurityTests(unittest.TestCase):
    def test_privacy_rejection_occurs_at_dto_construction_before_facade(self):
        with patch.object(proposals_module, "_construct_proposal") as construct:
            for value in ("token=secret", "/private/path", "sh -c whoami"):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    _parameter(
                        "value",
                        CapabilityParameterKind.TEXT,
                        value,
                    )
        construct.assert_not_called()
        self.assertNotIn(
            "PRIVACY_POLICY_BLOCKED",
            {item.value for item in _ProposalFailureCode},
        )

    def test_operation_invokes_no_io_or_existing_facade_operation(self):
        request = _request()
        other_methods = (
            "assess_current_system",
            "assess_and_save_current_system",
            "compare_saved_reports",
            "ingest_saved_report_into_memory",
            "list_recurring_findings",
            "get_finding_timeline",
            "get_score_history",
            "get_memory_health",
            "list_saved_reports",
            "get_saved_report",
            "get_latest_saved_report",
        )
        with ExitStack() as stack:
            blocked = [
                stack.enter_context(
                    patch.object(
                        CyberWatchtowerApplication,
                        name,
                        side_effect=AssertionError(f"unexpected facade call: {name}"),
                    )
                )
                for name in other_methods
            ]
            blocked.extend(
                (
                    stack.enter_context(
                        patch.object(
                            assessment_module.scanner,
                            "run_scan",
                            side_effect=AssertionError("scanner access"),
                        )
                    ),
                    stack.enter_context(
                        patch.object(
                            assessment_module._reports,
                            "_default_report_repository",
                            side_effect=AssertionError("report access"),
                        )
                    ),
                    stack.enter_context(
                        patch.object(
                            assessment_module._memory,
                            "_default_memory_factory",
                            side_effect=AssertionError("Memory access"),
                        )
                    ),
                )
            )
            stack.enter_context(
                patch.object(
                    assessment_module, "_assistant_operation_id", return_value=OPERATION_ID
                )
            )
            stack.enter_context(
                patch.object(
                    assessment_module, "_proposal_utc_now", return_value=ISSUED_AT
                )
            )
            stack.enter_context(
                patch.object(
                    proposals_module, "_new_proposal_id", return_value=PROPOSAL_ID
                )
            )
            result = CyberWatchtowerApplication().propose_capability(request)
        self.assertEqual(result.proposal.proposal_id, PROPOSAL_ID)
        for boundary in blocked:
            boundary.assert_not_called()

    def test_changed_method_has_no_io_execution_or_legacy_registry_path(self):
        method_source = inspect.getsource(
            CyberWatchtowerApplication.propose_capability
        )
        for forbidden in (
            "scanner",
            "_reports",
            "_memory",
            "sqlite",
            "socket",
            "requests",
            "subprocess",
            "platform",
            "getenv",
            "environ",
            "open(",
            "sleep",
            "retry",
            "create_task",
            "Thread",
            "CapabilityRegistry",
            "handler",
            "execute",
            "approve",
            "persist",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, method_source)

        complete_source = ASSESSMENT_SOURCE.read_text(encoding="utf-8")
        self.assertNotIn("CapabilityRegistry", complete_source)
        self.assertNotIn("_new_proposal_id", complete_source)


if __name__ == "__main__":
    unittest.main()
