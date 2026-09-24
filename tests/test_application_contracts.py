import dataclasses
import inspect
import unittest
from dataclasses import FrozenInstanceError

import cyberwatchtower.application as application
from cyberwatchtower.application import (
    ApplicationComponent,
    ApplicationErrorCode,
    ApplicationFailure,
    ApplicationFinding,
    CurrentSystemAssessmentRequest,
    CyberWatchtowerApplication,
    CyberWatchtowerApplicationError,
    SupportedPlatform,
)


class ApplicationContractTests(unittest.TestCase):
    def test_request_is_zero_field_frozen_and_slotted(self):
        request = CurrentSystemAssessmentRequest()
        self.assertEqual(dataclasses.fields(request), ())
        self.assertFalse(hasattr(request, "__dict__"))
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            request.target = "remote-host"
        with self.assertRaises(TypeError):
            CurrentSystemAssessmentRequest(target="remote-host")

    def test_public_dtos_are_frozen_slotted_dataclasses(self):
        dto_names = (
            "ApplicationEvidence",
            "ApplicationFailure",
            "ApplicationFinding",
            "AssessmentAssuranceSummary",
            "CurrentSystemAssessmentRequest",
            "CurrentSystemAssessmentResult",
            "DomainCoverage",
            "FirewallApplicabilitySummary",
            "FirewallTechnologySummary",
            "NetworkExposureContext",
            "ProjectionNotice",
            "ScoreCategoryBreakdown",
            "ScoreContributor",
            "ScoreGuardrail",
            "SecurityScore",
            "SecurityScoreBreakdown",
            "SeverityCount",
            "SystemSummary",
        )
        for name in dto_names:
            with self.subTest(name=name):
                dto = getattr(application, name)
                self.assertTrue(dataclasses.is_dataclass(dto))
                parameters = dto.__dataclass_params__
                self.assertTrue(parameters.frozen)
                self.assertIn("__slots__", dto.__dict__)

    def test_closed_platform_and_error_enums_preserve_contract(self):
        self.assertEqual(
            tuple(item.value for item in SupportedPlatform),
            ("LINUX", "WINDOWS"),
        )
        self.assertEqual(
            {
                ApplicationErrorCode.INVALID_REQUEST,
                ApplicationErrorCode.UNSUPPORTED_PLATFORM,
                ApplicationErrorCode.PRIVACY_POLICY_BLOCKED,
                ApplicationErrorCode.COMPATIBILITY_FAILURE,
                ApplicationErrorCode.INTERNAL_FAILURE,
            }.issubset(set(ApplicationErrorCode)),
            True,
        )

    def test_application_failure_is_immutable_bounded_and_operation_scoped(self):
        failure = ApplicationFailure(
            code=ApplicationErrorCode.INVALID_REQUEST,
            message="The request is invalid.",
            retryable=False,
            component=ApplicationComponent.APPLICATION,
            operation_id="assessment:" + "a" * 32,
        )
        error = CyberWatchtowerApplicationError(failure)
        self.assertIs(error.failure, failure)
        self.assertEqual(str(error), failure.message)
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            failure.message = "changed"
        with self.assertRaises(ValueError):
            ApplicationFailure(
                code=ApplicationErrorCode.INVALID_REQUEST,
                message="bad\ntrace",
                retryable=False,
                component=ApplicationComponent.APPLICATION,
                operation_id="assessment:" + "a" * 32,
            )
        with self.assertRaises(ValueError):
            ApplicationFailure(
                code=ApplicationErrorCode.INVALID_REQUEST,
                message="hidden\u200dformat",
                retryable=False,
                component=ApplicationComponent.APPLICATION,
                operation_id="assessment:" + "a" * 32,
            )

    def test_finding_contract_has_no_coverage_or_mutable_container_fields(self):
        names = {field.name for field in dataclasses.fields(ApplicationFinding)}
        self.assertNotIn("coverage_domains", names)
        self.assertEqual(
            {
                "finding_id", "title", "description", "severity",
                "recommendation", "evidence", "evidence_projection_state",
                "omitted_evidence_count", "confidence", "technique_id",
                "source", "kind", "assessment_state", "network_context",
                "presentation_group_id", "runtime_instance_count",
            },
            names,
        )
        annotations = ApplicationFinding.__annotations__
        rendered = " ".join(str(value) for value in annotations.values())
        for prohibited in ("list", "dict", "set", "Mapping", "Finding]"):
            self.assertNotIn(prohibited, rendered)

    def test_public_contract_has_no_wire_or_provider_safety_claim(self):
        public_names = set(application.__all__)
        rendered_names = " ".join(public_names).casefold()
        self.assertNotIn("provider_safe", rendered_names)
        self.assertNotIn("safe_to_send", rendered_names)
        for name in public_names:
            value = getattr(application, name)
            if inspect.isclass(value):
                self.assertFalse(hasattr(value, "to_dict"), name)
                if dataclasses.is_dataclass(value):
                    field_names = {field.name.casefold() for field in dataclasses.fields(value)}
                    self.assertNotIn("provider_safe", field_names)
                    self.assertNotIn("safe_to_send", field_names)

    def test_public_facade_has_zero_dependency_construction(self):
        signature = inspect.signature(CyberWatchtowerApplication)
        self.assertEqual(tuple(signature.parameters), ())
        facade = CyberWatchtowerApplication()
        self.assertFalse(hasattr(facade, "scanner"))
        self.assertFalse(hasattr(facade, "adapter"))
        self.assertFalse(hasattr(facade, "repository"))


if __name__ == "__main__":
    unittest.main()
