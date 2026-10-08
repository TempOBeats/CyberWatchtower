import ast
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import unittest

import cyberwatchtower.application as application
from cyberwatchtower.application import (
    CapabilityAvailability,
    CapabilityParameterKind,
    CapabilityTarget,
    CapabilityTargetKind,
    EffectClass,
    PermissionClass,
    ProposalParameter,
    ProposeCapabilityRequest,
    ReportId,
    ReusePolicy,
)
from cyberwatchtower.application._capabilities import (
    _capability_catalog,
    _lookup_capability,
    _parameter_digest,
    _target_digest,
)
from cyberwatchtower.application._proposals import (
    _ProposalConstructionError,
    _ProposalFailureCode,
    _construct_proposal,
    _construct_proposal_from_metadata,
    _construct_proposal_with_id,
    _materialize_parameters,
    _resolve_capability,
)


SYSTEM_ID = "system:alpha"
REPORT_A = ReportId("report:" + "a" * 64)
REPORT_B = ReportId("report:" + "b" * 64)
ISSUED_AT = datetime(2026, 1, 2, 3, 4, 5, 6, tzinfo=timezone.utc)
PROPOSAL_ID = "proposal:" + "a" * 12 + "4" + "b" * 3 + "8" + "c" * 15
ROOT = Path(__file__).resolve().parents[1]
PROPOSALS_SOURCE = (
    ROOT / "src" / "cyberwatchtower" / "application" / "_proposals.py"
)


def _capability_id(leaf: str) -> str:
    return f"cyberwatchtower.application.{leaf}"


def _target(
    kind: CapabilityTargetKind = CapabilityTargetKind.SYSTEM,
    report_ids: tuple[ReportId, ...] = (),
    finding_id: str | None = None,
) -> CapabilityTarget:
    return CapabilityTarget(kind, SYSTEM_ID, report_ids, finding_id)


def _request(
    leaf: str,
    *,
    target: CapabilityTarget | None = None,
    parameters: tuple[ProposalParameter, ...] = (),
    version: str = "1",
) -> ProposeCapabilityRequest:
    return ProposeCapabilityRequest(
        system_id=SYSTEM_ID,
        capability_id=_capability_id(leaf),
        capability_version=version,
        target=target or _target(),
        parameters=parameters,
    )


def _parameter(
    key: str,
    kind: CapabilityParameterKind,
    value: str,
) -> ProposalParameter:
    return ProposalParameter(key=key, kind=kind, value=value)


def _score_parameters(
    *,
    start: str = "2026-01-01T00:00:00.000000Z",
    end: str = "2026-01-02T00:00:00.000000Z",
    limit: str | None = None,
    scoring_version: str | None = None,
) -> tuple[ProposalParameter, ...]:
    values = [
        _parameter("end_at", CapabilityParameterKind.UTC_TIMESTAMP, end),
    ]
    if limit is not None:
        values.append(_parameter("limit", CapabilityParameterKind.INTEGER, limit))
    if scoring_version is not None:
        values.append(
            _parameter(
                "scoring_version", CapabilityParameterKind.TEXT, scoring_version
            )
        )
    values.append(
        _parameter("start_at", CapabilityParameterKind.UTC_TIMESTAMP, start)
    )
    return tuple(values)


class ProposalCatalogResolutionTests(unittest.TestCase):
    def test_exact_known_capability_resolves_without_mutating_catalog(self):
        before = _capability_catalog()
        metadata = _resolve_capability(
            _capability_id("assess_current_system"), "1"
        )
        self.assertIs(
            metadata,
            _lookup_capability(_capability_id("assess_current_system"), "1"),
        )
        self.assertIs(before, _capability_catalog())
        self.assertEqual(before, _capability_catalog())

    def test_unknown_and_stale_capabilities_fail_distinctly(self):
        cases = (
            (
                "cyberwatchtower.application.not_present",
                "1",
                _ProposalFailureCode.UNKNOWN_CAPABILITY,
            ),
            (
                _capability_id("assess_current_system"),
                "2",
                _ProposalFailureCode.STALE_CAPABILITY_VERSION,
            ),
        )
        for capability_id, version, expected in cases:
            with self.subTest(expected=expected):
                with self.assertRaises(_ProposalConstructionError) as caught:
                    _resolve_capability(capability_id, version)
                self.assertEqual(caught.exception.code, expected)

    def test_unavailable_and_prohibited_metadata_fail_closed(self):
        request = _request("assess_current_system")
        base = _resolve_capability(request.capability_id, request.capability_version)
        cases = (
            (
                replace(base, availability=CapabilityAvailability.UNAVAILABLE),
                _ProposalFailureCode.UNAVAILABLE_CAPABILITY,
            ),
            (
                replace(base, availability=CapabilityAvailability.PROHIBITED),
                _ProposalFailureCode.PROHIBITED_CAPABILITY,
            ),
            (
                replace(base, permission_class=PermissionClass.PROHIBITED),
                _ProposalFailureCode.PROHIBITED_CAPABILITY,
            ),
            (
                replace(base, effect_class=EffectClass.PROHIBITED),
                _ProposalFailureCode.PROHIBITED_CAPABILITY,
            ),
        )
        for metadata, expected in cases:
            with self.subTest(expected=expected):
                with self.assertRaises(_ProposalConstructionError) as caught:
                    _construct_proposal_from_metadata(
                        request, metadata, ISSUED_AT, PROPOSAL_ID
                    )
                self.assertEqual(caught.exception.code, expected)

    def test_catalog_has_no_f_capability_or_executable_field(self):
        forbidden_leaves = {
            "ask_assistant",
            "get_security_briefing",
            "list_capabilities",
            "propose_capability",
        }
        for metadata in _capability_catalog():
            self.assertNotIn(metadata.capability_id.rsplit(".", 1)[1], forbidden_leaves)
            self.assertTrue(
                {field.name for field in fields(metadata)}.isdisjoint(
                    {"handler", "callable", "command", "argv", "executable"}
                )
            )


class ProposalParameterTests(unittest.TestCase):
    def test_allowed_parameters_and_defaults_produce_canonical_effective_tuple(self):
        request = _request(
            "list_recurring_findings",
            parameters=(
                _parameter("active_only", CapabilityParameterKind.BOOLEAN, "true"),
            ),
        )
        proposal = _construct_proposal_with_id(request, ISSUED_AT, PROPOSAL_ID)
        self.assertEqual(
            proposal.parameters,
            (
                _parameter("active_only", CapabilityParameterKind.BOOLEAN, "true"),
                _parameter("limit", CapabilityParameterKind.INTEGER, "50"),
            ),
        )
        self.assertEqual(proposal.parameter_digest, _parameter_digest(proposal.parameters))

    def test_omitted_and_explicit_defaults_are_identical(self):
        omitted = _construct_proposal_with_id(
            _request("list_recurring_findings"), ISSUED_AT, PROPOSAL_ID
        )
        explicit = _construct_proposal_with_id(
            _request(
                "list_recurring_findings",
                parameters=(
                    _parameter(
                        "active_only", CapabilityParameterKind.BOOLEAN, "false"
                    ),
                    _parameter("limit", CapabilityParameterKind.INTEGER, "50"),
                ),
            ),
            ISSUED_AT,
            PROPOSAL_ID,
        )
        self.assertEqual(omitted.parameters, explicit.parameters)
        self.assertEqual(omitted.parameter_digest, explicit.parameter_digest)

    def test_finding_timeline_default_is_materialized_before_digest(self):
        proposal = _construct_proposal_with_id(
            _request(
                "get_finding_timeline",
                target=_target(
                    CapabilityTargetKind.FINDING,
                    finding_id="finding:alpha",
                ),
            ),
            ISSUED_AT,
            PROPOSAL_ID,
        )
        expected = (_parameter("limit", CapabilityParameterKind.INTEGER, "100"),)
        self.assertEqual(proposal.parameters, expected)
        self.assertEqual(proposal.parameter_digest, _parameter_digest(expected))

    def test_score_history_required_values_default_and_absent_series(self):
        proposal = _construct_proposal_with_id(
            _request("get_score_history", parameters=_score_parameters()),
            ISSUED_AT,
            PROPOSAL_ID,
        )
        self.assertEqual(
            tuple(parameter.key for parameter in proposal.parameters),
            ("end_at", "limit", "start_at"),
        )
        self.assertEqual(proposal.parameters[1].value, "100")
        self.assertNotIn(
            "scoring_version",
            tuple(parameter.key for parameter in proposal.parameters),
        )

    def test_unknown_duplicate_missing_and_wrong_kind_fail_distinctly(self):
        recurring = _resolve_capability(
            _capability_id("list_recurring_findings"), "1"
        )
        score = _resolve_capability(_capability_id("get_score_history"), "1")
        cases = (
            (
                recurring,
                (_parameter("extra", CapabilityParameterKind.TEXT, "value"),),
                _ProposalFailureCode.UNKNOWN_PARAMETER,
            ),
            (
                recurring,
                (
                    _parameter("limit", CapabilityParameterKind.INTEGER, "1"),
                    _parameter("limit", CapabilityParameterKind.INTEGER, "2"),
                ),
                _ProposalFailureCode.DUPLICATE_PARAMETER,
            ),
            (score, (), _ProposalFailureCode.MISSING_REQUIRED_PARAMETER),
            (
                score,
                (
                    _parameter("end_at", CapabilityParameterKind.TEXT, "value"),
                    _parameter(
                        "start_at",
                        CapabilityParameterKind.UTC_TIMESTAMP,
                        "2026-01-01T00:00:00.000000Z",
                    ),
                ),
                _ProposalFailureCode.WRONG_PARAMETER_KIND,
            ),
        )
        for metadata, parameters, expected in cases:
            with self.subTest(expected=expected):
                with self.assertRaises(_ProposalConstructionError) as caught:
                    _materialize_parameters(metadata, parameters)
                self.assertEqual(caught.exception.code, expected)

    def test_ranges_timestamp_order_and_scoring_version_fail_closed(self):
        cases = (
            _request(
                "list_recurring_findings",
                parameters=(
                    _parameter("limit", CapabilityParameterKind.INTEGER, "201"),
                ),
            ),
            _request("get_score_history", parameters=_score_parameters(limit="0")),
            _request(
                "get_score_history",
                parameters=_score_parameters(
                    start="2026-01-03T00:00:00.000000Z",
                    end="2026-01-02T00:00:00.000000Z",
                ),
            ),
            _request(
                "get_score_history",
                parameters=_score_parameters(
                    start="2024-01-01T00:00:00.000000Z",
                    end="2026-01-02T00:00:00.000000Z",
                ),
            ),
            _request(
                "get_score_history",
                parameters=_score_parameters(scoring_version="3"),
            ),
        )
        for request in cases:
            with self.subTest(parameters=request.parameters):
                with self.assertRaises(_ProposalConstructionError) as caught:
                    _construct_proposal_with_id(request, ISSUED_AT, PROPOSAL_ID)
                self.assertEqual(
                    caught.exception.code,
                    _ProposalFailureCode.INVALID_PARAMETER_VALUE,
                )

    def test_parameter_tuple_is_not_mutated_or_retained_mutably(self):
        supplied = (
            _parameter("active_only", CapabilityParameterKind.BOOLEAN, "true"),
        )
        before = tuple(supplied)
        proposal = _construct_proposal_with_id(
            _request("list_recurring_findings", parameters=supplied),
            ISSUED_AT,
            PROPOSAL_ID,
        )
        self.assertEqual(supplied, before)
        self.assertIsInstance(proposal.parameters, tuple)
        self.assertIsNot(proposal.parameters, supplied)

    def test_mapping_and_more_than_32_parameters_are_rejected(self):
        metadata = _resolve_capability(
            _capability_id("list_recurring_findings"), "1"
        )
        with self.assertRaises(TypeError):
            _materialize_parameters(metadata, {})  # type: ignore[arg-type]
        parameters = tuple(
            _parameter(f"key_{index:02d}", CapabilityParameterKind.TEXT, "value")
            for index in range(33)
        )
        with self.assertRaises(ValueError):
            _request("assess_current_system", parameters=parameters)


class ProposalTargetTests(unittest.TestCase):
    def test_allowed_targets_preserve_exact_identity_and_digest(self):
        cases = (
            _request("assess_current_system"),
            _request(
                "get_saved_report",
                target=_target(CapabilityTargetKind.REPORT, (REPORT_A,)),
            ),
            _request(
                "compare_saved_reports",
                target=_target(
                    CapabilityTargetKind.REPORT,
                    (REPORT_A, REPORT_B),
                ),
            ),
            _request(
                "get_finding_timeline",
                target=_target(
                    CapabilityTargetKind.FINDING,
                    finding_id="finding:alpha",
                ),
            ),
        )
        for request in cases:
            with self.subTest(capability=request.capability_id):
                proposal = _construct_proposal_with_id(
                    request, ISSUED_AT, PROPOSAL_ID
                )
                self.assertIs(proposal.target, request.target)
                self.assertEqual(proposal.system_id, SYSTEM_ID)
                self.assertEqual(proposal.target_digest, _target_digest(request.target))

    def test_incompatible_kind_and_capability_cardinality_fail_closed(self):
        cases = (
            _request(
                "list_saved_reports",
                target=_target(CapabilityTargetKind.REPORT, (REPORT_A,)),
            ),
            _request(
                "compare_saved_reports",
                target=_target(CapabilityTargetKind.REPORT, (REPORT_A,)),
            ),
            _request(
                "get_saved_report",
                target=_target(
                    CapabilityTargetKind.REPORT,
                    (REPORT_A, REPORT_B),
                ),
            ),
            _request(
                "get_finding_timeline",
                target=_target(
                    CapabilityTargetKind.FINDING,
                    (REPORT_A,),
                    "finding:alpha",
                ),
            ),
        )
        for request in cases:
            with self.subTest(capability=request.capability_id):
                with self.assertRaises(_ProposalConstructionError) as caught:
                    _construct_proposal_with_id(request, ISSUED_AT, PROPOSAL_ID)
                self.assertEqual(
                    caught.exception.code,
                    _ProposalFailureCode.INCOMPATIBLE_TARGET,
                )

    def test_report_and_finding_references_remain_inert(self):
        report_request = _request(
            "get_saved_report",
            target=_target(CapabilityTargetKind.REPORT, (REPORT_A,)),
        )
        finding_request = _request(
            "get_finding_timeline",
            target=_target(
                CapabilityTargetKind.FINDING,
                finding_id="finding:does_not_need_to_exist",
            ),
        )
        for request in (report_request, finding_request):
            proposal = _construct_proposal_with_id(
                request, ISSUED_AT, PROPOSAL_ID
            )
            self.assertEqual(proposal.target, request.target)


class CapabilityProposalTests(unittest.TestCase):
    def setUp(self):
        self.request = _request(
            "list_recurring_findings",
            parameters=(
                _parameter("active_only", CapabilityParameterKind.BOOLEAN, "true"),
            ),
        )

    def test_proposal_copies_identity_policy_effects_and_time_exactly(self):
        metadata = _resolve_capability(
            self.request.capability_id, self.request.capability_version
        )
        proposal = _construct_proposal_with_id(
            self.request, ISSUED_AT, PROPOSAL_ID
        )
        self.assertEqual(proposal.proposal_id, PROPOSAL_ID)
        self.assertEqual(proposal.capability_id, metadata.capability_id)
        self.assertEqual(proposal.capability_version, metadata.capability_version)
        self.assertEqual(proposal.effect_class, metadata.effect_class)
        self.assertEqual(proposal.permission_class, metadata.permission_class)
        self.assertEqual(proposal.privacy_class, metadata.privacy_class)
        self.assertIs(proposal.expected_effects, metadata.expected_effects)
        self.assertEqual(proposal.issued_at, ISSUED_AT)
        self.assertEqual(proposal.expires_at, ISSUED_AT + timedelta(minutes=10))
        self.assertEqual(proposal.reuse_policy, ReusePolicy.ONE_TIME)

    def test_invalid_proposal_id_and_non_utc_time_fail_contract_construction(self):
        with self.assertRaises(ValueError):
            _construct_proposal_with_id(self.request, ISSUED_AT, "proposal:bad")
        with self.assertRaises((TypeError, ValueError)):
            _construct_proposal_with_id(
                self.request,
                datetime(2026, 1, 2, 3, 4, 5),
                PROPOSAL_ID,
            )

    def test_private_default_constructor_generates_valid_uuid4_identifier(self):
        proposal = _construct_proposal(self.request, ISSUED_AT)
        self.assertRegex(proposal.proposal_id, r"^proposal:[0-9a-f]{32}$")
        raw = proposal.proposal_id.removeprefix("proposal:")
        self.assertEqual(raw[12], "4")
        self.assertIn(raw[16], "89ab")

    def test_fixed_id_and_time_make_construction_deterministic(self):
        first = _construct_proposal_with_id(
            self.request, ISSUED_AT, PROPOSAL_ID
        )
        second = _construct_proposal_with_id(
            self.request, ISSUED_AT, PROPOSAL_ID
        )
        self.assertEqual(first, second)

    def test_identifier_and_issuance_time_do_not_affect_binding_digests(self):
        first = _construct_proposal_with_id(
            self.request, ISSUED_AT, PROPOSAL_ID
        )
        other_id = "proposal:" + "d" * 12 + "4" + "e" * 3 + "9" + "f" * 15
        second = _construct_proposal_with_id(
            self.request,
            ISSUED_AT + timedelta(seconds=1),
            other_id,
        )
        self.assertNotEqual(first.proposal_id, second.proposal_id)
        self.assertNotEqual(first.issued_at, second.issued_at)
        self.assertEqual(first.target_digest, second.target_digest)
        self.assertEqual(first.parameter_digest, second.parameter_digest)

    def test_returned_proposal_graph_is_deeply_immutable(self):
        proposal = _construct_proposal_with_id(
            self.request, ISSUED_AT, PROPOSAL_ID
        )
        for item, field_name, replacement in (
            (proposal, "system_id", "system:changed"),
            (proposal.target, "system_id", "system:changed"),
            (proposal.parameters[0], "value", "false"),
            (proposal.expected_effects[0], "summary", "changed"),
        ):
            with self.subTest(type=type(item).__name__):
                with self.assertRaises((FrozenInstanceError, AttributeError, TypeError)):
                    setattr(item, field_name, replacement)

    def test_proposal_has_no_authorization_approval_or_execution_state(self):
        proposal = _construct_proposal_with_id(
            self.request, ISSUED_AT, PROPOSAL_ID
        )
        field_names = {field.name for field in fields(proposal)}
        self.assertTrue(
            field_names.isdisjoint(
                {
                    "approval",
                    "approved",
                    "authorization",
                    "authorized",
                    "consumed",
                    "execute",
                    "handler",
                }
            )
        )


class ProposalBoundaryTests(unittest.TestCase):
    def test_private_module_is_not_exported_and_no_facade_method_exists(self):
        self.assertNotIn("_construct_proposal", application.__all__)
        self.assertFalse(
            hasattr(application.CyberWatchtowerApplication, "propose_capability")
        )

    def test_source_imports_only_pure_application_contract_dependencies(self):
        source = PROPOSALS_SOURCE.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
        self.assertLessEqual(
            imported,
            {
                "__future__",
                "dataclasses",
                "datetime",
                "enum",
                "uuid",
                "_capabilities",
                "contracts",
            },
        )
        for forbidden in (
            "sqlite3",
            "subprocess",
            "socket",
            "requests",
            "urllib",
            "cyberwatchtower.memory",
            "cyberwatchtower.reporting",
            "cyberwatchtower.model_gateway",
            "CapabilityRegistry",
            "IntelligenceOrchestrator",
            "datetime.now",
            "os.environ",
            "getenv",
            "open(",
            "Path(",
        ):
            self.assertNotIn(forbidden, source)

    def test_source_has_no_persistence_execution_or_generic_handler_calls(self):
        tree = ast.parse(PROPOSALS_SOURCE.read_text(encoding="utf-8"))
        called_names = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertTrue(
            called_names.isdisjoint(
                {
                    "open",
                    "execute",
                    "exec",
                    "eval",
                    "compile",
                    "connect",
                    "save",
                    "write",
                    "authorize",
                    "approve",
                }
            )
        )


if __name__ == "__main__":
    unittest.main()
