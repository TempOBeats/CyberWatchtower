import ast
from dataclasses import FrozenInstanceError
from pathlib import Path
import re
import unittest

import cyberwatchtower.application as application
from cyberwatchtower.application import (
    CapabilityAvailability,
    CapabilityMetadata,
    CapabilityParameterKind,
    CapabilityTarget,
    CapabilityTargetKind,
    EffectClass,
    PermissionClass,
    PrivacyClass,
    ProposalParameter,
    ReportId,
)
from cyberwatchtower.application._capabilities import (
    _canonical_parameter_bytes,
    _canonical_target_bytes,
    _capability_catalog,
    _lookup_capability,
    _parameter_digest,
    _target_digest,
)


SYSTEM_ID = "system:alpha"
REPORT_A = ReportId("report:" + "a" * 64)
REPORT_B = ReportId("report:" + "b" * 64)

PARAMETER_VECTORS = (
    (
        "empty",
        (),
        b"CWT-PARAMETERS-V1\x00",
        "1044aeb111ad3b20c811e434d17b8df5f529665a4e61e674661ec41e4c551681",
    ),
    (
        "text",
        (ProposalParameter("note", CapabilityParameterKind.TEXT, "hello"),),
        b"CWT-PARAMETERS-V1\x00\x00\x04noteT\x00\x00\x00\x05hello",
        "c1890288e7cd0430e33d870ee215fd6facb1642d6dd4201a3eb6613c0e95b33e",
    ),
    (
        "integer",
        (ProposalParameter("limit", CapabilityParameterKind.INTEGER, "-42"),),
        b"CWT-PARAMETERS-V1\x00\x00\x05limitI\x00\x00\x00\x03-42",
        "ef45002edba89345af9a308860305bf3dc8f83c836c9a7cd49e17320ccc82555",
    ),
    (
        "boolean_false",
        (
            ProposalParameter(
                "active_only", CapabilityParameterKind.BOOLEAN, "false"
            ),
        ),
        b"CWT-PARAMETERS-V1\x00\x00\x0bactive_onlyB\x00\x00\x00\x05false",
        "1f7606219c12ec053e28555b9cfe9ffd6bf9707511670c2eac9a925c48eb59a8",
    ),
    (
        "boolean_true",
        (
            ProposalParameter(
                "active_only", CapabilityParameterKind.BOOLEAN, "true"
            ),
        ),
        b"CWT-PARAMETERS-V1\x00\x00\x0bactive_onlyB\x00\x00\x00\x04true",
        "9dec3d6d91b8e02af6219695e42864b0edd126dfb6a9f0aefa74b3e8d7a3f224",
    ),
    (
        "utc_timestamp",
        (
            ProposalParameter(
                "start_at",
                CapabilityParameterKind.UTC_TIMESTAMP,
                "2026-01-02T03:04:05.000006Z",
            ),
        ),
        b"CWT-PARAMETERS-V1\x00\x00\x08start_atD\x00\x00\x00\x1b"
        b"2026-01-02T03:04:05.000006Z",
        "9c96985c3f966a0ce8bd0694322ab3097ccda3b67273a78da415a8ca4a0b30b4",
    ),
    (
        "multiple",
        (
            ProposalParameter(
                "active_only", CapabilityParameterKind.BOOLEAN, "false"
            ),
            ProposalParameter("limit", CapabilityParameterKind.INTEGER, "50"),
        ),
        b"CWT-PARAMETERS-V1\x00\x00\x0bactive_onlyB\x00\x00\x00\x05false"
        b"\x00\x05limitI\x00\x00\x00\x0250",
        "b685e6df10c01564bbfd3a5f56b8d5fc2068ccc7c9603af72a43145bfe3943b0",
    ),
)

TARGET_VECTORS = (
    (
        "application",
        CapabilityTarget(CapabilityTargetKind.APPLICATION, SYSTEM_ID, (), None),
        b"CWT-TARGET-V1\x00A\x00\x00\x00\x0csystem:alpha\x00\x00",
        "6d482949a3a2fc4801a270aa966a75273b72b0da30c77aff47452e1f8e520551",
    ),
    (
        "system",
        CapabilityTarget(CapabilityTargetKind.SYSTEM, SYSTEM_ID, (), None),
        b"CWT-TARGET-V1\x00S\x00\x00\x00\x0csystem:alpha\x00\x00",
        "2202a1804b73495418cbc1f6656cffc53516c3a7e9204d8ee0c47765434a21e0",
    ),
    (
        "report",
        CapabilityTarget(CapabilityTargetKind.REPORT, SYSTEM_ID, (REPORT_A,), None),
        b"CWT-TARGET-V1\x00R\x00\x00\x00\x0csystem:alpha\x01\x00Greport:"
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x00",
        "b09c29fc1ac1ed38589f2dd1f5e4e6abfed219553ec7328d56b384adc16da70e",
    ),
    (
        "finding",
        CapabilityTarget(
            CapabilityTargetKind.FINDING,
            SYSTEM_ID,
            (),
            "finding:alpha",
        ),
        b"CWT-TARGET-V1\x00F\x00\x00\x00\x0csystem:alpha\x00\x01\x00\r"
        b"finding:alpha",
        "5544640a9a3257d215dd668839963fe64611395a574da9368c5e098b7ceff162",
    ),
)


EXPECTED_CATALOG = {
    "cyberwatchtower.application.assess_and_save_current_system": (
        EffectClass.LOCAL_AUTHORITATIVE_STATE_CHANGE,
        PermissionClass.USER_APPROVAL_REQUIRED,
        PrivacyClass.SENSITIVE_LOCAL_DATA,
        (CapabilityTargetKind.SYSTEM,),
        (),
        (
            (
                "observe_current_system",
                EffectClass.SYSTEM_OBSERVATION,
                "Observe the current local system through the frozen assessment boundary.",
            ),
            (
                "write_canonical_report",
                EffectClass.LOCAL_AUTHORITATIVE_STATE_CHANGE,
                "Create one canonical saved assessment report.",
            ),
        ),
    ),
    "cyberwatchtower.application.assess_current_system": (
        EffectClass.SYSTEM_OBSERVATION,
        PermissionClass.READ_ONLY,
        PrivacyClass.SENSITIVE_LOCAL_DATA,
        (CapabilityTargetKind.SYSTEM,),
        (),
        (
            (
                "observe_current_system",
                EffectClass.SYSTEM_OBSERVATION,
                "Observe the current local system through the frozen assessment boundary.",
            ),
        ),
    ),
    "cyberwatchtower.application.compare_saved_reports": (
        EffectClass.LOCAL_READ,
        PermissionClass.READ_ONLY,
        PrivacyClass.SENSITIVE_LOCAL_DATA,
        (CapabilityTargetKind.REPORT,),
        (),
        (
            (
                "read_canonical_reports",
                EffectClass.LOCAL_READ,
                "Read and compare two exact same-system canonical saved reports.",
            ),
        ),
    ),
    "cyberwatchtower.application.get_finding_timeline": (
        EffectClass.LOCAL_READ,
        PermissionClass.READ_ONLY,
        PrivacyClass.SENSITIVE_LOCAL_DATA,
        (CapabilityTargetKind.FINDING,),
        (("limit", CapabilityParameterKind.INTEGER, False, PrivacyClass.PUBLIC_METADATA),),
        (
            (
                "read_derived_memory",
                EffectClass.LOCAL_READ,
                "Read a bounded exact-system finding timeline from SecurityMemory.",
            ),
        ),
    ),
    "cyberwatchtower.application.get_latest_saved_report": (
        EffectClass.LOCAL_READ,
        PermissionClass.READ_ONLY,
        PrivacyClass.SENSITIVE_LOCAL_DATA,
        (CapabilityTargetKind.SYSTEM,),
        (),
        (
            (
                "read_report_catalog",
                EffectClass.LOCAL_READ,
                "Read the latest canonical saved-report metadata and report for one exact system.",
            ),
        ),
    ),
    "cyberwatchtower.application.get_memory_health": (
        EffectClass.LOCAL_READ,
        PermissionClass.READ_ONLY,
        PrivacyClass.LOCAL_SECURITY_DATA,
        (CapabilityTargetKind.APPLICATION,),
        (),
        (
            (
                "read_memory_health",
                EffectClass.LOCAL_READ,
                "Read bounded privacy-safe SecurityMemory health state.",
            ),
        ),
    ),
    "cyberwatchtower.application.get_saved_report": (
        EffectClass.LOCAL_READ,
        PermissionClass.READ_ONLY,
        PrivacyClass.SENSITIVE_LOCAL_DATA,
        (CapabilityTargetKind.REPORT,),
        (),
        (
            (
                "read_canonical_report",
                EffectClass.LOCAL_READ,
                "Read one exact canonical saved report.",
            ),
        ),
    ),
    "cyberwatchtower.application.get_score_history": (
        EffectClass.LOCAL_READ,
        PermissionClass.READ_ONLY,
        PrivacyClass.LOCAL_SECURITY_DATA,
        (CapabilityTargetKind.SYSTEM,),
        (
            ("end_at", CapabilityParameterKind.UTC_TIMESTAMP, True, PrivacyClass.LOCAL_SECURITY_DATA),
            ("limit", CapabilityParameterKind.INTEGER, False, PrivacyClass.PUBLIC_METADATA),
            ("scoring_version", CapabilityParameterKind.TEXT, False, PrivacyClass.PUBLIC_METADATA),
            ("start_at", CapabilityParameterKind.UTC_TIMESTAMP, True, PrivacyClass.LOCAL_SECURITY_DATA),
        ),
        (
            (
                "read_derived_memory",
                EffectClass.LOCAL_READ,
                "Read bounded score-history series from SecurityMemory.",
            ),
        ),
    ),
    "cyberwatchtower.application.ingest_saved_report_into_memory": (
        EffectClass.LOCAL_DERIVED_STATE_CHANGE,
        PermissionClass.USER_APPROVAL_REQUIRED,
        PrivacyClass.SENSITIVE_LOCAL_DATA,
        (CapabilityTargetKind.REPORT,),
        (),
        (
            (
                "read_canonical_report",
                EffectClass.LOCAL_READ,
                "Read one exact canonical saved report.",
            ),
            (
                "write_derived_memory",
                EffectClass.LOCAL_DERIVED_STATE_CHANGE,
                "Idempotently derive SecurityMemory state from that report.",
            ),
        ),
    ),
    "cyberwatchtower.application.list_recurring_findings": (
        EffectClass.LOCAL_READ,
        PermissionClass.READ_ONLY,
        PrivacyClass.SENSITIVE_LOCAL_DATA,
        (CapabilityTargetKind.SYSTEM,),
        (
            ("active_only", CapabilityParameterKind.BOOLEAN, False, PrivacyClass.LOCAL_SECURITY_DATA),
            ("limit", CapabilityParameterKind.INTEGER, False, PrivacyClass.PUBLIC_METADATA),
        ),
        (
            (
                "read_derived_memory",
                EffectClass.LOCAL_READ,
                "Read a bounded recurring-finding view from SecurityMemory.",
            ),
        ),
    ),
    "cyberwatchtower.application.list_saved_reports": (
        EffectClass.LOCAL_READ,
        PermissionClass.READ_ONLY,
        PrivacyClass.LOCAL_SECURITY_DATA,
        (CapabilityTargetKind.SYSTEM,),
        (),
        (
            (
                "read_report_catalog",
                EffectClass.LOCAL_READ,
                "Read bounded canonical saved-report metadata for one exact system.",
            ),
        ),
    ),
}


class ApplicationCapabilityCatalogTests(unittest.TestCase):
    def test_catalog_has_exact_frozen_identities_and_order(self):
        catalog = _capability_catalog()
        self.assertIsInstance(catalog, tuple)
        self.assertEqual(len(catalog), 11)
        self.assertLessEqual(len(catalog), 64)
        self.assertEqual(
            tuple(item.capability_id for item in catalog),
            tuple(EXPECTED_CATALOG),
        )
        self.assertEqual(
            tuple(item.capability_id for item in catalog),
            tuple(sorted(EXPECTED_CATALOG)),
        )
        self.assertEqual({item.capability_version for item in catalog}, {"1"})
        self.assertEqual(
            len({(item.capability_id, item.capability_version) for item in catalog}),
            11,
        )

    def test_catalog_metadata_matches_frozen_contract(self):
        for item in _capability_catalog():
            with self.subTest(capability_id=item.capability_id):
                (
                    effect_class,
                    permission_class,
                    privacy_class,
                    target_kinds,
                    parameters,
                    expected_effects,
                ) = EXPECTED_CATALOG[item.capability_id]
                self.assertIsInstance(item, CapabilityMetadata)
                self.assertEqual(item.effect_class, effect_class)
                self.assertEqual(item.permission_class, permission_class)
                self.assertEqual(item.privacy_class, privacy_class)
                self.assertEqual(item.availability, CapabilityAvailability.AVAILABLE)
                self.assertEqual(item.target_kinds, target_kinds)
                self.assertEqual(
                    tuple(
                        (spec.key, spec.kind, spec.required, spec.privacy_class)
                        for spec in item.parameters
                    ),
                    parameters,
                )
                self.assertEqual(
                    tuple(
                        (effect.effect_id, effect.effect_class, effect.summary)
                        for effect in item.expected_effects
                    ),
                    expected_effects,
                )

    def test_available_catalog_contains_no_secret_parameters(self):
        self.assertFalse(
            any(
                spec.privacy_class == PrivacyClass.SECRET
                for item in _capability_catalog()
                for spec in item.parameters
            )
        )

    def test_catalog_contains_no_hypothetical_or_f_capabilities(self):
        ids = {item.capability_id for item in _capability_catalog()}
        forbidden_leaves = {
            "ask_assistant",
            "get_security_briefing",
            "list_capabilities",
            "propose_capability",
            "scan_host",
            "inspect_process",
            "inspect_service",
            "remediation",
            "shell",
        }
        self.assertTrue(
            all(not identifier.endswith(tuple(forbidden_leaves)) for identifier in ids)
        )

    def test_catalog_and_entries_are_immutable(self):
        catalog = _capability_catalog()
        with self.assertRaises(TypeError):
            catalog[0] = catalog[1]
        with self.assertRaises(FrozenInstanceError):
            catalog[0].title = "changed"
        self.assertIs(catalog, _capability_catalog())

    def test_metadata_exposes_no_handler_or_callable(self):
        forbidden = {"handler", "callable", "command", "argv", "executable_path"}
        self.assertTrue(forbidden.isdisjoint(CapabilityMetadata.__dataclass_fields__))

    def test_exact_lookup_and_private_not_found_signal(self):
        item = _lookup_capability(
            "cyberwatchtower.application.get_saved_report", "1"
        )
        self.assertIsNotNone(item)
        self.assertEqual(item.capability_id, "cyberwatchtower.application.get_saved_report")
        self.assertIsNone(_lookup_capability("cyberwatchtower.application.unknown", "1"))
        self.assertIsNone(
            _lookup_capability("cyberwatchtower.application.get_saved_report", "2")
        )
        self.assertIsNone(_lookup_capability(1, "1"))


class ApplicationParameterBindingTests(unittest.TestCase):
    def test_parameter_byte_and_digest_vectors_are_exact(self):
        for name, parameters, expected_bytes, expected_digest in PARAMETER_VECTORS:
            with self.subTest(name=name):
                self.assertEqual(_canonical_parameter_bytes(parameters), expected_bytes)
                self.assertEqual(_parameter_digest(parameters), expected_digest)

    def test_parameter_binding_changes_with_key_type_or_value(self):
        baseline = (ProposalParameter("limit", CapabilityParameterKind.TEXT, "50"),)
        variants = (
            (ProposalParameter("count", CapabilityParameterKind.TEXT, "50"),),
            (ProposalParameter("limit", CapabilityParameterKind.INTEGER, "50"),),
            (ProposalParameter("limit", CapabilityParameterKind.TEXT, "51"),),
        )
        for variant in variants:
            self.assertNotEqual(
                _canonical_parameter_bytes(baseline),
                _canonical_parameter_bytes(variant),
            )
            self.assertNotEqual(_parameter_digest(baseline), _parameter_digest(variant))

    def test_parameter_binding_is_deterministic_lowercase_sha256(self):
        parameters = PARAMETER_VECTORS[-1][1]
        self.assertEqual(
            _canonical_parameter_bytes(parameters),
            _canonical_parameter_bytes(parameters),
        )
        digest = _parameter_digest(parameters)
        self.assertEqual(digest, _parameter_digest(parameters))
        self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_parameter_canonicalizer_requires_valid_ordered_tuple(self):
        active = ProposalParameter(
            "active_only", CapabilityParameterKind.BOOLEAN, "false"
        )
        limit = ProposalParameter("limit", CapabilityParameterKind.INTEGER, "50")
        for invalid in ([active], (limit, active), (limit, limit), (object(),)):
            with self.subTest(invalid=type(invalid).__name__):
                with self.assertRaises((TypeError, ValueError)):
                    _canonical_parameter_bytes(invalid)

    def test_parameter_canonicalizer_does_not_materialize_defaults(self):
        self.assertEqual(_canonical_parameter_bytes(()), b"CWT-PARAMETERS-V1\x00")
        self.assertNotIn(b"active_only", _canonical_parameter_bytes(()))
        self.assertNotIn(b"limit", _canonical_parameter_bytes(()))

    def test_parameter_canonicalizer_rejects_more_than_32_values(self):
        parameters = tuple(
            ProposalParameter(
                f"p{index:02d}", CapabilityParameterKind.INTEGER, str(index)
            )
            for index in range(33)
        )
        with self.assertRaises(ValueError):
            _canonical_parameter_bytes(parameters)


class ApplicationTargetBindingTests(unittest.TestCase):
    def test_target_byte_and_digest_vectors_are_exact(self):
        for name, target, expected_bytes, expected_digest in TARGET_VECTORS:
            with self.subTest(name=name):
                self.assertEqual(_canonical_target_bytes(target), expected_bytes)
                self.assertEqual(_target_digest(target), expected_digest)

    def test_target_kind_and_system_changes_alter_binding(self):
        application_target = TARGET_VECTORS[0][1]
        system_target = TARGET_VECTORS[1][1]
        other_system = CapabilityTarget(
            CapabilityTargetKind.SYSTEM, "system:beta", (), None
        )
        self.assertNotEqual(_target_digest(application_target), _target_digest(system_target))
        self.assertNotEqual(_target_digest(system_target), _target_digest(other_system))

    def test_report_order_and_identity_change_binding(self):
        one_a = CapabilityTarget(
            CapabilityTargetKind.REPORT, SYSTEM_ID, (REPORT_A,), None
        )
        one_b = CapabilityTarget(
            CapabilityTargetKind.REPORT, SYSTEM_ID, (REPORT_B,), None
        )
        previous_current = CapabilityTarget(
            CapabilityTargetKind.REPORT, SYSTEM_ID, (REPORT_A, REPORT_B), None
        )
        current_previous = CapabilityTarget(
            CapabilityTargetKind.REPORT, SYSTEM_ID, (REPORT_B, REPORT_A), None
        )
        self.assertNotEqual(_target_digest(one_a), _target_digest(one_b))
        self.assertNotEqual(_target_digest(previous_current), _target_digest(current_previous))

    def test_finding_identity_changes_binding(self):
        alpha = TARGET_VECTORS[-1][1]
        beta = CapabilityTarget(
            CapabilityTargetKind.FINDING, SYSTEM_ID, (), "finding:beta"
        )
        self.assertNotEqual(_canonical_target_bytes(alpha), _canonical_target_bytes(beta))
        self.assertNotEqual(_target_digest(alpha), _target_digest(beta))

    def test_target_binding_is_deterministic_lowercase_sha256(self):
        target = TARGET_VECTORS[-1][1]
        self.assertEqual(_canonical_target_bytes(target), _canonical_target_bytes(target))
        self.assertRegex(_target_digest(target), r"^[0-9a-f]{64}$")

    def test_target_canonicalizer_rejects_invalid_runtime_types(self):
        for invalid in (None, {}, object(), SYSTEM_ID):
            with self.subTest(invalid=type(invalid).__name__):
                with self.assertRaises(TypeError):
                    _canonical_target_bytes(invalid)


class ApplicationCapabilityCoreSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_path = (
            Path(__file__).parents[1]
            / "src"
            / "cyberwatchtower"
            / "application"
            / "_capabilities.py"
        )
        cls.source = cls.source_path.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)

    def test_module_is_private_and_adds_no_public_export(self):
        self.assertEqual(self.source_path.name, "_capabilities.py")
        self.assertNotIn("_capabilities", application.__all__)
        self.assertTrue(
            {
                "_capability_catalog",
                "_lookup_capability",
                "_canonical_parameter_bytes",
                "_parameter_digest",
                "_canonical_target_bytes",
                "_target_digest",
            }.isdisjoint(application.__all__)
        )

    def test_module_has_only_closed_local_imports(self):
        imported_modules = {
            node.module
            for node in ast.walk(self.tree)
            if isinstance(node, ast.ImportFrom)
        }
        self.assertEqual(imported_modules, {"__future__", "hashlib", "contracts"})
        self.assertFalse(any(isinstance(node, ast.Import) for node in ast.walk(self.tree)))

    def test_module_has_no_forbidden_runtime_dependencies(self):
        forbidden = {
            "CapabilityRegistry",
            "ModelGateway",
            "IntelligenceOrchestrator",
            "subprocess",
            "socket",
            "requests",
            "urllib",
            "sqlite3",
            "scanner",
            "platform",
            "getenv",
            "environ",
            "open",
            "Path",
        }
        names = {node.id for node in ast.walk(self.tree) if isinstance(node, ast.Name)}
        attrs = {node.attr for node in ast.walk(self.tree) if isinstance(node, ast.Attribute)}
        self.assertTrue(forbidden.isdisjoint(names | attrs))

    def test_module_has_no_registration_execution_or_proposal_generation(self):
        functions = {
            node.name
            for node in ast.walk(self.tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        self.assertFalse(
            any(
                re.search(r"register|execute|authorize|proposal", name)
                for name in functions
            )
        )
        self.assertNotIn("CapabilityProposal", self.source)
        self.assertNotIn("uuid", self.source.lower())

    def test_canonicalization_uses_no_repr_json_pickle_or_locale(self):
        forbidden_calls = {"repr", "dumps", "dump", "loads", "load"}
        calls = {
            node.func.id
            for node in ast.walk(self.tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertTrue(forbidden_calls.isdisjoint(calls))
        self.assertNotIn("json", self.source)
        self.assertNotIn("pickle", self.source)
        self.assertNotIn("locale", self.source)

    def test_facade_gains_no_f_methods(self):
        for method in (
            "get_security_briefing",
            "ask_assistant",
            "list_capabilities",
            "propose_capability",
        ):
            self.assertFalse(hasattr(application.CyberWatchtowerApplication, method))


if __name__ == "__main__":
    unittest.main()
