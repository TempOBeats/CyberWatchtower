import ast
import inspect
import unittest
from pathlib import Path

import cyberwatchtower.application as application
from cyberwatchtower.application import CyberWatchtowerApplication
from cyberwatchtower.memory.models import CURRENT_MEMORY_SCHEMA_VERSION
from cyberwatchtower.report_contracts import CURRENT_REPORT_SCHEMA_VERSION
from cyberwatchtower.scanner import run_scan
from cyberwatchtower.scoring_contracts import ScoringVersion


ROOT = Path(__file__).resolve().parents[1]
APPLICATION = ROOT / "src" / "cyberwatchtower" / "application"
PRODUCTION_FILES = (
    APPLICATION / "__init__.py",
    APPLICATION / "_history.py",
    APPLICATION / "_memory.py",
    APPLICATION / "_privacy.py",
    APPLICATION / "contracts.py",
    APPLICATION / "errors.py",
    APPLICATION / "assessment.py",
    APPLICATION / "reports.py",
)
AUTHORIZED_FILES = PRODUCTION_FILES + (
    ROOT / "tests" / "test_application_contracts.py",
    ROOT / "tests" / "test_application_assessment.py",
    ROOT / "tests" / "test_application_boundaries.py",
    ROOT / "tests" / "test_application_reports.py",
    ROOT / "tests" / "test_application_history_contracts.py",
    ROOT / "tests" / "test_application_history_comparison.py",
    ROOT / "tests" / "test_application_memory_ingestion.py",
)


def _source(path):
    return path.read_text(encoding="utf-8")


def _tree(path):
    return ast.parse(_source(path), filename=str(path))


def _imports(path):
    names = []
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.append(node.module or "")
    return tuple(names)


class ApplicationBoundaryTests(unittest.TestCase):
    def test_authorized_d3_file_boundary_exists(self):
        self.assertTrue(all(path.is_file() for path in AUTHORIZED_FILES))
        self.assertEqual(
            {path.name for path in APPLICATION.glob("*.py")},
            {
                "__init__.py", "_history.py", "_memory.py", "_privacy.py",
                "contracts.py", "errors.py", "assessment.py", "reports.py",
            },
        )

    def test_application_has_no_platform_specific_or_native_imports(self):
        forbidden_prefixes = (
            "cyberwatchtower.platform.linux",
            "cyberwatchtower.platform.windows",
            "cyberwatchtower.windows_firewall",
            "subprocess",
            "sqlite3",
            "asyncio",
            "threading",
            "multiprocessing",
            "cyberwatchtower.intelligence",
            "cyberwatchtower.advisor",
            "cyberwatchtower.model_gateway",
        )
        imports = set()
        for path in PRODUCTION_FILES:
            for imported in _imports(path):
                imports.add(imported)
                self.assertFalse(
                    imported.startswith(forbidden_prefixes),
                    f"forbidden application import: {imported}",
                )
                if imported == "cyberwatchtower.history":
                    self.assertEqual(path.name, "_history.py")
                if imported == "cyberwatchtower.reporting":
                    self.assertEqual(path.name, "reports.py")
        self.assertNotIn("platform", imports)

    def test_memory_import_is_limited_to_pure_models_and_normalization(self):
        for path in PRODUCTION_FILES:
            memory_imports = {
                imported for imported in _imports(path)
                if imported.startswith("cyberwatchtower.memory")
            }
            if path.name == "_memory.py":
                self.assertLessEqual(memory_imports, {
                    "cyberwatchtower.memory.errors",
                    "cyberwatchtower.memory.ingestion",
                    "cyberwatchtower.memory.ingestion_models",
                    "cyberwatchtower.memory.service",
                })
            else:
                self.assertLessEqual(memory_imports, {
                    "cyberwatchtower.memory.ingestion_models",
                    "cyberwatchtower.memory.normalizers",
                    "cyberwatchtower.memory.sanitization",
                })

    def test_scanner_authority_is_resolved_at_runtime_and_called_once(self):
        assessment = APPLICATION / "assessment.py"
        calls = []
        for node in ast.walk(_tree(assessment)):
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            if (
                isinstance(function, ast.Attribute)
                and isinstance(function.value, ast.Name)
                and function.value.id == "scanner"
                and function.attr == "run_scan"
            ):
                calls.append(node)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].args, [])
        self.assertEqual(calls[0].keywords, [])
        self.assertNotIn("run_scan as", _source(assessment))

    def test_no_domain_inference_or_recalculation_helpers_are_used(self):
        public_boundary = tuple(
            path for path in PRODUCTION_FILES if path.name != "_memory.py"
        )
        combined = "\n".join(_source(path) for path in public_boundary)
        for prohibited in (
            "SOURCE_COVERAGE_REQUIREMENTS",
            "platform.system",
            "select_platform_adapter",
            "calculate_security_score",
            "calculate_security_score_v2",
            "assess_listener_reachability",
            "assess_network_exposure",
            "evaluate_firewall",
        ):
            self.assertNotIn(prohibited, combined)

    def test_only_private_repository_has_canonical_persistence_authority(self):
        combined = "\n".join(
            _source(path) for path in PRODUCTION_FILES
            if path.name != "_memory.py"
        )
        for prohibited in (
            "open_memory_database",
            "report_directory",
            "database_path",
            "subprocess",
            "sqlite3",
            "create_task",
            "ThreadPool",
            "ProcessPool",
            "scheduler",
            "queue",
            "urllib",
            "requests",
        ):
            self.assertNotIn(prohibited, combined)
        for path in PRODUCTION_FILES:
            self.assertFalse(
                any(isinstance(node, ast.AsyncFunctionDef) for node in ast.walk(_tree(path)))
            )
            if path.name != "reports.py":
                self.assertNotIn("save_json_report", _source(path))
        self.assertEqual(
            _source(APPLICATION / "reports.py").count(
                "reporting._save_json_report_with_receipt("
            ),
            1,
        )
        self.assertNotIn(
            "reporting.save_json_report(",
            _source(APPLICATION / "reports.py"),
        )

    def test_finding_coverage_is_not_reconstructed(self):
        combined = "\n".join(_source(path) for path in PRODUCTION_FILES)
        self.assertNotIn("coverage_domains", combined)
        self.assertNotIn("SOURCE_COVERAGE_REQUIREMENTS", combined)

    def test_local_dtos_make_no_provider_safety_claim(self):
        combined = "\n".join(_source(path) for path in PRODUCTION_FILES).casefold()
        self.assertNotIn("provider_safe", combined)
        self.assertNotIn("safe_to_send", combined)
        self.assertNotIn("provider payload", combined)

    def test_no_wire_serialization_or_numeric_application_api_exists(self):
        combined = "\n".join(_source(path) for path in PRODUCTION_FILES)
        self.assertNotIn("def to_dict", combined)
        self.assertNotIn("api_version", combined)

    def test_public_exports_exclude_private_runner_and_authorities(self):
        exports = set(application.__all__)
        self.assertNotIn("_AssessmentRunner", exports)
        self.assertNotIn("scanner", exports)
        self.assertNotIn("run_scan", exports)
        self.assertNotIn("PlatformAdapter", exports)
        self.assertFalse(any(name.startswith("_") for name in exports))

    def test_public_facade_accepts_no_dependencies_and_scanner_api_is_unchanged(self):
        self.assertEqual(tuple(inspect.signature(CyberWatchtowerApplication).parameters), ())
        scanner_parameters = inspect.signature(run_scan).parameters
        self.assertEqual(tuple(scanner_parameters), ("adapter",))
        self.assertIsNone(scanner_parameters["adapter"].default)

    def test_d6_adds_only_the_frozen_report_facade_methods(self):
        for method in (
            "assess_and_save_current_system",
            "list_saved_reports",
            "get_saved_report",
            "get_latest_saved_report",
        ):
            self.assertTrue(hasattr(CyberWatchtowerApplication, method))
        combined = "\n".join(_source(path) for path in PRODUCTION_FILES)
        for prohibited in (
            ".write_text(",
            ".write_bytes(",
            ".mkdir(",
            ".unlink(",
            ".rename(",
            "os.remove",
            "os.unlink",
        ):
            self.assertNotIn(prohibited, combined)
        self.assertNotIn(
            "save_json_report",
            _source(APPLICATION / "assessment.py"),
        )

    def test_e4_adds_only_the_pairwise_comparison_facade_method(self):
        self.assertTrue(hasattr(CyberWatchtowerApplication, "compare_saved_reports"))
        history_source = _source(APPLICATION / "_history.py")
        self.assertNotIn("load_reports", history_source)
        self.assertNotIn("memory.database", history_source)
        self.assertNotIn("memory.service", history_source)

    def test_e5_and_e6_add_only_the_frozen_memory_facade_methods(self):
        self.assertTrue(hasattr(
            CyberWatchtowerApplication,
            "ingest_saved_report_into_memory",
        ))
        for method in (
            "list_recurring_findings",
            "get_finding_timeline",
            "get_score_history",
            "get_memory_health",
        ):
            self.assertTrue(hasattr(CyberWatchtowerApplication, method))
        private_memory = _source(APPLICATION / "_memory.py")
        contracts = _source(APPLICATION / "contracts.py")
        self.assertIn("CYBERWATCHTOWER_MEMORY_DB", private_memory)
        self.assertNotIn("CYBERWATCHTOWER_MEMORY_DB", contracts)
        self.assertNotIn("SQLiteSecurityMemory", contracts)

    def test_report_repository_is_private_and_has_no_wrong_way_import(self):
        exports = set(application.__all__)
        self.assertNotIn("_FileReportRepository", exports)
        self.assertNotIn("_ReportRepositoryPort", exports)
        self.assertNotIn("MAX_REPORT_BYTES", exports)
        report_imports = set(_imports(APPLICATION / "reports.py"))
        self.assertNotIn("assessment", report_imports)
        self.assertNotIn("cyberwatchtower.application.assessment", report_imports)

    def test_private_seams_confine_storage_and_out_of_scope_imports(self):
        for filename in ("_history.py",):
            imports = set(_imports(APPLICATION / filename))
            for prohibited in (
                "sqlite3", "subprocess", "os", "pathlib", "asyncio",
                "threading", "cyberwatchtower.memory.database",
                "cyberwatchtower.memory.service",
                "cyberwatchtower.intelligence", "cyberwatchtower.cli",
            ):
                self.assertNotIn(prohibited, imports, (filename, prohibited))
        memory_imports = set(_imports(APPLICATION / "_memory.py"))
        for prohibited in (
            "sqlite3", "subprocess", "asyncio", "threading",
            "cyberwatchtower.memory.database", "cyberwatchtower.intelligence",
            "cyberwatchtower.cli",
        ):
            self.assertNotIn(prohibited, memory_imports, prohibited)
        self.assertIn("cyberwatchtower.memory.service", memory_imports)
        self.assertIn("os", memory_imports)
        self.assertIn("pathlib", memory_imports)
        self.assertEqual(
            tuple(
                imported
                for imported in _imports(APPLICATION / "_history.py")
                if imported == "cyberwatchtower.history"
            ),
            ("cyberwatchtower.history",),
        )

    def test_shared_privacy_module_is_private_and_policy_is_not_duplicated(self):
        self.assertNotIn("_privacy", application.__all__)
        self.assertNotIn("_project_evidence", application.__all__)
        assessment_source = _source(APPLICATION / "assessment.py")
        privacy_source = _source(APPLICATION / "_privacy.py")
        self.assertNotIn("_EVIDENCE_CATEGORIES", assessment_source)
        self.assertNotIn("_SOURCE_EVIDENCE", assessment_source)
        self.assertIn("_EVIDENCE_CATEGORIES", privacy_source)
        self.assertIn("_SOURCE_EVIDENCE", privacy_source)

    def test_frozen_schema_and_scoring_versions_are_unchanged(self):
        self.assertEqual(CURRENT_REPORT_SCHEMA_VERSION, "1.7")
        self.assertEqual(CURRENT_MEMORY_SCHEMA_VERSION, 8)
        self.assertEqual(ScoringVersion.V2.value, "2")

    def test_application_init_only_reexports_application_modules(self):
        imports = _imports(APPLICATION / "__init__.py")
        self.assertEqual(set(imports), {"assessment", "contracts", "errors"})


if __name__ == "__main__":
    unittest.main()
