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
    APPLICATION / "contracts.py",
    APPLICATION / "errors.py",
    APPLICATION / "assessment.py",
)
AUTHORIZED_FILES = PRODUCTION_FILES + (
    ROOT / "tests" / "test_application_contracts.py",
    ROOT / "tests" / "test_application_assessment.py",
    ROOT / "tests" / "test_application_boundaries.py",
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
    def test_authorized_seven_file_boundary_exists(self):
        self.assertTrue(all(path.is_file() for path in AUTHORIZED_FILES))
        self.assertEqual(
            {path.name for path in APPLICATION.glob("*.py")},
            {"__init__.py", "contracts.py", "errors.py", "assessment.py"},
        )

    def test_application_has_no_platform_specific_or_native_imports(self):
        imports = {
            imported
            for path in PRODUCTION_FILES
            for imported in _imports(path)
        }
        forbidden_prefixes = (
            "cyberwatchtower.platform.linux",
            "cyberwatchtower.platform.windows",
            "cyberwatchtower.windows_firewall",
            "subprocess",
            "sqlite3",
            "asyncio",
            "threading",
            "multiprocessing",
        )
        for imported in imports:
            self.assertFalse(
                imported.startswith(forbidden_prefixes),
                f"forbidden application import: {imported}",
            )
        self.assertNotIn("platform", imports)

    def test_memory_import_is_limited_to_pure_sanitization(self):
        memory_imports = sorted(
            imported
            for path in PRODUCTION_FILES
            for imported in _imports(path)
            if imported.startswith("cyberwatchtower.memory")
        )
        self.assertEqual(
            memory_imports,
            ["cyberwatchtower.memory.sanitization"],
        )

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
        combined = "\n".join(_source(path) for path in PRODUCTION_FILES)
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

    def test_no_persistence_command_or_concurrency_authority_exists(self):
        combined = "\n".join(_source(path) for path in PRODUCTION_FILES)
        for prohibited in (
            "save_json_report",
            "open_memory_database",
            "report_directory",
            "database_path",
            "subprocess",
            "sqlite3",
            "create_task",
            "ThreadPool",
            "ProcessPool",
            "scheduler",
        ):
            self.assertNotIn(prohibited, combined)
        for path in PRODUCTION_FILES:
            self.assertFalse(
                any(isinstance(node, ast.AsyncFunctionDef) for node in ast.walk(_tree(path)))
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
        self.assertNotIn("schema_version:", combined)

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

    def test_frozen_schema_and_scoring_versions_are_unchanged(self):
        self.assertEqual(CURRENT_REPORT_SCHEMA_VERSION, "1.7")
        self.assertEqual(CURRENT_MEMORY_SCHEMA_VERSION, 8)
        self.assertEqual(ScoringVersion.V2.value, "2")

    def test_application_init_only_reexports_application_modules(self):
        imports = _imports(APPLICATION / "__init__.py")
        self.assertEqual(set(imports), {"assessment", "contracts", "errors"})


if __name__ == "__main__":
    unittest.main()
