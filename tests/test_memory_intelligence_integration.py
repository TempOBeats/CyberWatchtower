import copy
import io
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from contextlib import redirect_stdout

from cyberwatchtower.advisor.context import build_advisor_context
from cyberwatchtower.advisor.service import build_provider_request, generate_advisory
from cyberwatchtower.briefing.builder import build_security_briefing
from cyberwatchtower.capabilities.registry import (
    CapabilityContext, CapabilityDenied, CapabilityRequest, PermissionClass,
    build_read_only_registry,
)
from cyberwatchtower.cli import _ingest_saved_report
from cyberwatchtower.cli import main
from cyberwatchtower.conversation.session import ConversationSession
from cyberwatchtower.core.grounding import validate_grounding
from cyberwatchtower.core.orchestrator import IntelligenceOrchestrator, OrchestratorState
from cyberwatchtower.finding_identity import finding_identity
from cyberwatchtower.memory.context import MemoryContext, build_memory_context
from cyberwatchtower.memory.decision_models import FindingScope
from cyberwatchtower.memory.decision_models import BaselineEntry, BaselineType, ListenerScope
from cyberwatchtower.memory.ingestion_models import IngestionStatus
from cyberwatchtower.memory.errors import (
    MemoryCorrupt, MemoryIncompatibleVersion, MemoryLocked,
    MemoryMigrationFailed, MemoryUnavailable,
)
from cyberwatchtower.memory.investigation_models import ReferenceState, ReferenceType
from cyberwatchtower.memory.service import SecurityMemory, SQLiteSecurityMemory


def _reports():
    finding = {
        "finding_id": "finding:exposed",
        "title": "Exposed service",
        "description": "A listener is exposed.",
        "severity": "HIGH",
        "recommendation": "Restrict the listener.",
        "confidence": 95,
        "source": "network",
        "kind": "RISK",
        "assessment_state": "CONFIRMED",
        "evidence": ["Protocol: tcp", "Port: 8080", "Process: python3"],
    }
    base = {
        "schema_version": "1.1",
        "generated_at": "2026-08-12T00:00:00+00:00",
        "system": {"system_id": "cwt-test", "hostname": "host"},
        "coverage": {"network_socket_inspection": "COMPLETE"},
        "security_score": {"score": 90, "risk_level": "LOW", "counts": {}},
        "findings": [],
    }
    return (base, {
        **base,
        "generated_at": "2026-08-13T00:00:00+00:00",
        "security_score": {"score": 70, "risk_level": "MEDIUM", "counts": {"HIGH": 1}},
        "findings": [finding],
    })


class FakeMemory:
    def __init__(self, *, fail=False, references=()):
        self.fail = fail
        self.references = references
        self.remembered = []

    def _check(self):
        if self.fail:
            raise RuntimeError("database path=/secret/memory.db token=canary")

    def active_exceptions(self, **kwargs): self._check(); return ()
    def current_baseline(self, **kwargs): self._check(); return None
    def previous_investigation_for_finding(self, **kwargs): self._check(); return None
    def finding_timeline(self, query):
        self._check()
        return SimpleNamespace(summary=SimpleNamespace(
            finding_id=query.finding_id, occurrence_count=4,
            first_seen_at="2026-08-01T00:00:00+00:00",
            last_seen_at="2026-08-13T00:00:00+00:00",
            lifecycle_state="ACTIVE", reopened_count=1,
        ))
    def active_references(self, **kwargs): self._check(); return self.references
    def remember_reference(self, **kwargs): self._check(); self.remembered.append(kwargs)
    def recurring_findings(self, query): self._check(); return ()
    def score_trend(self, query): self._check(); return ()
    def decisions_for_scope(self, **kwargs): self._check(); return ()
    def previous_investigation_for_scope(self, **kwargs): self._check(); return None
    def action_history(self, **kwargs): self._check(); return ()
    def latest_report(self, query): self._check(); return None
    def ingest_report(self, request): self._check()
    def close(self): pass


class MemoryIntelligenceIntegrationTests(unittest.TestCase):
    def test_service_protocol_hides_sqlite_and_arbitrary_queries(self):
        with tempfile.TemporaryDirectory() as directory:
            service = SQLiteSecurityMemory.open(Path(directory, "memory.db"))
            try:
                self.assertIsInstance(service, SecurityMemory)
                self.assertFalse(hasattr(service, "connection"))
                self.assertFalse(hasattr(service, "execute"))
            finally:
                service.close()

    def test_memory_briefing_is_grounded_and_does_not_modify_authority(self):
        reports = _reports()
        original = copy.deepcopy(reports[-1])
        context = build_memory_context(
            FakeMemory(), system_id="cwt-test", finding_ids=("finding:exposed",)
        )
        briefing = build_security_briefing(reports[-1], None, None, context)
        self.assertTrue(validate_grounding(briefing.response).valid)
        self.assertEqual(reports[-1], original)
        self.assertEqual(briefing.advisor_context.score, 70)
        finding = briefing.advisor_context.findings[0]
        self.assertEqual((finding.severity, finding.kind.value, finding.assessment_state.value),
                         ("HIGH", "RISK", "CONFIRMED"))
        texts = " ".join(claim.text for section in briefing.response.sections for claim in section.claims)
        self.assertIn("appeared in 4 scan(s)", texts)
        self.assertIn("previously resolved and has reappeared", texts)

    def test_exception_baseline_investigation_and_action_are_context_only(self):
        class ContextMemory(FakeMemory):
            def active_exceptions(self, **kwargs):
                return (SimpleNamespace(
                    exception_id="exception:1",
                    system_id="cwt-test",
                    scope=ListenerScope("tcp", "0.0.0.0", "all interfaces", 8080, "python3"),
                    expires_at="2026-09-01T00:00:00+00:00",
                ),)
            def current_baseline(self, **kwargs):
                if kwargs["baseline_type"] != BaselineType.APPROVED_LISTENERS:
                    return None
                scope = ListenerScope(
                    "tcp", "0.0.0.0", "all interfaces", 8080, "python3"
                )
                return SimpleNamespace(
                    baseline_id="baseline:1",
                    system_id="cwt-test",
                    baseline_type=BaselineType.APPROVED_LISTENERS,
                    entries=(BaselineEntry.for_scope(scope),),
                )
            def previous_investigation_for_finding(self, **kwargs):
                return SimpleNamespace(
                    investigation_id="investigation:1", system_id="cwt-test"
                )
            def action_history(self, **kwargs):
                return (SimpleNamespace(
                    system_id="cwt-test", action_id=kwargs["action_id"],
                    response_id="response:1", response_type=SimpleNamespace(value="COMPLETED"),
                    recorded_at="2026-08-12T12:00:00+00:00",
                ),)

        reports = _reports()
        reports[-1]["findings"][0]["evidence"].extend([
            "Address: 0.0.0.0", "Exposure: all interfaces",
        ])
        before = copy.deepcopy(reports[-1])
        result = IntelligenceOrchestrator(memory=ContextMemory()).handle(
            "Give me my security briefing", reports=reports
        )
        text = " ".join(
            claim.text for section in result.response.sections for claim in section.claims
        )
        self.assertIn("active presentation exception", text)
        self.assertIn("matches an approved baseline", text)
        self.assertIn("examined in investigation", text)
        self.assertIn("recorded as COMPLETED", text)
        self.assertIn("only a deterministic scan can establish remediation", text)
        self.assertEqual(reports[-1], before)
        self.assertEqual(result.briefing.advisor_context.score, 70)
        self.assertTrue(validate_grounding(result.response).valid)

    def test_listener_baseline_requires_full_typed_scope_match(self):
        class BaselineMemory(FakeMemory):
            def current_baseline(self, **kwargs):
                if kwargs["baseline_type"] != BaselineType.APPROVED_LISTENERS:
                    return None
                different = ListenerScope(
                    "tcp", "127.0.0.1", "loopback", 8080, "python3"
                )
                return SimpleNamespace(
                    baseline_id="baseline:different", system_id="cwt-test",
                    baseline_type=BaselineType.APPROVED_LISTENERS,
                    entries=(BaselineEntry.for_scope(different),),
                )

        reports = _reports()
        reports[-1]["findings"][0]["evidence"].extend([
            "Address: 0.0.0.0", "Exposure: all interfaces",
        ])
        advisor = build_advisor_context(reports[-1], None, None)
        context = build_memory_context(
            BaselineMemory(), system_id="cwt-test",
            finding_ids=("finding:exposed",), findings=advisor.findings,
        )
        self.assertIsNone(context.findings[0].approved_baseline_id)
        self.assertFalse(any(item.source_id == "baseline:different"
                             for item in context.evidence))

    def test_memory_failure_falls_back_to_json_briefing_without_leaking_details(self):
        result = IntelligenceOrchestrator(memory=FakeMemory(fail=True)).handle(
            "Give me my security briefing", reports=_reports()
        )
        self.assertEqual(result.state, OrchestratorState.COMPLETED)
        self.assertEqual(result.briefing.advisor_context.score, 70)
        self.assertIn("memory context is unavailable", result.response.notice)
        self.assertNotIn("/secret", result.response.notice)
        self.assertNotIn("canary", result.response.notice)

    def test_memory_failure_keeps_supported_question_available(self):
        result = IntelligenceOrchestrator(memory=FakeMemory(fail=True)).handle(
            "What should I fix first?", reports=_reports()
        )
        self.assertEqual(result.state, OrchestratorState.COMPLETED)
        self.assertTrue(result.response.action_ids)
        self.assertIn("memory context is unavailable", result.response.notice)

    def test_unique_persisted_reference_is_candidate_after_session_state(self):
        reference = SimpleNamespace(
            target_id="finding:exposed", system_id="cwt-test",
            reference_type=ReferenceType.FINDING,
            reference_state=ReferenceState.FOCUSED,
        )
        session = ConversationSession(session_id="session:known")
        result = IntelligenceOrchestrator(memory=FakeMemory(references=(reference,))).handle(
            "Why is it dangerous?", reports=_reports(), session=session
        )
        self.assertEqual(result.state, OrchestratorState.COMPLETED)
        self.assertEqual(result.response.finding_ids, ("finding:exposed",))

    def test_successful_focus_persists_only_structured_reference(self):
        memory = FakeMemory()
        session = ConversationSession(session_id="session:known")
        IntelligenceOrchestrator(memory=memory).handle(
            "What should I fix first?", reports=_reports(), session=session
        )
        self.assertEqual(len(memory.remembered), 1)
        stored = memory.remembered[0]
        self.assertEqual(stored["system_id"], "cwt-test")
        self.assertEqual(stored["target_id"], "finding:exposed")
        self.assertEqual(stored["reference_type"], ReferenceType.FINDING)
        self.assertNotIn("question", stored)
        self.assertNotIn("transcript", stored)

    def test_ambiguous_or_cross_system_persisted_references_do_not_resolve(self):
        reports = _reports()
        second = copy.deepcopy(reports[-1]["findings"][0])
        second.update({"finding_id": "finding:second", "title": "Second exposed service"})
        reports[-1]["findings"].append(second)
        references = (
            SimpleNamespace(target_id="finding:exposed", system_id="other", reference_type=ReferenceType.FINDING),
            SimpleNamespace(target_id="finding:exposed", system_id="cwt-test", reference_type=ReferenceType.FINDING),
            SimpleNamespace(target_id="finding:second", system_id="cwt-test", reference_type=ReferenceType.FINDING),
        )
        result = IntelligenceOrchestrator(memory=FakeMemory(references=references)).handle(
            "Why is it dangerous?", reports=reports,
            session=ConversationSession(session_id="session:known"),
        )
        self.assertEqual(result.state, OrchestratorState.CLARIFICATION_REQUIRED)

    def test_memory_capabilities_are_read_only_typed_and_host_bound(self):
        memory = FakeMemory()
        registry = build_read_only_registry(memory)
        definition = registry.definition("memory.get_finding_timeline")
        self.assertEqual(definition.permission, PermissionClass.READ_ONLY)
        context = CapabilityContext(memory=memory, system_id="cwt-test")
        timeline = registry.execute(CapabilityRequest(
            "memory.get_finding_timeline",
            {"system_id": "cwt-test", "finding_id": "finding:exposed"},
        ), context)
        self.assertEqual(timeline.summary.occurrence_count, 4)
        with self.assertRaises(CapabilityDenied):
            registry.execute(CapabilityRequest(
                "memory.get_finding_timeline",
                {"system_id": "other", "finding_id": "finding:exposed"},
            ), context)
        with self.assertRaises(CapabilityDenied):
            registry.execute(CapabilityRequest(
                "memory.get_finding_timeline",
                {"system_id": "cwt-test", "finding_id": "finding:exposed", "sql": "SELECT *"},
            ), context)

    def test_provider_request_is_unchanged_and_contains_no_memory_private_fields(self):
        context = build_advisor_context(_reports()[-1], None, None)
        request = build_provider_request(context, generate_advisory(context))
        payload = repr(request)
        for forbidden in ("database_path", "report_path", "raw argv", "stdout", "stderr", "token=", "rationale"):
            self.assertNotIn(forbidden, payload)
        self.assertNotIn("cwt-test", payload)

    def test_classified_open_failures_are_concise_and_do_not_repair_database(self):
        failures = (
            MemoryUnavailable("missing"), MemoryLocked("locked"),
            MemoryCorrupt("corrupt"), MemoryMigrationFailed("migration"),
            MemoryIncompatibleVersion("newer"),
        )
        for failure in failures:
            with self.subTest(type=type(failure).__name__), patch(
                "cyberwatchtower.memory.service.SQLiteSecurityMemory.open",
                side_effect=failure,
            ):
                notice = _ingest_saved_report(Path("saved-report.json"), "memory.db")
                self.assertEqual(
                    notice,
                    "Persistent memory is unavailable; deterministic operation continues.",
                )
                self.assertNotIn(str(failure), notice)

    def test_malformed_memory_result_fails_closed(self):
        memory = FakeMemory()
        memory.finding_timeline = Mock(return_value=SimpleNamespace(
            summary=SimpleNamespace(finding_id="other", occurrence_count=999)
        ))
        context = build_memory_context(
            memory, system_id="cwt-test", finding_ids=("finding:exposed",)
        )
        self.assertFalse(context.findings)
        self.assertIn("unavailable", context.limitation)

    def test_post_save_ingestion_failure_is_concise_and_never_raises(self):
        memory = FakeMemory(fail=True)
        with patch("cyberwatchtower.cli._open_optional_memory", return_value=(memory, None)):
            notice = _ingest_saved_report(Path("saved-report.json"), "memory.db")
        self.assertIn("saved JSON report remains complete", notice)
        self.assertNotIn("canary", notice)

    def test_post_save_duplicate_is_success(self):
        memory = Mock()
        memory.ingest_report.return_value = SimpleNamespace(status=IngestionStatus.DUPLICATE)
        with patch("cyberwatchtower.cli._open_optional_memory", return_value=(memory, None)):
            notice = _ingest_saved_report(Path("saved-report.json"), "memory.db")
        self.assertIsNone(notice)
        memory.close.assert_called_once()

    def test_scan_display_and_json_save_survive_ingestion_failure_in_order(self):
        events = []
        results = {
            "system": {"hostname": "host", "system_id": "cwt-test"},
            "findings": [],
            "score": {"score": 100, "risk_level": "LOW", "counts": {
                "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
            }},
        }
        current = _reports()[0]
        memory = FakeMemory(fail=True)
        output = io.StringIO()

        def scan(): events.append("scan"); return results
        def save(_): events.append("save"); return Path("reports/saved.json")
        def open_memory(_): events.append("ingest"); return memory, None

        with (
            patch("cyberwatchtower.cli.run_scan", side_effect=scan),
            patch("cyberwatchtower.cli.save_json_report", side_effect=save),
            patch("cyberwatchtower.cli._open_optional_memory", side_effect=open_memory),
            patch("cyberwatchtower.cli.load_reports", return_value=[current]),
            patch("cyberwatchtower.cli._display_advisor"),
            redirect_stdout(output),
        ):
            main(["--memory-db", "memory.db"])
        self.assertEqual(events, ["scan", "save", "ingest"])
        self.assertIn("Score: 100/100", output.getvalue())
        self.assertIn(
            f"Saved to: {Path('reports') / 'saved.json'}",
            output.getvalue(),
        )
        self.assertIn("saved JSON report remains complete", output.getvalue())
        self.assertIn("scan complete", output.getvalue())
        self.assertNotIn("memory.db", output.getvalue())

    def test_environment_memory_path_is_not_exposed_on_open_failure(self):
        private_path = "/private/cyberwatchtower/operator-memory.db"
        with (
            patch.dict(os.environ, {"CYBERWATCHTOWER_MEMORY_DB": private_path}),
            patch(
                "cyberwatchtower.memory.service.SQLiteSecurityMemory.open",
                side_effect=MemoryCorrupt(f"corrupt database at {private_path}"),
            ),
        ):
            notice = _ingest_saved_report(Path("reports/saved.json"))
        self.assertEqual(
            notice,
            "Persistent memory is unavailable; deterministic operation continues.",
        )
        self.assertNotIn(private_path, notice)
        self.assertNotIn("operator-memory.db", notice)


if __name__ == "__main__":
    unittest.main()
