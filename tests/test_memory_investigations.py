import hashlib
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cyberwatchtower.capabilities.registry import PermissionClass
from cyberwatchtower.core.evidence import EpistemicRole
from cyberwatchtower.memory import open_memory_database
from cyberwatchtower.memory.decision_models import (
    ActionResponseType, ApplicationScope, DecisionType, FindingScope, ServiceScope,
)
from cyberwatchtower.memory.decisions import (
    create_decision, record_action_response, record_recommendation_shown,
)
from cyberwatchtower.memory.errors import MemoryInvestigationError, MemoryMigrationFailed
from cyberwatchtower.memory.ingestion import ingest_report
from cyberwatchtower.memory.ingestion_models import IngestionStatus, ReportIngestionRequest
from cyberwatchtower.memory.investigation_models import (
    CapabilityExecutionStatus, EvidenceType, InvestigationDisposition,
    InvestigationIntent, InvestigationStatus, ReferenceState, ReferenceType, SubjectType,
)
from cyberwatchtower.memory.investigations import (
    active_conversation_references, attach_related_finding, attach_subject_finding,
    attach_subject_scope, cancel_investigation, capability_history,
    complete_investigation, create_conversation_reference, create_investigation,
    evidence_for_investigation, investigation_by_id, investigation_timeline,
    latest_completed_for_finding, latest_completed_for_scope, open_investigations,
    link_recommendation, pause_investigation, record_capability_outcome, record_capability_proposal,
    record_evidence_consulted, record_question, resume_investigation,
)
from cyberwatchtower.memory.migrations import discover_migrations
from cyberwatchtower.memory.models import CURRENT_MEMORY_SCHEMA_VERSION


UTC = timezone.utc
T0 = datetime(2026, 8, 1, tzinfo=UTC)


def report(system_id):
    return {
        "schema_version": "1.1", "generated_at": T0.isoformat(),
        "system": {"system_id": system_id, "hostname": "shared"},
        "coverage": {"firewall_technology": "COMPLETE", "iptables_input_policy": "UNKNOWN",
                     "network_socket_inspection": "COMPLETE"},
        "security_score": {"score": 90, "risk_level": "LOW", "counts": {"LOW": 1}},
        "findings": [{"finding_id": "finding:service", "title": "Exposed service",
            "description": "A listener is exposed.", "severity": "LOW",
            "recommendation": "Restrict it.", "evidence": ["Port: 8080"],
            "confidence": 90, "technique_id": None, "source": "network",
            "kind": "RISK", "assessment_state": "CONFIRMED"}],
    }


class InvestigationSupport:
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.database = open_memory_database(Path(self.temporary.name, "memory.db"))
        self.report_ids = {}
        self.add_system("system-a")

    def tearDown(self):
        self.database.close()
        self.temporary.cleanup()

    def add_system(self, system_id):
        path = Path(self.temporary.name, f"{system_id}.json")
        path.write_text(json.dumps(report(system_id)), encoding="utf-8")
        result = ingest_report(self.database, ReportIngestionRequest(path))
        self.assertEqual(result.status, IngestionStatus.INGESTED)
        self.report_ids[system_id] = result.report_id

    def investigation(self, system_id="system-a", title="Review exposed service"):
        return create_investigation(
            self.database, system_id=system_id, title=title,
            actor="analyst", opened_at=T0)


class InvestigationLifecycleTests(InvestigationSupport, unittest.TestCase):
    def test_creation_pause_resume_completion_and_queries(self):
        item = self.investigation()
        self.assertEqual(item.status, InvestigationStatus.OPEN)
        self.assertEqual(len(open_investigations(self.database, system_id="system-a")), 1)
        self.assertEqual(pause_investigation(
            self.database, system_id="system-a",
            investigation_id=item.investigation_id).status, InvestigationStatus.PAUSED)
        resume_investigation(self.database, system_id="system-a",
                             investigation_id=item.investigation_id)
        completed = complete_investigation(
            self.database, system_id="system-a", investigation_id=item.investigation_id,
            closed_at=T0 + timedelta(hours=2),
            disposition=InvestigationDisposition.INCONCLUSIVE)
        self.assertEqual(completed.status, InvestigationStatus.COMPLETED)
        self.assertEqual(open_investigations(self.database, system_id="system-a"), ())
        self.assertEqual(investigation_by_id(
            self.database, system_id="system-a",
            investigation_id=item.investigation_id).final_disposition,
            InvestigationDisposition.INCONCLUSIVE)

    def test_cancellation_is_auditable(self):
        item = self.investigation()
        cancelled = cancel_investigation(
            self.database, system_id="system-a", investigation_id=item.investigation_id,
            closed_at=T0 + timedelta(hours=1))
        self.assertEqual((cancelled.status, cancelled.final_disposition),
                         (InvestigationStatus.CANCELLED, InvestigationDisposition.CANCELLED))

    def test_finding_relationships_isolation_and_previous_lookup(self):
        item = self.investigation()
        attach_subject_finding(
            self.database, system_id="system-a", investigation_id=item.investigation_id,
            finding_id="finding:service", attached_at=T0 + timedelta(minutes=1))
        attach_related_finding(
            self.database, system_id="system-a", investigation_id=item.investigation_id,
            finding_id="finding:service", attached_at=T0 + timedelta(minutes=2))
        complete_investigation(
            self.database, system_id="system-a", investigation_id=item.investigation_id,
            closed_at=T0 + timedelta(hours=1), disposition=InvestigationDisposition.NO_ACTION)
        self.assertEqual(latest_completed_for_finding(
            self.database, system_id="system-a",
            finding_id="finding:service").investigation_id, item.investigation_id)
        self.add_system("system-b")
        other = self.investigation("system-b")
        with self.assertRaises(MemoryInvestigationError):
            attach_subject_finding(
                self.database, system_id="system-b", investigation_id=other.investigation_id,
                finding_id="finding:missing", attached_at=T0)

    def test_service_scope_previous_lookup_and_timeline_order(self):
        item = self.investigation()
        scope = ServiceScope("HTTP", "tcp", 8080)
        attach_subject_scope(
            self.database, system_id="system-a", investigation_id=item.investigation_id,
            scope=scope, attached_at=T0 + timedelta(minutes=1))
        record_question(
            self.database, system_id="system-a", investigation_id=item.investigation_id,
            intent=InvestigationIntent.INVESTIGATE_SERVICE,
            subject_type=SubjectType.SERVICE, subject_id=scope.digest(),
            recorded_at=T0 + timedelta(minutes=2))
        complete_investigation(
            self.database, system_id="system-a", investigation_id=item.investigation_id,
            closed_at=T0 + timedelta(hours=1), disposition=InvestigationDisposition.NO_ACTION)
        self.assertEqual(latest_completed_for_scope(
            self.database, system_id="system-a", scope=scope).investigation_id,
            item.investigation_id)
        timeline = investigation_timeline(
            self.database, system_id="system-a", investigation_id=item.investigation_id)
        self.assertEqual([entry.occurred_at for entry in timeline.entries],
                         sorted(entry.occurred_at for entry in timeline.entries))

    def test_normalized_question_has_no_raw_prose_column(self):
        item = self.investigation()
        record = record_question(
            self.database, system_id="system-a", investigation_id=item.investigation_id,
            intent=InvestigationIntent.WHY_DANGEROUS, subject_type=SubjectType.FINDING,
            subject_id="finding:service", recorded_at=T0)
        columns = {row[1] for row in self.database.connection.execute(
            "PRAGMA table_info(investigation_questions)")}
        self.assertNotIn("question", columns)
        self.assertEqual(record.intent, InvestigationIntent.WHY_DANGEROUS)

    def test_unsafe_title_and_actor_are_rejected(self):
        for title, actor in (("token=secret", "analyst"),
                             ("Review service", "$ cat /etc/passwd"),
                             ("bad\x00title", "analyst")):
            with self.assertRaises(MemoryInvestigationError):
                create_investigation(
                    self.database, system_id="system-a", title=title,
                    actor=actor, opened_at=T0)


class CapabilityAuditTests(InvestigationSupport, unittest.TestCase):
    def test_proposal_approval_required_denied_failed_and_no_false_evidence(self):
        item = self.investigation()
        approval_required = record_capability_proposal(
            self.database, system_id="system-a", investigation_id=item.investigation_id,
            capability_id="scan_host", permission_class=PermissionClass.USER_APPROVAL_REQUIRED,
            requested_at=T0, parameter_summary={"system_id": "system-a"})
        self.assertEqual(approval_required.status, CapabilityExecutionStatus.APPROVAL_REQUIRED)
        denied = record_capability_proposal(
            self.database, system_id="system-a", investigation_id=item.investigation_id,
            capability_id="scan_host", permission_class=PermissionClass.PROHIBITED,
            requested_at=T0 + timedelta(minutes=1), parameter_summary={"system_id": "system-a"})
        self.assertEqual(denied.status, CapabilityExecutionStatus.DENIED)
        with self.assertRaises(MemoryInvestigationError):
            record_evidence_consulted(
                self.database, system_id="system-a", investigation_id=item.investigation_id,
                evidence_id="evidence:denied", evidence_type=EvidenceType.CAPABILITY_RESULT,
                source_record_id=denied.execution_id,
                epistemic_role=EpistemicRole.DETERMINISTIC_DERIVATION,
                consulted_at=T0 + timedelta(minutes=2))
        failed_proposal = record_capability_proposal(
            self.database, system_id="system-a", investigation_id=item.investigation_id,
            capability_id="inspect_service", permission_class=PermissionClass.READ_ONLY,
            requested_at=T0 + timedelta(minutes=2),
            parameter_summary={"protocol": "tcp", "address": "0.0.0.0", "port": 8080,
                               "application": "/usr/bin/app"})
        failed = record_capability_outcome(
            self.database, system_id="system-a", execution_id=failed_proposal.execution_id,
            status=CapabilityExecutionStatus.FAILED, started_at=T0 + timedelta(minutes=3),
            completed_at=T0 + timedelta(minutes=4), error_code="INSPECTION_FAILED")
        self.assertEqual(failed.status, CapabilityExecutionStatus.FAILED)
        with self.assertRaises(MemoryInvestigationError):
            record_evidence_consulted(
                self.database, system_id="system-a", investigation_id=item.investigation_id,
                evidence_id="evidence:failed", evidence_type=EvidenceType.CAPABILITY_RESULT,
                source_record_id=failed.execution_id,
                epistemic_role=EpistemicRole.DETERMINISTIC_DERIVATION,
                consulted_at=T0 + timedelta(minutes=5))

    def test_success_requires_valid_same_system_user_approval(self):
        item = self.investigation()
        proposal = record_capability_proposal(
            self.database, system_id="system-a", investigation_id=item.investigation_id,
            capability_id="scan_host", permission_class=PermissionClass.USER_APPROVAL_REQUIRED,
            requested_at=T0 + timedelta(minutes=1), parameter_summary={"system_id": "system-a"})
        with self.assertRaises(MemoryInvestigationError):
            record_capability_outcome(
                self.database, system_id="system-a", execution_id=proposal.execution_id,
                status=CapabilityExecutionStatus.SUCCEEDED,
                started_at=T0 + timedelta(minutes=2), completed_at=T0 + timedelta(minutes=3),
                result_summary={"report_id": self.report_ids["system-a"]})
        expired = create_decision(
            self.database, system_id="system-a", decision_type=DecisionType.CUSTOM,
            scope=ApplicationScope("capability:scan_host"), actor="owner",
            effective_at=T0, expires_at=T0 + timedelta(seconds=30))
        with self.assertRaises(MemoryInvestigationError):
            record_capability_outcome(
                self.database, system_id="system-a", execution_id=proposal.execution_id,
                status=CapabilityExecutionStatus.SUCCEEDED,
                authorization_decision_id=expired.decision_id,
                started_at=T0 + timedelta(minutes=2), completed_at=T0 + timedelta(minutes=3),
                result_summary={"report_id": self.report_ids["system-a"]})
        unrelated = create_decision(
            self.database, system_id="system-a", decision_type=DecisionType.REVIEWED,
            scope=FindingScope("finding:service"), actor="owner", effective_at=T0)
        with self.assertRaises(MemoryInvestigationError):
            record_capability_outcome(
                self.database, system_id="system-a", execution_id=proposal.execution_id,
                status=CapabilityExecutionStatus.SUCCEEDED,
                authorization_decision_id=unrelated.decision_id,
                started_at=T0 + timedelta(minutes=2), completed_at=T0 + timedelta(minutes=3),
                result_summary={"report_id": self.report_ids["system-a"]})
        approval = create_decision(
            self.database, system_id="system-a", decision_type=DecisionType.CUSTOM,
            scope=ApplicationScope("capability:scan_host"), actor="owner", effective_at=T0)
        succeeded = record_capability_outcome(
            self.database, system_id="system-a", execution_id=proposal.execution_id,
            status=CapabilityExecutionStatus.SUCCEEDED,
            authorization_decision_id=approval.decision_id,
            started_at=T0 + timedelta(minutes=2), completed_at=T0 + timedelta(minutes=3),
            result_summary={"report_id": self.report_ids["system-a"]})
        self.assertEqual(succeeded.status, CapabilityExecutionStatus.SUCCEEDED)
        evidence = record_evidence_consulted(
            self.database, system_id="system-a", investigation_id=item.investigation_id,
            evidence_id="evidence:success", evidence_type=EvidenceType.CAPABILITY_RESULT,
            source_record_id=succeeded.execution_id,
            epistemic_role=EpistemicRole.DETERMINISTIC_DERIVATION,
            consulted_at=T0 + timedelta(minutes=4))
        self.assertEqual(evidence.source_record_id, succeeded.execution_id)
        self.assertEqual(len(capability_history(
            self.database, system_id="system-a", investigation_id=item.investigation_id)), 1)

    def test_cross_system_approval_and_unsafe_summaries_are_rejected(self):
        self.add_system("system-b")
        approval = create_decision(
            self.database, system_id="system-b", decision_type=DecisionType.CUSTOM,
            scope=ApplicationScope("capability:scan_host"), actor="owner", effective_at=T0)
        proposal = record_capability_proposal(
            self.database, system_id="system-a", capability_id="scan_host",
            permission_class=PermissionClass.USER_APPROVAL_REQUIRED, requested_at=T0,
            parameter_summary={"system_id": "system-a"})
        with self.assertRaises(MemoryInvestigationError):
            record_capability_outcome(
                self.database, system_id="system-a", execution_id=proposal.execution_id,
                status=CapabilityExecutionStatus.SUCCEEDED,
                authorization_decision_id=approval.decision_id, started_at=T0,
                completed_at=T0 + timedelta(minutes=1),
                result_summary={"report_id": self.report_ids["system-a"]})
        canaries = (
            {"system_id": "token=secret-canary"},
            {"system_id": "$ cat /etc/passwd"},
            {"raw_command": "scan"},
        )
        for summary in canaries:
            with self.assertRaises(MemoryInvestigationError):
                record_capability_proposal(
                    self.database, system_id="system-a", capability_id="scan_host",
                    permission_class=PermissionClass.READ_ONLY, requested_at=T0,
                    parameter_summary=summary)
        result_proposal = record_capability_proposal(
            self.database, system_id="system-a", capability_id="scan_host",
            permission_class=PermissionClass.READ_ONLY, requested_at=T0,
            parameter_summary={"system_id": "system-a"})
        with self.assertRaises(MemoryInvestigationError):
            record_capability_outcome(
                self.database, system_id="system-a",
                execution_id=result_proposal.execution_id,
                status=CapabilityExecutionStatus.SUCCEEDED, started_at=T0,
                completed_at=T0 + timedelta(minutes=1),
                result_summary={"report_id": "token=secret-canary"})
        durable = " ".join(str(value) for row in self.database.connection.execute(
            "SELECT parameter_summary_json,result_summary_json FROM capability_executions")
                           for value in row if value)
        self.assertNotIn("secret-canary", durable)
        self.assertNotIn("/etc/passwd", durable)


class EvidenceReferenceAuthorityTests(InvestigationSupport, unittest.TestCase):
    def authoritative_snapshot(self):
        return {table: tuple(tuple(row) for row in self.database.connection.execute(
            f"SELECT * FROM {table} ORDER BY 1")) for table in
            ("score_history", "finding_occurrences", "findings", "finding_lifecycle_events")}

    def test_evidence_recommendation_reference_and_authority_invariant(self):
        before = self.authoritative_snapshot()
        item = self.investigation()
        attach_subject_finding(
            self.database, system_id="system-a", investigation_id=item.investigation_id,
            finding_id="finding:service", attached_at=T0)
        record_evidence_consulted(
            self.database, system_id="system-a", investigation_id=item.investigation_id,
            evidence_id="evidence:report", evidence_type=EvidenceType.REPORT,
            source_record_id=self.report_ids["system-a"],
            epistemic_role=EpistemicRole.OBSERVED_FACT, consulted_at=T0)
        recommendation = record_recommendation_shown(
            self.database, system_id="system-a", action_id="action:review",
            trusted_text_hash=hashlib.sha256(b"review").hexdigest(), shown_at=T0)
        link_recommendation(
            self.database, system_id="system-a", investigation_id=item.investigation_id,
            recommendation_event_id=recommendation.recommendation_event_id, linked_at=T0)
        record_action_response(
            self.database, system_id="system-a",
            recommendation_event_id=recommendation.recommendation_event_id,
            action_id="action:review", response_type=ActionResponseType.DEFERRED,
            actor="owner", recorded_at=T0, defer_until=T0 + timedelta(days=1))
        proposal = record_capability_proposal(
            self.database, system_id="system-a", investigation_id=item.investigation_id,
            capability_id="explain_finding", permission_class=PermissionClass.READ_ONLY,
            requested_at=T0, parameter_summary={"finding_id": "finding:service"})
        record_capability_outcome(
            self.database, system_id="system-a", execution_id=proposal.execution_id,
            status=CapabilityExecutionStatus.SUCCEEDED, started_at=T0,
            completed_at=T0 + timedelta(minutes=1),
            result_summary={"finding_id": "finding:service"})
        create_conversation_reference(
            self.database, system_id="system-a", session_id="session:1",
            reference_type=ReferenceType.FINDING, target_id="finding:service",
            reference_state=ReferenceState.FOCUSED, created_at=T0,
            expires_at=T0 + timedelta(hours=1))
        complete_investigation(
            self.database, system_id="system-a", investigation_id=item.investigation_id,
            closed_at=T0 + timedelta(hours=2), disposition=InvestigationDisposition.NO_ACTION)
        self.assertEqual(before, self.authoritative_snapshot())
        self.assertEqual(len(evidence_for_investigation(
            self.database, system_id="system-a", investigation_id=item.investigation_id)), 1)
        self.assertIsNotNone(recommendation.recommendation_event_id)

    def test_reference_expiry_isolation_and_no_transcript_table(self):
        self.add_system("system-b")
        other = self.investigation("system-b")
        with self.assertRaises(MemoryInvestigationError):
            record_evidence_consulted(
                self.database, system_id="system-b", investigation_id=other.investigation_id,
                evidence_id="evidence:cross-system", evidence_type=EvidenceType.REPORT,
                source_record_id=self.report_ids["system-a"],
                epistemic_role=EpistemicRole.OBSERVED_FACT, consulted_at=T0)
        with self.assertRaises(MemoryInvestigationError):
            create_conversation_reference(
                self.database, system_id="system-b", session_id="session:cross",
                reference_type=ReferenceType.REPORT,
                target_id=self.report_ids["system-a"],
                reference_state=ReferenceState.FOCUSED, created_at=T0,
                expires_at=T0 + timedelta(hours=1))
        create_conversation_reference(
            self.database, system_id="system-a", session_id="session:1",
            reference_type=ReferenceType.FINDING, target_id="finding:service",
            reference_state=ReferenceState.RECENTLY_MENTIONED, created_at=T0,
            expires_at=T0 + timedelta(hours=1))
        self.assertEqual(len(active_conversation_references(
            self.database, system_id="system-a", session_id="session:1",
            at=T0 + timedelta(minutes=30))), 1)
        self.assertEqual(active_conversation_references(
            self.database, system_id="system-a", session_id="session:1",
            at=T0 + timedelta(hours=1)), ())
        self.assertEqual(active_conversation_references(
            self.database, system_id="system-b", session_id="session:1", at=T0), ())
        tables = {row[0] for row in self.database.connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertNotIn("conversation_transcripts", tables)


class InvestigationMigrationTests(unittest.TestCase):
    def test_schema_four_migrates_without_rewriting_existing_records(self):
        migrations = discover_migrations()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "memory.db")
            connection = sqlite3.connect(path)
            for migration in migrations[:4]:
                connection.executescript(migration.sql)
            connection.execute("""CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,name TEXT NOT NULL,checksum TEXT NOT NULL,
                applied_at TEXT NOT NULL,application_version TEXT NOT NULL)""")
            for migration in migrations[:4]:
                connection.execute("INSERT INTO schema_migrations VALUES (?,?,?,'then','memory-v0.2')",
                                   (migration.version,migration.name,migration.checksum))
            connection.execute("INSERT INTO systems VALUES (?,?,?,?,?,?,?,?,?)",
                               ("preserved","host","then","then",1,"STABLE",
                                "DETERMINISTIC_OBSERVATION","then","then"))
            connection.execute("PRAGMA user_version=4")
            connection.commit(); connection.close()
            with open_memory_database(path) as database:
                version = database.connection.execute("PRAGMA user_version").fetchone()[0]
                retained = database.connection.execute("SELECT system_id FROM systems").fetchone()[0]
        self.assertEqual((version,retained),(CURRENT_MEMORY_SCHEMA_VERSION,"preserved"))

    def test_migration_five_failure_rolls_back(self):
        migrations = discover_migrations()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory,"migrations"); root.mkdir()
            for migration in migrations[:4]:
                Path(root,f"{migration.version:04d}_{migration.name}.sql").write_text(
                    migration.sql,encoding="utf-8")
            Path(root,"0005_broken.sql").write_text(
                "CREATE TABLE partial_m5(value TEXT);\nNOT SQL;\n",encoding="utf-8")
            Path(root,"0006_placeholder.sql").write_text(
                "CREATE TABLE never_reached_m6(value TEXT);\n",encoding="utf-8")
            path = Path(directory,"memory.db")
            with self.assertRaises(MemoryMigrationFailed):
                open_memory_database(path,migration_directory=root)
            connection=sqlite3.connect(path)
            version=connection.execute("PRAGMA user_version").fetchone()[0]
            tables={row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}; connection.close()
        self.assertEqual(version,4)
        self.assertNotIn("partial_m5",tables)
