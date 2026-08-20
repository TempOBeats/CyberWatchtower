import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from cyberwatchtower.memory import open_memory_database, rebuild_system_lifecycle
from cyberwatchtower.memory.errors import MemoryLifecycleError, MemoryQueryError
from cyberwatchtower.memory.history_models import (
    FindingHistoryQuery, RecurringFindingsQuery, ScoreTrendQuery, SystemHistoryQuery,
)
from cyberwatchtower.memory.ingestion import ingest_report
from cyberwatchtower.memory.ingestion_models import IngestionStatus, ReportIngestionRequest
from cyberwatchtower.memory.queries import (
    finding_timeline, latest_report_summary, recurring_findings, score_trend,
)
from cyberwatchtower.report_contracts import LegacyLinkPolicy


def report(system_id, timestamp, *, hostname="shared", findings=None, network="COMPLETE", score=90):
    return {
        "schema_version": "1.1", "generated_at": timestamp,
        "system": {"system_id": system_id, "hostname": hostname},
        "coverage": {"firewall_technology": "COMPLETE", "iptables_input_policy": "UNKNOWN",
                     "network_socket_inspection": network},
        "security_score": {"score": score, "risk_level": "LOW", "counts": {"LOW": len(findings or [])}},
        "findings": findings or [],
    }


def finding(**changes):
    value = {
        "finding_id": "finding:service", "title": "Exposed service",
        "description": "A listener is exposed.", "severity": "LOW",
        "recommendation": "Restrict the listener.", "evidence": ["Port: 8080"],
        "confidence": 90, "technique_id": None, "source": "network",
        "kind": "RISK", "assessment_state": "CONFIRMED",
    }
    value.update(changes)
    return value


class MemoryTestSupport:
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.database = open_memory_database(Path(self.temporary.name, "memory.db"))
        self.number = 0

    def tearDown(self):
        self.database.close()
        self.temporary.cleanup()

    def ingest(self, value):
        self.number += 1
        path = Path(self.temporary.name, f"report-{self.number}.json")
        path.write_text(json.dumps(value), encoding="utf-8")
        result = ingest_report(self.database, ReportIngestionRequest(path))
        self.assertEqual(result.status, IngestionStatus.INGESTED)
        return result

    def timeline(self, system="system-a"):
        return finding_timeline(self.database, FindingHistoryQuery(system, "finding:service"))


class MemoryLifecycleTests(MemoryTestSupport, unittest.TestCase):

    def test_first_seen_consecutive_seen_and_recurrence(self):
        self.ingest(report("system-a", "2026-08-01T00:00:00+00:00", findings=[finding()]))
        first = self.timeline()
        self.assertEqual((first.summary.first_seen_at, first.summary.last_seen_at),
                         ("2026-08-01T00:00:00+00:00",) * 2)
        self.assertEqual([event.event_type for event in first.events], ["FIRST_SEEN"])
        self.ingest(report("system-a", "2026-08-02T00:00:00+00:00", findings=[finding()]))
        timeline = self.timeline()
        self.assertEqual(timeline.summary.occurrence_count, 2)
        self.assertTrue(timeline.summary.recurring)
        self.assertEqual([event.event_type for event in timeline.events], ["FIRST_SEEN", "SEEN"])
        self.assertEqual(len(recurring_findings(self.database, RecurringFindingsQuery("system-a"))), 1)
        immutable_id = self.database.connection.execute(
            "SELECT stable_finding_id FROM finding_occurrences LIMIT 1").fetchone()[0]
        self.assertEqual(immutable_id, "finding:service")

    def test_complete_absence_resolves_and_reappearance_reopens(self):
        first = self.ingest(report("system-a", "2026-08-01T00:00:00+00:00", findings=[finding()]))
        resolved = self.ingest(report("system-a", "2026-08-02T00:00:00+00:00"))
        timeline = self.timeline()
        self.assertEqual(timeline.summary.lifecycle_state, "RESOLVED")
        self.assertEqual(timeline.summary.last_resolved_at, "2026-08-02T00:00:00+00:00")
        self.assertEqual(timeline.events[-1].event_type, "RESOLVED")
        self.assertEqual(timeline.events[-1].report_id, resolved.report_id)
        self.ingest(report("system-a", "2026-08-03T00:00:00+00:00", findings=[finding()]))
        timeline = self.timeline()
        self.assertEqual(timeline.summary.lifecycle_state, "ACTIVE")
        self.assertEqual(timeline.summary.reopened_count, 1)
        self.assertEqual(len(timeline.reopened_history), 1)
        self.assertEqual(timeline.events[0].report_id, first.report_id)

    def test_incomplete_and_unknown_absence_are_uncertain_and_not_reopens(self):
        for coverage in ("INCOMPLETE", "UNKNOWN"):
            system = f"system-{coverage.lower()}"
            self.ingest(report(system, "2026-08-01T00:00:00+00:00", findings=[finding()]))
            self.ingest(report(system, "2026-08-02T00:00:00+00:00", network=coverage))
            timeline = self.timeline(system)
            self.assertEqual(timeline.summary.lifecycle_state, "RESOLUTION_UNCERTAIN")
            self.assertNotIn("RESOLVED", [event.event_type for event in timeline.events])
            self.ingest(report(system, "2026-08-03T00:00:00+00:00", findings=[finding()]))
            timeline = self.timeline(system)
            self.assertEqual(timeline.summary.reopened_count, 0)
            self.assertEqual(timeline.events[-1].event_type, "SEEN")

    def test_firewall_source_requires_both_explicit_coverage_domains(self):
        firewall = finding(source="firewall")
        self.ingest(report("system-a", "2026-08-01T00:00:00+00:00", findings=[firewall]))
        uncertain = report("system-a", "2026-08-02T00:00:00+00:00")
        self.ingest(uncertain)
        self.assertEqual(self.timeline().summary.lifecycle_state, "RESOLUTION_UNCERTAIN")
        complete = report("system-a", "2026-08-03T00:00:00+00:00")
        complete["coverage"]["iptables_input_policy"] = "COMPLETE"
        self.ingest(complete)
        self.assertEqual(self.timeline().summary.lifecycle_state, "RESOLVED")

    def test_neutral_firewall_source_uses_explicit_inbound_domain(self):
        inbound = finding(source="firewall_inbound_policy")
        first = report(
            "system-a", "2026-08-01T00:00:00+00:00", findings=[inbound]
        )
        first.update({
            "schema_version": "1.2",
            "assessment_domains": ["firewall_inbound_policy"],
            "coverage": {"firewall_inbound_policy": "COMPLETE"},
        })
        self.ingest(first)
        for index, coverage in enumerate(("INCOMPLETE", "UNKNOWN"), start=2):
            missing = report("system-a", f"2026-08-0{index}T00:00:00+00:00")
            missing.update({
                "schema_version": "1.2",
                "assessment_domains": ["firewall_inbound_policy"],
                "coverage": {"firewall_inbound_policy": coverage},
            })
            self.ingest(missing)
            self.assertEqual(
                self.timeline().summary.lifecycle_state, "RESOLUTION_UNCERTAIN"
            )
        complete = report("system-a", "2026-08-04T00:00:00+00:00")
        complete.update({
            "schema_version": "1.2",
            "assessment_domains": ["firewall_inbound_policy"],
            "coverage": {"firewall_inbound_policy": "COMPLETE"},
        })
        self.ingest(complete)
        self.assertEqual(self.timeline().summary.lifecycle_state, "RESOLVED")

    def test_attribute_change_events_preserve_values_and_legacy_uncertainty(self):
        self.ingest(report("system-a", "2026-08-01T00:00:00+00:00", findings=[finding()]))
        changed = finding(severity="HIGH", kind="COVERAGE_GAP", assessment_state="INCOMPLETE")
        result = self.ingest(report("system-a", "2026-08-02T00:00:00+00:00", findings=[changed]))
        timeline = self.timeline()
        self.assertEqual([event.event_type for event in timeline.events[-3:]],
                         ["SEVERITY_CHANGED", "ASSESSMENT_STATE_CHANGED", "KIND_CHANGED"])
        self.assertEqual((timeline.severity_changes[0].previous_value,
                          timeline.severity_changes[0].current_value), ("LOW", "HIGH"))
        self.assertTrue(all(event.report_id == result.report_id for event in timeline.events[-3:]))

    def test_reachability_semantic_update_preserves_identity_without_false_reopen(self):
        first = report(
            "system-a", "2026-08-01T00:00:00+00:00",
            findings=[finding(assessment_state="CONFIRMED")],
        )
        self.ingest(first)
        current_finding = finding(assessment_state="POTENTIAL")
        current_finding["network_context"] = {
            "bind_exposure": "all_interfaces",
            "bind_epistemic_role": "OBSERVED_FACT",
            "reachability_state": "POTENTIALLY_REACHABLE",
            "reachability_epistemic_role": "DETERMINISTIC_DERIVATION",
            "evidence_basis": ["SOCKET_WILDCARD_BIND"],
        }
        current = report(
            "system-a", "2026-08-02T00:00:00+00:00",
            findings=[current_finding],
        )
        current.update({
            "schema_version": "1.3",
            "assessment_domains": [
                "network_socket_inspection", "network_reachability",
            ],
            "coverage": {
                "network_socket_inspection": "COMPLETE",
                "network_reachability": "INCOMPLETE",
            },
        })
        self.ingest(current)
        timeline = self.timeline()
        self.assertEqual(timeline.summary.lifecycle_state, "ACTIVE")
        self.assertEqual(timeline.summary.reopened_count, 0)
        self.assertEqual(timeline.summary.occurrence_count, 2)
        self.assertEqual(
            [item.event_type for item in timeline.events],
            ["FIRST_SEEN", "SEEN", "ASSESSMENT_STATE_CHANGED"],
        )

    def test_legacy_finding_remains_potential_and_inferred(self):
        self.ingest(report("system-a", "2026-08-01T00:00:00+00:00"))
        legacy = {
            "generated_at": "2026-08-02T00:00:00+00:00",
            "system": {"hostname": "shared"},
            "security_score": {"score": 95},
            "findings": [{"title": "Legacy issue", "severity": "LOW", "evidence": []}],
        }
        self.number += 1
        path = Path(self.temporary.name, f"report-{self.number}.json")
        path.write_text(json.dumps(legacy), encoding="utf-8")
        result = ingest_report(self.database, ReportIngestionRequest(
            path, expected_system_id="system-a",
            legacy_link_policy=LegacyLinkPolicy.ALLOW_EXPLICIT_HOSTNAME_FALLBACK))
        self.assertEqual(result.status, IngestionStatus.INGESTED)
        row = self.database.connection.execute(
            "SELECT latest_assessment_state, metadata_inferred FROM findings WHERE system_id=?",
            ("system-a",)).fetchone()
        self.assertEqual(tuple(row), ("POTENTIAL", 1))

    def test_rebuild_is_idempotent_and_does_not_mutate_occurrences(self):
        self.ingest(report("system-a", "2026-08-01T00:00:00+00:00", findings=[finding()]))
        self.ingest(report("system-a", "2026-08-02T00:00:00+00:00", findings=[finding()]))
        before_occurrences = self.database.connection.execute(
            "SELECT * FROM finding_occurrences ORDER BY occurrence_id").fetchall()
        rebuild_system_lifecycle(self.database, "system-a")
        first = [tuple(row) for row in self.database.connection.execute(
            "SELECT * FROM findings ORDER BY finding_pk")]
        first_events = [tuple(row) for row in self.database.connection.execute(
            "SELECT * FROM finding_lifecycle_events ORDER BY event_id")]
        rebuild_system_lifecycle(self.database, "system-a")
        second = [tuple(row) for row in self.database.connection.execute(
            "SELECT * FROM findings ORDER BY finding_pk")]
        second_events = [tuple(row) for row in self.database.connection.execute(
            "SELECT * FROM finding_lifecycle_events ORDER BY event_id")]
        after_occurrences = self.database.connection.execute(
            "SELECT * FROM finding_occurrences ORDER BY occurrence_id").fetchall()
        self.assertEqual(first, second)
        self.assertEqual(first_events, second_events)
        self.assertEqual([tuple(row) for row in before_occurrences], [tuple(row) for row in after_occurrences])

    def test_rebuild_failure_rolls_back_summary_and_events(self):
        self.ingest(report("system-a", "2026-08-01T00:00:00+00:00", findings=[finding()]))
        before = tuple(self.database.connection.execute(
            "SELECT lifecycle_state, occurrence_count FROM findings WHERE system_id=?", ("system-a",)).fetchone())
        events = [tuple(row) for row in self.database.connection.execute(
            "SELECT * FROM finding_lifecycle_events WHERE system_id=?", ("system-a",))]
        self.database.connection.execute(
            "CREATE TRIGGER deny_events BEFORE INSERT ON finding_lifecycle_events BEGIN SELECT RAISE(ABORT, 'denied'); END")
        with self.assertRaises(MemoryLifecycleError):
            rebuild_system_lifecycle(self.database, "system-a")
        after = tuple(self.database.connection.execute(
            "SELECT lifecycle_state, occurrence_count FROM findings WHERE system_id=?", ("system-a",)).fetchone())
        retained = [tuple(row) for row in self.database.connection.execute(
            "SELECT * FROM finding_lifecycle_events WHERE system_id=?", ("system-a",))]
        self.assertEqual((before, events), (after, retained))

    def test_system_id_isolation_ignores_same_hostname_and_same_finding_id(self):
        self.ingest(report("system-a", "2026-08-01T00:00:00+00:00", findings=[finding()]))
        self.ingest(report("system-b", "2026-08-02T00:00:00+00:00", findings=[finding()]))
        self.ingest(report("system-a", "2026-08-03T00:00:00+00:00"))
        self.assertEqual(self.timeline("system-a").summary.lifecycle_state, "RESOLVED")
        self.assertEqual(self.timeline("system-b").summary.lifecycle_state, "ACTIVE")


class MemoryHistoryQueryTests(MemoryTestSupport, unittest.TestCase):
    def test_timeline_first_last_and_ordering(self):
        self.ingest(report("system-a", "2026-08-02T00:00:00+00:00", findings=[finding()]))
        self.ingest(report("system-a", "2026-08-01T00:00:00+00:00", findings=[finding()], score=91))
        timeline = self.timeline()
        self.assertEqual([item.observed_at for item in timeline.occurrences], sorted(item.observed_at for item in timeline.occurrences))
        self.assertEqual(timeline.summary.first_seen_at, "2026-08-01T00:00:00+00:00")
        self.assertEqual(timeline.summary.last_seen_at, "2026-08-02T00:00:00+00:00")

    def test_score_trend_uses_authoritative_scores_and_utc_bounds(self):
        self.ingest(report("system-a", "2026-08-01T00:00:00+00:00", score=81))
        self.ingest(report("system-a", "2026-08-02T00:00:00+00:00", score=82))
        self.ingest(report("system-b", "2026-08-02T00:00:00+00:00", score=10))
        result = score_trend(self.database, ScoreTrendQuery(
            "system-a", datetime(2026, 8, 1, 12, tzinfo=timezone.utc),
            datetime(2026, 8, 3, tzinfo=timezone.utc)))
        self.assertEqual([point.score for point in result], [82])
        with self.assertRaises(MemoryQueryError):
            ScoreTrendQuery("system-a", datetime(2020, 1, 1, tzinfo=timezone.utc),
                            datetime(2026, 1, 1, tzinfo=timezone.utc))

    def test_latest_report_and_empty_results(self):
        self.assertIsNone(latest_report_summary(self.database, SystemHistoryQuery("missing")))
        self.assertIsNone(finding_timeline(self.database, FindingHistoryQuery("missing", "finding:x")))
        self.assertEqual(recurring_findings(self.database, RecurringFindingsQuery("missing")), ())
        self.ingest(report("system-a", "2026-08-01T00:00:00+00:00", findings=[finding()], score=77))
        latest = latest_report_summary(self.database, SystemHistoryQuery("system-a"))
        self.assertEqual((latest.score, latest.finding_count), (77, 1))

    def test_system_id_is_required_and_sql_metacharacters_are_data(self):
        with self.assertRaises((TypeError, ValueError)):
            SystemHistoryQuery()  # type: ignore
        with self.assertRaises(MemoryQueryError):
            FindingHistoryQuery("", "finding:service")
        self.ingest(report("system-a", "2026-08-01T00:00:00+00:00", findings=[finding()]))
        hostile = "system-a' OR 1=1 --"
        self.assertEqual(recurring_findings(self.database, RecurringFindingsQuery(hostile)), ())
        self.assertIsNone(finding_timeline(self.database, FindingHistoryQuery(hostile, "finding:service")))
