import copy
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from cyberwatchtower.advisor.context import build_advisor_context
from cyberwatchtower.advisor.deterministic import build_deterministic_advisory
from cyberwatchtower.advisor.service import build_provider_request
from cyberwatchtower.core.orchestrator import IntelligenceOrchestrator
from cyberwatchtower.history import compare_reports
from cyberwatchtower.memory import open_memory_database
from cyberwatchtower.memory.ingestion import ingest_report
from cyberwatchtower.memory.ingestion_models import ReportIngestionRequest
from cyberwatchtower.memory.normalizers import normalize_report
from cyberwatchtower.models import (
    AssessmentState, Finding, FindingKind, MAX_RUNTIME_INSTANCE_COUNT,
    Severity,
)
from cyberwatchtower.network_canonicalization import (
    NetworkFindingCandidate, canonicalize_network_findings,
)
from cyberwatchtower.platform import BindExposure
from cyberwatchtower.platform.windows import (
    FakeWindowsApi, RawProcessInfo, RawUdpEndpoint, WindowsAddressFamily,
    WindowsPlatformAdapter,
)
from cyberwatchtower.reachability import RemoteReachabilityState
from cyberwatchtower.reporting import save_json_report
from cyberwatchtower.scanner import run_scan
from cyberwatchtower.scoring_contracts import (
    NetworkScoringIdentity, ScoringCategory, ScoringFinding,
)
from cyberwatchtower.scoring_projection import (
    canonical_finding_id, project_scoring_findings,
)
from cyberwatchtower.scoring_v2 import calculate_security_score_v2
from tests.test_windows_platform_integration import fixture, ok


def identity(*, protocol="udp", port=5353,
             application="application:test"):
    return NetworkScoringIdentity(
        protocol, port, BindExposure.ALL_INTERFACES,
        RemoteReachabilityState.POTENTIALLY_REACHABLE,
        application_identity=application,
    )


def finding(*, finding_id=None, severity=Severity.MEDIUM,
            kind=FindingKind.RISK, state=AssessmentState.POTENTIAL,
            network_state=RemoteReachabilityState.POTENTIALLY_REACHABLE,
            count=1):
    return Finding(
        "Unknown service listening on all interfaces",
        "A UDP service is bound broadly.", severity,
        "Restrict exposure when unnecessary.",
        ["Protocol: udp", "Address: 0.0.0.0", "Port: 5353",
         "Process: example.exe", "Application: application:test", "PID: 100"],
        90, finding_id=finding_id, source="network", kind=kind,
        assessment_state=state,
        network_context={
            "bind_exposure": "all_interfaces",
            "reachability_state": network_state.value,
            "evidence_basis": ["NO_APPLICABLE_POLICY_PROOF"],
        },
        presentation_group_id="presentation:test",
        runtime_instance_count=count,
    )


def candidate(pid, **kwargs):
    value = finding(**kwargs)
    value.evidence[-1] = f"PID: {pid}"
    return NetworkFindingCandidate(value, identity(), pid)


def duplicate_windows_result(count=2):
    base = fixture()
    pids = tuple(range(201, 201 + count))
    updated = replace(
        base,
        udp_endpoints=ok(tuple(
            RawUdpEndpoint(WindowsAddressFamily.IPV4, "0.0.0.0", 5353, pid)
            for pid in pids
        )),
        processes=tuple(
            (pid, ok(RawProcessInfo(pid, "example.exe"))) for pid in pids
        ),
    )
    return run_scan(WindowsPlatformAdapter(FakeWindowsApi(updated)))


class CanonicalFindingMultiplicityTests(unittest.TestCase):
    def test_pid_distinct_windows_udp_instances_become_one_canonical_finding(self):
        single = duplicate_windows_result(1)
        multiple = duplicate_windows_result(2)
        one = next(item for item in single["findings"]
                   if item.source == "network" and "5353" in item.description)
        many = next(item for item in multiple["findings"]
                    if item.source == "network" and "5353" in item.description)
        self.assertEqual(many.runtime_instance_count, 2)
        self.assertEqual(canonical_finding_id(one), canonical_finding_id(many))
        self.assertEqual(single["score"]["score"], multiple["score"]["score"])
        single_network_group = next(
            group for group in single["score"]["breakdown"]["contributors"]
            if group["category"] == ScoringCategory.NETWORK_EXPOSURE.value
            and canonical_finding_id(one) in group["finding_ids"]
        )
        multiple_network_group = next(
            group for group in multiple["score"]["breakdown"]["contributors"]
            if group["category"] == ScoringCategory.NETWORK_EXPOSURE.value
            and canonical_finding_id(many) in group["finding_ids"]
        )
        self.assertEqual(
            single_network_group["group_id"], multiple_network_group["group_id"]
        )
        self.assertNotIn("PID:", "\n".join(many.evidence))
        scoring_ids = {
            group["finding_ids"][0]: identity()
            for group in multiple["score"]["breakdown"]["contributors"]
            if group["category"] == ScoringCategory.NETWORK_EXPOSURE.value
        }
        projected = project_scoring_findings(multiple["findings"], scoring_ids)
        self.assertEqual(
            len(projected), len({item.finding_id for item in projected})
        )

    def test_three_instances_and_pid_restart_are_deterministic(self):
        two = canonicalize_network_findings((candidate(10), candidate(20)))
        three = canonicalize_network_findings(
            (candidate(30), candidate(40), candidate(50))
        )
        restarted = canonicalize_network_findings((candidate(60), candidate(70)))
        self.assertEqual(two[0][0].runtime_instance_count, 2)
        self.assertEqual(three[0][0].runtime_instance_count, 3)
        self.assertEqual(
            canonical_finding_id(two[0][0]), canonical_finding_id(restarted[0][0])
        )

    def test_multiplicity_is_bounded_and_immutable(self):
        for invalid in (0, -1, MAX_RUNTIME_INSTANCE_COUNT + 1, 1.5, True, "2"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                finding(count=invalid)
        value = finding(count=2)
        with self.assertRaises(AttributeError):
            value.runtime_instance_count = 3

    def test_distinct_semantic_endpoints_remain_distinct(self):
        base = candidate(1)
        cases = (
            NetworkFindingCandidate(replace(
                finding(), evidence=["Protocol: udp", "Address: ::", "Port: 5353",
                                     "Process: example.exe",
                                     "Application: application:test", "PID: 2"]
            ), identity(), 2),
            NetworkFindingCandidate(replace(
                finding(), evidence=["Protocol: udp", "Address: 0.0.0.0",
                                     "Port: 5354", "Process: example.exe", "PID: 3"]
            ), identity(port=5354), 3),
            NetworkFindingCandidate(replace(
                finding(), evidence=["Protocol: tcp", "Address: 0.0.0.0",
                                     "Port: 5353", "Process: example.exe", "PID: 4"]
            ), identity(protocol="tcp"), 4),
            NetworkFindingCandidate(replace(
                finding(), evidence=["Protocol: udp", "Address: 0.0.0.0",
                                     "Port: 5353", "Process: other.exe",
                                     "Application: application:other", "PID: 5"]
            ), identity(application="application:other"), 5),
        )
        for other in cases:
            with self.subTest(other=other.scoring_identity):
                self.assertEqual(
                    len(canonicalize_network_findings((base, other))), 2
                )

    def test_same_id_with_conflicting_semantics_fails_closed(self):
        baseline = candidate(1, finding_id="stable:test")
        conflicts = (
            NetworkFindingCandidate(replace(
                finding(finding_id="stable:test"), severity=Severity.HIGH
            ), identity(), 2),
            NetworkFindingCandidate(replace(
                finding(finding_id="stable:test"), kind=FindingKind.COVERAGE_GAP
            ), identity(), 2),
            NetworkFindingCandidate(replace(
                finding(finding_id="stable:test"),
                assessment_state=AssessmentState.CONFIRMED
            ), identity(), 2),
            NetworkFindingCandidate(
                finding(finding_id="stable:test",
                        network_state=RemoteReachabilityState.UNKNOWN),
                identity(), 2,
            ),
        )
        for conflict in conflicts:
            with self.subTest(conflict=conflict), self.assertRaises(ValueError):
                canonicalize_network_findings((baseline, conflict))
        with self.assertRaises(ValueError):
            canonicalize_network_findings(
                (baseline, candidate(1, finding_id="stable:test"))
            )

    def test_report_round_trip_legacy_default_and_malformed_values(self):
        result = duplicate_windows_result(2)
        with tempfile.TemporaryDirectory() as directory:
            path = save_json_report(result, directory)
            report = json.loads(path.read_text(encoding="utf-8"))
        normalized, _ = normalize_report(report)
        self.assertEqual(report["schema_version"], "1.6")
        self.assertEqual(
            max(item.runtime_instance_count for item in normalized.findings), 2
        )
        legacy = copy.deepcopy(report)
        legacy["schema_version"] = "1.4"
        for item in legacy["findings"]:
            item.pop("runtime_instance_count")
        normalized_legacy, _ = normalize_report(legacy)
        self.assertTrue(all(
            item.runtime_instance_count == 1 for item in normalized_legacy.findings
        ))
        for invalid in (None, 0, -1, MAX_RUNTIME_INSTANCE_COUNT + 1, 1.5, True, "2"):
            malformed = copy.deepcopy(report)
            malformed["findings"][0]["runtime_instance_count"] = invalid
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                normalize_report(malformed)
        missing = copy.deepcopy(report)
        missing["findings"][0].pop("runtime_instance_count")
        with self.assertRaises(ValueError):
            normalize_report(missing)
        model_like = copy.deepcopy(report)
        model_like["findings"][0]["runtime_instance_count"] = {
            "model_estimate": 2
        }
        with self.assertRaises(ValueError):
            normalize_report(model_like)

    def test_history_memory_and_provider_keep_one_condition(self):
        result = duplicate_windows_result(2)
        with tempfile.TemporaryDirectory() as directory:
            first_path = save_json_report(result, directory)
            first = json.loads(first_path.read_text(encoding="utf-8"))
            current = copy.deepcopy(first)
            current["findings"][0]["runtime_instance_count"] = 4
            comparison = compare_reports(first, current)
            with open_memory_database(Path(directory, "memory.db")) as database:
                ingestion = ingest_report(
                    database, ReportIngestionRequest(first_path)
                )
                occurrences = database.connection.execute(
                    "SELECT COUNT(*) FROM finding_occurrences"
                ).fetchone()[0]
        self.assertEqual(comparison["new_findings"], [])
        self.assertEqual(comparison["resolved_findings"], [])
        self.assertIsNotNone(ingestion.report_id)
        self.assertEqual(occurrences, len(result["findings"]))
        context = build_advisor_context(first, comparison, None)
        advisory = build_deterministic_advisory(context)
        provider = build_provider_request(context, advisory)
        core = IntelligenceOrchestrator().handle(
            "Give me my security briefing", reports=(first,)
        )
        self.assertIn("Multiple runtime instances were observed: 2", repr(advisory))
        for boundary in (repr(context), repr(provider), repr(core), json.dumps(first)):
            for prohibited in (
                "PID: 201", "PID: 202", "member_pids", "runtime_members"
            ):
                self.assertNotIn(prohibited, boundary)

    def test_scoring_ignores_multiplicity(self):
        scores = []
        for count in (1, 2, MAX_RUNTIME_INSTANCE_COUNT):
            source = finding(count=count)
            scoring = ScoringFinding(
                canonical_finding_id(source), Severity.MEDIUM, FindingKind.RISK,
                AssessmentState.POTENTIAL, "network",
                ScoringCategory.NETWORK_EXPOSURE, identity(),
            )
            scores.append(calculate_security_score_v2((scoring,)).score)
        self.assertEqual(scores, [96, 96, 96])


if __name__ == "__main__":
    unittest.main()
