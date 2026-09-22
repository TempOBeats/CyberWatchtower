"""Portable Linux L4 proofs: real parser/evaluator, injected collection only."""

import dataclasses
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from cyberwatchtower.firewall_policy import EvaluatedPolicyDisposition as Disposition
from cyberwatchtower.history import compare_reports
from cyberwatchtower.memory.normalizers import normalize_report
from cyberwatchtower.platform.linux.adapter import LinuxPlatformAdapter
from cyberwatchtower.platform.linux import firewall_policy_integration as integration
from cyberwatchtower.platform.linux.firewall_contracts import LinuxNamespaceAlignment
from cyberwatchtower.platform.linux.nftables_contracts import NftParseResult, NftParseStatus
from cyberwatchtower.platform.linux.nftables_native import (
    NftablesNativeResult, NftablesNativeStatus as NativeStatus,
)
from cyberwatchtower.platform.linux.nftables_parser import parse_nftables_json
from cyberwatchtower.platform.models import ListenerObservation
from cyberwatchtower.report_contracts import CoverageState as Coverage
from cyberwatchtower.reporting import save_json_report
from cyberwatchtower.scoring_contracts import ScoringVersion
from cyberwatchtower.scanner import run_scan


HEADER = "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process"
ROW = 'tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("python3",pid=42,fd=3))'
TABLE = "private_table_L4_CANARY"
CHAIN = "private_chain_L4_CANARY"
INTERFACE = "private_iface_L4_CANARY"


def listener(address="0.0.0.0", port=8080, **extra):
    return ListenerObservation.from_mapping({
        "protocol": "tcp", "state": "LISTEN", "address": address,
        "port": port, "exposure": "all_interfaces" if address in {"0.0.0.0", "::"}
        else "interface", **extra,
    })


def collected(policy="drop", expressions=(), *, later_drop=False,
              alignment=LinuxNamespaceAlignment.SAME_CURRENT_NAMESPACE):
    objects = [
        {"table": {"family": "inet", "name": TABLE}},
        {"chain": {"family": "inet", "table": TABLE, "name": CHAIN,
                   "type": "filter", "hook": "input", "prio": 0, "policy": policy}},
    ]
    if expressions:
        objects.append({"rule": {"family": "inet", "table": TABLE,
                                  "chain": CHAIN, "expr": list(expressions)}})
    if later_drop:
        objects.append({"chain": {"family": "inet", "table": TABLE,
                                   "name": "later", "type": "filter",
                                   "hook": "input", "prio": 10, "policy": "drop"}})
    parsed = parse_nftables_json(json.dumps({"nftables": objects}),
                                namespace_alignment=alignment)
    return NftablesNativeResult(NativeStatus.COLLECTED, parsed, 0)


def address_match(field, value):
    return {"match": {"op": "==", "left": {"payload": {
        "protocol": "ip", "field": field}}, "right": value}}


class FakeProvider:
    def __init__(self, result):
        self.result = result
        self.calls = 0

    def collect_firewall_policy(self):
        self.calls += 1
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def fixture_adapter(provider, *, output=HEADER + "\n" + ROW, legacy=None, iptables=True):
    return LinuxPlatformAdapter(
        system_collector=lambda: {"system_id": "linux-l4-fixture", "hostname": "fixture"},
        firewall_collector=lambda: {"detected_tools": ["nftables", "iptables"] if iptables else ["nftables"]},
        network_collector=lambda: {"accessible": True, "raw_output": output},
        firewall_policy_collector=legacy or (lambda: {
            "available": True, "accessible": True, "policies": {"INPUT": "DROP"}}),
        process_enricher=lambda services: services,
        firewall_policy_provider=provider,
    )


class LinuxPolicyIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.native = self.enterContext(patch.object(
            integration.NativeLinuxFirewallPolicyProvider, "collect_firewall_policy",
            side_effect=AssertionError("ordinary fixture reached native provider"),
        ))
        self.addCleanup(self.native.assert_not_called)

    def integrate(self, result, listeners=None, coverage=Coverage.COMPLETE):
        provider = FakeProvider(result)
        value = integration.collect_linux_listener_policy(
            provider, (listener(),) if listeners is None else listeners, coverage)
        self.assertEqual(provider.calls, 1)
        return value

    def assert_disposition(self, native, expected, listeners=None):
        result = self.integrate(native, listeners)
        self.assertEqual(result.assessments[0].evaluated_policy_disposition, expected)
        return result

    def test_base_drop_and_accept(self):
        for policy, expected in (("drop", Disposition.BLOCK), ("accept", Disposition.ALLOW)):
            with self.subTest(policy=policy):
                result = self.assert_disposition(collected(policy), expected)
                self.assertEqual(result.collection_coverage, Coverage.COMPLETE)
                self.assertEqual(result.applicability_coverage, Coverage.COMPLETE)

    def test_explicit_drop(self):
        self.assert_disposition(collected("accept", ({"drop": None},)), Disposition.BLOCK)

    def test_accept_then_later_base_chain_drop(self):
        self.assert_disposition(collected("accept", ({"accept": None},), later_drop=True),
                                Disposition.BLOCK)

    def test_unsupported_predicate_never_evaluates_partial_snapshot(self):
        native = collected(expressions=({"match": {"op": "==", "left": {
            "meta": {"key": "mark"}}, "right": 42}}, {"accept": None}))
        self.assertEqual(native.parse_result.status, NftParseStatus.UNSUPPORTED_SEMANTICS)
        with patch.object(integration, "evaluate_linux_listener_policy") as evaluator:
            result = self.assert_disposition(native, Disposition.NOT_ESTABLISHED)
        evaluator.assert_not_called()
        self.assertEqual(result.applicability_coverage, Coverage.INCOMPLETE)

    def test_unknown_namespace_is_not_promoted_even_with_empty_listener_set(self):
        native = collected(alignment=LinuxNamespaceAlignment.UNKNOWN)
        for listeners in ((listener(),), ()):
            with self.subTest(listeners=listeners):
                result = self.integrate(native, listeners)
                self.assertEqual(result.collection_coverage, Coverage.COMPLETE)
                self.assertEqual(result.applicability_coverage, Coverage.INCOMPLETE)
                self.assertEqual(result.namespace_alignment, LinuxNamespaceAlignment.UNKNOWN)
                for assessment in result.assessments:
                    self.assertEqual(assessment.evaluated_policy_disposition,
                                     Disposition.NOT_ESTABLISHED)

    def test_unavailable_is_unknown_and_does_not_evaluate(self):
        with patch.object(integration, "evaluate_linux_listener_policy") as evaluator:
            result = self.integrate(NftablesNativeResult(NativeStatus.UNAVAILABLE))
        evaluator.assert_not_called()
        self.assertEqual(result.collection_coverage, Coverage.UNKNOWN)
        self.assertEqual(result.applicability_coverage, Coverage.UNKNOWN)
        self.assertEqual(result.assessments[0].evaluated_policy_disposition,
                         Disposition.NOT_ESTABLISHED)

    def test_every_other_native_failure_is_incomplete(self):
        for status in NativeStatus:
            if status in {NativeStatus.COLLECTED, NativeStatus.UNAVAILABLE}:
                continue
            code = 1 if status == NativeStatus.NONZERO_EXIT else (
                0 if status == NativeStatus.STDERR_PRESENT else None)
            with self.subTest(status=status), patch.object(
                integration, "evaluate_linux_listener_policy"
            ) as evaluator:
                result = self.integrate(NftablesNativeResult(status, exit_code=code))
                self.assertEqual(result.collection_coverage, Coverage.INCOMPLETE)
                self.assertEqual(result.applicability_coverage, Coverage.INCOMPLETE)
                evaluator.assert_not_called()

    def test_every_non_success_parser_status_is_incomplete(self):
        for status in NftParseStatus:
            if status == NftParseStatus.SUCCESS:
                continue
            # Even a retained partial snapshot must not be globally evaluated.
            parsed = NftParseResult(status, collected().parse_result.snapshot)
            with self.subTest(status=status), patch.object(
                integration, "evaluate_linux_listener_policy"
            ) as evaluator:
                result = self.integrate(NftablesNativeResult(NativeStatus.COLLECTED, parsed, 0))
                self.assertEqual(result.collection_coverage, Coverage.INCOMPLETE)
                self.assertEqual(result.applicability_coverage, Coverage.INCOMPLETE)
                evaluator.assert_not_called()

    def test_collected_missing_or_inconsistent_result_fails_closed(self):
        for field, value in (("parse_result", None), ("exit_code", 1)):
            invalid = collected()
            # Simulate a provider violating the immutable DTO contract.
            object.__setattr__(invalid, field, value)
            with self.subTest(field=field):
                self.assertEqual(self.integrate(invalid).collection_coverage, Coverage.INCOMPLETE)
        invalid = collected()
        object.__setattr__(invalid.parse_result.snapshot, "authority", "host-global")
        self.assertEqual(self.integrate(invalid).collection_coverage, Coverage.INCOMPLETE)
        self.assertEqual(self.integrate(object()).collection_coverage, Coverage.INCOMPLETE)

    def test_subject_projection_uses_no_invented_identity(self):
        observed = listener(application="/private/cmdline-CANARY", application_name="service",
                            process="service", pid=123)
        subject = integration.linux_listener_policy_subject(observed)
        self.assertEqual((subject.protocol.value, subject.local_address, subject.local_port),
                         ("tcp", "0.0.0.0", 8080))
        self.assertEqual(subject.profiles, ())
        self.assertIsNone(subject.application_digest)
        self.assertIsNone(subject.service_identity)
        self.assertIsNone(subject.interface)
        self.assertIsNone(subject.interface_digest)
        self.assertNotIn("CANARY", repr(subject))
        canonical = dataclasses.replace(observed, application_digest="a" * 64)
        self.assertEqual(integration.linux_listener_policy_subject(canonical).application_digest,
                         "a" * 64)

    def test_wildcard_destination_is_conservative(self):
        native = collected("accept", (address_match("daddr", "192.0.2.4"), {"drop": None}))
        self.assert_disposition(native, Disposition.NOT_ESTABLISHED)

    def test_unknown_ingress_interface_is_conservative(self):
        native = collected("accept", ({"match": {"op": "==", "left": {
            "meta": {"key": "iifname"}}, "right": INTERFACE}}, {"drop": None}))
        self.assertEqual(native.parse_result.status, NftParseStatus.SUCCESS)
        self.assert_disposition(native, Disposition.NOT_ESTABLISHED)

    def test_unknown_remote_peer_is_conservative(self):
        self.assert_disposition(collected("accept", (
            address_match("saddr", "192.0.2.4"), {"drop": None})), Disposition.NOT_ESTABLISHED)

    def test_empty_complete_listener_set_is_complete(self):
        result = self.integrate(collected(), ())
        self.assertEqual(result.assessments, ())
        self.assertEqual(result.applicability_coverage, Coverage.COMPLETE)

    def test_socket_incompleteness_never_becomes_complete_applicability(self):
        for coverage in (Coverage.INCOMPLETE, Coverage.UNKNOWN):
            with self.subTest(coverage=coverage):
                result = self.integrate(collected(), coverage=coverage)
                self.assertEqual(result.collection_coverage, Coverage.COMPLETE)
                self.assertEqual(result.applicability_coverage, Coverage.INCOMPLETE)

    def test_evaluator_exception_and_invalid_subject_fail_closed(self):
        with patch.object(integration, "evaluate_linux_listener_policy", side_effect=RuntimeError("secret")):
            result = self.integrate(collected())
        self.assertEqual(result.collection_coverage, Coverage.COMPLETE)
        self.assertEqual(result.applicability_coverage, Coverage.INCOMPLETE)
        self.assertNotIn("secret", repr(result))
        result = self.integrate(collected(), (listener(address="unusable"),))
        self.assertEqual(result.applicability_coverage, Coverage.INCOMPLETE)

    def test_result_is_immutable_slotted_and_contains_only_normalized_fields(self):
        result = self.integrate(collected())
        self.assertFalse(hasattr(result, "__dict__"))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.collection_coverage = Coverage.UNKNOWN
        self.assertEqual({field.name for field in dataclasses.fields(result)}, {
            "collection_coverage", "applicability_coverage", "bindings",
            "native_status", "parser_status", "authority", "namespace_alignment",
            "_snapshot",
        })
        binding = result.bindings[0]
        self.assertFalse(hasattr(binding, "__dict__"))
        self.assertEqual(
            {field.name for field in dataclasses.fields(binding)},
            {"subject", "assessment"},
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            binding.assessment = result.assessments[0]
        self.assertNotIn(TABLE, repr(result))
        self.assertNotIn(CHAIN, repr(result))


class LinuxPolicyAdapterTests(unittest.TestCase):
    def test_ordinary_fixture_factories_never_reach_native_provider(self):
        from tests.test_platform_contracts import adapter as platform_fixture
        from tests.test_scanner_scoring_v2 import linux_adapter as scoring_fixture
        from tests.test_scan_completeness import _run_linux_fixture_scan as completeness_fixture
        from tests.test_finding_metadata import _run_linux_fixture_scan as metadata_fixture

        with (
            patch.object(integration.NativeLinuxFirewallPolicyProvider, "collect_firewall_policy",
                         side_effect=AssertionError("ordinary fixture reached native provider")) as native,
            patch("cyberwatchtower.scanner.collect_system_information", return_value={}),
            patch("cyberwatchtower.scanner.check_firewall", return_value={"detected_tools": ["nftables"]}),
            patch("cyberwatchtower.scanner.inspect_listening_services",
                  return_value={"accessible": True, "raw_output": HEADER}),
            patch.object(integration.ClosedLinuxFirewallPolicyProvider, "collect_firewall_policy",
                         return_value=NftablesNativeResult(NativeStatus.UNAVAILABLE)) as closed,
        ):
            for factory in (platform_fixture, scoring_fixture):
                run_scan(factory())
            completeness_fixture()
            metadata_fixture()
        native.assert_not_called()
        self.assertEqual(closed.call_count, 4)

    def test_injected_provider_called_once_and_real_provider_unreachable(self):
        provider = FakeProvider(collected())
        with patch.object(integration.NativeLinuxFirewallPolicyProvider,
                          "collect_firewall_policy", side_effect=AssertionError("native reached")) as native:
            result = fixture_adapter(provider).collect_listener_firewall_policy(
                (listener(),), Coverage.COMPLETE)
        self.assertEqual(provider.calls, 1)
        native.assert_not_called()
        self.assertEqual(result.assessments[0].evaluated_policy_disposition, Disposition.BLOCK)

    def test_production_provider_delegates_only_to_public_l3b_boundary(self):
        # Explicit delegation proof; the public collector itself is replaced.
        expected = NftablesNativeResult(NativeStatus.UNAVAILABLE)
        with patch.object(integration, "collect_nftables_ruleset", return_value=expected) as collect:
            result = LinuxPlatformAdapter().collect_listener_firewall_policy((), Coverage.COMPLETE)
        collect.assert_called_once_with()
        self.assertEqual(result.collection_coverage, Coverage.UNKNOWN)


class LinuxPolicyScannerTests(unittest.TestCase):
    def setUp(self):
        self.native = self.enterContext(patch.object(
            integration.NativeLinuxFirewallPolicyProvider, "collect_firewall_policy",
            side_effect=AssertionError("ordinary fixture reached native provider"),
        ))
        self.addCleanup(self.native.assert_not_called)

    def scan(self, native, **kwargs):
        provider = FakeProvider(native)
        result = run_scan(fixture_adapter(provider, **kwargs))
        self.assertEqual(provider.calls, 1)
        return result

    def context(self, scan):
        return next(f.network_context for f in scan["findings"] if f.source == "network")

    def test_dispositions_reachability_and_no_confirmed_reachable(self):
        for native, disposition, state in (
            (collected(), "BLOCK", "BLOCKED_BY_OBSERVED_POLICY"),
            (collected("accept"), "ALLOW", "POTENTIALLY_REACHABLE"),
            (collected(alignment=LinuxNamespaceAlignment.UNKNOWN), "NOT_ESTABLISHED", "POTENTIALLY_REACHABLE"),
        ):
            with self.subTest(disposition=disposition):
                context = self.context(self.scan(native))
                self.assertEqual(context["reachability_state"], state)
                self.assertEqual(context["policy_assessment"]["evaluated_policy_disposition"], disposition)
                self.assertNotIn("CONFIRMED_REACHABLE", json.dumps(context))

    def test_provider_failure_does_not_abort_scan_or_leak_exception(self):
        scan = self.scan(RuntimeError("raw stderr /private/nft LD_PRELOAD=SECRET-CANARY"))
        self.assertEqual(scan["coverage"]["host_firewall_rule_collection"], "INCOMPLETE")
        self.assertEqual(scan["coverage"]["network_socket_inspection"], "COMPLETE")
        self.assertEqual(self.context(scan)["reachability_state"], "POTENTIALLY_REACHABLE")
        self.assertNotIn("SECRET-CANARY", repr(scan))

    def test_normalization_reuses_same_snapshot_without_recollection(self):
        provider = FakeProvider(collected())
        adapter = fixture_adapter(provider)
        evaluator = integration.evaluate_linux_listener_policy
        snapshots = []

        def record_snapshot(subject, snapshot):
            snapshots.append(snapshot)
            return evaluator(subject, snapshot)

        with patch.object(
            integration, "evaluate_linux_listener_policy",
            side_effect=record_snapshot,
        ):
            scan = run_scan(adapter)

        self.assertEqual(provider.calls, 1)
        self.assertEqual(len(snapshots), 2)
        self.assertIs(snapshots[0], snapshots[1])
        self.assertEqual(
            self.context(scan)["policy_assessment"]["evaluated_policy_disposition"],
            "BLOCK",
        )

    def test_usable_nft_bypasses_iptables_but_unusable_nft_retains_legacy_only(self):
        for native, usable, collection in (
            (collected(), True, "COMPLETE"),
            (NftablesNativeResult(NativeStatus.UNAVAILABLE), False, "UNKNOWN"),
            (NftablesNativeResult(NativeStatus.TIMEOUT), False, "INCOMPLETE"),
        ):
            with self.subTest(collection=collection):
                legacy = Mock(return_value={"available": True, "accessible": True,
                                            "policies": {"INPUT": "ACCEPT"}})
                scan = self.scan(native, legacy=legacy)
                self.assertEqual(legacy.call_count, 0 if usable else 1)
                self.assertEqual(sum(f.title == "iptables firewall assessment" for f in scan["findings"]),
                                 0 if usable else 1)
                self.assertEqual(scan["coverage"]["host_firewall_rule_collection"], collection)
                self.assertEqual(scan["coverage"]["host_firewall_rule_applicability"], collection)
                self.assertEqual(scan["coverage"]["iptables_input_policy"], "UNKNOWN" if usable else "COMPLETE")

    def test_firewall_socket_and_reachability_coverage_are_independent(self):
        for native, output, expected in (
            (collected("accept"), HEADER + "\n" + ROW, ("COMPLETE", "INCOMPLETE", "COMPLETE")),
            (collected(), HEADER + "\n" + ROW + "\nmalformed", ("INCOMPLETE", "INCOMPLETE", "COMPLETE")),
            (NftablesNativeResult(NativeStatus.TIMEOUT), HEADER, ("COMPLETE", "COMPLETE", "INCOMPLETE")),
        ):
            with self.subTest(expected=expected):
                coverage = self.scan(native, output=output)["coverage"]
                self.assertEqual(tuple(coverage[key] for key in (
                    "network_socket_inspection", "network_reachability", "host_firewall_rule_collection")), expected)

    def test_cardinality_and_assessment_order_mismatch_fail_closed_without_aborting(self):
        port_drop = (
            {"match": {"op": "==", "left": {"payload": {
                "protocol": "tcp", "field": "dport"}}, "right": 8080}},
            {"drop": None},
        )
        for mismatch in ("count", "binding_order", "assessment_order", "subject"):
            provider = FakeProvider(collected("accept", port_drop))
            adapter = fixture_adapter(
                provider,
                output=HEADER + "\n" + ROW + "\n" + ROW.replace("8080", "8081"),
            )
            observations = adapter.collect_network().observations
            value = adapter.collect_listener_firewall_policy(observations, Coverage.COMPLETE)
            self.assertEqual(
                tuple(item.evaluated_policy_disposition for item in value.assessments),
                (Disposition.BLOCK, Disposition.ALLOW),
            )
            if mismatch == "count":
                object.__setattr__(value, "bindings", value.bindings[:-1])
            elif mismatch == "binding_order":
                object.__setattr__(value, "bindings", value.bindings[::-1])
            elif mismatch == "assessment_order":
                assessments = value.assessments
                object.__setattr__(value.bindings[0], "assessment", assessments[1])
                object.__setattr__(value.bindings[1], "assessment", assessments[0])
            else:
                object.__setattr__(value.bindings[0], "subject", value.subjects[1])
            with self.subTest(mismatch=mismatch), patch.object(
                adapter, "collect_listener_firewall_policy", return_value=value,
            ):
                scan = run_scan(adapter)
            self.assertEqual(scan["coverage"]["host_firewall_rule_applicability"], "INCOMPLETE")
            contexts = [
                finding.network_context
                for finding in scan["findings"]
                if finding.source == "network"
            ]
            self.assertEqual(len(contexts), 2)
            self.assertTrue(all(
                context["reachability_state"] == "POTENTIALLY_REACHABLE"
                and context["policy_assessment"]["evaluated_policy_disposition"]
                == "NOT_ESTABLISHED"
                for context in contexts
            ))

    def test_fresh_wrong_subject_assessment_pair_fails_closed(self):
        port_drop = (
            {"match": {"op": "==", "left": {"payload": {
                "protocol": "tcp", "field": "dport"}}, "right": 8080}},
            {"drop": None},
        )
        adapter = fixture_adapter(
            FakeProvider(collected("accept", port_drop)),
            output=HEADER + "\n" + ROW + "\n" + ROW.replace("8080", "8081"),
        )
        observations = adapter.collect_network().observations
        valid = adapter.collect_listener_firewall_policy(
            observations, Coverage.COMPLETE,
        )
        self.assertEqual(
            tuple(item.evaluated_policy_disposition for item in valid.assessments),
            (Disposition.BLOCK, Disposition.ALLOW),
        )
        wrong = integration.LinuxListenerPolicyBinding(
            valid.subjects[0], valid.assessments[1],
        )
        malformed = dataclasses.replace(
            valid, bindings=(wrong, valid.bindings[1]),
        )

        with patch.object(
            adapter, "collect_listener_firewall_policy", return_value=malformed,
        ):
            scan = run_scan(adapter)

        self.assertEqual(
            scan["coverage"]["host_firewall_rule_collection"], "COMPLETE",
        )
        self.assertEqual(
            scan["coverage"]["host_firewall_rule_applicability"], "INCOMPLETE",
        )
        contexts = [
            finding.network_context
            for finding in scan["findings"]
            if finding.source == "network"
        ]
        self.assertEqual(len(contexts), 2)
        self.assertTrue(all(
            context["reachability_state"] == "POTENTIALLY_REACHABLE"
            and context["policy_assessment"]["evaluated_policy_disposition"]
            == "NOT_ESTABLISHED"
            for context in contexts
        ))

    def test_identical_subject_contradictory_strong_assessments_fail_closed(self):
        adapter = fixture_adapter(
            FakeProvider(collected()),
            output=HEADER + "\n" + ROW + "\n" + ROW.replace("pid=42", "pid=43"),
        )
        observations = adapter.collect_network().observations
        self.assertEqual(tuple(item.pid for item in observations), (42, 43))
        blocked = adapter.collect_listener_firewall_policy(
            observations, Coverage.COMPLETE,
        )
        allowed = integration.collect_linux_listener_policy(
            FakeProvider(collected("accept")), observations, Coverage.COMPLETE,
        )
        self.assertEqual(blocked.subjects[0], blocked.subjects[1])
        contradictory = dataclasses.replace(
            blocked,
            bindings=(
                integration.LinuxListenerPolicyBinding(
                    blocked.subjects[0], blocked.assessments[0],
                ),
                integration.LinuxListenerPolicyBinding(
                    blocked.subjects[1], allowed.assessments[1],
                ),
            ),
        )

        with patch.object(
            adapter, "collect_listener_firewall_policy", return_value=contradictory,
        ):
            scan = run_scan(adapter)

        self.assertEqual(
            scan["coverage"]["host_firewall_rule_collection"], "COMPLETE",
        )
        self.assertEqual(
            scan["coverage"]["host_firewall_rule_applicability"], "INCOMPLETE",
        )
        contexts = [
            finding.network_context
            for finding in scan["findings"]
            if finding.source == "network"
        ]
        self.assertEqual(sum(finding.runtime_instance_count for finding in scan["findings"]
                             if finding.source == "network"), 2)
        self.assertTrue(all(
            context["reachability_state"] == "POTENTIALLY_REACHABLE"
            and context["policy_assessment"]["evaluated_policy_disposition"]
            == "NOT_ESTABLISHED"
            for context in contexts
        ))

    def test_invalid_binding_shapes_fail_closed_and_duplicate_subjects_are_retained(self):
        listeners = (listener(pid=41), listener(pid=42))
        value = integration.collect_linux_listener_policy(
            FakeProvider(collected()), listeners, Coverage.COMPLETE,
        )
        self.assertEqual(len(value.bindings), 2)
        self.assertEqual(value.subjects[0], value.subjects[1])
        self.assertEqual(len(value.assessments), 2)
        self.assertEqual(value.assessments[0], value.assessments[1])
        self.assertEqual(value.applicability_coverage, Coverage.COMPLETE)
        duplicate_adapter = fixture_adapter(
            FakeProvider(collected()),
            output=HEADER + "\n" + ROW + "\n" + ROW.replace("pid=42", "pid=43"),
        )
        duplicate_observations = duplicate_adapter.collect_network().observations
        self.assertEqual(tuple(item.pid for item in duplicate_observations), (42, 43))
        duplicate_scan = run_scan(duplicate_adapter)
        duplicate_finding = next(
            finding for finding in duplicate_scan["findings"]
            if finding.source == "network"
        )
        self.assertEqual(duplicate_finding.runtime_instance_count, 2)

        for mutation in ("object", "assessment", "subject"):
            adapter = fixture_adapter(FakeProvider(collected()))
            malformed = integration.collect_linux_listener_policy(
                FakeProvider(collected()), (listener(),), Coverage.COMPLETE,
            )
            if mutation == "object":
                object.__setattr__(malformed, "bindings", (object(),))
            elif mutation == "assessment":
                object.__setattr__(malformed.bindings[0], "assessment", object())
            else:
                object.__setattr__(malformed.bindings[0], "subject", object())
            with self.subTest(mutation=mutation), patch.object(
                adapter, "collect_listener_firewall_policy", return_value=malformed,
            ):
                scan = run_scan(adapter)
            self.assertEqual(
                scan["coverage"]["host_firewall_rule_applicability"], "INCOMPLETE",
            )
            self.assertNotIn("CONFIRMED_REACHABLE", repr(scan))

    def test_scanner_capability_exception_continues(self):
        adapter = fixture_adapter(FakeProvider(collected()))
        with patch.object(adapter, "collect_listener_firewall_policy", side_effect=RuntimeError("CANARY")):
            result = run_scan(adapter)
        self.assertEqual(result["coverage"]["host_firewall_rule_collection"], "INCOMPLETE")
        self.assertNotIn("CANARY", repr(result))

    def test_completeness_alone_does_not_change_scoring(self):
        scans = [self.scan(result, iptables=False)
                 for result in (collected("accept"), NftablesNativeResult(NativeStatus.UNAVAILABLE),
                                NftablesNativeResult(NativeStatus.TIMEOUT))]
        self.assertEqual(scans[0]["score"], scans[1]["score"])
        self.assertEqual(scans[0]["score"], scans[2]["score"])
        self.assertEqual(scans[0]["score"]["scoring_version"], ScoringVersion.V2.value)

    def test_legacy_present_backends_preserve_single_authority_scoring_scope(self):
        usable_legacy = Mock(return_value={
            "available": True, "accessible": True, "policies": {"INPUT": "ACCEPT"},
        })
        fallback_legacy = Mock(return_value={
            "available": True, "accessible": True, "policies": {"INPUT": "ACCEPT"},
        })
        usable = self.scan(collected("accept"), legacy=usable_legacy)
        usable_without_legacy = self.scan(collected("accept"), iptables=False)
        fallback = self.scan(
            NftablesNativeResult(NativeStatus.UNAVAILABLE), legacy=fallback_legacy,
        )

        self.assertEqual(usable_legacy.call_count, 0)
        self.assertEqual(fallback_legacy.call_count, 1)
        usable_firewall = tuple(
            finding.title for finding in usable["findings"]
            if finding.source == "firewall"
        )
        fallback_firewall = tuple(
            finding.title for finding in fallback["findings"]
            if finding.source == "firewall"
        )

        # nft ALLOW is a listener-specific conclusion. Legacy INPUT ACCEPT is
        # a separate host-policy fact, so fallback legitimately adds one scored
        # finding; backend presence alone cannot affect the usable-nft scan.
        self.assertEqual(usable["score"], usable_without_legacy["score"])
        self.assertEqual(usable["score"]["score"], 96)
        self.assertEqual(fallback["score"]["score"], 86)
        self.assertEqual(usable_firewall, ("Firewall technology detected",))
        self.assertEqual(fallback_firewall, (
            "Firewall technology detected", "iptables firewall assessment",
        ))
        self.assertEqual(usable["coverage"]["host_firewall_rule_collection"], "COMPLETE")
        self.assertEqual(usable["coverage"]["iptables_input_policy"], "UNKNOWN")
        self.assertEqual(fallback["coverage"]["host_firewall_rule_collection"], "UNKNOWN")
        self.assertEqual(fallback["coverage"]["iptables_input_policy"], "COMPLETE")
        self.assertEqual(usable["assessment_assurance"]["level"], "PARTIAL")
        self.assertEqual(fallback["assessment_assurance"]["level"], "PARTIAL")
        self.assertEqual(usable["score"]["scoring_version"], ScoringVersion.V2.value)
        self.assertEqual(fallback["score"]["scoring_version"], ScoringVersion.V2.value)

    def test_serialization_privacy_schema_and_history_identity(self):
        reports = []
        for native in (collected(), collected("accept"), collected("accept", (
            {"match": {"op": "==", "left": {"meta": {"key": "iifname"}},
                       "right": INTERFACE}}, {"drop": None}))):
            scan = self.scan(native)
            with tempfile.TemporaryDirectory() as directory:
                path = save_json_report(scan, directory)
                text = Path(path).read_text(encoding="utf-8")
                report = json.loads(text)
            for sentinel in (TABLE, CHAIN, INTERFACE, '"nftables":', "stdout", "stderr",
                             "/usr/sbin/nft", "LD_PRELOAD", "/proc/42/cmdline"):
                self.assertNotIn(sentinel, text)
            self.assertEqual(report["schema_version"], "1.7")
            normalize_report(report)
            reports.append(report)
        for previous, current in zip(reports, reports[1:]):
            comparison = compare_reports(previous, current)
            self.assertEqual(comparison["new_findings"], [])
            self.assertEqual(comparison["resolved_findings"], [])
            self.assertEqual(comparison["uncertain_findings"], [])
            self.assertEqual([f["finding_id"] for f in previous["findings"]],
                             [f["finding_id"] for f in current["findings"]])


if __name__ == "__main__":
    unittest.main()
