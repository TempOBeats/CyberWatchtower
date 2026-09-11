import inspect
import json
import os
import stat
import subprocess
import threading
import unittest
from dataclasses import fields
from unittest.mock import patch

from cyberwatchtower.platform.linux.firewall_contracts import LinuxNamespaceAlignment
from cyberwatchtower.platform.linux.nftables_contracts import NftParseStatus
from cyberwatchtower.platform.linux.nftables_parser import parse_nftables_json
from cyberwatchtower.platform.linux.nftables_native import (
    MAX_NFT_STDERR_BYTES,
    NFT_EXECUTABLE_CANDIDATES,
    NftablesNativeResult,
    NftablesNativeStatus,
    _FileRecord,
    _ProcessOutcome,
    _collect_with_dependencies,
    _drain_process,
    collect_nftables_ruleset,
)


VALID_JSON = json.dumps({"nftables": []}).encode()


class FakeFileSystem:
    def __init__(self, records=(), *, path_value="malicious"):
        self.records = {record.candidate: record for record in records}
        self.path_value = path_value
        self.inspected = []

    def inspect(self, candidate):
        self.inspected.append(candidate)
        return self.records.get(candidate)


def trusted(candidate="/usr/sbin/nft", resolved="/usr/sbin/nft"):
    return _FileRecord(candidate, resolved, stat.S_IFREG | 0o755, 0)


class FakeProcess:
    def __init__(self, stdout=b"", stderr=b"", returncode=0, *, timeout=False,
                 terminate_exits=True):
        self.stdout = FakeStream(stdout)
        self.stderr = FakeStream(stderr)
        self.returncode = None if timeout else returncode
        self.final_returncode = returncode
        self.timeout = timeout
        self.terminate_exits = terminate_exits
        self.terminated = 0
        self.killed = 0
        self.waited = []

    def wait(self, timeout=None):
        self.waited.append(timeout)
        if self.returncode is not None:
            return self.returncode
        if self.terminated and self.terminate_exits:
            self.returncode = self.final_returncode
            return self.returncode
        if self.killed:
            self.returncode = self.final_returncode
            return self.returncode
        if timeout is not None:
            threading.Event().wait(timeout)
        raise subprocess.TimeoutExpired("nft", timeout)

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated += 1

    def kill(self):
        self.killed += 1


class FakeStream:
    def __init__(self, value):
        self.value = value
        self.offset = 0
        self.closed = False
        self.read_attempts = []
        self.read_sizes = []

    def read(self, size=-1):
        self.read_attempts.append(size)
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or size <= 0
            or size > 65_536
        ):
            raise AssertionError("every pipe read must have a finite positive bound")
        self.read_sizes.append(size)
        if self.offset >= len(self.value):
            return b""
        end = len(self.value) if size < 0 else min(len(self.value), self.offset + size)
        chunk = self.value[self.offset:end]
        self.offset = end
        return chunk

    def close(self):
        self.closed = True


class FailingStream(FakeStream):
    def read(self, size=-1):
        raise RuntimeError("private stream failure")


class BlockingStream(FakeStream):
    def __init__(self, value=b""):
        super().__init__(value)
        self.started = threading.Event()
        self.release = threading.Event()
        self.eof_seen = threading.Event()

    def read(self, size=-1):
        self.started.set()
        if not self.release.wait(timeout=2):
            raise AssertionError("test did not release controlled reader")
        chunk = super().read(size)
        if not chunk:
            self.eof_seen.set()
        return chunk


class FailingAfterSiblingStartsStream(FakeStream):
    def __init__(self, sibling):
        super().__init__(b"")
        self.sibling = sibling

    def read(self, size=-1):
        if not self.sibling.started.wait(timeout=1):
            raise AssertionError("sibling reader did not start")
        raise RuntimeError("private stream failure")


class DataAfterSiblingStartsStream(FakeStream):
    def __init__(self, value, sibling):
        super().__init__(value)
        self.sibling = sibling

    def read(self, size=-1):
        if not self.sibling.started.wait(timeout=1):
            raise AssertionError("sibling reader did not start")
        return super().read(size)


class CoordinatedStream(FakeStream):
    def __init__(self, value, barrier):
        super().__init__(value)
        self.barrier = barrier
        self.first = True

    def read(self, size=-1):
        if self.first:
            self.first = False
            self.barrier.wait(timeout=1)
        return super().read(size)


class CompletionTrackingThread(threading.Thread):
    instances = []

    def __init__(self, *, target, args):
        self.target_completed = threading.Event()
        self.join_completed = threading.Event()

        def tracked_target():
            try:
                target(*args)
            finally:
                self.target_completed.set()

        super().__init__(target=tracked_target)
        self.instances.append(self)

    def join(self, timeout=None):
        super().join(timeout)
        if not self.is_alive():
            self.join_completed.set()


class ObservableReaderState:
    instances = []
    overflow_observed = threading.Event()

    def __init__(self):
        self.data = b""
        self._overflow = False
        self.failed = False
        self.instances.append(self)

    @property
    def overflow(self):
        return self._overflow

    @overflow.setter
    def overflow(self, value):
        self._overflow = value
        if value:
            self.overflow_observed.set()


class FakeBackend:
    def __init__(self, process=None, error=None):
        self.process = process or FakeProcess(VALID_JSON)
        self.error = error
        self.calls = []

    def launch(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if self.error:
            raise self.error
        return self.process


def collect(*, records=(trusted(),), process=None, error=None, stdout_limit=8_388_608,
            stderr_limit=65_536, timeout=0.01):
    fs = FakeFileSystem(records)
    backend = FakeBackend(process, error)
    result = _collect_with_dependencies(
        filesystem=fs, backend=backend, timeout=timeout,
        stdout_limit=stdout_limit, stderr_limit=stderr_limit,
    )
    return result, fs, backend


class ResolverTests(unittest.TestCase):
    def test_unavailable_and_frozen_candidates_without_path_lookup(self):
        result, fs, backend = collect(records=())
        self.assertEqual(result.status, NftablesNativeStatus.UNAVAILABLE)
        self.assertEqual(tuple(fs.inspected), NFT_EXECUTABLE_CANDIDATES)
        self.assertEqual(backend.calls, [])
        self.assertNotIn(os.environ.get("PATH", ""), fs.inspected)

    def test_one_trusted_candidate_and_duplicate_symlinks_select_once(self):
        records = (trusted(), trusted("/sbin/nft", "/usr/sbin/nft"))
        result, _, backend = collect(records=records)
        self.assertEqual(result.status, NftablesNativeStatus.COLLECTED)
        self.assertEqual(backend.calls[0][0][0], "/usr/sbin/nft")

    def test_distinct_trusted_targets_are_ambiguous(self):
        result, _, backend = collect(records=(trusted(), trusted("/usr/bin/nft", "/usr/bin/nft")))
        self.assertEqual(result.status, NftablesNativeStatus.AMBIGUOUS_EXECUTABLE)
        self.assertEqual(backend.calls, [])

    def test_untrusted_candidate_variants(self):
        cases = (
            _FileRecord("/usr/sbin/nft", "/usr/sbin/nft", stat.S_IFREG | 0o755, 1000),
            _FileRecord("/usr/sbin/nft", "/usr/sbin/nft", stat.S_IFREG | 0o775, 0),
            _FileRecord("/usr/sbin/nft", "/usr/sbin/nft", stat.S_IFREG | 0o757, 0),
            _FileRecord("/usr/sbin/nft", "/usr/sbin/nft", stat.S_IFDIR | 0o755, 0),
            _FileRecord("/usr/sbin/nft", "/usr/sbin/nft", stat.S_IFREG | 0o644, 0),
            _FileRecord("/usr/sbin/nft", "/tmp/nft", stat.S_IFREG | 0o755, 0),
        )
        for record in cases:
            with self.subTest(record=record):
                result, _, backend = collect(records=(record,))
                self.assertEqual(result.status, NftablesNativeStatus.UNTRUSTED_EXECUTABLE)
                self.assertEqual(backend.calls, [])

    def test_symlink_resolution_is_judged_on_final_target(self):
        accepted, _, _ = collect(records=(trusted("/sbin/nft", "/usr/sbin/nft"),))
        rejected, _, _ = collect(records=(
            _FileRecord("/sbin/nft", "/tmp/nft", stat.S_IFREG | 0o755, 0),
        ))
        self.assertEqual(accepted.status, NftablesNativeStatus.COLLECTED)
        self.assertEqual(rejected.status, NftablesNativeStatus.UNTRUSTED_EXECUTABLE)


class CommandAndResultTests(unittest.TestCase):
    def test_portable_fake_path_never_calls_real_popen(self):
        with patch(
            "cyberwatchtower.platform.linux.nftables_native.subprocess.Popen",
            side_effect=AssertionError("portable test attempted native execution"),
        ) as real_popen:
            result, _, backend = collect()
        self.assertEqual(result.status, NftablesNativeStatus.COLLECTED)
        self.assertEqual(len(backend.calls), 1)
        real_popen.assert_not_called()

    def test_public_api_accepts_no_security_configuration(self):
        self.assertEqual(tuple(inspect.signature(collect_nftables_ruleset).parameters), ())

    def test_fixed_binary_launch_contract(self):
        result, _, backend = collect()
        argv, options = backend.calls[0]
        self.assertEqual(argv, ("/usr/sbin/nft", "-j", "list", "ruleset"))
        self.assertIs(options["stdin"], subprocess.DEVNULL)
        self.assertIs(options["stdout"], subprocess.PIPE)
        self.assertIs(options["stderr"], subprocess.PIPE)
        self.assertFalse(options["text"])
        self.assertFalse(options["shell"])
        self.assertTrue(options["close_fds"])
        self.assertEqual(options["cwd"], "/")
        self.assertEqual(result.status, NftablesNativeStatus.COLLECTED)

    def test_result_is_private_and_closed(self):
        self.assertEqual([item.name for item in fields(NftablesNativeResult)],
                         ["status", "parse_result", "exit_code"])
        self.assertEqual(set(NftablesNativeStatus.__members__), {
            "COLLECTED", "UNAVAILABLE", "UNTRUSTED_EXECUTABLE",
            "AMBIGUOUS_EXECUTABLE", "ACCESS_DENIED", "TIMEOUT",
            "STDOUT_LIMIT_EXCEEDED", "STDERR_LIMIT_EXCEEDED", "STDERR_PRESENT",
            "NONZERO_EXIT", "EXECUTION_ERROR", "INTERNAL_ERROR",
        })
        with self.assertRaises(Exception):
            NftablesNativeResult(NftablesNativeStatus.UNAVAILABLE).status = "changed"
        with self.assertRaises(ValueError):
            NftablesNativeResult(NftablesNativeStatus.COLLECTED)
        with self.assertRaises(ValueError):
            NftablesNativeResult(NftablesNativeStatus.NONZERO_EXIT, exit_code=0)

    def test_clean_success_attaches_same_namespace_only_in_orchestrator(self):
        result, _, backend = collect()
        self.assertEqual(result.status, NftablesNativeStatus.COLLECTED)
        self.assertEqual(result.parse_result.status, NftParseStatus.SUCCESS)
        self.assertEqual(result.parse_result.snapshot.namespace_alignment,
                         LinuxNamespaceAlignment.SAME_CURRENT_NAMESPACE)
        self.assertFalse(hasattr(backend.process, "namespace_alignment"))
        self.assertNotIn("namespace", {item.name for item in fields(_ProcessOutcome)})
        self.assertNotIn("namespace", {item.name for item in fields(_FileRecord)})

    def test_parser_failures_remain_collected_native_results(self):
        cases = (
            (b"not-json", NftParseStatus.INVALID_JSON),
            (json.dumps({"nftables": [{"future": {}}]}).encode(),
             NftParseStatus.UNSUPPORTED_SEMANTICS),
        )
        for raw, expected in cases:
            with self.subTest(expected=expected):
                result, _, _ = collect(process=FakeProcess(raw))
                self.assertEqual(result.status, NftablesNativeStatus.COLLECTED)
                self.assertEqual(result.parse_result.status, expected)

    def test_launch_errors_are_closed_and_have_no_parser_result(self):
        cases = (
            (PermissionError(), NftablesNativeStatus.ACCESS_DENIED),
            (FileNotFoundError(), NftablesNativeStatus.EXECUTION_ERROR),
            (OSError(), NftablesNativeStatus.EXECUTION_ERROR),
            (RuntimeError("private"), NftablesNativeStatus.INTERNAL_ERROR),
        )
        for error, expected in cases:
            with self.subTest(expected=expected):
                result, _, _ = collect(error=error)
                self.assertEqual(result.status, expected)
                self.assertIsNone(result.parse_result)

    def test_reader_failure_is_internal_and_never_reaches_parser(self):
        process = FakeProcess(VALID_JSON)
        process.stdout = FailingStream(b"")
        result, _, _ = collect(process=process)
        self.assertEqual(result.status, NftablesNativeStatus.INTERNAL_ERROR)
        self.assertIsNone(result.parse_result)

    def test_nonzero_exits_preserve_only_numeric_code(self):
        for code in (1, 23, -9):
            with self.subTest(code=code):
                result, _, _ = collect(process=FakeProcess(b"secret", b"private", code))
                self.assertEqual(result, NftablesNativeResult(
                    NftablesNativeStatus.NONZERO_EXIT, exit_code=code))


class StreamAndCleanupTests(unittest.TestCase):
    def run_collect_in_thread(self, process, **kwargs):
        result = []
        worker = threading.Thread(
            target=lambda: result.append(collect(process=process, **kwargs)[0])
        )
        worker.start()
        return worker, result

    def test_frozen_limits_detect_the_first_overflow_byte_incrementally(self):
        self.assertEqual(MAX_NFT_STDERR_BYTES, 65_536)
        exact_process = FakeProcess(b"x" * 8_388_608)
        exact_result, _, _ = collect(process=exact_process, timeout=1)
        stdout_process = FakeProcess(b"x" * 8_388_609)
        stdout_result, _, _ = collect(process=stdout_process, timeout=1)
        stderr_process = FakeProcess(VALID_JSON, b"x" * 65_537)
        stderr_result, _, _ = collect(process=stderr_process, timeout=1)
        self.assertEqual(exact_result.status, NftablesNativeStatus.COLLECTED)
        self.assertEqual(exact_result.parse_result.status, NftParseStatus.INVALID_JSON)
        self.assertEqual(stdout_result.status,
                         NftablesNativeStatus.STDOUT_LIMIT_EXCEEDED)
        self.assertEqual(stderr_result.status,
                         NftablesNativeStatus.STDERR_LIMIT_EXCEEDED)
        self.assertLessEqual(max(stdout_process.stdout.read_sizes), 65_536)
        self.assertLessEqual(max(stderr_process.stderr.read_sizes), 65_536)
        for stream in (
            exact_process.stdout,
            stdout_process.stdout,
            stderr_process.stderr,
        ):
            self.assertTrue(stream.read_sizes)
            self.assertTrue(all(
                isinstance(size, int) and not isinstance(size, bool)
                and 0 < size <= 65_536
                for size in stream.read_sizes
            ))

    def test_actual_readers_reject_oversized_stdout_and_stderr_requests(self):
        cases = (
            ("stdout", {"stderr_limit": 65_535}),
            ("stderr", {"stdout_limit": 65_535}),
        )
        for stream_name, limits in cases:
            with self.subTest(stream=stream_name):
                process = FakeProcess(VALID_JSON)
                with patch(
                    "cyberwatchtower.platform.linux.nftables_native."
                    "_READ_CHUNK_BYTES",
                    65_537,
                ):
                    result, _, _ = collect(process=process, timeout=1, **limits)
                stream = getattr(process, stream_name)
                self.assertIn(65_537, stream.read_attempts)
                self.assertNotIn(65_537, stream.read_sizes)
                self.assertEqual(result.status, NftablesNativeStatus.INTERNAL_ERROR)
                self.assertIsNone(result.parse_result)

    def test_stdout_exact_limit_and_limit_plus_one(self):
        accepted, _, _ = collect(process=FakeProcess(b"x" * 32), stdout_limit=32)
        rejected_process = FakeProcess(b"x" * 33)
        rejected, _, _ = collect(process=rejected_process, stdout_limit=32)
        self.assertEqual(accepted.status, NftablesNativeStatus.COLLECTED)
        self.assertEqual(accepted.parse_result.status, NftParseStatus.INVALID_JSON)
        self.assertEqual(rejected.status, NftablesNativeStatus.STDOUT_LIMIT_EXCEEDED)
        self.assertIsNone(rejected.parse_result)
        self.assertTrue(rejected_process.waited)

    def test_stderr_boundaries(self):
        cases = ((b"", NftablesNativeStatus.COLLECTED),
                 (b"x", NftablesNativeStatus.STDERR_PRESENT),
                 (b"x" * 16, NftablesNativeStatus.STDERR_PRESENT),
                 (b"x" * 17, NftablesNativeStatus.STDERR_LIMIT_EXCEEDED))
        for raw, expected in cases:
            with self.subTest(size=len(raw)):
                result, _, _ = collect(process=FakeProcess(VALID_JSON, raw), stderr_limit=16)
                self.assertEqual(result.status, expected)
                if expected is not NftablesNativeStatus.COLLECTED:
                    self.assertIsNone(result.parse_result)

    def test_timeout_terminate_success_and_kill_fallback_are_reaped(self):
        graceful = FakeProcess(timeout=True, returncode=0, terminate_exits=True)
        forced = FakeProcess(timeout=True, returncode=0, terminate_exits=False)
        for process, kills in ((graceful, 0), (forced, 1)):
            with self.subTest(kills=kills):
                result, _, _ = collect(process=process, timeout=0)
                self.assertEqual(result.status, NftablesNativeStatus.TIMEOUT)
                self.assertEqual(process.terminated, 1)
                self.assertEqual(process.killed, kills)
                self.assertIsNotNone(process.returncode)
                self.assertIsNone(result.parse_result)

    def test_timeout_does_not_return_while_reader_remains_blocked(self):
        process = FakeProcess(timeout=True, terminate_exits=True)
        blocked = BlockingStream()
        process.stdout = blocked
        with patch(
            "cyberwatchtower.platform.linux.nftables_native."
            "NFT_TERMINATION_GRACE_SECONDS",
            0.01,
        ):
            worker, results = self.run_collect_in_thread(process, timeout=0)
            self.assertTrue(blocked.started.wait(timeout=1))
            worker.join(timeout=0.05)
            self.assertTrue(worker.is_alive())
            self.assertEqual(results, [])
            blocked.release.set()
            worker.join(timeout=1)
        self.assertFalse(worker.is_alive())
        self.assertTrue(blocked.eof_seen.is_set())
        self.assertEqual(results[0].status, NftablesNativeStatus.TIMEOUT)

    def test_limit_cleanup_uses_terminate_kill_and_reap(self):
        for stream in ("stdout", "stderr"):
            process = FakeProcess(timeout=True, terminate_exits=False)
            setattr(process, stream, FakeStream(b"x" * 18))
            result, _, _ = collect(process=process, stdout_limit=17, stderr_limit=17)
            with self.subTest(stream=stream):
                self.assertIn(result.status, {
                    NftablesNativeStatus.STDOUT_LIMIT_EXCEEDED,
                    NftablesNativeStatus.STDERR_LIMIT_EXCEEDED,
                })
                self.assertEqual((process.terminated, process.killed), (1, 1))
                self.assertIsNotNone(process.returncode)

    def test_overflow_and_reader_failure_wait_for_blocked_sibling(self):
        for failure in ("overflow", "reader"):
            with self.subTest(failure=failure):
                blocked = BlockingStream()
                process = FakeProcess(timeout=True, terminate_exits=True)
                process.stderr = blocked
                if failure == "overflow":
                    process.stdout = DataAfterSiblingStartsStream(b"xx", blocked)
                    arguments = {"stdout_limit": 1, "timeout": 1}
                    expected = NftablesNativeStatus.STDOUT_LIMIT_EXCEEDED
                else:
                    process.stdout = FailingAfterSiblingStartsStream(blocked)
                    arguments = {}
                    expected = NftablesNativeStatus.INTERNAL_ERROR
                ObservableReaderState.instances = []
                ObservableReaderState.overflow_observed = threading.Event()
                with (
                    patch(
                        "cyberwatchtower.platform.linux.nftables_native."
                        "NFT_TERMINATION_GRACE_SECONDS",
                        0.01,
                    ),
                    patch(
                        "cyberwatchtower.platform.linux.nftables_native._ReaderState",
                        ObservableReaderState,
                    ),
                ):
                    try:
                        worker, results = self.run_collect_in_thread(process, **arguments)
                        self.assertTrue(blocked.started.wait(timeout=1))
                        if failure == "overflow":
                            self.assertTrue(
                                ObservableReaderState.overflow_observed.wait(timeout=1)
                            )
                        worker.join(timeout=0.05)
                        self.assertTrue(worker.is_alive())
                        self.assertEqual(results, [])
                    finally:
                        blocked.release.set()
                    worker.join(timeout=1)
                self.assertFalse(worker.is_alive())
                self.assertTrue(blocked.eof_seen.is_set())
                self.assertEqual(results[0].status, expected)

    def test_parser_handoff_occurs_after_reader_targets_and_joins_complete(self):
        process = FakeProcess(VALID_JSON)
        stdout = BlockingStream(VALID_JSON)
        stderr = BlockingStream()
        process.stdout = stdout
        process.stderr = stderr
        stdout.release.set()
        stderr.release.set()

        def checked_parser(*args, **kwargs):
            self.assertTrue(stdout.eof_seen.is_set())
            self.assertTrue(stderr.eof_seen.is_set())
            self.assertEqual(len(CompletionTrackingThread.instances), 2)
            self.assertTrue(all(
                reader.target_completed.is_set()
                for reader in CompletionTrackingThread.instances
            ))
            self.assertTrue(all(
                reader.join_completed.is_set()
                for reader in CompletionTrackingThread.instances
            ))
            return parse_nftables_json(*args, **kwargs)

        CompletionTrackingThread.instances = []
        with (
            patch(
                "cyberwatchtower.platform.linux.nftables_native.threading.Thread",
                CompletionTrackingThread,
            ),
            patch(
                "cyberwatchtower.platform.linux.nftables_native.parse_nftables_json",
                side_effect=checked_parser,
            ),
        ):
            try:
                result, _, _ = collect(process=process)
            finally:
                stdout.release.set()
                stderr.release.set()
        self.assertEqual(result.status, NftablesNativeStatus.COLLECTED)

    def test_both_streams_are_started_concurrently(self):
        process = FakeProcess()
        barrier = threading.Barrier(2)
        process.stdout = CoordinatedStream(VALID_JSON, barrier)
        process.stderr = CoordinatedStream(b"", barrier)
        outcome = _drain_process(process, timeout=1, stdout_limit=1024, stderr_limit=1024)
        self.assertEqual(outcome.stdout, VALID_JSON)

    def test_streams_are_not_cross_wired(self):
        success, _, _ = collect(process=FakeProcess(VALID_JSON, b""))
        wrong_stream, _, _ = collect(process=FakeProcess(b"", VALID_JSON))
        self.assertEqual(success.status, NftablesNativeStatus.COLLECTED)
        self.assertEqual(wrong_stream.status, NftablesNativeStatus.STDERR_PRESENT)


if __name__ == "__main__":
    unittest.main()
