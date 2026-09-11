"""Bounded native collection for an nftables ruleset in the current netns.

This dormant Linux-local boundary runs one observational command.  It does not
claim host-wide policy: successful output is only the passive nftables snapshot
visible in the CyberWatchtower process network namespace.  Concurrent policy
mutation remains a residual limitation of the command snapshot.
"""

from __future__ import annotations

import os
import stat
import subprocess
import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Protocol

from .firewall_contracts import LinuxNamespaceAlignment
from .nftables_contracts import MAX_NFT_JSON_BYTES, NftParseResult
from .nftables_parser import parse_nftables_json


NFT_EXECUTABLE_CANDIDATES = (
    "/usr/sbin/nft",
    "/usr/bin/nft",
    "/sbin/nft",
    "/bin/nft",
)
MAX_NFT_STDERR_BYTES = 65_536
NFT_EXECUTION_TIMEOUT_SECONDS = 10.0
NFT_TERMINATION_GRACE_SECONDS = 1.0
_TRUSTED_EXECUTABLE_DIRECTORIES = frozenset({
    "/usr/sbin", "/usr/bin", "/sbin", "/bin",
})
_READ_CHUNK_BYTES = 65_536


class NftablesNativeStatus(str, Enum):
    COLLECTED = "COLLECTED"
    UNAVAILABLE = "UNAVAILABLE"
    UNTRUSTED_EXECUTABLE = "UNTRUSTED_EXECUTABLE"
    AMBIGUOUS_EXECUTABLE = "AMBIGUOUS_EXECUTABLE"
    ACCESS_DENIED = "ACCESS_DENIED"
    TIMEOUT = "TIMEOUT"
    STDOUT_LIMIT_EXCEEDED = "STDOUT_LIMIT_EXCEEDED"
    STDERR_LIMIT_EXCEEDED = "STDERR_LIMIT_EXCEEDED"
    STDERR_PRESENT = "STDERR_PRESENT"
    NONZERO_EXIT = "NONZERO_EXIT"
    EXECUTION_ERROR = "EXECUTION_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"


@dataclass(frozen=True, slots=True)
class NftablesNativeResult:
    status: NftablesNativeStatus
    parse_result: NftParseResult | None = None
    exit_code: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, NftablesNativeStatus):
            raise TypeError("native nftables status must use the closed enum")
        if self.parse_result is not None and not isinstance(self.parse_result, NftParseResult):
            raise TypeError("parse_result must use the frozen nftables parser contract")
        if self.status != NftablesNativeStatus.COLLECTED and self.parse_result is not None:
            raise ValueError("native failures cannot retain parser output")
        if self.status == NftablesNativeStatus.COLLECTED:
            if self.parse_result is None or self.exit_code != 0:
                raise ValueError("collected native output requires parser output and exit zero")
        elif self.status == NftablesNativeStatus.NONZERO_EXIT:
            if not isinstance(self.exit_code, int) or self.exit_code == 0:
                raise ValueError("nonzero native exit requires its numeric exit code")
        elif self.status == NftablesNativeStatus.STDERR_PRESENT:
            if self.exit_code != 0:
                raise ValueError("stderr-present status requires successful native exit")
        elif self.exit_code is not None:
            raise ValueError("this native status cannot retain an exit code")


@dataclass(frozen=True, slots=True)
class _FileRecord:
    candidate: str
    resolved: str
    mode: int
    uid: int


@dataclass(frozen=True, slots=True)
class _ProcessOutcome:
    stdout: bytes = b""
    stderr: bytes = b""
    returncode: int | None = None
    stdout_overflow: bool = False
    stderr_overflow: bool = False
    timed_out: bool = False
    reader_failed: bool = False
    cleanup_failed: bool = False


class _FileSystemProtocol(Protocol):
    def inspect(self, candidate: str) -> _FileRecord | None: ...


class _ProcessProtocol(Protocol):
    stdout: BinaryIO
    stderr: BinaryIO
    returncode: int | None

    def poll(self) -> int | None: ...
    def wait(self, timeout: float | None = None) -> int: ...
    def terminate(self) -> None: ...
    def kill(self) -> None: ...


class _NftablesProcessBackendProtocol(Protocol):
    def launch(self, argv: tuple[str, ...], **kwargs: object) -> _ProcessProtocol: ...


class _LocalFileSystem:
    def inspect(self, candidate: str) -> _FileRecord | None:
        path = Path(candidate)
        if not os.path.lexists(candidate):
            return None
        try:
            resolved = path.resolve(strict=True)
            metadata = resolved.stat()
        except OSError:
            return _FileRecord(candidate, "", 0, -1)
        return _FileRecord(candidate, resolved.as_posix(), metadata.st_mode, metadata.st_uid)


class _SubprocessBackend:
    def launch(self, argv: tuple[str, ...], **kwargs: object) -> _ProcessProtocol:
        return subprocess.Popen(argv, **kwargs)  # type: ignore[return-value]


def _is_trusted(record: _FileRecord) -> bool:
    if not record.resolved or not PurePosixPath(record.resolved).is_absolute():
        return False
    if str(PurePosixPath(record.resolved).parent) not in _TRUSTED_EXECUTABLE_DIRECTORIES:
        return False
    if not stat.S_ISREG(record.mode) or record.uid != 0:
        return False
    if record.mode & (stat.S_IWGRP | stat.S_IWOTH):
        return False
    return bool(record.mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))


def _resolve_executable(filesystem: _FileSystemProtocol) -> tuple[NftablesNativeStatus, str | None]:
    existing = []
    trusted: dict[str, _FileRecord] = {}
    for candidate in NFT_EXECUTABLE_CANDIDATES:
        record = filesystem.inspect(candidate)
        if record is None:
            continue
        existing.append(record)
        if _is_trusted(record):
            trusted.setdefault(record.resolved, record)
    if not existing:
        return NftablesNativeStatus.UNAVAILABLE, None
    if not trusted:
        return NftablesNativeStatus.UNTRUSTED_EXECUTABLE, None
    if len(trusted) != 1:
        return NftablesNativeStatus.AMBIGUOUS_EXECUTABLE, None
    return NftablesNativeStatus.COLLECTED, next(iter(trusted))


@dataclass(slots=True)
class _ReaderState:
    data: bytes = b""
    overflow: bool = False
    failed: bool = False


def _bounded_read(stream: BinaryIO, limit: int, state: _ReaderState,
                  stop: threading.Event) -> None:
    retained = bytearray()
    try:
        while not stop.is_set():
            remaining = limit - len(retained)
            chunk = stream.read(min(_READ_CHUNK_BYTES, remaining + 1))
            if not chunk:
                break
            if len(chunk) > remaining:
                retained.extend(chunk[:remaining])
                state.overflow = True
                stop.set()
                break
            retained.extend(chunk)
    except Exception:
        state.failed = True
        stop.set()
    finally:
        state.data = bytes(retained)


def _stop_and_reap(process: _ProcessProtocol) -> bool:
    try:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=NFT_TERMINATION_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        else:
            process.wait()
        return True
    except Exception:
        try:
            process.kill()
            process.wait()
        except Exception:
            return False
        return True


def _drain_process(process: _ProcessProtocol, *, timeout: float, stdout_limit: int,
                   stderr_limit: int) -> _ProcessOutcome:
    stop = threading.Event()
    stdout_state = _ReaderState()
    stderr_state = _ReaderState()
    readers = (
        threading.Thread(target=_bounded_read, args=(process.stdout, stdout_limit,
                         stdout_state, stop)),
        threading.Thread(target=_bounded_read, args=(process.stderr, stderr_limit,
                         stderr_state, stop)),
    )
    started_readers: list[threading.Thread] = []
    for reader in readers:
        try:
            reader.start()
            started_readers.append(reader)
        except Exception:
            stdout_state.failed = True
            stop.set()
            break

    deadline = time.monotonic() + timeout
    timed_out = False
    if len(started_readers) == len(readers):
        try:
            while process.poll() is None and not stop.is_set():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    stop.set()
                    break
                try:
                    process.wait(timeout=min(remaining, 0.05))
                except subprocess.TimeoutExpired:
                    pass
        except Exception:
            stop.set()
            stdout_state.failed = True

    needs_cleanup = timed_out or stop.is_set()
    cleanup_ok = _stop_and_reap(process) if needs_cleanup else True
    if not needs_cleanup:
        try:
            process.wait()
        except Exception:
            stop.set()
            stdout_state.failed = True
            cleanup_ok = _stop_and_reap(process)
    for reader in started_readers:
        reader.join()
    for stream in (process.stdout, process.stderr):
        try:
            stream.close()
        except Exception:
            cleanup_ok = False
    return _ProcessOutcome(
        stdout=stdout_state.data,
        stderr=stderr_state.data,
        returncode=process.returncode,
        stdout_overflow=stdout_state.overflow,
        stderr_overflow=stderr_state.overflow,
        timed_out=timed_out,
        reader_failed=stdout_state.failed or stderr_state.failed,
        cleanup_failed=not cleanup_ok,
    )


def _collect_with_dependencies(*, filesystem: _FileSystemProtocol,
                               backend: _NftablesProcessBackendProtocol,
                               timeout: float = NFT_EXECUTION_TIMEOUT_SECONDS,
                               stdout_limit: int = MAX_NFT_JSON_BYTES,
                               stderr_limit: int = MAX_NFT_STDERR_BYTES,
                               ) -> NftablesNativeResult:
    resolution, executable = _resolve_executable(filesystem)
    if executable is None:
        return NftablesNativeResult(resolution)
    try:
        process = backend.launch(
            (executable, "-j", "list", "ruleset"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            shell=False,
            close_fds=True,
            cwd="/",
            env={"LANG": "C", "LC_ALL": "C"},
        )
    except PermissionError:
        return NftablesNativeResult(NftablesNativeStatus.ACCESS_DENIED)
    except OSError:
        return NftablesNativeResult(NftablesNativeStatus.EXECUTION_ERROR)
    except Exception:
        return NftablesNativeResult(NftablesNativeStatus.INTERNAL_ERROR)

    try:
        outcome = _drain_process(
            process, timeout=timeout, stdout_limit=stdout_limit,
            stderr_limit=stderr_limit,
        )
    except Exception:
        _stop_and_reap(process)
        return NftablesNativeResult(NftablesNativeStatus.INTERNAL_ERROR)
    if outcome.cleanup_failed or outcome.reader_failed:
        return NftablesNativeResult(NftablesNativeStatus.INTERNAL_ERROR)
    if outcome.timed_out:
        return NftablesNativeResult(NftablesNativeStatus.TIMEOUT)
    if outcome.stdout_overflow:
        return NftablesNativeResult(NftablesNativeStatus.STDOUT_LIMIT_EXCEEDED)
    if outcome.stderr_overflow:
        return NftablesNativeResult(NftablesNativeStatus.STDERR_LIMIT_EXCEEDED)
    if outcome.returncode != 0:
        return NftablesNativeResult(
            NftablesNativeStatus.NONZERO_EXIT, exit_code=outcome.returncode,
        )
    if outcome.stderr:
        return NftablesNativeResult(NftablesNativeStatus.STDERR_PRESENT, exit_code=0)
    try:
        parsed = parse_nftables_json(
            outcome.stdout,
            namespace_alignment=LinuxNamespaceAlignment.SAME_CURRENT_NAMESPACE,
        )
    except Exception:
        return NftablesNativeResult(NftablesNativeStatus.INTERNAL_ERROR)
    return NftablesNativeResult(NftablesNativeStatus.COLLECTED, parsed, 0)


def collect_nftables_ruleset() -> NftablesNativeResult:
    """Collect and normalize the current-process-network-namespace nft ruleset."""

    return _collect_with_dependencies(
        filesystem=_LocalFileSystem(), backend=_SubprocessBackend(),
    )


__all__ = [
    "MAX_NFT_STDERR_BYTES",
    "NFT_EXECUTABLE_CANDIDATES",
    "NFT_EXECUTION_TIMEOUT_SECONDS",
    "NftablesNativeResult",
    "NftablesNativeStatus",
    "collect_nftables_ruleset",
]
