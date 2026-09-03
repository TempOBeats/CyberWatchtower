"""Fixed subprocess transport for the isolated Windows Firewall helper."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import threading
import time

from .firewall_com_contracts import (
    WindowsComContractError,
    WindowsComFailureCategory,
)
from .firewall_rule_ipc import (
    MAX_WINDOWS_FIREWALL_IPC_RESPONSE_BYTES,
    WindowsFirewallHelperExitCode,
    WindowsFirewallHelperLauncherProtocol,
    WindowsFirewallHelperProcessProtocol,
    WindowsFirewallHelperTerminationState,
    WindowsFirewallHelperWaitResult,
    WindowsFirewallHelperWaitState,
    WindowsFirewallIpcPayload,
    WindowsFirewallIpcPayloadKind,
)
_HELPER_MODULE = "cyberwatchtower.platform.windows.firewall_rule_helper"
_HELPER_PACKAGE_ROOT = str(Path(__file__).resolve().parents[3])
_HELPER_BOOTSTRAP = (
    "import runpy, sys; "
    "sys.path.insert(0, sys.argv.pop()); "
    f"runpy.run_module({_HELPER_MODULE!r}, run_name='__main__', alter_sys=True)"
)
_READ_CHUNK_BYTES = 64 * 1024
_POLL_INTERVAL_SECONDS = 0.01
_REAP_TIMEOUT_SECONDS = 1.0
_MINIMAL_ENVIRONMENT_KEYS = ("SYSTEMROOT", "WINDIR")


class WindowsFirewallSubprocessLauncher:
    """Launch exactly one built-in helper with no caller-controlled process data."""

    __slots__ = ()

    def start(
        self, request: WindowsFirewallIpcPayload
    ) -> WindowsFirewallHelperProcessProtocol:
        if not isinstance(request, WindowsFirewallIpcPayload) \
                or request.kind != WindowsFirewallIpcPayloadKind.REQUEST:
            raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)
        try:
            process = subprocess.Popen(
                _fixed_helper_command(),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                shell=False,
                env=_minimal_environment(),
                close_fds=True,
            )
        except Exception:
            raise WindowsComContractError(
                WindowsComFailureCategory.API_UNAVAILABLE
            ) from None
        owned = _WindowsFirewallSubprocessProcess(process)
        try:
            assert process.stdin is not None
            process.stdin.write(request.consume_inside_boundary())
            process.stdin.close()
        except Exception:
            owned.contain_after_start_failure()
            raise WindowsComContractError(
                WindowsComFailureCategory.COLLECTION_INCOMPLETE
            ) from None
        owned.start_reader()
        return owned


def _fixed_helper_command() -> tuple[str, ...]:
    """Return the closed helper command for installed and source checkouts."""

    return (
        sys.executable,
        "-I",
        "-c",
        _HELPER_BOOTSTRAP,
        _HELPER_PACKAGE_ROOT,
    )


class _WindowsFirewallSubprocessProcess:
    __slots__ = (
        "_buffer", "_oversized", "_process", "_read_error", "_reader",
        "_reader_done",
    )

    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self._process = process
        self._buffer = bytearray()
        self._oversized = threading.Event()
        self._reader_done = threading.Event()
        self._read_error = False
        self._reader: threading.Thread | None = None
    def start_reader(self) -> None:
        if self._reader is not None:
            raise WindowsComContractError(WindowsComFailureCategory.INTERNAL_ERROR)
        self._reader = threading.Thread(
            target=self._read_bounded_stdout,
            name="cyberwatchtower-firewall-helper-reader",
            daemon=True,
        )
        self._reader.start()

    def wait_for_response(self, timeout_ms: int) -> WindowsFirewallHelperWaitResult:
        if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int) \
                or timeout_ms <= 0:
            raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)
        deadline = time.monotonic() + timeout_ms / 1000
        while time.monotonic() < deadline:
            if self._oversized.is_set():
                raise WindowsComContractError(
                    WindowsComFailureCategory.LIMIT_EXCEEDED
                )
            if self._process.poll() is not None:
                remaining = max(0.0, deadline - time.monotonic())
                if not self._reader_done.wait(remaining):
                    return WindowsFirewallHelperWaitResult(
                        WindowsFirewallHelperWaitState.TIMEOUT
                    )
                if self._read_error:
                    raise WindowsComContractError(
                        WindowsComFailureCategory.COLLECTION_INCOMPLETE
                    )
                if self._oversized.is_set():
                    raise WindowsComContractError(
                        WindowsComFailureCategory.LIMIT_EXCEEDED
                    )
                payload = WindowsFirewallIpcPayload(
                    WindowsFirewallIpcPayloadKind.RESPONSE, bytes(self._buffer)
                )
                return WindowsFirewallHelperWaitResult(
                    WindowsFirewallHelperWaitState.RESPONSE, payload
                )
            time.sleep(_POLL_INTERVAL_SECONDS)
        return WindowsFirewallHelperWaitResult(WindowsFirewallHelperWaitState.TIMEOUT)

    def request_termination(self) -> None:
        if self._process.poll() is None:
            self._process.terminate()

    def wait_after_termination(
        self, timeout_ms: int
    ) -> WindowsFirewallHelperTerminationState:
        if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int) \
                or timeout_ms <= 0:
            raise WindowsComContractError(WindowsComFailureCategory.INVALID_RESULT)
        try:
            self._process.wait(timeout=timeout_ms / 1000)
            return WindowsFirewallHelperTerminationState.EXITED
        except subprocess.TimeoutExpired:
            return WindowsFirewallHelperTerminationState.KILL_REQUIRED
        except Exception:
            raise WindowsComContractError(
                WindowsComFailureCategory.INTERNAL_ERROR
            ) from None

    def force_kill(self) -> None:
        if self._process.poll() is None:
            self._process.kill()

    def reap(self) -> WindowsFirewallHelperExitCode:
        try:
            status = self._process.wait(timeout=_REAP_TIMEOUT_SECONDS)
            if self._reader is not None:
                self._reader.join(timeout=1.0)
            if self._process.stdout is not None:
                self._process.stdout.close()
            try:
                return WindowsFirewallHelperExitCode(status)
            except ValueError:
                return WindowsFirewallHelperExitCode.HELPER_FAILURE
        except (OSError, subprocess.SubprocessError):
            raise WindowsComContractError(
                WindowsComFailureCategory.INTERNAL_ERROR
            ) from None

    def contain_after_start_failure(self) -> None:
        try:
            if self._process.stdin is not None and not self._process.stdin.closed:
                self._process.stdin.close()
            if self._process.poll() is None:
                self._process.terminate()
            try:
                self._process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=_REAP_TIMEOUT_SECONDS)
            if self._process.stdout is not None:
                self._process.stdout.close()
        except Exception:
            try:
                self._process.kill()
                self._process.wait(timeout=_REAP_TIMEOUT_SECONDS)
                if self._process.stdout is not None:
                    self._process.stdout.close()
            except Exception:
                pass

    def _read_bounded_stdout(self) -> None:
        try:
            assert self._process.stdout is not None
            while True:
                chunk = self._process.stdout.read(_READ_CHUNK_BYTES)
                if not chunk:
                    break
                remaining = MAX_WINDOWS_FIREWALL_IPC_RESPONSE_BYTES + 1 \
                    - len(self._buffer)
                if remaining > 0:
                    self._buffer.extend(chunk[:remaining])
                if len(self._buffer) > MAX_WINDOWS_FIREWALL_IPC_RESPONSE_BYTES:
                    self._oversized.set()
                # Continue draining to prevent a full pipe from blocking the child.
        except Exception:
            self._read_error = True
        finally:
            self._reader_done.set()


def _minimal_environment() -> dict[str, str]:
    environment = {
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUNBUFFERED": "1",
    }
    for key in _MINIMAL_ENVIRONMENT_KEYS:
        value = os.environ.get(key)
        if value:
            environment[key] = value
    return environment


assert isinstance(WindowsFirewallSubprocessLauncher(),
                  WindowsFirewallHelperLauncherProtocol)
