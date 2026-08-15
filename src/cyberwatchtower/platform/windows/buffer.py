"""Bounded table-acquisition contract for future native Windows APIs."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Generic, TypeVar

from .errors import WindowsFailureCode
from .models import WindowsApiResult


MAX_ENDPOINTS = 65_536
MAX_NATIVE_BUFFER_BYTES = 64 * 1024 * 1024
T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class NativeBufferRead(Generic[T]):
    required_size: int = 0
    entries: tuple[T, ...] = ()
    complete: bool = False

    def __post_init__(self) -> None:
        if (
            isinstance(self.required_size, bool)
            or not isinstance(self.required_size, int)
            or self.required_size < 0
        ):
            raise ValueError("native required buffer size is invalid.")
        if not isinstance(self.entries, tuple):
            raise TypeError("native buffer entries must be an immutable tuple.")
        if not isinstance(self.complete, bool):
            raise TypeError("native buffer completion state must be boolean.")


def read_bounded_native_table(
    size_query: Callable[[], int],
    reader: Callable[[int], NativeBufferRead[T]],
    *,
    max_size: int = MAX_NATIVE_BUFFER_BYTES,
    max_attempts: int = 3,
    max_entries: int = MAX_ENDPOINTS,
    sort_key: Callable[[T], object] | None = None,
) -> WindowsApiResult[tuple[T, ...]]:
    """Perform bounded two-call table acquisition without exposing raw buffers."""

    if any(
        isinstance(value, bool) or not isinstance(value, int) or value <= 0
        for value in (max_size, max_attempts, max_entries)
    ):
        raise ValueError("native table limits must be positive integers.")
    try:
        size = size_query()
    except Exception:
        return WindowsApiResult(failure=WindowsFailureCode.INTERNAL_ERROR)
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        return WindowsApiResult(failure=WindowsFailureCode.INVALID_RESULT)
    if size > max_size:
        return WindowsApiResult(failure=WindowsFailureCode.BUFFER_UNSTABLE)

    for _ in range(max_attempts):
        try:
            result = reader(size)
        except Exception:
            return WindowsApiResult(failure=WindowsFailureCode.INTERNAL_ERROR)
        if not isinstance(result, NativeBufferRead):
            return WindowsApiResult(failure=WindowsFailureCode.INVALID_RESULT)
        if result.complete:
            if result.required_size > size or len(result.entries) > max_entries:
                return WindowsApiResult(failure=WindowsFailureCode.INVALID_RESULT)
            if any(item in result.entries[:index]
                   for index, item in enumerate(result.entries)):
                return WindowsApiResult(failure=WindowsFailureCode.INVALID_RESULT)
            entries = (
                tuple(sorted(result.entries, key=sort_key))
                if sort_key is not None else result.entries
            )
            return WindowsApiResult(value=entries)
        if result.entries or result.required_size <= size:
            return WindowsApiResult(failure=WindowsFailureCode.INVALID_RESULT)
        if result.required_size > max_size:
            return WindowsApiResult(failure=WindowsFailureCode.BUFFER_UNSTABLE)
        size = result.required_size
    return WindowsApiResult(failure=WindowsFailureCode.BUFFER_UNSTABLE)
