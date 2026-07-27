"""Typed identifiers (PHASE-0 Task 3).

These are *distinct types*, not aliases. `ProjectId` and `RunId` are not
interchangeable under mypy strict, which is what stops a project scope being
silently satisfied by whatever UUID happened to be in scope. Every repository
builder takes `ProjectId` as its first parameter (PLAN.md §2 invariant 4), and
that only means anything if the type cannot be produced by accident.

Also home to UUIDv7 minting: `retrieve()` mints the `run_id` server-side so
credit assignment works with zero host support (PLAN.md §3).
"""

from __future__ import annotations

import os
import threading
import time
from typing import Any, ClassVar, Self
from uuid import UUID

__all__ = [
    "AgentTypeId",
    "MemoryId",
    "PrincipalId",
    "ProjectId",
    "RunId",
    "TypedId",
    "mint_memory_id",
    "mint_run_id",
    "uuid7",
    "uuid7_timestamp_ms",
]


class TypedId:
    """Base for UUID-backed identifiers. Subclasses do not compare equal."""

    __slots__ = ("_value",)
    label: ClassVar[str] = "id"

    def __init__(self, value: UUID | str) -> None:
        # Widened to `object` deliberately: the declared parameter type already
        # excludes TypedId, so mypy proves the branch unreachable and drops it —
        # but the whole point of this guard is the *untyped* caller, the one who
        # writes ProjectId(some_run_id) with a `# type: ignore` or from a dict.
        # Type-level distinctness is the first line; this is the second.
        raw: object = value
        if isinstance(raw, TypedId):
            raise TypeError(
                f"{type(self).__name__} cannot wrap {type(raw).__name__} — "
                "identifiers are distinct types, not interchangeable UUIDs"
            )
        if isinstance(value, str):
            try:
                value = UUID(value)
            except ValueError as exc:
                raise ValueError(f"{type(self).__name__}: not a UUID: {value!r}") from exc
        if not isinstance(value, UUID):
            raise TypeError(f"{type(self).__name__}: expected UUID or str, got {type(value).__name__}")
        object.__setattr__(self, "_value", value)

    @property
    def value(self) -> UUID:
        return self._value  # type: ignore[attr-defined,no-any-return]

    @classmethod
    def parse(cls, value: UUID | str) -> Self:
        return cls(value)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError(f"{type(self).__name__} is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError(f"{type(self).__name__} is immutable")

    def __eq__(self, other: object) -> bool:
        # Cross-type comparison is False, never a coincidence.
        if type(other) is not type(self):
            return NotImplemented if not isinstance(other, TypedId) else False
        return self.value == other.value

    def __hash__(self) -> int:
        return hash((type(self).__name__, self.value))

    def __str__(self) -> str:
        return str(self.value)

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.value})"

    # psycopg adapts UUID natively; expose it for parameter binding.
    def __conform__(self, proto: object) -> object:  # pragma: no cover - driver hook
        return self.value


class ProjectId(TypedId):
    """The wall. Derived server-side from the authenticated principal, never from a caller."""

    __slots__ = ()
    label = "project_id"


class RunId(TypedId):
    """UUIDv7, minted by the service at `retrieve()`. Time-ordered by construction."""

    __slots__ = ()
    label = "run_id"


class PrincipalId(TypedId):
    __slots__ = ()
    label = "principal_id"


class MemoryId(TypedId):
    __slots__ = ()
    label = "memory_id"


class AgentTypeId(TypedId):
    __slots__ = ()
    label = "agent_type_id"


# --------------------------------------------------------------------------- #
# UUIDv7 (RFC 9562 §5.7) with the method-2 monotonic counter in rand_a.
# Python 3.13 has no uuid.uuid7; 3.14 does. Implemented here so run ids are
# time-ordered even for several mints inside the same millisecond.
# --------------------------------------------------------------------------- #

_lock = threading.Lock()
_last_ms: int = -1
_counter: int = 0
_COUNTER_MAX = 0xFFF  # rand_a is 12 bits


def uuid7(*, now_ms: int | None = None) -> UUID:
    """A time-ordered UUIDv7. `now_ms` is for tests driven by a FakeClock."""
    global _last_ms, _counter

    with _lock:
        ms = now_ms if now_ms is not None else time.time_ns() // 1_000_000
        if ms == _last_ms:
            _counter += 1
            if _counter > _COUNTER_MAX:
                # Counter exhausted inside one millisecond: roll into the next.
                ms += 1
                _last_ms = ms
                _counter = 0
        elif ms < _last_ms:
            # Clock moved backwards (NTP step, or a FakeClock rewind in a test).
            # Keep monotonicity: stay on the last millisecond and advance the counter.
            _counter += 1
            if _counter > _COUNTER_MAX:
                _last_ms += 1
                _counter = 0
            ms = _last_ms
        else:
            _last_ms = ms
            _counter = 0
        seq = _counter

    rand_b = int.from_bytes(os.urandom(8), "big") & ((1 << 62) - 1)

    value = (ms & ((1 << 48) - 1)) << 80
    value |= 0x7 << 76
    value |= (seq & _COUNTER_MAX) << 64
    value |= 0b10 << 62
    value |= rand_b
    return UUID(int=value)


def uuid7_timestamp_ms(value: UUID) -> int:
    """Extract the embedded millisecond timestamp. Raises for non-v7 input."""
    if value.version != 7:
        raise ValueError(f"not a UUIDv7 (version={value.version})")
    return value.int >> 80


def mint_run_id(*, now_ms: int | None = None) -> RunId:
    return RunId(uuid7(now_ms=now_ms))


def mint_memory_id(*, now_ms: int | None = None) -> MemoryId:
    return MemoryId(uuid7(now_ms=now_ms))
