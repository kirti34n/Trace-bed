"""Injectable clock (PHASE-0 Task 2).

Every worker and every time-dependent test takes a `Clock`. `datetime.now()`
appears exactly once in the codebase — inside `SystemClock` — because Phase 2's
gate is a 30-simulated-day soak and Phase 0's is a feedback event arriving two
simulated days after its trace. Neither is runnable against a wall clock.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from typing import Protocol, runtime_checkable

__all__ = ["Clock", "FakeClock", "SystemClock"]


@runtime_checkable
class Clock(Protocol):
    def now(self) -> datetime:
        """Timezone-aware UTC instant."""
        ...

    def now_ms(self) -> int:
        """Milliseconds since the Unix epoch — for UUIDv7 minting."""
        ...

    def monotonic_ms(self) -> float:
        """Monotonic milliseconds — for latency budgets, never for timestamps."""
        ...


class SystemClock:
    """The only place `datetime.now` is called."""

    __slots__ = ()

    def now(self) -> datetime:
        return datetime.now(UTC)

    def now_ms(self) -> int:
        import time

        return time.time_ns() // 1_000_000

    def monotonic_ms(self) -> float:
        import time

        return time.monotonic_ns() / 1_000_000.0


class FakeClock:
    """Deterministic clock. `advance()` is the only way time passes."""

    __slots__ = ("_lock", "_mono_ms", "_now")

    def __init__(self, start: datetime | None = None) -> None:
        if start is None:
            start = datetime(2026, 1, 1, tzinfo=UTC)
        if start.tzinfo is None:
            raise ValueError("FakeClock requires a timezone-aware start instant")
        self._now = start.astimezone(UTC)
        self._mono_ms = 0.0
        self._lock = threading.Lock()

    def now(self) -> datetime:
        with self._lock:
            return self._now

    def now_ms(self) -> int:
        with self._lock:
            return int(self._now.timestamp() * 1000)

    def monotonic_ms(self) -> float:
        with self._lock:
            return self._mono_ms

    def advance(self, delta: timedelta | None = None, **kwargs: float) -> datetime:
        """`advance(timedelta(days=2))` or `advance(days=2)` / `advance(ms=150)`."""
        if delta is None:
            ms = float(kwargs.pop("ms", 0.0))
            delta = timedelta(**kwargs) + timedelta(milliseconds=ms)
        if delta < timedelta(0):
            raise ValueError("FakeClock cannot move backwards")
        with self._lock:
            self._now = self._now + delta
            self._mono_ms += delta.total_seconds() * 1000.0
            return self._now

    def set(self, instant: datetime) -> None:
        """Absolute reset. Only for fixture setup, never mid-scenario."""
        if instant.tzinfo is None:
            raise ValueError("FakeClock requires a timezone-aware instant")
        with self._lock:
            self._now = instant.astimezone(UTC)
