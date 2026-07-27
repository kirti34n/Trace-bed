"""RingBuffer — the in-process, lock-protected queue behind every SDK call.

PHASE0-CONTRACT.md §10 / PHASE-0.md Task 13. This is the entire mechanism
that makes invariant 5 (async writes) and half of invariant 2 (fail-open)
true: `TracebedClient.trace()`/`feedback()` do a dict-build and an
`append()` on the caller's thread and nothing else. Every other piece of
work — HTTP, retries, backoff — happens on the background flusher thread,
which drains this buffer. That split is why `append()` must be the only
synchronous primitive here: it takes one lock, does O(1) work, and returns.

Overflow policy is drop-oldest (D-033): a full buffer that blocked or raised
would turn a Tracebed outage into an outage of the *host* application, which
is exactly the failure mode invariant 2 exists to prevent. Silent unbounded
growth would be worse (an OOM of the host process), so the alternative is a
bounded ring with a visible, monotonically increasing drop counter instead.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass
from threading import Lock
from typing import Literal

from tracebed.domain.ids import RunId

__all__ = ["BufferedItem", "FlushReport", "RingBuffer"]

ItemKind = Literal["trace", "feedback", "proposal"]


@dataclass(frozen=True, slots=True)
class FlushReport:
    """What one `flush()` call accomplished (PHASE0-CONTRACT.md §10)."""

    sent: int
    dropped: int


@dataclass(frozen=True, slots=True)
class BufferedItem:
    """One ring-buffer slot, as handed back by `drain()`.

    `seq` is populated only for `kind == "trace"` (C-23: the per-run trace
    sequence, assigned here at enqueue so it survives any reordering the
    background flusher or the wire introduces later). `feedback`/`proposal`
    items have no sequence concept — `FeedbackEvent.event_id` and the lack of
    ordering requirements for proposals make one unnecessary — so `seq` is
    `None` for those kinds.
    """

    run_id: RunId
    kind: ItemKind
    seq: int | None
    body: Mapping[str, object]


class RingBuffer:
    """Fixed-capacity, thread-safe, drop-oldest buffer with per-run trace `seq`.

    A single `Lock` guards both the deque and the per-run seq counters so
    `append()` is atomic: the seq assignment and the drop-oldest decision for
    the same call never interleave with another thread's `append()`/`drain()`.
    Because the critical section is pure in-memory bookkeeping (no I/O, no
    serialization), holding the lock costs nanoseconds, not milliseconds —
    which is what keeps `TracebedClient.trace()`/`feedback()` under the 1ms
    p99 budget even under concurrent callers (PHASE-0 Task 13's thread-safety
    test: N threads tracing the same run must still produce a gapless seq).
    """

    __slots__ = ("_capacity", "_dropped_total", "_items", "_lock", "_run_seq")

    def __init__(self, capacity: int) -> None:
        if capacity < 1:
            raise ValueError("RingBuffer capacity must be >= 1")
        self._capacity = capacity
        self._items: deque[BufferedItem] = deque()
        # Deliberately UNBOUNDED, unlike every other collection in the SDK: an
        # LRU here would evict a live run's counter and restart its seq at 0,
        # and the trace writer dedups on (run_id, seq) — so eviction would not
        # cost memory, it would silently discard real trace events and leave a
        # gap the completeness sweeper reads as `incomplete`. Growth is one
        # small entry per distinct run for the client's lifetime; the contract
        # (§10) gives no session-end hook to prune it, so this is a reported
        # gap, not a bug traded for a worse one.
        self._run_seq: dict[RunId, int] = {}
        self._dropped_total = 0
        self._lock = Lock()

    def append(self, run_id: RunId, kind: ItemKind, body: Mapping[str, object]) -> int:
        """Append one item; returns the assigned trace `seq`, or -1 for non-trace kinds.

        Drop-oldest happens here, inside the same critical section as the seq
        assignment, so a dropped item and a newly-admitted item are never
        computed from an inconsistent snapshot of the buffer.
        """
        with self._lock:
            seq = -1
            item_seq: int | None = None
            if kind == "trace":
                seq = self._run_seq.get(run_id, 0)
                self._run_seq[run_id] = seq + 1
                item_seq = seq
            if len(self._items) >= self._capacity:
                self._items.popleft()
                self._dropped_total += 1
            self._items.append(BufferedItem(run_id=run_id, kind=kind, seq=item_seq, body=body))
            return seq

    def drain(self, max_items: int) -> list[BufferedItem]:
        """Pop up to `max_items` items, oldest first. Empty list if the buffer is empty."""
        with self._lock:
            n = min(max_items, len(self._items))
            return [self._items.popleft() for _ in range(n)]

    @property
    def dropped_total(self) -> int:
        """Cumulative drops since construction — monotonically increasing."""
        with self._lock:
            return self._dropped_total
