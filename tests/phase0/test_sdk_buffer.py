"""PHASE0-CONTRACT.md §10 — sdk.buffer.RingBuffer: seq assignment, drop-oldest, thread safety.

Task 13's async-write invariant splits into a latency half (RingBuffer.append()
is O(1), lock-only, no I/O — exercised for timing in test_sdk_client.py) and a
correctness half proved here: per-run `seq` is strictly monotonic and gapless
even under concurrent producers (C-23), and overflow drops the OLDEST item —
not an arbitrary one — while counting every drop (D-033).
"""

from __future__ import annotations

import threading

import pytest

from tracebed.domain.ids import RunId, uuid7
from tracebed.sdk.buffer import BufferedItem, RingBuffer

pytestmark = pytest.mark.phase0


def _run_id() -> RunId:
    return RunId(uuid7())


class TestSeqAssignment:
    def test_seq_starts_at_zero_and_increments_per_run(self) -> None:
        buf = RingBuffer(capacity=100)
        run = _run_id()
        seqs = [buf.append(run, "trace", {"n": i}) for i in range(5)]
        assert seqs == [0, 1, 2, 3, 4]

    def test_seq_is_independent_across_concurrent_runs(self) -> None:
        buf = RingBuffer(capacity=100)
        run_a, run_b = _run_id(), _run_id()
        assert buf.append(run_a, "trace", {}) == 0
        assert buf.append(run_b, "trace", {}) == 0
        assert buf.append(run_a, "trace", {}) == 1
        assert buf.append(run_b, "trace", {}) == 1
        assert buf.append(run_a, "trace", {}) == 2
        assert buf.append(run_b, "trace", {}) == 2

    def test_feedback_and_proposal_carry_no_seq(self) -> None:
        buf = RingBuffer(capacity=100)
        run = _run_id()
        assert buf.append(run, "feedback", {}) == -1
        assert buf.append(run, "proposal", {}) == -1
        items = buf.drain(2)
        assert [item.seq for item in items] == [None, None]

    def test_drained_items_carry_the_assigned_seq_and_body_in_order(self) -> None:
        buf = RingBuffer(capacity=100)
        run = _run_id()
        for i in range(10):
            buf.append(run, "trace", {"i": i})
        items = buf.drain(10)
        assert [item.seq for item in items] == list(range(10))
        assert [item.body["i"] for item in items] == list(range(10))
        assert all(item.run_id == run and item.kind == "trace" for item in items)


class TestDropOldest:
    def test_overflow_drops_oldest_survivors_are_the_newest(self) -> None:
        buf = RingBuffer(capacity=3)
        run = _run_id()
        for i in range(5):  # appends 0..4 into a capacity-3 ring: 0 and 1 must go
            buf.append(run, "trace", {"i": i})
        assert buf.dropped_total == 2
        items = buf.drain(10)
        # Survivors are the *newest* three (2,3,4), not merely "three items" —
        # a drop-newest or drop-random policy would also pass a count-only check.
        assert [item.body["i"] for item in items] == [2, 3, 4]

    def test_dropped_total_is_monotonic_and_unaffected_by_drain(self) -> None:
        buf = RingBuffer(capacity=1)
        run = _run_id()
        buf.append(run, "trace", {})
        assert buf.dropped_total == 0
        buf.append(run, "trace", {})  # evicts the first
        assert buf.dropped_total == 1
        buf.drain(10)  # empties the ring; must not reset the counter
        buf.append(run, "trace", {})
        buf.append(run, "trace", {})  # evicts again
        assert buf.dropped_total == 2

    def test_capacity_below_one_rejected(self) -> None:
        with pytest.raises(ValueError, match="capacity"):
            RingBuffer(capacity=0)


class TestDrain:
    def test_drain_returns_fewer_than_requested_when_buffer_short(self) -> None:
        buf = RingBuffer(capacity=100)
        run = _run_id()
        buf.append(run, "trace", {})
        buf.append(run, "trace", {})
        assert len(buf.drain(10)) == 2

    def test_drain_empties_progressively_then_returns_empty(self) -> None:
        buf = RingBuffer(capacity=100)
        run = _run_id()
        for _ in range(5):
            buf.append(run, "trace", {})
        assert len(buf.drain(2)) == 2
        assert len(buf.drain(2)) == 2
        assert len(buf.drain(2)) == 1
        assert buf.drain(1) == []


class TestThreadSafety:
    def test_n_threads_tracing_same_run_produce_gapless_seq(self) -> None:
        buf = RingBuffer(capacity=100_000)
        run = _run_id()
        n_threads = 16
        per_thread = 200
        barrier = threading.Barrier(n_threads)

        def worker() -> None:
            barrier.wait()  # maximize actual contention on the buffer's lock
            for _ in range(per_thread):
                buf.append(run, "trace", {})

        threads = [threading.Thread(target=worker) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        items: list[BufferedItem] = buf.drain(n_threads * per_thread)
        assert len(items) == n_threads * per_thread
        seqs = sorted(item.seq for item in items if item.seq is not None)
        # Dense 0..N-1 with no gaps and no duplicates -- the property a naive
        # unlocked "read counter, increment, write back" would violate under
        # concurrent writers.
        assert seqs == list(range(n_threads * per_thread))

    def test_n_threads_across_distinct_runs_never_cross_contaminate_seq(self) -> None:
        buf = RingBuffer(capacity=100_000)
        runs = [_run_id() for _ in range(8)]
        per_run = 300

        def worker(run: RunId) -> None:
            for _ in range(per_run):
                buf.append(run, "trace", {})

        threads = [threading.Thread(target=worker, args=(run,)) for run in runs]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        items = buf.drain(len(runs) * per_run)
        by_run: dict[RunId, list[int]] = {run: [] for run in runs}
        for item in items:
            assert item.seq is not None
            by_run[item.run_id].append(item.seq)
        for run in runs:
            assert sorted(by_run[run]) == list(range(per_run))
