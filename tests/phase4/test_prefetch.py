"""`workflow.prefetch.PrefetchingRetriever` (PLAN.md §7 Phase 4: "measured before
shipped"). Offline only, fixture-driven concurrency (PLAN.md §7's Phase 4 contention
tests are fixture-only, no host dependency) — every test here drives real background
threads with real `threading.Event`s rather than mocking away the concurrency the
properties (never blocks / never substitutes a different or older answer / provably
cancellable) are about.

The load-bearing tests are the ones that fail when the cache key stops separating
callers: a mutation that drops `project_id` or `query_text` from `_fingerprint` used to
pass this whole file, which meant nothing here proved a prefetch could not be served to
the wrong project (invariant 4) or to a different question.
"""

from __future__ import annotations

import inspect
import random
import sys
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from statistics import mean
from uuid import uuid4

import pytest

from tracebed.domain.clock import Clock, FakeClock, SystemClock
from tracebed.domain.config import RetrievalConfig
from tracebed.domain.ids import ProjectId
from tracebed.workflow.prefetch import (
    PrefetchingRetriever,
    RetrieverPort,
    _fingerprint,
    combined_project_flush,
)

pytestmark = pytest.mark.phase4


@pytest.fixture
def hair_trigger_thread_switching() -> Iterator[None]:
    """Force the interpreter to switch threads roughly every microsecond instead of
    every 5ms, then restore. Without it, two threads racing one short critical section
    almost always run to completion one after the other, and the race a lock exists to
    prevent stays invisible to the test that claims to prove the lock."""
    previous = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        yield
    finally:
        sys.setswitchinterval(previous)

# Fixture-only knobs. `workflow.prefetch` itself has no defaults for these (PLAN.md §6
# defines no `prefetch` section, so the module refuses to invent one); every test states
# what it needs. `_LONG_MS` is "longer than any test's wall-clock duration", i.e. the
# freshness window is not what any test below is measuring unless it says so.
_LONG_MS = 60_000
_WORKERS = 4
_ENTRIES = 8


@dataclass(frozen=True, slots=True)
class _Outcome:
    label: str


class _CountingRetriever:
    """Deterministic: identical inputs always produce an equal `_Outcome` — this is
    what makes "byte-identical to a cold call" a meaningful assertion rather than a
    tautology about a single shared instance."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self._lock = threading.Lock()

    def retrieve(
        self, project_id: ProjectId, query_text: str, *, cfg: RetrievalConfig
    ) -> _Outcome:
        with self._lock:
            self.calls.append((str(project_id), query_text))
        return _Outcome(label=f"{project_id}:{query_text}:{cfg.rrf_k}")


class _VersionedRetriever:
    """Answers with whatever `version` says RIGHT NOW — a stand-in for a memory store
    that other writers keep changing (a tombstone, an invalidation, a promotion). This
    is what makes "a warm hit can be stale" observable at all: with a retriever whose
    answer never changes, no cache can be caught serving an old one."""

    def __init__(self) -> None:
        self.version = "v1"
        self.calls = 0
        self._lock = threading.Lock()

    def retrieve(
        self, project_id: ProjectId, query_text: str, *, cfg: RetrievalConfig
    ) -> _Outcome:
        with self._lock:
            self.calls += 1
            return _Outcome(label=self.version)


class _BlockOnFirstCallRetriever:
    """Blocks its FIRST call on an `Event` until released; every later call returns
    immediately. This is what lets a test observe "still in flight" deterministically
    (no sleep-and-hope) and then prove a second call takes the fall-through path without
    itself waiting on the first."""

    def __init__(self) -> None:
        self.release = threading.Event()
        self.started = threading.Event()
        self.calls = 0

    def retrieve(
        self, project_id: ProjectId, query_text: str, *, cfg: RetrievalConfig
    ) -> _Outcome:
        self.calls += 1
        if self.calls == 1:
            self.started.set()
            self.release.wait(timeout=5.0)
            return _Outcome(label="first-call-result")
        return _Outcome(label="fast-call-result")


class _FlakyOnceRetriever:
    """Raises on its first call, succeeds on every call after — proves a failed
    prefetch does not poison the entry it left behind, only that the entry is gone."""

    def __init__(self) -> None:
        self.calls = 0

    def retrieve(
        self, project_id: ProjectId, query_text: str, *, cfg: RetrievalConfig
    ) -> _Outcome:
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("simulated prefetch failure")
        return _Outcome(label="recovered")


class _SleepingRetriever:
    """Stands in for a real BM25 + ANN + embedding round trip with a plain
    `time.sleep` — the one thing the benchmark measures a speedup against."""

    def __init__(self, latency_s: float) -> None:
        self._latency_s = latency_s
        self.calls = 0

    def retrieve(
        self, project_id: ProjectId, query_text: str, *, cfg: RetrievalConfig
    ) -> _Outcome:
        self.calls += 1
        time.sleep(self._latency_s)
        return _Outcome(label="slow-result")


class _RaisingClock:
    """A `Clock` whose monotonic source is broken. Third-party code sits behind the
    `Clock` Protocol, and `retrieve()` is reached from a call an agent runtime waits
    on (invariant 2)."""

    def now(self) -> datetime:  # pragma: no cover - never called by prefetch
        raise RuntimeError("clock is down")

    def now_ms(self) -> int:  # pragma: no cover - never called by prefetch
        raise RuntimeError("clock is down")

    def monotonic_ms(self) -> float:
        raise RuntimeError("clock is down")


def _project() -> ProjectId:
    return ProjectId(uuid4())


def _cfg() -> RetrievalConfig:
    return RetrievalConfig()


def _pref[T](
    inner: RetrieverPort[T],
    *,
    clock: Clock | None = None,
    max_age_ms: int = _LONG_MS,
    max_entries: int = _ENTRIES,
    max_workers: int = _WORKERS,
) -> PrefetchingRetriever[T]:
    return PrefetchingRetriever(
        inner,
        clock=clock if clock is not None else SystemClock(),
        max_age_ms=max_age_ms,
        max_entries=max_entries,
        max_workers=max_workers,
    )


def _wait_ready(pref: PrefetchingRetriever[_Outcome], key: bytes, timeout: float = 2.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pref.is_ready(key):
            return
        time.sleep(0.001)
    raise AssertionError("prefetch did not become ready within the timeout")


# --------------------------------------------------------------------------- #
# (b) Never substitutes a different answer.
# --------------------------------------------------------------------------- #


def test_prefetch_then_retrieve_is_byte_identical_to_cold() -> None:
    project_id = _project()
    cfg = _cfg()

    cold_result = _CountingRetriever().retrieve(project_id, "restart the payment webhook", cfg=cfg)

    warm_inner = _CountingRetriever()
    pref: PrefetchingRetriever[_Outcome] = _pref(warm_inner)
    try:
        key = pref.prefetch(project_id, "restart the payment webhook", cfg=cfg)
        _wait_ready(pref, key)
        warm_result = pref.retrieve(project_id, "restart the payment webhook", cfg=cfg)
    finally:
        pref.close()

    assert warm_result == cold_result
    # Exactly one call reached the wrapped retriever -- the prefetch's own call, whose
    # result was then served from cache, never a second recomputation.
    assert warm_inner.calls == [(str(project_id), "restart the payment webhook")]


def test_no_prefetch_falls_through_to_an_ordinary_call() -> None:
    inner = _CountingRetriever()
    pref: PrefetchingRetriever[_Outcome] = _pref(inner)
    try:
        result = pref.retrieve(_project(), "q", cfg=_cfg())
    finally:
        pref.close()
    assert result.label.endswith(":q:60")
    assert len(inner.calls) == 1


def test_a_warm_entry_is_never_served_to_another_project() -> None:
    """Invariant 4 on the newest cache in the codebase. A prefetch warmed under project
    A must be invisible to project B even for a byte-identical query and config: the
    fingerprint separates them AND `_take` re-checks the entry's project before serving
    it. Dropping `project_id` from the cache key used to pass this whole file."""
    project_a, project_b = _project(), _project()
    cfg = _cfg()
    inner = _CountingRetriever()
    pref: PrefetchingRetriever[_Outcome] = _pref(inner)
    try:
        key_a = pref.prefetch(project_a, "same question", cfg=cfg)
        _wait_ready(pref, key_a)

        result_b = pref.retrieve(project_b, "same question", cfg=cfg)

        # B's answer was computed for B, and A's warm entry is still untouched.
        assert result_b.label == f"{project_b}:same question:60"
        assert inner.calls == [
            (str(project_a), "same question"),
            (str(project_b), "same question"),
        ]
        assert pref.pending_count() == 1

        result_a = pref.retrieve(project_a, "same question", cfg=cfg)
        assert result_a.label == f"{project_a}:same question:60"
        assert len(inner.calls) == 2  # A was served from its own warm entry
    finally:
        pref.close()


def test_a_warm_entry_is_never_served_for_a_different_query() -> None:
    """Same project, different question: a cache hit here would answer one step with
    another step's retrieval. Dropping `query_text` from the cache key used to pass this
    whole file."""
    project_id = _project()
    cfg = _cfg()
    inner = _CountingRetriever()
    pref: PrefetchingRetriever[_Outcome] = _pref(inner)
    try:
        key = pref.prefetch(project_id, "restart the payment webhook", cfg=cfg)
        _wait_ready(pref, key)

        result = pref.retrieve(project_id, "draft the quarterly summary", cfg=cfg)
        assert result.label == f"{project_id}:draft the quarterly summary:60"
        assert len(inner.calls) == 2
    finally:
        pref.close()


def test_a_config_change_is_a_different_key_never_a_stale_hit() -> None:
    """Property (b) only holds for an EXACT repeat of the same call: changing any
    `RetrievalConfig` field must be a cache miss, not a hit against the old config."""
    project_id = _project()
    inner = _CountingRetriever()
    pref: PrefetchingRetriever[_Outcome] = _pref(inner)
    try:
        key = pref.prefetch(project_id, "q", cfg=RetrievalConfig(rrf_k=60))
        _wait_ready(pref, key)

        result = pref.retrieve(project_id, "q", cfg=RetrievalConfig(rrf_k=99))
        assert result.label.endswith(":q:99")
        assert len(inner.calls) == 2  # the prefetch's call, plus a fresh miss
    finally:
        pref.close()


def test_fingerprint_covers_every_parameter_of_the_retriever_port() -> None:
    """The cache key must span the wrapped call's ENTIRE input, or a hit answers a
    question that differs in whatever it omits. Checked against the real
    `hotpath.pipeline.HybridRetrieverPort` signature so that a port which grows a
    parameter (an agent_type, a scope, an arm) fails here instead of silently producing
    hits that ignore it."""
    from tracebed.hotpath.pipeline import HybridRetrieverPort

    port_params = set(inspect.signature(HybridRetrieverPort.retrieve).parameters) - {"self"}
    assert port_params == {"project_id", "query_text", "cfg"}

    # Each parameter, varied alone, must produce a different key.
    cfg = _cfg()
    project_id = _project()
    base = _fingerprint(project_id, "q", cfg)
    assert base != _fingerprint(_project(), "q", cfg)
    assert base != _fingerprint(project_id, "q2", cfg)
    assert base != _fingerprint(project_id, "q", RetrievalConfig(rrf_k=61))
    for field in RetrievalConfig.model_fields:
        current = getattr(cfg, field)
        altered = (
            not current
            if isinstance(current, bool)
            else (current + 1 if isinstance(current, int) else current + 1.0)
        )
        mutated = cfg.model_copy(update={field: altered})
        assert base != _fingerprint(project_id, "q", mutated), (
            f"RetrievalConfig.{field} does not affect the prefetch cache key"
        )


def test_not_yet_ready_falls_through_without_waiting_on_the_pending_future() -> None:
    inner = _BlockOnFirstCallRetriever()
    pref: PrefetchingRetriever[_Outcome] = _pref(inner)
    try:
        project_id, cfg = _project(), _cfg()
        key = pref.prefetch(project_id, "q", cfg=cfg)
        assert inner.started.wait(timeout=2.0)
        assert not pref.is_ready(key)

        start = time.monotonic()
        result = pref.retrieve(project_id, "q", cfg=cfg)
        elapsed = time.monotonic() - start

        assert elapsed < 0.2, f"retrieve() waited on a still-running prefetch: {elapsed * 1000:.1f}ms"
        assert result.label == "fast-call-result"
        assert inner.calls == 2
    finally:
        inner.release.set()
        pref.close()


def test_prefetch_failure_is_invisible_to_the_caller() -> None:
    inner = _FlakyOnceRetriever()
    pref: PrefetchingRetriever[_Outcome] = _pref(inner)
    try:
        project_id, cfg = _project(), _cfg()
        key = pref.prefetch(project_id, "q", cfg=cfg)
        _wait_ready(pref, key)  # finished -- by raising

        result = pref.retrieve(project_id, "q", cfg=cfg)  # must not raise
        assert result.label == "recovered"
        assert inner.calls == 2
        assert pref.pending_count() == 0
        assert key  # the failed prefetch still handed back a usable key
    finally:
        pref.close()


# --------------------------------------------------------------------------- #
# (b), the honest half: a warm hit is bounded in age and flushable.
# --------------------------------------------------------------------------- #


def test_a_warm_entry_expires_and_the_next_call_sees_the_new_store_state() -> None:
    """The scenario the module cannot make impossible and therefore bounds: a write
    lands between the prefetch and the retrieve. Inside `max_age_ms` the caller may get
    the pre-write snapshot; past it, never. `FakeClock` makes the boundary exact instead
    of a sleep."""
    clock = FakeClock()
    inner = _VersionedRetriever()
    pref: PrefetchingRetriever[_Outcome] = _pref(inner, clock=clock, max_age_ms=500)
    try:
        project_id, cfg = _project(), _cfg()
        key = pref.prefetch(project_id, "q", cfg=cfg)
        _wait_ready(pref, key)

        inner.version = "v2"  # a tombstone / invalidation / promotion lands

        clock.advance(ms=500)  # exactly at the window: still servable
        assert pref.retrieve(project_id, "q", cfg=cfg).label == "v1"

        key = pref.prefetch(project_id, "q", cfg=cfg)
        _wait_ready(pref, key)
        inner.version = "v3"
        clock.advance(ms=501)  # one millisecond past it: never servable
        assert pref.retrieve(project_id, "q", cfg=cfg).label == "v3"
        assert pref.pending_count() == 0
    finally:
        pref.close()


def test_max_age_zero_disables_warm_hits_entirely() -> None:
    """A deployment that tolerates no staleness window sets 0; every `retrieve()` is
    then exactly a cold call, and `prefetch()` does not even spend a thread."""
    clock = FakeClock()
    inner = _VersionedRetriever()
    pref: PrefetchingRetriever[_Outcome] = _pref(inner, clock=clock, max_age_ms=0)
    try:
        project_id, cfg = _project(), _cfg()
        pref.prefetch(project_id, "q", cfg=cfg)
        assert pref.pending_count() == 0

        inner.version = "v2"
        assert pref.retrieve(project_id, "q", cfg=cfg).label == "v2"
        assert inner.calls == 1  # only the cold call ever ran
    finally:
        pref.close()


def test_flush_project_drops_that_projects_entries_and_no_others() -> None:
    """The in-process twin of `stores.valkey.flush.flush_project_cache`: a `cache_flush`
    invalidation (or a project delete) must be able to reach this cache, or a prefetched
    result outlives the invalidation that removed the memories inside it."""
    clock = FakeClock()
    inner = _VersionedRetriever()
    pref: PrefetchingRetriever[_Outcome] = _pref(inner, clock=clock)
    try:
        project_a, project_b, cfg = _project(), _project(), _cfg()
        key_a = pref.prefetch(project_a, "q", cfg=cfg)
        key_b = pref.prefetch(project_b, "q", cfg=cfg)
        _wait_ready(pref, key_a)
        _wait_ready(pref, key_b)

        inner.version = "v2"
        assert pref.flush_project(project_a) == 1
        assert pref.pending_count() == 1

        assert pref.retrieve(project_a, "q", cfg=cfg).label == "v2"  # recomputed
        assert pref.retrieve(project_b, "q", cfg=cfg).label == "v1"  # untouched
        assert pref.flush_project(project_a) == 0  # idempotent
    finally:
        pref.close()


def test_the_cache_is_bounded_and_evicts_the_oldest_entry() -> None:
    """A speculative cache that only grows is a leak: an orchestrator that mispredicts
    every step would otherwise pin one full retrieval result per wrong guess for the
    life of the process. Eviction is always safe — the evicted key recomputes."""
    clock = FakeClock()
    inner = _CountingRetriever()
    pref: PrefetchingRetriever[_Outcome] = _pref(inner, clock=clock, max_entries=3)
    try:
        project_id, cfg = _project(), _cfg()
        keys = []
        for i in range(6):
            key = pref.prefetch(project_id, f"q{i}", cfg=cfg)
            _wait_ready(pref, key)
            keys.append(key)
            assert pref.pending_count() <= 3

        assert not pref.is_ready(keys[0])  # oldest evicted
        assert pref.is_ready(keys[-1])  # newest kept
        # An evicted key is a plain cache miss, never a wrong answer.
        assert pref.retrieve(project_id, "q0", cfg=cfg).label == f"{project_id}:q0:60"
    finally:
        pref.close()


def test_a_broken_clock_costs_a_cache_hit_never_the_run() -> None:
    """`Clock` is an injected Protocol; a monotonic source that raises must not surface
    as an exception on a call an agent runtime waits on (invariant 2). With no readable
    clock there is no bound on staleness, so nothing is cached and everything is cold."""
    inner = _VersionedRetriever()
    pref: PrefetchingRetriever[_Outcome] = _pref(inner, clock=_RaisingClock())
    try:
        project_id, cfg = _project(), _cfg()
        pref.prefetch(project_id, "q", cfg=cfg)  # must not raise
        assert pref.pending_count() == 0
        assert pref.is_ready(b"\x00" * 32) is False
        assert pref.retrieve(project_id, "q", cfg=cfg).label == "v1"
        assert inner.calls == 1
    finally:
        pref.close()


# --------------------------------------------------------------------------- #
# (a) Never blocks -- and never raises into -- the current step.
# --------------------------------------------------------------------------- #


def test_prefetch_call_itself_never_blocks() -> None:
    slow = _SleepingRetriever(latency_s=0.25)
    pref: PrefetchingRetriever[_Outcome] = _pref(slow)
    try:
        start = time.monotonic()
        pref.prefetch(_project(), "q", cfg=_cfg())
        elapsed = time.monotonic() - start
        assert elapsed < 0.05, f"prefetch() blocked for {elapsed * 1000:.1f}ms"
    finally:
        pref.close()  # waits out the 0.25s background call so the thread exits cleanly


def test_prefetch_after_close_is_a_noop_not_a_raise() -> None:
    """A shut-down `ThreadPoolExecutor` raises `RuntimeError` on submit. An orchestrator
    that prefetches during shutdown must not have its run fail for it (invariant 2);
    `retrieve()` still answers, cold."""
    inner = _CountingRetriever()
    pref: PrefetchingRetriever[_Outcome] = _pref(inner)
    pref.close()
    pref.close()  # idempotent

    project_id, cfg = _project(), _cfg()
    pref.prefetch(project_id, "q", cfg=cfg)  # must not raise
    assert pref.pending_count() == 0
    assert pref.retrieve(project_id, "q", cfg=cfg).label == f"{project_id}:q:60"


def test_scheduling_the_same_key_twice_is_a_noop() -> None:
    inner = _CountingRetriever()
    pref: PrefetchingRetriever[_Outcome] = _pref(inner)
    try:
        project_id, cfg = _project(), _cfg()
        key_a = pref.prefetch(project_id, "q", cfg=cfg)
        key_b = pref.prefetch(project_id, "q", cfg=cfg)
        _wait_ready(pref, key_a)
        assert key_a == key_b
        assert pref.pending_count() == 1
        assert len(inner.calls) == 1
    finally:
        pref.close()


def test_reprefetching_after_expiry_refreshes_rather_than_pinning_the_stale_entry() -> None:
    clock = FakeClock()
    inner = _VersionedRetriever()
    pref: PrefetchingRetriever[_Outcome] = _pref(inner, clock=clock, max_age_ms=100)
    try:
        project_id, cfg = _project(), _cfg()
        key = pref.prefetch(project_id, "q", cfg=cfg)
        _wait_ready(pref, key)

        inner.version = "v2"
        clock.advance(ms=101)
        key2 = pref.prefetch(project_id, "q", cfg=cfg)  # same key, expired entry
        assert key2 == key
        _wait_ready(pref, key2)
        assert inner.calls == 2
        assert pref.retrieve(project_id, "q", cfg=cfg).label == "v2"
    finally:
        pref.close()


def test_constructor_refuses_degenerate_bounds() -> None:
    with pytest.raises(ValueError, match="max_age_ms"):
        _pref(_CountingRetriever(), max_age_ms=-1)
    with pytest.raises(ValueError, match="max_entries"):
        _pref(_CountingRetriever(), max_entries=0)
    with pytest.raises(ValueError, match="max_workers"):
        _pref(_CountingRetriever(), max_workers=0)


# --------------------------------------------------------------------------- #
# (c) Provably cancellable.
# --------------------------------------------------------------------------- #


def test_cancel_leaves_no_state_behind() -> None:
    inner = _BlockOnFirstCallRetriever()
    pref: PrefetchingRetriever[_Outcome] = _pref(inner)
    try:
        project_id, cfg = _project(), _cfg()
        key = pref.prefetch(project_id, "q", cfg=cfg)
        assert inner.started.wait(timeout=2.0)
        assert pref.pending_count() == 1

        # Cancel strictly BEFORE the background call finishes -- the actual race
        # property (c) exists to hold.
        pref.cancel(key)
        assert pref.pending_count() == 0

        # Let the already-cancelled background call actually finish.
        inner.release.set()
        deadline = time.monotonic() + 2.0
        while inner.calls < 1 and time.monotonic() < deadline:
            time.sleep(0.001)

        # No trace remains, and the next retrieve() for the SAME key recomputes from
        # scratch rather than reusing the cancelled (and discarded) result.
        assert pref.pending_count() == 0
        result = pref.retrieve(project_id, "q", cfg=cfg)
        assert result.label == "fast-call-result"
        assert inner.calls == 2
    finally:
        inner.release.set()
        pref.close()


def test_cancel_after_completion_also_discards_the_cached_result() -> None:
    """A branch change can arrive after the prefetch already finished -- cancel must
    discard a completed-but-unconsumed entry exactly like a still-running one."""
    inner = _CountingRetriever()
    pref: PrefetchingRetriever[_Outcome] = _pref(inner)
    try:
        project_id, cfg = _project(), _cfg()
        key = pref.prefetch(project_id, "q", cfg=cfg)
        _wait_ready(pref, key)

        pref.cancel(key)
        assert pref.pending_count() == 0

        result = pref.retrieve(project_id, "q", cfg=cfg)
        assert len(inner.calls) == 2  # the prefetch's call, discarded, plus a fresh one
        assert result == _Outcome(label=f"{project_id}:q:60")
    finally:
        pref.close()


def test_a_cached_entry_is_served_at_most_once() -> None:
    """One speculative call answers one step. The second `retrieve()` for the same key
    must recompute, or two different steps would share one snapshot of the store."""
    inner = _CountingRetriever()
    pref: PrefetchingRetriever[_Outcome] = _pref(inner)
    try:
        project_id, cfg = _project(), _cfg()
        key = pref.prefetch(project_id, "q", cfg=cfg)
        _wait_ready(pref, key)

        first = pref.retrieve(project_id, "q", cfg=cfg)
        second = pref.retrieve(project_id, "q", cfg=cfg)
        assert first == second  # same value, because the retriever is deterministic
        assert len(inner.calls) == 2  # but recomputed, not re-served
    finally:
        pref.close()


def test_cancel_all_discards_every_pending_entry() -> None:
    inner = _CountingRetriever()
    pref: PrefetchingRetriever[_Outcome] = _pref(inner)
    try:
        cfg = _cfg()
        key_1 = pref.prefetch(_project(), "q1", cfg=cfg)
        key_2 = pref.prefetch(_project(), "q2", cfg=cfg)
        _wait_ready(pref, key_1)
        _wait_ready(pref, key_2)
        assert pref.pending_count() == 2

        pref.cancel_all()
        assert pref.pending_count() == 0
    finally:
        pref.close()


def test_cancelling_an_unknown_key_is_a_harmless_noop() -> None:
    pref: PrefetchingRetriever[_Outcome] = _pref(_CountingRetriever())
    try:
        pref.cancel(b"\x00" * 32)  # never scheduled
        assert pref.pending_count() == 0
    finally:
        pref.close()


# --------------------------------------------------------------------------- #
# Real concurrency, repeated. One interleaving proves almost nothing.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("attempt", range(8))
def test_concurrent_prefetch_retrieve_cancel_never_crosses_answers(attempt: int) -> None:
    """Eight threads hammering the same small key space with prefetch/retrieve/cancel/
    flush, repeated. Every value any thread receives must be the value that key's own
    inputs produce -- a cache that can hand one caller another caller's answer under
    contention shows up here as a mismatched label, and any exception escaping into a
    worker fails the run. Deterministic per attempt (seeded) so a failure is
    reproducible rather than folklore."""
    inner = _CountingRetriever()
    projects = [_project() for _ in range(3)]
    queries = ["alpha", "beta", "gamma"]
    cfg = _cfg()
    pref: PrefetchingRetriever[_Outcome] = _pref(
        inner, max_entries=4, max_workers=4, max_age_ms=_LONG_MS
    )
    errors: list[BaseException] = []
    start = threading.Barrier(8)

    def worker(seed: int) -> None:
        local = random.Random((attempt << 8) | seed)
        try:
            start.wait(timeout=5.0)
            for _ in range(60):
                project_id = local.choice(projects)
                query = local.choice(queries)
                action = local.random()
                if action < 0.35:
                    pref.prefetch(project_id, query, cfg=cfg)
                elif action < 0.85:
                    got = pref.retrieve(project_id, query, cfg=cfg)
                    expected = f"{project_id}:{query}:{cfg.rrf_k}"
                    if got.label != expected:
                        raise AssertionError(f"cache crossed answers: {got.label} != {expected}")
                elif action < 0.95:
                    pref.cancel(pref.prefetch(project_id, query, cfg=cfg))
                else:
                    pref.flush_project(project_id)
        # Broad on purpose: anything a worker raises is re-raised on the main thread
        # below, where pytest can report it. A thread that dies silently would turn a
        # contention bug into a green run.
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30.0)
            assert not thread.is_alive(), "a worker thread deadlocked"
    finally:
        pref.close()

    assert not errors, errors
    assert pref.pending_count() == 0  # close() drops everything


def test_concurrent_consumers_of_one_warm_entry_get_exactly_one_cache_hit(
    hair_trigger_thread_switching: None,
) -> None:
    """Two threads racing `retrieve()` on one warm key: `_take` pops under the lock, so
    exactly one of them is served from cache and the other recomputes -- never both
    served the same entry (two steps sharing one snapshot), never both blocked on it.

    Repeated, and under a microsecond thread-switch interval: at the default 5ms both
    threads pass through `_take` inside one scheduling quantum, and a `_take` with no
    mutual exclusion at all passes 25 rounds of this without a single interleaving. With
    hair-trigger switching that same unlocked version fails within a couple of rounds --
    which is what makes this a test of the lock rather than of the GIL."""
    for _ in range(60):
        inner = _CountingRetriever()
        pref: PrefetchingRetriever[_Outcome] = _pref(inner)
        project_id, cfg = _project(), _cfg()
        try:
            key = pref.prefetch(project_id, "q", cfg=cfg)
            _wait_ready(pref, key)

            results: list[_Outcome] = []
            gate = threading.Barrier(2)

            def consume(
                pref: PrefetchingRetriever[_Outcome] = pref,
                project_id: ProjectId = project_id,
                cfg: RetrievalConfig = cfg,
                gate: threading.Barrier = gate,
                results: list[_Outcome] = results,
            ) -> None:
                gate.wait(timeout=5.0)
                results.append(pref.retrieve(project_id, "q", cfg=cfg))

            threads = [threading.Thread(target=consume) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5.0)

            assert len(results) == 2
            assert all(r.label == f"{project_id}:q:60" for r in results)
            # 1 prefetch call + exactly 1 recomputation: one consumer took the entry.
            assert len(inner.calls) == 2
        finally:
            pref.close()


# --------------------------------------------------------------------------- #
# Drop-in compatibility: the exact `hotpath.pipeline.HybridRetrieverPort` shape.
# --------------------------------------------------------------------------- #


def test_structurally_satisfies_the_real_hybrid_retriever_port() -> None:
    from tracebed.hotpath.pipeline import HybridRetrieverPort

    pref: PrefetchingRetriever[_Outcome] = _pref(_CountingRetriever())
    try:
        assert isinstance(pref, HybridRetrieverPort)
        assert inspect.signature(PrefetchingRetriever.retrieve).parameters.keys() == (
            inspect.signature(HybridRetrieverPort.retrieve).parameters.keys()
        )
    finally:
        pref.close()


# --------------------------------------------------------------------------- #
# MEASURED, HONESTLY -- PLAN.md §7's "measured before shipped".
# --------------------------------------------------------------------------- #


def test_benchmark_warm_vs_cold_reports_honest_numbers() -> None:
    """The one workload this module can claim to speed up: an EXACT repeat of a
    prefetched call, background already finished, entry inside its freshness window,
    against a synthetic per-call latency standing in for a real retrieval round trip.
    Prints the measured numbers (visible with `pytest -s`) rather than asserting a
    specific ratio nobody can audit later; the module docstring records one
    representative run. This is not a production lift estimate -- see the module
    docstring's honest caveat about next-step prediction accuracy, which no telemetry in
    this codebase measures yet.
    """
    latency_s = 0.03
    trials = 5
    cfg = _cfg()

    cold_latencies: list[float] = []
    for _ in range(trials):
        inner = _SleepingRetriever(latency_s)
        start = time.monotonic()
        inner.retrieve(_project(), "q", cfg=cfg)
        cold_latencies.append(time.monotonic() - start)

    warm_latencies: list[float] = []
    for _ in range(trials):
        pref: PrefetchingRetriever[_Outcome] = _pref(_SleepingRetriever(latency_s))
        try:
            project_id = _project()
            key = pref.prefetch(project_id, "q", cfg=cfg)
            _wait_ready(pref, key, timeout=2.0)
            start = time.monotonic()
            pref.retrieve(project_id, "q", cfg=cfg)
            warm_latencies.append(time.monotonic() - start)
        finally:
            pref.close()

    cold_mean = mean(cold_latencies)
    warm_mean = mean(warm_latencies)
    print(
        f"\n[prefetch benchmark] cold mean={cold_mean * 1000:.3f}ms "
        f"warm mean={warm_mean * 1000:.3f}ms "
        f"speedup={cold_mean / max(warm_mean, 1e-9):.0f}x"
    )

    # A warm hit reads a completed `Future`; it does not re-run the simulated 30ms
    # latency. An order of magnitude is a conservative bound against scheduler noise,
    # not the actual measured ratio (which is far larger -- see the module docstring).
    assert warm_mean < cold_mean / 10


# --------------------------------------------------------------------------------------- #
# combined_project_flush -- composing the two project-scoped cache tiers into the one
# `Callable[[ProjectId], int]` that `workers.invalidator.Invalidator(flush_cache=...)`
# already takes. Before it existed, a wiring site reached the Valkey tier through
# `stores.valkey.flush.flush_project_cache` and had to separately remember that
# `PrefetchingRetriever` is also a project-scoped cache.
# --------------------------------------------------------------------------------------- #


def test_combined_flush_reaches_every_tier_and_sums_what_each_removed() -> None:
    """A wiring site that passed only the Valkey flusher would flush half the caches and
    report success."""
    seen: list[tuple[str, ProjectId]] = []
    project_id = _project()

    def _valkey(pid: ProjectId) -> int:
        seen.append(("valkey", pid))
        return 3

    def _other(pid: ProjectId) -> int:
        seen.append(("other", pid))
        return 4

    assert combined_project_flush(_valkey, _other)(project_id) == 7
    assert seen == [("valkey", project_id), ("other", project_id)]


def test_the_prefetch_cache_composes_through_its_own_flusher() -> None:
    """`project_flusher()` exists so a wiring site does not have to know this class is a
    cache at all; the composed callable must really empty it."""
    inner = _VersionedRetriever()
    pref: PrefetchingRetriever[_Outcome] = _pref(inner)
    try:
        project_id, cfg = _project(), _cfg()
        key = pref.prefetch(project_id, "q", cfg=cfg)
        _wait_ready(pref, key)
        assert pref.pending_count() == 1

        flush = combined_project_flush(lambda _pid: 0, pref.project_flusher())
        assert flush(project_id) == 1
        assert pref.pending_count() == 0

        # And the next retrieve really does see the new store state, which is the whole
        # reason an invalidation has to reach this tier.
        inner.version = "v2"
        assert pref.retrieve(project_id, "q", cfg=cfg).label == "v2"
    finally:
        pref.close()


def test_a_combined_flush_only_touches_the_project_it_was_given() -> None:
    inner = _VersionedRetriever()
    pref: PrefetchingRetriever[_Outcome] = _pref(inner)
    try:
        one, two, cfg = _project(), _project(), _cfg()
        _wait_ready(pref, pref.prefetch(one, "q", cfg=cfg))
        _wait_ready(pref, pref.prefetch(two, "q", cfg=cfg))
        assert pref.pending_count() == 2

        assert combined_project_flush(pref.project_flusher())(one) == 1
        assert pref.pending_count() == 1, "a project-scoped flush emptied another project"
    finally:
        pref.close()


def test_one_failing_tier_does_not_stop_the_others_and_the_error_still_surfaces() -> None:
    """A partial flush reported as a total failure is recoverable by a retry. A partial
    flush that silently skipped a tier is not -- the skipped tier keeps serving exactly the
    data the event exists to remove."""
    reached: list[str] = []

    def _boom(_pid: ProjectId) -> int:
        reached.append("boom")
        raise RuntimeError("valkey is down")

    def _later(_pid: ProjectId) -> int:
        reached.append("later")
        return 5

    with pytest.raises(RuntimeError, match="valkey is down"):
        combined_project_flush(_boom, _later)(_project())
    assert reached == ["boom", "later"], "a failing tier short-circuited the tiers after it"


def test_combining_nothing_is_a_no_op_rather_than_an_error() -> None:
    """A deployment with no cache tiers wired must still be able to hand `Invalidator` a
    callable; `Invalidator` distinguishes "no flusher" from "flushed nothing" itself."""
    assert combined_project_flush()(_project()) == 0
