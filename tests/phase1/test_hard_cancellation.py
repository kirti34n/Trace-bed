"""BMAD-EVALUATION's most serious finding: PLAN.md §2 invariant 2 ("a run never blocks or fails
because of Tracebed") was enforced against EXCEPTIONS only, never against HANGS. Before D-132:

  * `hotpath.retriever.Retriever.retrieve()` called `lexical_future.result()` / `vector_future
    .result()` with NO timeout — a stalled Postgres connection blocked `retrieve()`, and therefore
    the calling agent's run, indefinitely.
  * `stores.pg.pool` set no `statement_timeout`, no `connect_timeout`, and no
    `idle_in_transaction_session_timeout` — nothing bounded a query once it was already running.

`tests/phase1/test_degradation_ladder.py`'s existing fault-injection drill could never have caught
either half: every stall in it is `FakeClock.advance()`, which moves simulated time without ever
blocking a real thread. Every test below drives a REAL block on a REAL `threading.Event` (or, for
`pool.py`, a fake connection whose `execute` is asserted against rather than actually blocked,
since there is no Postgres in this environment — the mechanism is proved by the SQL it issues,
same as every other offline `stores/pg` test in this repository) measured against a REAL clock
(`SystemClock`), never a `FakeClock`.

D-138 (adversarial audit of D-132) adds the half a bounded WAIT does not buy. `ThreadPoolExecutor`'s
work queue is unbounded, so with both workers wedged the delivered fix still enqueued two work items
per request that could never run, and replayed all of them at Postgres on recovery — 200 requests
left 398 queued items and fired 400 arm queries, with the thread count flat the entire time, which
is why the thread-count test could not see it. The tests for that live in section 1 alongside two
controls that matter more than the bound: a busy-but-healthy pool must still QUEUE, and one wedged
worker must not refuse what the other can still serve. Section 3 additionally asserts on the TEXT of
`pool.py`'s `set_config` statements, because comparing `pool.log` against the module's own constants
pins which statement ran and nothing about what it says.

Section 1 exercises `hotpath.retriever.Retriever` directly (real thread, real stall, real clock).
Section 2 exercises the full `hotpath.pipeline.Pipeline` wired with the REAL `Retriever` (not a
fake `HybridRetrieverPort`, unlike every test in `test_degradation_ladder.py`) to prove the correct
ladder rung (`OutcomeCode.TIMEOUT_PREFIX_ONLY`) is what a stalled arm now produces end to end, not
`store_error` and not an escaped exception. Section 3 exercises `stores.pg.pool`'s two new,
opt-in controls (`scoped(..., statement_timeout_ms=..., idle_in_transaction_session_timeout_ms=...)`
and `create_pool(..., connect_timeout_s=...)`) offline, against fakes.
"""

from __future__ import annotations

import re
import threading
import time
import uuid
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from tracebed.domain.clock import SystemClock
from tracebed.domain.config import (
    AbstentionConfig,
    BudgetConfig,
    CacheConfig,
    DerivedConfig,
    EffectiveConfig,
    KillswitchConfig,
    LifecycleConfig,
    PromotionConfig,
    ProposalConfig,
    QueueConfig,
    RetirementConfig,
    RetrievalConfig,
    ScoreConfig,
    ScoringConfig,
    SessionConfig,
    SpendConfig,
    TierAConfig,
)
from tracebed.domain.enums import Arm, OutcomeCode, TrustTier
from tracebed.domain.events import RunContext
from tracebed.domain.ids import AgentTypeId, MemoryId, PrincipalId, ProjectId, RunId
from tracebed.domain.scope import ProjectScope
from tracebed.domain.state_machine import Status
from tracebed.hotpath import retriever as retriever_module
from tracebed.hotpath.pipeline import CandidateSetResult, Pipeline
from tracebed.hotpath.retriever import _ARM_WORKER_COUNT, RetrievalOutcome, Retriever
from tracebed.stores.pg import pool as pool_module
from tracebed.stores.pg.search import ArmHit, SearchStore

pytestmark = pytest.mark.phase1

PROJECT = ProjectId(uuid.UUID(int=42))
MEM_VECTOR_HIT = MemoryId(uuid.UUID(int=7))

# Section 4 reads the two `create_pool` call sites as SOURCE: both live inside `run()` entry
# points that build a real pool against a real DSN, so there is no offline way to observe the
# arguments they pass.
_SRC_ROOT = Path(__file__).resolve().parents[2] / "src" / "tracebed"

# Generous but finite: real thread scheduling on a loaded CI box can add tens of milliseconds of
# jitter on top of the configured budget, and this suite must never be flaky about "did it return
# at all" while still proving it did not simply wait forever. Every stalling fake also carries its
# own, much longer `safety_net_s` so a test failure never leaves a background thread blocked
# indefinitely (it either gets released by the test or gives up on its own).
_BOUND_S = 2.0


def _hit(memory_id: MemoryId, raw_score: float) -> ArmHit:
    return ArmHit(memory_id=memory_id, raw_score=raw_score, trust_tier=TrustTier.A, status=Status.VALIDATED)


class _FakeEmbeddingPort:
    """Returns a canned vector instantly — the embed sub-budget is not this file's subject."""

    def __init__(self, vectors: list[list[float]] | None = None) -> None:
        self._vectors = vectors if vectors is not None else [[0.1, 0.2, 0.3]]

    def embed(self, texts: Sequence[str], *, timeout_ms: int) -> list[list[float]]:
        return self._vectors

    @property
    def model_id(self) -> str:
        return "fake-embedding"

    @property
    def model_version(self) -> str:
        return "test"


class _StallingLexicalSearch:
    """The lexical arm blocks on a REAL `threading.Event` until released — mirroring "a fake arm
    that sleeps on a threading.Event" from the finding, i.e. an actual blocked OS thread, not
    simulated time. The vector arm answers immediately, so a test can prove a stalled arm does not
    prevent a healthy one from still contributing.

    `safety_net_s` is a hard ceiling on the block even if the test forgets to release it (or fails
    before its `finally` runs) — this fake must never be the reason a test hangs the whole suite.
    """

    def __init__(
        self,
        release: threading.Event,
        *,
        vector_hits: list[ArmHit] | None = None,
        safety_net_s: float = 10.0,
    ) -> None:
        self._release = release
        self._vector_hits = vector_hits if vector_hits is not None else []
        self._safety_net_s = safety_net_s
        self.lexical_started = threading.Event()

    def lexical_arm(
        self,
        project_id: ProjectId,
        query: str,
        top_n: int,
        *,
        statement_timeout_ms: int | None = None,
    ) -> list[ArmHit]:
        self.lexical_started.set()
        self._release.wait(timeout=self._safety_net_s)
        return []

    def vector_arm(
        self,
        project_id: ProjectId,
        embedding: Sequence[float],
        top_n: int,
        *,
        hnsw_iterative_scan: bool,
        hnsw_max_scan_tuples: int,
        statement_timeout_ms: int | None = None,
    ) -> list[ArmHit]:
        return self._vector_hits


class _StallingVectorSearch:
    """The mirror image of `_StallingLexicalSearch`: lexical answers immediately, the vector arm
    is the one blocked on a real `threading.Event`."""

    def __init__(
        self,
        release: threading.Event,
        *,
        lexical_hits: list[ArmHit] | None = None,
        safety_net_s: float = 10.0,
    ) -> None:
        self._release = release
        self._lexical_hits = lexical_hits if lexical_hits is not None else []
        self._safety_net_s = safety_net_s

    def lexical_arm(
        self,
        project_id: ProjectId,
        query: str,
        top_n: int,
        *,
        statement_timeout_ms: int | None = None,
    ) -> list[ArmHit]:
        return self._lexical_hits

    def vector_arm(
        self,
        project_id: ProjectId,
        embedding: Sequence[float],
        top_n: int,
        *,
        hnsw_iterative_scan: bool,
        hnsw_max_scan_tuples: int,
        statement_timeout_ms: int | None = None,
    ) -> list[ArmHit]:
        self._release.wait(timeout=self._safety_net_s)
        return []


class _AlwaysStallingSearch:
    """BOTH arms block on the same real `threading.Event` — used to drive the same `Retriever`
    through many consecutive stalled calls and prove thread count stays flat."""

    def __init__(self, release: threading.Event, *, safety_net_s: float = 10.0) -> None:
        self._release = release
        self._safety_net_s = safety_net_s

    def lexical_arm(
        self,
        project_id: ProjectId,
        query: str,
        top_n: int,
        *,
        statement_timeout_ms: int | None = None,
    ) -> list[ArmHit]:
        self._release.wait(timeout=self._safety_net_s)
        return []

    def vector_arm(
        self,
        project_id: ProjectId,
        embedding: Sequence[float],
        top_n: int,
        *,
        hnsw_iterative_scan: bool,
        hnsw_max_scan_tuples: int,
        statement_timeout_ms: int | None = None,
    ) -> list[ArmHit]:
        self._release.wait(timeout=self._safety_net_s)
        return []


# =============================================================================================== #
# Section 1 — `Retriever.retrieve()` directly: real thread, real stall, real (`SystemClock`) clock.
# =============================================================================================== #


def test_lexical_stall_past_the_budget_returns_within_bound_not_forever() -> None:
    """THE regression test for the finding's headline claim: before D-132 this call would have
    blocked until the fake OS-level stall itself gave up (here, up to 10s) rather than respecting
    `cfg.total_budget_ms` at all. `total_budget_ms=150` keeps the test itself fast while still
    being real wall-clock time on a real thread."""
    release = threading.Event()
    search = _StallingLexicalSearch(release, vector_hits=[_hit(MEM_VECTOR_HIT, 0.9)])
    retriever = Retriever(search, _FakeEmbeddingPort(), SystemClock())
    cfg = RetrievalConfig(total_budget_ms=150)

    started = time.perf_counter()
    try:
        outcome = retriever.retrieve(PROJECT, "how do I retry a tool call", cfg=cfg)
    finally:
        release.set()  # let the stalled background thread finish before teardown
        retriever.close()
    elapsed_s = time.perf_counter() - started

    assert isinstance(outcome, RetrievalOutcome)  # no exception escaped
    assert elapsed_s < _BOUND_S, (
        f"retrieve() took {elapsed_s:.3f}s against a 150ms budget -- the wait is unbounded again"
    )
    assert outcome.degraded is True
    # The lexical arm's own hit never arrives (it timed out); the vector arm, which answered
    # promptly, still gets to contribute -- a stalled arm must not poison a healthy one.
    assert [c.memory_id for c in outcome.candidates] == [MEM_VECTOR_HIT]


def test_vector_stall_past_the_budget_also_returns_within_bound() -> None:
    """The mirror of the test above: the vector arm's own `.result()` call must be bounded too,
    not only the lexical one — both were unbounded before D-132."""
    release = threading.Event()
    search = _StallingVectorSearch(release, lexical_hits=[_hit(MEM_VECTOR_HIT, 5.0)])
    retriever = Retriever(search, _FakeEmbeddingPort(), SystemClock())
    cfg = RetrievalConfig(total_budget_ms=150)

    started = time.perf_counter()
    try:
        outcome = retriever.retrieve(PROJECT, "query", cfg=cfg)
    finally:
        release.set()
        retriever.close()
    elapsed_s = time.perf_counter() - started

    assert elapsed_s < _BOUND_S
    assert outcome.degraded is True
    assert [c.memory_id for c in outcome.candidates] == [MEM_VECTOR_HIT]


def test_both_arms_stalling_degrades_to_empty_within_bound() -> None:
    """Neither arm answers in time: `retrieve()` must still return -- empty, degraded, bounded --
    rather than wait on whichever arm the caller happened to check first."""
    release = threading.Event()
    search = _AlwaysStallingSearch(release)
    retriever = Retriever(search, _FakeEmbeddingPort(), SystemClock())
    cfg = RetrievalConfig(total_budget_ms=120)

    started = time.perf_counter()
    try:
        outcome = retriever.retrieve(PROJECT, "query", cfg=cfg)
    finally:
        release.set()
        retriever.close()
    elapsed_s = time.perf_counter() - started

    assert elapsed_s < _BOUND_S
    assert outcome.degraded is True
    assert outcome.candidates == ()
    assert outcome.candidates_considered == 0


def test_a_lexical_stall_shorter_than_the_budget_does_not_degrade() -> None:
    """The control for the tests above: a slow-but-finite arm that answers WELL inside the budget
    must not be treated as a timeout — bounding the wait must not become "always degrade.\""""
    release = threading.Event()
    search = _StallingLexicalSearch(release, vector_hits=[])
    retriever = Retriever(search, _FakeEmbeddingPort(), SystemClock())
    cfg = RetrievalConfig(total_budget_ms=1500)

    def _release_soon() -> None:
        time.sleep(0.05)
        release.set()

    releaser = threading.Thread(target=_release_soon)
    releaser.start()
    try:
        outcome = retriever.retrieve(PROJECT, "query", cfg=cfg)
    finally:
        releaser.join()
        retriever.close()

    assert outcome.degraded is False


def test_many_stalled_calls_never_grow_the_thread_count() -> None:
    """The thread-leak half of D-132: a timed-out future is ABANDONED, never cancelled (module
    docstring's THREAD-LEAK CHOICE) -- `Future.cancel()` is a no-op once a task is running, and
    there is no way to forcibly kill a thread blocked in a psycopg call. Safety comes from reusing
    the SAME fixed-size executor across every call, not from killing anything: this drives one
    `Retriever` instance through many stalled calls and asserts the process's thread count never
    grows past the executor's own fixed worker count, no matter how many requests time out.
    """
    release = threading.Event()
    search = _AlwaysStallingSearch(release, safety_net_s=15.0)
    retriever = Retriever(search, _FakeEmbeddingPort(), SystemClock())
    cfg = RetrievalConfig(total_budget_ms=40)

    baseline_threads = threading.active_count()
    try:
        for i in range(6):
            started = time.perf_counter()
            outcome = retriever.retrieve(PROJECT, f"query {i}", cfg=cfg)
            elapsed_s = time.perf_counter() - started
            assert elapsed_s < _BOUND_S
            assert outcome.degraded is True
            assert outcome.candidates == ()

        # `_ARM_WORKER_COUNT` (2) is the ceiling: the executor is constructed once, in
        # `Retriever.__init__`, and every one of the 12 submissions above (2 arms x 6 calls) either
        # ran on one of those 2 worker threads or is still queued behind them -- never a new thread.
        grown_by = threading.active_count() - baseline_threads
        assert grown_by <= retriever_module._ARM_WORKER_COUNT, (
            f"thread count grew by {grown_by} across 6 stalled calls -- a timed-out request is "
            "leaking a thread instead of being abandoned in the fixed pool"
        )
    finally:
        release.set()  # unblock the two stuck workers so close() below does not hang draining them
        retriever.close()


def test_the_two_waits_share_one_budget_instead_of_each_getting_a_fresh_one() -> None:
    """D-132 claims the remaining budget is "re-derived, never re-widened" before each wait, so a
    lexical overrun eats into the vector arm's allowance. Nothing proved it: with both arms stalled
    and each wait handed a FRESH `total_budget_ms`, `retrieve()` takes 2x the budget and every
    other test in this file still passes (their bound is 2s). This is the test that fails for that
    mutation — the whole call, not each wait, is what invariant 2 bounds.
    """
    release = threading.Event()
    search = _AlwaysStallingSearch(release)
    retriever = Retriever(search, _FakeEmbeddingPort(), SystemClock())
    budget_ms = 600
    cfg = RetrievalConfig(total_budget_ms=budget_ms)

    started = time.perf_counter()
    try:
        outcome = retriever.retrieve(PROJECT, "query", cfg=cfg)
    finally:
        release.set()
        retriever.close()
    elapsed_s = time.perf_counter() - started

    assert outcome.degraded is True
    # Halfway between the correct bound (0.6s + scheduling jitter) and the two-fresh-budgets
    # mutant (1.2s): generous about jitter, still nowhere near "each arm got its own 600ms".
    assert elapsed_s < 0.9, (
        f"retrieve() took {elapsed_s:.3f}s for a {budget_ms}ms budget -- the second wait is "
        "getting a fresh allowance instead of what is left of the first one's"
    )


class _CountingStallingSearch:
    """Both arms block on a real `threading.Event`, and every INVOCATION is counted.

    The counter is the subject: it distinguishes "the caller stopped waiting" (which the D-132
    bound already gave us) from "the work stopped existing", which is what a wedged pool must
    actually achieve. Work that is merely abandoned is still queued, still holds its query
    embedding, and still runs — against a Postgres that has just recovered — the moment a worker
    frees up.
    """

    def __init__(self, release: threading.Event, *, safety_net_s: float = 20.0) -> None:
        self._release = release
        self._safety_net_s = safety_net_s
        self._lock = threading.Lock()
        self.invocations = 0

    def _arm(self) -> list[ArmHit]:
        with self._lock:
            self.invocations += 1
        self._release.wait(timeout=self._safety_net_s)
        return []

    def lexical_arm(
        self,
        project_id: ProjectId,
        query: str,
        top_n: int,
        *,
        statement_timeout_ms: int | None = None,
    ) -> list[ArmHit]:
        return self._arm()

    def vector_arm(
        self,
        project_id: ProjectId,
        embedding: Sequence[float],
        top_n: int,
        *,
        hnsw_iterative_scan: bool,
        hnsw_max_scan_tuples: int,
        statement_timeout_ms: int | None = None,
    ) -> list[ArmHit]:
        return self._arm()


def test_a_wedged_pool_stops_accepting_work_instead_of_queueing_it_forever() -> None:
    """`ThreadPoolExecutor`'s work queue is UNBOUNDED. Bounding only the wait (D-132) converts an
    unbounded hang into an unbounded queue: with both workers stuck in psycopg, every subsequent
    request still enqueued two more work items that could never run, each holding a whole query
    embedding, and every one of them eventually fired at Postgres. Measured directly before D-138:
    200 requests against a stalled store left 398 queued work items and executed 400 arm queries
    after recovery. The thread count stayed flat the whole time, which is why
    `test_many_stalled_calls_never_grow_the_thread_count` could not see any of it.
    """
    release = threading.Event()
    search = _CountingStallingSearch(release)
    retriever = Retriever(search, _FakeEmbeddingPort(), SystemClock())
    cfg = RetrievalConfig(total_budget_ms=30)

    requests = 40
    try:
        for i in range(requests):
            outcome = retriever.retrieve(PROJECT, f"query {i}", cfg=cfg)
            assert outcome.degraded is True
            assert outcome.candidates == ()
    finally:
        release.set()
        retriever.close()  # drains anything still queued, so the count below is final

    assert search.invocations <= _ARM_WORKER_COUNT, (
        f"{requests} requests against a wedged pool produced {search.invocations} arm queries -- "
        "abandoned work is still being queued and will be replayed at a recovering store"
    )
    # Submissions, not just executions: an item that is queued and later skipped is still a queue
    # entry holding a query embedding for as long as the stall lasts.
    assert retriever._submitted_arms <= 2 * _ARM_WORKER_COUNT, (
        f"{requests} requests submitted {retriever._submitted_arms} arm tasks to a wedged pool -- "
        "the executor's unbounded work queue grows once per request"
    )


def test_work_queued_before_the_pool_wedged_is_skipped_once_its_caller_has_given_up() -> None:
    """The other half of D-138, and the one a wedge test alone cannot reach: a request that arrives
    while the workers are merely BUSY (deadlines not yet passed) is correctly queued, then times
    out. When a worker finally frees, that task must not run — its caller returned long ago, and
    running it means a recovering store being handed every query issued during the outage.
    """
    release = threading.Event()
    search = _CountingStallingSearch(release)
    retriever = Retriever(search, _FakeEmbeddingPort(), SystemClock())
    occupied = threading.Event()

    def _occupy_both_workers() -> None:
        # A long budget, so this call's two arms are "busy", not "wedged", while the second call
        # below is admitted -- which is exactly the state that fills the queue.
        occupied.set()
        retriever.retrieve(PROJECT, "long-budget call", cfg=RetrievalConfig(total_budget_ms=900))

    occupier = threading.Thread(target=_occupy_both_workers)
    occupier.start()
    try:
        assert occupied.wait(timeout=_BOUND_S)
        time.sleep(0.05)  # let both of the first call's arms actually reach the worker threads
        queued = retriever.retrieve(PROJECT, "short-budget call", cfg=RetrievalConfig(total_budget_ms=40))
        assert queued.degraded is True
        assert retriever._submitted_arms == 4, (
            "the second call's arms were refused, not queued -- this test is no longer exercising "
            "the queued-then-stale path it exists for"
        )
    finally:
        release.set()
        occupier.join(timeout=_BOUND_S * 5)
        retriever.close()

    assert search.invocations == _ARM_WORKER_COUNT, (
        f"{search.invocations} arm queries ran; the two that were queued behind a stall outlived "
        "their caller's budget and must have been skipped, not executed"
    )


def test_a_busy_but_healthy_pool_still_queues_work_rather_than_refusing_it() -> None:
    """The control for the two tests above: admission control must fire ONLY when every worker is
    stuck past its own deadline. A second request arriving while the workers are busy with
    in-budget work must still be served normally — otherwise "bounded" would have been bought by
    refusing ordinary concurrency.
    """
    barrier = threading.Barrier(2, timeout=_BOUND_S * 2)

    class _SlowButHealthySearch:
        def lexical_arm(
            self,
            project_id: ProjectId,
            query: str,
            top_n: int,
            *,
            statement_timeout_ms: int | None = None,
        ) -> list[ArmHit]:
            barrier.wait()
            return [_hit(MEM_VECTOR_HIT, 5.0)]

        def vector_arm(
            self,
            project_id: ProjectId,
            embedding: Sequence[float],
            top_n: int,
            *,
            hnsw_iterative_scan: bool,
            hnsw_max_scan_tuples: int,
            statement_timeout_ms: int | None = None,
        ) -> list[ArmHit]:
            barrier.wait()
            return [_hit(MEM_VECTOR_HIT, 0.9)]

    retriever = Retriever(_SlowButHealthySearch(), _FakeEmbeddingPort(), SystemClock())
    cfg = RetrievalConfig(total_budget_ms=1500)
    outcomes: list[RetrievalOutcome] = []
    lock = threading.Lock()

    def _one(i: int) -> None:
        outcome = retriever.retrieve(PROJECT, f"q{i}", cfg=cfg)
        with lock:
            outcomes.append(outcome)

    threads = [threading.Thread(target=_one, args=(i,)) for i in range(2)]
    try:
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=_BOUND_S * 3)
    finally:
        retriever.close()

    assert len(outcomes) == 2
    assert [o.degraded for o in outcomes] == [False, False]
    assert all(o.candidates for o in outcomes)


class _EmptyEmbedder:
    """Returns no vector, so `retrieve()` never submits a vector arm — each call in the test below
    therefore consumes exactly ONE worker, which is what makes a mixed pool state constructible."""

    def embed(self, texts: Sequence[str], *, timeout_ms: int) -> list[list[float]]:
        return []

    @property
    def model_id(self) -> str:
        return "empty"

    @property
    def model_version(self) -> str:
        return "test"


def test_one_wedged_worker_does_not_refuse_work_the_other_worker_can_still_do() -> None:
    """Admission control must read ALL workers, not ANY: one connection stuck in psycopg while the
    other is healthy is the ordinary shape of a partial Postgres fault, and it must cost throughput,
    not the whole retrieval plane. With `any`, a single permanently-wedged worker would refuse
    every arm forever — a self-inflicted total outage strictly worse than the stall it reacts to.
    """
    stuck = threading.Event()
    stuck_started = threading.Event()
    busy = threading.Event()
    busy_started = threading.Event()

    class _MixedSearch:
        def lexical_arm(
            self,
            project_id: ProjectId,
            query: str,
            top_n: int,
            *,
            statement_timeout_ms: int | None = None,
        ) -> list[ArmHit]:
            if query == "stuck":
                stuck_started.set()
                stuck.wait(timeout=20.0)
                return []
            if query == "busy":
                busy_started.set()
                busy.wait(timeout=20.0)
                return []
            return [_hit(MEM_VECTOR_HIT, 5.0)]

        def vector_arm(
            self,
            project_id: ProjectId,
            embedding: Sequence[float],
            top_n: int,
            *,
            hnsw_iterative_scan: bool,
            hnsw_max_scan_tuples: int,
            statement_timeout_ms: int | None = None,
        ) -> list[ArmHit]:  # pragma: no cover - `_EmptyEmbedder` means this is never submitted
            raise AssertionError("no vector arm should be submitted without an embedding")

    retriever = Retriever(_MixedSearch(), _EmptyEmbedder(), SystemClock())

    def _busy_call() -> None:
        retriever.retrieve(PROJECT, "busy", cfg=RetrievalConfig(total_budget_ms=3000))

    def _free_the_busy_worker() -> None:
        time.sleep(0.15)
        busy.set()

    busy_thread = threading.Thread(target=_busy_call)
    releaser = threading.Thread(target=_free_the_busy_worker)
    try:
        # Worker 1: permanently wedged, its caller long gone.
        wedged = retriever.retrieve(PROJECT, "stuck", cfg=RetrievalConfig(total_budget_ms=30))
        assert wedged.degraded is True
        assert stuck_started.wait(timeout=_BOUND_S)

        # Worker 2: busy with in-budget work, so the pool now holds one stuck and one healthy task.
        busy_thread.start()
        assert busy_started.wait(timeout=_BOUND_S)

        releaser.start()
        outcome = retriever.retrieve(PROJECT, "third", cfg=RetrievalConfig(total_budget_ms=3000))
    finally:
        busy.set()
        stuck.set()
        for thread in (busy_thread, releaser):
            if thread.is_alive():
                thread.join(timeout=_BOUND_S * 3)
        retriever.close()

    assert [c.memory_id for c in outcome.candidates] == [MEM_VECTOR_HIT], (
        "a request was refused while one worker was still healthy -- admission control is reading "
        "ANY wedged worker instead of ALL of them"
    )


def test_a_refused_lexical_arm_degrades_even_when_the_vector_arm_is_admitted() -> None:
    """The asymmetric case, and the only one that pins the lexical half of the refusal handling:
    the pool is wedged when the lexical arm is submitted (refused) but has freed by the time the
    vector arm is (admitted). A retrieval that ran on ONE arm because the other was refused is
    degraded — reporting it as healthy would hand the caller half a candidate set with nothing on
    the `retrieval_event` row saying so. The vector arm still contributes: a refused arm must not
    poison a healthy one, exactly as a timed-out one does not.
    """
    release = threading.Event()

    class _StallThenAnswerSearch:
        """Both arms block until `release`, then answer. `completed` counts arms that finished, so
        the embedder below can wait for the wedged workers to drain."""

        def __init__(self) -> None:
            self.completed = threading.Semaphore(0)

        def _arm(self) -> list[ArmHit]:
            release.wait(timeout=20.0)
            self.completed.release()
            return [_hit(MEM_VECTOR_HIT, 0.9)]

        def lexical_arm(
            self,
            project_id: ProjectId,
            query: str,
            top_n: int,
            *,
            statement_timeout_ms: int | None = None,
        ) -> list[ArmHit]:
            return self._arm()

        def vector_arm(
            self,
            project_id: ProjectId,
            embedding: Sequence[float],
            top_n: int,
            *,
            hnsw_iterative_scan: bool,
            hnsw_max_scan_tuples: int,
            statement_timeout_ms: int | None = None,
        ) -> list[ArmHit]:
            return self._arm()

    search = _StallThenAnswerSearch()

    class _UnwedgingEmbedder:
        """`retrieve()` submits the lexical arm BEFORE embedding, so everything this does happens
        strictly between the two submissions: it frees the wedged workers, so the vector arm that
        is submitted right after this returns is admitted while the lexical one was not."""

        def __init__(self, retriever: Retriever) -> None:
            self._retriever = retriever

        def embed(self, texts: Sequence[str], *, timeout_ms: int) -> list[list[float]]:
            release.set()
            assert search.completed.acquire(timeout=_BOUND_S)
            assert search.completed.acquire(timeout=_BOUND_S)
            # A worker is still holding its slot between finishing the call and clearing its
            # registration; wait for the state the admission check actually reads.
            deadline = time.perf_counter() + _BOUND_S
            while retriever._running_deadlines and time.perf_counter() < deadline:
                time.sleep(0.001)
            assert not retriever._running_deadlines
            return [[0.1, 0.2, 0.3]]

        @property
        def model_id(self) -> str:
            return "unwedging"

        @property
        def model_version(self) -> str:
            return "test"

    retriever = Retriever(search, _FakeEmbeddingPort(), SystemClock())
    try:
        wedging = retriever.retrieve(PROJECT, "wedge me", cfg=RetrievalConfig(total_budget_ms=30))
        assert wedging.degraded is True  # both arms are now stuck past their own deadline

        retriever._embedding = _UnwedgingEmbedder(retriever)  # type: ignore[assignment]
        outcome = retriever.retrieve(PROJECT, "asymmetric", cfg=RetrievalConfig(total_budget_ms=1500))
    finally:
        release.set()
        retriever.close()

    assert [c.memory_id for c in outcome.candidates] == [MEM_VECTOR_HIT], (
        "the admitted vector arm did not contribute -- this test is no longer exercising the "
        "asymmetric refusal it exists for"
    )
    assert outcome.degraded is True, (
        "the lexical arm was refused outright and the retrieval was still reported as healthy"
    )


class _TimeoutRaisingLexicalSearch:
    """The lexical arm RAISES a builtin `TimeoutError` — what psycopg surfaces for a socket
    read/connect expiry — rather than the wait expiring."""

    def lexical_arm(
        self,
        project_id: ProjectId,
        query: str,
        top_n: int,
        *,
        statement_timeout_ms: int | None = None,
    ) -> list[ArmHit]:
        raise TimeoutError("psycopg: socket read timed out")

    def vector_arm(
        self,
        project_id: ProjectId,
        embedding: Sequence[float],
        top_n: int,
        *,
        hnsw_iterative_scan: bool,
        hnsw_max_scan_tuples: int,
        statement_timeout_ms: int | None = None,
    ) -> list[ArmHit]:
        return []


def test_a_store_raised_timeout_propagates_instead_of_reading_as_the_budget_expiring() -> None:
    """`concurrent.futures.TimeoutError` IS the builtin `TimeoutError` on 3.11+, so the D-132 catch
    swallowed a store's own timeout as though the retrieval budget had expired: a Postgres that
    refused to answer in 3ms was recorded as `degraded_lexical`/`timeout_prefix_only` (a met
    contract) instead of `store_error` (a broken one) — on the very `retrieval_event` row PLAN.md
    §5 keeps to tell those two apart, and against `Retriever`'s own documented promise that a
    non-timeout arm exception propagates unmodified. Told apart by identity (D-138): the exception
    the future holds IS the one raised, so it came from the arm, not from the wait.
    """
    retriever = Retriever(_TimeoutRaisingLexicalSearch(), _FakeEmbeddingPort(), SystemClock())
    started = time.perf_counter()
    try:
        with pytest.raises(TimeoutError, match="socket read timed out"):
            retriever.retrieve(PROJECT, "query", cfg=RetrievalConfig(total_budget_ms=1500))
    finally:
        retriever.close()

    # It must surface AT ONCE, not after the full budget: proof the arm's exception is what came
    # out, rather than the wait quietly running to its own expiry and re-raising something else.
    assert time.perf_counter() - started < 1.0


# =============================================================================================== #
# Section 2 — the full `Pipeline`, wired with the REAL `Retriever` (not a fake retriever port).
# =============================================================================================== #


def _scope() -> ProjectScope:
    return ProjectScope(
        project_id=PROJECT,
        agent_type_id=AgentTypeId(uuid4()),
        principal_id=PrincipalId(uuid4()),
    )


def _cfg(*, total_budget_ms: int) -> EffectiveConfig:
    return EffectiveConfig(
        retrieval=RetrievalConfig(total_budget_ms=total_budget_ms),
        abstention=AbstentionConfig(),
        score=ScoreConfig(),
        budget=BudgetConfig(),
        scoring=ScoringConfig(),
        promotion=PromotionConfig(),
        retirement=RetirementConfig(),
        lifecycle=LifecycleConfig(),
        derived=DerivedConfig(),
        proposals=ProposalConfig(),
        tier_a=TierAConfig(),
        # 0.0, not the shipped 5.0 default: this file is not testing the holdout arm, and a random
        # draw would occasionally withhold the block this test is asserting the CONTENT of.
        killswitch=KillswitchConfig(holdout_pct=0.0),
        spend=SpendConfig(),
        cache=CacheConfig(),
        session=SessionConfig(),
        queue=QueueConfig(),
        killswitch_overlay={},
    )


class _ConfigProvider:
    def __init__(self, cfg: EffectiveConfig) -> None:
        self._cfg = cfg

    def effective(
        self, project_id: ProjectId, agent_type_id: AgentTypeId | None = None
    ) -> EffectiveConfig:
        return self._cfg


class _RecordingTelemetry:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def record_retrieval(
        self,
        project_id: ProjectId,
        run_id: RunId,
        *,
        outcome_code: OutcomeCode,
        latency_ms: int,
        embed_latency_ms: int | None,
        candidates_considered: int,
        top_score: float | None,
        arm: Arm,
    ) -> None:
        self.calls.append({"outcome_code": outcome_code, "latency_ms": latency_ms})


class _AssemblyMustNotBeCalled:
    """Satisfies `CandidateAssemblyPort`. `hotpath.pipeline.Pipeline._run_ladder` checks
    `deadline.total_exceeded()` a SECOND time right after the retriever call and returns
    `timeout_prefix_only` before ever reaching assembly -- so a stalled retriever must mean this
    is never invoked at all. Raising proves that rather than merely hoping for it."""

    def run(self, scope: ProjectScope, *, query_text: str, candidates: object, cfg: object) -> CandidateSetResult:
        raise AssertionError(
            "assembly.run() was called even though the retriever stalled past the total "
            "budget -- the second deadline check before assembly did not fire"
        )


def test_pipeline_maps_a_stalled_retriever_to_timeout_prefix_only_not_store_error() -> None:
    """End-to-end proof, with the REAL `Retriever` (unlike every test in
    `test_degradation_ladder.py`, which fakes `HybridRetrieverPort` directly): a stalled lexical
    arm must surface as `OutcomeCode.TIMEOUT_PREFIX_ONLY` -- the ladder's own, correctly-named
    "total budget exceeded" rung -- not `store_error`, and `Pipeline.retrieve()` must still return
    (no exception) within a bound, on a real clock.
    """
    release = threading.Event()
    search = _StallingLexicalSearch(release, vector_hits=[_hit(MEM_VECTOR_HIT, 0.9)])
    clock = SystemClock()
    retriever = Retriever(search, _FakeEmbeddingPort(), clock)
    pipeline = Pipeline(
        clock=clock,
        config=_ConfigProvider(_cfg(total_budget_ms=150)),
        telemetry=(telemetry := _RecordingTelemetry()),
        retriever=retriever,
        assembly=_AssemblyMustNotBeCalled(),
        holdout_salt="test-salt",
    )

    started = time.perf_counter()
    try:
        result = pipeline.retrieve(_scope(), RunContext(query_text="q"), session_id="s-1")
    finally:
        release.set()
        retriever.close()
    elapsed_s = time.perf_counter() - started

    assert elapsed_s < _BOUND_S
    assert result.outcome_code is OutcomeCode.TIMEOUT_PREFIX_ONLY
    assert telemetry.calls == [
        {"outcome_code": OutcomeCode.TIMEOUT_PREFIX_ONLY, "latency_ms": telemetry.calls[0]["latency_ms"]}
    ]
    assert isinstance(telemetry.calls[0]["latency_ms"], int)
    assert telemetry.calls[0]["latency_ms"] >= 0


# =============================================================================================== #
# Section 3 — `stores.pg.pool`'s new, opt-in `statement_timeout` / `idle_in_transaction_session_
# timeout` (per-transaction) and `connect_timeout` (per-connection) controls. Offline: there is no
# Postgres in this environment, so — same convention as every other `stores/pg` offline test in
# this repository (e.g. `tests/phase0/test_repo_isolation_offline.py`) — a fake connection records
# the SQL it is handed and the assertions are on exactly what was issued, in what order.
# =============================================================================================== #


class _FakeCursor:
    """Only what `stores.pg.search` uses: `execute` (logged, same list as the connection's, so
    statement ORDER across the two is preserved) and a `fetchall` that returns nothing. The rows
    are not this file's subject -- which SQL the transaction issued, in what order, is."""

    def __init__(self, log: list[tuple[str, Any]]) -> None:
        self._log = log

    def execute(self, sql: str, params: Any = None) -> None:
        self._log.append((sql, params))

    def fetchall(self) -> list[Any]:
        return []

    def __enter__(self) -> _FakeCursor:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class _FakeConn:
    def __init__(self, log: list[tuple[str, Any]]) -> None:
        self._log = log

    def execute(self, sql: str, params: Any = None) -> None:
        self._log.append((sql, params))

    def cursor(self, **_kwargs: Any) -> _FakeCursor:
        return _FakeCursor(self._log)

    def transaction(self) -> _FakeConn:
        return self

    def __enter__(self) -> _FakeConn:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class _FakePool:
    """Stands in for `psycopg_pool.ConnectionPool`; `scoped()` only ever calls `.connection()`."""

    def __init__(self) -> None:
        self.log: list[tuple[str, Any]] = []

    def connection(self) -> _FakeConn:
        return _FakeConn(self.log)


def test_scoped_without_timeouts_issues_only_the_rls_guc_unchanged_behaviour() -> None:
    """The default (no keyword args) must be byte-identical to `scoped()`'s behaviour before
    D-132 -- `stores.pg.search.SearchStore` and `stores.pg.repo.Repo` are not edited by this
    change, so every call either of them makes today must keep working exactly as before."""
    pool = _FakePool()  # type: ignore[arg-type]
    with pool_module.scoped(pool, PROJECT):  # type: ignore[arg-type]
        pass

    assert pool.log == [(pool_module._SET_PROJECT_GUC, {"project_id": str(PROJECT)})]


def test_scoped_with_statement_timeout_issues_it_right_after_the_rls_guc() -> None:
    pool = _FakePool()  # type: ignore[arg-type]
    with pool_module.scoped(pool, PROJECT, statement_timeout_ms=250):  # type: ignore[arg-type]
        pass

    assert pool.log == [
        (pool_module._SET_PROJECT_GUC, {"project_id": str(PROJECT)}),
        (pool_module._SET_STATEMENT_TIMEOUT, {"statement_timeout_ms": "250"}),
    ]


def test_scoped_with_idle_in_transaction_timeout_issues_it_too() -> None:
    pool = _FakePool()  # type: ignore[arg-type]
    with pool_module.scoped(  # type: ignore[arg-type]
        pool, PROJECT, statement_timeout_ms=250, idle_in_transaction_session_timeout_ms=500
    ):
        pass

    assert pool.log == [
        (pool_module._SET_PROJECT_GUC, {"project_id": str(PROJECT)}),
        (pool_module._SET_STATEMENT_TIMEOUT, {"statement_timeout_ms": "250"}),
        (
            pool_module._SET_IDLE_IN_TRANSACTION_TIMEOUT,
            {"idle_in_transaction_session_timeout_ms": "500"},
        ),
    ]


@pytest.mark.parametrize("bad", [0, -1, -300])
def test_scoped_rejects_a_non_positive_statement_timeout(bad: int) -> None:
    pool = _FakePool()  # type: ignore[arg-type]
    with (
        pytest.raises(ValueError, match="statement_timeout_ms"),
        pool_module.scoped(pool, PROJECT, statement_timeout_ms=bad),  # type: ignore[arg-type]
    ):
        pass  # pragma: no cover - never reached
    # Refusing the value must not have left a half-applied GUC on the (fake) connection.
    assert pool.log == []


@pytest.mark.parametrize("bad", [0, -1])
def test_scoped_rejects_a_non_positive_idle_in_transaction_timeout(bad: int) -> None:
    pool = _FakePool()  # type: ignore[arg-type]
    with (
        pytest.raises(ValueError, match="idle_in_transaction_session_timeout_ms"),
        pool_module.scoped(  # type: ignore[arg-type]
            pool, PROJECT, idle_in_transaction_session_timeout_ms=bad
        ),
    ):
        pass  # pragma: no cover - never reached
    assert pool.log == []


@pytest.mark.parametrize(
    ("statement", "guc"),
    [
        (pool_module._SET_PROJECT_GUC, "tracebed.project_id"),
        (pool_module._SET_STATEMENT_TIMEOUT, "statement_timeout"),
        (pool_module._SET_IDLE_IN_TRANSACTION_TIMEOUT, "idle_in_transaction_session_timeout"),
    ],
)
def test_every_scoped_guc_is_named_correctly_and_scoped_to_the_transaction(
    statement: str, guc: str
) -> None:
    """The three assertions above compare `pool.log` against `pool_module`'s OWN constants, so they
    pin WHICH statement runs and in what order — and nothing at all about what it says. Changing
    `set_config(..., true)` to `false` (session-scoped: a hot path's 300ms `statement_timeout`
    survives the transaction and lands on whatever checks that pooled connection out next — the
    background worker this design exists to protect) or misspelling a GUC name leaves all of them
    green. This is the assertion on the text itself; `true` is the whole safety argument for
    letting one shared pool carry a hot-path budget at all (C-09, pool.py's HARD CANCELLATION note).
    """
    normalised = " ".join(statement.split())
    assert f"set_config('{guc}'" in normalised, f"the GUC name in {normalised!r} is not {guc!r}"
    assert normalised.endswith(", true)"), (
        f"{normalised!r} is not transaction-scoped -- it leaks onto the pooled connection's next "
        "checkout, which for a shared pool means the background plane inherits a hot-path bound"
    )


class _FakeConnectionPoolCtor:
    """Captures exactly what `create_pool()` hands to `psycopg_pool.ConnectionPool.__init__` --
    swapped in via monkeypatch so this test never opens a real socket (there is no Postgres here).
    """

    _SENTINEL = object()

    last_kwargs: dict[str, Any] | None = None
    last_call: dict[str, Any] | None = None
    last_timeout: object = _SENTINEL

    def __init__(
        self,
        dsn: str,
        *,
        min_size: int,
        max_size: int,
        open: bool,
        kwargs: dict[str, Any] | None,
        timeout: float | object = _SENTINEL,
    ) -> None:
        type(self).last_call = {
            "dsn": dsn,
            "min_size": min_size,
            "max_size": max_size,
            "open": open,
        }
        type(self).last_kwargs = kwargs
        # `timeout` is captured as "was it passed at all", not as a value with a default, because
        # NOT passing it is the behaviour under test for the no-checkout-timeout case: psycopg's
        # own 30s default must remain psycopg's business, not something this repository restates.
        type(self).last_timeout = timeout


def test_create_pool_without_connect_timeout_matches_the_prior_call_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pool_module, "ConnectionPool", _FakeConnectionPoolCtor)

    pool_module.create_pool("postgresql://example/db")

    assert _FakeConnectionPoolCtor.last_call == {
        "dsn": "postgresql://example/db",
        "min_size": 1,
        "max_size": 10,
        "open": True,
    }
    assert _FakeConnectionPoolCtor.last_kwargs is None


def test_create_pool_with_connect_timeout_passes_it_as_connection_kwargs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pool_module, "ConnectionPool", _FakeConnectionPoolCtor)

    pool_module.create_pool("postgresql://example/db", connect_timeout_s=7)

    assert _FakeConnectionPoolCtor.last_kwargs == {"connect_timeout": 7}


def test_create_pool_without_checkout_timeout_does_not_pass_one_at_all(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Absence, not a restated default. `psycopg_pool`'s own 30s `timeout` is that library's
    decision; passing it back explicitly would freeze it into this repository's source, where it
    would silently stop tracking the library on any upgrade."""
    monkeypatch.setattr(pool_module, "ConnectionPool", _FakeConnectionPoolCtor)

    pool_module.create_pool("postgresql://example/db")

    assert _FakeConnectionPoolCtor.last_timeout is _FakeConnectionPoolCtor._SENTINEL


def test_create_pool_with_checkout_timeout_passes_it_as_the_pools_own_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The third bound (D-139), and the only one needing no server cooperation: how long
    `pool.connection()` waits for a FREE connection. It is `ConnectionPool`'s `timeout=`, NOT a
    `kwargs` entry -- `kwargs` is forwarded to `psycopg.Connection.connect()`, where a `timeout`
    key is not a libpq parameter at all and would be silently meaningless."""
    monkeypatch.setattr(pool_module, "ConnectionPool", _FakeConnectionPoolCtor)

    pool_module.create_pool("postgresql://example/db", checkout_timeout_s=2.5)

    assert _FakeConnectionPoolCtor.last_timeout == 2.5
    assert _FakeConnectionPoolCtor.last_kwargs is None


@pytest.mark.parametrize("bad", [0, -1, -0.5])
def test_create_pool_refuses_a_non_positive_checkout_timeout(
    bad: float, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Zero would mean "never wait", which turns a momentarily-saturated pool into a total
    outage; a negative value is not a duration at all. Refused where it is passed, so the
    misconfiguration is named rather than becoming an unexplained flood of `PoolTimeout`."""
    monkeypatch.setattr(pool_module, "ConnectionPool", _FakeConnectionPoolCtor)

    with pytest.raises(ValueError, match="checkout_timeout_s must be positive"):
        pool_module.create_pool("postgresql://example/db", checkout_timeout_s=bad)


# =============================================================================================== #
# Section 4 -- D-139: the wiring. Every mechanism in sections 1-3 was complete and INERT: no call
# site passed any of it, so nothing ever un-wedged a stuck retriever worker except the query
# returning on its own. These tests are about the arguments, which is where the gap actually was.
# =============================================================================================== #


class _RecordingSearch:
    """Records the `statement_timeout_ms` each arm was handed, and nothing else."""

    def __init__(self) -> None:
        self.lexical_timeouts: list[int | None] = []
        self.vector_timeouts: list[int | None] = []

    def lexical_arm(
        self,
        project_id: ProjectId,
        query: str,
        top_n: int,
        *,
        statement_timeout_ms: int | None = None,
    ) -> list[ArmHit]:
        self.lexical_timeouts.append(statement_timeout_ms)
        return []

    def vector_arm(
        self,
        project_id: ProjectId,
        embedding: Sequence[float],
        top_n: int,
        *,
        hnsw_iterative_scan: bool,
        hnsw_max_scan_tuples: int,
        statement_timeout_ms: int | None = None,
    ) -> list[ArmHit]:
        self.vector_timeouts.append(statement_timeout_ms)
        return []


def test_both_arms_receive_a_server_side_bound_inside_the_configured_budget() -> None:
    """The bound reaches the store, and it is derived from `retrieval.total_budget_ms` rather
    than being a constant. Two projects with different budgets must produce different bounds --
    a hardcoded number would satisfy the first assertion and fail the second."""
    search = _RecordingSearch()
    retriever = Retriever(search, _FakeEmbeddingPort(), SystemClock())  # type: ignore[arg-type]
    try:
        retriever.retrieve(PROJECT, "q", cfg=RetrievalConfig(total_budget_ms=300))
        retriever.retrieve(PROJECT, "q", cfg=RetrievalConfig(total_budget_ms=50))
    finally:
        retriever.close()

    assert len(search.lexical_timeouts) == 2
    assert len(search.vector_timeouts) == 2
    for bound in search.lexical_timeouts + search.vector_timeouts:
        assert bound is not None, "an arm was issued with no server-side bound at all"
        assert bound >= 1, "a bound of 0 means NO LIMIT to Postgres -- the opposite of a bound"

    generous_lexical, tight_lexical = search.lexical_timeouts
    assert generous_lexical is not None
    assert tight_lexical is not None
    assert generous_lexical <= 300
    assert tight_lexical <= 50
    assert tight_lexical < generous_lexical, (
        "both budgets produced the same server-side bound -- it is a constant, not a derivation "
        "of retrieval.total_budget_ms"
    )


def test_the_server_side_bound_narrows_as_the_budget_is_spent() -> None:
    """The vector arm is submitted only AFTER the embed call returns, so by the time it starts,
    part of the budget is already gone. Its server-side bound must reflect what is actually left,
    not the full budget again -- otherwise the one call could hold a Postgres backend for close
    to twice `total_budget_ms`, which is the overrun the whole D-132 derivation exists to stop."""

    class _SlowEmbedder:
        def embed(self, texts: Sequence[str], *, timeout_ms: int) -> list[list[float]]:
            time.sleep(0.12)
            return [[0.1, 0.2, 0.3]]

        @property
        def model_id(self) -> str:
            return "slow"

        @property
        def model_version(self) -> str:
            return "test"

    search = _RecordingSearch()
    retriever = Retriever(search, _SlowEmbedder(), SystemClock())  # type: ignore[arg-type]
    try:
        retriever.retrieve(PROJECT, "q", cfg=RetrievalConfig(total_budget_ms=1000))
    finally:
        retriever.close()

    lexical = search.lexical_timeouts[0]
    vector = search.vector_timeouts[0]
    assert lexical is not None
    assert vector is not None
    assert vector < lexical, (
        f"vector bound {vector} is not narrower than lexical bound {lexical} -- each arm is "
        "getting a fresh full budget server-side"
    )
    assert lexical - vector >= 100, (
        "the 120ms spent embedding is not reflected in the vector arm's server-side bound"
    )


def test_the_search_store_turns_the_bound_into_a_transaction_scoped_guc() -> None:
    """The last hop, and the one that makes the bound real rather than a parameter that is
    accepted and dropped: `SearchStore` must hand it to `scoped()`, which issues it as
    `set_config(..., true)`. Driven through the real `SearchStore` against the same fake
    connection section 3 uses."""
    pool = _FakePool()
    store = SearchStore(pool)  # type: ignore[arg-type]

    store.lexical_arm(PROJECT, "hello world", 10, statement_timeout_ms=137)

    issued = [sql for sql, _ in pool.log]
    assert pool_module._SET_STATEMENT_TIMEOUT in issued, (
        f"SearchStore.lexical_arm accepted a statement_timeout_ms and never issued it: {issued}"
    )
    assert dict(pool.log)[pool_module._SET_STATEMENT_TIMEOUT] == {"statement_timeout_ms": "137"}
    assert issued.index(pool_module._SET_PROJECT_GUC) < issued.index(
        pool_module._SET_STATEMENT_TIMEOUT
    ), "the RLS GUC must remain the FIRST statement of the transaction (invariant 4)"


def test_a_search_store_call_without_a_bound_still_issues_only_the_rls_guc() -> None:
    """The control for the test above: every non-hot-path caller of `SearchStore` passes nothing,
    and must keep getting exactly the pre-D-139 transaction. A default that quietly applied the
    hot path's bound would strangle the background plane through the shared pool."""
    pool = _FakePool()
    store = SearchStore(pool)  # type: ignore[arg-type]

    store.lexical_arm(PROJECT, "hello world", 10)

    assert [sql for sql, _ in pool.log if "set_config" in sql] == [pool_module._SET_PROJECT_GUC]


@pytest.mark.parametrize("call_site", ["api/main.py", "workers/runner.py"])
def test_both_pool_call_sites_pass_both_process_level_bounds(call_site: str) -> None:
    """The finding this section exists for: the mechanism was complete and NO CALL SITE USED IT.
    Asserted on the source text of the two `create_pool` calls, because both live inside `run()`
    entry points that construct a real pool against a real DSN -- unreachable offline.
    """
    source = (_SRC_ROOT / call_site).read_text(encoding="utf-8")
    call = re.search(r"create_pool\((?P<args>[^)]*)\)", source)
    assert call is not None, f"{call_site} no longer calls create_pool at all"
    args = call.group("args")
    assert "connect_timeout_s=settings.storage.pg_connect_timeout_s" in args, (
        f"{call_site}'s pool takes no connect_timeout: {args!r}"
    )
    assert "checkout_timeout_s=settings.storage.pg_checkout_timeout_s" in args, (
        f"{call_site}'s pool takes no checkout timeout: {args!r}"
    )


@pytest.mark.parametrize("call_site", ["api/main.py", "workers/runner.py"])
def test_neither_pool_bound_is_a_literal_at_the_call_site(call_site: str) -> None:
    """Hard rule 4. Both values must come from `StorageConfig`, so an operator can move them and
    so the two planes cannot silently drift apart."""
    source = (_SRC_ROOT / call_site).read_text(encoding="utf-8")
    call = re.search(r"create_pool\((?P<args>[^)]*)\)", source)
    assert call is not None
    assert not re.search(r"timeout_s=\s*[\d.]", call.group("args")), (
        f"{call_site} passes a literal timeout to create_pool instead of reading config"
    )
