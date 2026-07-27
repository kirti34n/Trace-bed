"""Hybrid retrieval: BM25 arm + ANN arm, concurrently, fused by RRF (PLAN.md §7 Phase 1).

`Retriever.retrieve()` is the hot path's single entry point into the two search arms
(`stores.pg.search.SearchStore`). It owns exactly two responsibilities beyond calling out to its
collaborators:

1. **The embed sub-budget (invariant 2 / D-010).** Query embedding goes through an
   `EmbeddingPort`-shaped port under its own `retrieval.embed_timeout_ms` (default 200ms)
   sub-budget. That port's contract (`adapters.ports.EmbeddingPort`) is "raises `EmbeddingTimeout`
   past `timeout_ms`; must not retry internally — the caller owns the budget", so this module's job
   is exactly that: pass the sub-budget through, and on `EmbeddingTimeout` degrade to a
   lexical-only retrieval rather than raising. `degraded=True` on the returned `RetrievalOutcome`
   is that signal — it is never silently absorbed into a shorter candidate list with no indication
   why.
2. **Concurrency, HARD-BOUNDED.** The two arms are independent Postgres reads; running them
   sequentially would simply add their latencies for no benefit. `retrieve()` submits both to a
   small thread pool (they are blocking I/O, so the GIL is released for the duration of each) and
   waits for both. The lexical arm is submitted BEFORE the embed call, not after: the embed
   sub-budget (200ms) is two thirds of the whole retrieval budget (`retrieval.total_budget_ms`,
   300ms), so an embed that runs to its timeout with the lexical arm not yet started spends 200ms
   and only then begins the one arm that is still going to answer — the degraded path would
   routinely blow the total budget and be downgraded again, by the ladder, to prefix-only.
   Overlapping the two means the lexical arm's latency is paid inside the embed window instead of
   after it, so "the embedder stalled" costs the ladder one rung, not two.

   BMAD-EVALUATION finding (D-132): `Future.result()` used to be called with no timeout at all, so
   a stalled Postgres connection blocked `retrieve()` — and the calling agent's run — indefinitely.
   The 300ms budget was checked only BEFORE each arm started, never WHILE one was running. Both
   `.result()` calls below are now bounded by `cfg.total_budget_ms`, measured from this method's own
   entry against the injected `Clock`, and re-derived (never re-widened) before each wait so the
   lexical arm's overrun eats into the vector arm's own allowance rather than being paid twice. A
   timed-out wait does not raise: it returns that arm's hits as empty and flips `degraded`, the same
   signal an embed timeout produces, so `retrieve()` still returns a valid `RetrievalOutcome` and
   `hotpath.pipeline.Pipeline`'s OWN post-call `deadline.total_exceeded()` check — unchanged,
   already there — is what correctly stamps `OutcomeCode.TIMEOUT_PREFIX_ONLY` on the retrieval_event
   row, because by the time a wait here has actually timed out, the total budget checked from
   `Pipeline`'s (earlier) anchor has necessarily also elapsed. Letting the `TimeoutError` "escape"
   raw would instead hit `Pipeline`'s blanket exception guard and mislabel a budget expiry as
   `store_error` — a real failure — rather than the ladder's own, correctly-named second rung.

   THREAD-LEAK CHOICE: a timed-out future is abandoned, never cancelled. `Future.cancel()` is a
   documented no-op once a submitted callable has started running (`concurrent.futures`'s own
   contract), and there is no supported way in this codebase to forcibly kill a thread blocked
   inside a psycopg call. Abandoning it — simply stopping the wait and moving on — never creates a
   NEW thread, because the executor is the one, fixed-size (`_ARM_WORKER_COUNT` = 2) pool
   constructed once in `Retriever.__init__` and reused for the object's whole lifetime: a stuck arm
   occupies one of those two slots until its own query is stopped. What stops it is the SERVER-side
   bound described next; thread count stays flat at two no matter how many requests time out.

   SERVER-SIDE BOUND (D-139), the half that actually un-wedges a worker. Everything above bounds
   what THIS process waits for. None of it stops Postgres executing, so until this was wired a
   stuck arm held one of the two slots for the entire life of the stall and only the query
   returning on its own ever released it — which also meant `close()` blocked at shutdown, and the
   admission control above spent most of a stall refusing rather than serving. `_run_arm` now
   derives `statement_timeout_ms` from the SAME `deadline_ms` every other bound in this module
   uses, at the instant the query is about to be issued, and `stores.pg.search` passes it to
   `stores.pg.pool.scoped()` as a transaction-scoped `set_config`. No new configuration knob
   exists for it: the number is `retrieval.total_budget_ms` minus elapsed, so the client-side and
   server-side bounds cannot drift apart, and being transaction-scoped it can never leak onto the
   next checkout of that pooled connection — which is the property that lets one shared pool carry
   a hot-path bound at all.

   ADMISSION CONTROL (D-138), the half a flat thread count hides: `ThreadPoolExecutor`'s work queue
   is UNBOUNDED, so bounding only the WAIT converts an unbounded hang into an unbounded queue. With
   both workers wedged in psycopg, every further request still enqueued two work items that could
   never run, each holding a whole query embedding — measured on this code before the fix, 200
   requests against a stalled store left 398 queued items and then fired all 400 arm queries at
   Postgres the instant it recovered, which is a self-inflicted stampede at exactly the worst
   moment. Two changes close it, and neither adds a tunable: an arm is submitted only if some worker
   is doing work whose caller can still use it (`_arm_pool_is_wedged` — ALL workers past their own
   deadline, not any, so one bad connection costs throughput rather than the whole retrieval
   plane), and an arm that reaches a worker after its caller's deadline has passed does not run at
   all (`_run_arm`). Both refusals report `_ArmAbandoned` through the same `Future` a timed-out wait
   reads, so there is exactly one way for this module to learn an arm contributed nothing, and
   `degraded` cannot be forgotten on a new path. `tests/phase1/test_hard_cancellation.py` proves
   each part, including the two controls that matter more than the bound itself: a busy-but-healthy
   pool still queues, and one wedged worker does not refuse what the other can still serve.
3. **The fused cut (`retrieval.fused_top_n`).** Each arm returns up to `arm_top_n` (50) rows, so
   fusion can hand back up to 100 candidates; PLAN.md §6 pins the fused list at `fused_top_n` (20).
   Applying it here, rather than leaving it to the assembler, is what keeps the per-candidate work
   downstream (content fetch, tokenisation, abstention signals) proportional to the configured
   number rather than to twice the arm width.

Everything else — RRF fusion, the "no thresholdable score" structural guarantee — is
`hotpath.fusion`'s job; this module never computes a score itself.

CONTRACT NOTE (reported, not silently assumed): `hotpath.abstention`'s own module docstring
states that "computing per-term document frequency ... is the retriever's job, not this
module's" — implying a future integration wires `stores.pg.search.document_frequency` /
`corpus_size` through this module into `abstention.CandidateSignals.rarity`. That wiring needs a
candidate's full content text to compute *shared* query/candidate terms, which
`hotpath.fusion.FusedCandidate` deliberately does not carry (this chunk's own task boundary is
"returns candidates with raw signals attached," with no rarity-evidence assembly named in its test
list). `SearchStore.document_frequency`/`corpus_size` are implemented and exported for that future
chunk to call — composing them into `CandidateSignals` is left to whichever component already
holds candidate content (the assembler, which fetches it to render slots).

Purity (invariant 1): this module imports only `domain`, `stores`, `adapters.embedding`,
`hotpath`, and stdlib — all on `scripts/purity_check.py`'s allowlist, which proves no generative
client and no `workers`/`ingest`/`crypto` module is reachable from here by reachability, not by
convention.

`QueryEmbedderPort` below is a locally-declared, structurally-compatible narrowing of
`adapters.ports.EmbeddingPort` down to the single method this module calls. It was originally
introduced to route around a `scripts/purity_check.py` false positive (`adapters.ports` names
`adapters.identity` under `if TYPE_CHECKING:`, and the AST walk counted that never-executed
import as a reachability edge); that root cause is fixed — the walker now skips
`if TYPE_CHECKING:` bodies (D-064) — so the Protocol is kept for the reason that outlives it:
it is the smallest surface a fake embedder in an offline test has to satisfy.
`tests/phase1/test_retriever.py::test_local_query_embedder_port_matches_the_real_embedding_port`
compares it against the real `EmbeddingPort` signature, so the narrowing cannot drift into a
second, competing port definition.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import dataclass
from functools import partial
from math import ceil
from typing import Protocol, runtime_checkable

from tracebed.adapters.embedding.pinning import EmbeddingProviderError
from tracebed.domain.clock import Clock
from tracebed.domain.config import RetrievalConfig
from tracebed.domain.errors import EmbeddingTimeout
from tracebed.domain.ids import ProjectId
from tracebed.hotpath.fusion import FusedCandidate, fuse
from tracebed.stores.pg.search import ArmHit, SearchStore

__all__ = [
    "QueryEmbedderPort",
    "RetrievalOutcome",
    "Retriever",
]

# Exactly the two arms; a Retriever never needs more workers than concurrent queries it issues.
_ARM_WORKER_COUNT = 2


@runtime_checkable
class QueryEmbedderPort(Protocol):
    """Exactly the one method of `adapters.ports.EmbeddingPort` this module calls.

    Structural, so the real `EmbeddingPort` implementations satisfy it with no registration and
    no adapter. Declared here purely to keep `adapters.identity` off this module's static import
    graph (see the module docstring) — it is not a second, competing port definition, and
    `tests/phase1/test_retriever.py::test_local_query_embedder_port_matches_the_real_embedding_port`
    fails if the two signatures ever diverge.
    """

    def embed(self, texts: Sequence[str], *, timeout_ms: int) -> list[list[float]]: ...


@dataclass(frozen=True, slots=True)
class RetrievalOutcome:
    """What one `retrieve()` call produced.

    `degraded` is `True` when the embed sub-budget was exceeded and the vector arm was skipped
    entirely, OR when either search arm's own wait timed out against `cfg.total_budget_ms` (D-132:
    a stalled arm returns its hits as empty rather than blocking `retrieve()` indefinitely — module
    docstring's "HARD-BOUNDED" section). Either way the caller (assembler / API layer) is expected
    to map this to `OutcomeCode.DEGRADED_LEXICAL` on the `retrieval_event` row, UNLESS
    `hotpath.pipeline.Pipeline`'s own post-call `deadline.total_exceeded()` check fires first — which
    it will whenever an arm-level timeout is what produced this flag, since that timeout is itself
    evidence the total budget ran out. This module does not stamp an `OutcomeCode` itself, because
    "abstained" / "empty" / "injected" are decisions this module has no visibility into (abstention
    and slot assembly happen downstream).

    `candidates_considered` is the size of the union of both arms' own candidate sets, before RRF
    fusion collapses duplicates AND before the `fused_top_n` cut — matching
    `RetrievalEventInsert.candidates_considered`'s intent (contract §5.2): how much work the
    retriever actually did, not how many candidates survived fusion. It is therefore `>=
    len(candidates)` always, and the gap between the two is exactly what the cut discarded.
    """

    candidates: tuple[FusedCandidate, ...]
    degraded: bool
    embed_latency_ms: int
    candidates_considered: int


class _ArmAbandoned(Exception):
    """This arm produced nothing because the call's budget was already spent, not because the
    store failed.

    Carried through the `Future` so that BOTH "the pool was wedged, so this arm was never
    submitted" and "this arm reached a worker only after its caller's deadline had passed" arrive
    at the caller through the exact same channel a timed-out wait does — `_await_arm`'s
    `(hits, timed_out)` pair. Signalling them by returning an empty list instead would be
    indistinguishable from "the query legitimately matched nothing," and a retrieval that ran on
    one arm would be recorded as healthy (D-138).
    """


def _abandoned_arm(reason: str) -> Future[list[ArmHit]]:
    """A future that is already resolved to `_ArmAbandoned` — an arm that never ran."""
    future: Future[list[ArmHit]] = Future()
    future.set_exception(_ArmAbandoned(reason))
    return future


def _await_arm(future: Future[list[ArmHit]], remaining_ms: float) -> tuple[list[ArmHit], bool]:
    """Waits up to `remaining_ms` (already clamped to `>= 0` by the caller) for one arm's future.

    Returns `(hits, timed_out)` rather than raising: a timed-out arm is not an error this module
    reports, it is the same "unusable, degrade" signal an embed timeout already produces (module
    docstring's HARD-BOUNDED section / D-132). `remaining_ms == 0` still calls `future.result(
    timeout=0)`, which is a legitimate, well-defined operation (return immediately if already done,
    else raise `TimeoutError` at once) — it never blocks, it only means "there is no time left to
    wait," which is exactly correct once the budget is spent.

    D-138: `concurrent.futures.TimeoutError` has been a plain ALIAS of the builtin `TimeoutError`
    since Python 3.11, and psycopg surfaces a socket read/connect expiry as that same builtin. So a
    bare `except FutureTimeoutError` cannot tell "MY wait expired" (degrade — the budget ran out)
    from "the ARM raised a timeout" (a store failure, which the class docstring promises propagates
    unmodified so `Pipeline` records the ladder's `store_error` rung rather than reporting a broken
    Postgres as a met-budget degradation). The two are told apart by identity, not by state: if the
    future is done AND the object it holds IS the exception just caught, the arm raised it. Checking
    `future.done()` alone would be a race — a task that completes microseconds after the wait
    expires would be misread as having raised — and `exception(timeout=0)` cannot block here because
    it is guarded by `done()`.
    """
    try:
        return future.result(timeout=remaining_ms / 1000.0), False
    except _ArmAbandoned:
        return [], True
    except FutureTimeoutError as expiry:
        if future.done() and future.exception(timeout=0) is expiry:
            raise
        return [], True


class Retriever:
    """Runs both search arms concurrently, fuses them by RRF, degrades fail-open on embed timeout.

    Owns one small thread pool for the lifetime of the instance rather than spawning one per
    call — `retrieve()` sits on the 300ms p99 hot path (PLAN.md §6
    `retrieval.total_budget_ms`), and per-call thread creation is pure overhead a long-lived
    instance does not need to pay.
    """

    def __init__(self, search: SearchStore, embedding: QueryEmbedderPort, clock: Clock) -> None:
        self._search = search
        self._embedding = embedding
        self._clock = clock
        self._executor = ThreadPoolExecutor(
            max_workers=_ARM_WORKER_COUNT, thread_name_prefix="tb-retriever"
        )
        # Deadline of each arm task currently EXECUTING, keyed by submission token. Only started
        # tasks are in here, so it can never hold more than `_ARM_WORKER_COUNT` entries, and its
        # whole purpose is to answer one question cheaply under the lock: is every worker already
        # stuck on work nobody can still use? (`_arm_pool_is_wedged`.)
        self._lock = threading.Lock()
        self._running_deadlines: dict[int, float] = {}
        self._submitted_arms = 0

    def close(self) -> None:
        """Releases the thread pool. Called once, at process shutdown, by whoever constructed
        this `Retriever` — not exercised on the hot path itself."""
        self._executor.shutdown(wait=True)

    def _arm_pool_is_wedged(self, now_ms: float) -> bool:
        """True when EVERY worker is executing an arm whose own caller has already given up.

        Caller must hold `self._lock`. This is the admission test that keeps a stalled store from
        turning into unbounded growth (D-138): `Future.result(timeout=...)` bounds the WAIT, but
        `ThreadPoolExecutor`'s work queue is unbounded, so with both workers wedged in psycopg every
        subsequent request still enqueued two more work items that could never run — one leaked
        queue entry pair per request, each holding a whole query embedding, plus a stampede of
        thousands of long-dead queries fired at Postgres the moment it recovered. Refusing to
        enqueue in exactly this state costs nothing when the store is healthy (a busy worker whose
        deadline has NOT passed is doing work someone is still waiting for, so the queue is the
        right place for the next arm) and is the correct answer when it is not: a request that
        cannot be served is served nothing, immediately, rather than after paying the full budget
        waiting on a future that provably cannot start.
        """
        if len(self._running_deadlines) < _ARM_WORKER_COUNT:
            return False
        return all(now_ms >= deadline for deadline in self._running_deadlines.values())

    def _submit_arm(
        self, call: Callable[..., list[ArmHit]], deadline_ms: float
    ) -> Future[list[ArmHit]]:
        """Submits one arm, or hands back an already-abandoned future when the pool is wedged.

        Refusal is reported as `_ArmAbandoned` rather than as `None` so that the caller has exactly
        ONE way to learn an arm contributed nothing — `_await_arm`'s `timed_out` flag — instead of
        a second, parallel branch that a future edit could forget to fold into `degraded`.
        """
        with self._lock:
            if self._arm_pool_is_wedged(self._clock.monotonic_ms()):
                return _abandoned_arm("every retriever worker is stuck past its own deadline")
            token = self._submitted_arms
            self._submitted_arms += 1
        return self._executor.submit(self._run_arm, token, deadline_ms, call)

    def _run_arm(
        self, token: int, deadline_ms: float, call: Callable[..., list[ArmHit]]
    ) -> list[ArmHit]:
        """Runs one arm on a worker thread, but only if its caller can still use the answer.

        The deadline check happens HERE, at the moment the task actually starts, not at submission:
        a task that sat in the queue behind a stalled worker until after its own caller's budget
        expired is work no one is waiting for, and running it would mean a recovering Postgres
        receiving every query issued during the outage (D-138). Registering the deadline before the
        check, and clearing it in `finally`, is what lets `_arm_pool_is_wedged` see a worker that is
        stuck rather than merely busy.

        `statement_timeout_ms` is computed here for the same reason, and is the third bound of the
        set (D-139). Submission time is the wrong instant to derive it from -- a task that waited in
        the queue would carry a server-side budget larger than the time its caller actually has
        left -- so it is `deadline_ms` minus the reading taken one line above, which is by
        construction the caller's true remaining budget at the moment the query is about to be
        issued. Rounded UP to at least one millisecond: this line is only reached when the deadline
        has NOT passed, so the correct bound is "the sliver that remains", and `int()` truncating a
        0.4ms remainder to 0 would mean "no limit" to Postgres -- the exact opposite.
        """
        with self._lock:
            self._running_deadlines[token] = deadline_ms
        try:
            now_ms = self._clock.monotonic_ms()
            if now_ms >= deadline_ms:
                raise _ArmAbandoned("this arm reached a worker after its caller's budget expired")
            return call(statement_timeout_ms=max(1, ceil(deadline_ms - now_ms)))
        finally:
            with self._lock:
                self._running_deadlines.pop(token, None)

    def retrieve(
        self, project_id: ProjectId, query_text: str, *, cfg: RetrievalConfig
    ) -> RetrievalOutcome:
        """Start the lexical arm, embed (sub-budgeted) alongside it, run the vector arm, fuse.

        Every threshold/weight/top-n this method uses comes from `cfg` (`EffectiveConfig
        .retrieval`, PLAN.md §6, hard rule 4) — nothing here is a literal. `EmbeddingTimeout` /
        `EmbeddingProviderError` are the only exceptions this method catches from the embedder;
        anything else it raises propagates to the caller unmodified. No search arm can make this
        method exceed `cfg.total_budget_ms` any more (D-132/D-138, module docstring's HARD-BOUNDED
        and ADMISSION CONTROL sections): each wait is bounded against one deadline computed on
        entry, and an arm that times out, is refused, or starts too late degrades in place instead
        of raising. An arm's own exception — including a `TimeoutError` RAISED BY the store, which
        is a store failure and not this method's budget expiring — still propagates unmodified,
        which is the store-error rung of the degradation ladder (PLAN.md §2 invariant 2), the
        assembler/API layer's responsibility, not this module's.
        """
        retrieve_started_ms = self._clock.monotonic_ms()
        # One deadline for the whole call, computed once from this method's own entry reading: both
        # waits below narrow against it, and both arm tasks check it before touching Postgres, so
        # "the budget" means the same instant everywhere in this call instead of each consumer
        # re-deriving its own (D-132's re-derivation, D-138's stale-work check).
        deadline_ms = retrieve_started_ms + float(cfg.total_budget_ms)

        # Submitted BEFORE the embed call so the lexical arm's latency is paid inside the embed
        # sub-budget rather than after it (module docstring §2): on the degraded path the embedder
        # may burn its entire 200ms of a 300ms total budget, and a lexical arm that only starts
        # then would push the whole call past `retrieval.total_budget_ms`.
        lexical_future = self._submit_arm(
            partial(self._search.lexical_arm, project_id, query_text, cfg.arm_top_n), deadline_ms
        )
        embed_start_ms = self._clock.monotonic_ms()
        embedding: list[float] | None = None
        degraded = False
        try:
            vectors = self._embedding.embed([query_text], timeout_ms=cfg.embed_timeout_ms)
            embedding = vectors[0] if vectors else None
            if embedding is None:
                # An embedder that answers a non-empty request with nothing is exactly as
                # unusable to the vector arm as one that timed out — degrade the same way rather
                # than let a downstream IndexError stand in for "no vector was produced."
                degraded = True
        except (EmbeddingTimeout, EmbeddingProviderError):
            # `EmbeddingProviderError` alongside `EmbeddingTimeout`, deliberately: PLAN.md §2's
            # first ladder rung is "query embedding is unusable -> lexical-only", and a refused
            # connection, a malformed provider payload, or an over-sized response body leaves the
            # vector arm exactly as unusable as a timeout does — while the lexical arm is
            # perfectly healthy. Letting a provider error propagate instead would drop the whole
            # retrieval to the ladder's THIRD rung (`store_error`, nothing at all) via
            # `pipeline.py`'s blanket guard, discarding a working arm and mislabelling "the
            # embedding endpoint is broken" as "the memory store failed" on the very
            # `retrieval_event` row that exists to tell those two apart (PLAN.md §5).
            degraded = True
        # `max(0, ...)` because a monotonic source that ever ticks backwards must not put a
        # negative duration on a `retrieval_event` row; it is a clock fault, not a negative wait.
        embed_latency_ms = max(0, int(self._clock.monotonic_ms() - embed_start_ms))

        vector_future: Future[list[ArmHit]] | None = (
            None
            if embedding is None
            else self._submit_arm(
                partial(
                    self._search.vector_arm,
                    project_id,
                    embedding,
                    cfg.arm_top_n,
                    hnsw_iterative_scan=cfg.hnsw_iterative_scan,
                    hnsw_max_scan_tuples=cfg.hnsw_max_scan_tuples,
                ),
                deadline_ms,
            )
        )

        # Remaining budget re-derived from THIS method's own clock reading before each wait, never
        # widened (D-132, module docstring's HARD-BOUNDED section): the lexical wait's overrun eats
        # into what is left for the vector wait rather than each arm getting a fresh, independent
        # `total_budget_ms` allowance. `max(0.0, ...)` because a wait that starts after the budget
        # is already gone must produce "no time left" (timeout=0), not a negative number handed to
        # `Future.result` -- undocumented behaviour is not a budget guarantee, so this never relies
        # on how a negative timeout happens to behave.
        def _remaining_budget_ms() -> float:
            return max(0.0, deadline_ms - self._clock.monotonic_ms())

        lexical_hits, lexical_timed_out = _await_arm(lexical_future, _remaining_budget_ms())
        if lexical_timed_out:
            degraded = True

        vector_hits: list[ArmHit] = []
        if vector_future is not None:
            vector_hits, vector_timed_out = _await_arm(vector_future, _remaining_budget_ms())
            if vector_timed_out:
                degraded = True

        fused = fuse(
            lexical_hits,
            vector_hits,
            rrf_k=cfg.rrf_k,
            weight_lexical=cfg.rrf_weight_lexical,
            weight_vector=cfg.rrf_weight_vector,
        )
        # PLAN.md §6 `retrieval.fused_top_n`: the fused list is cut here, not downstream, so the
        # per-candidate work the assembler does is bounded by the configured number instead of by
        # `2 * arm_top_n`. Clamped at 0 rather than passed through, because a negative slice bound
        # would silently mean "all but the last |n|" — the opposite of a cap.
        keep = cfg.fused_top_n if cfg.fused_top_n > 0 else 0
        considered = len(
            {hit.memory_id for hit in lexical_hits} | {hit.memory_id for hit in vector_hits}
        )

        return RetrievalOutcome(
            candidates=tuple(fused[:keep]),
            degraded=degraded,
            embed_latency_ms=embed_latency_ms,
            candidates_considered=considered,
        )
