"""Orchestrator prefetch API (PLAN.md §7 Phase 4: "measured before shipped").

Prefetch speculatively warms retrieval for the next likely step while the current step
is still running. `PrefetchingRetriever` wraps anything shaped like
`hotpath.retriever.Retriever.retrieve` / `hotpath.pipeline.HybridRetrieverPort` — the
exact `.retrieve(project_id, query_text, *, cfg) -> outcome` call — and can be handed to
`hotpath.pipeline.Pipeline(retriever=...)` in its place with zero change on that side
(structural typing; `tests/phase4/test_prefetch.py` proves the shape match against the
real Protocol AND that this module's cache key covers every parameter of it, so the port
cannot grow a dimension the key ignores).

THE PROPERTIES THIS MODULE HOLDS, stated at the strength they are actually enforced at:

(a) NEVER BLOCKS THE CURRENT STEP. `prefetch()` only ever calls
    `ThreadPoolExecutor.submit`, which enqueues the call and returns a `Future`
    immediately — it does not wait for the wrapped retriever to run.
    `test_prefetch_call_itself_never_blocks` measures this directly against a retriever
    that sleeps. It also never *raises* into the current step: after `close()`, or if the
    injected clock refuses to report monotonic time, `prefetch()` degrades to a no-op
    rather than propagating (invariant 2: a run never fails because of Tracebed).

(b) NEVER SUBSTITUTES A DIFFERENT ANSWER — AND NEVER AN OLDER ONE THAN `max_age_ms`.
    A cached value is served ONLY when all of the following hold: the fingerprint
    (`_fingerprint`: project_id, query_text, and every field of `RetrievalConfig`)
    matches exactly; the entry's recorded `project_id` equals the caller's (the wall is
    re-checked, not merely hashed into the key — invariant 4); the background call has
    actually finished (`Future.done()`, checked without blocking); and the entry is at
    most `max_age_ms` old on the injected `Clock`'s monotonic scale. Anything else —
    never prefetched, still running, cancelled, flushed, evicted, expired, or raised —
    falls straight through to a synchronous call on the wrapped retriever, i.e. exactly
    what happens with no `PrefetchingRetriever` in front at all. An entry is served at
    most once (`_take` pops it), so one speculative call can never answer two steps.

    THE HONEST LIMIT, which an earlier version of this docstring got wrong: a retrieval
    result is a snapshot of the memory store, and the store changes underneath it — a
    memory is tombstoned, an `invalidation_event` fires, a distiller promotes a
    candidate. A cached hit therefore reflects the store as of when the background call
    was ISSUED, and can differ from a cold call made now by exactly the writes that
    landed in between. That window is not "assumed small": it is bounded by
    `max_age_ms`, a value the CALLER supplies (see the contract-gap note below), and it
    collapses to zero with `max_age_ms=0`, which makes every `retrieve()` cold. The
    entry's age is measured from submit time, not completion time — the conservative end
    of the interval the snapshot could have been taken in.

    INVALIDATION IS A PUSH, NOT A GUESS. `flush_project(project_id)` drops every cached
    entry for one project, mirroring `stores.valkey.flush.flush_project_cache` (PLAN.md
    §5: "per-project key sets are tracked for O(1) flush; a `cache_flush` invalidation
    event type exists from Phase 1"). Whoever consumes `invalidation_event` rows — and
    `stores.pg.partitions.drop_project` on a project delete — must call it for the same
    reason they call the Valkey flush: an in-process cache holding one project's
    retrieval results is one more store the wall has to cover.
    `combined_project_flush()` at the bottom of this module is how the two tiers are
    composed into the ONE `Callable[[ProjectId], int]` that
    `workers.invalidator.Invalidator(flush_cache=...)` already takes, so a wiring site
    cannot reach the Valkey tier and forget this one. What is still missing is a live
    consumer to hand it to: nothing in `src/` reads `invalidation_event` rows back off
    the table yet (`POST /v1/invalidation` writes them and no loop drains them), so
    today the freshness window `max_age_ms` is the only bound actually in force on a
    prefetched result outliving an invalidation. That gap is the invalidation
    consumer's, not this module's, and it is stated rather than implied away.

(c) PROVABLY CANCELLABLE. `cancel(key)` removes the cache entry under `self._lock` and
    returns. Python threads cannot be pre-empted, so a background call already running
    keeps running to completion — but because the entry is gone from `self._pending`
    before that happens, `_take()` (also lock-guarded) can never observe it again: the
    eventual result, success or failure, is silently discarded, and `retrieve()` for
    that key recomputes from scratch exactly as if the prefetch had never been issued.
    `test_cancel_leaves_no_state_behind` drives this under an actual timing race (the
    wrapped retriever blocks on a `threading.Event` so the test can cancel strictly
    before the background call finishes). `cancel_all()` and `flush_project()` are the
    same operation over a set of keys, applied atomically under one lock acquisition.

A prefetch failure is invisible to the run: `_take()` catches any exception the
background call raised and treats it exactly like a cache miss
(`test_prefetch_failure_is_invisible_to_the_caller`) — `retrieve()` never re-raises a
stale background exception; it falls through to a fresh synchronous call, which is the
same thing that would happen had no prefetch ever been attempted.

BOUNDED, because a speculative cache that only grows is a leak: at most `max_entries`
entries are held, expired ones are dropped first and the oldest surviving entry is
evicted after that. Both bounds, and `max_workers`, are constructor arguments with no
defaults — see the contract gap.

CONTRACT GAP (reported, not improvised): PLAN.md §6's config table has no `prefetch`
section, so there is no `EffectiveConfig` field for the freshness window, the entry
cap, or the background pool width. Inventing three defaults here would be exactly the
magic numbers §6 exists to forbid, so all three are REQUIRED constructor arguments: the
caller that owns a config surface states them, and this module contains no policy number
of its own. A `prefetch.max_age_ms` / `max_entries` / `max_workers` trio belongs in §6
before an API route constructs one of these.

MEASURED, HONESTLY (the task's explicit requirement — PLAN.md ships this only if
measured): `test_benchmark_warm_vs_cold_reports_honest_numbers` runs the one workload
this module can actually claim to speed up — an EXACT repeat of a prefetched call, with
a synthetic per-call latency (30ms) standing in for a real BM25 + ANN + embedding round
trip — and asserts the warm path is at least an order of magnitude faster. An actual run
of that benchmark on the machine this chunk was built on measured (5 trials, 30ms
simulated retriever latency, four consecutive runs): cold mean 30.198-30.756ms, warm
mean 0.077-0.093ms, i.e. 330-399x. That number
is real for the one thing it measures — an exact repeat, background call already
finished, entry inside its freshness window — and it is NOT a production lift estimate:
it says nothing about how often an orchestrator's "next likely step" prediction actually
matches the step that happens (a wrong prediction, or a right one that finishes
retrieving before the background call completes, both fall through to the unchanged cold
path per property (b), so a wrong guess costs nothing beyond one wasted background call).
No telemetry on real next-step prediction accuracy exists yet in this codebase to turn
"prefetch is fast when it hits" into "prefetch helps in production, this often" — that
gap is reported here rather than papered over with an invented hit-rate.
"""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from typing import Final, Protocol, cast, runtime_checkable

from tracebed.domain.canonical import canonical_json
from tracebed.domain.clock import Clock
from tracebed.domain.config import RetrievalConfig
from tracebed.domain.ids import ProjectId

__all__ = ["PrefetchingRetriever", "RetrieverPort", "combined_project_flush"]

# Sentinel distinguishing "no cached value" from "the wrapped retriever's own outcome
# happens to be falsy/None" — the outcome type is generic and unconstrained, so `None`
# cannot be reused as the miss marker without conflating the two.
_MISS: Final[object] = object()


@runtime_checkable
class RetrieverPort[Outcome_co](Protocol):
    """Exactly `hotpath.retriever.Retriever.retrieve`'s call shape (also
    `hotpath.pipeline.HybridRetrieverPort`'s) — declared locally, not imported, so this
    module never drags in `hotpath.retriever`'s live thread pool / `SearchStore` or
    `hotpath.pipeline`'s Protocol zoo just to name the shape it wraps. `Outcome_co`
    (PEP 695 type parameter, scoped to this class only — mypy infers it covariant
    because the one method only ever produces it) is never inspected or reconstructed
    anywhere in this module: `PrefetchingRetriever` is a pure memoizing decorator over
    whatever the wrapped retriever returns, which is exactly why it cannot itself be the
    thing that computes a different answer (property (b))."""

    def retrieve(
        self, project_id: ProjectId, query_text: str, *, cfg: RetrievalConfig
    ) -> Outcome_co: ...


def _fingerprint(project_id: ProjectId, query_text: str, cfg: RetrievalConfig) -> bytes:
    """The exact-match cache key: every parameter of `RetrieverPort.retrieve`, and
    nothing else.

    `canonical_json` (`domain.canonical` — THE one serialiser, C-01) over every field of
    `cfg` means a caller that changes any budget/weight/top-n gets a different key rather
    than a stale hit from a differently-configured call; nothing here is a fuzzy match,
    because property (b) only holds for an EXACT repeat of the same call.
    `test_fingerprint_covers_every_parameter_of_the_retriever_port` compares these keys
    against the real Protocol's signature, so a port that grows a parameter fails a test
    instead of silently producing cache hits that ignore it.
    """
    payload = {
        "project_id": str(project_id),
        "query_text": query_text,
        "cfg": cfg.model_dump(),
    }
    return hashlib.sha256(canonical_json(payload)).digest()


@dataclass(frozen=True, slots=True)
class _Entry[Outcome]:
    """One speculative call in flight or awaiting collection.

    `project_id` is carried alongside the future rather than left implicit in the
    fingerprint: serving a cached value re-checks it (invariant 4 is a construction-time
    check in every store, and "the project is inside a sha256 somewhere" is not one).
    `issued_at_ms` is the SUBMIT time on the injected clock's monotonic scale — the
    oldest instant the snapshot in `future` could have been taken at, which is the
    conservative end for a freshness bound.
    """

    project_id: ProjectId
    future: Future[Outcome]
    issued_at_ms: float


class PrefetchingRetriever[Outcome]:
    """Wraps a `RetrieverPort` with a speculative, cancellable, age-bounded warm cache.

    Structurally satisfies `RetrieverPort` itself (and therefore
    `hotpath.pipeline.HybridRetrieverPort`), so it drops into
    `hotpath.pipeline.Pipeline(retriever=prefetching_retriever, ...)` with no change on
    that side — an orchestrator calls `.prefetch(...)` once it has predicted the next
    step, and the `Pipeline` it already owns keeps calling `.retrieve(...)` exactly as
    before.

    See the module docstring for properties (a)/(b)/(c), the freshness bound, the
    flush hook, and the measurement.
    """

    def __init__(
        self,
        inner: RetrieverPort[Outcome],
        *,
        clock: Clock,
        max_age_ms: int,
        max_entries: int,
        max_workers: int,
    ) -> None:
        """Every bound is injected; this module invents none of them (module docstring's
        contract gap). `max_age_ms=0` is legal and meaningful — it disables warm hits
        entirely (and makes `prefetch()` a no-op) while leaving the wiring in place,
        which is the setting a deployment that tolerates no staleness window at all uses.
        """
        if max_age_ms < 0:
            raise ValueError("PrefetchingRetriever.max_age_ms must be >= 0")
        if max_entries < 1:
            raise ValueError("PrefetchingRetriever.max_entries must be >= 1")
        if max_workers < 1:
            raise ValueError("PrefetchingRetriever.max_workers must be >= 1")
        self._inner = inner
        self._clock = clock
        self._max_age_ms = max_age_ms
        self._max_entries = max_entries
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="tb-prefetch"
        )
        self._lock = threading.Lock()
        self._pending: dict[bytes, _Entry[Outcome]] = {}
        self._closed = False

    def close(self) -> None:
        """Releases the background thread pool and drops every cached entry. Idempotent,
        and safe to call while prefetches are in flight — mirrors
        `hotpath.retriever.Retriever.close`. After it, `prefetch()` is a no-op rather
        than a `RuntimeError` from a shut-down executor (property (a)).
        """
        with self._lock:
            already_closed = self._closed
            self._closed = True
            self._pending.clear()
        if not already_closed:
            # Outside the lock: shutdown waits for in-flight calls, and those calls are
            # the wrapped retriever's, which may take the whole retrieval budget.
            self._executor.shutdown(wait=True)

    def prefetch(self, project_id: ProjectId, query_text: str, *, cfg: RetrievalConfig) -> bytes:
        """Speculatively warm one call. Returns the fingerprint key immediately —
        property (a) — for later use with `cancel()`. Scheduling twice for the same key
        while a live entry exists is a no-op: the existing entry is left alone rather
        than doubling the background work. An EXPIRED entry is replaced instead, so a
        re-prefetch after the freshness window refreshes rather than pinning the stale
        one forever.
        """
        key = _fingerprint(project_id, query_text, cfg)
        if self._max_age_ms == 0:
            # Warm hits are disabled, so a background call could only ever produce a
            # value `_take` would refuse. Spending a thread on it is pure waste.
            return key
        now_ms = self._monotonic_ms()
        if now_ms is None:
            # No readable clock means no bound on how stale a cached entry would be, and
            # an unbounded warm hit is precisely what property (b) refuses. Skipping the
            # prefetch costs the next call its (correct, cold) latency and nothing else.
            return key
        with self._lock:
            if self._closed:
                return key
            existing = self._pending.get(key)
            if existing is not None and not self._expired(existing, now_ms):
                return key
            self._evict_locked(now_ms)
            submit: Callable[..., Outcome] = self._inner.retrieve
            future: Future[Outcome] = self._executor.submit(
                submit, project_id, query_text, cfg=cfg
            )
            self._pending[key] = _Entry(
                project_id=project_id, future=future, issued_at_ms=now_ms
            )
        return key

    def is_ready(self, key: bytes) -> bool:
        """Non-blocking: is there a live entry for `key` whose background call has
        finished and which is still inside the freshness window? Never used by
        `retrieve()` itself (which never blocks on a future either) — this is
        observability for an orchestrator or a test that wants to wait deterministically
        rather than poll `retrieve()` and guess."""
        now_ms = self._monotonic_ms()
        with self._lock:
            entry = self._pending.get(key)
            if entry is None or now_ms is None or self._expired(entry, now_ms):
                return False
            return entry.future.done()

    def cancel(self, key: bytes) -> None:
        """Property (c): discard one prefetch. Removes the entry from `self._pending`
        under the lock and returns; a background call already in flight keeps running
        (Python threads are not preemptible) but its eventual result — success or
        failure — is never stored or served, because `_take()` cannot find an entry that
        is no longer in the dict. "Leaves no state behind" means the dict entry is gone
        the instant this call returns, not merely flagged for later cleanup.
        """
        with self._lock:
            self._pending.pop(key, None)

    def cancel_all(self) -> None:
        """Every pending/completed prefetch discarded in ONE lock acquisition — the shape
        an orchestrator reaches for on a branch change when it is not tracking individual
        keys itself. Atomic on purpose: draining a snapshot of the keys and then removing
        them one at a time would leave any entry scheduled in between still cached, which
        is not what "discard everything" can be allowed to mean on a branch change."""
        with self._lock:
            self._pending.clear()

    def flush_project(self, project_id: ProjectId) -> int:
        """Discard every cached entry belonging to one project; returns the count.

        The in-process twin of `stores.valkey.flush.flush_project_cache`, and required
        for the same two call sites: a `cache_flush` invalidation delivery, and project
        deletion. Without it, a prefetched result outlives the invalidation that was
        supposed to remove the memories it contains (module docstring, property (b)).
        """
        with self._lock:
            keys = [k for k, entry in self._pending.items() if entry.project_id == project_id]
            for key in keys:
                del self._pending[key]
        return len(keys)

    def project_flusher(self) -> Callable[[ProjectId], int]:
        """`flush_project` as a bare callable, shaped exactly like
        `workers.invalidator.Invalidator`'s `flush_cache` parameter and
        `stores.valkey.flush.flush_project_cache` bound to a client.

        Exists so this cache can be composed into a deployment's ONE flush callable via
        `combined_project_flush` below, instead of a wiring site having to know that
        `PrefetchingRetriever` is a cache at all."""
        return self.flush_project

    def pending_count(self) -> int:
        """How many keys are in flight or cached right now. Observability only —
        `retrieve()` never reads this."""
        with self._lock:
            return len(self._pending)

    def retrieve(self, project_id: ProjectId, query_text: str, *, cfg: RetrievalConfig) -> Outcome:
        """The drop-in `RetrieverPort.retrieve`. Exact-fingerprint, same-project,
        within-freshness-window cache hit, or a synchronous fall-through to the wrapped
        retriever — property (b)."""
        key = _fingerprint(project_id, query_text, cfg)
        cached = self._take(key, project_id)
        if cached is not _MISS:
            return cast(Outcome, cached)
        return self._inner.retrieve(project_id, query_text, cfg=cfg)

    # ----------------------------------------------------------------- #
    # Internals.
    # ----------------------------------------------------------------- #

    def _monotonic_ms(self) -> float | None:
        """`Clock` is an injected Protocol, so `monotonic_ms()` is third-party code
        reachable from a call an agent runtime waits on. A clock that raises must cost
        the caller a cache hit, never its run (invariant 2)."""
        try:
            return self._clock.monotonic_ms()
        except Exception:
            return None

    def _expired(self, entry: _Entry[Outcome], now_ms: float) -> bool:
        """Age measured from submit time (see `_Entry`).

        `max_age_ms == 0` short-circuits to "expired" rather than relying on elapsed
        time exceeding zero: under a `FakeClock` that nobody advanced, or a coarse
        monotonic source, an entry can be consumed at the same reading it was created
        at, and "no staleness tolerated" must not depend on how finely the clock ticks.
        """
        if self._max_age_ms == 0:
            return True
        return (now_ms - entry.issued_at_ms) > self._max_age_ms

    def _evict_locked(self, now_ms: float) -> None:
        """Keep `self._pending` bounded. Caller holds `self._lock`.

        Expired entries go first (they can never be served anyway), then the oldest
        surviving entry if the cap is still reached — insertion order is age order here,
        because an entry is inserted exactly once with the clock reading of that moment.
        Evicting is always SAFE, never merely convenient: the evicted key's next
        `retrieve()` takes the cold path, which is the correct answer by construction.
        """
        for key in [k for k, entry in self._pending.items() if self._expired(entry, now_ms)]:
            del self._pending[key]
        while len(self._pending) >= self._max_entries:
            oldest = next(iter(self._pending))
            del self._pending[oldest]

    def _take(self, key: bytes, project_id: ProjectId) -> object:
        """`_MISS` on anything short of "a completed, uncancelled, unexpired prefetch for
        this exact key and this exact project" — not yet scheduled, not yet finished,
        cancelled, flushed, evicted, past `max_age_ms`, or the background call raised.

        Whether the background call has finished is checked with `Future.done()` (never
        `Future.result()` while the lock is held, and never a blocking wait at all):
        `retrieve()` must never become slower than the cold path it is standing in for by
        waiting on a prefetch that is still running — a still-running prefetch is exactly
        as much "not ready" as one that was never issued.
        """
        now_ms = self._monotonic_ms()
        with self._lock:
            entry = self._pending.get(key)
            if entry is None:
                return _MISS
            if now_ms is None or self._expired(entry, now_ms):
                # An entry whose age cannot be established, or is past the window, is
                # dropped rather than left to be re-tested on every later call.
                del self._pending[key]
                return _MISS
            if entry.project_id != project_id:
                # Unreachable short of a sha256 collision, because project_id is part of
                # the key — which is exactly why it is worth checking rather than
                # assuming: invariant 4's wall is a check at the point of use in every
                # store, not a property of a hash input.
                del self._pending[key]
                return _MISS
            if not entry.future.done():
                return _MISS
            # Popped here, under the same lock that guards `cancel()`/`flush_project()`:
            # whichever of this call or a concurrent removal reaches the lock first
            # decides the entry's fate, and the other finds nothing left to act on.
            # There is no window in which both a consumer and a canceller see the entry
            # as live, and no entry is ever served twice.
            del self._pending[key]
        try:
            return entry.future.result()
        except Exception:
            # A prefetch failure is invisible to the run: treat it exactly like a
            # cache miss rather than re-raising a stale background exception into an
            # unrelated `retrieve()` call.
            return _MISS


def combined_project_flush(
    *flushes: Callable[[ProjectId], int],
) -> Callable[[ProjectId], int]:
    """Compose every project-scoped cache tier into the ONE flush callable a deployment
    hands `workers.invalidator.Invalidator(flush_cache=...)` and calls on project deletion.

    PLAN.md §5 says per-project key sets are tracked for O(1) flush and a `cache_flush`
    invalidation event exists. That is a claim about EVERY cache holding project-scoped
    data, and there are now two tiers: `stores.valkey.flush.flush_project_cache` (tool
    cache, working memory, static prefix) and `PrefetchingRetriever.flush_project`
    (retrieval outcomes). A wiring site that passes only the Valkey one flushes half the
    caches and reports success, which is the failure mode `Invalidator` already refuses to
    have for the no-flusher case: it reports `cache_flushed=False` rather than claiming a
    flush it did not perform.

    Every flusher runs even if an earlier one raises, and the first exception is re-raised
    after all of them have been attempted. Stopping at the first failure would leave the
    later tiers serving exactly the data the event exists to remove -- a partial flush that
    reports as a total failure is recoverable by a retry; a partial flush that silently
    skipped a tier is not.
    """
    def _flush(project_id: ProjectId) -> int:
        removed = 0
        first_error: BaseException | None = None
        for flush in flushes:
            try:
                removed += flush(project_id)
            except BaseException as exc:  # re-raised below, never swallowed
                if first_error is None:
                    first_error = exc
        if first_error is not None:
            raise first_error
        return removed

    return _flush
