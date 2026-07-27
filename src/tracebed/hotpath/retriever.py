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
2. **Concurrency.** The two arms are independent Postgres reads; running them sequentially would
   simply add their latencies for no benefit. `retrieve()` submits both to a small thread pool
   (they are blocking I/O, so the GIL is released for the duration of each) and waits for both.
   The lexical arm is submitted BEFORE the embed call, not after: the embed sub-budget (200ms) is
   two thirds of the whole retrieval budget (`retrieval.total_budget_ms`, 300ms), so an embed that
   runs to its timeout with the lexical arm not yet started spends 200ms and only then begins the
   one arm that is still going to answer — the degraded path would routinely blow the total budget
   and be downgraded again, by the ladder, to prefix-only. Overlapping the two means the lexical
   arm's latency is paid inside the embed window instead of after it, so "the embedder stalled"
   costs the ladder one rung, not two.
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

from collections.abc import Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
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

    `degraded` is `True` iff the embed sub-budget was exceeded and the vector arm was skipped
    entirely — the caller (assembler / API layer) is expected to map this to
    `OutcomeCode.DEGRADED_LEXICAL` on the `retrieval_event` row; this module does not stamp an
    `OutcomeCode` itself, because "abstained" / "empty" / "injected" are decisions this module has
    no visibility into (abstention and slot assembly happen downstream).

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

    def close(self) -> None:
        """Releases the thread pool. Called once, at process shutdown, by whoever constructed
        this `Retriever` — not exercised on the hot path itself."""
        self._executor.shutdown(wait=True)

    def retrieve(
        self, project_id: ProjectId, query_text: str, *, cfg: RetrievalConfig
    ) -> RetrievalOutcome:
        """Start the lexical arm, embed (sub-budgeted) alongside it, run the vector arm, fuse.

        Every threshold/weight/top-n this method uses comes from `cfg` (`EffectiveConfig
        .retrieval`, PLAN.md §6, hard rule 4) — nothing here is a literal. `EmbeddingTimeout` is
        the only exception this method catches; anything else the embedder or `SearchStore`'s arms
        raise propagates to the caller unmodified — the store-error / total-budget-exceeded rungs
        of the degradation ladder (PLAN.md §2 invariant 2) are the assembler/API layer's
        responsibility, not this module's (see the module docstring's contract note on scope).
        """
        # Submitted BEFORE the embed call so the lexical arm's latency is paid inside the embed
        # sub-budget rather than after it (module docstring §2): on the degraded path the embedder
        # may burn its entire 200ms of a 300ms total budget, and a lexical arm that only starts
        # then would push the whole call past `retrieval.total_budget_ms`.
        lexical_future: Future[list[ArmHit]] = self._executor.submit(
            self._search.lexical_arm, project_id, query_text, cfg.arm_top_n
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
            else self._executor.submit(
                self._search.vector_arm,
                project_id,
                embedding,
                cfg.arm_top_n,
                hnsw_iterative_scan=cfg.hnsw_iterative_scan,
                hnsw_max_scan_tuples=cfg.hnsw_max_scan_tuples,
            )
        )

        lexical_hits = lexical_future.result()
        vector_hits = vector_future.result() if vector_future is not None else []

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
