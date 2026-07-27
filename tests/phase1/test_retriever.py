"""`Retriever` against fake arms and a fake `EmbeddingPort` (PLAN.md §7 Phase 1).

No database, no network: `stores.pg.search.SearchStore` and `adapters.ports.EmbeddingPort` are
both faked at their public method signatures, so these tests exercise exactly the concurrency,
degradation, and fusion-wiring logic `Retriever.retrieve()` owns.
"""

from __future__ import annotations

import inspect
import threading
import time
import uuid
from collections.abc import Sequence

import pytest

from tracebed.adapters.ports import EmbeddingPort
from tracebed.domain.clock import FakeClock
from tracebed.domain.config import RetrievalConfig
from tracebed.domain.enums import TrustTier
from tracebed.domain.errors import EmbeddingTimeout
from tracebed.domain.ids import MemoryId, ProjectId
from tracebed.domain.state_machine import Status
from tracebed.hotpath.retriever import QueryEmbedderPort, RetrievalOutcome, Retriever
from tracebed.stores.pg.search import ArmHit

pytestmark = pytest.mark.phase1

PROJECT = ProjectId(uuid.UUID(int=100))
MEM_A = MemoryId(uuid.UUID(int=1))
MEM_B = MemoryId(uuid.UUID(int=2))


def _hit(memory_id: MemoryId, raw_score: float) -> ArmHit:
    return ArmHit(memory_id=memory_id, raw_score=raw_score, trust_tier=TrustTier.A, status=Status.VALIDATED)


class _FakeSearch:
    """Records every call it receives; returns canned hits."""

    def __init__(
        self, lexical: list[ArmHit] | None = None, vector: list[ArmHit] | None = None
    ) -> None:
        self._lexical = lexical if lexical is not None else []
        self._vector = vector if vector is not None else []
        self.lexical_calls: list[tuple[ProjectId, str, int]] = []
        self.vector_calls: list[tuple[ProjectId, Sequence[float], int, bool, int]] = []

    def lexical_arm(self, project_id: ProjectId, query: str, top_n: int) -> list[ArmHit]:
        self.lexical_calls.append((project_id, query, top_n))
        return self._lexical

    def vector_arm(
        self,
        project_id: ProjectId,
        embedding: Sequence[float],
        top_n: int,
        *,
        hnsw_iterative_scan: bool,
        hnsw_max_scan_tuples: int,
    ) -> list[ArmHit]:
        self.vector_calls.append(
            (project_id, embedding, top_n, hnsw_iterative_scan, hnsw_max_scan_tuples)
        )
        return self._vector


class _FakeEmbeddingPort:
    """Satisfies `EmbeddingPort` structurally. Either returns canned vectors, raises a canned
    exception, or (via `empty_response`) simulates a port that answers with nothing."""

    def __init__(
        self,
        vectors: list[list[float]] | None = None,
        *,
        raise_: Exception | None = None,
        empty_response: bool = False,
    ) -> None:
        self._vectors = vectors
        self._raise = raise_
        self._empty_response = empty_response
        self.calls: list[tuple[tuple[str, ...], int]] = []

    def embed(self, texts: Sequence[str], *, timeout_ms: int) -> list[list[float]]:
        self.calls.append((tuple(texts), timeout_ms))
        if self._raise is not None:
            raise self._raise
        if self._empty_response:
            return []
        return self._vectors if self._vectors is not None else [[0.1, 0.2, 0.3] for _ in texts]

    @property
    def model_id(self) -> str:
        return "fake-embedding"

    @property
    def model_version(self) -> str:
        return "test"


def test_fake_embedding_port_satisfies_the_protocol() -> None:
    assert isinstance(_FakeEmbeddingPort(), EmbeddingPort)
    assert isinstance(_FakeEmbeddingPort(), QueryEmbedderPort)


def test_local_query_embedder_port_matches_the_real_embedding_port() -> None:
    """`hotpath.retriever` declares its own `QueryEmbedderPort` instead of importing
    `adapters.ports.EmbeddingPort`, because `adapters.ports` pulls `adapters.identity` onto the
    hot path's static import graph and `scripts/purity_check.py` (invariant 1, CI-blocking) walks
    that graph including `TYPE_CHECKING` blocks.

    A hand-copied protocol is only safe while it stays a copy, so this asserts the copy directly:
    identical `embed` signature, and identical runtime behaviour of the two `isinstance` checks
    across an object that has `embed` and one that does not. If `EmbeddingPort.embed` ever grows a
    parameter, this goes red rather than the retriever silently accepting a stale shape.
    """
    assert inspect.signature(QueryEmbedderPort.embed) == inspect.signature(EmbeddingPort.embed)

    class _NoEmbed:
        pass

    assert not isinstance(_NoEmbed(), QueryEmbedderPort)
    assert not isinstance(_NoEmbed(), EmbeddingPort)


# --------------------------------------------------------------------------- #
# EmbeddingTimeout -> lexical-only + degraded flag, never a raise.
# --------------------------------------------------------------------------- #


def test_embedding_timeout_degrades_to_lexical_only_with_flag_set() -> None:
    search = _FakeSearch(lexical=[_hit(MEM_A, 5.0)], vector=[_hit(MEM_B, 0.9)])
    embedding = _FakeEmbeddingPort(raise_=EmbeddingTimeout("simulated slow endpoint"))
    retriever = Retriever(search, embedding, FakeClock())

    outcome = retriever.retrieve(PROJECT, "how do I retry a tool call", cfg=RetrievalConfig())

    assert isinstance(outcome, RetrievalOutcome)
    assert outcome.degraded is True
    # Lexical-only: the vector arm's canned hit must never appear, and the arm must never have
    # been called at all -- "degraded" cannot mean "called and ignored."
    assert [c.memory_id for c in outcome.candidates] == [MEM_A]
    assert outcome.candidates[0].vector is None
    assert search.vector_calls == []
    assert search.lexical_calls  # the lexical arm still ran


def test_embedding_timeout_does_not_raise() -> None:
    search = _FakeSearch()
    embedding = _FakeEmbeddingPort(raise_=EmbeddingTimeout("simulated"))
    retriever = Retriever(search, embedding, FakeClock())
    # Must not raise -- PLAN.md §2 invariant 2: a run never fails because of Tracebed.
    outcome = retriever.retrieve(PROJECT, "query", cfg=RetrievalConfig())
    assert outcome.degraded is True


def test_embedding_port_returning_no_vectors_degrades_like_a_timeout() -> None:
    """A port that answers a non-empty request with an empty vector list is exactly as unusable
    to the vector arm as a timeout -- must degrade the same way, not raise `IndexError`."""
    search = _FakeSearch(lexical=[_hit(MEM_A, 1.0)])
    embedding = _FakeEmbeddingPort(empty_response=True)
    retriever = Retriever(search, embedding, FakeClock())

    outcome = retriever.retrieve(PROJECT, "query", cfg=RetrievalConfig())

    assert outcome.degraded is True
    assert search.vector_calls == []


# --------------------------------------------------------------------------- #
# Both arms empty -> empty, not an error.
# --------------------------------------------------------------------------- #


def test_both_arms_empty_returns_empty_candidates_not_an_error() -> None:
    search = _FakeSearch(lexical=[], vector=[])
    embedding = _FakeEmbeddingPort(vectors=[[0.1, 0.2]])
    retriever = Retriever(search, embedding, FakeClock())

    outcome = retriever.retrieve(PROJECT, "query", cfg=RetrievalConfig())

    assert outcome.candidates == ()
    assert outcome.degraded is False
    assert outcome.candidates_considered == 0


# --------------------------------------------------------------------------- #
# Concurrency: both arms actually run in parallel, not one after the other.
# --------------------------------------------------------------------------- #


def test_both_arms_run_concurrently() -> None:
    """A `threading.Barrier(2)` can only be cleared if both arms reach it before either proceeds
    -- if `retrieve()` ran them sequentially, the first call would block on the barrier until its
    timeout and this test would fail loudly (`BrokenBarrierError`), never pass by accident."""
    barrier = threading.Barrier(2, timeout=2.0)
    order: list[str] = []
    lock = threading.Lock()

    class _SynchronizedSearch:
        def lexical_arm(self, project_id: ProjectId, query: str, top_n: int) -> list[ArmHit]:
            barrier.wait()
            with lock:
                order.append("lexical")
            return []

        def vector_arm(
            self,
            project_id: ProjectId,
            embedding: Sequence[float],
            top_n: int,
            *,
            hnsw_iterative_scan: bool,
            hnsw_max_scan_tuples: int,
        ) -> list[ArmHit]:
            barrier.wait()
            with lock:
                order.append("vector")
            return []

    retriever = Retriever(_SynchronizedSearch(), _FakeEmbeddingPort(), FakeClock())
    outcome = retriever.retrieve(PROJECT, "query", cfg=RetrievalConfig())
    retriever.close()

    assert outcome.candidates == ()
    assert sorted(order) == ["lexical", "vector"]


def test_lexical_arm_starts_before_the_embed_call_returns() -> None:
    """PLAN.md §2 invariant 2's arithmetic: `embed_timeout_ms` (200) is two thirds of
    `total_budget_ms` (300). If the lexical arm only starts after the embedder gives up, the
    degraded path costs 200ms PLUS the lexical query and the ladder demotes it a second time, to
    prefix-only. So the lexical arm must already be in flight while the embed is outstanding.

    Proven by making the embedder refuse to return until the lexical arm has actually started:
    if `retrieve()` embedded first, nothing would ever start the lexical arm and the wait below
    would time out.
    """
    lexical_started = threading.Event()

    class _SignallingSearch:
        def lexical_arm(self, project_id: ProjectId, query: str, top_n: int) -> list[ArmHit]:
            lexical_started.set()
            return []

        def vector_arm(
            self,
            project_id: ProjectId,
            embedding: Sequence[float],
            top_n: int,
            *,
            hnsw_iterative_scan: bool,
            hnsw_max_scan_tuples: int,
        ) -> list[ArmHit]:
            return []

    class _BlockingEmbedder:
        def embed(self, texts: Sequence[str], *, timeout_ms: int) -> list[list[float]]:
            assert lexical_started.wait(timeout=2.0), (
                "the lexical arm had not started while the embed call was outstanding -- "
                "the embed sub-budget is being spent before retrieval begins"
            )
            return [[0.1] for _ in texts]

        @property
        def model_id(self) -> str:
            return "blocking"

        @property
        def model_version(self) -> str:
            return "v1"

    retriever = Retriever(_SignallingSearch(), _BlockingEmbedder(), FakeClock())
    try:
        outcome = retriever.retrieve(PROJECT, "query", cfg=RetrievalConfig())
    finally:
        retriever.close()
    assert outcome.candidates == ()


# --------------------------------------------------------------------------- #
# `retrieval.fused_top_n` -- the fused list is cut here, not left to the assembler.
# --------------------------------------------------------------------------- #


def _ten_lexical_hits() -> list[ArmHit]:
    """Ten hits in a known, strictly-decreasing raw_score order, so fused order == list order."""
    return [_hit(MemoryId(uuid.UUID(int=n)), float(100 - n)) for n in range(1, 11)]


def test_fused_candidates_are_cut_to_fused_top_n() -> None:
    hits = _ten_lexical_hits()
    search = _FakeSearch(lexical=hits, vector=[])
    retriever = Retriever(search, _FakeEmbeddingPort(), FakeClock())

    outcome = retriever.retrieve(PROJECT, "query", cfg=RetrievalConfig(fused_top_n=3))

    assert [c.memory_id for c in outcome.candidates] == [h.memory_id for h in hits[:3]]
    assert [c.fused_rank for c in outcome.candidates] == [1, 2, 3]
    # The cut is a cut, not a rewrite of how much work was done: `candidates_considered` still
    # reports the full pre-fusion union (contract §5.2).
    assert outcome.candidates_considered == 10


def test_fused_top_n_comes_from_config_and_is_not_a_hardcoded_number() -> None:
    hits = _ten_lexical_hits()
    search = _FakeSearch(lexical=hits, vector=[])
    retriever = Retriever(search, _FakeEmbeddingPort(), FakeClock())

    # Default is 20 (PLAN.md §6) -- above the ten available hits, so nothing is cut.
    assert len(retriever.retrieve(PROJECT, "q", cfg=RetrievalConfig()).candidates) == 10
    assert len(
        retriever.retrieve(PROJECT, "q", cfg=RetrievalConfig(fused_top_n=7)).candidates
    ) == 7


@pytest.mark.parametrize("bad_top_n", [0, -5])
def test_non_positive_fused_top_n_yields_nothing_never_a_negative_slice(bad_top_n: int) -> None:
    """A negative bound must not silently mean "all but the last |n|" -- the one way a cap can
    turn into its own opposite."""
    search = _FakeSearch(lexical=_ten_lexical_hits(), vector=[])
    retriever = Retriever(search, _FakeEmbeddingPort(), FakeClock())

    outcome = retriever.retrieve(PROJECT, "q", cfg=RetrievalConfig(fused_top_n=bad_top_n))

    assert outcome.candidates == ()


def test_close_shuts_down_the_executor_and_further_calls_are_rejected() -> None:
    retriever = Retriever(_FakeSearch(), _FakeEmbeddingPort(), FakeClock())
    retriever.close()
    with pytest.raises(RuntimeError):
        retriever.retrieve(PROJECT, "query", cfg=RetrievalConfig())


# --------------------------------------------------------------------------- #
# Config values are threaded through to each arm untouched -- no magic numbers.
# --------------------------------------------------------------------------- #


def test_config_values_are_passed_through_to_both_arms_and_to_fusion() -> None:
    search = _FakeSearch(lexical=[_hit(MEM_A, 5.0)], vector=[_hit(MEM_B, 0.9)])
    embedding = _FakeEmbeddingPort(vectors=[[1.0, 2.0, 3.0]])
    retriever = Retriever(search, embedding, FakeClock())
    cfg = RetrievalConfig(
        embed_timeout_ms=123,
        arm_top_n=7,
        hnsw_iterative_scan=False,
        hnsw_max_scan_tuples=999,
        rrf_k=10,
        rrf_weight_lexical=2.0,
        rrf_weight_vector=0.5,
    )

    retriever.retrieve(PROJECT, "hello world", cfg=cfg)

    (embed_call,) = embedding.calls
    assert embed_call == (("hello world",), 123)

    (lexical_call,) = search.lexical_calls
    assert lexical_call == (PROJECT, "hello world", 7)

    (vector_call,) = search.vector_calls
    assert vector_call == (PROJECT, [1.0, 2.0, 3.0], 7, False, 999)


def test_candidates_considered_counts_the_union_before_fusion_collapses_duplicates() -> None:
    # MEM_A appears in both arms; MEM_B only in lexical. Union size is 2, not 3.
    search = _FakeSearch(lexical=[_hit(MEM_A, 5.0), _hit(MEM_B, 1.0)], vector=[_hit(MEM_A, 0.9)])
    embedding = _FakeEmbeddingPort(vectors=[[0.1, 0.2]])
    retriever = Retriever(search, embedding, FakeClock())

    outcome = retriever.retrieve(PROJECT, "query", cfg=RetrievalConfig())

    assert outcome.candidates_considered == 2
    assert len(outcome.candidates) == 2


def test_embed_latency_is_measured_from_the_injected_clock() -> None:
    clock = FakeClock()

    class _SlowEmbeddingPort:
        def embed(self, texts: Sequence[str], *, timeout_ms: int) -> list[list[float]]:
            clock.advance(ms=42)
            return [[0.1] for _ in texts]

        @property
        def model_id(self) -> str:
            return "slow"

        @property
        def model_version(self) -> str:
            return "v1"

    retriever = Retriever(_FakeSearch(), _SlowEmbeddingPort(), clock)
    outcome = retriever.retrieve(PROJECT, "query", cfg=RetrievalConfig())
    assert outcome.embed_latency_ms == 42


# --------------------------------------------------------------------------- #
# Sanity: real thread pool timing shows concurrency reduces wall time.
# --------------------------------------------------------------------------- #


def test_concurrent_arms_complete_faster_than_the_sum_of_their_latencies() -> None:
    class _SlowSearch:
        def lexical_arm(self, project_id: ProjectId, query: str, top_n: int) -> list[ArmHit]:
            time.sleep(0.05)
            return []

        def vector_arm(
            self,
            project_id: ProjectId,
            embedding: Sequence[float],
            top_n: int,
            *,
            hnsw_iterative_scan: bool,
            hnsw_max_scan_tuples: int,
        ) -> list[ArmHit]:
            time.sleep(0.05)
            return []

    retriever = Retriever(_SlowSearch(), _FakeEmbeddingPort(), FakeClock())
    started = time.perf_counter()
    retriever.retrieve(PROJECT, "query", cfg=RetrievalConfig())
    elapsed = time.perf_counter() - started
    retriever.close()

    # Sequential would take >= 0.10s; concurrent should complete well under that.
    assert elapsed < 0.09
