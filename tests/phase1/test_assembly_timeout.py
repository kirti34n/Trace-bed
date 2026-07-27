"""The assembly stage's server-side `statement_timeout` bound (invariant 2, D-139).

`CandidateAssembly.run` issues three synchronous `SearchStore` round trips — content fetch, corpus
count, per-term document frequency — on the SAME 300ms budget the two retrieval arms run under.
Before D-139 those three opened `scoped()` with no `statement_timeout_ms`, so a wedged Postgres ran
them unbounded server-side even after `hotpath.pipeline` had already given up on the call and
degraded it to `timeout_prefix_only`: the client-side report was correct, but the backend stayed
busy. The retrieval arms already carried the bound; this closes the same gap on the assembly stage.

Two layers are proven here, both fully offline (no Postgres in this environment — the same fake-pool
convention as `tests/phase1/test_search_sql.py` and `tests/phase1/test_hard_cancellation.py`):

  1. STORE LEVEL — `SearchStore.fetch_candidates`/`corpus_size`/`document_frequency` forward a
     supplied `statement_timeout_ms` into `scoped()` as the transaction-scoped
     `set_config('statement_timeout', ...)` GUC (exactly as `lexical_arm`/`vector_arm` do), and
     issue NO such GUC when none is supplied (the unbounded default every non-hot-path caller —
     `hotpath.jit`, background workers — relies on).

  2. RUN LEVEL — `CandidateAssembly.run` derives that timeout from `cfg.retrieval.total_budget_ms`
     (the exact source the retriever derives its own arm bounds from) and hands it to all three
     store calls; and, because `CandidateStorePort` is only structurally checked, a store that has
     NOT grown the parameter is called WITHOUT the keyword rather than with one it cannot accept,
     so the assembly stage bounds the production store server-side without changing the call shape
     any test double or alternative driver sees.
"""

from __future__ import annotations

import inspect
import uuid
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from tracebed.domain.clock import FakeClock
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
from tracebed.domain.enums import MemType, ScopeType, TrustTier
from tracebed.domain.ids import AgentTypeId, MemoryId, PrincipalId, ProjectId
from tracebed.domain.scope import ProjectScope
from tracebed.domain.state_machine import Status
from tracebed.hotpath.assembly import CandidateAssembly, CandidateStorePort
from tracebed.hotpath.fusion import ArmSignal, FusedCandidate
from tracebed.stores.pg import pool as pool_module
from tracebed.stores.pg.search import CandidateRow, SearchStore

pytestmark = pytest.mark.phase1

PROJECT = ProjectId(uuid.UUID(int=42))
NOW = datetime(2026, 7, 26, 12, 0, 0, tzinfo=UTC)
# Two rare terms shared between query and content, so the rarity gate reaches the df lookup.
QUERY = "retry idempotent tool invocation"


# --------------------------------------------------------------------------- #
# Layer 1: the fake pool that records what `scoped()` and the store issue.
# --------------------------------------------------------------------------- #


class _FakeCursor:
    def __init__(self, log: list[tuple[str, Any]], rows: list[Any]) -> None:
        self._log = log
        self._rows = rows

    def execute(self, sql: str, params: Any = None) -> _FakeCursor:
        self._log.append((sql, params))
        return self

    def fetchall(self) -> list[Any]:
        return list(self._rows)

    def fetchone(self) -> Any:
        return self._rows[0] if self._rows else None

    def __enter__(self) -> _FakeCursor:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class _FakeConn:
    def __init__(self, log: list[tuple[str, Any]], rows: list[Any]) -> None:
        self._log = log
        self._rows = rows

    def execute(self, sql: str, params: Any = None) -> _FakeCursor:
        self._log.append((sql, params))
        return _FakeCursor(self._log, self._rows)

    def cursor(self, **_kwargs: Any) -> _FakeCursor:
        return _FakeCursor(self._log, self._rows)

    @contextmanager
    def transaction(self) -> Iterator[_FakeConn]:
        yield self


class _FakePool:
    """Stands in for `psycopg_pool.ConnectionPool`; `scoped()` only ever calls `.connection()`."""

    def __init__(self, rows: list[Any] | None = None) -> None:
        self.log: list[tuple[str, Any]] = []
        self._rows = rows if rows is not None else []

    @contextmanager
    def connection(self) -> Iterator[_FakeConn]:
        yield _FakeConn(self.log, self._rows)


def _store(rows: list[Any] | None = None) -> tuple[SearchStore, _FakePool]:
    pool = _FakePool(rows)
    return SearchStore(pool), pool  # type: ignore[arg-type]


def _timeout_gucs(log: list[tuple[str, Any]]) -> list[Any]:
    """Every `SET statement_timeout` GUC `scoped()` issued, by its bound params."""
    return [params for sql, params in log if sql == pool_module._SET_STATEMENT_TIMEOUT]


# --------------------------------------------------------------------------- #
# Layer 1: each store method carries the GUC when supplied, none when not.
# --------------------------------------------------------------------------- #


def test_fetch_candidates_issues_the_statement_timeout_guc_when_supplied() -> None:
    store, pool = _store()
    store.fetch_candidates(PROJECT, [MemoryId(uuid.UUID(int=1))], statement_timeout_ms=250)
    assert _timeout_gucs(pool.log) == [{"statement_timeout_ms": "250"}]


def test_corpus_size_issues_the_statement_timeout_guc_when_supplied() -> None:
    store, pool = _store()
    store.corpus_size(PROJECT, statement_timeout_ms=250)
    assert _timeout_gucs(pool.log) == [{"statement_timeout_ms": "250"}]


def test_document_frequency_issues_the_statement_timeout_guc_when_supplied() -> None:
    store, pool = _store()
    store.document_frequency(PROJECT, ["retry"], statement_timeout_ms=250)
    assert _timeout_gucs(pool.log) == [{"statement_timeout_ms": "250"}]


@pytest.mark.parametrize(
    "call",
    [
        lambda s: s.fetch_candidates(PROJECT, [MemoryId(uuid.UUID(int=1))]),
        lambda s: s.corpus_size(PROJECT),
        lambda s: s.document_frequency(PROJECT, ["retry"]),
    ],
)
def test_no_statement_timeout_guc_when_none_is_supplied(call: Any) -> None:
    """The unbounded default: a non-hot-path caller (`hotpath.jit`, a worker) that passes nothing
    gets exactly the pre-D-139 statement stream — only the RLS GUC, never a `statement_timeout`."""
    store, pool = _store()
    call(store)
    assert _timeout_gucs(pool.log) == []
    # And the RLS project GUC is still the first thing issued, unchanged.
    assert pool.log[0] == (pool_module._SET_PROJECT_GUC, {"project_id": str(PROJECT)})


def test_the_guc_value_is_the_bound_verbatim_not_a_constant() -> None:
    """Kills a mutation that hard-codes or drops the bound: the GUC must carry the caller's own
    millisecond count, stringified exactly as `scoped()` binds it."""
    store, pool = _store()
    store.corpus_size(PROJECT, statement_timeout_ms=137)
    assert _timeout_gucs(pool.log) == [{"statement_timeout_ms": "137"}]


# --------------------------------------------------------------------------- #
# Layer 2: run() derives the bound from the budget and forwards it to all three.
# --------------------------------------------------------------------------- #


def _scope() -> ProjectScope:
    return ProjectScope(
        project_id=PROJECT,
        agent_type_id=AgentTypeId(uuid.UUID(int=7)),
        principal_id=PrincipalId(uuid.UUID(int=8)),
    )


def _cfg(total_budget_ms: int = 300) -> EffectiveConfig:
    """A full `EffectiveConfig` from the real Phase 0 section models (so a field rename in
    `domain/config.py` breaks this rather than leaving it silently green), with only
    `retrieval.total_budget_ms` — the number `run` derives its bound from — varied."""
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
        killswitch=KillswitchConfig(),
        spend=SpendConfig(),
        cache=CacheConfig(),
        session=SessionConfig(),
        queue=QueueConfig(),
    )


def _row(memory_id: MemoryId) -> CandidateRow:
    return CandidateRow(
        memory_id=memory_id,
        mem_type=MemType.SEMANTIC,
        trust_tier=TrustTier.B,
        status=Status.VALIDATED,
        content="retry idempotent invocation guidance",
        token_count=10,
        q_value=0.8,
        confidence=0.9,
        created_at=NOW - timedelta(days=1),
        scope_type=ScopeType.PROJECT_SHARED,
        scope_id=None,
    )


def _fused(memory_id: MemoryId) -> FusedCandidate:
    return FusedCandidate(
        memory_id=memory_id,
        trust_tier=TrustTier.B,
        status=Status.VALIDATED,
        fused_rank=1,
        lexical=ArmSignal(raw_score=50.0, rank=1),
        vector=ArmSignal(raw_score=0.9, rank=1),
    )


class _RecordingStore:
    """A `CandidateStorePort` that ACCEPTS the D-139 bound and records what it was passed — the
    shape the production `SearchStore` has. Returns a matching row so `run()` proceeds past the
    content fetch into the rarity lookup, exercising all three round trips."""

    def __init__(self, rows: Sequence[CandidateRow]) -> None:
        self._rows = list(rows)
        self.fetch_timeout: int | None = None
        self.corpus_timeout: int | None = None
        self.df_timeout: int | None = None
        self.corpus_called = False
        self.df_called = False

    def fetch_candidates(
        self,
        project_id: ProjectId,
        memory_ids: Sequence[MemoryId],
        *,
        statement_timeout_ms: int | None = None,
    ) -> list[CandidateRow]:
        self.fetch_timeout = statement_timeout_ms
        wanted = set(memory_ids)
        return [r for r in self._rows if r.memory_id in wanted]

    def document_frequency(
        self,
        project_id: ProjectId,
        terms: Sequence[str],
        *,
        statement_timeout_ms: int | None = None,
    ) -> dict[str, int]:
        self.df_called = True
        self.df_timeout = statement_timeout_ms
        return dict.fromkeys(terms, 1)

    def corpus_size(
        self, project_id: ProjectId, *, statement_timeout_ms: int | None = None
    ) -> int:
        self.corpus_called = True
        self.corpus_timeout = statement_timeout_ms
        return 1_000


class _LegacyStore:
    """A `CandidateStorePort` that PRE-DATES the bound: its three methods take no
    `statement_timeout_ms`, exactly like the fakes still shipping in other test modules and like an
    alternative retrieval driver that has not grown the parameter. If `run()` forwarded the keyword
    unconditionally, every call here would raise `TypeError` — so a green run is the proof that the
    feature-detection left the non-hot-path call shape untouched."""

    def __init__(self, rows: Sequence[CandidateRow]) -> None:
        self._rows = list(rows)
        self.corpus_called = False
        self.df_called = False

    def fetch_candidates(
        self, project_id: ProjectId, memory_ids: Sequence[MemoryId]
    ) -> list[CandidateRow]:
        wanted = set(memory_ids)
        return [r for r in self._rows if r.memory_id in wanted]

    def document_frequency(self, project_id: ProjectId, terms: Sequence[str]) -> dict[str, int]:
        self.df_called = True
        return dict.fromkeys(terms, 1)

    def corpus_size(self, project_id: ProjectId) -> int:
        self.corpus_called = True
        return 1_000


def test_run_bounds_all_three_store_calls_by_the_total_budget() -> None:
    mid = MemoryId(uuid.UUID(int=1))
    store = _RecordingStore([_row(mid)])
    assembly = CandidateAssembly(store, FakeClock(NOW))

    assembly.run(_scope(), query_text=QUERY, candidates=[_fused(mid)], cfg=_cfg(300))

    # All three round trips happened, and each carried the SAME budget-derived bound.
    assert store.corpus_called and store.df_called
    assert store.fetch_timeout == 300
    assert store.corpus_timeout == 300
    assert store.df_timeout == 300


def test_run_derives_the_bound_from_config_not_a_literal() -> None:
    """A non-default `total_budget_ms` must flow through verbatim — proof the bound is read from
    `cfg.retrieval.total_budget_ms` (the retriever's own source) rather than a hard-coded 300."""
    mid = MemoryId(uuid.UUID(int=1))
    store = _RecordingStore([_row(mid)])
    assembly = CandidateAssembly(store, FakeClock(NOW))

    assembly.run(_scope(), query_text=QUERY, candidates=[_fused(mid)], cfg=_cfg(123))

    assert store.fetch_timeout == 123
    assert store.corpus_timeout == 123
    assert store.df_timeout == 123


def test_run_passes_no_keyword_to_a_store_that_cannot_accept_it() -> None:
    """The feature-detection: a store without the parameter is called with its original argument
    list, so bounding the assembly stage never breaks a test double or a driver that predates the
    bound. A `TypeError` here would mean the keyword was forwarded unconditionally."""
    mid = MemoryId(uuid.UUID(int=1))
    store = _LegacyStore([_row(mid)])
    assembly = CandidateAssembly(store, FakeClock(NOW))

    result = assembly.run(_scope(), query_text=QUERY, candidates=[_fused(mid)], cfg=_cfg(300))

    # It ran to completion (no unexpected-keyword TypeError) and still exercised all three reads.
    assert store.corpus_called and store.df_called
    assert result.outcome_code is not None


def test_the_store_port_advertises_the_optional_bound() -> None:
    """`CandidateStorePort` — shared with `hotpath.jit` — must carry the optional keyword on all
    three methods, so the production `SearchStore` and the port stay one contract (the parity guard
    in `tests/phase1/test_assembly.py` compares their signatures) and `run` can rely on it."""
    for name in ("fetch_candidates", "document_frequency", "corpus_size"):
        params = inspect.signature(getattr(CandidateStorePort, name)).parameters
        assert "statement_timeout_ms" in params, name
        assert params["statement_timeout_ms"].kind is inspect.Parameter.KEYWORD_ONLY, name
