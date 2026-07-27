"""`stores.pg.search.SearchStore` — offline SQL-shape proofs, plus a guarded integration test.

OFFLINE (runs everywhere, no database): there is no Postgres on this build machine, so every
assertion about *which* SQL is issued is made against a fake connection that records statements —
the same technique `tests/phase0/test_repo_isolation_offline.py` uses for `Repo`, and for the same
reason: this is the regression guard PLAN.md §7 itself asks for ("an offline test that parses the
generated SQL and asserts the status predicate and the project_id predicate are both present in
every query ... dropping either is a silent leak").

INTEGRATION (`@pytest.mark.integration`, needs a live Postgres 18 with `pgvector` + `pg_textsearch`
— absent on this build machine): provisions one real project, inserts rows across every status,
and proves the retrievable-status predicate holds against a real database, not just against the
SQL text. Skips cleanly — never errors at setup — exactly like every other fixture in this
repository when no database is reachable, per the environment constraint this whole test suite is
written under; it additionally skips (rather than erroring) if the database IS reachable but
lacks the `pg_textsearch`/`pgvector` extensions this module's queries depend on, because "database
present, extension absent" is a provisioning gap, not a proof that invariant 7's retrieval-side
predicate is wrong.
"""

from __future__ import annotations

import math
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest

from tracebed.domain.enums import TrustTier
from tracebed.domain.errors import TracebedError
from tracebed.domain.ids import MemoryId, ProjectId
from tracebed.domain.state_machine import Status
from tracebed.stores.pg.search import ArmHit, SearchStore

pytestmark = pytest.mark.phase1

PROJECT = ProjectId(uuid.UUID(int=42))


# --------------------------------------------------------------------------- #
# The fake database (mirrors tests/phase0/test_repo_isolation_offline.py's fakes).
# --------------------------------------------------------------------------- #


class _FakeCursor:
    def __init__(
        self, log: list[tuple[str, Any]], rows: list[Any] | None = None, *, name: str | None = None
    ) -> None:
        self._log = log
        self._rows = rows if rows is not None else []
        self.name = name

    def execute(self, sql: str, params: Any = None) -> _FakeCursor:
        self._log.append((sql, params))
        return self

    def fetchone(self) -> Any:
        return self._rows[0] if self._rows else None

    def fetchall(self) -> list[Any]:
        return list(self._rows)

    def __enter__(self) -> _FakeCursor:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class _FakeConnection:
    def __init__(self, log: list[tuple[str, Any]], rows: list[Any] | None = None) -> None:
        self._log = log
        self._rows = rows if rows is not None else []

    def execute(self, sql: str, params: Any = None) -> _FakeCursor:
        self._log.append((sql, params))
        return _FakeCursor(self._log)

    def cursor(self, *, row_factory: Any = None, name: str | None = None) -> _FakeCursor:
        return _FakeCursor(self._log, self._rows, name=name)

    @contextmanager
    def transaction(self) -> Iterator[_FakeConnection]:
        yield self


class _FakePool:
    """Stands in for `psycopg_pool.ConnectionPool`; `scoped()` only ever calls `.connection()`."""

    def __init__(self, rows: list[Any] | None = None) -> None:
        self.log: list[tuple[str, Any]] = []
        self._rows = rows if rows is not None else []

    @contextmanager
    def connection(self) -> Iterator[_FakeConnection]:
        yield _FakeConnection(self.log, self._rows)


def _store(rows: list[Any] | None = None) -> tuple[SearchStore, _FakePool]:
    pool = _FakePool(rows)
    return SearchStore(pool), pool  # type: ignore[arg-type]


def _row(memory_id: MemoryId, raw_score: float, *, tier: str = "A", status: str = "validated") -> dict[str, Any]:
    return {"id": memory_id.value, "trust_tier": tier, "status": status, "raw_score": raw_score}


# --------------------------------------------------------------------------- #
# The regression guard: project_id AND the status predicate in EVERY query.
# --------------------------------------------------------------------------- #


def _memory_item_statements(log: list[tuple[str, Any]]) -> list[tuple[str, Any]]:
    return [(sql, params) for sql, params in log if "FROM memory_item" in sql or "JOIN memory_item" in sql]


def test_lexical_arm_query_carries_project_id_and_status_predicates() -> None:
    store, pool = _store()
    store.lexical_arm(PROJECT, "retry budget", 10)
    statements = _memory_item_statements(pool.log)
    assert statements, "lexical_arm issued no memory_item query"
    sql, params = statements[0]
    assert "project_id = %(project_id)s" in sql
    assert "status = ANY(%(statuses)s)" in sql
    assert "trust_tier = %(tier_a)s" in sql
    assert params["project_id"] == PROJECT
    assert set(params["statuses"]) == {Status.VALIDATED.value, Status.CANDIDATE.value}
    assert params["tier_a"] == TrustTier.A.value


def test_vector_arm_query_carries_project_id_and_status_predicates() -> None:
    store, pool = _store()
    store.vector_arm(
        PROJECT, [0.1, 0.2, 0.3], 10, hnsw_iterative_scan=True, hnsw_max_scan_tuples=20_000
    )
    statements = _memory_item_statements(pool.log)
    assert statements, "vector_arm issued no memory_item query"
    sql, params = statements[0]
    assert "project_id = %(project_id)s" in sql
    assert "status = ANY(%(statuses)s)" in sql
    assert "trust_tier = %(tier_a)s" in sql
    assert params["project_id"] == PROJECT


def test_document_frequency_query_carries_project_id_and_status_predicates() -> None:
    store, pool = _store()
    store.document_frequency(PROJECT, ["retry", "budget"])
    statements = _memory_item_statements(pool.log)
    assert statements, "document_frequency issued no memory_item query"
    sql, params = statements[0]
    assert "m.project_id = %(project_id)s" in sql
    assert "m.status = ANY(%(statuses)s)" in sql
    assert "m.trust_tier = %(tier_a)s" in sql
    assert params["project_id"] == PROJECT


def test_corpus_size_query_carries_project_id_and_status_predicates() -> None:
    store, pool = _store()
    store.corpus_size(PROJECT)
    statements = _memory_item_statements(pool.log)
    assert statements, "corpus_size issued no memory_item query"
    sql, params = statements[0]
    assert "project_id = %(project_id)s" in sql
    assert "status = ANY(%(statuses)s)" in sql
    assert "trust_tier = %(tier_a)s" in sql
    assert params["project_id"] == PROJECT


def test_no_memory_item_query_anywhere_omits_either_predicate() -> None:
    """The consolidated regression guard: run every public method once, then walk every
    `memory_item` statement issued by ANY of them and assert both predicates are present.
    Dropping either from a future edit to any one method fails this test, not just that
    method's own dedicated test above."""
    store, pool = _store()
    store.lexical_arm(PROJECT, "q", 10)
    store.vector_arm(PROJECT, [0.1], 10, hnsw_iterative_scan=True, hnsw_max_scan_tuples=1_000)
    store.document_frequency(PROJECT, ["term"])
    store.corpus_size(PROJECT)

    statements = _memory_item_statements(pool.log)
    assert len(statements) == 4, f"expected one memory_item statement per method, got {len(statements)}"
    for sql, params in statements:
        assert "project_id = %(project_id)s" in sql or "m.project_id = %(project_id)s" in sql, sql
        assert params["project_id"] == PROJECT
        assert "status = ANY(%(statuses)s)" in sql or "m.status = ANY(%(statuses)s)" in sql, sql
        assert set(params["statuses"]) == {Status.VALIDATED.value, Status.CANDIDATE.value}


def test_every_query_carries_the_exact_retrievable_predicate_text() -> None:
    """The presence tests above assert that the two conjuncts APPEAR; this asserts the predicate's
    SHAPE, character for character.

    Without it, mutating `status <> candidate OR trust_tier = 'A'` into `... AND ...` (which
    silently drops every validated Tier-B memory from every result) leaves both substrings intact
    and every other test in this file green. The expected text is spelled out here rather than
    imported from `search._retrievable_predicate`, so a test that changed with the code would not
    be a test at all.
    """
    expected = (
        "status = ANY(%(statuses)s) AND "
        "(status <> %(candidate_status)s OR trust_tier = %(tier_a)s)"
    )
    store, pool = _store()
    store.lexical_arm(PROJECT, "q", 10)
    store.vector_arm(PROJECT, [0.1], 10, hnsw_iterative_scan=True, hnsw_max_scan_tuples=1_000)
    store.corpus_size(PROJECT)
    store.document_frequency(PROJECT, ["term"])

    unprefixed = [sql for sql, _ in _memory_item_statements(pool.log) if "JOIN memory_item" not in sql]
    assert len(unprefixed) == 3
    for sql in unprefixed:
        assert expected in sql, sql

    # The join form is the same predicate with `m.` on the COLUMN names only -- the bind-parameter
    # names (`%(statuses)s`, `%(candidate_status)s`) must survive un-prefixed, or psycopg would be
    # asked for parameters nothing binds.
    prefixed = (
        "m.status = ANY(%(statuses)s) AND "
        "(m.status <> %(candidate_status)s OR m.trust_tier = %(tier_a)s)"
    )
    (joined,) = [sql for sql, _ in _memory_item_statements(pool.log) if "JOIN memory_item" in sql]
    assert prefixed in joined, joined


def test_every_method_sets_the_rls_project_guc_before_its_own_statement() -> None:
    """Invariant 4: every one of these queries must run inside `pool.scoped()`, which issues the
    `tracebed.project_id` GUC as the transaction's first statement. Swapping any single method to
    a bare `pool.connection()` would keep its explicit `project_id = ...` predicate (so every
    predicate test above stays green) while removing the RLS backstop underneath it."""
    for call in (
        lambda s: s.lexical_arm(PROJECT, "q", 10),
        lambda s: s.vector_arm(PROJECT, [0.1], 10, hnsw_iterative_scan=True, hnsw_max_scan_tuples=1),
        lambda s: s.document_frequency(PROJECT, ["term"]),
        lambda s: s.corpus_size(PROJECT),
    ):
        store, pool = _store()
        call(store)
        first_sql, first_params = pool.log[0]
        assert "tracebed.project_id" in first_sql, first_sql
        assert first_params == {"project_id": str(PROJECT)}


@pytest.mark.parametrize(
    "excluded_status",
    [
        Status.QUARANTINED,
        Status.SUPERSEDED,
        Status.STALE,
        Status.RETIRED,
        Status.ARCHIVED,
        Status.PINNED,
        Status.TOMBSTONED,
    ],
)
def test_retrievable_status_list_never_includes_a_non_retrievable_status(
    excluded_status: Status,
) -> None:
    """PLAN.md §2 invariant 7's retrieval half, restated directly against the bound parameter:
    quarantined/stale/superseded/retired/archived/tombstoned must never appear, and `pinned` is
    deliberately excluded from these dynamic arms too (module docstring: prefix-only, Phase 2)."""
    store, pool = _store()
    store.corpus_size(PROJECT)
    _, params = _memory_item_statements(pool.log)[0]
    assert excluded_status.value not in params["statuses"]


# --------------------------------------------------------------------------- #
# "Asked for nothing" short-circuits issue no statement at all.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("query", ["", "   "])
def test_lexical_arm_blank_query_issues_no_statement(query: str) -> None:
    store, pool = _store()
    assert store.lexical_arm(PROJECT, query, 10) == []
    assert pool.log == []


def test_lexical_arm_nonpositive_top_n_issues_no_statement() -> None:
    store, pool = _store()
    assert store.lexical_arm(PROJECT, "query", 0) == []
    assert pool.log == []


def test_vector_arm_empty_embedding_issues_no_statement() -> None:
    store, pool = _store()
    assert store.vector_arm(PROJECT, [], 10, hnsw_iterative_scan=True, hnsw_max_scan_tuples=1) == []
    assert pool.log == []


def test_vector_arm_nonpositive_top_n_issues_no_statement() -> None:
    store, pool = _store()
    result = store.vector_arm(
        PROJECT, [0.1, 0.2], -1, hnsw_iterative_scan=True, hnsw_max_scan_tuples=1
    )
    assert result == []
    assert pool.log == []


def test_document_frequency_empty_terms_issues_no_statement() -> None:
    store, pool = _store()
    assert store.document_frequency(PROJECT, []) == {}
    assert pool.log == []


def test_document_frequency_deduplicates_terms_before_binding() -> None:
    store, pool = _store()
    store.document_frequency(PROJECT, ["retry", "retry", "budget", "retry"])
    _, params = _memory_item_statements(pool.log)[0]
    assert params["terms"] == ["retry", "budget"]


# --------------------------------------------------------------------------- #
# top_n clamping.
# --------------------------------------------------------------------------- #


def test_lexical_arm_top_n_is_clamped_to_the_ceiling() -> None:
    store, pool = _store()
    store.lexical_arm(PROJECT, "query", 10_000_000)
    _, params = _memory_item_statements(pool.log)[0]
    assert params["top_n"] == 1_000


# --------------------------------------------------------------------------- #
# vector_arm's HNSW GUCs — set before the SELECT, mapped from the config bool.
# --------------------------------------------------------------------------- #


def test_vector_arm_sets_hnsw_gucs_before_the_select() -> None:
    store, pool = _store()
    store.vector_arm(
        PROJECT, [0.1, 0.2], 5, hnsw_iterative_scan=True, hnsw_max_scan_tuples=20_000
    )
    kinds = [
        "project_guc" if "tracebed.project_id" in sql else
        "iterative_scan" if "hnsw.iterative_scan" in sql else
        "max_scan_tuples" if "hnsw.max_scan_tuples" in sql else
        "select" if "FROM memory_item" in sql else "other"
        for sql, _ in pool.log
    ]
    # scoped() sets the RLS GUC first (contract §5.0); the two HNSW GUCs come next, in that
    # fixed order, and only then the SELECT that actually needs them.
    assert kinds == ["project_guc", "iterative_scan", "max_scan_tuples", "select"]


@pytest.mark.parametrize(("flag", "expected_mode"), [(True, "relaxed_order"), (False, "off")])
def test_vector_arm_maps_iterative_scan_bool_to_the_pgvector_guc_value(
    flag: bool, expected_mode: str
) -> None:
    store, pool = _store()
    store.vector_arm(PROJECT, [0.1], 5, hnsw_iterative_scan=flag, hnsw_max_scan_tuples=100)
    guc_call = next(p for sql, p in pool.log if "hnsw.iterative_scan" in sql)
    assert guc_call == {"mode": expected_mode}


def test_vector_arm_max_scan_tuples_guc_value_is_stringified() -> None:
    store, pool = _store()
    store.vector_arm(PROJECT, [0.1], 5, hnsw_iterative_scan=True, hnsw_max_scan_tuples=12_345)
    guc_call = next(p for sql, p in pool.log if "hnsw.max_scan_tuples" in sql)
    assert guc_call == {"max_tuples": "12345"}


def test_vector_arm_binds_the_embedding_as_a_pgvector_text_literal() -> None:
    store, pool = _store()
    store.vector_arm(PROJECT, [0.5, -1.0, 2.25], 5, hnsw_iterative_scan=True, hnsw_max_scan_tuples=1)
    _, params = _memory_item_statements(pool.log)[0]
    assert params["embedding"] == "[0.5,-1.0,2.25]"


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_vector_arm_rejects_non_finite_embedding_components(bad: float) -> None:
    store, _ = _store()
    with pytest.raises(ValueError, match="NaN or infinite"):
        store.vector_arm(
            PROJECT, [0.1, bad], 5, hnsw_iterative_scan=True, hnsw_max_scan_tuples=1
        )


# --------------------------------------------------------------------------- #
# Row parsing.
# --------------------------------------------------------------------------- #


def test_lexical_arm_parses_rows_into_arm_hits() -> None:
    mem_id = MemoryId(uuid.uuid4())
    store, _pool = _store([_row(mem_id, 4.5, tier="A", status="candidate")])
    (hit,) = store.lexical_arm(PROJECT, "query", 10)
    assert hit == ArmHit(
        memory_id=mem_id, raw_score=4.5, trust_tier=TrustTier.A, status=Status.CANDIDATE
    )


@pytest.mark.parametrize(
    "leaked_status",
    ["quarantined", "stale", "superseded", "retired", "archived", "tombstoned", "pinned"],
)
def test_a_non_retrievable_row_coming_back_from_the_database_is_refused_not_returned(
    leaked_status: str,
) -> None:
    """PLAN.md §2 invariant 7, enforced rather than documented.

    Every other test in this file asserts a property of the query TEXT. This one asserts the
    post-condition: simulate the predicate having been broken (a UNION arm without it, a hand-
    written variant, a partition created before the predicate existed) by handing the parser a row
    it should never have seen, and require that it aborts the retrieval instead of passing a
    quarantined/retired/tombstoned memory to fusion. Failing closed costs one retrieval; failing
    open costs the whole quarantine guarantee.
    """
    store, _pool = _store([_row(MemoryId(uuid.uuid4()), 4.5, tier="A", status=leaked_status)])
    with pytest.raises(TracebedError, match="retrievability predicate breached"):
        store.lexical_arm(PROJECT, "query", 10)


def test_a_tier_b_candidate_row_coming_back_from_the_database_is_refused() -> None:
    """`candidate` IS a retrievable status, but only at Tier A (PLAN.md §7). A Tier-B candidate
    reaching the parser means the second conjunct of the predicate was lost, which the status
    check alone would not notice."""
    store, _pool = _store([_row(MemoryId(uuid.uuid4()), 1.0, tier="B", status="candidate")])
    with pytest.raises(TracebedError, match="only Tier A candidates"):
        store.lexical_arm(PROJECT, "query", 10)


def test_the_refusal_message_never_carries_memory_content() -> None:
    """The exception crosses into logs and the ladder's store-error rung; a memory's content must
    not ride along with it."""
    row = _row(MemoryId(uuid.uuid4()), 1.0, status="tombstoned")
    row["content"] = "SECRET-CANARY-VALUE"
    store, _pool = _store([row])
    with pytest.raises(TracebedError) as excinfo:
        store.vector_arm(PROJECT, [0.1], 10, hnsw_iterative_scan=True, hnsw_max_scan_tuples=1)
    assert "SECRET-CANARY-VALUE" not in str(excinfo.value)


@pytest.mark.parametrize("allowed", [("A", "validated"), ("B", "validated"), ("A", "candidate")])
def test_every_genuinely_retrievable_shape_still_parses(allowed: tuple[str, str]) -> None:
    """The guard must not be so tight that it rejects what invariant 7 permits: validated at
    either tier, and candidate at Tier A."""
    tier, status = allowed
    store, _pool = _store([_row(MemoryId(uuid.uuid4()), 1.0, tier=tier, status=status)])
    (hit,) = store.lexical_arm(PROJECT, "query", 10)
    assert hit.status.value == status
    assert hit.trust_tier.value == tier


def test_document_frequency_bounds_the_term_list_it_binds() -> None:
    """`terms` is derived from caller-supplied query text; its sibling `top_n` is clamped, so this
    must be too, or one pathological query becomes an unbounded `text[]` parameter and an
    unbounded server-side `unnest`."""
    store, pool = _store()
    store.document_frequency(PROJECT, [f"t{n}" for n in range(10_000)])
    _, params = _memory_item_statements(pool.log)[0]
    assert len(params["terms"]) == 512
    # The bound truncates the tail, it does not reorder or resample: the retained terms are the
    # first ones, so the mapping a caller gets back still lines up with the query it asked about.
    assert params["terms"][:3] == ["t0", "t1", "t2"]


def test_corpus_size_parses_the_count() -> None:
    pool = _FakePool()

    class _CountConnection(_FakeConnection):
        def cursor(self, *, row_factory: Any = None, name: str | None = None) -> _FakeCursor:
            return _FakeCursor(self._log, [(7,)], name=name)

    @contextmanager
    def connection() -> Iterator[_FakeConnection]:
        yield _CountConnection(pool.log)

    pool.connection = connection  # type: ignore[method-assign]
    store = SearchStore(pool)  # type: ignore[arg-type]
    assert store.corpus_size(PROJECT) == 7


def test_document_frequency_parses_term_to_count_mapping() -> None:
    store, _pool = _store([{"term": "retry", "df": 3}, {"term": "budget", "df": 0}])
    result = store.document_frequency(PROJECT, ["retry", "budget"])
    assert result == {"retry": 3, "budget": 0}


# --------------------------------------------------------------------------- #
# `_embedding_literal` edge cases reachable only through `vector_arm`.
# --------------------------------------------------------------------------- #


def test_vector_arm_rejects_an_all_nan_embedding_even_at_length_one() -> None:
    store, _ = _store()
    with pytest.raises(ValueError):
        store.vector_arm(
            PROJECT, [math.nan], 5, hnsw_iterative_scan=True, hnsw_max_scan_tuples=1
        )


# --------------------------------------------------------------------------- #
# Integration — a real Postgres 18 with pgvector + pg_textsearch (absent here; skips cleanly).
# --------------------------------------------------------------------------- #


@pytest.mark.integration
def test_retrievable_predicate_holds_against_a_real_database(pg: str) -> None:
    """PLAN.md §2 invariant 7's retrieval-side half, proven against a live database rather than
    against SQL text: insert one row per status (plus a Tier-B `candidate`), and assert every
    method here returns/counts ONLY the validated row and the Tier-A candidate row.

    Skips (does not error) if the reachable Postgres lacks the `pg_textsearch` / `pgvector`
    extensions or the `bm25`/`vector` access methods this module's queries depend on — that is a
    provisioning gap on this machine, not evidence about the predicate under test, and the
    environment constraint governing every fixture in this repository requires a clean skip over
    an error in exactly this situation.
    """
    import psycopg

    from tracebed.core.scans import ScanContext, scan
    from tracebed.domain.clock import FakeClock
    from tracebed.domain.enums import Lane, MemType, ProvenanceClass, ScopeType
    from tracebed.domain.ids import mint_run_id
    from tracebed.domain.memory import NewMemoryItem, Provenance
    from tracebed.stores.pg.migrate import apply_migrations
    from tracebed.stores.pg.partitions import create_project_partitions
    from tracebed.stores.pg.pool import create_pool
    from tracebed.stores.pg.repo import Repo

    try:
        apply_migrations(pg)
    except Exception as exc:
        pytest.skip(f"could not bring the schema current: {exc.__class__.__name__}")

    pool = create_pool(pg)
    try:
        project_id = ProjectId(uuid.uuid4())
        try:
            with pool.connection() as conn:
                create_project_partitions(conn, project_id)
        except psycopg.errors.UndefinedObject as exc:
            pytest.skip(f"pgvector/pg_textsearch access method unavailable: {exc}")
        except Exception as exc:  # pragma: no cover - environment-dependent
            pytest.skip(f"could not provision a test project: {exc.__class__.__name__}")

        repo = Repo(pool, FakeClock())
        run_id = mint_run_id()

        def _insert(content: str, *, status: Status, tier: TrustTier) -> MemoryId:
            item = NewMemoryItem(
                scope_type=ScopeType.PROJECT_SHARED,
                scope_id=None,
                mem_type=MemType.LESSON,
                kind="k",
                lane=Lane.OPERATIONAL,
                trust_tier=tier,
                status=status,
                content=content,
                token_count=len(content.split()),
                provenance=Provenance(cls=ProvenanceClass.PARSER, trace_ids=(run_id,)),
            )
            verdict = scan(
                content,
                context=ScanContext(
                    project_id=project_id,
                    mem_type=item.mem_type,
                    trust_tier=item.trust_tier,
                    provenance_class=item.provenance.cls,
                    lane=Lane.OPERATIONAL,
                ),
            ).verdict()
            return repo.insert_memory_item(project_id, item, verdict)

        validated_id = _insert(
            "retry the flaky tool with jittered backoff", status=Status.VALIDATED, tier=TrustTier.A
        )
        candidate_a_id = _insert(
            "retry budget for the flaky tool is three attempts",
            status=Status.CANDIDATE,
            tier=TrustTier.A,
        )
        # A Tier-B row that has reached `candidate` directly (never legitimate via the state
        # machine, but the repository does not itself enforce that — this row exists purely to
        # prove the SQL predicate, not the state machine's guard) must still be excluded.
        _insert(
            "retry budget for the flaky tool is three attempts too",
            status=Status.CANDIDATE,
            tier=TrustTier.B,
        )
        _insert("retry budget note", status=Status.QUARANTINED, tier=TrustTier.B)
        _insert("retry budget note", status=Status.TOMBSTONED, tier=TrustTier.B)

        try:
            search = SearchStore(pool)
            hits = search.lexical_arm(project_id, "retry budget", 10)
        except psycopg.errors.UndefinedFunction as exc:
            pytest.skip(f"pg_textsearch bm25_score()/@@@ unavailable: {exc}")

        returned_ids = {hit.memory_id for hit in hits}
        assert returned_ids <= {validated_id, candidate_a_id}
        assert returned_ids, "expected at least the validated/candidate-A rows to match"

        corpus = search.corpus_size(project_id)
        assert corpus == 2
    finally:
        pool.close()
