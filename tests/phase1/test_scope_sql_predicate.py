"""`stores.pg.search`'s scope-visibility predicate (D-097 follow-up, D-126).

D-097 filtered `scope_type`/`scope_id` in the ASSEMBLER (`hotpath.assembly`/`hotpath.jit`,
`tests/phase1/test_scope_visibility.py`), which closes the exposure a rendered prompt could carry,
but `lexical_arm` still RETURNED ids for rows outside the caller's scope. This file guards the SQL
half.

WHY THIS FILE DOES NOT ASSERT SUBSTRINGS AND STOP THERE. The obvious suite -- "`scope_type =
%(scope_user)s` appears in the generated SQL" -- passes unchanged if `_scope_fragment`'s `user`
branch binds `%(visible_agent_type_id)s` instead of `%(visible_user_scope_id)s`. That mutation is
precisely the cross-user exposure the predicate exists to prevent, and every substring assertion in
the world stays green through it, because the scope constant and the resolver name are asserted
independently and the PAIRING between them is never checked. The core of this file is therefore
`_evaluate`, a small evaluator for the restricted grammar `_SCOPE_PREDICATE` is written in, which
runs the ACTUAL generated predicate text against an actual `(scope_type, scope_id)` row with the
ACTUAL bound parameters and compares the verdict to `domain.visibility.scope_visible`. A swapped
resolver, a dropped `scope_id` conjunct, a wrong scope constant and a broken NULL semantic are all
one assertion away from red.

The second thing this file guards is the OPT-IN semantics (`stores.pg.search`'s module docstring):
no `visibility` means the arm issues its pre-D-126 statement, NOT a scoped statement with every
resolver bound to `NULL`. The latter reads as conservative and is a total retrieval outage --
`workers/extractors/base.py` and `workers/distiller.py` hard-code `scope_type=AGENT_TYPE`, so
essentially every retrievable row in a real deployment is agent-type scoped and none of them would
match. Those are rows `scope_visible` accepts and the assembler places; dropping them in SQL is not
a narrowing, it is a regression, and `test_absent_visibility_issues_the_unscoped_statement` is what
would catch it coming back.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Any

import pytest

from tracebed.domain.enums import ScopeType
from tracebed.domain.ids import AgentTypeId, ProjectId
from tracebed.domain.visibility import RunVisibility, scope_visible
from tracebed.stores.pg import search as search_module
from tracebed.stores.pg.search import SearchStore

pytestmark = pytest.mark.phase1

PROJECT = ProjectId(uuid.UUID(int=7))
AGENT = AgentTypeId(uuid.UUID(int=11))
OTHER_AGENT = AgentTypeId(uuid.UUID(int=12))
WORKFLOW = uuid.UUID(int=21)
OTHER_WORKFLOW = uuid.UUID(int=22)
USER = uuid.UUID(int=31)
OTHER_USER = uuid.UUID(int=32)


# --------------------------------------------------------------------------- #
# The fake database — identical technique to tests/phase1/test_search_sql.py.
# --------------------------------------------------------------------------- #


class _FakeCursor:
    def __init__(self, log: list[tuple[str, Any]]) -> None:
        self._log = log

    def execute(self, sql: str, params: Any = None) -> _FakeCursor:
        self._log.append((sql, params))
        return self

    def fetchall(self) -> list[Any]:
        return []

    def __enter__(self) -> _FakeCursor:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class _FakeConnection:
    def __init__(self, log: list[tuple[str, Any]]) -> None:
        self._log = log

    def execute(self, sql: str, params: Any = None) -> _FakeCursor:
        self._log.append((sql, params))
        return _FakeCursor(self._log)

    def cursor(self, *, row_factory: Any = None, name: str | None = None) -> _FakeCursor:
        return _FakeCursor(self._log)

    @contextmanager
    def transaction(self) -> Iterator[_FakeConnection]:
        yield self


class _FakePool:
    def __init__(self) -> None:
        self.log: list[tuple[str, Any]] = []

    @contextmanager
    def connection(self) -> Iterator[_FakeConnection]:
        yield _FakeConnection(self.log)


def _store() -> tuple[SearchStore, _FakePool]:
    pool = _FakePool()
    return SearchStore(pool), pool  # type: ignore[arg-type]


def _memory_item_statements(log: list[tuple[str, Any]]) -> list[tuple[str, Any]]:
    return [(sql, params) for sql, params in log if "FROM memory_item" in sql]


# --------------------------------------------------------------------------- #
# The predicate evaluator — the part of this file that can actually go red.
# --------------------------------------------------------------------------- #

_CONJUNCT = re.compile(r"^\s*(?P<column>[a-z_]+)\s*=\s*%\((?P<param>[a-z_]+)\)s\s*$")


def _evaluate(
    predicate: str, row: Mapping[str, object], params: Mapping[str, object]
) -> bool:
    """Evaluate `_SCOPE_PREDICATE`'s generated text against one row, with SQL NULL semantics.

    The grammar `_scope_predicate` emits is deliberately tiny: an outer parenthesised disjunction
    of branches joined by ` OR `, each branch either a bare `col = %(param)s` comparison or a
    parenthesised conjunction of two of them joined by ` AND `. Nothing here tries to be a SQL
    engine; it implements exactly that grammar and REFUSES anything else, so a future edit that
    writes a cleverer predicate makes this file fail loudly rather than silently evaluating
    something it does not understand into a passing `False`.

    NULL semantics are the point: `x = NULL` is UNKNOWN, never TRUE, in SQL. Modelled as "either
    side is `None` -> this conjunct is false", which is what makes the unresolved
    `workflow_template_id` / `user_scope_id` references fail closed exactly the way
    `domain.visibility.scope_visible`'s `is not None` guards do.
    """
    body = predicate.strip()
    if not (body.startswith("(") and body.endswith(")")):
        raise AssertionError(f"scope predicate is not a parenthesised expression: {predicate!r}")
    body = body[1:-1]
    for branch in body.split(" OR "):
        branch = branch.strip()
        if branch.startswith("(") and branch.endswith(")"):
            branch = branch[1:-1]
        conjuncts = branch.split(" AND ")
        satisfied = True
        for conjunct in conjuncts:
            match = _CONJUNCT.match(conjunct)
            if match is None:
                raise AssertionError(f"unrecognised conjunct in scope predicate: {conjunct!r}")
            column, param = match.group("column"), match.group("param")
            if column not in row:
                raise AssertionError(f"scope predicate reads unknown column {column!r}")
            if param not in params:
                raise AssertionError(f"scope predicate binds unbound parameter {param!r}")
            left, right = row[column], params[param]
            if left is None or right is None or left != right:
                satisfied = False
                break
        if satisfied:
            return True
    return False


_ROWS: tuple[tuple[ScopeType, uuid.UUID | None], ...] = (
    (ScopeType.PROJECT_SHARED, None),
    (ScopeType.AGENT_TYPE, AGENT.value),
    (ScopeType.AGENT_TYPE, OTHER_AGENT.value),
    (ScopeType.AGENT_TYPE, None),
    (ScopeType.WORKFLOW_TEMPLATE, WORKFLOW),
    (ScopeType.WORKFLOW_TEMPLATE, OTHER_WORKFLOW),
    (ScopeType.WORKFLOW_TEMPLATE, None),
    (ScopeType.USER, USER),
    (ScopeType.USER, OTHER_USER),
    (ScopeType.USER, None),
    # A project_shared row carrying a stray scope_id: `NewMemoryItem.__post_init__` forbids it,
    # but the predicate must not depend on that being true of every historical row.
    (ScopeType.PROJECT_SHARED, USER),
)

_VISIBILITIES: tuple[RunVisibility, ...] = (
    RunVisibility(agent_type_id=AGENT),
    RunVisibility(agent_type_id=AGENT, workflow_template_id=WORKFLOW),
    RunVisibility(agent_type_id=AGENT, user_scope_id=USER),
    RunVisibility(agent_type_id=AGENT, workflow_template_id=WORKFLOW, user_scope_id=USER),
    RunVisibility(agent_type_id=OTHER_AGENT, workflow_template_id=OTHER_WORKFLOW,
                  user_scope_id=OTHER_USER),
)


def test_the_generated_sql_predicate_decides_exactly_what_scope_visible_decides() -> None:
    """THE theorem this file exists for: for every row shape and every visibility, the WHERE
    clause `stores.pg.search` actually sends and `domain.visibility.scope_visible` agree.

    Evaluated against the real `_SCOPE_PREDICATE` text and the real `_scope_predicate_params`
    bindings, so there is no hand-written scope-type -> parameter-name table in this test for a
    mutation to stay consistent with.
    """
    for visibility in _VISIBILITIES:
        params = search_module._scope_predicate_params(visibility)
        for scope_type, scope_id in _ROWS:
            row = {"scope_type": scope_type.value, "scope_id": scope_id}
            sql_verdict = _evaluate(search_module._SCOPE_PREDICATE, row, params)
            python_verdict = scope_visible(scope_type, scope_id, visibility)
            assert sql_verdict is python_verdict, (visibility, scope_type, scope_id)


def test_the_evaluator_itself_can_report_false() -> None:
    """A positive control for `_evaluate`. An evaluator that returned `True` unconditionally would
    make the theorem above vacuous, and this repository has shipped exactly that shape of fake
    before (a leak probe whose fake raised unconditionally)."""
    params = search_module._scope_predicate_params(RunVisibility(agent_type_id=AGENT))
    visible = {"scope_type": ScopeType.PROJECT_SHARED.value, "scope_id": None}
    invisible = {"scope_type": ScopeType.USER.value, "scope_id": USER}
    assert _evaluate(search_module._SCOPE_PREDICATE, visible, params) is True
    assert _evaluate(search_module._SCOPE_PREDICATE, invisible, params) is False


def test_the_evaluator_refuses_a_grammar_it_does_not_understand() -> None:
    """`_evaluate` must fail loudly, not quietly return `False`, if the predicate stops being the
    shape it knows how to read -- otherwise a rewritten predicate would turn the theorem above
    into "everything is invisible", which passes nothing and asserts nothing."""
    with pytest.raises(AssertionError, match="not a parenthesised expression"):
        _evaluate("scope_type = %(scope_user)s", {"scope_type": "user"}, {"scope_user": "user"})
    with pytest.raises(AssertionError, match="unrecognised conjunct"):
        _evaluate("(scope_id > %(scope_user)s)", {"scope_id": None}, {"scope_user": "user"})
    with pytest.raises(AssertionError, match="unbound parameter"):
        _evaluate("(scope_type = %(nope)s)", {"scope_type": "user"}, {})
    with pytest.raises(AssertionError, match="unknown column"):
        _evaluate("(nope = %(scope_user)s)", {"scope_type": "user"}, {"scope_user": "user"})


# --------------------------------------------------------------------------- #
# The enum drives the SQL: every ScopeType is handled; an unknown one fails the build.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("scope_type", list(ScopeType))
def test_every_scope_type_member_has_a_fragment(scope_type: ScopeType) -> None:
    """Generated from `ScopeType` itself (not a hand-written list of four cases) — a member
    added to the enum without a matching case in `_scope_fragment` lands here automatically."""
    fragment = search_module._scope_fragment(scope_type, "")
    assert isinstance(fragment, str) and fragment
    assert "scope_type" in fragment


def test_an_unhandled_scope_type_fails_the_build_via_assert_never() -> None:
    """The exhaustiveness guarantee, exercised directly: a value that is not one of the four known
    `ScopeType` members falls through every `case` in `_scope_fragment` to `assert_never`, which
    raises rather than silently matching nothing or matching everything."""
    from typing import cast

    bogus = cast(ScopeType, "not_a_real_scope_type")
    with pytest.raises(AssertionError):
        search_module._scope_fragment(bogus, "")


def test_scope_predicate_is_built_from_iterating_scopetype_not_a_literal_list() -> None:
    """`_SCOPE_PREDICATE` must contain exactly `len(ScopeType)` OR-branches — proof it was
    assembled by walking the enum, so a fifth member automatically gets a fifth branch (or the
    import-time `assert_never` fires) rather than being silently dropped."""
    branch_count = search_module._SCOPE_PREDICATE.count(" OR ") + 1
    assert branch_count == len(list(ScopeType))


def test_every_scope_type_value_appears_as_a_bound_constant() -> None:
    """Each branch compares `scope_type` against a BOUND parameter carrying the enum's own value,
    never an inlined string literal — so the SQL and `ScopeType` cannot drift on spelling."""
    params = search_module._scope_predicate_params(RunVisibility(agent_type_id=AGENT))
    bound_values = {v for k, v in params.items() if k.startswith("scope_")}
    assert bound_values == {st.value for st in ScopeType}


# --------------------------------------------------------------------------- #
# Statement selection: opt-in scoping, and the two statements differ by exactly one line.
# --------------------------------------------------------------------------- #


def test_absent_visibility_issues_the_unscoped_statement() -> None:
    """No `visibility` -> the pre-D-126 statement, with NO scope conjunct and NO `visible_*`
    bindings. The regression this guards is the tempting "fail closed" alternative: applying the
    predicate with every resolver bound to `NULL`, which drops every agent-type-scoped row —
    essentially the whole corpus (`workers/extractors/base.py` hard-codes `AGENT_TYPE`) — and is
    an outage rather than a control."""
    store, pool = _store()
    store.lexical_arm(PROJECT, "retry budget", 10)
    sql, params = _memory_item_statements(pool.log)[0]
    assert "project_id = %(project_id)s" in sql
    assert "status = ANY(%(statuses)s)" in sql
    assert search_module._SCOPE_PREDICATE not in sql
    assert not [k for k in params if k.startswith("visible_") or k.startswith("scope_")]
    assert params["project_id"] == PROJECT


def test_supplied_visibility_issues_the_scoped_statement_with_every_binding() -> None:
    store, pool = _store()
    visibility = RunVisibility(
        agent_type_id=AGENT, workflow_template_id=WORKFLOW, user_scope_id=USER
    )
    store.lexical_arm(PROJECT, "retry budget", 10, visibility=visibility)
    sql, params = _memory_item_statements(pool.log)[0]
    assert "project_id = %(project_id)s" in sql
    assert "status = ANY(%(statuses)s)" in sql
    assert search_module._SCOPE_PREDICATE in sql
    assert params["project_id"] == PROJECT
    assert params["visible_agent_type_id"] == AGENT.value
    assert params["visible_workflow_template_id"] == WORKFLOW
    assert params["visible_user_scope_id"] == USER


def test_a_partially_resolved_visibility_binds_null_for_the_unresolved_references() -> None:
    """`workflow_template_id`/`user_scope_id` are `None` until a resolver exists
    (`domain.visibility`'s own fail-closed note). They must reach the wire as `NULL`, not be
    omitted (which psycopg would reject) and not be silently widened."""
    store, pool = _store()
    store.lexical_arm(PROJECT, "q", 10, visibility=RunVisibility(agent_type_id=AGENT))
    _, params = _memory_item_statements(pool.log)[0]
    assert params["visible_agent_type_id"] == AGENT.value
    assert params["visible_workflow_template_id"] is None
    assert params["visible_user_scope_id"] is None


def test_the_scoped_and_unscoped_statements_differ_by_exactly_the_scope_conjunct() -> None:
    """Both come from ONE template, so they cannot drift on the `project_id` predicate, the
    retrievability predicate, the ORDER BY or the LIMIT. Reconstructing one from the other is the
    assertion that keeps that true after a future edit to either."""
    scoped = search_module._LEXICAL_ARM_SCOPED_SQL
    unscoped = search_module._LEXICAL_ARM_SQL
    stripped = "\n".join(
        line for line in scoped.splitlines() if search_module._SCOPE_PREDICATE not in line
    )
    assert stripped == unscoped
    assert scoped != unscoped


def test_the_vector_arm_is_documented_as_unscoped_and_binds_nothing_scope_shaped() -> None:
    """`vector_arm`'s signature is pinned to three vector-driver methods outside this chunk
    (`tests/phase4/test_vector_drivers.py`), so it cannot take a `RunVisibility`. It must
    therefore NOT carry a scope conjunct it has nothing to bind into — the failure mode that
    would produce is "the ANN arm returns only project_shared rows", i.e. nothing."""
    store, pool = _store()
    store.vector_arm(PROJECT, [0.1, 0.2], 10, hnsw_iterative_scan=True, hnsw_max_scan_tuples=1)
    sql, params = _memory_item_statements(pool.log)[0]
    assert search_module._SCOPE_PREDICATE not in sql
    assert not [k for k in params if k.startswith("visible_") or k.startswith("scope_")]


def test_the_scoped_statement_still_runs_inside_the_rls_guc_transaction() -> None:
    """Invariant 4 for the NEW statement. `tests/phase1/test_search_sql.py`'s GUC-first test walks
    `lexical_arm(PROJECT, "q", 10)` -- the UNSCOPED path -- so the scoped path is a second
    statement it has never seen. A scoped call that ran on a bare `pool.connection()` would keep
    every predicate assertion in this file green while losing the RLS backstop underneath them."""
    store, pool = _store()
    store.lexical_arm(PROJECT, "q", 10, visibility=RunVisibility(agent_type_id=AGENT))
    first_sql, first_params = pool.log[0]
    assert "tracebed.project_id" in first_sql, first_sql
    assert first_params == {"project_id": str(PROJECT)}


def test_no_statement_is_issued_for_a_blank_query_or_empty_embedding() -> None:
    """The "asked for nothing" short circuits both arms already had must still short-circuit with
    the scope wiring in place, not issue a statement that happens to return nothing."""
    store, pool = _store()
    assert store.lexical_arm(PROJECT, "   ", 10) == []
    assert (
        store.lexical_arm(
            PROJECT, "   ", 10, visibility=RunVisibility(agent_type_id=AGENT)
        )
        == []
    )
    assert store.vector_arm(PROJECT, [], 10, hnsw_iterative_scan=True, hnsw_max_scan_tuples=1) == []
    assert pool.log == []


# --------------------------------------------------------------------------- #
# 4. The same predicate, against a real Postgres.
#
# Everything above proves the predicate TEXT decides what `scope_visible` decides. It cannot prove
# Postgres evaluates that text the way `_evaluate` models it -- in particular the NULL semantics
# the unresolved-reference fail-closed behaviour rests on. That needs a database. Skips cleanly
# (never errors at setup) when none is reachable, exactly like every other integration fixture in
# this repository, and skips again if the reachable database lacks the `pg_textsearch`/`pgvector`
# access methods `stores.pg.search`'s statements depend on.
# --------------------------------------------------------------------------- #


@pytest.mark.integration
def test_the_scoped_arm_returns_exactly_what_scope_visible_accepts_on_a_real_database(
    pg: str,
) -> None:
    """One memory per scope shape, then the scoped lexical arm, then the same rows through
    `scope_visible`. The two sets must be equal -- not merely "the SQL returned a subset", which a
    predicate that matched nothing would also satisfy, so the assertion below requires the
    agent-type and project_shared rows to actually come back."""
    import psycopg

    from tracebed.core.scans import ScanContext, scan
    from tracebed.domain.clock import FakeClock
    from tracebed.domain.enums import Lane, MemType, ProvenanceClass, TrustTier
    from tracebed.domain.ids import MemoryId, mint_run_id
    from tracebed.domain.memory import NewMemoryItem, Provenance
    from tracebed.domain.state_machine import Status
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
        visibility = RunVisibility(
            agent_type_id=AGENT, workflow_template_id=WORKFLOW, user_scope_id=USER
        )

        def _insert(scope_type: ScopeType, scope_id: uuid.UUID | None) -> MemoryId:
            content = "retry budget for the flaky tool is three attempts"
            item = NewMemoryItem(
                scope_type=scope_type,
                scope_id=scope_id,
                mem_type=MemType.LESSON,
                kind="k",
                lane=Lane.OPERATIONAL,
                trust_tier=TrustTier.A,
                status=Status.VALIDATED,
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

        planted: dict[MemoryId, tuple[ScopeType, uuid.UUID | None]] = {}
        for scope_type, scope_id in (
            (ScopeType.PROJECT_SHARED, None),
            (ScopeType.AGENT_TYPE, AGENT.value),
            (ScopeType.AGENT_TYPE, OTHER_AGENT.value),
            (ScopeType.WORKFLOW_TEMPLATE, WORKFLOW),
            (ScopeType.WORKFLOW_TEMPLATE, OTHER_WORKFLOW),
            (ScopeType.USER, USER),
            (ScopeType.USER, OTHER_USER),
        ):
            planted[_insert(scope_type, scope_id)] = (scope_type, scope_id)

        search = SearchStore(pool)
        try:
            hits = search.lexical_arm(project_id, "retry budget", 50, visibility=visibility)
        except psycopg.errors.UndefinedFunction as exc:
            pytest.skip(f"pg_textsearch bm25_score()/@@@ unavailable: {exc}")

        returned = {hit.memory_id for hit in hits}
        expected = {
            memory_id
            for memory_id, (scope_type, scope_id) in planted.items()
            if scope_visible(scope_type, scope_id, visibility)
        }
        assert returned == expected
        # A predicate that matched nothing would satisfy `returned <= expected`; this does not.
        assert len(expected) == 4

        # And the unscoped call still sees every planted row, so the difference above is the scope
        # predicate doing work rather than the rows never having been inserted.
        assert {hit.memory_id for hit in search.lexical_arm(project_id, "retry budget", 50)} == set(
            planted
        )
    finally:
        pool.close()
