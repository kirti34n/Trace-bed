"""Offline, database-free proof of the two structural claims `Repo` makes (PHASE-0 Task 7).

There is no Postgres on the build machine, so every assertion here is made against a fake
connection that records the SQL it is handed. That is deliberate and it is not "mocking the thing
under test": the thing under test is *which statements the repository issues, and in what order*.
A fake database is the only way to assert that without a database, and it catches the two classes
of defect that a docstring cannot:

1. **Invariant 4 (PLAN.md §2).** `test_every_partitioned_builder_sets_the_guc_first` drives EVERY
   public `Repo` method and asserts the RLS GUC (`set_config('tracebed.project_id', ...)`) is the
   literal first statement of the transaction, with `REGISTRY_METHODS_WITHOUT_GUC` as the only
   exception. Delete `scoped()` from any one method and this goes red. The companion test asserts
   the *value* bound into the GUC is the project the caller asked for, not some other project.
2. **Invariant 6 (PLAN.md §2).** `test_insert_memory_item_executes_no_sql_when_*` asserts that a
   rejected insert issues *zero* statements -- not merely that an exception escaped. "The row does
   not exist afterward" and "no write was ever attempted" are different guarantees, and only the
   second one survives a future refactor that inserts first and validates later.

Plus `test_typed_ids_are_adaptable_by_psycopg`, which is the offline regression test for a defect
that is invisible without a database and fatal with one: psycopg 3 has no `__conform__` hook, so
binding a `ProjectId` as a query parameter raises `ProgrammingError` unless
`stores.pg.pool.register_typed_id_adapters()` has run.
"""

from __future__ import annotations

import inspect
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import UTC, date, datetime
from typing import Any

import psycopg
import pytest
from psycopg.abc import PyFormat

from tracebed.domain.clock import FakeClock
from tracebed.domain.enums import (
    AdapterClass,
    Arm,
    InstrumentationSource,
    Lane,
    MemType,
    OutcomeCode,
    ProvenanceClass,
    ScopeType,
    Slot,
    TraceOutcomeStatus,
    TrustTier,
)
from tracebed.domain.errors import (
    IllegalTransition,
    NotFound,
    ProvenanceIncomplete,
    ScanVerdictForgery,
)
from tracebed.domain.ids import (
    AgentTypeId,
    MemoryId,
    PrincipalId,
    ProjectId,
    RunId,
    TypedId,
    mint_memory_id,
    mint_run_id,
)
from tracebed.domain.memory import NewMemoryItem, Provenance
from tracebed.domain.state_machine import LEGAL_CREATION_STATUSES, Status
from tracebed.stores.pg import pool as pool_module
from tracebed.stores.pg.repo import (
    MAX_ROW_LIMIT,
    PROPOSAL_CAP_LOCK_CLASS,
    REGISTRY_METHODS_WITHOUT_GUC,
    REGISTRY_METHODS_WITHOUT_PROJECT_ID,
    ProposalCapOutcome,
    Repo,
    ScopedRepo,
)
from tracebed.stores.pg.rows import (
    InjectionRow,
    OutcomeEventInsert,
    RetrievalEventInsert,
    TraceIndexUpsert,
)

pytestmark = pytest.mark.phase0

EPOCH = datetime(2026, 1, 1, tzinfo=UTC)


# --------------------------------------------------------------------------------------- #
# The fake database. Records statements; returns nothing. Every Repo read therefore behaves
# as "no rows", which is exactly the shape we want -- we are asserting on statements issued.
# --------------------------------------------------------------------------------------- #


class _FakeCursor:
    def __init__(self, log: list[tuple[str, Any]], *, name: str | None = None) -> None:
        self._log = log
        self.name = name
        self.itersize = 100

    def execute(self, sql: str, params: Any = None) -> _FakeCursor:
        self._log.append((sql, params))
        return self

    def executemany(self, sql: str, seq: Any) -> None:
        for params in seq:
            self._log.append((sql, params))

    def fetchone(self) -> Any:
        return None

    def fetchall(self) -> list[Any]:
        return []

    def __iter__(self) -> Iterator[Any]:
        return iter(())

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

    def cursor(self, name: str | None = None, **kwargs: Any) -> _FakeCursor:
        return _FakeCursor(self._log, name=name)

    @contextmanager
    def transaction(self) -> Iterator[_FakeConnection]:
        yield self


class _FakePool:
    """Stands in for `psycopg_pool.ConnectionPool`; `scoped()`/`_unscoped()` only ever call
    `.connection()` on it."""

    def __init__(self) -> None:
        self.log: list[tuple[str, Any]] = []

    @contextmanager
    def connection(self) -> Iterator[_FakeConnection]:
        yield _FakeConnection(self.log)


def _repo() -> tuple[Repo, _FakePool]:
    pool = _FakePool()
    return Repo(pool, FakeClock(EPOCH)), pool  # type: ignore[arg-type]


# --------------------------------------------------------------------------------------- #
# A call for every public Repo method. The exhaustiveness assertion below is what makes this
# a gate rather than a sample: a new public method with no entry here fails the suite.
# --------------------------------------------------------------------------------------- #

PROJECT = ProjectId(uuid.UUID("11111111-1111-1111-1111-111111111111"))
OTHER_PROJECT = ProjectId(uuid.UUID("22222222-2222-2222-2222-222222222222"))

# The psycopg named-placeholder form. A statement that does not contain this text cannot be
# using the `project_id` its params dict binds, however faithfully that dict is populated.
_PROJECT_ID_PLACEHOLDER = "%(project_id)s"
PRINCIPAL = PrincipalId(uuid.uuid4())
AGENT_TYPE = AgentTypeId(uuid.uuid4())
RUN = mint_run_id()
MEMORY = mint_memory_id()


def _trace_upsert() -> TraceIndexUpsert:
    return TraceIndexUpsert(
        run_id=RUN,
        agent_type_id=AGENT_TYPE,
        workflow_template_id=None,
        submitter_principal=PRINCIPAL,
        input_signature_hash=b"\x00" * 40,
        instrumentation_source=InstrumentationSource.SDK,
        path=None,
        started_at=EPOCH,
        ended_at=None,
        payload_ref=None,
        outcome_status=TraceOutcomeStatus.PENDING,
    )


def _calls(repo: Repo) -> dict[str, Any]:
    """method name -> a zero-argument callable that exercises it once."""
    return {
        # registry (no GUC)
        "resolve_project": lambda: repo.resolve_project(PRINCIPAL),
        "create_project": lambda: repo.create_project("p"),
        "create_principal": lambda: repo.create_principal("api_key", "ref", "hash"),
        "get_principal_by_external_ref": lambda: repo.get_principal_by_external_ref("ref"),
        "list_project_ids": lambda: repo.list_project_ids(),
        "record_embedding_model": lambda: repo.record_embedding_model("m", "v", 768, "p"),
        "create_agent_type": lambda: repo.create_agent_type(PROJECT, "at"),
        "register_agent": lambda: repo.register_agent(PROJECT, PRINCIPAL, AGENT_TYPE),
        "create_agent_registration": lambda: repo.create_agent_registration(
            PROJECT, "at", "api_key", "ref", "hash"
        ),
        # partitioned (GUC required)
        "tx": lambda: _enter_tx(repo),
        "insert_memory_item": lambda: repo.insert_memory_item(PROJECT, _item(), _verdict()),
        "get_memory_by_id": lambda: repo.get_memory_by_id(PROJECT, MEMORY),
        "count_proposals_in_run": lambda: repo.count_proposals_in_run(PROJECT, RUN),
        "count_proposals_in_project_day": lambda: repo.count_proposals_in_project_day(
            PROJECT, date(2026, 1, 1)
        ),
        "find_proposal_in_run": lambda: repo.find_proposal_in_run(PROJECT, RUN, "ab" * 32),
        "insert_proposal_within_caps": lambda: repo.insert_proposal_within_caps(
            PROJECT,
            RUN,
            _item(provenance=Provenance(cls=ProvenanceClass.PROPOSAL, run_id=RUN)),
            _verdict(),
            per_run_cap=2,
            per_project_daily_cap=50,
            day=date(2026, 1, 1),
        ),
        "list_memories": lambda: repo.list_memories(PROJECT),
        "upsert_trace_index": lambda: repo.upsert_trace_index(PROJECT, _trace_upsert()),
        "get_trace_index": lambda: repo.get_trace_index(PROJECT, RUN),
        "list_runs": lambda: repo.list_runs(PROJECT),
        "find_runs_missing_sentinel": lambda: repo.find_runs_missing_sentinel(PROJECT, EPOCH),
        "mark_run_incomplete": lambda: repo.mark_run_incomplete(PROJECT, RUN),
        "append_trace_subject": lambda: repo.append_trace_subject(PROJECT, RUN, ["user:a"]),
        "insert_outcome_event": lambda: repo.insert_outcome_event(PROJECT, _outcome()),
        "insert_retrieval_event": lambda: repo.insert_retrieval_event(PROJECT, _retrieval()),
        "insert_injection_rows": lambda: repo.insert_injection_rows(
            PROJECT, RUN, [InjectionRow(memory_id=MEMORY, slot=Slot.FACT, score=1.0, tokens=3)]
        ),
        "spend_add": lambda: repo.spend_add(
            PROJECT, date(2026, 1, 1), "w", "m", 1, 2, 0.5
        ),
        "spend_by_day": lambda: repo.spend_by_day(PROJECT, date(2026, 1, 1)),
        "spend_since": lambda: repo.spend_since(PROJECT, date(2026, 1, 1)),
        "get_subject_key": lambda: repo.get_subject_key(PROJECT, "user:a"),
        "insert_subject_key": lambda: repo.insert_subject_key(
            PROJECT, "user:a", uuid.uuid4(), b"kek"
        ),
        "destroy_subject_key": lambda: repo.destroy_subject_key(PROJECT, "user:a"),
        "insert_review_item": lambda: repo.insert_review_item(PROJECT, "reason"),
        "list_review_items": lambda: repo.list_review_items(PROJECT),
        "list_killswitch_state": lambda: repo.list_killswitch_state(PROJECT),
        "insert_invalidation_event": lambda: repo.insert_invalidation_event(PROJECT, "kind"),
        "list_invalidation_events": lambda: repo.list_invalidation_events(PROJECT),
        "get_project_config": lambda: repo.get_project_config(PROJECT),
        "get_agent_type_config": lambda: repo.get_agent_type_config(PROJECT, AGENT_TYPE),
        "get_killswitch_overlay": lambda: repo.get_killswitch_overlay(PROJECT, None),
        "set_project_config": lambda: repo.set_project_config(PROJECT, "k", 1),
        "iter_export_rows": lambda: list(repo.iter_export_rows(PROJECT)),
    }


def _enter_tx(repo: Repo) -> None:
    with repo.tx(PROJECT):
        pass


def _item(*, provenance: Provenance | None = None) -> NewMemoryItem:
    return NewMemoryItem(
        scope_type=ScopeType.PROJECT_SHARED,
        scope_id=None,
        mem_type=MemType.LESSON,
        kind="k",
        lane=Lane.OPERATIONAL,
        trust_tier=TrustTier.A,
        status=Status.CANDIDATE,
        content="retry budget for tool X is three attempts with jittered backoff",
        token_count=11,
        provenance=provenance
        if provenance is not None
        else Provenance(cls=ProvenanceClass.PARSER, trace_ids=(RUN,)),
        id=MEMORY,
    )


def _verdict(content: str | None = None) -> Any:
    """A genuine `ScanVerdict` from the real scan suite (the only legal minting site)."""
    from tracebed.core.scans import ScanContext, scan

    item = _item()
    return scan(
        content if content is not None else item.content,
        context=ScanContext(
            project_id=PROJECT,
            mem_type=item.mem_type,
            trust_tier=item.trust_tier,
            provenance_class=item.provenance.cls,
            lane=Lane.OPERATIONAL,
        ),
    ).verdict()


def _outcome() -> OutcomeEventInsert:
    return OutcomeEventInsert(
        event_id=uuid.uuid4(),
        run_id=RUN,
        principal_id=PRINCIPAL,
        adapter=AdapterClass.VERDICT,
        r=1.0,
        w_zero=False,
        payload={},
        occurred_at=EPOCH,
        arrived_at=EPOCH,
    )


def _retrieval() -> RetrievalEventInsert:
    return RetrievalEventInsert(
        run_id=RUN,
        outcome_code=OutcomeCode.EMPTY_RESULT,
        latency_ms=1,
        embed_latency_ms=None,
        candidates_considered=0,
        top_score=None,
        arm=Arm.MEMORY_ON,
    )


def _public_method_names() -> set[str]:
    return {
        name
        for name, _ in inspect.getmembers(Repo, predicate=inspect.isfunction)
        if not name.startswith("_")
    }


# --------------------------------------------------------------------------------------- #
# Invariant 4
# --------------------------------------------------------------------------------------- #


def test_call_table_covers_every_public_repo_method() -> None:
    """Exhaustiveness gate: a new public builder with no entry in `_calls` would otherwise be
    silently exempt from the GUC assertion below -- which is precisely the method most likely to
    have forgotten `scoped()`.
    """
    repo, _ = _repo()
    assert _public_method_names() == set(_calls(repo))


@pytest.mark.parametrize("method_name", sorted(_public_method_names()))
def test_every_partitioned_builder_sets_the_guc_first(method_name: str) -> None:
    """PLAN.md §2 invariant 4, enforced structurally rather than asserted in prose.

    Mutation this catches: swap any one `scoped(self._pool, project_id)` for `_unscoped(self._pool)`
    and that method's parameterisation goes red. Under RLS FORCE the same mutation returns zero
    rows in production instead of raising, i.e. it is silent data loss on reads and an RLS policy
    violation on writes -- never a visible failure.
    """
    repo, pool = _repo()
    # The fake database returns no rows, so reads legitimately raise NotFound /
    # ScopeResolutionFailed. The assertion is about statements issued, not about outcomes.
    with suppress(Exception):
        _calls(repo)[method_name]()

    guc_statements = [sql for sql, _ in pool.log if "set_config" in sql]

    if method_name in REGISTRY_METHODS_WITHOUT_GUC:
        assert not guc_statements, (
            f"Repo.{method_name} is declared registry-only (unpartitioned tables) but set the "
            "RLS GUC -- either the declaration or the implementation is wrong"
        )
        return

    assert pool.log, f"Repo.{method_name} issued no SQL at all"
    first_sql, first_params = pool.log[0]
    assert "set_config" in first_sql and "tracebed.project_id" in first_sql, (
        f"Repo.{method_name} touches a partitioned table but its transaction's FIRST statement "
        f"was not the RLS GUC; it was: {first_sql.strip()[:120]!r}"
    )
    assert first_params == {"project_id": str(PROJECT)}, (
        f"Repo.{method_name} set the GUC to {first_params!r}, not to the project it was called "
        "for -- the GUC value is what RLS compares every row against"
    )


def test_guc_value_tracks_the_requested_project() -> None:
    """The GUC is not a constant: two different `ProjectId`s produce two different bindings.
    A `scoped()` that stamped a fixed or stale project would pass the ordering assertion above
    while making RLS enforce the wrong wall.
    """
    repo, pool = _repo()
    repo.list_memories(PROJECT)
    repo.list_memories(OTHER_PROJECT)
    bound = [params for sql, params in pool.log if "set_config" in sql]
    assert bound == [{"project_id": str(PROJECT)}, {"project_id": str(OTHER_PROJECT)}]


def test_every_scoped_statement_carries_the_project_id_predicate() -> None:
    """Belt to the GUC's braces: the primary control is the query builder, not RLS (PLAN.md §5
    "Typed repository (primary) ... RLS backstop"). Every non-GUC statement a partitioned-table
    method issues must bind `project_id` itself, so the query is still project-scoped on a
    connection where the GUC was somehow lost.
    """
    repo, _ = _repo()
    calls = _calls(repo)
    offenders: list[str] = []
    for name in sorted(_public_method_names() - REGISTRY_METHODS_WITHOUT_GUC):
        pool = _FakePool()
        scoped_repo = Repo(pool, FakeClock(EPOCH))  # type: ignore[arg-type]
        with suppress(Exception):
            _calls(scoped_repo)[name]()
        # The params dict is deliberately NOT consulted -- that was the defect. Whether a
        # statement is project-scoped is a property of the STATEMENT.
        for sql, _params in pool.log:
            if "set_config" in sql:
                continue
            if _PROJECT_ID_PLACEHOLDER in sql:
                continue
            offenders.append(f"{name}: {sql.strip()[:80]}")
    assert not offenders, f"statements with no project_id predicate: {offenders}"
    assert calls  # the table was actually built


def test_binding_project_id_without_referencing_it_is_not_project_scoping() -> None:
    """The anti-tautology control for the gate above, and the reason that gate was rewritten.

    It used to accept a statement as scoped as soon as its PARAMS dict bound `project_id`,
    without ever checking the SQL referenced the binding -- so deleting a `WHERE project_id =
    %(project_id)s` predicate while leaving the (now unused) parameter in place satisfied the
    control that PLAN.md §5 makes the PRIMARY isolation mechanism, with RLS as the only
    remaining wall. That mutation was applied to `get_killswitch_overlay` and survived the
    whole suite. The check is now the placeholder's presence in the statement text, which is
    the thing that makes the binding load-bearing; this test proves the distinction is real by
    running the old rule and the new rule over the same widened statement.
    """
    widened = "SELECT mem_type, disabled FROM killswitch_state"
    params = {"project_id": PROJECT, "agent_type_id": None}

    assert params.get("project_id") == PROJECT  # the OLD rule accepts it
    assert _PROJECT_ID_PLACEHOLDER not in widened  # the NEW rule refuses it


def test_registry_guc_allowlist_is_a_superset_of_the_signature_allowlist() -> None:
    """The two allowlists answer different questions (first-parameter vs GUC) and must not be
    silently unified: every method exempt from `project_id` is necessarily exempt from the GUC,
    but not vice versa (`create_agent_type` takes a project_id and still skips the GUC).
    """
    assert REGISTRY_METHODS_WITHOUT_PROJECT_ID <= REGISTRY_METHODS_WITHOUT_GUC
    assert {
        "create_agent_type",
        "register_agent",
        "create_agent_registration",
    } == REGISTRY_METHODS_WITHOUT_GUC - REGISTRY_METHODS_WITHOUT_PROJECT_ID
    assert _public_method_names() >= REGISTRY_METHODS_WITHOUT_GUC


# --------------------------------------------------------------------------------------- #
# Invariant 6 -- rejected inserts must not reach the database at all
# --------------------------------------------------------------------------------------- #


def test_insert_memory_item_executes_no_sql_when_provenance_incomplete() -> None:
    """PLAN.md §2 invariant 6. Asserting "no statement was issued" is strictly stronger than
    "the row is absent afterwards": it fails a refactor that writes first and validates later,
    which an after-the-fact row check inside a rolled-back transaction cannot see.
    """
    repo, pool = _repo()
    incomplete = Provenance(cls=ProvenanceClass.PARSER)  # PARSER requires trace_ids
    with pytest.raises(ProvenanceIncomplete):
        repo.insert_memory_item(PROJECT, _item(provenance=incomplete), _verdict())
    assert pool.log == [], f"a rejected insert still issued SQL: {pool.log}"


def test_insert_memory_item_executes_no_sql_when_verdict_is_for_other_content() -> None:
    """Contract §3.7 step 4: a verdict minted for content A must not authorise content B.
    Same "zero statements" standard -- the scan gate has to run before the connection is taken,
    not inside the transaction where a partial write could already have happened.
    """
    repo, pool = _repo()
    foreign_verdict = _verdict("a completely different sentence that was scanned instead")
    with pytest.raises(ScanVerdictForgery):
        repo.insert_memory_item(PROJECT, _item(), foreign_verdict)
    assert pool.log == [], f"a forged-verdict insert still issued SQL: {pool.log}"


def test_insert_memory_item_checks_provenance_before_the_scan_verdict() -> None:
    """Contract §5.1 fixes the order: `validate_provenance` -> `verify_verdict` -> INSERT.
    With BOTH deficient, the provenance error is the one that surfaces; a reordering would
    surface `ScanVerdictForgery` instead and this goes red.
    """
    repo, _ = _repo()
    incomplete = Provenance(cls=ProvenanceClass.PARSER)
    foreign_verdict = _verdict("unrelated scanned content")
    with pytest.raises(ProvenanceIncomplete):
        repo.insert_memory_item(PROJECT, _item(provenance=incomplete), foreign_verdict)


@pytest.mark.parametrize(
    "status",
    sorted(set(Status) - LEGAL_CREATION_STATUSES, key=lambda s: s.value),
)
def test_insert_memory_item_executes_no_sql_for_a_status_that_is_not_creatable(
    status: Status,
) -> None:
    """PLAN.md §2 invariant 7's CREATION half — the door the transition table did not cover.

    `insert_memory_item` used to bind `item.status.value` straight through and the DB CHECK
    admits all nine statuses, so a caller could insert a directly-retrievable `validated` row
    having never called `apply()`. `NewMemoryItem.__post_init__` now refuses to CONSTRUCT one,
    so this test forges the object the way the bypass would have to happen in practice (a
    mutated/rehydrated instance) and asserts the repository refuses it anyway — with zero
    statements issued, the same standard invariant 6 is held to above.

    Parametrised over every non-creation status, generated from the transition table, so a
    new `Status` member is covered the day it is added.
    """
    repo, pool = _repo()
    item = _item()
    object.__setattr__(item, "status", status)  # forged: __post_init__ would have refused
    with pytest.raises(IllegalTransition):
        repo.insert_memory_item(PROJECT, item, _verdict())
    assert pool.log == [], f"an illegal-creation-status insert still issued SQL: {pool.log}"


def test_a_new_memory_item_cannot_even_be_constructed_at_a_non_creation_status() -> None:
    """The type-level half: no repository implementation — Postgres, an offline fake, a
    future driver — can be handed an item whose status is not a `(None, X)` target."""
    with pytest.raises(IllegalTransition):
        NewMemoryItem(
            scope_type=ScopeType.PROJECT_SHARED,
            scope_id=None,
            mem_type=MemType.LESSON,
            kind="k",
            lane=Lane.OPERATIONAL,
            trust_tier=TrustTier.A,
            status=Status.VALIDATED,
            content="a lesson that skipped the state machine",
            token_count=7,
            provenance=Provenance(cls=ProvenanceClass.PARSER, trace_ids=(RUN,)),
        )


def test_insert_memory_item_pins_the_pinned_column_to_status() -> None:
    """`memory_item` carries both `status` and a legacy `pinned boolean` column
    (migrations/0002). They can never disagree: `pinned` is derived, never caller-set.
    """
    repo, pool = _repo()
    repo.insert_memory_item(PROJECT, _item(), _verdict())
    inserts = [p for sql, p in pool.log if "INSERT INTO memory_item" in sql]
    assert len(inserts) == 1
    assert inserts[0]["pinned"] is False
    assert inserts[0]["status"] == Status.CANDIDATE.value


# --------------------------------------------------------------------------------------- #
# psycopg parameter adaptation -- the defect that is invisible without a database
# --------------------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "id_value",
    [
        ProjectId(uuid.uuid4()),
        RunId(uuid.uuid4()),
        MemoryId(uuid.uuid4()),
        PrincipalId(uuid.uuid4()),
        AgentTypeId(uuid.uuid4()),
    ],
    ids=lambda v: type(v).__name__,
)
def test_typed_ids_are_adaptable_by_psycopg(id_value: TypedId) -> None:
    """Every repository query binds domain newtypes directly as parameters. psycopg 3 resolves
    dumpers by MRO lookup and has no `__conform__` hook, so without
    `pool.register_typed_id_adapters()` EVERY query in `repo.py` dies with
    `ProgrammingError: cannot adapt type 'ProjectId'`. With no Postgres on this machine, nothing
    else in Phase 0 can catch that -- this test does, by resolving the dumper directly.
    """
    pool_module.register_typed_id_adapters()
    dumper_cls = psycopg.adapters.get_dumper(type(id_value), PyFormat.AUTO)
    dumped = dumper_cls(type(id_value)).dump(id_value)
    assert dumped is not None
    # Whatever the format, the bytes must encode the wrapped UUID and nothing else.
    assert bytes(dumped) in (id_value.value.bytes, str(id_value.value).encode("ascii"))


def test_typed_id_dumper_declares_the_uuid_oid() -> None:
    """The parameter must arrive typed as `uuid`, not as an untyped literal: every id column in
    migrations/0001-0002 is `uuid`, and an unknown-typed parameter makes Postgres guess.
    """
    pool_module.register_typed_id_adapters()
    dumper_cls = psycopg.adapters.get_dumper(ProjectId, PyFormat.AUTO)
    assert dumper_cls.oid == psycopg.postgres.types["uuid"].oid


# --------------------------------------------------------------------------------------- #
# Filter and bound behaviour that a fail-open bug would hide
# --------------------------------------------------------------------------------------- #


def test_list_memories_with_empty_status_filter_returns_nothing() -> None:
    """`statuses=[]` means "no statuses", not "all statuses". Under the previous truthiness
    check this returned the entire vault -- quarantined and tombstoned rows included -- which is
    a fail-open retrieval filter (PLAN.md §2 invariant 7).
    """
    repo, pool = _repo()
    assert repo.list_memories(PROJECT, statuses=[]) == []
    assert pool.log == [], "an empty status filter still queried the database"


def test_list_memories_status_filter_reaches_the_query() -> None:
    repo, pool = _repo()
    repo.list_memories(PROJECT, statuses=[Status.VALIDATED])
    selects = [(sql, p) for sql, p in pool.log if "FROM memory_item" in sql]
    assert selects, "no memory_item query was issued"
    sql, params = selects[0]
    assert "status = ANY" in sql
    assert params["statuses"] == [Status.VALIDATED.value]


@pytest.mark.parametrize(
    ("requested", "expected"), [(0, 1), (-5, 1), (10, 10), (MAX_ROW_LIMIT + 5000, MAX_ROW_LIMIT)]
)
def test_row_limits_are_clamped(requested: int, expected: int) -> None:
    """A caller-supplied limit is clamped into [1, MAX_ROW_LIMIT]: negative/zero is a SQL error
    and unbounded is an unbounded server-side allocation on a route reachable by any principal.
    """
    repo, pool = _repo()
    repo.list_memories(PROJECT, limit=requested)
    selects = [p for sql, p in pool.log if "FROM memory_item" in sql]
    assert selects[0]["limit"] == expected


def test_find_runs_missing_sentinel_rejects_naive_datetime() -> None:
    """`started_at` is `timestamptz`; a naive bound is silently reinterpreted in the server's
    session timezone, so the sweep window would depend on deployment geography rather than on the
    injected Clock.
    """
    repo, _ = _repo()
    with pytest.raises(ValueError, match="timezone-aware"):
        repo.find_runs_missing_sentinel(PROJECT, datetime(2026, 1, 1))


def test_mark_run_incomplete_only_touches_pending_runs() -> None:
    """The sweeper reads and writes in separate transactions, so a `run_end` can land between
    them. Without the status predicate that race permanently marks a complete run `incomplete`
    and the distiller then refuses it (PLAN.md §3).
    """
    repo, pool = _repo()
    repo.mark_run_incomplete(PROJECT, RUN)
    updates = [(sql, p) for sql, p in pool.log if "UPDATE trace_index" in sql]
    assert updates, "no update was issued"
    sql, params = updates[0]
    assert "outcome_status = %(pending)s" in sql
    assert params["pending"] == TraceOutcomeStatus.PENDING.value


def test_trace_index_upsert_never_regresses_a_finished_run_to_pending() -> None:
    """At-least-once delivery means a partial batch (outcome_status='pending') can arrive after
    `run_end`. Plain `EXCLUDED.outcome_status` un-finished the run, after which the sweeper marks
    it incomplete and the distiller refuses a perfectly complete trace.
    """
    repo, pool = _repo()
    repo.upsert_trace_index(PROJECT, _trace_upsert())
    upserts = [sql for sql, _ in pool.log if "INSERT INTO trace_index" in sql]
    assert upserts, "no upsert was issued"
    body = " ".join(upserts[0].split())
    assert "WHEN EXCLUDED.outcome_status = 'pending' THEN trace_index.outcome_status" in body
    # PLAN.md §10: no caller-supplied arm reaches this column. There is no `%(arm)s`
    # parameter at all; both halves of the upsert read `retrieval_event.arm`, the value the
    # server itself wrote from `hotpath.holdout.assign_arm`.
    assert "%(arm)s" not in body
    assert "SELECT re.arm FROM retrieval_event re" in body
    assert body.rstrip().endswith("), trace_index.arm)")
    # Postgres rejects two assignments to the same column in one DO UPDATE SET with
    # "multiple assignments to same column" -- the CASE rules must REPLACE the plain
    # `EXCLUDED.x` assignments, not sit beside them. Every upsert would fail outright.
    assert "arm = EXCLUDED.arm" not in body
    assert "outcome_status = EXCLUDED.outcome_status," not in body
    set_clause = body.split("DO UPDATE SET", 1)[1]
    assigned = [
        segment.split("=")[0].strip()
        for segment in set_clause.split(",")
        if "=" in segment and segment.split("=")[0].strip().isidentifier()
    ]
    assert len(assigned) == len(set(assigned)), f"duplicate SET targets: {assigned}"
    # And the placeholder substitution actually happened.
    assert "@" not in body


def test_append_trace_subject_deduplicates_caller_supplied_tags() -> None:
    """`subject_tags` comes from a caller-supplied trace payload (C-05); repeating one tag N
    times must not become N statements.
    """
    repo, pool = _repo()
    repo.append_trace_subject(PROJECT, RUN, ["user:a", "user:a", "user:b", "user:a"])
    inserts = [p for sql, p in pool.log if "INSERT INTO trace_subject" in sql]
    assert [p["subject_tag"] for p in inserts] == ["user:a", "user:b"]


def test_memory_queries_do_not_select_star() -> None:
    """`memory_item` carries `embedding halfvec(768)` and `lexemes tsvector` (migrations/0002),
    neither of which appears in `MemoryItemRow`. `SELECT *` decoded multiple kilobytes per row on
    every by-id fetch and bound this module to column order.
    """
    repo, pool = _repo()
    for call in (lambda: repo.get_memory_by_id(PROJECT, MEMORY), lambda: repo.list_memories(PROJECT)):
        with suppress(Exception):
            call()
    for sql, _ in pool.log:
        if "FROM memory_item" in sql:
            assert "SELECT *" not in sql
            assert "embedding" not in sql
            assert "lexemes" not in sql


# --------------------------------------------------------------------------------------- #
# ScopedRepo may not be fabricated
# --------------------------------------------------------------------------------------- #


def test_scoped_repo_cannot_be_constructed_directly() -> None:
    """`ScopedRepo` is exported (it is `Repo.tx`'s declared return type), and an exported class
    with an ordinary `__init__` is a public constructor. Hand-building one lets a caller pair an
    arbitrary connection -- one whose transaction never set the GUC, or one scoped to a different
    project -- with a `project_id` that every method then writes into its SQL.
    """
    repo, pool = _repo()
    with pytest.raises(TypeError, match="not directly constructible"):
        ScopedRepo(repo, _FakeConnection(pool.log), PROJECT)


def test_repo_tx_yields_a_usable_scoped_repo_bound_to_one_transaction() -> None:
    """The legitimate path still works, and reuses the single GUC set at `tx()` entry rather
    than re-scoping per statement (contract §5.0: "one transaction, GUC set once at entry").
    """
    repo, pool = _repo()
    with repo.tx(PROJECT) as tx:
        tx.upsert_trace_index(_trace_upsert())
        tx.append_trace_subject(RUN, ["user:a"])
    guc = [sql for sql, _ in pool.log if "set_config" in sql]
    assert len(guc) == 1, f"expected exactly one GUC statement per tx(), got {len(guc)}"
    assert "set_config" in pool.log[0][0]


# --------------------------------------------------------------------------------------- #
# Behaviour that depends on what the database hands BACK -- a fake that returns canned rows.
# --------------------------------------------------------------------------------------- #


class _RowsCursor(_FakeCursor):
    def __init__(
        self, log: list[tuple[str, Any]], rows: list[Any], *, name: str | None = None
    ) -> None:
        super().__init__(log, name=name)
        self._rows = rows

    def fetchone(self) -> Any:
        return self._rows[0] if self._rows else None

    def fetchall(self) -> list[Any]:
        return list(self._rows)

    def __iter__(self) -> Iterator[Any]:
        return iter(self._rows)


class _RowsConnection(_FakeConnection):
    def __init__(self, log: list[tuple[str, Any]], rows: list[Any]) -> None:
        super().__init__(log)
        self._rows = rows

    def cursor(self, name: str | None = None, **kwargs: Any) -> _FakeCursor:
        return _RowsCursor(self._log, self._rows, name=name)


class _RowsPool(_FakePool):
    def __init__(self, rows: list[Any]) -> None:
        super().__init__()
        self._rows = rows

    @contextmanager
    def connection(self) -> Iterator[_FakeConnection]:
        yield _RowsConnection(self.log, self._rows)


def _repo_returning(rows: list[Any]) -> Repo:
    return Repo(_RowsPool(rows), FakeClock(EPOCH))  # type: ignore[arg-type]


def test_principal_lookup_fails_closed_when_external_ref_is_ambiguous() -> None:
    """`principal` is `UNIQUE (kind, external_ref)` (migrations/0001), not unique on
    `external_ref` alone, but the contract fixes this lookup at a single argument. An IdP-supplied
    `oidc_sub` claim colliding with a server-minted api-key id would otherwise return an arbitrary
    one of two rows -- and the row returned decides `principal_id`, which decides
    `agent_registration`, which decides `project_id`. Returning None denies both identities
    instead of scoping one caller into the other's project (PLAN.md §2 invariant 4).
    """
    both = [
        {
            "principal_id": uuid.uuid4(),
            "kind": "api_key",
            "external_ref": "collide",
            "key_hash": "h",
            "revoked_at": None,
        },
        {
            "principal_id": uuid.uuid4(),
            "kind": "oidc_sub",
            "external_ref": "collide",
            "key_hash": None,
            "revoked_at": None,
        },
    ]
    assert _repo_returning(both).get_principal_by_external_ref("collide") is None

    only_one = [both[0]]
    row = _repo_returning(only_one).get_principal_by_external_ref("collide")
    assert row is not None
    assert row.principal_id == PrincipalId(only_one[0]["principal_id"])


def test_principal_lookup_asks_for_two_rows_so_ambiguity_is_detectable() -> None:
    """A `LIMIT 1` query cannot tell "unique" from "arbitrary pick" -- the second row is the
    evidence, so it has to be fetched.
    """
    repo = _repo_returning([])
    repo.get_principal_by_external_ref("ref")
    sql = next(s for s, _ in repo._pool.log if "FROM principal" in s)  # type: ignore[attr-defined]
    assert "LIMIT 2" in sql


def test_spend_rows_are_plain_floats_not_decimals() -> None:
    """`spend_ledger.cost_usd` is `numeric(14,6)`, which psycopg loads as `Decimal`.
    `SpendRow.cost_usd` is declared `float` and `SpendMeter.check_cap` compares it against a float
    cap -- `Decimal + float` raises TypeError, so the spend cap would crash on the first non-empty
    ledger rather than pausing workers.
    """
    from decimal import Decimal

    repo = _repo_returning(
        [
            {
                "day": date(2026, 1, 1),
                "worker": "distiller",
                "model_id": "gemini-3.1-pro",
                "tokens_in": 10,
                "tokens_out": 20,
                "cost_usd": Decimal("1.250000"),
            }
        ]
    )
    (row,) = repo.spend_by_day(PROJECT, date(2026, 1, 1))
    assert type(row.cost_usd) is float
    assert row.cost_usd == 1.25
    assert row.cost_usd + 0.5 == 1.75  # the operation that used to raise TypeError


def test_destroy_subject_key_preserves_the_first_erasure_timestamp() -> None:
    """`destroyed_at` is the record that an erasure request was honoured, and the row is the only
    place it exists. A retry, a replayed queue item or a double click must not move it forward.
    """
    repo, pool = _repo()
    repo.destroy_subject_key(PROJECT, "user:a")
    sql = next(s for s, _ in pool.log if "UPDATE subject_key" in s)
    assert "COALESCE(destroyed_at" in sql


def test_set_project_config_stamps_updated_at_from_the_injected_clock() -> None:
    """Hard rule 5 / PLAN.md §7 Phase 2's simulated-clock soak: every timestamp Tracebed writes
    must move with `Clock`, not with the database's `now()` default (which also never fires on
    the ON CONFLICT UPDATE path at all).
    """
    repo, pool = _repo()
    repo.set_project_config(PROJECT, "retrieval.total_budget_ms", 250)
    sql, params = next((s, p) for s, p in pool.log if "INTO project_config" in s)
    assert "updated_at = EXCLUDED.updated_at" in sql
    assert params["updated_at"] == EPOCH


def test_export_rows_are_json_serialisable() -> None:
    """`GET /export/project` streams NDJSON from this iterator (contract §9.3). Raw psycopg values
    include `memoryview` for every `bytea` (`trace_index.input_signature_hash` is `bytea NOT
    NULL`), `Decimal` for `numeric` and `datetime`/`UUID` objects -- all of which raise TypeError
    inside `json.dumps`, i.e. the export route would 500 on its first non-empty project.
    """
    import json
    from decimal import Decimal

    repo = _repo_returning(
        [
            {
                "project_id": PROJECT.value,
                "run_id": RUN.value,
                "input_signature_hash": memoryview(b"\x01\x02\x03"),
                "created_at": EPOCH,
                "day": date(2026, 1, 1),
                "cost_usd": Decimal("0.5"),
                "path": {"nested": memoryview(b"\xff")},
                "tags": [uuid.UUID(int=1)],
            }
        ]
    )
    emitted = list(repo.iter_export_rows(PROJECT))
    assert emitted, "no rows were exported"
    json.dumps(emitted)  # must not raise
    row = emitted[0]["row"]
    assert row["input_signature_hash"] == "010203"  # type: ignore[index]
    assert row["path"] == {"nested": "ff"}  # type: ignore[index]


def test_export_uses_a_server_side_cursor() -> None:
    """A client-side cursor materialises the ENTIRE result set before the first `yield`, so
    "streaming" a project export was a full in-RAM copy of every memory_item row, content
    included. The generator shape hid that.
    """
    seen_names: list[str | None] = []

    class _NameSpyConnection(_FakeConnection):
        def cursor(self, name: str | None = None, **kwargs: Any) -> _FakeCursor:
            seen_names.append(name)
            return _FakeCursor(self._log, name=name)

    class _NameSpyPool(_FakePool):
        @contextmanager
        def connection(self) -> Iterator[_FakeConnection]:
            yield _NameSpyConnection(self.log)

    repo = Repo(_NameSpyPool(), FakeClock(EPOCH))  # type: ignore[arg-type]
    list(repo.iter_export_rows(PROJECT))
    assert seen_names, "no cursor was opened"
    assert all(n and n.startswith("tb_export_") for n in seen_names), (
        f"export opened a client-side (unnamed) cursor: {seen_names}"
    )


# --------------------------------------------------------------------------------------- #
# Proposal caps (PLAN.md §6 `proposals.*`; workflow.agent_control's durable half).
#
# The caps are a read-modify-write over durable state. Everything below asserts the two
# properties that make `insert_proposal_within_caps` a cross-PROCESS control rather than a
# restatement of the in-process one: it takes a project-scoped advisory lock BEFORE it
# counts anything, and the counts and the INSERT are in that same transaction.
# --------------------------------------------------------------------------------------- #


class _ScriptedCursor(_FakeCursor):
    """A `_FakeCursor` whose `fetchone` answers from a queue, so a count query can return a
    real number instead of `None`."""

    def __init__(self, log: list[tuple[str, Any]], answers: list[Any], **kwargs: Any) -> None:
        super().__init__(log, **kwargs)
        self._answers = answers

    def fetchone(self) -> Any:
        return self._answers.pop(0) if self._answers else None


class _ScriptedConnection(_FakeConnection):
    def __init__(self, log: list[tuple[str, Any]], answers: list[Any]) -> None:
        super().__init__(log)
        self._answers = answers

    def execute(self, sql: str, params: Any = None) -> _FakeCursor:
        self._log.append((sql, params))
        return _ScriptedCursor(self._log, self._answers)

    def cursor(self, name: str | None = None, **kwargs: Any) -> _FakeCursor:
        return _ScriptedCursor(self._log, self._answers, name=name)


class _ScriptedPool(_FakePool):
    def __init__(self, answers: list[Any]) -> None:
        super().__init__()
        self._answers = answers

    @contextmanager
    def connection(self) -> Iterator[_FakeConnection]:
        yield _ScriptedConnection(self.log, self._answers)


def _scripted_repo(answers: list[Any]) -> tuple[Repo, _ScriptedPool]:
    pool = _ScriptedPool(answers)
    return Repo(pool, FakeClock(EPOCH)), pool  # type: ignore[arg-type]


def _proposal_item() -> NewMemoryItem:
    return _item(provenance=Provenance(cls=ProvenanceClass.PROPOSAL, run_id=RUN))


def _cap_call(repo: Repo, item: NewMemoryItem | None = None, verdict: Any = None) -> Any:
    return repo.insert_proposal_within_caps(
        PROJECT,
        RUN,
        item if item is not None else _proposal_item(),
        verdict if verdict is not None else _verdict(),
        per_run_cap=2,
        per_project_daily_cap=50,
        day=date(2026, 3, 14),
    )


def test_proposal_counts_are_scoped_to_the_project_and_to_the_proposal_class() -> None:
    """A count that forgot either predicate enforces the cap against the wrong population:
    without `project_id` it counts every tenant's proposals (invariant 4); without the
    provenance-class filter it counts every memory in the project, so the cap binds after
    two parser notes and no agent can ever propose anything again."""
    repo, pool = _scripted_repo([(0,)])
    repo.count_proposals_in_run(PROJECT, RUN)
    sql, params = pool.log[-1]
    assert "project_id = %(project_id)s" in sql
    assert "provenance->>'class' = %(provenance_class)s" in sql
    assert "provenance->>'run_id' = %(run_id)s" in sql
    assert params["project_id"] == PROJECT
    assert params["provenance_class"] == ProvenanceClass.PROPOSAL.value
    assert params["run_id"] == str(RUN)


def test_the_daily_cap_uses_an_explicit_utc_range_never_date_of_a_timestamptz() -> None:
    """`DATE(created_at)` on a `timestamptz` renders in the SESSION's TimeZone, so the same
    row falls on different "days" for two connections and a per-UTC-day cap silently becomes
    a per-server-local-day cap. The bounds are computed here, as UTC instants."""
    repo, pool = _scripted_repo([(0,)])
    repo.count_proposals_in_project_day(PROJECT, date(2026, 3, 14))
    sql, params = pool.log[-1]
    assert "date(" not in sql.lower()
    assert "created_at >= %(day_start)s" in sql
    assert "created_at < %(day_end)s" in sql
    assert params["day_start"] == datetime(2026, 3, 14, tzinfo=UTC)
    assert params["day_end"] == datetime(2026, 3, 15, tzinfo=UTC)


def test_a_count_query_that_returns_no_row_raises_instead_of_reading_as_zero() -> None:
    """`count(*)` always returns exactly one row. A `None` means the statement did not run
    as written, and reporting 0 there would read as "no proposals yet" -- i.e. it would OPEN
    the cap, which is the one direction a broken count must never fail in."""
    repo, _ = _scripted_repo([])
    with pytest.raises(NotFound):
        repo.count_proposals_in_run(PROJECT, RUN)


def test_the_cap_transaction_takes_its_advisory_lock_before_it_counts_anything() -> None:
    """The whole point of the method. With the lock taken after the first count -- or not at
    all -- two processes each observe `cap - 1` and each insert, which is exactly the
    cross-process leak the in-process `_cap_lock` cannot close."""
    repo, pool = _scripted_repo([None, (0,), (0,)])
    _cap_call(repo)
    statements = [sql for sql, _ in pool.log]
    guc = next(i for i, s in enumerate(statements) if "set_config" in s)
    lock = next(i for i, s in enumerate(statements) if "pg_advisory_xact_lock" in s)
    counts = [i for i, s in enumerate(statements) if "count(*)" in s]
    inserts = [i for i, s in enumerate(statements) if "INSERT INTO memory_item" in s]
    assert guc < lock, "the RLS GUC must still be the transaction's first statement"
    assert counts and inserts, "the protocol did not run to an insert"
    assert lock < min(counts), "the advisory lock was taken after a count had already read"
    assert lock < min(inserts)
    lock_params = pool.log[lock][1]
    assert lock_params["cls"] == PROPOSAL_CAP_LOCK_CLASS
    assert lock_params["project_id"] == PROJECT


def test_the_cap_check_and_the_insert_are_one_transaction() -> None:
    """Count-then-insert across two transactions is the same race with extra steps: the
    advisory lock is transaction-scoped, so a second transaction for the INSERT would run
    with the lock already released. `scoped()` opens exactly one transaction per entry and
    issues exactly one GUC statement, so one GUC == one transaction."""
    repo, pool = _scripted_repo([None, (0,), (0,)])
    _cap_call(repo)
    assert sum(1 for sql, _ in pool.log if "set_config" in sql) == 1


@pytest.mark.parametrize(
    ("run_count", "day_count", "expected"),
    [
        (2, 0, ProposalCapOutcome.PER_RUN_CAP),
        (0, 50, ProposalCapOutcome.PER_PROJECT_DAILY_CAP),
        (0, 0, ProposalCapOutcome.INSERTED),
    ],
)
def test_each_cap_refuses_at_its_own_boundary_and_writes_no_row(
    run_count: int, day_count: int, expected: ProposalCapOutcome
) -> None:
    repo, pool = _scripted_repo([None, (run_count,), (day_count,)])
    result = _cap_call(repo)
    assert result.outcome is expected
    wrote = any("INSERT INTO memory_item" in sql for sql, _ in pool.log)
    assert wrote is (expected is ProposalCapOutcome.INSERTED)
    if expected is not ProposalCapOutcome.INSERTED:
        assert result.memory_id is None, "a refusal must not name a row that was never written"


def test_a_redelivered_proposal_is_reported_duplicate_and_consumes_no_cap_slot() -> None:
    """The dedup lookup runs BEFORE either count: a redelivery that spent a cap slot would
    let at-least-once delivery silently halve `per_run_cap`."""
    existing = mint_memory_id()
    repo, pool = _scripted_repo([(existing.value,)])
    result = _cap_call(repo)
    assert result.outcome is ProposalCapOutcome.DUPLICATE
    assert result.memory_id == existing
    assert not any("count(*)" in sql for sql, _ in pool.log)
    assert not any("INSERT INTO memory_item" in sql for sql, _ in pool.log)


def test_the_cap_insert_rejects_bad_provenance_before_opening_a_transaction() -> None:
    """Invariant 6 must not have a second door. `insert_proposal_within_caps` writes a
    `memory_item` row, so it runs the same `validate_provenance` -> `verify_verdict` -> INSERT
    order `insert_memory_item` does, and it rejects BEFORE any connection is taken."""
    repo, pool = _scripted_repo([None, (0,), (0,)])
    bad = _item(provenance=Provenance(cls=ProvenanceClass.PARSER))  # PARSER requires trace_ids
    with pytest.raises(ProvenanceIncomplete):
        _cap_call(repo, item=bad)
    assert pool.log == [], "a transaction was opened before provenance was validated"


def test_the_cap_insert_rejects_a_verdict_issued_for_other_content() -> None:
    repo, pool = _scripted_repo([None, (0,), (0,)])
    with pytest.raises(ScanVerdictForgery):
        _cap_call(repo, verdict=_verdict(content="entirely different content"))
    assert pool.log == [], "a transaction was opened before the scan verdict was verified"
