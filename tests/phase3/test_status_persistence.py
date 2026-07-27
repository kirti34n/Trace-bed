"""`stores.pg.lifecycle.LifecycleWriter` — the status-write path (docs/FIDELITY-AUDIT.md M1;
PLAN.md §11 M1).

Offline half: a fake `psycopg_pool.ConnectionPool` that records every statement issued (same
technique as `tests/phase0/test_repo_isolation_offline.py`) with a controllable UPDATE
`rowcount`, so "the row already moved" (optimistic-concurrency loss) is reproducible without a
database. Every assertion that a transition was REFUSED also asserts the statement log is
empty — "no SQL was ever attempted" is a different, stronger guarantee than "an exception was
raised", and only the stronger one survives a future refactor that writes first and validates
second (the exact framing `tests/phase0/test_repo_isolation_offline.py`'s own docstring uses
for the same class of assertion on `insert_memory_item`).

Integration half (`@pytest.mark.integration`): a real round trip against Postgres. Documented
up front, not hidden: it exercises `memory_status_log`, and that table has no per-project
partition until `stores/pg/ddl.py` (out of this chunk's file list — see `lifecycle.py`'s module
docstring) adds it to `PARTITIONED_TABLES`. Until then this test fails against a live database
with "no partition of relation found for row" — a real, disclosed gap, not a bug in this file.
"""

from __future__ import annotations

import itertools
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

import pytest

from tracebed.domain.clock import FakeClock
from tracebed.domain.enums import Lane, MemType, ProvenanceClass, ScopeType, TrustTier
from tracebed.domain.errors import GuardNotSatisfied, IllegalTransition
from tracebed.domain.ids import MemoryId, PrincipalId, ProjectId, mint_memory_id, mint_run_id
from tracebed.domain.state_machine import (
    TRANSITIONS,
    Status,
    TransitionEvidence,
    TransitionLimits,
)
from tracebed.stores.pg.lifecycle import LifecycleWriter, StaleStatusTransition
from tracebed.workers.edit_ops import MemoryStatusWrite

pytestmark = pytest.mark.phase3

EPOCH = datetime(2026, 1, 1, tzinfo=UTC)
PROJECT = ProjectId(uuid.UUID("11111111-1111-1111-1111-111111111111"))
MEMORY = mint_memory_id(now_ms=0)
PRINCIPAL = PrincipalId(uuid.uuid4())

LIMITS = TransitionLimits(
    quarantine_ttl_days=30,
    candidate_ttl_days=45,
    promote_min_outcomes=2,
    failure_lesson_outcomes=1,
    promotion_min_distinct_principals=2,
    retire_q_threshold=0.25,
    retire_min_scored_uses=4,
    retire_min_distinct_principals=3,
    archive_floor=0.15,
)

# Every legal non-creation edge (module docstring: `None -> X` creation edges go through
# `Repo.insert_memory_item`, never this module) -- the "full guard matrix" the task asks for.
_LEGAL_EDGES: tuple[tuple[Status, Status], ...] = tuple(
    (current, target) for (current, target) in TRANSITIONS if current is not None
)


# --------------------------------------------------------------------------------------- #
# Fake database: records every statement; UPDATE rowcount is controllable per test, which is
# the whole mechanism for reproducing optimistic-concurrency loss without a real database.
# --------------------------------------------------------------------------------------- #


class _FakeCursor:
    def __init__(self, sql: str, params: Any, *, rowcount: int) -> None:
        self.sql = sql
        self.params = params
        self.rowcount = rowcount


class _FakeConnection:
    def __init__(self, log: list[tuple[str, Any]], *, update_rowcount: int) -> None:
        self._log = log
        self._update_rowcount = update_rowcount

    def execute(self, sql: str, params: Any = None) -> _FakeCursor:
        self._log.append((sql, params))
        is_update = sql.strip().upper().startswith("UPDATE")
        return _FakeCursor(sql, params, rowcount=self._update_rowcount if is_update else 1)

    @contextmanager
    def transaction(self) -> Iterator[_FakeConnection]:
        yield self


class _FakePool:
    """Stands in for `psycopg_pool.ConnectionPool`; `stores.pg.pool.scoped()` only ever calls
    `.connection()` on it -- identical contract to `test_repo_isolation_offline.py`'s fake."""

    def __init__(self, *, update_rowcount: int = 1) -> None:
        self.log: list[tuple[str, Any]] = []
        self.update_rowcount = update_rowcount

    @contextmanager
    def connection(self) -> Iterator[_FakeConnection]:
        yield _FakeConnection(self.log, update_rowcount=self.update_rowcount)


def _writer(pool: _FakePool, *, clock: FakeClock | None = None) -> LifecycleWriter:
    return LifecycleWriter(pool, clock if clock is not None else FakeClock(EPOCH))  # type: ignore[arg-type]


def _write(
    from_status: Status,
    to_status: Status,
    *,
    now: datetime = EPOCH,
    actor: PrincipalId | None = None,
    memory_id: MemoryId = MEMORY,
) -> MemoryStatusWrite:
    return MemoryStatusWrite(
        memory_id=memory_id, from_status=from_status, to_status=to_status, now=now,
        actor_principal=actor,
    )


# --------------------------------------------------------------------------------------- #
# (a) Structural legality -- the full transition-table matrix.
# --------------------------------------------------------------------------------------- #


@pytest.mark.parametrize(("current", "target"), _LEGAL_EDGES, ids=[f"{c.value}->{t.value}" for c, t in _LEGAL_EDGES])
def test_every_legal_edge_is_persisted(current: Status, target: Status) -> None:
    pool = _FakePool(update_rowcount=1)
    _writer(pool).persist_status(PROJECT, _write(current, target))
    # GUC, UPDATE, INSERT -- exactly three statements, in that order.
    assert len(pool.log) == 3
    assert "set_config" in pool.log[0][0]
    assert pool.log[1][0].strip().upper().startswith("UPDATE")
    assert pool.log[2][0].strip().upper().startswith("INSERT")


_ALL_PAIRS = tuple(itertools.product(Status, Status))
_ILLEGAL_PAIRS = tuple((c, t) for c, t in _ALL_PAIRS if c != t and (c, t) not in _LEGAL_EDGES)


@pytest.mark.parametrize(("current", "target"), _ILLEGAL_PAIRS, ids=[f"{c.value}->{t.value}" for c, t in _ILLEGAL_PAIRS])
def test_every_illegal_edge_is_refused_with_zero_sql(current: Status, target: Status) -> None:
    """The exhaustive complement of the table above -- every `(Status, Status)` pair that is
    NOT a real edge in `TRANSITIONS`, generated as a product rather than hand-listed (the same
    discipline `tests/phase0/test_state_machine.py` uses for `apply()` itself)."""
    pool = _FakePool(update_rowcount=1)
    with pytest.raises(IllegalTransition):
        _writer(pool).persist_status(PROJECT, _write(current, target))
    assert pool.log == []


def test_all_nine_statuses_are_covered_by_the_matrix_above() -> None:
    """Guards the parametrization itself: if a future `Status` member is added and
    `TRANSITIONS` is not updated to match, this notices rather than the matrix silently
    shrinking to fewer than 9*9-9 = 72 pairs."""
    assert len(_ALL_PAIRS) == 81
    assert len(_LEGAL_EDGES) + len(_ILLEGAL_PAIRS) + 9 == 81  # +9 self-pairs, excluded by construction


# --------------------------------------------------------------------------------------- #
# (d) Terminal statuses are terminal.
# --------------------------------------------------------------------------------------- #


@pytest.mark.parametrize("target", [s for s in Status if s is not Status.TOMBSTONED])
def test_tombstoned_has_no_outgoing_edge_to_any_status(target: Status) -> None:
    """Every member of `Status` except TOMBSTONED itself, as the `to_status` off a
    `from_status` of TOMBSTONED -- exhaustive, not a single example."""
    pool = _FakePool(update_rowcount=1)
    with pytest.raises(IllegalTransition):
        _writer(pool).persist_status(PROJECT, _write(Status.TOMBSTONED, target))
    assert pool.log == []


# --------------------------------------------------------------------------------------- #
# (b) Optimistic concurrency.
# --------------------------------------------------------------------------------------- #


def test_update_where_clause_carries_project_memory_and_expected_status_predicates() -> None:
    """The exact WHERE clause the audit requires, asserted as literal SQL text -- this is the
    mutation-check assertion: delete `AND status = %(expected_from)s` from
    `lifecycle._UPDATE_STATUS_SQL` and this test goes red, because the substring this asserts
    on would no longer be present in the statement the fake pool captured."""
    pool = _FakePool(update_rowcount=1)
    _writer(pool).persist_status(PROJECT, _write(Status.CANDIDATE, Status.VALIDATED))
    update_sql, update_params = pool.log[1]
    assert "project_id = %(project_id)s" in update_sql
    assert "id = %(memory_id)s" in update_sql
    assert "status = %(expected_from)s" in update_sql
    assert update_params["project_id"] == PROJECT
    assert update_params["memory_id"] == MEMORY
    assert update_params["expected_from"] == Status.CANDIDATE.value
    assert update_params["to_status"] == Status.VALIDATED.value


def test_zero_rows_updated_raises_stale_status_transition_and_writes_no_history() -> None:
    """Two sweeps racing on the same memory: a concurrent writer already moved `from_status`
    away, so the optimistic-concurrency UPDATE matches zero rows. The history INSERT must
    never run afterward -- a row in `memory_status_log` describing a transition that was
    never actually applied to `memory_item` would be a worse lie than no history at all."""
    pool = _FakePool(update_rowcount=0)
    writer = _writer(pool)
    with pytest.raises(StaleStatusTransition) as exc_info:
        writer.persist_status(PROJECT, _write(Status.CANDIDATE, Status.VALIDATED))
    err = exc_info.value
    assert err.project_id == PROJECT
    assert err.memory_id == MEMORY
    assert err.expected_from is Status.CANDIDATE
    assert err.to is Status.VALIDATED
    # GUC + the UPDATE that matched zero rows -- no INSERT.
    assert len(pool.log) == 2
    assert pool.log[1][0].strip().upper().startswith("UPDATE")


def test_successful_update_persists_status_changed_at_from_write_now_not_the_clock() -> None:
    """Non-negotiable property (c). `write.now` is the caller's own `Clock` read (already
    validated tz-aware by `MemoryStatusWrite.__post_init__`) -- `LifecycleWriter`'s injected
    clock is deliberately never consulted on this path (module docstring): using it instead
    would let `status_changed_at` disagree with the instant `apply()` actually evaluated its
    TTL guards against, which is the exact single-clock-read discipline
    `workers.forensics.Forensics.recall_and_rollback` documents for the same reason."""
    caller_now = datetime(2026, 3, 3, tzinfo=UTC)
    writer_clock = FakeClock(datetime(2099, 1, 1, tzinfo=UTC))  # deliberately far away
    pool = _FakePool(update_rowcount=1)
    _writer(pool, clock=writer_clock).persist_status(
        PROJECT, _write(Status.CANDIDATE, Status.VALIDATED, now=caller_now)
    )
    _, update_params = pool.log[1]
    _, history_params = pool.log[2]
    assert update_params["changed_at"] == caller_now
    assert history_params["changed_at"] == caller_now


# --------------------------------------------------------------------------------------- #
# memory_status_log row content.
# --------------------------------------------------------------------------------------- #


def test_history_row_defaults_when_the_caller_supplies_nothing_extra() -> None:
    """The three real callers today (`workers.edit_ops`, `workers.forensics`,
    `workers.preferences`) never pass `reason`/`evidence`/`epoch_id` -- see `lifecycle.py`'s
    module docstring for why `MemoryStatusWrite` cannot carry them. Defaults must be
    well-formed jsonb/NULL, not merely "whatever json.dumps(None) produces"."""
    pool = _FakePool(update_rowcount=1)
    _writer(pool).persist_status(PROJECT, _write(Status.CANDIDATE, Status.VALIDATED, actor=None))
    _, params = pool.log[2]
    assert params["reason"] == ""
    assert params["actor"] is None
    assert params["epoch_id"] is None
    assert params["evidence"].obj == {}  # psycopg.types.json.Json wraps the dict in .obj


def test_history_row_carries_reason_evidence_epoch_id_and_actor_when_supplied() -> None:
    pool = _FakePool(update_rowcount=1)
    _writer(pool).persist_status(
        PROJECT,
        _write(Status.CANDIDATE, Status.VALIDATED, actor=PRINCIPAL),
        reason="promotion predicate satisfied",
        evidence={"promotion_outcomes": 3},
        epoch_id=7,
    )
    _, params = pool.log[2]
    assert params["reason"] == "promotion predicate satisfied"
    assert params["actor"] == PRINCIPAL
    assert params["epoch_id"] == 7
    assert params["evidence"].obj == {"promotion_outcomes": 3}
    assert params["from_status"] == Status.CANDIDATE.value
    assert params["to_status"] == Status.VALIDATED.value
    assert params["memory_id"] == MEMORY
    assert params["project_id"] == PROJECT


# --------------------------------------------------------------------------------------- #
# Optional full guard reverification (`guard_evidence` + `guard_limits`).
# --------------------------------------------------------------------------------------- #


def _stale_to_validated_evidence(*, reverified: bool) -> TransitionEvidence:
    return TransitionEvidence(
        now=EPOCH,
        provenance_class=ProvenanceClass.DISTILLER,
        trust_tier=TrustTier.B,
        mem_type=MemType.LESSON,
        status_changed_at=EPOCH,
        reverified=reverified,
    )


def test_guard_evidence_and_limits_must_be_supplied_together() -> None:
    pool = _FakePool(update_rowcount=1)
    writer = _writer(pool)
    with pytest.raises(ValueError, match="together"):
        writer.persist_status(
            PROJECT,
            _write(Status.STALE, Status.VALIDATED),
            guard_evidence=_stale_to_validated_evidence(reverified=True),
        )
    with pytest.raises(ValueError, match="together"):
        writer.persist_status(
            PROJECT, _write(Status.STALE, Status.VALIDATED), guard_limits=LIMITS
        )
    assert pool.log == []


def test_guard_reverification_success_persists_the_transition() -> None:
    pool = _FakePool(update_rowcount=1)
    _writer(pool).persist_status(
        PROJECT,
        _write(Status.STALE, Status.VALIDATED),
        guard_evidence=_stale_to_validated_evidence(reverified=True),
        guard_limits=LIMITS,
    )
    assert len(pool.log) == 3


def test_guard_reverification_refusal_issues_zero_sql() -> None:
    """`apply()` itself raises `GuardNotSatisfied` for `stale -> validated` with
    `reverified=False` (the field's default) -- propagated unchanged, before `scoped()` is
    ever entered."""
    pool = _FakePool(update_rowcount=1)
    with pytest.raises(GuardNotSatisfied):
        _writer(pool).persist_status(
            PROJECT,
            _write(Status.STALE, Status.VALIDATED),
            guard_evidence=_stale_to_validated_evidence(reverified=False),
            guard_limits=LIMITS,
        )
    assert pool.log == []


# --------------------------------------------------------------------------------------- #
# Construction-time refusal `MemoryStatusWrite` already provides (defence-in-depth check;
# this module inherits it for free, proven here so a future refactor that stops routing
# through `MemoryStatusWrite` notices).
# --------------------------------------------------------------------------------------- #


def test_memory_status_write_rejects_a_self_transition_before_reaching_this_module() -> None:
    with pytest.raises(ValueError, match="not a transition"):
        MemoryStatusWrite(memory_id=MEMORY, from_status=Status.VALIDATED, to_status=Status.VALIDATED, now=EPOCH)


# --------------------------------------------------------------------------------------- #
# Integration: the real round trip (module docstring -- expected to fail today on the
# documented, disclosed ddl.py gap; skips cleanly with no Postgres, per every other
# integration test in this repository).
# --------------------------------------------------------------------------------------- #


@pytest.mark.integration
def test_persist_status_round_trip_against_postgres(pg: str) -> None:
    from tracebed.domain.memory import NewMemoryItem, Provenance
    from tracebed.domain.scan import ScanVerdict
    from tracebed.stores.pg.migrate import apply_migrations
    from tracebed.stores.pg.pool import create_pool
    from tracebed.stores.pg.repo import Repo

    apply_migrations(pg)
    pool = create_pool(pg)
    clock = FakeClock(EPOCH)
    repo = Repo(pool, clock)
    writer = LifecycleWriter(pool, clock)

    project_id = repo.create_project(f"lifecycle-writer-it-{uuid.uuid4().hex[:8]}")
    from tracebed.stores.pg.partitions import create_project_partitions

    with pool.connection() as conn:
        create_project_partitions(conn, project_id)

    item = NewMemoryItem(
        scope_type=ScopeType.PROJECT_SHARED,
        scope_id=None,
        mem_type=MemType.LESSON,
        kind="tool_failure",
        lane=Lane.OPERATIONAL,
        trust_tier=TrustTier.A,
        status=Status.CANDIDATE,
        content="integration-test content",
        token_count=4,
        provenance=Provenance(cls=ProvenanceClass.PARSER, trace_ids=(mint_run_id(),)),
    )
    from tracebed.core.scans import scan
    from tracebed.domain.scan import ScanContext

    verdict: ScanVerdict = scan(
        item.content,
        context=ScanContext(
            project_id=project_id,
            mem_type=item.mem_type,
            trust_tier=item.trust_tier,
            provenance_class=item.provenance.cls,
            lane=item.lane,
        ),
    ).verdict(clock=clock)
    memory_id = repo.insert_memory_item(project_id, item, verdict)

    # NOTE (disclosed, see module docstring): fails here with "no partition of relation
    # memory_status_log found for row" until stores/pg/ddl.py adds this table to
    # PARTITIONED_TABLES -- a real, reported cross-chunk gap, not a defect in this test.
    writer.persist_status(
        project_id,
        MemoryStatusWrite(
            memory_id=memory_id, from_status=Status.CANDIDATE, to_status=Status.VALIDATED, now=clock.now()
        ),
    )

    row = repo.get_memory_by_id(project_id, memory_id)
    assert row.status is Status.VALIDATED

    with pytest.raises(StaleStatusTransition):
        writer.persist_status(
            project_id,
            MemoryStatusWrite(
                memory_id=memory_id, from_status=Status.CANDIDATE, to_status=Status.VALIDATED, now=clock.now()
            ),
        )
