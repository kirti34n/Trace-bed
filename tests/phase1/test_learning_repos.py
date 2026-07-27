"""`stores.pg.learning` — the two Postgres worker-port implementations that closed
FIDELITY-AUDIT.md M6/M8's store half.

OFFLINE (runs everywhere, no database): every assertion about *which* SQL is issued is made
against the same recording fake `tests/phase1/test_search_sql.py` and
`tests/phase0/test_repo_isolation_offline.py` use, for the reason PLAN.md §7 states — "an
offline test that parses the generated SQL and asserts the status predicate and the project_id
predicate are both present in every query ... dropping either is a silent leak". The
environment rule this repository is written under adds one clause on top of that: a new SQL
statement that cannot be executed here still gets a structural test asserting the project
predicate and the RLS GUC are present. Both are asserted below, for all four statements.

INTEGRATION (`@pytest.mark.integration`): executes each statement against a real Postgres and
asserts the behaviour the offline tests can only assert the SHAPE of — that the embedding
predicate really re-selects a row after a pin change, that the append really is idempotent, and
that a second project's rows are really invisible. Skips cleanly through the shared `pg`
fixture when no database is reachable, which is the case on this build machine.

WHAT THE OFFLINE HALF CANNOT PROVE, stated rather than implied: a fake cursor does not evaluate
`WHERE`. Every offline assertion here is about statement text and bound parameters. The claim
"a quarantined row is never returned" is proven offline only in the sense that the conjunct is
present and bound correctly; it is proven as behaviour only by the integration tests, which
have not run on this machine.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest

from tracebed.domain.enums import ProvenanceClass
from tracebed.domain.errors import TracebedError
from tracebed.domain.ids import MemoryId, ProjectId, RunId, mint_run_id
from tracebed.domain.memory import Provenance
from tracebed.domain.state_machine import RETRIEVABLE_STATUSES, Status
from tracebed.stores.pg import learning as learning_module
from tracebed.stores.pg.learning import CorroborationRepo, EmbeddingRepo
from tracebed.workers.corroboration import (
    AppendOutcome,
    CorroborationRepoPort,
    QuarantinedMemoryForCorroboration,
)
from tracebed.workers.embedder import EmbeddingCandidateRow, EmbeddingRepoPort

pytestmark = pytest.mark.phase1

PROJECT = ProjectId(uuid.UUID(int=7))
OTHER_PROJECT = ProjectId(uuid.UUID(int=8))
MEMORY = MemoryId(uuid.UUID(int=11))

# `stores.pg.pool.scoped` issues this as the first statement of every transaction. Asserting on
# the substring rather than importing the private constant keeps the test honest about what a
# reader of the query log would see.
_GUC_FRAGMENT = "tracebed.project_id"


# --------------------------------------------------------------------------- #
# Recording fake (same shape as tests/phase1/test_search_sql.py's).
# --------------------------------------------------------------------------- #


class _FakeCursor:
    def __init__(self, log: list[tuple[str, Any]], rows: list[Any]) -> None:
        self._log = log
        self._rows = rows

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
    def __init__(self, log: list[tuple[str, Any]], rows: list[Any]) -> None:
        self._log = log
        self._rows = rows

    def execute(self, sql: str, params: Any = None) -> _FakeCursor:
        self._log.append((sql, params))
        return _FakeCursor(self._log, [])

    def cursor(self, *, row_factory: Any = None, name: str | None = None) -> _FakeCursor:
        del row_factory, name
        return _FakeCursor(self._log, self._rows)

    @contextmanager
    def transaction(self) -> Iterator[_FakeConnection]:
        yield self


class _FakePool:
    def __init__(self, rows: list[Any] | None = None) -> None:
        self.log: list[tuple[str, Any]] = []
        self._rows = rows if rows is not None else []

    @contextmanager
    def connection(self) -> Iterator[_FakeConnection]:
        yield _FakeConnection(self.log, self._rows)


def _embedding_repo(rows: list[Any] | None = None) -> tuple[EmbeddingRepo, _FakePool]:
    pool = _FakePool(rows)
    return EmbeddingRepo(pool), pool  # type: ignore[arg-type]


def _corroboration_repo(rows: list[Any] | None = None) -> tuple[CorroborationRepo, _FakePool]:
    pool = _FakePool(rows)
    return CorroborationRepo(pool), pool  # type: ignore[arg-type]


def _memory_statements(log: list[tuple[str, Any]]) -> list[tuple[str, Any]]:
    return [(sql, params) for sql, params in log if "memory_item" in sql]


# --------------------------------------------------------------------------- #
# The ports actually have implementations now (M3/M6/M8's whole point).
# --------------------------------------------------------------------------- #


def test_both_classes_satisfy_the_worker_protocols_they_were_written_for() -> None:
    """The audit's M3 is "no Postgres implementation for the worker ports". `isinstance`
    against the `runtime_checkable` Protocol is what makes that claim falsifiable: a signature
    drift on either side turns this red instead of turning a deployment into a `TypeError`."""
    assert isinstance(EmbeddingRepo(_FakePool()), EmbeddingRepoPort)  # type: ignore[arg-type]
    assert isinstance(CorroborationRepo(_FakePool()), CorroborationRepoPort)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Invariant 4: the project predicate AND the RLS GUC, on every statement.
# --------------------------------------------------------------------------- #


def test_select_needing_embedding_carries_the_project_predicate_and_the_guc() -> None:
    repo, pool = _embedding_repo()
    repo.select_needing_embedding(PROJECT, model_id="m", model_version="v", limit=5)

    guc_statements = [sql for sql, _ in pool.log if _GUC_FRAGMENT in sql]
    assert guc_statements, "no RLS GUC statement was issued for this transaction"
    statements = _memory_statements(pool.log)
    assert statements
    sql, params = statements[0]
    assert "project_id = %(project_id)s" in sql
    assert params["project_id"] == PROJECT
    # The GUC must be FIRST -- a predicate-less future edit would otherwise run unprotected.
    assert pool.log[0][0] is not sql or _GUC_FRAGMENT in pool.log[0][0]
    assert _GUC_FRAGMENT in pool.log[0][0]


def test_write_embedding_carries_the_project_predicate_and_the_guc() -> None:
    repo, pool = _embedding_repo()
    repo.write_embedding(PROJECT, MEMORY, [0.1, 0.2], model_id="m", model_version="v")

    assert _GUC_FRAGMENT in pool.log[0][0]
    statements = _memory_statements(pool.log)
    assert statements
    sql, params = statements[0]
    assert "project_id = %(project_id)s" in sql
    assert "id = %(memory_id)s" in sql
    assert params["project_id"] == PROJECT
    assert params["memory_id"] == MEMORY


def test_select_quarantined_carries_the_project_predicate_and_the_guc() -> None:
    repo, pool = _corroboration_repo()
    repo.select_quarantined(PROJECT)

    assert _GUC_FRAGMENT in pool.log[0][0]
    sql, params = _memory_statements(pool.log)[0]
    assert "project_id = %(project_id)s" in sql
    assert params["project_id"] == PROJECT
    assert params["quarantined"] == Status.QUARANTINED.value


def test_append_confirming_run_carries_the_project_predicate_on_both_halves() -> None:
    """The append reaches `memory_item` twice — once to lock, once to update — and invariant 4
    is not weakened by the second reach. Counting the occurrences, not merely asserting one, is
    what would catch an edit that dropped the predicate from the `UPDATE` while leaving it on
    the `SELECT ... FOR NO KEY UPDATE`."""
    repo, pool = _corroboration_repo(
        [{"appended": True, "already_present": False, "eligible": True}]
    )
    repo.append_confirming_run(PROJECT, MEMORY, mint_run_id())

    assert _GUC_FRAGMENT in pool.log[0][0]
    sql, params = _memory_statements(pool.log)[0]
    assert sql.count("project_id = %(project_id)s") == 2, sql
    assert "FOR NO KEY UPDATE" in sql
    assert params["project_id"] == PROJECT


# --------------------------------------------------------------------------- #
# The predicates themselves.
# --------------------------------------------------------------------------- #


def test_the_embedding_predicate_is_the_one_the_port_contracts_for() -> None:
    """`workers.embedder.EmbeddingRepoPort.select_needing_embedding` states the predicate in
    prose; this asserts the statement implements exactly it, including the three-way OR that
    makes both idempotent re-runs and a pin-change migration fall out of one query."""
    repo, pool = _embedding_repo()
    repo.select_needing_embedding(PROJECT, model_id="mm", model_version="vv", limit=5)
    sql, params = _memory_statements(pool.log)[0]

    assert "status = ANY(%(statuses)s)" in sql
    assert "embedding IS NULL" in sql
    assert "embedding_model_id <> %(model_id)s" in sql
    assert "embedding_model_version <> %(model_version)s" in sql
    assert "ORDER BY id" in sql
    assert params["model_id"] == "mm"
    assert params["model_version"] == "vv"
    assert params["limit"] == 5


def test_the_bound_statuses_are_derived_from_the_domain_constant_not_retyped() -> None:
    """A re-listed copy of the retrievable set in SQL is the D-118 defect (two authors for one
    governing definition). Mutating `RETRIEVABLE_STATUSES` must move this binding."""
    repo, pool = _embedding_repo()
    repo.select_needing_embedding(PROJECT, model_id="m", model_version="v", limit=1)
    _, params = _memory_statements(pool.log)[0]
    assert set(params["statuses"]) == {status.value for status in RETRIEVABLE_STATUSES}


def test_write_embedding_touches_exactly_three_columns_in_one_statement() -> None:
    """Hard rule 5 at the store layer, and the port's own atomicity requirement: split across
    two statements a crash between them leaves a row stamped with the new pin holding the old
    vector, which the re-embed predicate then treats as done forever. Also asserts no status
    column is assigned — this writer must not be a second way to move a memory."""
    repo, pool = _embedding_repo()
    repo.write_embedding(PROJECT, MEMORY, [0.5], model_id="m", model_version="v")
    updates = [sql for sql, _ in pool.log if sql.strip().upper().startswith("UPDATE")]
    assert len(updates) == 1, updates
    sql = updates[0]
    assert "SET embedding = %(embedding)s::halfvec" in sql
    assert "embedding_model_id = %(model_id)s" in sql
    assert "embedding_model_version = %(model_version)s" in sql
    assert "status" not in sql
    assert "q_value" not in sql


def test_the_append_statement_matches_the_shape_the_port_docstring_prescribes() -> None:
    """The port docstring IS the specification (D-125 rewrote it precisely because the previous
    bare-`UPDATE` form could not report three outcomes). A statement that drifts from it
    silently reintroduces the ambiguity between "already present" and "the row left
    quarantine"."""
    sql = learning_module._APPEND_CONFIRMING_RUN_SQL
    for fragment in (
        "FOR NO KEY UPDATE",
        "array_append(m.shadow_confirm_runs, %(run_id)s)",
        "NOT (%(run_id)s = ANY(l.shadow_confirm_runs))",
        "AS appended",
        "AS already_present",
        "AS eligible",
    ):
        assert fragment in sql, fragment
    assert "SET status" not in sql, "recording evidence is not a transition (hard rule 5)"


def test_write_embedding_refuses_an_empty_vector_before_issuing_anything() -> None:
    repo, pool = _embedding_repo()
    with pytest.raises(ValueError, match="must not be empty"):
        repo.write_embedding(PROJECT, MEMORY, [], model_id="m", model_version="v")
    assert pool.log == [], "a refused write must issue no SQL at all"


def test_select_needing_embedding_refuses_a_non_positive_limit_before_issuing_anything() -> None:
    repo, pool = _embedding_repo()
    with pytest.raises(ValueError, match="limit must be positive"):
        repo.select_needing_embedding(PROJECT, model_id="m", model_version="v", limit=0)
    assert pool.log == []


# --------------------------------------------------------------------------- #
# Row parsing: the assertion that the predicate held.
# --------------------------------------------------------------------------- #


def test_a_non_retrievable_row_coming_back_is_refused_rather_than_embedded() -> None:
    """The SQL predicate is the control; this is the assertion the control held (the same
    discipline `stores.pg.search._row_to_arm_hit` applies on the read side). A repository whose
    status conjunct was lost by an edit must fail loudly on its first sweep, not silently put a
    vector for quarantined content within an ANN scan's reach."""
    repo, _ = _embedding_repo(
        [
            {
                "id": MEMORY.value,
                "project_id": PROJECT.value,
                "status": Status.QUARANTINED.value,
                "content": "secret",
            }
        ]
    )
    with pytest.raises(TracebedError, match="non-retrievable status"):
        repo.select_needing_embedding(PROJECT, model_id="m", model_version="v", limit=5)


def test_a_non_quarantined_row_coming_back_from_select_quarantined_is_refused() -> None:
    repo, _ = _corroboration_repo(
        [
            {
                "id": MEMORY.value,
                "project_id": PROJECT.value,
                "status": Status.VALIDATED.value,
                "provenance": {"class": ProvenanceClass.DISTILLER.value},
                "shadow_confirm_runs": [],
            }
        ]
    )
    with pytest.raises(TracebedError, match="status conjunct"):
        repo.select_quarantined(PROJECT)


def test_a_retrievable_row_parses_into_the_workers_own_projection_type() -> None:
    repo, _ = _embedding_repo(
        [
            {
                "id": MEMORY.value,
                "project_id": PROJECT.value,
                "status": Status.VALIDATED.value,
                "content": "retry with jittered backoff",
            }
        ]
    )
    rows = repo.select_needing_embedding(PROJECT, model_id="m", model_version="v", limit=5)
    assert rows == [
        EmbeddingCandidateRow(
            project_id=PROJECT,
            id=MEMORY,
            status=Status.VALIDATED,
            content="retry with jittered backoff",
        )
    ]


def test_a_quarantined_row_parses_with_its_provenance_and_confirmations() -> None:
    run = mint_run_id()
    already = mint_run_id()
    repo, _ = _corroboration_repo(
        [
            {
                "id": MEMORY.value,
                "project_id": PROJECT.value,
                "status": Status.QUARANTINED.value,
                "provenance": Provenance(
                    cls=ProvenanceClass.DISTILLER, trace_ids=(run,)
                ).to_json(),
                "shadow_confirm_runs": [already.value],
            }
        ]
    )
    rows = repo.select_quarantined(PROJECT)
    assert rows == [
        QuarantinedMemoryForCorroboration(
            id=MEMORY,
            project_id=PROJECT,
            status=Status.QUARANTINED,
            provenance=Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(run,)),
            confirming_run_ids=(already,),
        )
    ]


# --------------------------------------------------------------------------- #
# The three-valued outcome mapping.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("row", "expected"),
    [
        ({"appended": True, "already_present": False, "eligible": True}, AppendOutcome.APPENDED),
        (
            {"appended": False, "already_present": True, "eligible": True},
            AppendOutcome.ALREADY_PRESENT,
        ),
        (
            {"appended": False, "already_present": False, "eligible": False},
            AppendOutcome.ROW_NOT_ELIGIBLE,
        ),
        (
            # A row that left quarantine while already carrying the run. `eligible` is checked
            # before `already_present` on purpose: the memory received nothing from this call
            # and never will, so reporting a write would be the lie D-125 exists to prevent.
            {"appended": False, "already_present": True, "eligible": False},
            AppendOutcome.ROW_NOT_ELIGIBLE,
        ),
        (None, AppendOutcome.ROW_NOT_ELIGIBLE),
    ],
)
def test_every_statement_result_maps_to_exactly_one_outcome(
    row: dict[str, bool] | None, expected: AppendOutcome
) -> None:
    repo, _ = _corroboration_repo([row] if row is not None else [])
    assert repo.append_confirming_run(PROJECT, MEMORY, mint_run_id()) is expected


def test_an_impossible_statement_result_raises_rather_than_guessing() -> None:
    """Eligible, not already present, nothing appended — the `updated` CTE's own two conjuncts
    both held and it still returned no row. Unreachable while the statement and the mapping
    agree; if they ever stop agreeing, every one of the three answers would be a guess about a
    governance write, so none is given."""
    repo, _ = _corroboration_repo(
        [{"appended": False, "already_present": False, "eligible": True}]
    )
    with pytest.raises(TracebedError, match="diverged"):
        repo.append_confirming_run(PROJECT, MEMORY, mint_run_id())


# --------------------------------------------------------------------------- #
# MemoryEditRepo / ForensicsRepo -- the two ports whose only implementations
# were three test fakes (FIDELITY-AUDIT.md M1/M3).
# --------------------------------------------------------------------------- #


class _RecordingLifecycle:
    """Stands in for `LifecycleWriter` so the delegation is observable.

    Observable is the point: a `persist_status` that quietly did nothing would satisfy the
    Protocol, satisfy mypy, and re-open M1 in full -- verified by mutation, which is why these
    tests exist. The real `LifecycleWriter` has its own suite in
    `tests/phase3/test_status_persistence.py`.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[ProjectId, object]] = []

    def persist_status(self, project_id: ProjectId, write: object) -> None:
        self.calls.append((project_id, write))


class _StubRepo:
    def __init__(self, row: object | None = None) -> None:
        self.row = row
        self.get_calls: list[tuple[ProjectId, MemoryId]] = []
        self.insert_calls: list[ProjectId] = []

    def get_memory_by_id(self, project_id: ProjectId, memory_id: MemoryId) -> object:
        self.get_calls.append((project_id, memory_id))
        assert self.row is not None
        return self.row

    def insert_memory_item(
        self, project_id: ProjectId, item: object, verdict: object
    ) -> MemoryId:
        del item, verdict
        self.insert_calls.append(project_id)
        return MEMORY


def _memory_item_row() -> Any:
    from datetime import UTC, datetime

    from tracebed.domain.enums import Lane, MemType, ScopeType, TrustTier
    from tracebed.stores.pg.rows import MemoryItemRow

    return MemoryItemRow(
        id=MEMORY,
        project_id=PROJECT,
        scope_type=ScopeType.PROJECT_SHARED,
        scope_id=None,
        mem_type=MemType.LESSON,
        kind="k",
        lane=Lane.QUALITY,
        trust_tier=TrustTier.B,
        status=Status.VALIDATED,
        content="c",
        content_hash="h",
        token_count=1,
        subject_tag="subject-42",
        q_value=0.5,
        confidence=0.0,
        scored_use_count=0,
        strike_count=0,
        provenance=Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(mint_run_id(),)),
        scan_verdict_id=uuid.uuid4(),
        schema_version=1,
        created_at=datetime(2026, 7, 27, tzinfo=UTC),
        status_changed_at=datetime(2026, 7, 27, tzinfo=UTC),
    )


def _edit_repo(
    rows: list[Any] | None = None,
) -> tuple[Any, _FakePool, _RecordingLifecycle, _StubRepo]:
    from tracebed.stores.pg.lifecycle import MemoryEditRepo

    pool = _FakePool(rows)
    lifecycle = _RecordingLifecycle()
    repo = _StubRepo(_memory_item_row())
    return MemoryEditRepo(pool, repo, lifecycle), pool, lifecycle, repo  # type: ignore[arg-type]


def test_the_edit_and_forensics_repos_satisfy_the_worker_protocols() -> None:
    """M1's real closure: `persist_status`'s only implementations were three test fakes
    (`tests/phase3/test_edit_ops.py`, `test_forensics.py`, `tests/phase4/test_preferences.py`).
    These two classes are the first production ones."""
    from tracebed.stores.pg.lifecycle import ForensicsRepo
    from tracebed.workers.edit_ops import MemoryEditRepoPort
    from tracebed.workers.forensics import ForensicsRepoPort

    edit, _, _, _ = _edit_repo()
    assert isinstance(edit, MemoryEditRepoPort)
    forensics = ForensicsRepo(_FakePool(), _StubRepo(), _RecordingLifecycle())  # type: ignore[arg-type]
    assert isinstance(forensics, ForensicsRepoPort)


def test_persist_status_is_delegated_to_the_one_status_writer() -> None:
    """Hard rule 5 at the store layer. A `MemoryEditRepo` that wrote its own `UPDATE ... SET
    status` would be a SECOND way to move a memory, which is the admin bypass PLAN.md section
    10 forbids wearing a repository's clothes -- and one that did NOTHING would re-open M1 in
    full while every Protocol check still passed."""
    from datetime import UTC, datetime

    from tracebed.workers.edit_ops import MemoryStatusWrite

    edit, pool, lifecycle, _ = _edit_repo()
    write = MemoryStatusWrite(
        memory_id=MEMORY,
        from_status=Status.VALIDATED,
        to_status=Status.STALE,
        now=datetime(2026, 7, 27, tzinfo=UTC),
    )
    edit.persist_status(PROJECT, write)
    assert lifecycle.calls == [(PROJECT, write)]
    assert pool.log == [], "MemoryEditRepo must issue no status SQL of its own"


def test_forensics_persist_status_is_delegated_too() -> None:
    """The second caller of the same seam. `workers.forensics` quarantines a memory and every
    descendant it finds, so a no-op here is a Recall & Rollback that reports a blast radius and
    contains nothing."""
    from datetime import UTC, datetime

    from tracebed.stores.pg.lifecycle import ForensicsRepo
    from tracebed.workers.edit_ops import MemoryStatusWrite

    lifecycle = _RecordingLifecycle()
    pool = _FakePool()
    repo = ForensicsRepo(pool, _StubRepo(_memory_item_row()), lifecycle)  # type: ignore[arg-type]
    write = MemoryStatusWrite(
        memory_id=MEMORY,
        from_status=Status.VALIDATED,
        to_status=Status.STALE,
        now=datetime(2026, 7, 27, tzinfo=UTC),
    )
    repo.persist_status(PROJECT, write)
    assert lifecycle.calls == [(PROJECT, write)]
    assert pool.log == []


def test_exactly_one_status_writing_statement_exists_in_the_lifecycle_module() -> None:
    """The whole-module version of the same rule: one `SET status`, and it is
    `LifecycleWriter`'s."""
    import pathlib

    from tracebed.stores.pg import lifecycle as lifecycle_module

    source = pathlib.Path(lifecycle_module.__file__ or "").read_text(encoding="utf-8")
    # The bound-parameter form, not the bare words: two docstrings in this module quote
    # "UPDATE memory_item SET status = ..." while explaining why they must not contain one, and
    # a check that cannot tell prose from a statement is a check that fails for the wrong
    # reason (or, worse, passes for one).
    assert source.count("SET status = %(to_status)s") == 1, (
        "a second status-writing statement has appeared in stores/pg/lifecycle.py"
    )
    # And nowhere else in stores/pg/ either -- the whole of M1's closure is that there is ONE.
    import pathlib as _pathlib

    package = _pathlib.Path(lifecycle_module.__file__ or "").parent
    writers = [
        path.name
        for path in package.glob("*.py")
        if "SET status = %(to_status)s" in path.read_text(encoding="utf-8")
    ]
    assert writers == ["lifecycle.py"], writers


def test_get_memory_by_id_is_a_projection_over_the_real_repo_not_a_new_query() -> None:
    """`MemoryEditRepoPort.get_memory_by_id`'s own docstring predicted this: "a real `Repo`
    needs only a projection adapter, not a new query". Asserted rather than assumed -- a second
    query here would be a second definition of what a memory row is."""
    edit, pool, _, repo = _edit_repo()
    row = edit.get_memory_by_id(PROJECT, MEMORY)
    assert repo.get_calls == [(PROJECT, MEMORY)]
    assert pool.log == [], "the projection must issue no SQL of its own"
    assert row.id == MEMORY
    assert row.subject_tag == "subject-42"


def test_insert_memory_item_is_delegated_to_the_real_repo() -> None:
    """The provenance-or-rejection and scan-verdict checks (invariant 6) live in
    `Repo.insert_memory_item`. A second insert path here would bypass both."""
    edit, pool, _, repo = _edit_repo()
    assert edit.insert_memory_item(PROJECT, object(), object()) == MEMORY
    assert repo.insert_calls == [PROJECT]
    assert pool.log == []


def test_select_by_subject_tag_binds_the_tag_and_carries_the_project_predicate() -> None:
    """The one genuinely new statement on this class, and the one whose input is
    caller-derived: `subject_tag` reaches it from an erasure request."""
    edit, pool, _, _ = _edit_repo([])
    edit.select_by_subject_tag(PROJECT, "subject-42")
    assert _GUC_FRAGMENT in pool.log[0][0]
    sql, params = _memory_statements(pool.log)[0]
    assert "project_id = %(project_id)s" in sql
    assert "subject_tag = %(subject_tag)s" in sql
    assert "subject-42" not in sql, "the tag must be bound, never interpolated"
    assert params["subject_tag"] == "subject-42"
    assert params["project_id"] == PROJECT


def test_select_by_subject_tag_refuses_a_row_from_another_project() -> None:
    """This read feeds `EditOps.delete_by_subject`, so a row that crossed the project wall is a
    memory this caller is about to tombstone and crypto-shred."""
    from datetime import UTC, datetime

    edit, _, _, _ = _edit_repo(
        [
            {
                "id": MEMORY.value,
                "project_id": OTHER_PROJECT.value,
                "status": Status.VALIDATED.value,
                "trust_tier": "B",
                "mem_type": "lesson",
                "provenance": {"class": ProvenanceClass.DISTILLER.value},
                "status_changed_at": datetime(2026, 7, 27, tzinfo=UTC),
                "subject_tag": "subject-42",
            }
        ]
    )
    with pytest.raises(TracebedError, match="invariant 4"):
        edit.select_by_subject_tag(PROJECT, "subject-42")


def test_the_forensics_reads_carry_the_project_predicate_and_the_guc() -> None:
    from tracebed.stores.pg.lifecycle import ForensicsRepo

    cases = (
        (lambda r: r.list_runs_injected_with(PROJECT, MEMORY), "injection_log"),
        (lambda r: r.list_direct_derived_descendants(PROJECT, MEMORY), "memory_link"),
        (lambda r: r.list_outcome_events_for_runs(PROJECT, [mint_run_id()]), "outcome_event"),
    )
    for call, table in cases:
        pool = _FakePool([])
        call(ForensicsRepo(pool, _StubRepo(), _RecordingLifecycle()))  # type: ignore[arg-type]
        assert _GUC_FRAGMENT in pool.log[0][0], table
        sql = next(s for s, _ in pool.log if table in s)
        assert "project_id = %(project_id)s" in sql, sql


def test_the_descendant_query_is_one_hop_and_only_derived_from() -> None:
    """The port requires ONE HOP; the transitive closure is
    `Forensics._transitive_descendants`' BFS. A recursive CTE here would make the depth bound
    invisible to the worker that enforces it, and dropping the relation filter would silently
    walk `supersedes`/`contradicts` links as if they were derivations."""
    from tracebed.stores.pg import lifecycle as lifecycle_module

    sql = lifecycle_module._DIRECT_DERIVED_DESCENDANTS_SQL
    assert "relation = 'derived_from'" in sql
    assert "RECURSIVE" not in sql.upper()


def test_an_empty_run_list_issues_no_statement_at_all() -> None:
    """`= ANY(ARRAY[])` matches nothing, so the query is pure cost. A blast radius over zero
    runs is an ordinary call for a memory that was never injected."""
    from tracebed.stores.pg.lifecycle import ForensicsRepo

    pool = _FakePool([])
    repo = ForensicsRepo(pool, _StubRepo(), _RecordingLifecycle())  # type: ignore[arg-type]
    assert repo.list_outcome_events_for_runs(PROJECT, []) == []
    assert pool.log == []


# --------------------------------------------------------------------------- #
# Integration — a real Postgres (absent on this machine; skips cleanly).
# --------------------------------------------------------------------------- #


@pytest.mark.integration
def test_the_embedding_sweep_round_trips_against_a_real_database(pg: str) -> None:
    """What the offline half structurally cannot prove: that the predicate SELECTS what it
    should. Inserts a retrievable row and a quarantined one, asserts only the first is offered,
    writes a vector, asserts the row stops being offered, then changes the pin and asserts it is
    offered again — the versioned re-embedding migration PLAN.md §10 requires, executed."""
    import psycopg

    from tracebed.stores.pg.migrate import apply_migrations
    from tracebed.stores.pg.partitions import create_project_partitions
    from tracebed.stores.pg.pool import create_pool

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

        validated_id, _ = _seed_two_rows(pool, project_id)

        repo = EmbeddingRepo(pool)
        offered = repo.select_needing_embedding(
            project_id, model_id="m", model_version="v1", limit=10
        )
        assert [row.id for row in offered] == [validated_id], (
            "only the retrievable row may be offered for embedding"
        )

        # `migrations/0002_partitioned.sql` fixes the column at halfvec(768).
        repo.write_embedding(
            project_id, validated_id, [0.01] * 768, model_id="m", model_version="v1"
        )
        assert repo.select_needing_embedding(
            project_id, model_id="m", model_version="v1", limit=10
        ) == [], "an embedded row under an unchanged pin must not be re-offered"

        again = repo.select_needing_embedding(
            project_id, model_id="m", model_version="v2", limit=10
        )
        assert [row.id for row in again] == [validated_id], (
            "a pin change must make every row eligible again -- that IS the migration"
        )
    finally:
        pool.close()


@pytest.mark.integration
def test_the_append_is_idempotent_and_three_valued_against_a_real_database(pg: str) -> None:
    """Executes the `FOR NO KEY UPDATE` CTE. Asserts all three outcomes come from one
    statement: a first append, a repeat of the same run, and an append against a memory id that
    does not exist in this project."""
    import psycopg

    from tracebed.stores.pg.migrate import apply_migrations
    from tracebed.stores.pg.partitions import create_project_partitions
    from tracebed.stores.pg.pool import create_pool

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

        _, quarantined_id = _seed_two_rows(pool, project_id)
        repo = CorroborationRepo(pool)
        run: RunId = mint_run_id()

        assert repo.append_confirming_run(project_id, quarantined_id, run) is (
            AppendOutcome.APPENDED
        )
        assert repo.append_confirming_run(project_id, quarantined_id, run) is (
            AppendOutcome.ALREADY_PRESENT
        )
        assert repo.append_confirming_run(
            project_id, MemoryId(uuid.uuid4()), run
        ) is AppendOutcome.ROW_NOT_ELIGIBLE

        rows = repo.select_quarantined(project_id)
        assert [row.id for row in rows] == [quarantined_id]
        assert rows[0].confirming_run_ids == (run,), (
            "distinctness is the statement's job: two appends of one run must leave one element"
        )
    finally:
        pool.close()


def _seed_two_rows(pool: Any, project_id: ProjectId) -> tuple[MemoryId, MemoryId]:
    """One `validated` Tier-A row and one `quarantined` Tier-B row, inserted through the real
    `Repo` so provenance/scan-verdict validation is exercised rather than bypassed."""
    from tracebed.core.scans import ScanContext, scan
    from tracebed.domain.clock import FakeClock
    from tracebed.domain.enums import Lane, MemType, ScopeType, TrustTier
    from tracebed.stores.pg.repo import Repo

    repo = Repo(pool, FakeClock())
    run_id = mint_run_id()

    def _insert(content: str, *, status: Status, tier: TrustTier) -> MemoryId:
        from tracebed.domain.memory import NewMemoryItem

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

    validated_id = _insert("retry with jittered backoff", status=Status.VALIDATED, tier=TrustTier.A)
    quarantined_id = _insert("an unconfirmed lesson", status=Status.QUARANTINED, tier=TrustTier.B)
    return validated_id, quarantined_id
