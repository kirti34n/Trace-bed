"""Parallel-branch contention + key-squatting DIRECT DRILL (PLAN.md section 7 Phase 4
gate, clauses 1-2, verbatim):

    "parallel-branch contention tests green (fixture-only -- no host
    dependency); key-squatting test: proposed keys cannot shadow another
    agent's committed keys."

    ... REAL THREADS, repeated enough times to catch an interleaving, not a
    single scripted ordering.

This is a pure drill LIBRARY, not a pytest test module -- `contention.py` matches
neither pytest's `test_*.py` nor `*_test.py` collection pattern (`pyproject.toml`'s
`testpaths = ["tests", "harness"]` with pytest's default `python_files`), the same
convention `harness/lift_sim.py` / `harness/guessed_reward.py` / `harness/ledger_audit.py`
already follow. `harness/phase4_gate.py` calls `run_contention_drill()` directly, exactly
the way `harness/phase3_gate.py` calls `harness.lift_sim.run_lift_sim()` -- for the
concrete numbers a bare JUnit pass/fail cannot carry on its own -- ALONGSIDE the real
pytest coverage the `blackboard` chunk already built and owns
(`tests/phase4/test_blackboard_contention.py`'s real-OS-thread N-committers-one-winner
suite, `tests/phase4/test_blackboard.py`'s single-threaded key-squatting tests).

Both this module and that pytest suite drive the SAME production entry point,
`tracebed.stores.pg.blackboard.BlackboardRepo.commit`, against an in-memory fake that
enforces `blackboard_entry`'s real primary key
(`UNIQUE(project_id, run_id, branch_id, key)`) under one `threading.Lock` -- a faithful
model of what a real unique index gives a concurrent `INSERT ... ON CONFLICT DO NOTHING`
(see `stores.pg.blackboard`'s own module docstring for the commit protocol this fake
stands in for). The fake here is written independently rather than imported from
`tests.phase4.test_blackboard` -- harness code that a gate runner executes at any time
(not only under `pytest`) should not depend on the `tests` package, and per-chunk
fake/helper duplication is an accepted convention in this codebase
(PHASE0-CONTRACT.md section 13.1's own note, repeated verbatim by every sibling
`harness/*_gate.py` module for its own duplicated JUnit-parsing helpers).

WHAT THIS CAN AND CANNOT PROVE (same caveat `test_blackboard_contention.py` states for
itself): the fake enforces the declared primary key under one lock, which faithfully
models a real unique index's atomicity under concurrent inserts, but it cannot prove
Postgres' own speculative-insertion behaviour, nor that RLS FORCE returns zero rows --
those are proven, or documented as unprovable offline, elsewhere (`stores.pg.blackboard`'s
own module docstring; the leak suite).

TWO SCENARIOS, RUN MANY TIMES EACH WITH FRESH REAL OS THREADS:

  1. `_race_shared_key_once` -- N branches, genuinely barrier-synchronised, race to
     commit N DIFFERENT values under one (run_id, branch_id, key). Exactly one must win,
     N-1 must receive a typed `BlackboardKeyConflict` all naming the SAME winner (no torn
     read), and the row the store holds afterwards must be the winner's, unchanged.

  2. `_race_key_squat_once` -- the literal PLAN.md clause 2 shape: one legitimate
     committer commits FIRST (durably, before any attacker thread starts), then M
     attacker threads, barrier-synchronised against EACH OTHER, race to commit DIFFERENT
     values under the SAME already-committed key. Every attacker must be refused
     (`BlackboardKeyConflict` naming the legitimate committer), none may ever land
     ("shadow") the key, and the row must read back unchanged afterwards. This is the
     concurrent-attack version of `test_blackboard.py`'s
     `test_second_committer_cannot_shadow_an_already_committed_key`, which proves the
     same property with one sequential attacker rather than a swarm of concurrent ones.
"""

from __future__ import annotations

import re
import threading
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from tracebed.domain.clock import FakeClock
from tracebed.domain.ids import AgentTypeId, PrincipalId, ProjectId, TypedId, mint_run_id
from tracebed.domain.scope import ProjectScope
from tracebed.stores.pg.blackboard import BlackboardRepo
from tracebed.workflow.blackboard import (
    BlackboardCommitResult,
    BlackboardKeyConflict,
    BlackboardProposal,
)

__all__ = [
    "ContentionReport",
    "render_text",
    "run_contention_drill",
]

_EPOCH: Final = datetime(2026, 1, 1, tzinfo=UTC)

#: `blackboard_entry`'s declared primary key (migrations/0002_partitioned.sql). The fake
#: enforces THIS, whatever a statement's `ON CONFLICT` target claims -- exactly as
#: Postgres does (SQLSTATE 42P10 for a conflict target that is not a real unique index).
_TABLE_PRIMARY_KEY: Final[tuple[str, ...]] = ("project_id", "run_id", "branch_id", "key")

_CONFLICT_TARGET = re.compile(r"ON CONFLICT \(([^)]*)\) DO NOTHING", re.IGNORECASE)
_EQUALITY_PREDICATE = re.compile(r"\b(\w+) = %\((\w+)\)s")

#: Enough concurrent branches that "got lucky and never actually overlapped" is
#: implausible without making a round slow; the `threading.Barrier` below is what
#: actually guarantees overlap, this is only insurance against a scheduler that somehow
#: runs every thread to completion before starting the next.
DEFAULT_N_BRANCHES: Final[int] = 32

#: One race is one interleaving. Repeating it is the only way an offline drill samples
#: more than the one schedule the author happened to get -- PLAN.md's own words.
DEFAULT_ROUNDS: Final[int] = 8

DEFAULT_N_SQUAT_ATTACKERS: Final[int] = 16
DEFAULT_SQUAT_ROUNDS: Final[int] = 8


class _FakeSqlError(RuntimeError):
    """What this fake raises where a real Postgres would reject the statement."""


class _ConcurrentStore:
    """In-memory stand-in for `blackboard_entry` and its primary-key index.
    `insert_on_conflict` is the one operation that must be atomic (check-then-set under
    one lock) -- exactly what a real unique index guarantees for a concurrent
    `INSERT ... ON CONFLICT DO NOTHING`. Nothing here ever removes or mutates a row once
    written, mirroring `BlackboardRepo`'s own "no UPDATE, no DELETE, ever" discipline.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._rows: dict[tuple[str, ...], dict[str, Any]] = {}

    def insert_on_conflict(
        self, row: Mapping[str, Any], conflict_target: tuple[str, ...]
    ) -> dict[str, Any] | None:
        if tuple(sorted(conflict_target)) != tuple(sorted(_TABLE_PRIMARY_KEY)):
            raise _FakeSqlError(
                "no unique or exclusion constraint matching the ON CONFLICT specification "
                f"{conflict_target!r}; blackboard_entry's is {_TABLE_PRIMARY_KEY!r}"
            )
        pk = tuple(str(row[column]) for column in _TABLE_PRIMARY_KEY)
        with self._lock:
            if pk in self._rows:
                return None
            self._rows[pk] = dict(row)
            return dict(row)

    def select(self, predicates: Mapping[str, Any]) -> list[dict[str, Any]]:
        with self._lock:
            return [
                dict(row)
                for row in self._rows.values()
                if all(str(row[column]) == str(value) for column, value in predicates.items())
            ]


def _as_wire_value(value: Any) -> Any:
    """Mirrors a real psycopg round trip: a `uuid` column returns a plain `uuid.UUID`,
    never one of `domain.ids`' `TypedId` subclasses (see `tests.phase4.test_blackboard`'s
    identically-named helper for the full rationale -- duplicated here rather than
    imported, per this module's own docstring on that convention)."""
    return value.value if isinstance(value, TypedId) else value


def _named_predicates(sql: str, params: Mapping[str, Any]) -> dict[str, Any]:
    where = sql.split(" WHERE ", 1)[1] if " WHERE " in sql else ""
    return {column: params[param] for column, param in _EQUALITY_PREDICATE.findall(where)}


class _FakeCursor:
    def __init__(self, store: _ConcurrentStore, log: list[tuple[str, Any]]) -> None:
        self._store = store
        self._log = log
        self._result: list[dict[str, Any]] = []

    def execute(self, sql: str, params: Any = None) -> _FakeCursor:
        self._log.append((sql, params))
        if "INSERT INTO blackboard_entry" in sql:
            target = _CONFLICT_TARGET.search(sql)
            if target is None:
                raise _FakeSqlError("INSERT INTO blackboard_entry without ON CONFLICT ... DO NOTHING")
            if "RETURNING" not in sql:
                raise _FakeSqlError("INSERT INTO blackboard_entry without RETURNING")
            columns = tuple(part.strip() for part in target.group(1).split(","))
            wire_row = {k: _as_wire_value(v) for k, v in dict(params).items()}
            inserted = self._store.insert_on_conflict(wire_row, columns)
            self._result = [inserted] if inserted is not None else []
        elif "FROM blackboard_entry" in sql:
            self._result = self._store.select(_named_predicates(sql, params))
        else:
            self._result = []
        return self

    def fetchone(self) -> Any:
        return self._result[0] if self._result else None

    def fetchall(self) -> list[Any]:
        return list(self._result)

    def __enter__(self) -> _FakeCursor:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class _FakeConnection:
    def __init__(self, store: _ConcurrentStore, log: list[tuple[str, Any]]) -> None:
        self._store = store
        self._log = log
        self.isolation_level: object = None  # "server default" -> READ COMMITTED

    def execute(self, sql: str, params: Any = None) -> _FakeCursor:
        self._log.append((sql, params))
        return _FakeCursor(self._store, self._log)

    def cursor(self, name: str | None = None, **kwargs: Any) -> _FakeCursor:
        return _FakeCursor(self._store, self._log)

    @contextmanager
    def transaction(self) -> Iterator[_FakeConnection]:
        yield self


class _FakePool:
    """Every checkout shares the SAME store and log, so concurrent callers race against
    real shared state -- mirrors `psycopg_pool.ConnectionPool` only to the extent
    `stores.pg.pool.scoped()` actually uses it (`.connection()`, `conn.transaction()`)."""

    def __init__(self, store: _ConcurrentStore) -> None:
        self.store = store
        self.log: list[tuple[str, Any]] = []

    @contextmanager
    def connection(self) -> Iterator[_FakeConnection]:
        yield _FakeConnection(self.store, self.log)


def _scope(project: ProjectId, agent_type: AgentTypeId, principal: PrincipalId) -> ProjectScope:
    return ProjectScope(project_id=project, agent_type_id=agent_type, principal_id=principal)


def _new_repo() -> BlackboardRepo:
    pool = _FakePool(_ConcurrentStore())
    return BlackboardRepo(pool, FakeClock(_EPOCH))  # type: ignore[arg-type]


def _join_all(threads: list[threading.Thread]) -> bool:
    """Joins every thread with a bounded timeout. Returns True iff every thread
    finished -- a hung thread is itself a drill finding (a real deadlock), never
    silently ignored."""
    for t in threads:
        t.join(timeout=15)
    return all(not t.is_alive() for t in threads)


@dataclass(frozen=True, slots=True)
class _SharedKeyRoundResult:
    winners: int
    conflicts: int
    errors: int
    hung: bool
    consistent: bool
    """True iff exactly one winner existed, every conflict named that exact winner (no
    torn read), and the store's own row afterwards matches the winner -- i.e. every
    property PLAN.md clause 1 names, for this one round."""


def _race_shared_key_once(
    *, n_branches: int, project: ProjectId, agent_type: AgentTypeId
) -> _SharedKeyRoundResult:
    run_id = mint_run_id()
    repo = _new_repo()
    principals = [PrincipalId(uuid.uuid4()) for _ in range(n_branches)]
    barrier = threading.Barrier(n_branches)
    results: list[tuple[str, object]] = []
    results_lock = threading.Lock()

    def commit_one(i: int) -> None:
        scope = _scope(project, agent_type, principals[i])
        proposal = BlackboardProposal.create(scope, run_id, "shared-branch", "plan", {"branch": i})
        barrier.wait(timeout=10)
        outcome: tuple[str, object]
        try:
            outcome = ("ok", repo.commit(scope, proposal))
        except BlackboardKeyConflict as exc:
            outcome = ("conflict", exc)
        except Exception as exc:  # any other exception IS a drill finding, not a bug to hide
            outcome = ("error", exc)
        with results_lock:
            results.append(outcome)

    threads = [threading.Thread(target=commit_one, args=(i,)) for i in range(n_branches)]
    for t in threads:
        t.start()
    hung = not _join_all(threads)
    if hung:
        return _SharedKeyRoundResult(winners=0, conflicts=0, errors=n_branches, hung=True, consistent=False)

    wins: list[BlackboardCommitResult] = [r for k, r in results if k == "ok"]  # type: ignore[misc]
    conflicts: list[BlackboardKeyConflict] = [r for k, r in results if k == "conflict"]  # type: ignore[misc]
    errors = [r for k, r in results if k == "error"]

    consistent = len(wins) == 1 and not errors
    if consistent:
        winner = wins[0]
        consistent = (
            {c.winning_value_ref for c in conflicts} <= {winner.value_ref}
            and {c.winning_author for c in conflicts} <= {str(winner.author_agent)}
        )
        final = repo.get_entry(_scope(project, agent_type, winner.author_agent), run_id, "shared-branch", "plan")
        consistent = consistent and final is not None and final.value_ref == winner.value_ref

    return _SharedKeyRoundResult(
        winners=len(wins),
        conflicts=len(conflicts),
        errors=len(errors),
        hung=False,
        consistent=consistent,
    )


@dataclass(frozen=True, slots=True)
class _KeySquatRoundResult:
    n_attackers: int
    shadows: int
    """Attackers whose commit LANDED (overwrote/claimed the key). Must always be 0."""
    blocked: int
    errors: int
    hung: bool
    row_unchanged: bool
    all_conflicts_name_legit: bool


def _race_key_squat_once(
    *, n_attackers: int, project: ProjectId, agent_type: AgentTypeId
) -> _KeySquatRoundResult:
    run_id = mint_run_id()
    repo = _new_repo()

    legit_principal = PrincipalId(uuid.uuid4())
    legit_scope = _scope(project, agent_type, legit_principal)
    legit_proposal = BlackboardProposal.create(legit_scope, run_id, "main", "plan", {"legit": True})
    legit_result = repo.commit(legit_scope, legit_proposal)
    if legit_result.outcome != "committed":
        # The legitimate first commit itself failing to land is a drill defect, not an
        # attacker success -- report it as every attacker "shadowing" so `ok` reads False
        # loudly rather than silently skipping the round.
        return _KeySquatRoundResult(
            n_attackers=n_attackers, shadows=n_attackers, blocked=0, errors=0, hung=False,
            row_unchanged=False, all_conflicts_name_legit=False,
        )

    attacker_principals = [PrincipalId(uuid.uuid4()) for _ in range(n_attackers)]
    barrier = threading.Barrier(n_attackers)
    results: list[tuple[str, object]] = []
    results_lock = threading.Lock()

    def attack(i: int) -> None:
        scope = _scope(project, agent_type, attacker_principals[i])
        proposal = BlackboardProposal.create(scope, run_id, "main", "plan", {"attacker": i})
        barrier.wait(timeout=10)
        outcome: tuple[str, object]
        try:
            outcome = ("shadowed", repo.commit(scope, proposal))  # BAD if this ever happens
        except BlackboardKeyConflict as exc:
            outcome = ("blocked", exc)
        except Exception as exc:  # any other exception IS a drill finding, not a bug to hide
            outcome = ("error", exc)
        with results_lock:
            results.append(outcome)

    threads = [threading.Thread(target=attack, args=(i,)) for i in range(n_attackers)]
    for t in threads:
        t.start()
    hung = not _join_all(threads)
    if hung:
        return _KeySquatRoundResult(
            n_attackers=n_attackers, shadows=0, blocked=0, errors=n_attackers, hung=True,
            row_unchanged=False, all_conflicts_name_legit=False,
        )

    shadows = [r for k, r in results if k == "shadowed"]
    blocked: list[BlackboardKeyConflict] = [r for k, r in results if k == "blocked"]  # type: ignore[misc]
    errors = [r for k, r in results if k == "error"]

    final = repo.get_entry(legit_scope, run_id, "main", "plan")
    row_unchanged = (
        final is not None
        and final.value_ref == legit_result.value_ref
        and final.author_agent == legit_principal
    )
    all_named_legit = all(c.winning_author == str(legit_principal) for c in blocked)

    return _KeySquatRoundResult(
        n_attackers=n_attackers,
        shadows=len(shadows),
        blocked=len(blocked),
        errors=len(errors),
        hung=False,
        row_unchanged=row_unchanged,
        all_conflicts_name_legit=all_named_legit,
    )


@dataclass(frozen=True, slots=True)
class ContentionReport:
    rounds: int
    n_branches: int
    total_winners: int
    total_conflicts: int
    total_errors: int
    inconsistent_rounds: int
    hung_rounds: int
    squat_rounds: int
    n_squat_attackers: int
    total_shadows: int
    """Attackers that ever landed a commit over an already-committed key. Must be 0
    across every round for `key_squat_ok` to hold."""
    total_blocked: int
    squat_row_unchanged_rounds: int
    squat_conflicts_named_legit_rounds: int
    squat_errors: int

    @property
    def parallel_branch_ok(self) -> bool:
        """PLAN.md clause 1: "parallel-branch contention tests green ... REAL THREADS,
        repeated enough times to catch an interleaving." """
        return (
            self.hung_rounds == 0
            and self.inconsistent_rounds == 0
            and self.total_errors == 0
            and self.total_winners == self.rounds
            and self.total_conflicts == self.rounds * (self.n_branches - 1)
        )

    @property
    def key_squat_ok(self) -> bool:
        """PLAN.md clause 2: "key-squatting test: proposed keys cannot shadow another
        agent's committed keys." """
        return (
            self.squat_rounds > 0
            and self.total_shadows == 0
            and self.squat_errors == 0
            and self.squat_row_unchanged_rounds == self.squat_rounds
            and self.squat_conflicts_named_legit_rounds == self.squat_rounds
            and self.total_blocked == self.squat_rounds * self.n_squat_attackers
        )

    @property
    def ok(self) -> bool:
        return self.parallel_branch_ok and self.key_squat_ok


def run_contention_drill(
    *,
    n_branches: int = DEFAULT_N_BRANCHES,
    rounds: int = DEFAULT_ROUNDS,
    n_squat_attackers: int = DEFAULT_N_SQUAT_ATTACKERS,
    squat_rounds: int = DEFAULT_SQUAT_ROUNDS,
) -> ContentionReport:
    """Runs both scenarios described in this module's docstring, `rounds` /
    `squat_rounds` times respectively, each round with fresh real OS threads racing
    through the real `BlackboardRepo.commit` production path against a fresh in-memory
    store (so no round's outcome can leak into the next round's interleaving)."""
    project = ProjectId(uuid.uuid4())
    agent_type = AgentTypeId(uuid.uuid4())

    total_winners = total_conflicts = total_errors = 0
    inconsistent_rounds = hung_rounds = 0
    for _ in range(rounds):
        result = _race_shared_key_once(n_branches=n_branches, project=project, agent_type=agent_type)
        total_winners += result.winners
        total_conflicts += result.conflicts
        total_errors += result.errors
        if result.hung:
            hung_rounds += 1
        elif not result.consistent:
            inconsistent_rounds += 1

    total_shadows = total_blocked = squat_errors = 0
    squat_row_unchanged_rounds = squat_conflicts_named_legit_rounds = 0
    for _ in range(squat_rounds):
        squat = _race_key_squat_once(n_attackers=n_squat_attackers, project=project, agent_type=agent_type)
        total_shadows += squat.shadows
        total_blocked += squat.blocked
        squat_errors += squat.errors
        if squat.hung:
            squat_errors += 1
        if squat.row_unchanged:
            squat_row_unchanged_rounds += 1
        if squat.all_conflicts_name_legit:
            squat_conflicts_named_legit_rounds += 1

    return ContentionReport(
        rounds=rounds,
        n_branches=n_branches,
        total_winners=total_winners,
        total_conflicts=total_conflicts,
        total_errors=total_errors,
        inconsistent_rounds=inconsistent_rounds,
        hung_rounds=hung_rounds,
        squat_rounds=squat_rounds,
        n_squat_attackers=n_squat_attackers,
        total_shadows=total_shadows,
        total_blocked=total_blocked,
        squat_row_unchanged_rounds=squat_row_unchanged_rounds,
        squat_conflicts_named_legit_rounds=squat_conflicts_named_legit_rounds,
        squat_errors=squat_errors,
    )


def render_text(report: ContentionReport) -> str:
    lines = [
        f"parallel-branch race: {report.rounds} rounds x {report.n_branches} real OS threads/round",
        f"  winners: {report.total_winners} (expect {report.rounds}, exactly one per round)",
        f"  conflicts: {report.total_conflicts} (expect {report.rounds * (report.n_branches - 1)})",
        f"  errors: {report.total_errors} (expect 0)",
        f"  inconsistent rounds (torn read / wrong winner recorded): {report.inconsistent_rounds} (expect 0)",
        f"  hung rounds (a commit thread never returned): {report.hung_rounds} (expect 0)",
        f"  clause 1 (parallel-branch contention): {'PASS' if report.parallel_branch_ok else 'FAIL'}",
        "",
        f"key-squatting race: {report.squat_rounds} rounds x {report.n_squat_attackers} "
        "concurrent attackers/round, against one already-committed key",
        f"  attacker commits that SHADOWED (landed over) the committed key: {report.total_shadows} (expect 0)",
        f"  attacker commits correctly blocked: {report.total_blocked} "
        f"(expect {report.squat_rounds * report.n_squat_attackers})",
        f"  errors: {report.squat_errors} (expect 0)",
        f"  rounds where the committed row read back unchanged: {report.squat_row_unchanged_rounds} "
        f"/ {report.squat_rounds}",
        f"  rounds where every conflict named the legitimate committer: "
        f"{report.squat_conflicts_named_legit_rounds} / {report.squat_rounds}",
        f"  clause 2 (key-squatting): {'PASS' if report.key_squat_ok else 'FAIL'}",
        "",
        f"overall: {'PASS' if report.ok else 'FAIL'}",
    ]
    return "\n".join(lines)
