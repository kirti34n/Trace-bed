"""Parallel-branch contention gate (PLAN.md §7 Phase 4): "N concurrent branches
committing to the same key produce exactly one winner and N-1 typed conflicts, never a
lost update and never a torn read." Fixture-only, no host dependency (PLAN.md §7:
"Phase 4 contention tests are FIXTURE-ONLY, no host dependency") — genuine OS threads
racing through the real `BlackboardRepo.commit` code path against the in-memory
`ConcurrentBlackboardStore` fake (imported from `test_blackboard.py`, so both modules
exercise the identical production path and the identical fake).

Every race here is REPEATED (`ROUNDS`) with a fresh run id, because one execution of one
interleaving proves close to nothing: thread scheduling is the variable under test, so a
property that holds must hold across many schedules, and a property that fails
intermittently must be given the chance to fail. The `threading.Barrier` guarantees the
threads are all inside the same window; the repetition is what samples the window.

WHAT THIS CAN AND CANNOT PROVE. The fake enforces `blackboard_entry`'s real primary key
under one lock, which is a faithful model of what a unique index gives a concurrent
`INSERT ... ON CONFLICT DO NOTHING` — so these tests genuinely exercise
`BlackboardRepo.commit`'s branching, its read-back, and its two outcomes under real
preemption. They do not, and cannot here, prove Postgres' own concurrency behaviour; the
statement-level facts that protocol depends on (the conflict target being the declared
primary key, the read-back constraining the full key, READ COMMITTED) are pinned by
`test_blackboard.py` instead.
"""

from __future__ import annotations

import contextlib
import threading
import uuid
from collections.abc import Callable
from datetime import UTC, datetime

import pytest

from tests.phase4.test_blackboard import ConcurrentBlackboardStore, FakeBlackboardPool
from tracebed.domain.clock import FakeClock
from tracebed.domain.ids import AgentTypeId, PrincipalId, ProjectId, RunId, mint_run_id
from tracebed.domain.scope import ProjectScope
from tracebed.stores.pg.blackboard import BlackboardRepo
from tracebed.workflow.blackboard import (
    STATUS_COMMITTED,
    BlackboardCommitResult,
    BlackboardKeyConflict,
    BlackboardProposal,
    compute_value_ref,
)

pytestmark = pytest.mark.phase4

EPOCH = datetime(2026, 1, 1, tzinfo=UTC)
PROJECT = ProjectId(uuid.uuid4())
AGENT_TYPE = AgentTypeId(uuid.uuid4())

# Enough concurrent branches to make "got lucky and never actually overlapped" implausible
# without making the test slow; the barrier below is what actually guarantees overlap.
N_BRANCHES = 32

# One race is one schedule. Repeating it is the only way an offline test samples more than
# the interleaving the author happened to get.
ROUNDS = 8

#: The value half the branches agree on in the mixed-population race.
AGREED_VALUE = {"agreed": "plan"}


def _scope(principal: PrincipalId) -> ProjectScope:
    return ProjectScope(project_id=PROJECT, agent_type_id=AGENT_TYPE, principal_id=principal)


def _join_all(threads: list[threading.Thread]) -> None:
    for t in threads:
        t.join(timeout=15)
    assert all(not t.is_alive() for t in threads), "a commit thread hung"


def _run_concurrent_commits(
    *,
    n: int,
    run_id: RunId,
    key: str,
    value_for: Callable[[int], object],
    branch_for: Callable[[int], str] = lambda _i: "shared-branch",
) -> tuple[BlackboardRepo, list[PrincipalId], list[tuple[str, object]]]:
    """Launch `n` real OS threads, each proposing and committing under the same
    (run_id, key) and the branch `branch_for` gives it, synchronised with a
    `threading.Barrier` so their commit attempts genuinely overlap rather than merely
    running in short succession. Returns the repo (for post-hoc reads), the principals
    used, and each thread's ("ok" | "conflict", BlackboardCommitResult |
    BlackboardKeyConflict) outcome.
    """
    pool = FakeBlackboardPool(ConcurrentBlackboardStore())
    repo = BlackboardRepo(pool, FakeClock(EPOCH))  # type: ignore[arg-type]
    principals = [PrincipalId(uuid.uuid4()) for _ in range(n)]
    barrier = threading.Barrier(n)
    results: list[tuple[str, object]] = []
    results_lock = threading.Lock()

    def commit_one(i: int) -> None:
        scope = _scope(principals[i])
        proposal = BlackboardProposal.create(scope, run_id, branch_for(i), key, value_for(i))
        barrier.wait(timeout=10)  # every thread proposes BEFORE any of them commits
        try:
            result = repo.commit(scope, proposal)
            outcome: tuple[str, object] = ("ok", result)
        except BlackboardKeyConflict as exc:
            outcome = ("conflict", exc)
        with results_lock:
            results.append(outcome)

    threads = [threading.Thread(target=commit_one, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    _join_all(threads)
    return repo, principals, results


#: One reader observation: (value_ref, author, created_at, status).
Observation = tuple[str, str, object, str]


def _race_readers_against_writers(
    *, run_id: RunId, writers: int, readers: int
) -> tuple[BlackboardRepo, ProjectScope, list[Observation]]:
    """`writers` threads race to commit one key while `readers` threads poll `get_entry`
    for the whole window. Defined at module level rather than inside the test's repetition
    loop so each thread body closes over exactly one round's state (a closure defined in a
    loop would read whichever round's variables happened to be current when it ran).
    """
    pool = FakeBlackboardPool(ConcurrentBlackboardStore())
    repo = BlackboardRepo(pool, FakeClock(EPOCH))  # type: ignore[arg-type]
    reader_scope = _scope(PrincipalId(uuid.uuid4()))
    principals = [PrincipalId(uuid.uuid4()) for _ in range(writers)]
    barrier = threading.Barrier(writers + readers)
    stop = threading.Event()
    observations: list[Observation] = []
    obs_lock = threading.Lock()

    def write_one(i: int) -> None:
        scope = _scope(principals[i])
        proposal = BlackboardProposal.create(scope, run_id, "main", "plan", {"from": i})
        barrier.wait(timeout=10)
        with contextlib.suppress(BlackboardKeyConflict):
            repo.commit(scope, proposal)

    def read_many() -> None:
        barrier.wait(timeout=10)
        seen: list[Observation] = []
        while not stop.is_set():
            entry = repo.get_entry(reader_scope, run_id, "main", "plan")
            if entry is not None:
                seen.append(
                    (entry.value_ref, str(entry.author_agent), entry.created_at, entry.status)
                )
        with obs_lock:
            observations.extend(seen)

    threads = [threading.Thread(target=write_one, args=(i,)) for i in range(writers)]
    threads += [threading.Thread(target=read_many) for _ in range(readers)]
    for t in threads:
        t.start()
    for t in threads[:writers]:
        t.join(timeout=15)
    stop.set()
    _join_all(threads)
    return repo, reader_scope, observations


def _race_distinct_keys(
    *, run_id: RunId, n: int
) -> tuple[BlackboardRepo, list[BlackboardCommitResult]]:
    """`n` threads committing `n` different keys at once. Module level for the same reason
    as `_race_readers_against_writers`.
    """
    pool = FakeBlackboardPool(ConcurrentBlackboardStore())
    repo = BlackboardRepo(pool, FakeClock(EPOCH))  # type: ignore[arg-type]
    principals = [PrincipalId(uuid.uuid4()) for _ in range(n)]
    barrier = threading.Barrier(n)
    commits: list[BlackboardCommitResult] = []
    commits_lock = threading.Lock()

    def commit_one(i: int) -> None:
        scope = _scope(principals[i])
        proposal = BlackboardProposal.create(scope, run_id, "main", f"key-{i}", {"payload": i})
        barrier.wait(timeout=10)
        result = repo.commit(scope, proposal)
        with commits_lock:
            commits.append(result)

    threads = [threading.Thread(target=commit_one, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    _join_all(threads)
    return repo, commits


def test_n_concurrent_branches_produce_exactly_one_winner_and_n_minus_1_conflicts() -> None:
    for _round in range(ROUNDS):
        run_id = mint_run_id()
        repo, _principals, results = _run_concurrent_commits(
            n=N_BRANCHES,
            run_id=run_id,
            key="plan",
            value_for=lambda i: {"branch_plan": i},  # every branch proposes a DIFFERENT value
        )

        assert len(results) == N_BRANCHES
        wins = [r for kind, r in results if kind == "ok"]
        conflicts = [r for kind, r in results if kind == "conflict"]

        assert len(wins) == 1, f"expected exactly one winner, got {len(wins)}"
        assert len(conflicts) == N_BRANCHES - 1, (
            f"expected {N_BRANCHES - 1} conflicts, got {len(conflicts)}"
        )

        winner: BlackboardCommitResult = wins[0]  # type: ignore[assignment]
        assert winner.outcome == "committed"

        # No torn read: every one of the N-1 losers saw the SAME winning value_ref --
        # nobody observed a different "current winner" than anybody else.
        winning_refs_seen = {c.winning_value_ref for c in conflicts}  # type: ignore[union-attr]
        assert winning_refs_seen == {winner.value_ref}
        winning_authors_seen = {c.winning_author for c in conflicts}  # type: ignore[union-attr]
        assert winning_authors_seen == {str(winner.author_agent)}

        # No lost update: the row the store actually holds afterwards IS the winner's row,
        # not some other thread's write that raced in after the fact -- and there is
        # exactly one row, so no loser's attempt left a second one behind.
        final = repo.get_entry(_scope(winner.author_agent), run_id, "shared-branch", "plan")
        assert final is not None
        assert final.value_ref == winner.value_ref
        assert final.author_agent == winner.author_agent
        assert final.status == STATUS_COMMITTED
        assert len(repo.list_entries(_scope(winner.author_agent), run_id)) == 1


def test_concurrent_identical_values_converge_never_conflict() -> None:
    """The complementary contention case: N branches racing to commit the SAME logical
    value never produce a `BlackboardKeyConflict` -- content addressing converges them
    (PLAN.md §7), even under genuine concurrency.
    """
    shared_value = {"identical": "content", "for": "every branch"}
    for _round in range(ROUNDS):
        run_id = mint_run_id()
        repo, _principals, results = _run_concurrent_commits(
            n=N_BRANCHES,
            run_id=run_id,
            key="consensus",
            value_for=lambda _i: shared_value,
        )

        assert len(results) == N_BRANCHES
        assert all(kind == "ok" for kind, _ in results), (
            f"identical-value commits must never conflict, got: "
            f"{[kind for kind, _ in results if kind != 'ok']}"
        )
        outcomes: list[BlackboardCommitResult] = [r for _, r in results]  # type: ignore[misc]
        committed = [r for r in outcomes if r.outcome == "committed"]
        converged = [r for r in outcomes if r.outcome == "converged"]
        assert len(committed) == 1
        assert len(converged) == N_BRANCHES - 1
        # Every result -- winner and every converger -- reports the identical value_ref
        # and the identical (first) author, proving no torn read across N-1 concurrent
        # readers.
        assert {r.value_ref for r in outcomes} == {compute_value_ref(shared_value)}
        assert {r.author_agent for r in outcomes} == {committed[0].author_agent}
        assert {r.created_at for r in outcomes} == {committed[0].created_at}

        final = repo.get_entry(
            _scope(committed[0].author_agent), run_id, "shared-branch", "consensus"
        )
        assert final is not None
        assert final.value_ref == compute_value_ref(shared_value)


def test_a_mixed_population_still_yields_one_winner_and_correct_per_agent_outcomes() -> None:
    """The realistic race, and the one a pure all-different or all-identical population
    cannot produce: half the branches propose one agreed value, half propose their own.

    Whether the single winner comes from the agreeing half or the dissenting half is
    scheduler-dependent, and BOTH shapes must be correct -- if the agreed value wins, every
    other agreeing branch converges and every dissenter conflicts; if a dissenter wins,
    everyone else conflicts. Asserting the invariant that holds either way (exactly one
    row, exactly one "committed", and every non-conflicting caller agreeing on the winner)
    is what makes this test independent of which schedule the OS picked.
    """
    for _round in range(ROUNDS):
        run_id = mint_run_id()
        repo, _principals, results = _run_concurrent_commits(
            n=N_BRANCHES,
            run_id=run_id,
            key="plan",
            value_for=lambda i: AGREED_VALUE if i % 2 == 0 else {"dissent": i},
        )

        oks: list[BlackboardCommitResult] = [r for kind, r in results if kind == "ok"]  # type: ignore[misc]
        conflicts = [r for kind, r in results if kind == "conflict"]
        committed = [r for r in oks if r.outcome == "committed"]
        converged = [r for r in oks if r.outcome == "converged"]

        assert len(committed) == 1, f"expected exactly one winner, got {len(committed)}"
        winner = committed[0]
        assert len(oks) + len(conflicts) == N_BRANCHES

        # Everyone who did not raise agrees on exactly one committed row...
        assert {r.value_ref for r in oks} == {winner.value_ref}
        assert {r.author_agent for r in oks} == {winner.author_agent}
        # ...and everyone who raised names that same row as the winner.
        assert {c.winning_value_ref for c in conflicts} == ({winner.value_ref} if conflicts else set())  # type: ignore[union-attr]

        # Convergence is possible only when the agreed value won; when it did, every other
        # agreeing branch must have converged rather than conflicted.
        if winner.value_ref == compute_value_ref(AGREED_VALUE):
            assert len(converged) == N_BRANCHES // 2 - 1
            assert len(conflicts) == N_BRANCHES // 2
        else:
            assert not converged
            assert len(conflicts) == N_BRANCHES - 1

        assert len(repo.list_entries(_scope(winner.author_agent), run_id)) == 1


def test_readers_racing_writers_never_observe_a_partial_or_superseded_row() -> None:
    """"A parallel branch either sees a whole commit or none" (PLAN.md §7), tested from the
    READ side: while N writers race for one key, R readers poll `get_entry` throughout the
    window. Every non-`None` observation must be the same complete row -- same value_ref,
    same author, same created_at, status committed -- because no code path in
    `BlackboardRepo` ever rewrites a committed row. A reader that ever saw two different
    answers would mean a value was mutated in place; a reader that saw a row with a missing
    field would mean a commit was observable mid-flight.
    """
    for _round in range(ROUNDS):
        run_id = mint_run_id()
        repo, reader_scope, observations = _race_readers_against_writers(
            run_id=run_id, writers=N_BRANCHES, readers=8
        )

        assert observations, "readers never saw the committed row at all"
        assert len(set(observations)) == 1, (
            f"readers disagreed about the committed row: {set(observations)}"
        )
        value_ref, author, created_at, status = observations[0]
        assert status == STATUS_COMMITTED
        assert created_at == EPOCH
        final = repo.get_entry(reader_scope, run_id, "main", "plan")
        assert final is not None
        assert (final.value_ref, str(final.author_agent)) == (value_ref, author)


def test_concurrent_commits_of_one_key_on_distinct_branches_all_win() -> None:
    """Parallel branches of one run each own their own copy of a key: `branch_id` is part
    of the identity, so N branches concurrently committing `plan` do not contend at all.
    The over-serialising failure (a conflict target or a read-back that forgot `branch_id`)
    turns this into N-1 spurious conflicts.
    """
    for _round in range(ROUNDS):
        run_id = mint_run_id()
        repo, _principals, results = _run_concurrent_commits(
            n=N_BRANCHES,
            run_id=run_id,
            key="plan",
            value_for=lambda i: {"branch_plan": i},
            branch_for=lambda i: f"branch-{i}",
        )
        assert all(kind == "ok" for kind, _ in results), (
            "distinct branches must not contend on the same key"
        )
        outcomes: list[BlackboardCommitResult] = [r for _, r in results]  # type: ignore[misc]
        assert all(r.outcome == "committed" for r in outcomes)
        assert len({r.branch_id for r in outcomes}) == N_BRANCHES
        assert len(repo.list_entries(_scope(_principals[0]), run_id)) == N_BRANCHES
        for i, principal in enumerate(_principals):
            entry = repo.get_entry(_scope(principal), run_id, f"branch-{i}", "plan")
            assert entry is not None
            assert entry.value_ref == compute_value_ref({"branch_plan": i})


def test_contention_on_distinct_keys_never_conflicts_with_each_other() -> None:
    """Sanity check on the fake's isolation: N branches committing to N *different* keys
    (no shared key at all) must all win -- the contention machinery must not
    over-serialise unrelated keys into false conflicts.
    """
    for _round in range(ROUNDS):
        run_id = mint_run_id()
        repo, commits = _race_distinct_keys(run_id=run_id, n=N_BRANCHES)

        assert len(commits) == N_BRANCHES
        assert all(r.outcome == "committed" for r in commits)
        assert len({r.key for r in commits}) == N_BRANCHES
        assert len(repo.list_entries(_scope(commits[0].author_agent), run_id, limit=100)) == (
            N_BRANCHES
        )
