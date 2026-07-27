"""`blackboard_entry` repository (PLAN.md §7 Phase 4 chunk `blackboard`).

`BlackboardRepo` is this chunk's own typed repository, separate from
`stores.pg.repo.Repo` (a different chunk's file, not touched here) but built to the
same structural rules that make invariant 4 (project isolation) true everywhere in
`stores/pg/`:

  1. Every public method's first meaningful parameter is a `ProjectScope` (or takes one
     implicitly via the connection it opens); every connection is obtained through
     `stores.pg.pool.scoped(pool, project_id)`, which sets the RLS GUC
     (`tracebed.project_id`) as the transaction's FIRST statement before this module's
     own SQL runs. `migrations/0003_rls.sql` FORCEs row-level security on
     `blackboard_entry` as the backstop; this is the primary control.
  2. All SQL lives in this file (`stores/pg/`), never in `workflow.blackboard`
     (`scripts/raw_sql_lint.py` enforces the package boundary for the whole `src/` tree).

NAMED SYNCHRONOUS EXCEPTION (invariant 5). `commit()` opens exactly one transaction via
`scoped()` and returns synchronously — there is no `work_queue` topic for blackboard
commits and there must never be one. See `workflow.blackboard`'s module docstring for
the full rationale; it is not repeated here beyond this pointer so the two modules
cannot drift into two different explanations of the same exception.

COMMIT PROTOCOL, exactly (PLAN.md §7 — "propose -> commit in transactions, so a
parallel branch either sees a whole commit or none"; "UNIQUE(project_id, run_id,
branch_id, key) IS the anti-key-squatting control"):

    INSERT INTO blackboard_entry (..., status='committed') VALUES (...)
    ON CONFLICT (project_id, run_id, branch_id, key) DO NOTHING
    RETURNING ...

  - A row comes back  -> this call won the race; `outcome="committed"`.
  - No row comes back  -> some commit (possibly this exact content, possibly a
    concurrent winner) already holds the key. A second statement, in the SAME
    transaction, reads that row back; `workflow.blackboard.resolve_after_conflict`
    (pure) decides `converged` (identical `value_ref`) or raises `BlackboardKeyConflict`
    naming the winner. Both statements share one `scoped()` transaction, which is what
    "a parallel branch either sees a whole commit or none" means concretely: nothing
    external ever observes the moment between the failed INSERT and the follow-up
    SELECT, and the two can never be split across two different rows because the row
    they both address is unique and immutable (see next paragraph).

THE PROTOCOL REQUIRES READ COMMITTED, and `commit()` enforces that rather than assuming
it. The two statements are deliberately two statements: at READ COMMITTED each takes its
own snapshot, so the SELECT sees the winner's row that the INSERT just lost to (a single
`WITH ins AS (INSERT ...) SELECT ... UNION ALL SELECT ...` would NOT — one statement, one
snapshot, taken before the concurrent commit became visible). Under REPEATABLE READ or
SERIALIZABLE the transaction snapshot is fixed at its first statement, so
`ON CONFLICT DO NOTHING` skips the insert (it does not raise the way `DO UPDATE` would)
and the follow-up SELECT then finds nothing -- a commit that neither committed nor
converged nor conflicted. `commit()` therefore refuses to run on a connection configured
for anything stricter, and the "no existing row" branch below raises with that cause
named instead of claiming it cannot happen. The check reads the CONNECTION's configured
isolation level; a server-side `default_transaction_isolation` of `repeatable read` with
the connection left on the default is the residual it cannot see, which is why the branch
below is a loud, tested error rather than a `pragma: no cover` comment.

VALUE_REF IS NEVER MUTATED IN PLACE (PLAN.md §7). No method in this file issues an
`UPDATE` or `DELETE` against `blackboard_entry` — the only two statements are the
`INSERT ... ON CONFLICT DO NOTHING` above and plain `SELECT`s. Once a row exists for a
given `(project_id, run_id, branch_id, key)`, its `value_ref` is what
`test_blackboard.py` calls "still resolves": re-reading that key later, from any
transaction, returns the identical `value_ref` a caller saw at commit time, whether that
caller won, converged, or lost the race. "A new commit supersedes it" (PLAN.md §7)
therefore cannot mean an UPDATE of this row under this table's actual primary key
(`PRIMARY KEY (project_id, run_id, branch_id, key)`, migrations/0002_partitioned.sql) —
superseding a value requires a NEW key (a new commit under a name nobody holds yet),
which is exactly what the anti-squatting UNIQUE constraint is protecting: nobody, ever,
turns an already-committed key's row into a different value.

CONTRACT GAP (recorded, not silently improvised): `blackboard_entry` has no column for
the value's byte content, only its content-addressed `value_ref` pointer
(migrations/0002_partitioned.sql: `value_ref text NOT NULL`). Durable, cross-process resolution
of a `value_ref` back to bytes (e.g. via `TraceStorePort` or a Valkey-backed
content-addressed cache) is not wired by this chunk — `workflow.blackboard`'s file list
is `workflow/__init__.py` + `workflow/blackboard.py` and this chunk's is
`stores/pg/blackboard.py` + `workflow/*` (rule 7); neither owns a place to add such a
store. "The old value_ref still resolves" in this chunk's tests means exactly what is
durable today: reading the row back yields the same `value_ref`, unchanged, forever.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final

from psycopg import IsolationLevel
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from tracebed.domain.clock import Clock
from tracebed.domain.ids import PrincipalId, ProjectId, RunId
from tracebed.domain.scope import ProjectScope
from tracebed.stores.pg.pool import scoped
from tracebed.workflow.blackboard import (
    STATUS_COMMITTED,
    BlackboardCommitResult,
    BlackboardCommitUnresolved,
    BlackboardEntryRow,
    BlackboardProposal,
    resolve_after_conflict,
)

__all__ = ["MAX_BLACKBOARD_ROW_LIMIT", "BlackboardRepo"]

# Mirrors `stores.pg.repo.MAX_ROW_LIMIT`'s rationale exactly (a hard ceiling on any
# caller-supplied `limit`, since `list_entries` is reachable from a dashboard/API layer
# this chunk does not own and cannot rely on that layer to clamp) -- kept as this
# module's own constant rather than importing the sibling one, so this file's public
# surface has no dependency on `stores.pg.repo`'s internals.
MAX_BLACKBOARD_ROW_LIMIT: Final[int] = 1_000

_ENTRY_COLUMNS: Final[str] = (
    "project_id, run_id, branch_id, author_agent, key, value_ref, status, created_at"
)

# `None` means "whatever the server's default_transaction_isolation is", which
# `create_pool` never overrides and which Postgres ships as `read committed`. See the
# module docstring for why anything stricter silently breaks the commit protocol.
_COMMIT_SAFE_ISOLATION: Final[frozenset[IsolationLevel | None]] = frozenset(
    {None, IsolationLevel.READ_COMMITTED}
)

# `created_at` alone is not a total order: two commits inside the same clock tick (or,
# under a FakeClock, every commit in a test) tie, and a tie makes "most recent first" a
# claim the database is free to break differently on every execution. The primary-key
# remainder breaks it deterministically.
_LIST_ORDER_BY: Final[str] = "ORDER BY created_at DESC, branch_id ASC, key ASC"


def _require_read_committed(conn: object) -> None:
    """Refuse to run the commit protocol on a connection configured for an isolation
    level stricter than READ COMMITTED (module docstring: the protocol's second statement
    depends on taking a fresh snapshot).

    `getattr` rather than an attribute access because the offline fixtures that drive this
    repository stand in for `psycopg.Connection` and do not implement the whole surface; a
    stand-in that does not report an isolation level is treated exactly like a real
    connection that reports `None` -- server default, which Postgres ships as read
    committed.
    """
    level = getattr(conn, "isolation_level", None)
    if level not in _COMMIT_SAFE_ISOLATION:
        raise BlackboardCommitUnresolved(
            f"blackboard commits require READ COMMITTED, got isolation_level={level!r}: "
            "under a stricter level INSERT ... ON CONFLICT DO NOTHING skips the insert "
            "and the winning row stays invisible to this transaction's snapshot"
        )


def _row_to_entry(row: Mapping[str, Any]) -> BlackboardEntryRow:
    """The one place a `blackboard_entry` DB row becomes a `BlackboardEntryRow`.

    `value_ref` and `status` are `NOT NULL` in migrations/0002_partitioned.sql, so against
    the shipped schema this check cannot fire. It is kept as defence in depth, not as the
    primary control: `row` is a `Mapping[str, Any]` by the time psycopg is done, so mypy
    proves nothing here, and this repository is also driven against offline fixtures and
    (per the module docstring) can be pointed at a database whose migrations are older than
    this file. Letting a NULL through would hand a caller a `value_ref=None` typed `str`,
    which `resolve_after_conflict` would compare against a real content hash and report as
    a conflict "won" by a value that does not exist -- a silent wrong answer rather than an
    error, which is the one outcome worth an extra comparison per row.
    """
    for column in ("value_ref", "status"):
        if row[column] is None:
            raise ValueError(
                f"blackboard_entry row has NULL {column} (project_id={row['project_id']}, "
                f"run_id={row['run_id']}, branch_id={row['branch_id']!r}, key={row['key']!r}) "
                "-- every row this repository writes fills it, so this row was written by "
                "something else and cannot be interpreted as a committed entry"
            )
    return BlackboardEntryRow(
        project_id=ProjectId(row["project_id"]),
        run_id=RunId(row["run_id"]),
        branch_id=row["branch_id"],
        author_agent=PrincipalId(row["author_agent"]),
        key=row["key"],
        value_ref=row["value_ref"],
        status=row["status"],
        created_at=row["created_at"],
    )


class BlackboardRepo:
    """`BlackboardRepo(pool, clock)`. See module docstring for the commit protocol and
    the invariant-5 exception it implements.
    """

    def __init__(self, pool: ConnectionPool, clock: Clock) -> None:
        self._pool = pool
        self._clock = clock

    def commit(self, scope: ProjectScope, proposal: BlackboardProposal) -> BlackboardCommitResult:
        """Try to land `proposal` as the row for its key. Raises `BlackboardKeyConflict`
        (via `workflow.blackboard.resolve_after_conflict`) when the key is already
        committed to a DIFFERENT value; returns `outcome="converged"` when it is already
        committed to the SAME value (content addressing, PLAN.md §7); returns
        `outcome="committed"` when this call is the one that wins the race.

        `scope` and `proposal.project_id`/`proposal.author_agent` must agree: `scope` is
        what opens the RLS-scoped connection (invariant 4), and a proposal built for a
        different project would otherwise silently commit into the caller's own project
        under someone else's authored identity. Checked explicitly rather than trusted,
        because `BlackboardProposal.create` binds `project_id`/`author_agent` from
        WHATEVER `scope` its caller happened to pass it — nothing stops a caller from
        building a proposal from one scope and committing it through another.
        """
        if proposal.project_id != scope.project_id:
            raise ValueError(
                "BlackboardRepo.commit: proposal.project_id does not match scope.project_id"
            )
        if proposal.author_agent != scope.principal_id:
            raise ValueError(
                "BlackboardRepo.commit: proposal.author_agent does not match "
                "scope.principal_id -- author_agent must be derived from the scope "
                "actually committing, never a different one"
            )
        with scoped(self._pool, scope.project_id) as conn:
            _require_read_committed(conn)
            now = self._clock.now()
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    f"INSERT INTO blackboard_entry ({_ENTRY_COLUMNS}) "  # noqa: S608
                    "VALUES (%(project_id)s, %(run_id)s, %(branch_id)s, %(author_agent)s, "
                    "%(key)s, %(value_ref)s, %(status)s, %(created_at)s) "
                    "ON CONFLICT (project_id, run_id, branch_id, key) DO NOTHING "
                    f"RETURNING {_ENTRY_COLUMNS}",
                    {
                        "project_id": proposal.project_id,
                        "run_id": proposal.run_id,
                        "branch_id": proposal.branch_id,
                        # The `PrincipalId` itself, never `str(...)`: `author_agent` is
                        # `uuid NOT NULL` and `stores.pg.pool.register_typed_id_adapters`
                        # binds a `TypedId` with the uuid OID declared. A text-typed
                        # parameter would make Postgres reject the INSERT outright
                        # ("column is of type uuid but expression is of type text"), and
                        # this is the one write path an agent runtime synchronously awaits.
                        "author_agent": proposal.author_agent,
                        "key": proposal.key,
                        "value_ref": proposal.value_ref,
                        "status": STATUS_COMMITTED,
                        "created_at": now,
                    },
                )
                won = cur.fetchone()
                if won is not None:
                    # Built from the RETURNING row, not from `proposal` + `now`: the
                    # result a caller gets back is then a report of what the database
                    # actually holds, not a restatement of what this process hoped it
                    # would write. Same function the losing path uses, so both outcomes
                    # go through one row->row translation.
                    stored = _row_to_entry(won)
                    return BlackboardCommitResult(
                        outcome="committed",
                        project_id=stored.project_id,
                        run_id=stored.run_id,
                        branch_id=stored.branch_id,
                        key=stored.key,
                        value_ref=stored.value_ref,
                        author_agent=stored.author_agent,
                        created_at=stored.created_at,
                    )

                # Lost the race (or the key was already committed before this call
                # started). Same transaction, same connection: no external observer
                # sees a state where the failed INSERT happened but the winning row
                # cannot yet be read.
                cur.execute(
                    f"SELECT {_ENTRY_COLUMNS} FROM blackboard_entry "  # noqa: S608
                    "WHERE project_id = %(project_id)s AND run_id = %(run_id)s "
                    "AND branch_id = %(branch_id)s AND key = %(key)s",
                    {
                        "project_id": proposal.project_id,
                        "run_id": proposal.run_id,
                        "branch_id": proposal.branch_id,
                        "key": proposal.key,
                    },
                )
                existing_row = cur.fetchone()
            if existing_row is None:
                # Nothing in this file ever UPDATEs or DELETEs a blackboard_entry row, so
                # a row that just won an insert race cannot vanish before the very next
                # statement of the same transaction. What CAN produce this state is a
                # transaction snapshot older than the winner's commit -- i.e. an
                # isolation level stricter than READ COMMITTED arriving from the server's
                # `default_transaction_isolation` rather than from the connection (which
                # `_require_read_committed` already screens). Name that cause instead of
                # returning a plausible-looking result for a commit that did not happen.
                raise BlackboardCommitUnresolved(
                    "blackboard commit lost the insert race but the winning row is not "
                    f"visible to this transaction (key={proposal.key!r} "
                    f"branch={proposal.branch_id!r}) -- blackboard_entry rows are never "
                    "deleted, so the usual cause is a transaction snapshot older than "
                    "the winner's commit: check that transaction_isolation is "
                    "'read committed' on this server"
                )
            existing = _row_to_entry(existing_row)
        return resolve_after_conflict(proposal, existing)

    def get_entry(
        self, scope: ProjectScope, run_id: RunId, branch_id: str, key: str
    ) -> BlackboardEntryRow | None:
        """By-key lookup. `None` when no entry has been committed for this key yet --
        deliberately not `NotFound` (contract §3.1's `NotFound` is for by-id fetches
        where absence usually signals a caller error; "nobody has committed this key
        yet" is an entirely ordinary, expected state for a blackboard read).
        """
        with (
            scoped(self._pool, scope.project_id) as conn,
            conn.cursor(row_factory=dict_row) as cur,
        ):
            cur.execute(
                f"SELECT {_ENTRY_COLUMNS} FROM blackboard_entry "  # noqa: S608
                "WHERE project_id = %(project_id)s AND run_id = %(run_id)s "
                "AND branch_id = %(branch_id)s AND key = %(key)s",
                {
                    "project_id": scope.project_id,
                    "run_id": run_id,
                    "branch_id": branch_id,
                    "key": key,
                },
            )
            row = cur.fetchone()
        return _row_to_entry(row) if row is not None else None

    def list_entries(
        self,
        scope: ProjectScope,
        run_id: RunId,
        *,
        branch_id: str | None = None,
        limit: int = 200,
    ) -> list[BlackboardEntryRow]:
        """Every entry committed so far for `run_id` (optionally narrowed to one
        `branch_id`), most recent first, ties broken by `(branch_id, key)` so the order is
        total and the same on every execution (see `_LIST_ORDER_BY`). `limit` is clamped into
        `[1, MAX_BLACKBOARD_ROW_LIMIT]` -- same reasoning as
        `stores.pg.repo.MAX_ROW_LIMIT`: a caller-supplied limit reachable from a route
        this chunk does not own must not translate into an unbounded server-side
        allocation.
        """
        bounded = max(1, min(limit, MAX_BLACKBOARD_ROW_LIMIT))
        with (
            scoped(self._pool, scope.project_id) as conn,
            conn.cursor(row_factory=dict_row) as cur,
        ):
            if branch_id is not None:
                cur.execute(
                    f"SELECT {_ENTRY_COLUMNS} FROM blackboard_entry "  # noqa: S608
                    "WHERE project_id = %(project_id)s AND run_id = %(run_id)s "
                    "AND branch_id = %(branch_id)s "
                    f"{_LIST_ORDER_BY} LIMIT %(limit)s",
                    {
                        "project_id": scope.project_id,
                        "run_id": run_id,
                        "branch_id": branch_id,
                        "limit": bounded,
                    },
                )
            else:
                cur.execute(
                    f"SELECT {_ENTRY_COLUMNS} FROM blackboard_entry "  # noqa: S608
                    "WHERE project_id = %(project_id)s AND run_id = %(run_id)s "
                    f"{_LIST_ORDER_BY} LIMIT %(limit)s",
                    {"project_id": scope.project_id, "run_id": run_id, "limit": bounded},
                )
            rows = cur.fetchall()
        return [_row_to_entry(r) for r in rows]
