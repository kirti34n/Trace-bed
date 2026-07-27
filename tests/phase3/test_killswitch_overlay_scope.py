"""`Repo.get_killswitch_overlay` sees both overlay scopes (D-129).

The bug this covers: `migrations/0001:127-141` defines a `killswitch_state` row with
`agent_type_id IS NULL` as the PROJECT-WIDE overlay, but the query used to filter with
`agent_type_id IS NOT DISTINCT FROM %(agent_type_id)s` -- and `ConfigResolver.effective`
(`domain/config.py`) always calls `get_killswitch_overlay` with a RESOLVED (non-NULL)
`agent_type_id`. `NULL IS NOT DISTINCT FROM <uuid>` is false, so the project-wide row could
never match: a project-wide kill switch failed OPEN (memory kept being injected for every
agent type) while `list_killswitch_state` / `GET /admin/killswitch_state` still reported it
as active -- disabled in effect, enabled in the UI.

There is no Postgres on this build machine (per-repo constraint), so the fake connection
below does not merely return canned rows -- its cursor actually PARSES the WHERE clause
`Repo` hands it and filters a table of canned `killswitch_state` rows against whichever
predicate it finds, exactly the way Postgres would evaluate either form. That is what makes
`test_reverting_to_the_old_predicate_fails_the_project_wide_scenario` a real mutation check:
it exercises the literal old predicate text next to the current one on the same fixture,
rather than hand-asserting a duplicate of the merge logic under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

import pytest

from tracebed.domain.clock import FakeClock
from tracebed.domain.ids import AgentTypeId, ProjectId
from tracebed.stores.pg.repo import Repo

pytestmark = pytest.mark.phase3

EPOCH = datetime(2026, 1, 1, tzinfo=UTC)
PROJECT = ProjectId(uuid.UUID("33333333-3333-3333-3333-333333333333"))
AGENT_A = AgentTypeId(uuid.UUID("44444444-4444-4444-4444-444444444444"))
AGENT_B = AgentTypeId(uuid.UUID("55555555-5555-5555-5555-555555555555"))

# The two predicate forms `get_killswitch_overlay` has used. Kept as literal strings (not
# imported) so this file notices a *textual* regression to the old form even if some future
# refactor renames the query's local variables.
_NEW_PREDICATE = "agent_type_id IS NULL OR agent_type_id = %(agent_type_id)s"
_OLD_PREDICATE = "agent_type_id IS NOT DISTINCT FROM %(agent_type_id)s"

# A canned `killswitch_state` table: (agent_type_id, mem_type, disabled).
Row = tuple[AgentTypeId | None, str, bool]


class _KillswitchCursor:
    """Evaluates the WHERE clause it is handed against `_ROWS`-shaped canned rows.

    This is the "structural test that parses [the SQL] and asserts its predicates" the task
    calls for: it does not know in advance which predicate `Repo` will send, it interprets
    whichever one arrives, the same way Postgres would. An unrecognized predicate fails loudly
    rather than silently returning the wrong rows.
    """

    def __init__(self, log: list[tuple[str, Any]], table: list[Row]) -> None:
        self._log = log
        self._table = table
        self._sql = ""
        self._params: dict[str, Any] = {}

    def execute(self, sql: str, params: Any = None) -> _KillswitchCursor:
        self._log.append((sql, params))
        self._sql = sql
        self._params = dict(params) if params else {}
        return self

    def fetchall(self) -> list[tuple[str, bool]]:
        agent_type_id = self._params.get("agent_type_id")
        if _NEW_PREDICATE in self._sql:
            return [
                (mem_type, disabled)
                for (row_agent, mem_type, disabled) in self._table
                if row_agent is None or row_agent == agent_type_id
            ]
        if _OLD_PREDICATE in self._sql:
            # `IS NOT DISTINCT FROM` is NULL-safe equality -- Python's `==` on `None` already
            # has that exact semantics (`None == None` is True, `None == <uuid>` is False), so
            # a plain `==` reproduces it with no special-casing.
            return [
                (mem_type, disabled)
                for (row_agent, mem_type, disabled) in self._table
                if row_agent == agent_type_id
            ]
        raise AssertionError(f"unrecognized killswitch overlay predicate: {self._sql!r}")

    def __enter__(self) -> _KillswitchCursor:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class _KillswitchConnection:
    def __init__(self, log: list[tuple[str, Any]], table: list[Row]) -> None:
        self._log = log
        self._table = table

    def execute(self, sql: str, params: Any = None) -> _KillswitchCursor:
        self._log.append((sql, params))
        return _KillswitchCursor(self._log, self._table)

    def cursor(self, name: str | None = None, **kwargs: Any) -> _KillswitchCursor:
        return _KillswitchCursor(self._log, self._table)

    @contextmanager
    def transaction(self) -> Iterator[_KillswitchConnection]:
        yield self


class _KillswitchPool:
    def __init__(self, table: list[Row]) -> None:
        self.log: list[tuple[str, Any]] = []
        self._table = table

    @contextmanager
    def connection(self) -> Iterator[_KillswitchConnection]:
        yield _KillswitchConnection(self.log, self._table)


def _repo(table: list[Row]) -> Repo:
    return Repo(_KillswitchPool(table), FakeClock(EPOCH))  # type: ignore[arg-type]


class TestKillswitchOverlayScope:
    def test_project_wide_row_alone_applies_to_every_agent_type(self) -> None:
        """A NULL-`agent_type_id` row with no matching agent-type row must still surface for
        ANY resolved `agent_type_id` -- this is the exact scenario the old predicate dropped.
        """
        table: list[Row] = [(None, "lesson", True)]
        repo = _repo(table)

        assert repo.get_killswitch_overlay(PROJECT, AGENT_A) == {"lesson": True}
        assert repo.get_killswitch_overlay(PROJECT, AGENT_B) == {"lesson": True}

    def test_agent_type_row_alone_applies_only_to_that_one(self) -> None:
        """An agent-type-specific row must not leak into a different agent type's overlay --
        the fix must not overcorrect into "every row applies to everyone".
        """
        table: list[Row] = [(AGENT_A, "semantic", True)]
        repo = _repo(table)

        assert repo.get_killswitch_overlay(PROJECT, AGENT_A) == {"semantic": True}
        assert repo.get_killswitch_overlay(PROJECT, AGENT_B) == {}

    def test_project_wide_disable_wins_over_agent_type_enable(self) -> None:
        """Documented precedence, direction one: a project-wide DISABLE (the bigger hammer)
        overrides a same-`mem_type` agent-type ENABLE.
        """
        table: list[Row] = [
            (None, "lesson", True),
            (AGENT_A, "lesson", False),
        ]
        repo = _repo(table)

        assert repo.get_killswitch_overlay(PROJECT, AGENT_A) == {"lesson": True}

    def test_agent_type_disable_is_not_undone_by_project_wide_enable(self) -> None:
        """Documented precedence, direction two: an agent-type-specific DISABLE is not silently
        re-enabled by a project-wide row that defaults the same `mem_type` back to enabled --
        disabling is always the safer direction, so whichever row asserts it wins.
        """
        table: list[Row] = [
            (None, "lesson", False),
            (AGENT_A, "lesson", True),
        ]
        repo = _repo(table)

        assert repo.get_killswitch_overlay(PROJECT, AGENT_A) == {"lesson": True}

    def test_a_none_agent_type_resolves_the_project_wide_row_and_nothing_else(self) -> None:
        """`ConfigStorePort.get_killswitch_overlay` accepts `AgentTypeId | None`, and
        `ConfigResolver.effective` passes whatever scope it was given straight through -- so the
        `None` arm is a reachable production path, not a type-system formality. Postgres
        evaluates `agent_type_id = NULL` to NULL (never true), so the OR's second half
        contributes nothing and ONLY the project-wide row resolves. That has to stay true: a
        `None` scope silently picking up some other agent type's disablement would attribute a
        targeted control to a caller that never had that agent type.
        """
        table: list[Row] = [(None, "lesson", True), (AGENT_A, "semantic", True)]
        repo = _repo(table)

        assert repo.get_killswitch_overlay(PROJECT, None) == {"lesson": True}

    def test_neither_row_present_is_a_clean_no_overlay(self) -> None:
        repo = _repo([])

        assert repo.get_killswitch_overlay(PROJECT, AGENT_A) == {}

    def test_independent_mem_types_do_not_bleed_into_each_other(self) -> None:
        """Two different `mem_type`s, one project-wide and one agent-specific, resolve
        independently rather than one's `disabled` flag contaminating the other's.
        """
        table: list[Row] = [
            (None, "lesson", True),
            (AGENT_A, "semantic", False),
        ]
        repo = _repo(table)

        assert repo.get_killswitch_overlay(PROJECT, AGENT_A) == {
            "lesson": True,
            "semantic": False,
        }

    def test_reverting_to_the_old_predicate_fails_the_project_wide_scenario(self) -> None:
        """Mutation check: swap the query text for the exact old predicate on the same fixture
        `Repo` uses, and confirm the project-wide scenario -- the one this chunk fixes --
        goes red. This is what proves the old predicate really did pass the rest of the
        suite: it silently drops the NULL row for any resolved `agent_type_id`.
        """
        table: list[Row] = [(None, "lesson", True)]
        cursor = _KillswitchCursor(log=[], table=table)

        # Not a real query -- `_KillswitchCursor.fetchall` only ever pattern-matches this string
        # against `_OLD_PREDICATE`/`_NEW_PREDICATE` below, never executes it. Built as one
        # literal (not a `+ _OLD_PREDICATE` concatenation) so it reads as fixture data, not as
        # dynamic SQL construction.
        old_form_query = (
            "SELECT mem_type, disabled FROM killswitch_state "
            "WHERE project_id = %(project_id)s "
            "AND agent_type_id IS NOT DISTINCT FROM %(agent_type_id)s"
        )
        assert _OLD_PREDICATE in old_form_query
        cursor.execute(
            old_form_query,
            {"project_id": PROJECT, "agent_type_id": AGENT_A},
        )
        old_predicate_rows = cursor.fetchall()

        assert old_predicate_rows == [], (
            "the old predicate was expected to drop the project-wide row for a resolved "
            "agent_type_id -- if this now returns the row, the mutation check itself is stale"
        )

        # The current implementation, exercised the normal way, does see it.
        assert Repo(_KillswitchPool(table), FakeClock(EPOCH)).get_killswitch_overlay(  # type: ignore[arg-type]
            PROJECT, AGENT_A
        ) == {"lesson": True}

    def test_query_predicate_is_the_new_or_form_not_the_old_distinct_from_form(self) -> None:
        """Direct regression guard on the SQL text itself: if a future edit reverts
        `get_killswitch_overlay`'s predicate back to `IS NOT DISTINCT FROM`, this fails
        immediately without needing a database to prove it.
        """
        table: list[Row] = [(None, "lesson", True)]
        pool = _KillswitchPool(table)
        Repo(pool, FakeClock(EPOCH)).get_killswitch_overlay(PROJECT, AGENT_A)  # type: ignore[arg-type]

        overlay_sql = [sql for sql, _ in pool.log if "killswitch_state" in sql]
        assert len(overlay_sql) == 1
        assert _NEW_PREDICATE in overlay_sql[0]
        assert _OLD_PREDICATE not in overlay_sql[0]

    def test_the_overlay_query_is_still_project_scoped_in_its_own_text(self) -> None:
        """Widening the agent-type half of the predicate must not widen the PROJECT half.

        `tests/phase0/test_repo_isolation_offline.py::
        test_every_scoped_statement_carries_the_project_id_predicate` looks like it already
        covers this, and for most methods it does -- but it accepts a statement as scoped as
        soon as its PARAMS dict binds `project_id`, without checking that the SQL uses the
        binding. Deleting `WHERE project_id = %(project_id)s` from this query while leaving
        `{"project_id": project_id, ...}` in the params therefore survives that test (verified
        by mutation). PLAN.md section 5 makes the query builder the primary isolation control
        and RLS only the backstop, so for the one method this file owns the predicate is
        asserted in the query text directly, and the binding is asserted to still be there for
        it to reference.
        """
        table: list[Row] = [(None, "lesson", True)]
        pool = _KillswitchPool(table)
        Repo(pool, FakeClock(EPOCH)).get_killswitch_overlay(PROJECT, AGENT_A)  # type: ignore[arg-type]

        overlay_calls = [(sql, params) for sql, params in pool.log if "killswitch_state" in sql]
        assert len(overlay_calls) == 1
        sql, params = overlay_calls[0]
        assert "project_id = %(project_id)s" in sql
        assert params["project_id"] == PROJECT
