"""Invariant 4 for `ReportsRepo`, offline — the same standard `Repo` is already held to.

`stores.pg.repo.Repo` has three independent layers proving project isolation at query
construction: an exhaustive call table, "the RLS GUC is the transaction's FIRST statement",
and "every statement binds `project_id` itself". `stores.pg.reports.ReportsRepo` has seven
builders over the same partitioned learning-plane tables and had NONE of them — it was
correct by inspection and nothing would have caught it becoming incorrect. That is the
definition of an invariant resting on convention, and this file is the mechanism.

Exactly the design of `tests/phase0/test_repo_isolation_offline.py`, deliberately: a fake
pool that records statements, a call table asserted exhaustive against
`inspect.getmembers`, and assertions about *which statements are issued in what order*
rather than about return values (there are none — the fake returns no rows).

Mutation this catches: swap any one `scoped(self._pool, project_id)` in `reports.py` for a
bare `self._pool.connection()`, or drop a `WHERE project_id = %(project_id)s` conjunct from
any one query, and a parametrisation here goes red. In production the same mutation returns
another project's rows on a dashboard, silently.
"""

from __future__ import annotations

import inspect
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from typing import Any

import pytest

from tracebed.domain.clock import FakeClock
from tracebed.domain.ids import ProjectId
from tracebed.stores.pg.reports import ReportsRepo

pytestmark = pytest.mark.phase0

PROJECT = ProjectId(uuid.UUID("11111111-1111-1111-1111-111111111111"))
OTHER_PROJECT = ProjectId(uuid.UUID("22222222-2222-2222-2222-222222222222"))
EPOCH = datetime(2026, 1, 1, tzinfo=UTC)


class _FakeCursor:
    def __init__(self, log: list[tuple[str, Any]]) -> None:
        self._log = log

    def execute(self, sql: str, params: Any = None) -> _FakeCursor:
        self._log.append((sql, params))
        return self

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


def _reports() -> tuple[ReportsRepo, _FakePool]:
    pool = _FakePool()
    return ReportsRepo(pool, FakeClock(EPOCH)), pool  # type: ignore[arg-type]


def _calls(repo: ReportsRepo) -> dict[str, Any]:
    """method name -> a zero-argument callable that exercises it once."""
    return {
        "lift_observations": lambda: repo.lift_observations(PROJECT, since=EPOCH),
        "q_trajectory": lambda: repo.q_trajectory(PROJECT),
        "invalidation_events": lambda: repo.invalidation_events(PROJECT),
        "stale_memories": lambda: repo.stale_memories(PROJECT),
        "revalidation_candidates": lambda: repo.revalidation_candidates(
            PROJECT, threshold_at=EPOCH, now=EPOCH
        ),
        "consolidation_diffs": lambda: repo.consolidation_diffs(PROJECT),
        "injection_feed": lambda: repo.injection_feed(PROJECT),
    }


def _public_method_names() -> set[str]:
    return {
        name
        for name, _ in inspect.getmembers(ReportsRepo, predicate=inspect.isfunction)
        if not name.startswith("_")
    }


def test_call_table_covers_every_public_reports_method() -> None:
    """Exhaustiveness gate: a new report builder with no entry here would be silently exempt
    from every assertion below — and a brand-new query is exactly the one most likely to have
    forgotten `scoped()`."""
    repo, _ = _reports()
    assert _public_method_names() == set(_calls(repo))


@pytest.mark.parametrize("method_name", sorted(_public_method_names()))
def test_every_report_builder_sets_the_guc_first(method_name: str) -> None:
    repo, pool = _reports()
    with suppress(Exception):
        _calls(repo)[method_name]()

    assert pool.log, f"ReportsRepo.{method_name} issued no SQL at all"
    first_sql, first_params = pool.log[0]
    assert "set_config" in first_sql and "tracebed.project_id" in first_sql, (
        f"ReportsRepo.{method_name} reads a partitioned table but its transaction's FIRST "
        f"statement was not the RLS GUC; it was: {first_sql.strip()[:120]!r}"
    )
    assert first_params == {"project_id": str(PROJECT)}


@pytest.mark.parametrize("method_name", sorted(_public_method_names()))
def test_every_report_statement_carries_the_project_id_predicate(method_name: str) -> None:
    """Belt to the GUC's braces (PLAN.md §5: "typed repository (primary) ... RLS backstop"):
    every non-GUC statement must bind `project_id` itself, so the query is still scoped on a
    connection where the GUC was somehow lost."""
    repo, pool = _reports()
    with suppress(Exception):
        _calls(repo)[method_name]()
    for sql, params in pool.log:
        if "set_config" in sql:
            continue
        assert isinstance(params, dict) and params.get("project_id") == PROJECT, (
            f"ReportsRepo.{method_name} issued a statement with no bound project_id: "
            f"{sql.strip()[:120]!r}"
        )
        assert "project_id" in sql, (
            f"ReportsRepo.{method_name} bound a project_id that its SQL never compares against"
        )


def test_the_guc_value_tracks_the_requested_project() -> None:
    """The GUC is not a constant: a builder that stamped a fixed or stale project would pass
    the ordering assertion above while making RLS enforce the wrong wall."""
    repo, pool = _reports()
    with suppress(Exception):
        repo.injection_feed(PROJECT)
    with suppress(Exception):
        repo.injection_feed(OTHER_PROJECT)
    bound = [params for sql, params in pool.log if "set_config" in sql]
    assert bound == [{"project_id": str(PROJECT)}, {"project_id": str(OTHER_PROJECT)}]


def test_no_report_query_selects_star() -> None:
    """`SELECT *` binds a report to column order and to every column a future migration adds
    — including `content`, which no report is supposed to project."""
    repo, pool = _reports()
    for call in _calls(repo).values():
        with suppress(Exception):
            call()
    offenders = [sql.strip()[:80] for sql, _ in pool.log if "SELECT *" in sql.upper()]
    assert not offenders, f"report queries using SELECT *: {offenders}"
