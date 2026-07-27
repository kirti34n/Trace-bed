"""Postgres connection pool + the single structural gateway to the RLS GUC.

PHASE-0 Task 7 / PHASE0-CONTRACT.md §5.0 (invariant 4, PLAN.md §2). Every transaction that
touches a partitioned table must set ``tracebed.project_id`` as its first statement, or Postgres
row-level security (FORCE ROW LEVEL SECURITY, migrations Task 6) returns zero rows instead of
another tenant's data. That backstop only works if the GUC is set on the path that is actually
used -- this module exists so the GUC-setting path is the *only* path, not a convention every
caller has to remember.

``scoped()`` is the one public way to obtain a connection bound to a project: it requires a
``ProjectId`` positionally, with no default, so there is no call shape that yields a connection
without the GUC set. ``create_pool()`` hands out the bare ``psycopg_pool.ConnectionPool`` that
``Repo`` and ``stores.pg.queue.WorkQueue`` both take in their constructors (contract §5.0)  --
``WorkQueue`` never touches a partitioned table (``work_queue``/``dead_letter`` are unpartitioned,
contract §5.3), so it never needs ``scoped()`` and is not weakened by getting the raw pool.

``_unscoped()`` is the deliberately private escape hatch for the registry tables (``project``,
``principal``, ``agent_type``, ``agent_registration``, ``embedding_model``, ``scoring_epoch``) --
unpartitioned, no RLS policy, and for ``resolve_project``/``create_project``/``create_principal``
there is no ``project_id`` to scope by yet: those calls are what *establish* or *derive* project
identity in the first place (contract §5.1's six-method registry allowlist). It is not exported
in ``__all__``; the only importer is ``stores.pg.repo``, and only for that allowlist.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, Final

import psycopg
from psycopg import postgres, pq
from psycopg.abc import Buffer
from psycopg.adapt import Dumper
from psycopg_pool import ConnectionPool

from tracebed.domain.ids import ProjectId, TypedId

__all__ = ["create_pool", "register_typed_id_adapters", "scoped"]

# --------------------------------------------------------------------------------------- #
# psycopg parameter adaptation for `domain.ids.TypedId`.
#
# WHY THIS EXISTS (audit finding, invariant 4): every repository builder binds `ProjectId` /
# `RunId` / `MemoryId` / `PrincipalId` / `AgentTypeId` values straight into query parameters --
# that is the whole point of the newtypes (a bare UUID cannot satisfy a scope-required builder).
# psycopg 3 has NO `__conform__` hook (that was psycopg 2's protocol; `domain/ids.py`'s
# `__conform__` method is inert here) and resolves dumpers by walking `type(obj).__mro__`
# against a registry. Without the registration below, EVERY parameterised query in `repo.py`
# fails at execution time with:
#     psycopg.ProgrammingError: cannot adapt type 'ProjectId' using placeholder '%s'
# There is no Postgres on the build machine, so nothing else in Phase 0 can catch this --
# `tests/phase0/test_repo_isolation_offline.py::test_typed_ids_are_adaptable_by_psycopg`
# exercises the dumper resolution directly, with no database.
#
# Registered against the `TypedId` BASE class: psycopg's `AdaptersMap.get_dumper` walks the MRO,
# so one registration covers every present and future id subclass -- a new id type can never
# silently become unbindable.
# --------------------------------------------------------------------------------------- #

_UUID_OID: Final[int] = postgres.types["uuid"].oid


class _TypedIdTextDumper(Dumper):
    """Text-format dumper for any `TypedId`: emits the wrapped UUID's canonical string."""

    oid = _UUID_OID

    def dump(self, obj: Any) -> Buffer:
        return str(obj.value).encode("ascii")


class _TypedIdBinaryDumper(Dumper):
    """Binary-format dumper for any `TypedId`: emits the wrapped UUID's 16 raw bytes."""

    format = pq.Format.BINARY
    oid = _UUID_OID

    def dump(self, obj: Any) -> Buffer:
        raw: bytes = obj.value.bytes
        return raw


def register_typed_id_adapters() -> None:
    """Teach psycopg how to bind `TypedId` values as `uuid` parameters.

    Idempotent, and called at import of this module so that merely importing anything under
    `stores.pg` is enough -- no caller has to remember. Registered on the global
    `psycopg.adapters` (the map every new connection inherits from), which is why it must run
    before any connection is opened; `create_pool` lives in this module, so it always does.
    Binary is registered last so `PyFormat.AUTO` resolves to it, matching how psycopg treats a
    plain `uuid.UUID`.
    """
    psycopg.adapters.register_dumper(TypedId, _TypedIdTextDumper)
    psycopg.adapters.register_dumper(TypedId, _TypedIdBinaryDumper)


register_typed_id_adapters()

# CHOICE C-09 (contract §5.0, §15): `SET LOCAL` is a utility statement and cannot bind a query
# parameter -- `SET LOCAL tracebed.project_id = %s` is a syntax error at the protocol level, not
# just a style issue. `select set_config(name, value, is_local)` is an ordinary function call and
# takes parameters normally; `is_local=true` gives the same transaction-scoped-only semantics as
# `SET LOCAL` (the setting reverts at COMMIT/ROLLBACK, never leaking onto a pooled connection's
# next checkout).
_SET_PROJECT_GUC = "SELECT set_config('tracebed.project_id', %(project_id)s, true)"


def create_pool(dsn: str, *, min_size: int = 1, max_size: int = 10) -> ConnectionPool:
    """The one pool constructor (contract §5.0). Opens eagerly so connection failures surface at
    startup, not on the first request. `Repo` and `WorkQueue` are constructed with this same
    instance -- neither builds its own pool.
    """
    return ConnectionPool(dsn, min_size=min_size, max_size=max_size, open=True)


@contextmanager
def scoped(pool: ConnectionPool, project_id: ProjectId) -> Iterator[psycopg.Connection[Any]]:
    """THE only way anything in this codebase obtains a connection inside a transaction that may
    touch a partitioned table (invariant 4). `project_id` is positional and type-required --
    there is no optional/defaulted form of this function. Issues the GUC statement above as the
    first statement of the transaction, before the caller's own SQL runs, then yields the
    connection. RLS FORCE (migrations Task 6) is the backstop if this is ever bypassed by a
    future edit; it must never become the *primary* control -- `raw_sql_lint.py` keeping all SQL
    inside `stores/pg/` is what makes this the only place that can bypass it in the first place.
    """
    if not isinstance(project_id, ProjectId):
        # mypy --strict is a build-time gate; this is the runtime backstop for anything that
        # reaches here through an `Any`-typed edge (e.g. a dynamically dispatched caller).
        raise TypeError(f"scoped() requires a ProjectId, got {type(project_id).__name__}")
    with pool.connection() as conn, conn.transaction():
        conn.execute(_SET_PROJECT_GUC, {"project_id": str(project_id)})
        yield conn


@contextmanager
def _unscoped(pool: ConnectionPool) -> Iterator[psycopg.Connection[Any]]:
    """Module-private: registry-table access with no project scope to set (see module docstring).
    Not in `__all__`; `stores.pg.repo` is the only importer.
    """
    with pool.connection() as conn, conn.transaction():
        yield conn
