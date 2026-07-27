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

HARD CANCELLATION (BMAD-EVALUATION finding, D-132). Invariant 2's 300ms budget was enforced
against exceptions only: nothing here bounded a connection attempt or an in-flight statement, so a
stalled Postgres backend blocked whatever transaction reached it indefinitely -- and, through
``hotpath.retriever.Retriever`` (fixed separately, same decision), the calling agent's run. Two
independent, OPT-IN controls close that gap without touching any of this module's existing callers:

1. ``create_pool(..., connect_timeout_s=...)`` bounds how long ESTABLISHING a new physical
   connection may take (libpq's own ``connect_timeout``) -- a per-CONNECTION setting, passed once
   at pool construction. Safe to apply uniformly regardless of which plane a pool serves: a slow
   TCP-and-auth handshake is never something ANY caller, hot path or worker, wants to wait out
   (``psycopg_pool.ConnectionPool`` retries the attempt on its own schedule; this only bounds each
   individual try).
2. ``scoped(..., statement_timeout_ms=..., idle_in_transaction_session_timeout_ms=...)`` bounds
   the transaction it opens -- a per-TRANSACTION setting, issued as an additional ``set_config(...,
   true)`` right after the RLS GUC, using the exact same transaction-scoped idiom C-09 already
   established for that GUC and ``stores.pg.search``'s HNSW GUCs. ``statement_timeout`` is the one
   of the three that Postgres enforces SERVER-SIDE (a client that stopped waiting on a stalled
   query has not made the query stop running; a session-level statement_timeout does): it is the
   real backstop behind ``hotpath.retriever``'s own client-side ``Future.result(timeout=...)`` bound,
   catching the case that bound cannot -- a query that keeps consuming server resources after the
   caller has given up on it.

BOTH DEFAULT TO ``None`` (NO TIMEOUT), preserving today's behaviour for every existing call exactly
-- and that is deliberate, not an oversight: ``create_pool()`` is the ONE constructor
``api/main.py``'s hot-path pool and ``workers/runner.py``'s background-plane pool both call, and
``scoped()`` is the ONE gateway both ``stores.pg.search.SearchStore`` (hot path) and
``stores.pg.repo.Repo`` (background workers' partitioned writes, e.g. the distiller's, the
scorer's) call -- a non-optional default here would be "one global that strangles the background
plane" exactly as PLAN.md §2 invariant 2's own audit warns against: workers' statements
legitimately run far longer than 300ms, and neither of those two call sites is this chunk's file
list to edit and differentiate. Making the values OPT-IN means the mechanism is real, complete, and
independently tested (below and in ``tests/phase1/test_hard_cancellation.py``) without any risk of
starving a worker that never asked for a hot-path budget -- and it is recorded as a contract gap
(DECISIONS.md D-132) that wiring ``retrieval.total_budget_ms`` through to the hot-path pool's
``create_pool``/``scoped`` calls in ``api/main.py``/``stores.pg.search`` is therefore still open,
owned by whichever chunk holds those files.
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

# Same `set_config(..., true)` idiom as the RLS GUC above (C-09) and `stores.pg.search`'s HNSW
# GUCs: transaction-scoped, so a hot-path caller's tight budget can never leak onto a pooled
# connection's next checkout by some unrelated later caller (module docstring, HARD CANCELLATION).
# Values are bound as the literal string Postgres expects for a bare millisecond count -- these
# GUCs take either a unit-suffixed string or a plain integer of milliseconds; a plain string of
# digits satisfies the latter, matching `stores.pg.search`'s own `str(hnsw_max_scan_tuples)` choice.
_SET_STATEMENT_TIMEOUT = "SELECT set_config('statement_timeout', %(statement_timeout_ms)s, true)"
_SET_IDLE_IN_TRANSACTION_TIMEOUT = (
    "SELECT set_config('idle_in_transaction_session_timeout', "
    "%(idle_in_transaction_session_timeout_ms)s, true)"
)


def _connect_timeout_kwargs(connect_timeout_s: int) -> dict[str, Any]:
    """The `kwargs` dict `ConnectionPool` forwards to `psycopg.Connection.connect()` for every
    connection it opens -- `connect_timeout` is a real libpq parameter (seconds), bounding only
    connection ESTABLISHMENT, never a query already running on an established connection (module
    docstring, HARD CANCELLATION point 1)."""
    return {"connect_timeout": connect_timeout_s}


def create_pool(
    dsn: str,
    *,
    min_size: int = 1,
    max_size: int = 10,
    connect_timeout_s: int | None = None,
    checkout_timeout_s: float | None = None,
) -> ConnectionPool:
    """The one pool constructor (contract §5.0). Opens eagerly so connection failures surface at
    startup, not on the first request. `Repo` and `WorkQueue` are constructed with this same
    instance -- neither builds its own pool.

    `connect_timeout_s`, when given, bounds how long establishing each new physical connection may
    take (module docstring, HARD CANCELLATION point 1).

    `checkout_timeout_s` is the third bound, and the only one of the three that needs no server
    cooperation at all: it is `psycopg_pool.ConnectionPool`'s own `timeout`, how long
    `pool.connection()` waits for a FREE connection before raising `PoolTimeout`. Its library
    default is 30 seconds, which on the hot path is a hundred times invariant 2's whole budget --
    with every connection busy, a retrieval that has already been bounded on both the client and
    the server side could still sit half a minute in the checkout queue, before either bound has
    anything to measure. Both are keyword-only with a `None` default meaning "the library's
    behaviour, unchanged", so this function's behaviour is decided entirely by its callers rather
    than by a value chosen here.
    """
    kwargs = _connect_timeout_kwargs(connect_timeout_s) if connect_timeout_s is not None else None
    if checkout_timeout_s is not None:
        if checkout_timeout_s <= 0:
            raise ValueError(f"checkout_timeout_s must be positive, got {checkout_timeout_s!r}")
        return ConnectionPool(
            dsn,
            min_size=min_size,
            max_size=max_size,
            open=True,
            kwargs=kwargs,
            timeout=checkout_timeout_s,
        )
    return ConnectionPool(dsn, min_size=min_size, max_size=max_size, open=True, kwargs=kwargs)


@contextmanager
def scoped(
    pool: ConnectionPool,
    project_id: ProjectId,
    *,
    statement_timeout_ms: int | None = None,
    idle_in_transaction_session_timeout_ms: int | None = None,
) -> Iterator[psycopg.Connection[Any]]:
    """THE only way anything in this codebase obtains a connection inside a transaction that may
    touch a partitioned table (invariant 4). `project_id` is positional and type-required --
    there is no optional/defaulted form of this function. Issues the GUC statement above as the
    first statement of the transaction, before the caller's own SQL runs, then yields the
    connection. RLS FORCE (migrations Task 6) is the backstop if this is ever bypassed by a
    future edit; it must never become the *primary* control -- `raw_sql_lint.py` keeping all SQL
    inside `stores/pg/` is what makes this the only place that can bypass it in the first place.

    `statement_timeout_ms` / `idle_in_transaction_session_timeout_ms`, when given, are issued as
    additional transaction-scoped `set_config` statements right after the RLS GUC (module
    docstring, HARD CANCELLATION point 2) -- `statement_timeout` is Postgres's own server-side
    bound on how long ONE statement in this transaction may run; `idle_in_transaction_session_timeout`
    bounds how long the transaction may sit open without issuing one. Both default to `None` (no
    bound, today's behaviour) so that `stores.pg.search.SearchStore` and `stores.pg.repo.Repo` --
    neither edited by this change -- keep calling `scoped()` exactly as they do today until a
    caller passes one of these explicitly.
    """
    if not isinstance(project_id, ProjectId):
        # mypy --strict is a build-time gate; this is the runtime backstop for anything that
        # reaches here through an `Any`-typed edge (e.g. a dynamically dispatched caller).
        raise TypeError(f"scoped() requires a ProjectId, got {type(project_id).__name__}")
    if statement_timeout_ms is not None and statement_timeout_ms <= 0:
        raise ValueError(f"statement_timeout_ms must be positive, got {statement_timeout_ms!r}")
    if idle_in_transaction_session_timeout_ms is not None and (
        idle_in_transaction_session_timeout_ms <= 0
    ):
        raise ValueError(
            "idle_in_transaction_session_timeout_ms must be positive, got "
            f"{idle_in_transaction_session_timeout_ms!r}"
        )
    with pool.connection() as conn, conn.transaction():
        conn.execute(_SET_PROJECT_GUC, {"project_id": str(project_id)})
        if statement_timeout_ms is not None:
            conn.execute(
                _SET_STATEMENT_TIMEOUT, {"statement_timeout_ms": str(statement_timeout_ms)}
            )
        if idle_in_transaction_session_timeout_ms is not None:
            conn.execute(
                _SET_IDLE_IN_TRANSACTION_TIMEOUT,
                {
                    "idle_in_transaction_session_timeout_ms": str(
                        idle_in_transaction_session_timeout_ms
                    )
                },
            )
        yield conn


@contextmanager
def _unscoped(pool: ConnectionPool) -> Iterator[psycopg.Connection[Any]]:
    """Module-private: registry-table access with no project scope to set (see module docstring).
    Not in `__all__`; `stores.pg.repo` is the only importer.
    """
    with pool.connection() as conn, conn.transaction():
        yield conn
