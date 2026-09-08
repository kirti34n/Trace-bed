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
in ``__all__``; the registry-bound ``stores.pg.repo`` and
``stores.pg.authority.AuthorityStore`` are its only importers, each with explicit
project/principal predicates.

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

BOTH DEFAULT TO ``None`` (NO TIMEOUT), preserving historical non-request callers. Request paths
may instead pass a shared ``RemainingBudget`` to ``scoped()`` or ``_unscoped()``. Those helpers
bound pool checkout to the remaining allowance and require a fresh transaction-local statement
timeout before each caller-owned data statement. This is cooperative accounting, not strict native
cancellation: a pool health check, connection setup, or query already under way can outlive the
caller waiting for it.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from math import ceil
from typing import Any, Final

import psycopg
from psycopg import postgres, pq
from psycopg.abc import Buffer
from psycopg.adapt import Dumper
from psycopg.errors import QueryCanceled
from psycopg_pool import ConnectionPool, PoolTimeout

from tracebed.domain.deadline import RemainingBudget as RemainingBudget
from tracebed.domain.ids import ProjectId, TypedId

__all__ = ["create_pool", "register_typed_id_adapters", "scoped"]


class PoolDeadlineExceeded(TimeoutError):
    """The caller's retrieval deadline elapsed before a scoped statement could start."""


def is_expired_deadline_query_cancellation(
    exc: BaseException, deadline: RemainingBudget | None
) -> bool:
    """Identify a PostgreSQL cancellation observed while this request is expired.

    PostgreSQL uses ``QueryCanceled`` for both statement-timeout and manual
    cancellation, so this cannot establish the original cause of the error.
    Callers use it only when the request deadline is already exhausted.
    """
    return isinstance(exc, QueryCanceled) and deadline is not None and deadline.remaining_ms() <= 0


def refresh_deadline_statement_timeout(
    conn: psycopg.Connection[Any], deadline: RemainingBudget
) -> None:
    """Apply the remaining request budget immediately before a data statement.

    Checkout and setup SQL consume time too.  Refreshing after that work prevents a SELECT from
    inheriting a stale, wider timeout; an exhausted deadline starts no further statement.
    """
    remaining_ms = deadline.remaining_ms()
    if remaining_ms <= 0:
        raise PoolDeadlineExceeded("retrieval deadline expired before data statement")
    conn.execute(_SET_STATEMENT_TIMEOUT, {"statement_timeout_ms": str(max(1, ceil(remaining_ms)))})
    if deadline.remaining_ms() <= 0:
        raise PoolDeadlineExceeded("retrieval deadline expired while refreshing statement timeout")


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
# This dumper resolution needs no database at all, so
# `tests/phase0/test_repo_isolation_offline.py::test_typed_ids_are_adaptable_by_psycopg`
# exercises it directly and catches a missing registration whether or not a live Postgres is
# reachable -- it does not depend on a stack being present or absent.
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
    configure: Callable[[Any], None] | None = None,
    checkout_check: Callable[[Any], None] | None = None,
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
    pool_kwargs: dict[str, Any] = {
        "min_size": min_size,
        "max_size": max_size,
        "open": True,
        "kwargs": kwargs,
    }
    if configure is not None:
        pool_kwargs["configure"] = configure
    if checkout_check is not None:
        # Runtime pools opt into libpq's fresh checkout probe so a Postgres
        # restart cannot leave a stale idle socket for the next API request.
        # Keep it explicit: hot-path/offline callers retain their established
        # checkout cost unless their runtime boundary requires this recovery.
        pool_kwargs["check"] = checkout_check
    if checkout_timeout_s is not None:
        if checkout_timeout_s <= 0:
            raise ValueError(f"checkout_timeout_s must be positive, got {checkout_timeout_s!r}")
        pool_kwargs["timeout"] = checkout_timeout_s
    return ConnectionPool(dsn, **pool_kwargs)


@contextmanager
def scoped(
    pool: ConnectionPool,
    project_id: ProjectId,
    *,
    statement_timeout_ms: int | None = None,
    idle_in_transaction_session_timeout_ms: int | None = None,
    deadline: RemainingBudget | None = None,
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
    if deadline is not None and statement_timeout_ms is not None:
        raise ValueError("deadline and statement_timeout_ms are mutually exclusive")
    if deadline is None:
        connection = pool.connection()
    else:
        remaining_ms = deadline.remaining_ms()
        if remaining_ms <= 0:
            raise PoolDeadlineExceeded("retrieval deadline expired before pool checkout")
        connection = pool.connection(timeout=remaining_ms / 1000.0)
    with ExitStack() as stack:
        try:
            conn = stack.enter_context(connection)
        except PoolTimeout as exc:
            if deadline is None:
                raise
            raise PoolDeadlineExceeded("pool checkout exceeded retrieval deadline") from exc
        if deadline is not None:
            # The wait for a pooled connection consumes the same request budget.  PostgreSQL
            # treats zero as unlimited, so do not begin a transaction in that case.
            remaining_ms = deadline.remaining_ms()
            if remaining_ms <= 0:
                raise PoolDeadlineExceeded("retrieval deadline expired during pool checkout")
            statement_timeout_ms = max(1, ceil(remaining_ms))
        with conn.transaction():
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
def _unscoped(
    pool: ConnectionPool, *, deadline: RemainingBudget | None = None
) -> Iterator[psycopg.Connection[Any]]:
    """Open a registry-table transaction without setting a project GUC.

    The default path intentionally retains the historical unbounded checkout and transaction
    behavior.  A caller that supplies ``deadline`` gets a cooperative bound on pool checkout and
    an expiry guard before work is yielded.  This helper deliberately issues *no* setup SQL:
    callers that require transaction characteristics must establish those first, then call
    :func:`refresh_deadline_statement_timeout` immediately before each data query.  In
    particular, ``AuthorityStore`` must issue its ``SET TRANSACTION ... READ ONLY`` before any
    timeout ``set_config`` statement, because PostgreSQL rejects changing transaction
    characteristics after a query has started a snapshot.
    """
    if deadline is None:
        with pool.connection() as conn, conn.transaction():
            yield conn
        return

    remaining_ms = deadline.remaining_ms()
    if remaining_ms <= 0:
        raise PoolDeadlineExceeded("request deadline expired before pool checkout")
    connection = pool.connection(timeout=remaining_ms / 1000.0)
    with ExitStack() as stack:
        try:
            conn = stack.enter_context(connection)
        except PoolTimeout as exc:
            # ``ConnectionPool.connection`` returns a lazy context manager.  Restrict this
            # translation to its enter operation so a PoolTimeout raised by a query/body keeps
            # its original identity.
            raise PoolDeadlineExceeded("pool checkout exceeded request deadline") from exc
        if deadline.remaining_ms() <= 0:
            raise PoolDeadlineExceeded("request deadline expired during pool checkout")
        with conn.transaction():
            # Starting a transaction can itself consume the final budget.  Do not hand a
            # connection to a caller after that happens.
            if deadline.remaining_ms() <= 0:
                raise PoolDeadlineExceeded("request deadline expired during transaction entry")
            yield conn
