"""Project-keyed, nonblocking activity locks for authorized writes.

The activity pool is intentionally distinct from the ordinary RLS pool.  A
waiting or poisoned activity checkout must not consume a connection needed for
normal API/worker work, and advisory locks are always released on the physical
connection that acquired them.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from hashlib import sha256
from math import ceil
from typing import Any, Final

from psycopg.errors import QueryCanceled
from psycopg_pool import ConnectionPool, PoolTimeout

from tracebed.domain.deadline import RemainingBudget
from tracebed.domain.errors import ActivityBusy, ProjectInactive, RequestDeadlineExceeded
from tracebed.domain.ids import ProjectId

__all__ = ["ActivityGate", "activity_lock_key", "create_activity_pool"]

logger = logging.getLogger(__name__)

_ACTIVITY_PREFIX: Final = b"tracebed.activity.v1\0"
_LOCK_SHARED_SQL: Final = "SELECT pg_try_advisory_lock_shared(%(key)s::bigint)"
_LOCK_EXCLUSIVE_SQL: Final = "SELECT pg_try_advisory_lock(%(key)s::bigint)"
_UNLOCK_SHARED_SQL: Final = "SELECT pg_advisory_unlock_shared(%(key)s::bigint)"
_UNLOCK_EXCLUSIVE_SQL: Final = "SELECT pg_advisory_unlock(%(key)s::bigint)"
_PROJECT_ACTIVE_SQL: Final = (
    "SELECT EXISTS(SELECT 1 FROM project WHERE project_id = %(project_id)s "
    "AND status = 'active' AND deleted_at IS NULL)"
)
_RESET_ACTIVITY_LOCKS_SQL: Final = "SELECT pg_advisory_unlock_all()"
_SET_LOCAL_STATEMENT_TIMEOUT_SQL: Final = (
    "SELECT set_config('statement_timeout', %(timeout_ms)s, true)"
)
_SET_LOCAL_LOCK_TIMEOUT_SQL: Final = "SELECT set_config('lock_timeout', %(timeout_ms)s, true)"
_DEFAULT_CLEANUP_TIMEOUT_MS: Final = 5_000


def activity_lock_key(project_id: ProjectId) -> int:
    """Stable signed-64 advisory key for one project's activity lane."""

    if type(project_id) is not ProjectId:
        raise TypeError("project_id must be a ProjectId")
    digest = sha256(_ACTIVITY_PREFIX + project_id.value.bytes).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


def _configure_activity_connection(
    conn: Any, connection_check: Callable[[Any], None] | None
) -> None:
    conn.autocommit = True
    if connection_check is not None:
        connection_check(conn)


def _reset_activity_connection(conn: Any) -> None:
    conn.execute(_RESET_ACTIVITY_LOCKS_SQL)


def create_activity_pool(
    dsn: str,
    *,
    connect_timeout_s: int,
    checkout_timeout_s: float,
    min_size: int = 1,
    max_size: int = 10,
    connection_check: Callable[[Any], None] | None = None,
    checkout_check: Callable[[Any], None] | None = None,
) -> ConnectionPool:
    """Construct the dedicated autocommit advisory-lock pool.

    Positive timeouts are mandatory: admission must return busy rather than
    block behind a stalled connection acquisition.
    """

    if type(connect_timeout_s) is not int or connect_timeout_s <= 0:
        raise ValueError("connect_timeout_s must be positive")
    if type(checkout_timeout_s) not in {float, int} or checkout_timeout_s <= 0:
        raise ValueError("checkout_timeout_s must be positive")
    pool_kwargs: dict[str, Any] = {
        "min_size": min_size,
        "max_size": max_size,
        "open": True,
        "kwargs": {"connect_timeout": connect_timeout_s},
        "timeout": float(checkout_timeout_s),
        "configure": lambda connection: _configure_activity_connection(
            connection, connection_check
        ),
        "reset": _reset_activity_connection,
    }
    if checkout_check is not None:
        pool_kwargs["check"] = checkout_check
    return ConnectionPool(
        dsn,
        **pool_kwargs,
    )


class ActivityGate:
    """Nonblocking shared/exclusive activity ownership under one checkout."""

    def __init__(
        self, pool: ConnectionPool, *, cleanup_timeout_ms: int = _DEFAULT_CLEANUP_TIMEOUT_MS
    ) -> None:
        if type(cleanup_timeout_ms) is not int or cleanup_timeout_ms <= 0:
            raise ValueError("cleanup_timeout_ms must be positive")
        self._pool = pool
        self._cleanup_timeout_ms = cleanup_timeout_ms

    @contextmanager
    def shared(
        self, project_id: ProjectId, *, deadline: RemainingBudget | None = None
    ) -> Iterator[None]:
        with self._hold(project_id, shared=True, deadline=deadline):
            yield

    @contextmanager
    def exclusive(
        self, project_id: ProjectId, *, deadline: RemainingBudget | None = None
    ) -> Iterator[None]:
        with self._hold(project_id, shared=False, deadline=deadline):
            yield

    @contextmanager
    def _hold(
        self, project_id: ProjectId, *, shared: bool, deadline: RemainingBudget | None
    ) -> Iterator[None]:
        if deadline is None:
            with self._hold_unbounded(project_id, shared=shared):
                yield
            return
        with self._hold_bounded(project_id, shared=shared, deadline=deadline):
            yield

    @contextmanager
    def _hold_unbounded(self, project_id: ProjectId, *, shared: bool) -> Iterator[None]:
        key = activity_lock_key(project_id)
        try:
            checkout = self._pool.connection()
            conn_context = checkout
            conn = conn_context.__enter__()
        except PoolTimeout:
            raise ActivityBusy() from None

        acquired = False
        body_error: BaseException | None = None
        try:
            try:
                lock_sql = _LOCK_SHARED_SQL if shared else _LOCK_EXCLUSIVE_SQL
                row = conn.execute(lock_sql, {"key": key}).fetchone()
                if row is None or row[0] is not True:
                    raise ActivityBusy()
                acquired = True
                active_row = conn.execute(
                    _PROJECT_ACTIVE_SQL, {"project_id": project_id.value}
                ).fetchone()
                if active_row is None or active_row[0] is not True:
                    # One release attempt only.  It closes the physical
                    # connection if that release fails, and the outer cleanup
                    # still returns the checkout to pool bookkeeping.
                    acquired = False
                    self._unlock_or_close(conn, key, shared=shared, body_error=None)
                    raise ProjectInactive()
                yield
            except BaseException as exc:
                body_error = exc
                raise
            finally:
                if acquired:
                    self._unlock_or_close(conn, key, shared=shared, body_error=body_error)
        finally:
            conn_context.__exit__(
                type(body_error) if body_error is not None else None,
                body_error,
                body_error.__traceback__ if body_error is not None else None,
            )

    @contextmanager
    def _hold_bounded(
        self, project_id: ProjectId, *, shared: bool, deadline: RemainingBudget
    ) -> Iterator[None]:
        """Acquire a session advisory lock under short, local-GUC transactions.

        The advisory lock itself survives the acquisition transaction and is retained on this
        checked-out connection until the caller exits. Cleanup uses a fixed *per-statement* bound:
        it is intentionally independent of an already-expired request budget and does not claim a
        whole-cleanup wall-clock guarantee.
        """
        key = activity_lock_key(project_id)
        remaining_ms = deadline.remaining_ms()
        if remaining_ms <= 0:
            raise RequestDeadlineExceeded("request deadline expired before activity pool checkout")
        remaining_s = remaining_ms / 1000.0
        checkout_timeout = min(float(self._pool.timeout), remaining_s)
        acquired = False
        lock_attempted = False
        confirmed_not_acquired = False
        acquisition_complete = False
        body_error: BaseException | None = None
        try:
            connection = self._pool.connection(timeout=checkout_timeout)
        except PoolTimeout:
            if deadline.remaining_ms() <= 0:
                raise RequestDeadlineExceeded() from None
            raise ActivityBusy() from None
        with ExitStack() as stack:
            try:
                conn = stack.enter_context(connection)
            except PoolTimeout:
                if deadline.remaining_ms() <= 0:
                    raise RequestDeadlineExceeded() from None
                raise ActivityBusy() from None
            self._require_remaining(deadline, "after activity pool checkout")
            try:
                with conn.transaction():
                    self._arm_local_deadline_timeouts(conn, deadline)
                    self._require_remaining(deadline, "before activity lock acquisition")
                    lock_attempted = True
                    lock_sql = _LOCK_SHARED_SQL if shared else _LOCK_EXCLUSIVE_SQL
                    row = conn.execute(lock_sql, {"key": key}).fetchone()
                    if row is not None and row[0] is False:
                        confirmed_not_acquired = True
                        raise ActivityBusy()
                    if row is None or row[0] is not True:
                        raise RuntimeError("activity lock acquisition returned malformed result")
                    acquired = True
                    self._require_remaining(deadline, "after activity lock acquisition")
                    self._arm_local_deadline_timeouts(conn, deadline)
                    self._require_remaining(deadline, "before project activity check")
                    active_row = conn.execute(
                        _PROJECT_ACTIVE_SQL, {"project_id": project_id.value}
                    ).fetchone()
                    if active_row is None or active_row[0] is not True:
                        raise ProjectInactive()
                    self._require_remaining(deadline, "before activity gate yield")
                self._require_remaining(deadline, "after activity acquisition transaction")
                acquisition_complete = True
                yield
            except BaseException as exc:
                body_error = exc
                if lock_attempted and not acquired and not confirmed_not_acquired:
                    # A failed lock command can have an unknown server-side outcome.  Do not
                    # unlock a lock we never observed, and do not return its connection to pool.
                    self._close_connection(conn)
                if (
                    not acquisition_complete
                    and isinstance(exc, QueryCanceled)
                    and deadline.remaining_ms() <= 0
                ):
                    raise RequestDeadlineExceeded() from exc
                raise
            finally:
                if acquired:
                    self._cleanup_unlock_or_close(conn, key, shared=shared, body_error=body_error)

    @staticmethod
    def _require_remaining(deadline: RemainingBudget, stage: str) -> None:
        if deadline.remaining_ms() <= 0:
            raise RequestDeadlineExceeded(f"request deadline expired {stage}")

    def _arm_local_deadline_timeouts(self, conn: Any, deadline: RemainingBudget) -> None:
        for sql in (_SET_LOCAL_LOCK_TIMEOUT_SQL, _SET_LOCAL_STATEMENT_TIMEOUT_SQL):
            self._require_remaining(deadline, "before activity timeout setup")
            timeout_ms = max(1, ceil(deadline.remaining_ms()))
            conn.execute(sql, {"timeout_ms": str(timeout_ms)})
            self._require_remaining(deadline, "during activity timeout setup")

    def _cleanup_unlock_or_close(
        self,
        conn: Any,
        key: int,
        *,
        shared: bool,
        body_error: BaseException | None,
    ) -> None:
        unlock_sql = _UNLOCK_SHARED_SQL if shared else _UNLOCK_EXCLUSIVE_SQL
        try:
            with conn.transaction():
                timeout = {"timeout_ms": str(self._cleanup_timeout_ms)}
                conn.execute(_SET_LOCAL_LOCK_TIMEOUT_SQL, timeout)
                conn.execute(_SET_LOCAL_STATEMENT_TIMEOUT_SQL, timeout)
                row = conn.execute(unlock_sql, {"key": key}).fetchone()
                if row is None or row[0] is not True:
                    raise RuntimeError("activity lock release failed")
        except Exception:
            self._close_connection(conn)
            logger.error("activity lock release failed")
            if body_error is None:
                raise RuntimeError("activity lock release failed") from None

    @staticmethod
    def _close_connection(conn: Any) -> None:
        try:
            conn.close()
        except Exception:
            logger.error("activity connection close failed")

    def _unlock_or_close(
        self,
        conn: Any,
        key: int,
        *,
        shared: bool,
        body_error: BaseException | None,
    ) -> None:
        unlock_sql = _UNLOCK_SHARED_SQL if shared else _UNLOCK_EXCLUSIVE_SQL
        try:
            row = conn.execute(unlock_sql, {"key": key}).fetchone()
            if row is None or row[0] is not True:
                raise RuntimeError("activity lock release failed")
        except Exception:
            self._close_connection(conn)
            logger.error("activity lock release failed")
            if body_error is None:
                raise RuntimeError("activity lock release failed") from None
