"""Runtime DB identity and readiness checks for the B3 split processes.

No production listener imports an owner, bootstrap, app, or opposite-process
credential. The checks run on every physical pool connection, then again for
each readiness probe, so a reconnect cannot silently cross the identity
boundary after process startup.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Final

from psycopg import Error
from psycopg_pool import ConnectionPool, PoolTimeout

from tracebed.domain.errors import ConfigError

RuntimeRole = str

_IDENTITY_SQL: Final = (
    "SELECT session_user::text, current_user::text, "
    "current_setting('tracebed.project_id', true)::text"
)
_PREPUBLICATION_READINESS_SQL: Final = "SELECT public.tracebed_runtime_prepublication_readiness()"
_SERVING_READINESS_SQL: Final = "SELECT public.tracebed_runtime_readiness()"
_ERASURE_PREPUBLICATION_READINESS_SQL: Final = (
    "SELECT public.tracebed_erasure_prepublication_readiness()"
)
_ERASURE_SERVING_READINESS_SQL: Final = "SELECT public.tracebed_erasure_readiness()"


def _invalid_runtime_database() -> ConfigError:
    """Keep startup/readiness diagnostics opaque to credentials and catalog state."""

    return ConfigError("runtime database identity or readiness check failed")


def assert_runtime_connection(connection: Any, *, expected_role: RuntimeRole) -> None:
    """Refuse a connection whose authenticated session or cutover state drifts."""

    if expected_role not in {"tracebed_api", "tracebed_worker", "tracebed_erasure"}:
        raise _invalid_runtime_database()
    try:
        row = connection.execute(_IDENTITY_SQL).fetchone()
        if (
            row is None
            or len(row) != 3
            or row[0] != expected_role
            or row[1] != expected_role
            or row[2] not in (None, "")
        ):
            raise _invalid_runtime_database()
        readiness_sql = (
            _ERASURE_PREPUBLICATION_READINESS_SQL
            if expected_role == "tracebed_erasure"
            else _PREPUBLICATION_READINESS_SQL
        )
        connection.execute(readiness_sql).fetchone()
    except ConfigError:
        raise
    except Error:
        raise _invalid_runtime_database() from None


def runtime_pool_configure(expected_role: RuntimeRole) -> Callable[[Any], None]:
    """Return the physical-connection callback used by normal and activity pools."""

    def configure(connection: Any) -> None:
        # psycopg_pool requires a configure callback to return an idle
        # connection. A transaction also ensures no configuration probe can
        # persist a project GUC on a connection that will be reused.
        with connection.transaction():
            assert_runtime_connection(connection, expected_role=expected_role)

    return configure


def probe_runtime_readiness(pool: ConnectionPool, *, expected_role: RuntimeRole) -> None:
    """Check a checked-out connection for dependency-backed /readyz semantics."""

    try:
        # A database restart can leave more than one idle physical connection
        # in the long-lived API/worker pool.  Checking only the connection
        # borrowed below can mark readiness green while the next request is
        # handed a different stale socket.  ``check()`` discards/recreates all
        # invalid idle members before this public serving proof returns.
        pool.check()
        with pool.connection() as connection, connection.transaction():
            assert_runtime_connection(connection, expected_role=expected_role)
            readiness_sql = (
                _ERASURE_SERVING_READINESS_SQL
                if expected_role == "tracebed_erasure"
                else _SERVING_READINESS_SQL
            )
            connection.execute(readiness_sql).fetchone()
    except ConfigError:
        raise
    except (Error, PoolTimeout):
        raise _invalid_runtime_database() from None


def probe_runtime_prepublication_readiness(
    pool: ConnectionPool, *, expected_role: RuntimeRole
) -> None:
    """Prove runtime identity/profile before the controller opens admission.

    This is intentionally not the serving readiness surface: a Compose-v1
    controller needs to start the fixed API and worker processes while the
    durable authority gate is still closed, then perform its final owner open
    as the last publication mutation.
    """

    try:
        with pool.connection() as connection, connection.transaction():
            assert_runtime_connection(connection, expected_role=expected_role)
    except ConfigError:
        raise
    except Error:
        raise _invalid_runtime_database() from None
