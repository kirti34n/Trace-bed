"""Offline activity-lock semantics; live races are separately environment-gated."""

from __future__ import annotations

import inspect
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from uuid import UUID

import pytest
from psycopg.errors import QueryCanceled
from psycopg_pool import PoolTimeout

from tracebed.domain.errors import ActivityBusy, ProjectInactive, RequestDeadlineExceeded
from tracebed.domain.ids import ProjectId
from tracebed.stores.pg import activity as activity_module
from tracebed.stores.pg.activity import (
    _LOCK_EXCLUSIVE_SQL,
    _LOCK_SHARED_SQL,
    _RESET_ACTIVITY_LOCKS_SQL,
    ActivityGate,
    activity_lock_key,
    create_activity_pool,
)

pytestmark = pytest.mark.phase3


class _Result:
    def __init__(self, value: bool) -> None:
        self._value = value

    def fetchone(self) -> tuple[bool]:
        return (self._value,)


class _Conn:
    def __init__(self, results: list[bool], *, error_at: int | None = None) -> None:
        self.results = results
        self.sql: list[str] = []
        self.closed = False
        self.calls = 0
        self.error_at = error_at

    def execute(self, sql: str, _params: object = None) -> _Result:
        self.sql.append(sql)
        self.calls += 1
        if self.calls == self.error_at:
            raise OSError("infrastructure failure")
        return _Result(self.results.pop(0))

    def close(self) -> None:
        self.closed = True


class _Pool:
    def __init__(self, conn: _Conn) -> None:
        self.conn = conn
        self.enters = 0
        self.exits = 0

    @contextmanager
    def connection(self) -> Iterator[_Conn]:
        self.enters += 1
        try:
            yield self.conn
        finally:
            self.exits += 1


class _Budget:
    def __init__(self, remaining: float) -> None:
        self.remaining = remaining

    def remaining_ms(self) -> float:
        return self.remaining


class _BudgetConn(_Conn):
    def __init__(
        self,
        results: list[bool],
        *,
        on_execute: Callable[[str], None] | None = None,
        on_transaction_exit: Callable[[int], None] | None = None,
        error_at: int | None = None,
    ) -> None:
        super().__init__(results, error_at=error_at)
        self.on_execute = on_execute
        self.on_transaction_exit = on_transaction_exit
        self.params: list[object] = []
        self.transaction_enters = 0
        self.transaction_exits = 0

    def execute(self, sql: str, params: object = None) -> _Result:
        self.sql.append(sql)
        self.params.append(params)
        self.calls += 1
        if self.calls == self.error_at:
            raise OSError("infrastructure failure")
        if self.on_execute is not None:
            self.on_execute(sql)
        if sql in {
            _LOCK_SHARED_SQL,
            _LOCK_EXCLUSIVE_SQL,
            activity_module._PROJECT_ACTIVE_SQL,
            activity_module._UNLOCK_SHARED_SQL,
            activity_module._UNLOCK_EXCLUSIVE_SQL,
        }:
            return _Result(self.results.pop(0))
        return _Result(True)

    @contextmanager
    def transaction(self) -> Iterator[_BudgetConn]:
        self.transaction_enters += 1
        try:
            yield self
        finally:
            self.transaction_exits += 1
            if self.on_transaction_exit is not None:
                self.on_transaction_exit(self.transaction_exits)


class _BudgetPool:
    def __init__(self, conn: _BudgetConn, *, timeout: float = 1.0) -> None:
        self.conn = conn
        self.timeout = timeout
        self.timeouts: list[float | None] = []
        self.enters = 0
        self.exits = 0

    @contextmanager
    def connection(self, *, timeout: float | None = None) -> Iterator[_BudgetConn]:
        self.timeouts.append(timeout)
        self.enters += 1
        try:
            yield self.conn
        finally:
            self.exits += 1


def test_activity_key_has_the_pinned_signed_64_vector() -> None:
    project_id = ProjectId(UUID("12345678-1234-5678-1234-567812345678"))
    assert activity_lock_key(project_id) == -3071229134531699503


def test_try_lock_false_is_busy_without_discarding_a_connection() -> None:
    conn = _Conn([False])
    gate = ActivityGate(_Pool(conn))  # type: ignore[arg-type]
    with pytest.raises(ActivityBusy), gate.shared(ProjectId(UUID(int=1))):
        pass
    assert conn.closed is False
    assert conn.sql == [_LOCK_SHARED_SQL]


class _PoolTimeout:
    def connection(self) -> object:
        raise PoolTimeout()


class _BrokenPool:
    def connection(self) -> object:
        raise OSError("checkout failed")


def test_checkout_timeout_is_busy_but_infrastructure_checkout_failure_propagates() -> None:
    with pytest.raises(ActivityBusy), ActivityGate(_PoolTimeout()).shared(ProjectId(UUID(int=19))):  # type: ignore[arg-type]
        pass
    with (
        pytest.raises(OSError, match="checkout failed"),
        ActivityGate(_BrokenPool()).exclusive(  # type: ignore[arg-type]
            ProjectId(UUID(int=20))
        ),
    ):
        pass


def test_inactive_project_unlocks_before_opaque_denial() -> None:
    conn = _Conn([True, False, True])
    gate = ActivityGate(_Pool(conn))  # type: ignore[arg-type]
    with pytest.raises(ProjectInactive), gate.exclusive(ProjectId(UUID(int=2))):
        pass
    assert "deleted_at IS NULL" in conn.sql[1]
    assert "pg_advisory_unlock" in conn.sql[2]


def test_inactive_unlock_failure_has_one_release_attempt_and_checks_connection_back_in() -> None:
    conn = _Conn([True, False], error_at=3)
    pool = _Pool(conn)
    gate = ActivityGate(pool)  # type: ignore[arg-type]
    with (
        pytest.raises(RuntimeError, match="activity lock release failed"),
        gate.exclusive(ProjectId(UUID(int=21))),
    ):
        pass
    assert conn.closed is True
    assert conn.calls == 3
    assert pool.exits == 1


def test_unlock_failure_discards_connection_and_preserves_body_error() -> None:
    conn = _Conn([True, True, False])
    pool = _Pool(conn)
    gate = ActivityGate(pool)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="body"), gate.shared(ProjectId(UUID(int=3))):
        raise ValueError("body")
    assert conn.closed is True
    assert pool.exits == 1

    execute_error = _Conn([True, True], error_at=3)
    execute_error_pool = _Pool(execute_error)
    execute_error_gate = ActivityGate(execute_error_pool)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="body"), execute_error_gate.shared(ProjectId(UUID(int=5))):
        raise ValueError("body")
    assert execute_error.closed is True
    assert execute_error_pool.exits == 1


def test_pool_factory_configures_autocommit_and_reset_unlocks_all(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: dict[str, object] = {}

    class _Factory:
        def __call__(self, dsn: str, **kwargs: object) -> object:
            calls["dsn"] = dsn
            calls.update(kwargs)
            return object()

    monkeypatch.setattr(activity_module, "ConnectionPool", _Factory())
    assert (
        create_activity_pool("postgresql://example", connect_timeout_s=2, checkout_timeout_s=1.5)
        is not None
    )
    assert calls["kwargs"] == {"connect_timeout": 2}
    assert calls["timeout"] == 1.5
    assert calls["max_size"] == 10

    class _Configured:
        autocommit = False

        def __init__(self) -> None:
            self.sql: list[str] = []

        def execute(self, sql: str) -> None:
            self.sql.append(sql)

    conn = _Configured()
    configure = calls["configure"]
    reset = calls["reset"]
    assert callable(configure) and callable(reset)
    configure(conn)
    reset(conn)
    assert conn.autocommit is True
    assert conn.sql == [_RESET_ACTIVITY_LOCKS_SQL]

    class _ResetFails(_Configured):
        def execute(self, _sql: str) -> None:
            raise OSError("reset error")

    with pytest.raises(OSError, match="reset error"):
        reset(_ResetFails())


def test_activity_gate_uses_exact_nonblocking_sql_without_polling() -> None:
    assert _LOCK_SHARED_SQL == "SELECT pg_try_advisory_lock_shared(%(key)s::bigint)"
    assert _LOCK_EXCLUSIVE_SQL == "SELECT pg_try_advisory_lock(%(key)s::bigint)"
    assert "sleep(" not in inspect.getsource(ActivityGate)

    conn = _Conn([True, True, False])
    pool = _Pool(conn)
    gate = ActivityGate(pool)  # type: ignore[arg-type]
    with (
        pytest.raises(RuntimeError, match="activity lock release failed"),
        gate.shared(ProjectId(UUID(int=4))),
    ):
        pass
    assert conn.closed is True
    assert pool.exits == 1


def test_budgeted_activity_gate_checks_preexpiry_without_checkout_or_sql() -> None:
    conn = _BudgetConn([True, True, True])
    pool = _BudgetPool(conn)

    with (
        pytest.raises(RequestDeadlineExceeded),
        ActivityGate(pool).shared(  # type: ignore[arg-type]
            ProjectId(UUID(int=30)), deadline=_Budget(0.0)
        ),
    ):
        pass

    assert pool.timeouts == []
    assert conn.sql == []
    assert conn.transaction_enters == 0


def test_budgeted_activity_gate_clamps_checkout_and_uses_two_short_local_transactions() -> None:
    conn = _BudgetConn([True, True, True])
    pool = _BudgetPool(conn, timeout=0.050)

    with ActivityGate(pool).shared(ProjectId(UUID(int=31)), deadline=_Budget(123.0)):  # type: ignore[arg-type]
        assert conn.transaction_enters == 1
        assert conn.transaction_exits == 1

    assert pool.timeouts == [0.050]
    assert conn.transaction_enters == conn.transaction_exits == 2
    assert conn.sql == [
        activity_module._SET_LOCAL_LOCK_TIMEOUT_SQL,
        activity_module._SET_LOCAL_STATEMENT_TIMEOUT_SQL,
        _LOCK_SHARED_SQL,
        activity_module._SET_LOCAL_LOCK_TIMEOUT_SQL,
        activity_module._SET_LOCAL_STATEMENT_TIMEOUT_SQL,
        activity_module._PROJECT_ACTIVE_SQL,
        activity_module._SET_LOCAL_LOCK_TIMEOUT_SQL,
        activity_module._SET_LOCAL_STATEMENT_TIMEOUT_SQL,
        activity_module._UNLOCK_SHARED_SQL,
    ]


def test_budgeted_activity_checkout_timeout_is_busy_only_while_budget_remains() -> None:
    class TimeoutPool:
        timeout = 1.0

        def connection(self, *, timeout: float | None = None) -> object:
            assert timeout == pytest.approx(0.123)
            raise PoolTimeout("pool exhausted")

    with (
        pytest.raises(ActivityBusy),
        ActivityGate(TimeoutPool()).shared(  # type: ignore[arg-type]
            ProjectId(UUID(int=311)), deadline=_Budget(123.0)
        ),
    ):
        pass


def test_budgeted_activity_samples_checkout_budget_once_before_lazy_enter() -> None:
    class AdvancingBudget:
        def __init__(self) -> None:
            self.calls = 0

        def remaining_ms(self) -> float:
            self.calls += 1
            return 123.0 if self.calls == 1 else 0.0

    conn = _BudgetConn([True, True, True])
    pool = _BudgetPool(conn)
    budget = AdvancingBudget()

    with (
        pytest.raises(RequestDeadlineExceeded),
        ActivityGate(pool).shared(  # type: ignore[arg-type]
            ProjectId(UUID(int=312)), deadline=budget
        ),
    ):
        pass

    assert pool.timeouts == [0.123]

    budget = _Budget(123.0)

    class ExpiringTimeout:
        def __enter__(self) -> object:
            budget.remaining = 0.0
            raise PoolTimeout("deadline exhausted")

        def __exit__(self, *exc: object) -> None:
            return None

    class ExpiringPool:
        timeout = 1.0

        def connection(self, *, timeout: float | None = None) -> ExpiringTimeout:
            assert timeout == pytest.approx(0.123)
            return ExpiringTimeout()

    with (
        pytest.raises(RequestDeadlineExceeded),
        ActivityGate(ExpiringPool()).shared(  # type: ignore[arg-type]
            ProjectId(UUID(int=312)), deadline=budget
        ),
    ):
        pass


def test_budgeted_activity_false_lock_is_busy_and_keeps_a_healthy_connection() -> None:
    conn = _BudgetConn([False])
    pool = _BudgetPool(conn)

    with (
        pytest.raises(ActivityBusy),
        ActivityGate(pool).shared(  # type: ignore[arg-type]
            ProjectId(UUID(int=313)), deadline=_Budget(123.0)
        ),
    ):
        pass

    assert conn.closed is False
    assert activity_module._UNLOCK_SHARED_SQL not in conn.sql
    assert conn.transaction_enters == conn.transaction_exits == 1


def test_budgeted_activity_refreshes_local_timeout_before_project_query() -> None:
    budget = _Budget(123.0)

    def narrow_after_lock(sql: str) -> None:
        if sql == _LOCK_SHARED_SQL:
            budget.remaining = 37.0

    conn = _BudgetConn([True, True, True], on_execute=narrow_after_lock)
    pool = _BudgetPool(conn)

    with ActivityGate(pool).shared(ProjectId(UUID(int=314)), deadline=budget):  # type: ignore[arg-type]
        pass

    assert conn.params[:5] == [
        {"timeout_ms": "123"},
        {"timeout_ms": "123"},
        {"key": activity_lock_key(ProjectId(UUID(int=314)))},
        {"timeout_ms": "37"},
        {"timeout_ms": "37"},
    ]


def test_budgeted_activity_expiry_during_acquisition_commit_never_yields() -> None:
    budget = _Budget(123.0)

    def expire_after_first_transaction(exit_count: int) -> None:
        if exit_count == 1:
            budget.remaining = 0.0

    conn = _BudgetConn([True, True, True], on_transaction_exit=expire_after_first_transaction)
    pool = _BudgetPool(conn)
    yielded = False

    with (
        pytest.raises(RequestDeadlineExceeded),
        ActivityGate(pool).shared(  # type: ignore[arg-type]
            ProjectId(UUID(int=315)), deadline=budget
        ),
    ):
        yielded = True

    assert yielded is False
    assert activity_module._UNLOCK_SHARED_SQL in conn.sql


def test_budgeted_activity_translates_only_expired_acquisition_query_cancellation() -> None:
    budget = _Budget(123.0)
    cancellation = QueryCanceled("statement cancelled")

    def cancel_after_expiry(sql: str) -> None:
        if sql == activity_module._PROJECT_ACTIVE_SQL:
            budget.remaining = 0.0
            raise cancellation

    conn = _BudgetConn([True, True], on_execute=cancel_after_expiry)
    pool = _BudgetPool(conn)
    with (
        pytest.raises(RequestDeadlineExceeded) as raised,
        ActivityGate(pool).shared(  # type: ignore[arg-type]
            ProjectId(UUID(int=316)), deadline=budget
        ),
    ):
        pass
    assert raised.value.__cause__ is cancellation
    assert activity_module._UNLOCK_SHARED_SQL in conn.sql

    early = QueryCanceled("manual cancellation")

    def cancel_early(sql: str) -> None:
        if sql == activity_module._PROJECT_ACTIVE_SQL:
            raise early

    early_conn = _BudgetConn([True, True], on_execute=cancel_early)
    with (
        pytest.raises(QueryCanceled) as early_raised,
        ActivityGate(_BudgetPool(early_conn)).shared(  # type: ignore[arg-type]
            ProjectId(UUID(int=317)), deadline=_Budget(123.0)
        ),
    ):
        pass
    assert early_raised.value is early


def test_budgeted_activity_discards_unknown_lock_cancellation_before_translation() -> None:
    budget = _Budget(123.0)
    expired_lock_cancel = QueryCanceled("lock cancellation")

    def cancel_lock_after_expiry(sql: str) -> None:
        if sql == _LOCK_SHARED_SQL:
            budget.remaining = 0.0
            raise expired_lock_cancel

    conn = _BudgetConn([True], on_execute=cancel_lock_after_expiry)
    yielded = False
    with (
        pytest.raises(RequestDeadlineExceeded) as raised,
        ActivityGate(_BudgetPool(conn)).shared(  # type: ignore[arg-type]
            ProjectId(UUID(int=319)), deadline=budget
        ),
    ):
        yielded = True
    assert raised.value.__cause__ is expired_lock_cancel
    assert yielded is False
    assert conn.closed is True
    assert activity_module._UNLOCK_SHARED_SQL not in conn.sql

    early_lock_cancel = QueryCanceled("manual lock cancellation")

    def cancel_lock_early(sql: str) -> None:
        if sql == _LOCK_SHARED_SQL:
            raise early_lock_cancel

    early_conn = _BudgetConn([True], on_execute=cancel_lock_early)
    with (
        pytest.raises(QueryCanceled) as early_raised,
        ActivityGate(_BudgetPool(early_conn)).shared(  # type: ignore[arg-type]
            ProjectId(UUID(int=320)), deadline=_Budget(123.0)
        ),
    ):
        pass
    assert early_raised.value is early_lock_cancel
    assert early_conn.closed is True
    assert activity_module._UNLOCK_SHARED_SQL not in early_conn.sql


def test_budgeted_activity_never_reclassifies_a_body_cancellation_after_expiry() -> None:
    budget = _Budget(123.0)
    body_error = QueryCanceled("body cancellation")
    conn = _BudgetConn([True, True, True])

    with (
        pytest.raises(QueryCanceled) as raised,
        ActivityGate(_BudgetPool(conn)).shared(  # type: ignore[arg-type]
            ProjectId(UUID(int=318)), deadline=budget
        ),
    ):
        budget.remaining = 0.0
        raise body_error

    assert raised.value is body_error
    assert activity_module._UNLOCK_SHARED_SQL in conn.sql


def test_budgeted_activity_gate_expiry_after_acquisition_never_yields_and_cleans_up() -> None:
    budget = _Budget(123.0)

    def expire_after_lock(sql: str) -> None:
        if sql == _LOCK_SHARED_SQL:
            budget.remaining = 0.0

    conn = _BudgetConn([True, True, True], on_execute=expire_after_lock)
    pool = _BudgetPool(conn)
    yielded = False

    with (
        pytest.raises(RequestDeadlineExceeded),
        ActivityGate(pool).shared(  # type: ignore[arg-type]
            ProjectId(UUID(int=32)), deadline=budget
        ),
    ):
        yielded = True

    assert yielded is False
    assert activity_module._UNLOCK_SHARED_SQL in conn.sql
    assert conn.closed is False


def test_budgeted_activity_gate_unknown_lock_result_closes_without_unlocking() -> None:
    conn = _BudgetConn([True, True], error_at=3)
    pool = _BudgetPool(conn)

    with (
        pytest.raises(OSError, match="infrastructure failure"),
        ActivityGate(pool).shared(  # type: ignore[arg-type]
            ProjectId(UUID(int=33)), deadline=_Budget(123.0)
        ),
    ):
        pass

    assert conn.closed is True
    assert activity_module._UNLOCK_SHARED_SQL not in conn.sql


def test_budgeted_activity_gate_preserves_body_pool_timeout_and_releases_lock() -> None:
    conn = _BudgetConn([True, True, True])
    pool = _BudgetPool(conn)
    body_error = PoolTimeout("body timeout")

    with (
        pytest.raises(PoolTimeout) as raised,
        ActivityGate(pool).shared(  # type: ignore[arg-type]
            ProjectId(UUID(int=34)), deadline=_Budget(123.0)
        ),
    ):
        raise body_error

    assert raised.value is body_error
    assert activity_module._UNLOCK_SHARED_SQL in conn.sql


def test_budgeted_activity_cleanup_failure_closes_connection_and_preserves_body_error() -> None:
    conn = _BudgetConn([True, True], error_at=7)
    pool = _BudgetPool(conn)

    with (
        pytest.raises(ValueError, match="body"),
        ActivityGate(pool).shared(  # type: ignore[arg-type]
            ProjectId(UUID(int=35)), deadline=_Budget(123.0)
        ),
    ):
        raise ValueError("body")

    assert conn.closed is True


def test_activity_gate_rejects_nonpositive_cleanup_timeout() -> None:
    with pytest.raises(ValueError, match="cleanup_timeout_ms"):
        ActivityGate(_Pool(_Conn([])), cleanup_timeout_ms=0)  # type: ignore[arg-type]
