"""Offline contracts for the future durable grant and run-owner stores."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from uuid import uuid4

import pytest
from psycopg.errors import QueryCanceled
from psycopg_pool import PoolTimeout

from tracebed.domain.authority import AccessContext, GrantBinding
from tracebed.domain.enums import FeedbackSource, ProjectRole, RunOrigin
from tracebed.domain.errors import (
    AuthorizationDenied,
    ErasureFenced,
    RequestDeadlineExceeded,
    RunAuthorityDenied,
    TracebedError,
)
from tracebed.domain.ids import AgentTypeId, PrincipalId, ProjectId, RunId
from tracebed.stores.pg import pool as pool_module
from tracebed.stores.pg.authority import (
    _REQUIRE_ACTIVE_GRANT_SQL,
    _RESOLVE_ACCESS_SQL,
    _RESOLVE_SNAPSHOT_SQL,
    _RUN_OWNER_INSERT_SQL,
    _RUN_OWNER_SELECT_SQL,
    AuthorityStore,
    AuthorizedRetrievalOpener,
    RunAuthorityStore,
)

pytestmark = pytest.mark.phase3


def _ids() -> tuple[ProjectId, AgentTypeId, PrincipalId, RunId]:
    return ProjectId(uuid4()), AgentTypeId(uuid4()), PrincipalId(uuid4()), RunId(uuid4())


def _row(
    project_id: ProjectId,
    agent_type_id: AgentTypeId,
    principal_id: PrincipalId,
    *,
    role: str = "data",
    feedback_source: str | None = None,
) -> dict[str, object]:
    return {
        "project_id": project_id.value,
        "agent_type_id": agent_type_id.value,
        "principal_id": principal_id.value,
        "grant_id": uuid4(),
        "role": role,
        "feedback_source": feedback_source,
    }


def test_authority_sql_uses_the_narrow_definer_recheck_for_mutating_decisions() -> None:
    for sql in (_RESOLVE_ACCESS_SQL,):
        assert "g.project_id = ar.project_id" in sql
        assert "g.principal_id = pr.principal_id" in sql
        assert "g.agent_type_id" not in sql
        assert "ar.revoked_at IS NULL" in sql
        assert "p.deleted_at IS NULL" in sql
    assert "public.tracebed_require_active_grant" in _REQUIRE_ACTIVE_GRANT_SQL
    assert "FOR SHARE" not in _REQUIRE_ACTIVE_GRANT_SQL
    assert "%(feedback_source)s::text" in _REQUIRE_ACTIVE_GRANT_SQL
    assert "REPEATABLE READ" in _RESOLVE_SNAPSHOT_SQL.upper()


def test_resolved_access_is_fail_closed_for_duplicate_or_malformed_rows() -> None:
    project_id, agent_type_id, principal_id, _run_id = _ids()
    row = _row(project_id, agent_type_id, principal_id)
    access = AuthorityStore._access_from_rows(principal_id, [row])
    assert access.project_id == project_id
    assert access.grant_for(ProjectRole.DATA) is not None

    duplicate = dict(row)
    duplicate["grant_id"] = uuid4()
    with pytest.raises(AuthorizationDenied):
        AuthorityStore._access_from_rows(principal_id, [row, duplicate])
    duplicate_id = dict(row)
    duplicate_id["role"] = "feedback"
    duplicate_id["feedback_source"] = "verdict"
    with pytest.raises(AuthorizationDenied) as error:
        AuthorityStore._access_from_rows(principal_id, [row, duplicate_id])
    assert error.value.__cause__ is None
    assert "grant" not in str(error.value)
    malformed = dict(row)
    malformed["role"] = "unknown"
    with pytest.raises(AuthorizationDenied):
        AuthorityStore._access_from_rows(principal_id, [malformed])


class _Budget:
    def __init__(self, remaining: float) -> None:
        self.remaining = remaining

    def remaining_ms(self) -> float:
        return self.remaining


def test_retrieval_hold_does_not_begin_gate_or_run_work_when_expired() -> None:
    project_id, agent_type_id, principal_id, run_id = _ids()
    access = AccessContext(
        project_id=project_id,
        agent_type_id=agent_type_id,
        principal_id=principal_id,
        grants=(GrantBinding(uuid4(), ProjectRole.DATA),),
    )

    class NeverGate:
        def shared(self, *args: object, **kwargs: object) -> object:
            raise AssertionError("expired hold must not enter the activity gate")

    opener = AuthorizedRetrievalOpener(object(), activity=NeverGate())  # type: ignore[arg-type]
    with pytest.raises(RequestDeadlineExceeded), opener.hold(access, run_id, deadline=_Budget(0.0)):
        pass


def test_retrieval_hold_stops_after_activity_expiry_before_ordinary_run_work() -> None:
    project_id, agent_type_id, principal_id, run_id = _ids()
    access = AccessContext(
        project_id=project_id,
        agent_type_id=agent_type_id,
        principal_id=principal_id,
        grants=(GrantBinding(uuid4(), ProjectRole.DATA),),
    )
    budget = _Budget(123.0)

    class ExpiringGate:
        @contextmanager
        def shared(self, project: ProjectId, *, deadline: _Budget) -> Iterator[None]:
            assert project == project_id
            assert deadline is budget
            budget.remaining = 0.0
            yield

    opener = AuthorizedRetrievalOpener(object(), activity=ExpiringGate())  # type: ignore[arg-type]
    with pytest.raises(RequestDeadlineExceeded), opener.hold(access, run_id, deadline=budget):
        pass


class _Cursor:
    def __init__(
        self,
        log: list[tuple[str, object]],
        rows: list[dict[str, object]],
        *,
        on_select: Callable[[], None] | None = None,
        query_error: BaseException | None = None,
    ) -> None:
        self._log = log
        self._rows = rows
        self._on_select = on_select
        self._query_error = query_error

    def execute(self, sql: str, params: object = None) -> _Cursor:
        self._log.append((sql, params))
        if "FROM principal AS pr" in sql:
            if self._on_select is not None:
                self._on_select()
            if self._query_error is not None:
                raise self._query_error
        return self

    def fetchall(self) -> list[dict[str, object]]:
        return self._rows

    def __enter__(self) -> _Cursor:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class _Connection:
    def __init__(
        self,
        log: list[tuple[str, object]],
        rows: list[dict[str, object]],
        *,
        on_snapshot: Callable[[], None] | None = None,
        on_select: Callable[[], None] | None = None,
        query_error: BaseException | None = None,
    ) -> None:
        self._log = log
        self._rows = rows
        self._on_snapshot = on_snapshot
        self._on_select = on_select
        self._query_error = query_error

    def execute(self, sql: str, params: object = None) -> None:
        self._log.append((sql, params))
        if sql == _RESOLVE_SNAPSHOT_SQL and self._on_snapshot is not None:
            self._on_snapshot()

    def cursor(self, **kwargs: object) -> _Cursor:
        del kwargs
        return _Cursor(
            self._log,
            self._rows,
            on_select=self._on_select,
            query_error=self._query_error,
        )

    @contextmanager
    def transaction(self) -> Iterator[_Connection]:
        yield self


class _Pool:
    def __init__(
        self,
        rows: list[dict[str, object]],
        *,
        on_snapshot: Callable[[], None] | None = None,
        on_select: Callable[[], None] | None = None,
        query_error: BaseException | None = None,
    ) -> None:
        self.log: list[tuple[str, object]] = []
        self.timeouts: list[float] = []
        self._rows = rows
        self._on_snapshot = on_snapshot
        self._on_select = on_select
        self._query_error = query_error

    @contextmanager
    def connection(self, *, timeout: float | None = None) -> Iterator[_Connection]:
        if timeout is not None:
            self.timeouts.append(timeout)
        yield _Connection(
            self.log,
            self._rows,
            on_snapshot=self._on_snapshot,
            on_select=self._on_select,
            query_error=self._query_error,
        )


def test_authority_access_uses_one_budget_after_repeatable_read_then_timeout_refresh() -> None:
    project_id, agent_type_id, principal_id, _run_id = _ids()
    budget = _Budget(123.0)
    pool = _Pool(
        [_row(project_id, agent_type_id, principal_id)],
        on_snapshot=lambda: setattr(budget, "remaining", 37.0),
    )

    access = AuthorityStore(pool).resolve_access(principal_id, deadline=budget)  # type: ignore[arg-type]

    assert access.principal_id == principal_id
    assert pool.timeouts == [0.123]
    assert pool.log[0] == (_RESOLVE_SNAPSHOT_SQL, None)
    assert pool.log[1] == (
        pool_module._SET_STATEMENT_TIMEOUT,
        {"statement_timeout_ms": "37"},
    )
    assert "FROM principal AS pr" in pool.log[2][0]


def test_authority_access_preexpired_budget_does_not_checkout_or_execute_sql() -> None:
    project_id, agent_type_id, principal_id, _run_id = _ids()
    pool = _Pool([_row(project_id, agent_type_id, principal_id)])

    with pytest.raises(RequestDeadlineExceeded):
        AuthorityStore(pool).resolve_access(principal_id, deadline=_Budget(0.0))  # type: ignore[arg-type]

    assert pool.timeouts == []
    assert pool.log == []


def test_authority_access_without_deadline_preserves_historical_unscoped_path() -> None:
    project_id, agent_type_id, principal_id, _run_id = _ids()
    pool = _Pool([_row(project_id, agent_type_id, principal_id)])

    access = AuthorityStore(pool).resolve_access(principal_id)

    assert access.principal_id == principal_id
    assert pool.timeouts == []
    assert pool.log[0] == (_RESOLVE_SNAPSHOT_SQL, None)
    assert all(sql != pool_module._SET_STATEMENT_TIMEOUT for sql, _ in pool.log)


def test_authority_access_preserves_evaluated_denial() -> None:
    _project_id, _agent_type_id, principal_id, _run_id = _ids()

    with pytest.raises(AuthorizationDenied):
        AuthorityStore(_Pool([])).resolve_access(principal_id, deadline=_Budget(123.0))  # type: ignore[arg-type]


def test_authority_access_late_valid_result_is_request_expiry() -> None:
    project_id, agent_type_id, principal_id, _run_id = _ids()
    budget = _Budget(123.0)
    pool = _Pool(
        [_row(project_id, agent_type_id, principal_id)],
        on_select=lambda: setattr(budget, "remaining", 0.0),
    )

    with pytest.raises(RequestDeadlineExceeded):
        AuthorityStore(pool).resolve_access(principal_id, deadline=budget)  # type: ignore[arg-type]


def test_authority_access_refresh_expiry_starts_no_grant_select() -> None:
    project_id, agent_type_id, principal_id, _run_id = _ids()
    budget = _Budget(123.0)
    pool = _Pool(
        [_row(project_id, agent_type_id, principal_id)],
        on_snapshot=lambda: setattr(budget, "remaining", 0.0),
    )

    with pytest.raises(RequestDeadlineExceeded):
        AuthorityStore(pool).resolve_access(principal_id, deadline=budget)  # type: ignore[arg-type]

    assert not any("FROM principal AS pr" in sql for sql, _ in pool.log)


@pytest.mark.parametrize("expired", [False, True])
def test_authority_access_keeps_early_query_cancel_and_translates_expired(
    expired: bool,
) -> None:
    project_id, agent_type_id, principal_id, _run_id = _ids()
    budget = _Budget(123.0)
    query_error = QueryCanceled("statement cancelled")
    pool = _Pool(
        [_row(project_id, agent_type_id, principal_id)],
        on_select=(lambda: setattr(budget, "remaining", 0.0)) if expired else None,
        query_error=query_error,
    )

    if expired:
        with pytest.raises(RequestDeadlineExceeded) as raised:
            AuthorityStore(pool).resolve_access(principal_id, deadline=budget)  # type: ignore[arg-type]
        assert raised.value.__cause__ is query_error
    else:
        with pytest.raises(QueryCanceled) as raised:
            AuthorityStore(pool).resolve_access(principal_id, deadline=budget)  # type: ignore[arg-type]
        assert raised.value is query_error


def test_authority_access_translates_lazy_checkout_timeout_with_its_cause() -> None:
    principal_id = _ids()[2]
    checkout_error = PoolTimeout("checkout stalled")

    class LazyTimeout:
        def __enter__(self) -> _Connection:
            raise checkout_error

        def __exit__(self, *exc: object) -> None:
            return None

    class Pool:
        def connection(self, *, timeout: float | None = None) -> LazyTimeout:
            assert timeout == 0.123
            return LazyTimeout()

    with pytest.raises(RequestDeadlineExceeded) as raised:
        AuthorityStore(Pool()).resolve_access(principal_id, deadline=_Budget(123.0))  # type: ignore[arg-type]
    assert isinstance(raised.value.__cause__, pool_module.PoolDeadlineExceeded)
    assert raised.value.__cause__.__cause__ is checkout_error


def test_run_owner_sql_is_insert_do_nothing_then_immutable_select_without_update() -> None:
    assert "ON CONFLICT (project_id, run_id) DO NOTHING" in _RUN_OWNER_INSERT_SQL
    assert "DO UPDATE" not in _RUN_OWNER_INSERT_SQL
    assert "FOR SHARE" not in _RUN_OWNER_SELECT_SQL


def test_run_owner_row_is_exact_and_preserves_the_persisted_first_origin() -> None:
    project_id, agent_type_id, principal_id, run_id = _ids()
    row = {
        "project_id": project_id.value,
        "run_id": run_id.value,
        "principal_id": principal_id.value,
        "agent_type_id": agent_type_id.value,
        "origin": "retrieve",
    }
    value = RunAuthorityStore._run_authority_from_row(row, project_id, run_id)
    assert value.origin is RunOrigin.RETRIEVE
    wrong = dict(row)
    wrong["origin"] = "unknown"
    with pytest.raises(RunAuthorityDenied):
        RunAuthorityStore._run_authority_from_row(wrong, project_id, run_id)


def test_require_active_grant_query_binds_feedback_source_exactly() -> None:
    project_id, agent_type_id, principal_id, _run_id = _ids()
    access = AccessContext(
        project_id=project_id,
        agent_type_id=agent_type_id,
        principal_id=principal_id,
        grants=(
            GrantBinding(
                grant_id=uuid4(),
                role=ProjectRole.FEEDBACK,
                feedback_source=FeedbackSource.DOWNSTREAM,
            ),
        ),
    )
    assert access.feedback_source is FeedbackSource.DOWNSTREAM


def test_hold_forwards_one_budget_and_stops_before_the_next_authority_stage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_id, agent_type_id, principal_id, run_id = _ids()
    access = AccessContext(
        project_id=project_id,
        agent_type_id=agent_type_id,
        principal_id=principal_id,
        grants=(GrantBinding(uuid4(), ProjectRole.DATA),),
    )
    budget = _Budget(123.0)
    calls: list[tuple[str, object]] = []

    @contextmanager
    def fake_scoped(*args: object, **kwargs: object) -> Iterator[object]:
        assert args == (opener._pool, project_id)
        assert kwargs == {"deadline": budget}
        yield object()

    class Gate:
        @contextmanager
        def shared(self, project: ProjectId, *, deadline: _Budget) -> Iterator[None]:
            assert project == project_id
            assert deadline is budget
            yield

    class Authority:
        def require_active_grant_on(
            self, conn: object, supplied: AccessContext, role: ProjectRole, *, deadline: _Budget
        ) -> GrantBinding:
            assert conn is not None and supplied is access and role is ProjectRole.DATA
            calls.append(("grant", deadline))
            budget.remaining = 0.0
            return access.grants[0]

    class Runs:
        def open_for_subject_bind_on(self, *args: object, **kwargs: object) -> object:
            calls.append(("open", kwargs))
            raise AssertionError("expired grant recheck must not start run opening")

    opener = AuthorizedRetrievalOpener(object(), activity=Gate())  # type: ignore[arg-type]
    opener._authority = Authority()  # type: ignore[assignment]
    opener._runs = Runs()  # type: ignore[assignment]
    monkeypatch.setattr("tracebed.stores.pg.authority.scoped", fake_scoped)

    with pytest.raises(RequestDeadlineExceeded), opener.hold(access, run_id, deadline=budget):
        pass
    assert calls == [("grant", budget)]


def test_hold_commits_false_subject_containment_after_budget_expiry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_id, agent_type_id, principal_id, run_id = _ids()
    access = AccessContext(
        project_id=project_id,
        agent_type_id=agent_type_id,
        principal_id=principal_id,
        grants=(GrantBinding(uuid4(), ProjectRole.DATA),),
    )
    budget = _Budget(123.0)
    transaction: list[str] = []

    @contextmanager
    def fake_scoped(*args: object, **kwargs: object) -> Iterator[object]:
        assert kwargs == {"deadline": budget}
        try:
            yield object()
        except BaseException:
            transaction.append("rollback")
            raise
        else:
            transaction.append("commit")

    class Gate:
        @contextmanager
        def shared(self, *args: object, **kwargs: object) -> Iterator[None]:
            yield

    class Authority:
        def require_active_grant_on(self, *args: object, **kwargs: object) -> GrantBinding:
            return access.grants[0]

    class Runs:
        def open_for_subject_bind_on(self, *args: object, **kwargs: object) -> object:
            return type(
                "Opened", (), {"authority": object(), "writable": True, "late_bind_eligible": False}
            )()

        def bind_subject_tags_outcome_on(self, *args: object, **kwargs: object) -> object:
            budget.remaining = 0.0
            return type("Bound", (), {"writable": False})()

    opener = AuthorizedRetrievalOpener(object(), activity=Gate())  # type: ignore[arg-type]
    opener._authority = Authority()  # type: ignore[assignment]
    opener._runs = Runs()  # type: ignore[assignment]
    monkeypatch.setattr("tracebed.stores.pg.authority.scoped", fake_scoped)

    with (
        pytest.raises(ErasureFenced),
        opener.hold(access, run_id, subject_tags=("subject",), deadline=budget),
    ):
        pass
    assert transaction == ["commit"]


def test_hold_rolls_back_late_success_before_it_can_yield(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_id, agent_type_id, principal_id, run_id = _ids()
    access = AccessContext(
        project_id=project_id,
        agent_type_id=agent_type_id,
        principal_id=principal_id,
        grants=(GrantBinding(uuid4(), ProjectRole.DATA),),
    )
    budget = _Budget(123.0)
    transaction: list[str] = []

    @contextmanager
    def fake_scoped(*args: object, **kwargs: object) -> Iterator[object]:
        assert kwargs == {"deadline": budget}
        try:
            yield object()
        except BaseException:
            transaction.append("rollback")
            raise
        else:
            transaction.append("commit")

    class Gate:
        @contextmanager
        def shared(self, *args: object, **kwargs: object) -> Iterator[None]:
            yield

    class Authority:
        def require_active_grant_on(self, *args: object, **kwargs: object) -> GrantBinding:
            return access.grants[0]

    class Runs:
        def open_for_subject_bind_on(self, *args: object, **kwargs: object) -> object:
            budget.remaining = 0.0
            return type(
                "Opened", (), {"authority": object(), "writable": True, "late_bind_eligible": False}
            )()

    opener = AuthorizedRetrievalOpener(object(), activity=Gate())  # type: ignore[arg-type]
    opener._authority = Authority()  # type: ignore[assignment]
    opener._runs = Runs()  # type: ignore[assignment]
    monkeypatch.setattr("tracebed.stores.pg.authority.scoped", fake_scoped)

    with pytest.raises(RequestDeadlineExceeded), opener.hold(access, run_id, deadline=budget):
        raise AssertionError("late authority result must never be disclosed")
    assert transaction == ["rollback"]


@pytest.mark.parametrize("expired", [False, True])
def test_hold_translates_only_expired_scoped_setup_cancellation(
    expired: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_id, agent_type_id, principal_id, run_id = _ids()
    access = AccessContext(
        project_id=project_id,
        agent_type_id=agent_type_id,
        principal_id=principal_id,
        grants=(GrantBinding(uuid4(), ProjectRole.DATA),),
    )
    budget = _Budget(123.0)
    cancellation = QueryCanceled("RLS setup cancelled")
    grant_calls: list[object] = []

    class Setup:
        def __enter__(self) -> object:
            if expired:
                budget.remaining = 0.0
            raise cancellation

        def __exit__(self, *exc: object) -> None:
            return None

    class Gate:
        @contextmanager
        def shared(self, *args: object, **kwargs: object) -> Iterator[None]:
            yield

    class Authority:
        def require_active_grant_on(self, *args: object, **kwargs: object) -> GrantBinding:
            grant_calls.append(object())
            return access.grants[0]

    opener = AuthorizedRetrievalOpener(object(), activity=Gate())  # type: ignore[arg-type]
    opener._authority = Authority()  # type: ignore[assignment]
    monkeypatch.setattr("tracebed.stores.pg.authority.scoped", lambda *args, **kwargs: Setup())

    if expired:
        with (
            pytest.raises(RequestDeadlineExceeded) as raised,
            opener.hold(access, run_id, deadline=budget),
        ):
            pass
        assert raised.value.__cause__ is cancellation
    else:
        with pytest.raises(QueryCanceled) as raised, opener.hold(access, run_id, deadline=budget):
            pass
        assert raised.value is cancellation
    assert grant_calls == []


def test_hold_yields_once_commits_and_preserves_body_error_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_id, agent_type_id, principal_id, run_id = _ids()
    access = AccessContext(
        project_id=project_id,
        agent_type_id=agent_type_id,
        principal_id=principal_id,
        grants=(GrantBinding(uuid4(), ProjectRole.DATA),),
    )
    transaction: list[str] = []
    authority = object()

    @contextmanager
    def fake_scoped(*args: object, **kwargs: object) -> Iterator[object]:
        assert kwargs == {}
        try:
            yield object()
        except BaseException:
            transaction.append("rollback")
            raise
        else:
            transaction.append("commit")

    class Gate:
        @contextmanager
        def shared(self, *args: object, **kwargs: object) -> Iterator[None]:
            yield

    class Authority:
        def require_active_grant_on(self, *args: object, **kwargs: object) -> GrantBinding:
            return access.grants[0]

    class Runs:
        def open_for_subject_bind_on(self, *args: object, **kwargs: object) -> object:
            return type(
                "Opened",
                (),
                {"authority": authority, "writable": True, "late_bind_eligible": False},
            )()

    opener = AuthorizedRetrievalOpener(object(), activity=Gate())  # type: ignore[arg-type]
    opener._authority = Authority()  # type: ignore[assignment]
    opener._runs = Runs()  # type: ignore[assignment]
    monkeypatch.setattr("tracebed.stores.pg.authority.scoped", fake_scoped)

    with opener.hold(access, run_id) as yielded:
        assert yielded.authority is authority
    assert transaction == ["commit"]

    body_error = PoolTimeout("body failure")
    with pytest.raises(PoolTimeout) as raised, opener.hold(access, run_id):
        raise body_error
    assert raised.value is body_error
    assert transaction == ["commit", "rollback"]


def test_concrete_hold_queries_refresh_the_same_decreasing_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_id, agent_type_id, principal_id, run_id = _ids()
    grant = GrantBinding(uuid4(), ProjectRole.DATA)
    access = AccessContext(project_id, agent_type_id, principal_id, (grant,))
    budget = _Budget(123.0)
    refreshed: list[float] = []

    def refresh(conn: object, supplied: _Budget) -> None:
        assert conn is connection and supplied is budget
        refreshed.append(supplied.remaining)

    class Cursor:
        def execute(self, sql: str, params: object = None) -> Cursor:
            del params
            if "require_active_grant" in sql:
                self.row = {
                    "grant_id": grant.grant_id,
                    "role": "data",
                    "feedback_source": None,
                }
                budget.remaining = 80.0
            elif "open_erasure_guarded_run" in sql:
                self.row = {"writable": True, "late_bind_eligible": False, "origin": "retrieve"}
                budget.remaining = 37.0
            else:
                self.row = {"writable": True, "subject_digests": []}
            return self

        def fetchone(self) -> dict[str, object]:
            return self.row

        def __enter__(self) -> Cursor:
            return self

        def __exit__(self, *exc: object) -> None:
            return None

    class Connection:
        def cursor(self, **kwargs: object) -> Cursor:
            del kwargs
            return Cursor()

    connection = Connection()
    monkeypatch.setattr("tracebed.stores.pg.authority.refresh_deadline_statement_timeout", refresh)

    assert (
        AuthorityStore(object()).require_active_grant_on(  # type: ignore[arg-type]
            connection, access, ProjectRole.DATA, deadline=budget
        )
        == grant
    )
    opened = RunAuthorityStore(object()).open_for_subject_bind_on(  # type: ignore[arg-type]
        connection, access, run_id, origin=RunOrigin.RETRIEVE, deadline=budget
    )
    assert opened.writable
    assert (
        RunAuthorityStore(object())
        .bind_subject_tags_outcome_on(  # type: ignore[arg-type]
            connection,
            access,
            run_id,
            required_role=ProjectRole.DATA,
            subject_tags=("subject",),
            deadline=budget,
        )
        .writable
    )
    assert refreshed == [123.0, 80.0, 37.0]


@pytest.mark.parametrize("expired", [False, True])
def test_run_open_preserves_early_cancellation_and_translates_expired(
    expired: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_id, agent_type_id, principal_id, run_id = _ids()
    access = AccessContext(
        project_id, agent_type_id, principal_id, (GrantBinding(uuid4(), ProjectRole.DATA),)
    )
    budget = _Budget(123.0)
    cancellation = QueryCanceled("statement cancelled")

    def refresh(conn: object, supplied: _Budget) -> None:
        del conn, supplied

    class Cursor:
        def execute(self, sql: str, params: object = None) -> Cursor:
            del sql, params
            if expired:
                budget.remaining = 0.0
            raise cancellation

        def __enter__(self) -> Cursor:
            return self

        def __exit__(self, *exc: object) -> None:
            return None

    class Connection:
        def cursor(self, **kwargs: object) -> Cursor:
            del kwargs
            return Cursor()

    monkeypatch.setattr("tracebed.stores.pg.authority.refresh_deadline_statement_timeout", refresh)
    if expired:
        with pytest.raises(RequestDeadlineExceeded) as raised:
            RunAuthorityStore(object()).open_for_subject_bind_on(  # type: ignore[arg-type]
                Connection(), access, run_id, origin=RunOrigin.RETRIEVE, deadline=budget
            )
        assert raised.value.__cause__ is cancellation
    else:
        with pytest.raises(TracebedError) as raised:
            RunAuthorityStore(object()).open_for_subject_bind_on(  # type: ignore[arg-type]
                Connection(), access, run_id, origin=RunOrigin.RETRIEVE, deadline=budget
            )
        assert raised.value.__cause__ is None
