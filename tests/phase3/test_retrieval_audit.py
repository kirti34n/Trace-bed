"""Offline contracts for the private same-transaction retrieval audit handle."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from uuid import uuid4

import pytest
from psycopg.errors import OperationalError, QueryCanceled

from tracebed.domain.authority import AccessContext, GrantBinding
from tracebed.domain.clock import FakeClock
from tracebed.domain.enums import Arm, OutcomeCode, ProjectRole, Slot
from tracebed.domain.errors import (
    AuthorizationDenied,
    ErasureFenced,
    RequestDeadlineExceeded,
    RetrievalAuditUnavailable,
)
from tracebed.domain.ids import AgentTypeId, MemoryId, PrincipalId, ProjectId, RunId
from tracebed.stores.pg.authority import AuthorizedRetrievalOpener
from tracebed.stores.pg.pool import PoolDeadlineExceeded
from tracebed.stores.pg.repo import (
    _AUTHORIZED_RETRIEVAL_AUDIT_CAPABILITY,
    Repo,
    _AuthorizedRetrievalAudit,
)
from tracebed.stores.pg.rows import InjectionRow, RetrievalEventInsert


class _Budget:
    def __init__(self, remaining: float = 100.0) -> None:
        self.remaining = remaining

    def remaining_ms(self) -> float:
        return self.remaining


def _row(run_id: RunId) -> RetrievalEventInsert:
    return RetrievalEventInsert(
        run_id=run_id,
        outcome_code=OutcomeCode.EMPTY_RESULT,
        latency_ms=1,
        embed_latency_ms=None,
        candidates_considered=0,
        top_score=None,
        arm=Arm.MEMORY_ON,
    )


class _Repo:
    def __init__(
        self, failure: BaseException | None = None, before_failure: object | None = None
    ) -> None:
        self.calls: list[str] = []
        self.failure = failure
        self.before_failure = before_failure

    def _impl_insert_injection_rows(self, *args: object, **kwargs: object) -> None:
        self.calls.append("injections")

    def _impl_insert_retrieval_event(self, *args: object, **kwargs: object) -> None:
        self.calls.append("terminal")
        if self.before_failure is not None:
            self.before_failure()
        if self.failure is not None:
            raise self.failure


def _handle(repo: _Repo, budget: _Budget | None = None) -> tuple[_AuthorizedRetrievalAudit, RunId]:
    run_id = RunId(uuid4())
    return (
        _AuthorizedRetrievalAudit(
            repo,
            object(),
            ProjectId(uuid4()),
            run_id,
            budget or _Budget(),
            _capability=_AUTHORIZED_RETRIEVAL_AUDIT_CAPABILITY,
        ),
        run_id,
    )


def test_private_token_run_identity_double_use_and_closed_handle() -> None:
    repo = _Repo()
    handle, run_id = _handle(repo)
    with pytest.raises(TypeError):
        _AuthorizedRetrievalAudit(
            repo, object(), ProjectId(uuid4()), run_id, _Budget(), _capability=object()
        )
    with pytest.raises(ValueError):
        handle.record_terminal(injections=(), row=_row(RunId(uuid4())))
    assert repo.calls == []
    handle.record_terminal(injections=(), row=_row(run_id))
    with pytest.raises(RuntimeError):
        handle.record_terminal(injections=(), row=_row(run_id))
    handle._close()
    with pytest.raises(RuntimeError):
        handle.record_terminal(injections=(), row=_row(run_id))


@pytest.mark.parametrize(
    "failure, expected",
    [
        (PoolDeadlineExceeded("pool"), RequestDeadlineExceeded),
        (QueryCanceled("early"), RetrievalAuditUnavailable),
        (ErasureFenced(), ErasureFenced),
        (AuthorizationDenied(), AuthorizationDenied),
    ],
)
def test_audit_error_classification(failure: BaseException, expected: type[BaseException]) -> None:
    handle, run_id = _handle(_Repo(failure))
    with pytest.raises(expected):
        handle.record_terminal(injections=(), row=_row(run_id))
    with pytest.raises(RetrievalAuditUnavailable):
        handle._require_complete()


def test_expired_cancellation_and_keyboard_interrupt_keep_required_identity() -> None:
    budget = _Budget()
    cancellation = QueryCanceled("expired")
    repo = _Repo(cancellation, before_failure=lambda: setattr(budget, "remaining", 0.0))
    handle, run_id = _handle(repo, budget)
    with pytest.raises(RequestDeadlineExceeded) as raised:
        handle.record_terminal(injections=(), row=_row(run_id))
    assert raised.value.__cause__ is cancellation
    assert repo.calls == ["injections", "terminal"]

    interrupted = KeyboardInterrupt()
    handle, run_id = _handle(_Repo(interrupted))
    with pytest.raises(KeyboardInterrupt) as raised:
        handle.record_terminal(injections=(), row=_row(run_id))
    assert raised.value is interrupted


def test_cross_thread_handle_is_rejected() -> None:
    handle, run_id = _handle(_Repo())
    errors: list[BaseException] = []
    thread = threading.Thread(
        target=lambda: _record_in_thread(handle, run_id, errors),
    )
    thread.start()
    thread.join()
    assert len(errors) == 1 and isinstance(errors[0], RuntimeError)


def _record_in_thread(
    handle: _AuthorizedRetrievalAudit, run_id: RunId, errors: list[BaseException]
) -> None:
    try:
        handle.record_terminal(injections=(), row=_row(run_id))
    except BaseException as exc:
        errors.append(exc)


class _Result:
    def __init__(self, row: tuple[object, ...] | None = None) -> None:
        self._row = row

    def fetchone(self) -> tuple[object, ...] | None:
        return self._row


class _AuditCursor:
    def __init__(self, conn: _AuditConnection) -> None:
        self._conn = conn

    def __enter__(self) -> _AuditCursor:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def execute(self, sql: str, params: object = None) -> _Result:
        return self._conn.execute(sql, params)

    def executemany(self, sql: str, params: list[object]) -> None:
        self._conn.events.append(("executemany", len(params)))


class _AuditConnection:
    """Records the actual Repo SQL shapes while each statement consumes 10ms."""

    def __init__(self, budget: _Budget | None, *, expire_after: str | None = None) -> None:
        self.budget = budget
        self.expire_after = expire_after
        self.events: list[tuple[str, object]] = []

    def cursor(self) -> _AuditCursor:
        return _AuditCursor(self)

    def execute(self, sql: str, params: object = None) -> _Result:
        if "statement_timeout" in sql:
            assert isinstance(params, dict)
            self.events.append(("timeout", int(str(params["statement_timeout_ms"]))))
            self._consume()
            return _Result()
        if "tracebed_erasure_run_subject_digests" in sql:
            label = "union"
            result = _Result(([b"a" * 32],))
        elif "tracebed_assert_erasure_write_allowed" in sql:
            label = "fence"
            result = _Result()
        elif "INSERT INTO retrieval_event" in sql:
            label = "terminal"
            result = _Result()
        elif "INSERT INTO injection_log" in sql:
            label = "injection"
            result = _Result()
        else:
            raise AssertionError(f"unexpected SQL: {sql}")
        self.events.append((label, None))
        self._consume()
        if label == self.expire_after and self.budget is not None:
            self.budget.remaining = 0
        return result

    def _consume(self) -> None:
        if self.budget is not None:
            self.budget.remaining -= 10


def _real_repo() -> Repo:
    return Repo(object(), FakeClock())  # type: ignore[arg-type]


def _injections() -> tuple[InjectionRow, InjectionRow]:
    return (
        InjectionRow(MemoryId(uuid4()), Slot.FACT, 0.9, 1),
        InjectionRow(MemoryId(uuid4()), Slot.FACT, 0.8, 2),
    )


def test_repo_audit_sql_refreshes_before_each_data_statement() -> None:
    budget = _Budget(1000)
    conn = _AuditConnection(budget)
    repo, project_id, run_id = _real_repo(), ProjectId(uuid4()), RunId(uuid4())

    repo._impl_insert_injection_rows(conn, project_id, run_id, _injections(), deadline=budget)  # type: ignore[arg-type]
    repo._impl_insert_retrieval_event(conn, project_id, _row(run_id), deadline=budget)  # type: ignore[arg-type]

    assert conn.events == [
        ("timeout", 1000),
        ("union", None),
        ("timeout", 980),
        ("fence", None),
        ("timeout", 960),
        ("injection", None),
        ("timeout", 940),
        ("injection", None),
        ("timeout", 920),
        ("union", None),
        ("timeout", 900),
        ("fence", None),
        ("timeout", 880),
        ("terminal", None),
    ]


def test_repo_audit_sql_preserves_none_budget_executemany_shape() -> None:
    conn = _AuditConnection(None)
    repo, project_id, run_id = _real_repo(), ProjectId(uuid4()), RunId(uuid4())

    repo._impl_insert_injection_rows(conn, project_id, run_id, _injections())  # type: ignore[arg-type]

    assert conn.events == [("union", None), ("fence", None), ("executemany", 2)]


@pytest.mark.parametrize(
    ("expire_after", "expected"),
    [
        ("union", ["timeout", "union"]),
        ("injection", ["timeout", "union", "timeout", "fence", "timeout", "injection"]),
    ],
)
def test_repo_audit_expiry_starts_no_next_data_sql(expire_after: str, expected: list[str]) -> None:
    budget = _Budget(1000)
    conn = _AuditConnection(budget, expire_after=expire_after)
    repo, project_id, run_id = _real_repo(), ProjectId(uuid4()), RunId(uuid4())

    with pytest.raises(PoolDeadlineExceeded):
        repo._impl_insert_injection_rows(conn, project_id, run_id, _injections(), deadline=budget)  # type: ignore[arg-type]

    assert [name for name, _ in conn.events] == expected


class _HeldAudit:
    def __init__(self, *, complete: bool) -> None:
        self.complete = complete
        self.closed = False

    def _require_complete(self) -> None:
        if not self.complete:
            raise RetrievalAuditUnavailable("terminal write failed")

    def _close(self) -> None:
        self.closed = True


class _AuditFactory:
    def __init__(self, audit: _HeldAudit) -> None:
        self.audit = audit

    def _authorized_retrieval_audit(self, *args: object, **kwargs: object) -> _HeldAudit:
        return self.audit


def _hold_fixture(
    monkeypatch: pytest.MonkeyPatch, audit: _HeldAudit, transaction: list[str]
) -> tuple[AuthorizedRetrievalOpener, AccessContext, RunId, _Budget]:
    from tracebed.stores.pg import authority as authority_module

    project_id, agent_type_id, principal_id, run_id = (
        ProjectId(uuid4()),
        AgentTypeId(uuid4()),
        PrincipalId(uuid4()),
        RunId(uuid4()),
    )
    access = AccessContext(
        project_id=project_id,
        agent_type_id=agent_type_id,
        principal_id=principal_id,
        grants=(GrantBinding(uuid4(), ProjectRole.DATA),),
    )
    budget = _Budget(100)

    @contextmanager
    def fake_scoped(*args: object, **kwargs: object) -> Iterator[object]:
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

    opener = AuthorizedRetrievalOpener(object(), activity=Gate(), audit_repo=_AuditFactory(audit))  # type: ignore[arg-type]
    opener._authority = Authority()  # type: ignore[assignment]
    opener._runs = Runs()  # type: ignore[assignment]
    monkeypatch.setattr(authority_module, "scoped", fake_scoped)
    monkeypatch.setattr(authority_module, "refresh_deadline_statement_timeout", lambda *args: None)
    return opener, access, run_id, budget


def test_hold_rejects_missing_terminal_audit_rolls_back_and_invalidates_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    audit, transaction = _HeldAudit(complete=False), []
    opener, access, run_id, budget = _hold_fixture(monkeypatch, audit, transaction)

    with pytest.raises(RetrievalAuditUnavailable), opener.hold(access, run_id, deadline=budget):
        pass

    assert transaction == ["rollback"]
    assert audit.closed


def test_hold_translates_clean_audit_commit_failure_and_invalidates_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    audit, transaction = _HeldAudit(complete=True), []
    opener, access, run_id, budget = _hold_fixture(monkeypatch, audit, transaction)
    commit_error = OperationalError("commit unavailable")

    @contextmanager
    def failing_scoped(*args: object, **kwargs: object) -> Iterator[object]:
        yield object()
        transaction.append("commit")
        raise commit_error

    monkeypatch.setattr("tracebed.stores.pg.authority.scoped", failing_scoped)
    with (
        pytest.raises(RetrievalAuditUnavailable) as raised,
        opener.hold(access, run_id, deadline=budget),
    ):
        pass

    assert raised.value.__cause__ is commit_error
    assert transaction == ["commit"]
    assert audit.closed


def test_hold_preserves_body_error_and_invalidates_audit_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    audit, transaction = _HeldAudit(complete=True), []
    opener, access, run_id, budget = _hold_fixture(monkeypatch, audit, transaction)
    body_error = RuntimeError("body")

    with pytest.raises(RuntimeError) as raised, opener.hold(access, run_id, deadline=budget):
        raise body_error

    assert raised.value is body_error
    assert transaction == ["rollback"]
    assert audit.closed


def _real_audited_hold(
    monkeypatch: pytest.MonkeyPatch,
    transaction: list[str],
) -> tuple[AuthorizedRetrievalOpener, Repo, AccessContext, RunId, _Budget]:
    opener, access, run_id, budget = _hold_fixture(
        monkeypatch, _HeldAudit(complete=True), transaction
    )
    repo = _real_repo()
    opener._audit_repo = repo
    return opener, repo, access, run_id, budget


def _record_real_terminal(scope: object, run_id: RunId) -> _AuthorizedRetrievalAudit:
    audit = scope.audit
    assert isinstance(audit, _AuthorizedRetrievalAudit)
    audit.record_terminal(injections=(), row=_row(run_id))
    return audit


def test_real_handle_rolls_back_when_budget_expires_after_terminal_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transaction: list[str] = []
    opener, repo, access, run_id, budget = _real_audited_hold(monkeypatch, transaction)
    monkeypatch.setattr(repo, "_impl_insert_injection_rows", lambda *args, **kwargs: None)
    monkeypatch.setattr(repo, "_impl_insert_retrieval_event", lambda *args, **kwargs: None)

    with (
        pytest.raises(RequestDeadlineExceeded),
        opener.hold(access, run_id, deadline=budget) as scope,
    ):
        audit = _record_real_terminal(scope, run_id)
        budget.remaining = 0.0

    assert transaction == ["rollback"]
    assert audit._closed


@pytest.mark.parametrize("expired", [False, True])
def test_real_handle_final_refresh_cancellation_classification_and_close(
    expired: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tracebed.stores.pg import authority as authority_module

    transaction: list[str] = []
    opener, repo, access, run_id, budget = _real_audited_hold(monkeypatch, transaction)
    monkeypatch.setattr(repo, "_impl_insert_injection_rows", lambda *args, **kwargs: None)
    monkeypatch.setattr(repo, "_impl_insert_retrieval_event", lambda *args, **kwargs: None)
    cancellation = QueryCanceled("final refresh")

    def cancel_refresh(*args: object) -> None:
        if expired:
            budget.remaining = 0.0
        raise cancellation

    monkeypatch.setattr(authority_module, "refresh_deadline_statement_timeout", cancel_refresh)
    expected = RequestDeadlineExceeded if expired else RetrievalAuditUnavailable
    with pytest.raises(expected) as raised, opener.hold(access, run_id, deadline=budget) as scope:
        audit = _record_real_terminal(scope, run_id)

    assert raised.value.__cause__ is cancellation
    assert transaction == ["rollback"]
    assert audit._closed


def test_real_handle_caught_second_write_failure_still_rolls_back_and_closes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transaction: list[str] = []
    opener, repo, access, run_id, budget = _real_audited_hold(monkeypatch, transaction)
    monkeypatch.setattr(repo, "_impl_insert_injection_rows", lambda *args, **kwargs: None)

    def fail_second(*args: object, **kwargs: object) -> None:
        raise RuntimeError("terminal unavailable")

    monkeypatch.setattr(repo, "_impl_insert_retrieval_event", fail_second)
    with (
        pytest.raises(RetrievalAuditUnavailable),
        opener.hold(access, run_id, deadline=budget) as scope,
    ):
        audit = scope.audit
        assert isinstance(audit, _AuthorizedRetrievalAudit)
        with pytest.raises(RetrievalAuditUnavailable):
            audit.record_terminal(injections=(), row=_row(run_id))

    assert transaction == ["rollback"]
    assert audit._closed


def test_concurrent_real_audit_handles_remain_bound_to_their_own_request_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _real_repo()
    calls: list[tuple[str, ProjectId, RunId]] = []
    lock = threading.Lock()
    barrier = threading.Barrier(2)
    errors: list[BaseException] = []

    def injection(
        conn: object, project: ProjectId, run: RunId, *args: object, **kwargs: object
    ) -> None:
        with lock:
            calls.append(("injections", project, run))

    def terminal(
        conn: object, project: ProjectId, row: RetrievalEventInsert, **kwargs: object
    ) -> None:
        with lock:
            calls.append(("terminal", project, row.run_id))

    monkeypatch.setattr(repo, "_impl_insert_injection_rows", injection)
    monkeypatch.setattr(repo, "_impl_insert_retrieval_event", terminal)
    identities = [(ProjectId(uuid4()), RunId(uuid4())), (ProjectId(uuid4()), RunId(uuid4()))]

    def request(project: ProjectId, run: RunId) -> None:
        try:
            handle = repo._authorized_retrieval_audit(
                object(),
                project,
                run,
                _Budget(),
                _capability=_AUTHORIZED_RETRIEVAL_AUDIT_CAPABILITY,
            )
            barrier.wait(timeout=1.0)
            handle.record_terminal(injections=(), row=_row(run))
            handle._require_complete()
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=request, args=identity) for identity in identities]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=1.0)

    assert errors == []
    assert all(not thread.is_alive() for thread in threads)
    assert len(calls) == 4
    assert set(calls) == {("injections", project, run) for project, run in identities} | {
        ("terminal", project, run) for project, run in identities
    }
