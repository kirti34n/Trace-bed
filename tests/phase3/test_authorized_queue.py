"""Pure/offline authorized queue admission contracts."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from uuid import UUID, uuid4

import pytest

from tracebed.adapters.ports import (
    AuthorizedQueueProducerPort,
    AuthorizedQueueWrite,
    OutcomeQueuePayload,
    ProposalQueuePayload,
    QueueProducerPort,
    TraceQueuePayload,
)
from tracebed.domain.authority import AccessContext, GrantBinding
from tracebed.domain.clock import FakeClock
from tracebed.domain.config import QueueAdmissionLimits, QueueConfig
from tracebed.domain.enums import FeedbackSource, ProjectRole
from tracebed.domain.errors import AuthorizationDenied
from tracebed.domain.ids import AgentTypeId, PrincipalId, ProjectId, RunId
from tracebed.stores.pg.queue import (
    _AUTHORIZED_ENQUEUE_FUNCTION_SQL,
    TOPIC_MEMORY_PROPOSAL,
    TOPIC_OUTCOME_EVENT,
    TOPIC_TRACE_EVENT,
    AuthorizedWorkQueue,
    _compact_json_bytes,
    plan_authorized_enqueue,
)

pytestmark = pytest.mark.phase3


def _access(*roles: ProjectRole) -> AccessContext:
    sources = {ProjectRole.FEEDBACK: FeedbackSource.DOWNSTREAM}
    return AccessContext(
        project_id=ProjectId(uuid4()),
        agent_type_id=AgentTypeId(uuid4()),
        principal_id=PrincipalId(uuid4()),
        grants=tuple(
            GrantBinding(grant_id=uuid4(), role=role, feedback_source=sources.get(role))
            for role in roles
        ),
    )


def _trace(run_id: RunId) -> AuthorizedQueueWrite:
    return AuthorizedQueueWrite(
        topic=TOPIC_TRACE_EVENT,
        run_id=run_id,
        payload=TraceQueuePayload(
            seq=0,
            event={
                "type": "run_end",
                "ts": "2026-01-01T00:00:00+00:00",
                "payload": {"status": "ok"},
            },
        ),
    )


def _proposal(run_id: RunId) -> AuthorizedQueueWrite:
    return AuthorizedQueueWrite(
        topic=TOPIC_MEMORY_PROPOSAL,
        run_id=run_id,
        payload=ProposalQueuePayload(
            proposal={
                "mem_type": "lesson",
                "content": "A bounded proposal.",
                "claimed_scope": "agent_type",
            }
        ),
    )


def _outcome(run_id: RunId) -> AuthorizedQueueWrite:
    return AuthorizedQueueWrite(
        topic=TOPIC_OUTCOME_EVENT,
        run_id=run_id,
        payload=OutcomeQueuePayload(event_id=uuid4(), outcome="positive", payload={"status": "ok"}),
    )


def test_pure_plan_requires_exact_role_shapes_and_sorts_distinct_trace_runs() -> None:
    access = _access(ProjectRole.DATA, ProjectRole.FEEDBACK)
    run_a, run_b = RunId(UUID(int=2)), RunId(UUID(int=1))
    plan = plan_authorized_enqueue(access, (_trace(run_a), _trace(run_b), _trace(run_a)))
    assert plan.topic == TOPIC_TRACE_EVENT and plan.required_role is ProjectRole.DATA
    assert plan.run_ids == (run_b, run_a)
    assert plan_authorized_enqueue(access, (_proposal(run_a),)).required_role is ProjectRole.DATA
    assert plan_authorized_enqueue(access, (_outcome(run_a),)).required_role is ProjectRole.FEEDBACK
    with pytest.raises(AuthorizationDenied):
        plan_authorized_enqueue(_access(ProjectRole.DATA), (_outcome(run_a),))
    with pytest.raises(ValueError):
        plan_authorized_enqueue(access, (_proposal(run_a), _proposal(run_b)))
    with pytest.raises(TypeError):
        plan_authorized_enqueue(access, [_trace(run_a)])  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        plan_authorized_enqueue(access, (object(),))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        plan_authorized_enqueue(object(), (_trace(run_a),))  # type: ignore[arg-type]


def test_profiled_server_admission_shape_is_pinned() -> None:
    assert "tracebed_enqueue_authorized" in _AUTHORIZED_ENQUEUE_FUNCTION_SQL
    for field in (
        "project_id",
        "principal_id",
        "agent_type_id",
        "grant_id",
        "topic",
        "run_id",
        "payload",
        "max_global_depth",
        "max_topic_depth",
        "max_project_depth",
        "enqueue",
    ):
        assert f"%({field})s" in _AUTHORIZED_ENQUEUE_FUNCTION_SQL
    assert "INSERT INTO work_queue" not in _AUTHORIZED_ENQUEUE_FUNCTION_SQL


def test_oversized_authorized_batch_rejects_before_activity_or_pool_use() -> None:
    queue = object.__new__(AuthorizedWorkQueue)
    object.__setattr__(
        queue,
        "_cfg",
        QueueConfig(
            admission=QueueAdmissionLimits(max_item_bytes=1, max_batch_bytes=1, max_batch_items=1)
        ),
    )
    object.__setattr__(queue, "_clock", FakeClock())
    object.__setattr__(queue, "_activity", _ExplodingActivity())
    with pytest.raises(ValueError, match="byte limit"):
        queue.enqueue_many_authorized(_access(ProjectRole.DATA), (_trace(RunId(uuid4())),))


def test_configured_item_count_limit_rejects_before_activity_or_pool_use() -> None:
    queue = object.__new__(AuthorizedWorkQueue)
    object.__setattr__(
        queue,
        "_cfg",
        QueueConfig(admission=QueueAdmissionLimits(max_batch_items=1)),
    )
    object.__setattr__(queue, "_clock", FakeClock())
    object.__setattr__(queue, "_activity", _ExplodingActivity())
    with pytest.raises(ValueError, match="item limit"):
        queue.enqueue_many_authorized(
            _access(ProjectRole.DATA),
            (_trace(RunId(uuid4())), _trace(RunId(uuid4()))),
        )


def test_authorized_and_legacy_queue_protocol_surfaces_do_not_overlap() -> None:
    queue = object.__new__(AuthorizedWorkQueue)
    assert isinstance(queue, AuthorizedQueueProducerPort)
    assert not isinstance(queue, QueueProducerPort)


def test_admission_config_relationships_and_defaults() -> None:
    limits = QueueAdmissionLimits()
    assert (limits.max_item_bytes, limits.max_batch_bytes, limits.max_batch_items) == (
        256 * 1024,
        4 * 1024 * 1024,
        500,
    )
    with pytest.raises(ValueError):
        QueueAdmissionLimits(max_item_bytes=2, max_batch_bytes=1)


def test_canonical_item_and_batch_byte_limits_are_exact() -> None:
    run_a, run_b = RunId(UUID(int=31)), RunId(UUID(int=32))
    writes = (_trace(run_a), _trace(run_b))
    probe = object.__new__(AuthorizedWorkQueue)
    object.__setattr__(probe, "_cfg", QueueConfig())
    measured = probe._measure_writes(writes)
    envelopes = [
        {
            "topic": entry.write.topic,
            "run_id": str(entry.write.run_id.value),
            "payload": entry.payload,
            "priority": entry.write.priority,
            "available_at": None,
        }
        for entry in measured
    ]
    item_size = len(_compact_json_bytes(envelopes[0]))
    batch_size = len(_compact_json_bytes(envelopes))

    object.__setattr__(
        probe,
        "_cfg",
        QueueConfig(
            admission=QueueAdmissionLimits(
                max_item_bytes=item_size,
                max_batch_bytes=batch_size,
                max_batch_items=2,
            )
        ),
    )
    assert len(probe._measure_writes(writes)) == 2

    object.__setattr__(
        probe,
        "_cfg",
        QueueConfig(
            admission=QueueAdmissionLimits(
                max_item_bytes=item_size - 1,
                max_batch_bytes=batch_size,
                max_batch_items=2,
            )
        ),
    )
    with pytest.raises(ValueError, match="item exceeds"):
        probe._measure_writes(writes)

    object.__setattr__(
        probe,
        "_cfg",
        QueueConfig(
            admission=QueueAdmissionLimits(
                max_item_bytes=item_size,
                max_batch_bytes=batch_size - 1,
                max_batch_items=2,
            )
        ),
    )
    with pytest.raises(ValueError, match="batch exceeds"):
        probe._measure_writes(writes)


class _Result:
    def __init__(self, row: tuple[object, ...] | None) -> None:
        self._row = row

    def fetchone(self) -> tuple[object, ...] | None:
        return self._row


class _Cursor:
    def __init__(self, conn: _Conn) -> None:
        self._conn = conn
        self._row: tuple[object, ...] | None = None

    def execute(self, sql: str, params: object = None) -> None:
        self._conn.executed.append((sql, params))
        if sql == _AUTHORIZED_ENQUEUE_FUNCTION_SQL:
            assert isinstance(params, dict)
            if params["enqueue"]:
                self._conn.insert_count += 1
                if self._conn.fail_insert_at == self._conn.insert_count:
                    raise RuntimeError("forced insert failure")
                self._conn.staged_rows.append(params)
                self._conn.next_id += 1
                self._row = (self._conn.next_id, True)
            else:
                self._row = (None, True)

    def fetchone(self) -> tuple[object, ...] | None:
        return self._row

    def __enter__(self) -> _Cursor:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class _Conn:
    def __init__(self, order: list[str]) -> None:
        self.order = order
        self.executed: list[tuple[str, object]] = []
        self.next_id = 100
        self.insert_count = 0
        self.fail_insert_at: int | None = None
        self.staged_rows: list[object] = []
        self.committed_rows: list[object] = []

    @contextmanager
    def transaction(self) -> Iterator[None]:
        self.order.append("transaction")
        try:
            yield
        except BaseException:
            self.staged_rows.clear()
            raise
        else:
            self.committed_rows.extend(self.staged_rows)
            self.staged_rows.clear()

    def execute(self, sql: str, params: object = None) -> _Result:
        self.executed.append((sql, params))
        return _Result(None)

    def cursor(self, *args: object, **kwargs: object) -> _Cursor:
        return _Cursor(self)


class _Pool:
    def __init__(self, conn: _Conn, order: list[str]) -> None:
        self.conn = conn
        self.order = order

    @contextmanager
    def connection(self) -> Iterator[_Conn]:
        self.order.append("pool")
        yield self.conn


class _Activity:
    def __init__(self, order: list[str]) -> None:
        self.order = order

    @contextmanager
    def shared(self, _project_id: ProjectId) -> Iterator[None]:
        self.order.append("activity")
        yield


class _ExplodingActivity:
    def shared(self, _project_id: ProjectId) -> None:
        raise AssertionError("oversize must reject before activity")


def test_authorized_enqueue_uses_only_the_profiled_server_admission_boundary() -> None:
    access = _access(ProjectRole.DATA)
    run_a, run_b = RunId(UUID(int=2)), RunId(UUID(int=1))
    writes = (_trace(run_a), _trace(run_b))
    order: list[str] = []
    conn = _Conn(order)
    queue = AuthorizedWorkQueue(
        _Pool(conn, order),  # type: ignore[arg-type]
        FakeClock(),
        QueueConfig(),
        activity=_Activity(order),  # type: ignore[arg-type]
    )
    assert queue.enqueue_many_authorized(access, writes) == (101, 102)
    assert order[:3] == ["activity", "pool", "transaction"]
    sql = [statement for statement, _params in conn.executed]
    assert sql.count(_AUTHORIZED_ENQUEUE_FUNCTION_SQL) == 4
    inserted = [
        params for statement, params in conn.executed if statement == _AUTHORIZED_ENQUEUE_FUNCTION_SQL
    ]
    assert [params["run_id"] for params in inserted] == [  # type: ignore[index]
        run_b.value,
        run_a.value,
        run_b.value,
        run_a.value,
    ]
    assert [params["enqueue"] for params in inserted] == [False, False, True, True]  # type: ignore[index]
    assert all("run_id" not in params["payload"].obj for params in inserted)  # type: ignore[index,union-attr]
    assert all("source_grant_id" not in params["payload"].obj for params in inserted)  # type: ignore[index,union-attr]
    assert all("subject_digests" not in params for params in inserted)  # type: ignore[operator]
    assert all("run_owner_principal_id" not in params for params in inserted)  # type: ignore[operator]


class _CountingClock:
    def __init__(self) -> None:
        self.calls = 0
        self.instant = FakeClock().now()

    def now(self) -> object:
        self.calls += 1
        return self.instant


def test_one_clock_instant_is_shared_by_caller_ordered_profiled_calls() -> None:
    access = _access(ProjectRole.DATA)
    run_a, run_b = RunId(UUID(int=18)), RunId(UUID(int=19))
    order: list[str] = []
    conn = _Conn(order)
    clock = _CountingClock()
    queue = AuthorizedWorkQueue(
        _Pool(conn, order),  # type: ignore[arg-type]
        clock,  # type: ignore[arg-type]
        QueueConfig(),
        activity=_Activity(order),  # type: ignore[arg-type]
    )
    queue.enqueue_many_authorized(access, (_trace(run_a), _trace(run_b)))
    inserted = conn.committed_rows
    assert clock.calls == 1
    assert [params["run_id"] for params in inserted] == [run_a.value, run_b.value]  # type: ignore[index]
    assert inserted[0]["available_at"] is inserted[1]["available_at"]  # type: ignore[index]


def test_profiled_admission_binds_only_access_context_authority() -> None:
    access = _access(ProjectRole.FEEDBACK)
    run_id = RunId(UUID(int=16))
    order: list[str] = []
    conn = _Conn(order)
    queue = AuthorizedWorkQueue(
        _Pool(conn, order),  # type: ignore[arg-type]
        FakeClock(),
        QueueConfig(),
        activity=_Activity(order),  # type: ignore[arg-type]
    )
    assert queue.enqueue_many_authorized(access, (_outcome(run_id),)) == (101,)
    inserted = conn.committed_rows[0]
    assert inserted["principal_id"] == access.principal_id.value  # type: ignore[index]
    assert inserted["agent_type_id"] == access.agent_type_id.value  # type: ignore[index]
    assert inserted["grant_id"] == access.grant_for(ProjectRole.FEEDBACK).grant_id  # type: ignore[union-attr,index]
    assert inserted["feedback_source"] == FeedbackSource.DOWNSTREAM.value  # type: ignore[index]
    assert "source_principal_id" not in inserted  # type: ignore[operator]
