"""OutcomeIntake proving tests (PHASE0-CONTRACT.md §13.2, PHASE-0 Task 15).

Offline throughout — fakes stand in for `QueueConsumerPort` and
`OutcomeRepoPort` (§12: no Postgres needed to prove this consumer).

Proves: `r`/`w_zero` derivation (`positive`/`negative` -> 1.0/0.0; `w_zero`
from `scoring.adapter_weights`, never from the wire); a trace posted at T and
feedback posted at T+2 SIMULATED DAYS (`FakeClock`) join by `run_id`; replaying
the same `event_id` inserts exactly one row; a raw queue payload naming a
`weight` field is rejected (nacked, never inserted) — the offline equivalent
of the wire's 422, since `FeedbackEvent.extra="forbid"` has no `weight` field
to accept one; and an `implicit`-adapter outcome is recorded with the `w_zero`
marker while touching NOTHING beyond `insert_outcome_event` — `FakeOutcomeRepo`
defines no other method, so any Q-mutation call would be a bare
`AttributeError`, not a silently-accepted side effect.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from types import MappingProxyType
from typing import Any
from uuid import UUID, uuid4

import pytest

from tracebed.domain.clock import FakeClock
from tracebed.domain.config import ScoringConfig, TracebedSettings
from tracebed.domain.enums import AdapterClass
from tracebed.domain.ids import PrincipalId, ProjectId, RunId, uuid7
from tracebed.ingest.outcome_intake import OutcomeIntake
from tracebed.stores.pg.queue import TOPIC_OUTCOME_EVENT, QueueItem
from tracebed.stores.pg.rows import OutcomeEventInsert

pytestmark = pytest.mark.phase0


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #


@dataclass
class _QueueRow:
    id: int
    topic: str
    project_id: ProjectId
    payload: dict[str, object]
    attempts: int = 0


class FakeQueue:
    """`QueueConsumerPort` + a test-only `enqueue`. The row's `project_id`
    column can be set independently of the payload so a test can build the
    one shape the real producer never emits: a row whose scoping column and
    whose envelope disagree."""

    def __init__(self) -> None:
        self._rows: dict[int, _QueueRow] = {}
        self._next_id = 1
        self.acked: list[int] = []
        self.nacked: list[tuple[int, timedelta]] = []

    def enqueue(
        self, topic: str, payload: Mapping[str, object], *, project_id: ProjectId | None = None
    ) -> int:
        row_id = self._next_id
        self._next_id += 1
        scoped = (
            project_id if project_id is not None else ProjectId(UUID(str(payload["project_id"])))
        )
        self._rows[row_id] = _QueueRow(
            id=row_id, topic=topic, project_id=scoped, payload=dict(payload)
        )
        return row_id

    def claim(self, topic: str, n: int) -> list[QueueItem]:
        claimed: list[QueueItem] = []
        for row in list(self._rows.values()):
            if row.topic != topic:
                continue
            if len(claimed) >= n:
                break
            row.attempts += 1
            claimed.append(
                QueueItem(
                    id=row.id,
                    topic=row.topic,
                    project_id=row.project_id,
                    payload=MappingProxyType(dict(row.payload)),
                    priority=100,
                    attempts=row.attempts,
                )
            )
        return claimed

    def ack(self, item_id: int) -> None:
        self._rows.pop(item_id, None)
        self.acked.append(item_id)

    def nack(self, item_id: int, backoff: timedelta) -> None:
        self.nacked.append((item_id, backoff))


class FakeOutcomeRepo:
    """`OutcomeRepoPort` — exactly one method. `OutcomeIntake` calling
    anything else (a Q-mutation, a status write, ...) would be a bare
    `AttributeError` here, not a silently-tolerated side effect — that IS
    the "zero Q-mutation code path" assertion (contract §11), made
    structural rather than merely observed."""

    def __init__(self) -> None:
        self.rows: dict[tuple[ProjectId, UUID], OutcomeEventInsert] = {}
        self.insert_calls: list[tuple[ProjectId, OutcomeEventInsert]] = []
        # Not a method: the "one method only" property above is what makes a
        # stray Q-mutation call an AttributeError, and that must stay true.
        self.fail_event_ids: set[UUID] = set()

    def insert_outcome_event(self, project_id: ProjectId, row: OutcomeEventInsert) -> bool:
        self.insert_calls.append((project_id, row))
        if row.event_id in self.fail_event_ids:
            # A driver-level failure, deliberately NOT a TracebedError: the
            # consumer must isolate the item either way.
            raise RuntimeError("connection reset by peer")
        key = (project_id, row.event_id)
        if key in self.rows:
            return False
        self.rows[key] = row
        return True


# --------------------------------------------------------------------------- #
# Scaffolding
# --------------------------------------------------------------------------- #


def _feedback_event(
    *, adapter: str, outcome: str, event_id: UUID, occurred_at: str | None = None, extra: dict[str, Any] | None = None
) -> dict[str, object]:
    body: dict[str, object] = {
        "adapter": adapter,
        "outcome": outcome,
        "event_id": str(event_id),
        "payload": {},
    }
    if occurred_at is not None:
        body["occurred_at"] = occurred_at
    if extra:
        body.update(extra)
    return body


def _outcome_payload(
    *, project_id: ProjectId, principal_id: PrincipalId, run_id: RunId, event: dict[str, object]
) -> dict[str, object]:
    return {
        "project_id": str(project_id.value),
        "principal_id": str(principal_id.value),
        "run_id": str(run_id.value),
        "event": event,
    }


@dataclass
class _Harness:
    queue: FakeQueue
    repo: FakeOutcomeRepo
    clock: FakeClock
    settings: TracebedSettings
    intake: OutcomeIntake


def _harness(settings: TracebedSettings) -> _Harness:
    clock = FakeClock()
    queue = FakeQueue()
    repo = FakeOutcomeRepo()
    intake = OutcomeIntake(queue, repo, clock, settings)
    return _Harness(queue, repo, clock, settings, intake)


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("adapter", "outcome", "expected_r", "expected_w_zero"),
    [
        (AdapterClass.VERDICT.value, "positive", 1.0, False),
        (AdapterClass.VERDICT.value, "negative", 0.0, False),
        (AdapterClass.CORRECTION_ADAPTER.value, "positive", 1.0, False),
        (AdapterClass.DOWNSTREAM.value, "negative", 0.0, False),
        (AdapterClass.IMPLICIT.value, "positive", 1.0, True),
        (AdapterClass.IMPLICIT.value, "negative", 0.0, True),
    ],
)
def test_r_and_w_zero_derivation(
    settings: TracebedSettings, adapter: str, outcome: str, expected_r: float, expected_w_zero: bool
) -> None:
    h = _harness(settings)
    project_id = ProjectId(uuid7())
    principal_id = PrincipalId(uuid7())
    run_id = RunId(uuid7())
    event_id = uuid4()

    h.queue.enqueue(
        TOPIC_OUTCOME_EVENT,
        _outcome_payload(
            project_id=project_id,
            principal_id=principal_id,
            run_id=run_id,
            event=_feedback_event(adapter=adapter, outcome=outcome, event_id=event_id),
        ),
    )
    processed = h.intake.run_once()

    assert processed == 1
    row = h.repo.rows[(project_id, event_id)]
    assert row.r == expected_r
    assert row.w_zero is expected_w_zero
    assert row.adapter.value == adapter
    assert row.principal_id == principal_id  # authenticated principal, not caller-supplied
    assert row.run_id == run_id


def test_feedback_days_after_trace_joins_by_run_id(settings: TracebedSettings) -> None:
    """A trace posted at T and feedback posted at T+2 SIMULATED DAYS still
    join by `run_id` -- `occurred_at` precedes `arrived_at` by two days, and
    nothing here requires the trace to already exist (no FK, contract §11)."""
    h = _harness(settings)
    project_id = ProjectId(uuid7())
    principal_id = PrincipalId(uuid7())
    run_id = RunId(uuid7())
    event_id = uuid4()

    occurred_at = h.clock.now()  # "T": when the underlying trace happened
    h.clock.advance(timedelta(days=2))  # feedback arrives two simulated days later

    h.queue.enqueue(
        TOPIC_OUTCOME_EVENT,
        _outcome_payload(
            project_id=project_id,
            principal_id=principal_id,
            run_id=run_id,
            event=_feedback_event(
                adapter=AdapterClass.VERDICT.value,
                outcome="positive",
                event_id=event_id,
                occurred_at=occurred_at.isoformat(),
            ),
        ),
    )
    processed = h.intake.run_once()

    assert processed == 1
    row = h.repo.rows[(project_id, event_id)]
    assert row.run_id == run_id  # the logical join key
    assert row.occurred_at == occurred_at
    assert row.arrived_at == occurred_at + timedelta(days=2)
    assert row.arrived_at - row.occurred_at == timedelta(days=2)


def test_replayed_event_id_inserts_exactly_one_row(settings: TracebedSettings) -> None:
    h = _harness(settings)
    project_id = ProjectId(uuid7())
    principal_id = PrincipalId(uuid7())
    run_id = RunId(uuid7())
    event_id = uuid4()

    event = _feedback_event(adapter=AdapterClass.VERDICT.value, outcome="positive", event_id=event_id)
    id1 = h.queue.enqueue(
        TOPIC_OUTCOME_EVENT,
        _outcome_payload(project_id=project_id, principal_id=principal_id, run_id=run_id, event=event),
    )
    id2 = h.queue.enqueue(
        TOPIC_OUTCOME_EVENT,
        _outcome_payload(project_id=project_id, principal_id=principal_id, run_id=run_id, event=event),
    )

    processed = h.intake.run_once()

    assert processed == 2  # both items successfully handled (dedup is a repo-level no-op, not a failure)
    assert sorted(h.queue.acked) == sorted([id1, id2])
    assert h.queue.nacked == []
    assert len(h.repo.rows) == 1  # ON CONFLICT (project_id, event_id) DO NOTHING -> exactly one row
    assert len(h.repo.insert_calls) == 2  # the repo WAS called twice; it deduped, not the consumer


def test_payload_with_weight_field_is_rejected(settings: TracebedSettings) -> None:
    """`FeedbackEvent` has no `weight` field and `extra="forbid"` — a raw
    queue payload naming one fails Pydantic validation exactly the way the
    wire route would 422 it, and nothing is ever inserted for it."""
    h = _harness(settings)
    project_id = ProjectId(uuid7())
    principal_id = PrincipalId(uuid7())
    run_id = RunId(uuid7())

    event = _feedback_event(
        adapter=AdapterClass.VERDICT.value,
        outcome="positive",
        event_id=uuid4(),
        extra={"weight": 0.9},
    )
    bad_id = h.queue.enqueue(
        TOPIC_OUTCOME_EVENT,
        _outcome_payload(project_id=project_id, principal_id=principal_id, run_id=run_id, event=event),
    )

    processed = h.intake.run_once()

    assert processed == 0
    assert h.repo.insert_calls == []
    assert h.repo.rows == {}
    assert h.queue.nacked and h.queue.nacked[0][0] == bad_id
    assert h.queue.acked == []


def test_unknown_adapter_is_rejected(settings: TracebedSettings) -> None:
    """`adapter` is validated against the closed `AdapterClass` vocabulary --
    an out-of-vocabulary value fails the same way a missing field does."""
    h = _harness(settings)
    project_id = ProjectId(uuid7())
    principal_id = PrincipalId(uuid7())
    run_id = RunId(uuid7())

    event = _feedback_event(adapter="not_a_real_adapter", outcome="positive", event_id=uuid4())
    bad_id = h.queue.enqueue(
        TOPIC_OUTCOME_EVENT,
        _outcome_payload(project_id=project_id, principal_id=principal_id, run_id=run_id, event=event),
    )

    processed = h.intake.run_once()

    assert processed == 0
    assert h.repo.insert_calls == []
    assert h.queue.nacked and h.queue.nacked[0][0] == bad_id


def test_outcome_intake_module_never_imports_state_machine() -> None:
    """PHASE0-CONTRACT.md §11: "zero Q-mutation code exists in Phase 0 at
    all" -- checked here as a static property of `outcome_intake.py`'s own
    import list (not the whole process's `sys.modules`, which other test
    modules may have already populated), so this holds regardless of test
    order."""
    import ast
    import inspect

    import tracebed.ingest.outcome_intake as module

    tree = ast.parse(inspect.getsource(module))
    imported_modules = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    assert not any("state_machine" in name for name in imported_modules)


def test_implicit_adapter_never_reaches_state_machine_or_scoring(settings: TracebedSettings) -> None:
    """An `implicit`-adapter outcome is recorded with the `w_zero` marker
    while touching NOTHING beyond `insert_outcome_event` -- `FakeOutcomeRepo`
    defines no other method, so any Q-mutation call would be a bare
    `AttributeError`, not a silently-tolerated side effect."""
    h = _harness(settings)
    project_id = ProjectId(uuid7())
    principal_id = PrincipalId(uuid7())
    run_id = RunId(uuid7())
    event_id = uuid4()

    h.queue.enqueue(
        TOPIC_OUTCOME_EVENT,
        _outcome_payload(
            project_id=project_id,
            principal_id=principal_id,
            run_id=run_id,
            event=_feedback_event(adapter=AdapterClass.IMPLICIT.value, outcome="positive", event_id=event_id),
        ),
    )
    processed = h.intake.run_once()

    assert processed == 1
    row = h.repo.rows[(project_id, event_id)]
    assert row.w_zero is True
    # FakeOutcomeRepo defines exactly one method -- insert_outcome_event was
    # the only call the consumer could possibly have made.
    assert h.repo.insert_calls == [(project_id, row)]


# --------------------------------------------------------------------------- #
# Adversarial: identity, tenancy, clocks, and failure isolation
# --------------------------------------------------------------------------- #


def test_identity_comes_from_the_envelope_not_the_event_body(
    settings: TracebedSettings,
) -> None:
    """§9.5: `project_id`/`principal_id` are injected server-side from
    `ProjectScope`. `FeedbackEvent.payload` is open business data — naming
    those keys inside it must be inert, never an identity the row is
    attributed to (invariant 4 and the `w`-derivation half of invariant 8,
    which keys off the AUTHENTICATED adapter/principal)."""
    h = _harness(settings)
    project_id = ProjectId(uuid7())
    principal_id = PrincipalId(uuid7())
    forged_principal = PrincipalId(uuid7())
    forged_project = ProjectId(uuid7())
    run_id = RunId(uuid7())
    event_id = uuid4()

    event = _feedback_event(
        adapter=AdapterClass.VERDICT.value, outcome="positive", event_id=event_id
    )
    event["payload"] = {
        "principal_id": str(forged_principal.value),
        "project_id": str(forged_project.value),
    }
    h.queue.enqueue(
        TOPIC_OUTCOME_EVENT,
        _outcome_payload(
            project_id=project_id, principal_id=principal_id, run_id=run_id, event=event
        ),
    )

    assert h.intake.run_once() == 1
    assert (forged_project, event_id) not in h.repo.rows
    row = h.repo.rows[(project_id, event_id)]
    assert row.principal_id == principal_id
    assert h.repo.insert_calls[0][0] == project_id


def test_envelope_project_id_disagreeing_with_the_queue_row_is_refused(
    settings: TracebedSettings,
) -> None:
    """The queue row's `project_id` column is the scoping authority (§5.3);
    a payload-derived one must never choose the tenant a row lands in."""
    h = _harness(settings)
    claimed_project = ProjectId(uuid7())
    row_project = ProjectId(uuid7())

    bad_id = h.queue.enqueue(
        TOPIC_OUTCOME_EVENT,
        _outcome_payload(
            project_id=claimed_project,
            principal_id=PrincipalId(uuid7()),
            run_id=RunId(uuid7()),
            event=_feedback_event(
                adapter=AdapterClass.VERDICT.value, outcome="positive", event_id=uuid4()
            ),
        ),
        project_id=row_project,
    )

    assert h.intake.run_once() == 0
    assert h.repo.insert_calls == []
    assert h.queue.nacked and h.queue.nacked[0][0] == bad_id
    assert h.queue.acked == []


def test_naive_occurred_at_is_refused(settings: TracebedSettings) -> None:
    """`outcome_event.occurred_at` is `timestamptz`. A naive value is
    silently reinterpreted in the server session's timezone — the event moves
    by hours and nothing downstream can tell. Every other wire timestamp is
    rejected when naive (`_EventBase.ts`); this one has no such validator on
    the model, so ingest refuses it."""
    h = _harness(settings)
    project_id = ProjectId(uuid7())

    bad_id = h.queue.enqueue(
        TOPIC_OUTCOME_EVENT,
        _outcome_payload(
            project_id=project_id,
            principal_id=PrincipalId(uuid7()),
            run_id=RunId(uuid7()),
            event=_feedback_event(
                adapter=AdapterClass.VERDICT.value,
                outcome="positive",
                event_id=uuid4(),
                occurred_at="2026-01-01T00:00:00",  # no offset
            ),
        ),
    )

    assert h.intake.run_once() == 0
    assert h.repo.insert_calls == []
    assert h.queue.nacked and h.queue.nacked[0][0] == bad_id
    assert h.queue.acked == []


def test_insert_failure_isolates_one_item_and_the_batch_continues(
    settings: TracebedSettings,
) -> None:
    """One item whose insert raises must be nacked on its own. Letting the
    exception escape `run_once` abandons every later item in the claimed
    batch to its lease timeout — a stall that looks like data loss."""
    h = _harness(settings)
    project_id = ProjectId(uuid7())
    principal_id = PrincipalId(uuid7())
    run_id = RunId(uuid7())
    doomed_event_id = uuid4()
    good_event_id = uuid4()
    h.repo.fail_event_ids.add(doomed_event_id)

    bad_id = h.queue.enqueue(
        TOPIC_OUTCOME_EVENT,
        _outcome_payload(
            project_id=project_id,
            principal_id=principal_id,
            run_id=run_id,
            event=_feedback_event(
                adapter=AdapterClass.VERDICT.value, outcome="positive", event_id=doomed_event_id
            ),
        ),
    )
    good_id = h.queue.enqueue(
        TOPIC_OUTCOME_EVENT,
        _outcome_payload(
            project_id=project_id,
            principal_id=principal_id,
            run_id=run_id,
            event=_feedback_event(
                adapter=AdapterClass.VERDICT.value, outcome="negative", event_id=good_event_id
            ),
        ),
    )

    assert h.intake.run_once() == 1
    assert h.queue.acked == [good_id]
    assert [i for i, _b in h.queue.nacked] == [bad_id]
    assert (project_id, good_event_id) in h.repo.rows
    assert (project_id, doomed_event_id) not in h.repo.rows


def test_negative_or_missing_adapter_weight_fails_closed(
    settings: TracebedSettings,
) -> None:
    """`w` is server-derived. A weights map that omits an adapter class, or
    configures it negative, must fail closed to "do not score" — a negative
    `w` inverts the Q update, which is strictly worse than the guessed reward
    invariant 8 exists to forbid."""
    hostile = settings.model_copy(update={"scoring": ScoringConfig(adapter_weights={"verdict": -1.0})})
    h = _harness(hostile)
    project_id = ProjectId(uuid7())
    principal_id = PrincipalId(uuid7())

    ids = {}
    for adapter in (AdapterClass.VERDICT, AdapterClass.DOWNSTREAM):
        event_id = uuid4()
        ids[adapter] = event_id
        h.queue.enqueue(
            TOPIC_OUTCOME_EVENT,
            _outcome_payload(
                project_id=project_id,
                principal_id=principal_id,
                run_id=RunId(uuid7()),
                event=_feedback_event(
                    adapter=adapter.value, outcome="positive", event_id=event_id
                ),
            ),
        )

    assert h.intake.run_once() == 2
    assert h.repo.rows[(project_id, ids[AdapterClass.VERDICT])].w_zero is True  # negative weight
    assert h.repo.rows[(project_id, ids[AdapterClass.DOWNSTREAM])].w_zero is True  # absent key


def test_real_repo_satisfies_the_port_outcome_intake_declares() -> None:
    """Keeps `FakeOutcomeRepo` honest without a database: a renamed method or
    parameter on the real `Repo` would otherwise leave every test above
    green while production broke on the first outcome."""
    import inspect

    from tracebed.stores.pg.repo import Repo

    row = OutcomeEventInsert(
        event_id=uuid4(),
        run_id=RunId(uuid7()),
        principal_id=PrincipalId(uuid7()),
        adapter=AdapterClass.VERDICT,
        r=1.0,
        w_zero=False,
        payload={},
        occurred_at=FakeClock().now(),
        arrived_at=FakeClock().now(),
    )
    inspect.signature(Repo.insert_outcome_event).bind(object(), ProjectId(uuid7()), row)
