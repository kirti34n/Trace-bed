"""`workers.registry` -- queue-topic -> `BatchHandler` coverage (PLAN.md §7 Phase 2, chunk
`worker-handlers`).

Everything here is offline: a fake `QueueConsumerPort` and `FakeClock`, no Postgres. Own fakes
per this codebase's convention (`tests/phase2/test_worker_runner.py`'s own docstring: "a shared
fakes module would be a merge collision") -- this file does not import `test_worker_runner.py`'s.

See `src/tracebed/workers/registry.py`'s module docstring for why `build_default_registry`
returns an empty mapping today: every topic `stores.pg.queue` currently defines is either
already owned end-to-end by a dedicated, self-claiming consumer thread (the three real topics)
or does not exist as a queue topic at all (the five extra names this chunk's own task brief
named, which `stores.pg.queue`'s module comment and PHASE0-CONTRACT.md §14 explicitly forbid
adding). What is tested here is that this is an AUDITED empty registry, not the unaudited
`handlers={}` literal the chunk exists to remove: every topic is accounted for by name and
reason, the coverage relationship is ENFORCED in both directions by `validate_topic_coverage`
(driven here with synthetic arrangements, so each refusal is observed failing rather than only
asserted true of the one arrangement that happens to be correct today), `build_default_registry`
is shown to actually run that check on the map it returns, the forbidden literal cannot creep
back into `runner.py`, and a handler that WOULD be plugged into this exact `Mapping[str,
BatchHandler]` shape is dispatched, retried, kept project-homogeneous, and shut down correctly by
`WorkerRunner` -- proving the registry's output type is genuinely usable, not merely well-typed.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from types import MappingProxyType
from uuid import uuid4

import pytest

import tracebed.stores.pg.queue as queue_module
from tracebed.domain.clock import FakeClock
from tracebed.domain.errors import ConfigError
from tracebed.domain.ids import ProjectId
from tracebed.stores.pg.queue import QueueItem, compute_backoff
from tracebed.workers import registry as registry_module
from tracebed.workers import runner as runner_module
from tracebed.workers.registry import (
    ALL_TOPICS,
    UNREGISTERED_TOPICS,
    WorkerDeps,
    build_default_registry,
    validate_topic_coverage,
)
from tracebed.workers.runner import WorkBatch, WorkerRunner

# --------------------------------------------------------------------------- #
# Fakes -- one per test module (see docstring).
# --------------------------------------------------------------------------- #


@dataclass
class _Row:
    id: int
    topic: str
    project_id: ProjectId
    payload: dict[str, object]
    attempts: int = 0
    leased: bool = False


class FakeQueue:
    """Minimal `QueueConsumerPort`: `claim()` skips already-leased rows (mirrors SKIP LOCKED),
    `ack()` deletes, `nack()` clears the lease so the row is claimable again."""

    def __init__(self) -> None:
        self._rows: dict[int, _Row] = {}
        self._next_id = 1
        self.acked: list[int] = []
        self.nacked: list[tuple[int, timedelta]] = []
        self.claim_calls: list[tuple[str, int]] = []

    def enqueue(self, topic: str, project_id: ProjectId, payload: dict[str, object]) -> int:
        row_id = self._next_id
        self._next_id += 1
        self._rows[row_id] = _Row(id=row_id, topic=topic, project_id=project_id, payload=payload)
        return row_id

    def claim(self, topic: str, n: int) -> list[QueueItem]:
        self.claim_calls.append((topic, n))
        claimed: list[QueueItem] = []
        for row in self._rows.values():
            if row.topic != topic or row.leased:
                continue
            if len(claimed) >= n:
                break
            row.leased = True
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
        if item_id in self._rows:
            self._rows[item_id].leased = False
        self.nacked.append((item_id, backoff))


@dataclass
class _RaisingHandler:
    """A `BatchHandler` that always raises -- proves a handler plugged into this registry's
    exact `Mapping[str, BatchHandler]` shape is nacked with backoff and does not kill the
    runner, without re-deriving `test_worker_runner.py`'s own broader coverage of that
    machinery."""

    calls: list[WorkBatch] = field(default_factory=list)

    def handle(self, batch: WorkBatch) -> None:
        self.calls.append(batch)
        raise RuntimeError("synthetic handler failure")


@dataclass
class _RecordingHandler:
    """A `BatchHandler` that only records what it was handed."""

    seen: list[WorkBatch] = field(default_factory=list)

    def handle(self, batch: WorkBatch) -> None:
        self.seen.append(batch)


@dataclass
class _StopMidBatchHandler:
    """Sets `stop` as a side effect of handling -- simulates a shutdown request arriving
    while a batch this registry's mapping dispatched to is still in flight."""

    stop: threading.Event
    seen: list[WorkBatch] = field(default_factory=list)

    def handle(self, batch: WorkBatch) -> None:
        self.seen.append(batch)
        self.stop.set()


# --------------------------------------------------------------------------- #
# Coverage: every topic `stores.pg.queue` defines is registered or justified,
# in both directions -- the regression `handlers={}` was a silent backlog.
# --------------------------------------------------------------------------- #


def test_all_topics_matches_the_three_queue_defines_today() -> None:
    """`ALL_TOPICS` is discovered by introspecting `stores.pg.queue`, not hand-copied (see
    `registry.py`'s module docstring) -- pinned here against the three constants that module
    exports today so a silent drift in either direction fails loudly."""
    assert {
        queue_module.TOPIC_TRACE_EVENT,
        queue_module.TOPIC_OUTCOME_EVENT,
        queue_module.TOPIC_MEMORY_PROPOSAL,
    } == ALL_TOPICS


def test_every_queue_topic_is_registered_or_explicitly_unregistered_with_a_reason() -> None:
    registered = set(build_default_registry(WorkerDeps()))
    unregistered = set(UNREGISTERED_TOPICS)
    # Neither: a topic nothing consumes is a silent backlog.
    assert registered | unregistered >= ALL_TOPICS
    # Both: a topic cannot be simultaneously live and disclaimed.
    assert registered.isdisjoint(unregistered)
    # Exactly: nothing is claimed for a topic that does not exist.
    assert (registered | unregistered) == ALL_TOPICS


def test_unregistered_reasons_are_real_explanations_not_placeholders() -> None:
    for topic, reason in UNREGISTERED_TOPICS.items():
        assert topic in ALL_TOPICS
        assert isinstance(reason, str)
        # A placeholder ("TODO", "n/a", "") would trivially fail this floor; the real reasons
        # each cite the owning consumer and the specific hazard of registering the topic twice.
        assert len(reason) > 60


# --------------------------------------------------------------------------- #
# The coverage relationship is ENFORCED, not merely asserted about today's
# arrangement. Each refusal below is driven with synthetic inputs so it is
# observed firing; the positive control proves the validator is not simply
# raising on everything.
# --------------------------------------------------------------------------- #

_A = "alpha_topic"
_B = "beta_topic"
_REASON = (
    "consumed end-to-end by a dedicated self-claiming loop constructed directly in "
    "workers.runner.run(); a second BatchHandler layer would double-claim its rows"
)


def test_validate_accepts_a_registry_that_partitions_the_topic_set() -> None:
    """Positive control: without this, every refusal below would also pass against a
    validator that raised unconditionally -- the leak-probe failure mode this repo has
    shipped before."""
    validate_topic_coverage(
        {_A: _RecordingHandler()},
        all_topics=frozenset({_A, _B}),
        unregistered={_B: _REASON},
    )


def test_validate_rejects_a_handler_for_a_topic_the_queue_does_not_define() -> None:
    """A typo'd or invented topic key: `WorkerRunner` would poll it forever against a topic
    no producer writes to -- no error, no work, and a process that looks busy."""
    with pytest.raises(ConfigError) as excinfo:
        validate_topic_coverage(
            {_A: _RecordingHandler(), "distil": _RecordingHandler()},
            all_topics=frozenset({_A, _B}),
            unregistered={_B: _REASON},
        )
    assert "distil" in str(excinfo.value)


def test_validate_rejects_a_topic_covered_by_neither_half() -> None:
    """The omitted-worker case: a handler dropped because its dependency was absent shrinks
    the registry, and the deployed process then drains that topic never."""
    with pytest.raises(ConfigError) as excinfo:
        validate_topic_coverage(
            {_A: _RecordingHandler()},
            all_topics=frozenset({_A, _B}),
            unregistered={},
        )
    assert _B in str(excinfo.value)


def test_validate_rejects_a_topic_that_is_both_registered_and_disclaimed() -> None:
    with pytest.raises(ConfigError) as excinfo:
        validate_topic_coverage(
            {_A: _RecordingHandler(), _B: _RecordingHandler()},
            all_topics=frozenset({_A, _B}),
            unregistered={_B: _REASON},
        )
    assert _B in str(excinfo.value)


def test_validate_rejects_a_stale_disclaimer_for_a_topic_that_no_longer_exists() -> None:
    """A disclaimer outliving its topic silently discharges the coverage check for a name
    nothing enqueues onto."""
    with pytest.raises(ConfigError) as excinfo:
        validate_topic_coverage(
            {_A: _RecordingHandler()},
            all_topics=frozenset({_A}),
            unregistered={_B: _REASON},
        )
    assert _B in str(excinfo.value)


def test_validate_rejects_an_empty_topic_set_rather_than_passing_vacuously() -> None:
    """`ALL_TOPICS` is introspected off `stores.pg.queue`. If that discovery silently stops
    finding anything, every set relation in the validator is satisfied by any registry at
    all -- including one consuming nothing. That degeneracy is refused, not tolerated."""
    with pytest.raises(ConfigError) as excinfo:
        validate_topic_coverage({}, all_topics=frozenset(), unregistered={})
    assert "ALL_TOPICS" in str(excinfo.value)


def test_validate_rejects_a_placeholder_reason_that_would_discharge_the_check() -> None:
    with pytest.raises(ConfigError) as excinfo:
        validate_topic_coverage(
            {_A: _RecordingHandler()},
            all_topics=frozenset({_A, _B}),
            unregistered={_B: "TODO"},
        )
    assert _B in str(excinfo.value)


def test_build_default_registry_actually_runs_the_coverage_check_on_what_it_returns() -> None:
    """Guards the WIRING, not the validator: the checks above all pass if
    `build_default_registry` never calls `validate_topic_coverage` at all. Records the exact
    argument, so a call that validated some other mapping than the one returned is caught
    too."""
    checked: list[Mapping[str, object]] = []

    def _spy(registered: Mapping[str, object]) -> None:
        checked.append(dict(registered))

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(registry_module, "validate_topic_coverage", _spy)
        built = build_default_registry(WorkerDeps())

    assert checked == [dict(built)]


def test_the_returned_registry_and_the_reason_table_cannot_be_mutated_after_the_check() -> None:
    """Both are read-only views. A mutable registry could gain a phantom topic AFTER
    validation; a mutable reason table lets an importer rewrite the audit trail a deployed
    process reports."""
    built = build_default_registry(WorkerDeps())
    with pytest.raises(TypeError):
        built["sneaked_in"] = _RecordingHandler()  # type: ignore[index]
    with pytest.raises(TypeError):
        UNREGISTERED_TOPICS["sneaked_in"] = _REASON  # type: ignore[index]


# --------------------------------------------------------------------------- #
# `handlers={}` cannot come back silently.
# --------------------------------------------------------------------------- #


def test_build_default_registry_is_a_real_mapping_and_is_pure() -> None:
    first = build_default_registry(WorkerDeps())
    second = build_default_registry(WorkerDeps())
    assert isinstance(first, Mapping)
    assert first == second == {}


def test_runner_no_longer_constructs_the_bare_empty_handlers_literal() -> None:
    """The regression this chunk exists to prevent: `workers/runner.py:422` used to read
    `handlers={}` -- an unaudited empty literal with no record of why nothing was reachable.
    Asserts the literal is gone AS CODE and the real construction call is in its place,
    directly against the source `runner.run()` ships, so a future edit that reintroduces the
    literal (even one that happens to still pass every other test) fails this one.

    Matches only the dict-literal-as-argument shape (`handlers={}` immediately followed by `,`
    or `)`), not the substring anywhere in the file: `run()`'s own docstring still narrates the
    pre-fix history in prose ("registered with `handlers={}` today") per this chunk's hard
    rule to change nothing else in `runner.py` -- that sentence is now stale prose, reported as
    a contract_gap, not a second thing this regression guard needs to police.
    """
    source = Path(runner_module.__file__).read_text(encoding="utf-8")
    assert re.search(r"handlers=\{\}\s*[,)]", source) is None
    assert "handlers=build_default_registry(" in source


# --------------------------------------------------------------------------- #
# The registry's output type is genuinely usable by `WorkerRunner`, not merely
# well-typed: an idle run with today's (empty) registry, and a handler plugged
# into the same `Mapping[str, BatchHandler]` shape dispatched/retried/shut down
# correctly.
# --------------------------------------------------------------------------- #


def test_worker_runner_accepts_registry_output_and_idles_cleanly() -> None:
    fake_queue = FakeQueue()
    worker = WorkerRunner(
        queue=fake_queue,
        clock=FakeClock(),
        handlers=build_default_registry(WorkerDeps()),
        batch_size=10,
        lease_seconds=30,
    )
    processed = worker.run_once()
    assert processed == 0
    # No topics registered today (see module docstring) -- nothing should even be polled.
    assert fake_queue.claim_calls == []


def test_a_raising_handler_is_nacked_with_backoff_and_the_runner_survives() -> None:
    fake_queue = FakeQueue()
    project_id = ProjectId(uuid4())
    row_id = fake_queue.enqueue("probe_topic", project_id, {"k": "v"})
    handler = _RaisingHandler()
    worker = WorkerRunner(
        queue=fake_queue,
        clock=FakeClock(),
        handlers={"probe_topic": handler},
        batch_size=10,
        lease_seconds=30,
    )

    processed = worker.run_once()

    assert processed == 1
    assert len(handler.calls) == 1
    assert fake_queue.acked == []
    assert fake_queue.nacked == [(row_id, compute_backoff(1))]
    # The runner itself did not raise -- it can still take another round.
    worker.run_once()


def test_a_registered_handler_never_sees_two_projects_in_one_batch() -> None:
    """PLAN.md §10. `work_queue` is unpartitioned, so ONE `claim()` for one topic returns rows
    for several projects interleaved; a handler reached through this registry's `Mapping[str,
    BatchHandler]` must still only ever be handed one project at a time."""
    fake_queue = FakeQueue()
    left, right = ProjectId(uuid4()), ProjectId(uuid4())
    for project_id in (left, right, left, right):
        fake_queue.enqueue("probe_topic", project_id, {})
    handler = _RecordingHandler()
    worker = WorkerRunner(
        queue=fake_queue,
        clock=FakeClock(),
        handlers={"probe_topic": handler},
        batch_size=10,
        lease_seconds=30,
    )

    assert worker.run_once() == 4

    assert [batch.project_id for batch in handler.seen] == [left, right]
    for batch in handler.seen:
        assert {item.project_id for item in batch.items} == {batch.project_id}
        assert len(batch.items) == 2


def test_graceful_shutdown_mid_batch_completes_the_round_without_double_acking() -> None:
    fake_queue = FakeQueue()
    project_id = ProjectId(uuid4())
    row_ids = [fake_queue.enqueue("probe_topic", project_id, {}) for _ in range(3)]
    stop = threading.Event()
    handler = _StopMidBatchHandler(stop=stop)
    worker = WorkerRunner(
        queue=fake_queue,
        clock=FakeClock(),
        handlers={"probe_topic": handler},
        batch_size=10,
        lease_seconds=30,
    )

    worker.run_forever(stop, max_iterations=5)

    # `stop` was set from inside the handler while the round was in flight; only that one
    # round ran (checked BETWEEN run_once() calls, never inside one -- module docstring).
    assert len(handler.seen) == 1
    assert sorted(fake_queue.acked) == sorted(row_ids)
    assert fake_queue.nacked == []
    assert len(fake_queue.acked) == len(set(fake_queue.acked))
