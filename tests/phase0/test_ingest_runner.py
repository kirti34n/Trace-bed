"""ConsumerRunner tests (`src/tracebed/ingest/runner.py`).

NOTE: `ingest/runner.py` is not in PHASE0-CONTRACT.md §1's module map and so
has no §13.2 test-file row either — it exists because the ingest chunk's
assigned file list names it (the conflict is reported as a contract_gap in
the module's own docstring). It is real scheduling logic on the write path
and is tested here rather than shipped unexercised.

Offline: the two consumers are replaced by counting stubs, so this file
proves the SCHEDULER's behaviour (isolation, cadence, shutdown) and nothing
about ingestion itself.
"""

from __future__ import annotations

import threading

import pytest

from tracebed.domain.clock import FakeClock
from tracebed.ingest.runner import ConsumerRunner, RunnerConfig

pytestmark = pytest.mark.phase0


class _StubConsumer:
    """Stands in for `TraceWriter`/`OutcomeIntake`'s `run_once`."""

    def __init__(self, per_call: int = 0, *, raises: bool = False) -> None:
        self.per_call = per_call
        self.raises = raises
        self.calls: list[int | None] = []
        self.sweeps = 0
        self.sweep_raises = False

    def run_once(self, max_batch: int | None = None) -> int:
        self.calls.append(max_batch)
        if self.raises:
            raise RuntimeError("consumer down")
        return self.per_call

    def sweep_incomplete(self) -> int:
        self.sweeps += 1
        if self.sweep_raises:
            raise RuntimeError("sweep down")
        return 3


def _runner(
    writer: _StubConsumer, outcomes: _StubConsumer, clock: FakeClock, config: RunnerConfig
) -> ConsumerRunner:
    return ConsumerRunner(writer, outcomes, clock, config)  # type: ignore[arg-type]


def test_poll_once_dispatches_both_topics_with_their_batch_sizes() -> None:
    writer, outcomes, clock = _StubConsumer(4), _StubConsumer(2), FakeClock()
    runner = _runner(writer, outcomes, clock, RunnerConfig(trace_batch=7, outcome_batch=9))

    assert runner.poll_once() == 6
    assert writer.calls == [7]
    assert outcomes.calls == [9]


def test_one_topic_failing_does_not_stop_the_other() -> None:
    """A crashed dispatch loop stops BOTH drains; that is strictly worse than
    one topic being down."""
    writer, outcomes, clock = _StubConsumer(raises=True), _StubConsumer(5), FakeClock()
    runner = _runner(writer, outcomes, clock, RunnerConfig())

    assert runner.poll_once() == 5
    assert outcomes.calls == [None]


def test_sweep_failure_is_isolated_too() -> None:
    writer, clock = _StubConsumer(), FakeClock()
    writer.sweep_raises = True
    runner = _runner(writer, _StubConsumer(), clock, RunnerConfig())

    assert runner.sweep_once() == 0
    assert writer.sweeps == 1


def test_sweep_cadence_is_wall_clock_not_poll_count() -> None:
    """A busy queue makes `poll_once` return immediately. A poll-counted
    cadence would then run a full `list_project_ids` x
    `find_runs_missing_sentinel` scan every few milliseconds — the sweeper
    out-loading the ingest it supervises, exactly when it is busiest."""
    writer, clock = _StubConsumer(per_call=100), FakeClock()
    runner = _runner(writer, _StubConsumer(), clock, RunnerConfig(sweep_interval_s=60.0))

    for _ in range(500):  # 500 back-to-back busy polls, no time passing
        runner.poll_once()
        runner.sweep_if_due()
    assert writer.sweeps == 0

    clock.advance(seconds=60)
    runner.sweep_if_due()
    assert writer.sweeps == 1

    # And the interval restarts from the sweep, not from process start.
    clock.advance(seconds=59)
    runner.sweep_if_due()
    assert writer.sweeps == 1
    clock.advance(seconds=1)
    runner.sweep_if_due()
    assert writer.sweeps == 2


def test_run_forever_stops_on_the_event_and_on_max_iterations() -> None:
    writer, outcomes, clock = _StubConsumer(1), _StubConsumer(), FakeClock()
    runner = _runner(writer, outcomes, clock, RunnerConfig(poll_interval_s=0.0))

    runner.run_forever(threading.Event(), max_iterations=3)
    assert len(writer.calls) == 3

    already_stopped = threading.Event()
    already_stopped.set()
    runner.run_forever(already_stopped, max_iterations=10)
    assert len(writer.calls) == 3  # not one extra poll after shutdown was requested


def test_idle_loop_waits_on_the_stop_event_rather_than_sleeping() -> None:
    """`stop.wait()` (not `time.sleep`) is what makes shutdown immediate
    during an idle interval instead of one full poll period late."""
    writer, clock = _StubConsumer(0), FakeClock()
    runner = _runner(writer, _StubConsumer(0), clock, RunnerConfig(poll_interval_s=30.0))
    stop = threading.Event()

    thread = threading.Thread(target=runner.run_forever, args=(stop,), daemon=True)
    thread.start()
    stop.set()
    thread.join(timeout=5.0)
    assert not thread.is_alive()
