"""Consumer runner: the process loop that drives `TraceWriter`/`OutcomeIntake`.

CONTRACT_GAP: PHASE0-CONTRACT.md §1's module map has no row for
`ingest/runner.py` -- only `ingest/trace_writer.py` and
`ingest/outcome_intake.py` are listed under chunk `ingest`, and §1 states
plainly: "If a file is not in this table, it is not part of Phase 0 -- do
not create it." This file exists because the orchestrating task's explicit
FILE LIST for this chunk names `src/tracebed/ingest/runner.py` and describes
its job ("the consumer loop -- claim/ack/nack via QueueConsumerPort, lease
renewal, graceful shutdown, per-topic dispatch, metrics"). The two
instructions conflict; per this chunk's hard rule 6 ("write ONLY the files
in YOUR FILE LIST"), the file is written, and the conflict is reported
verbatim as a contract_gap rather than silently resolved in either
direction.

Scope, given the conflict: `TraceWriter.run_once`/`OutcomeIntake.run_once`
already own claim/ack/nack internally (contract §11) -- a second layer of
claim/ack/nack here would double-claim the same queue rows against the same
`QueueConsumerPort`. This module is therefore a thin scheduler over the two
`run_once`/`sweep_incomplete` methods, never a second consumer
implementation reaching into the queue directly. "Lease renewal" is
deliberately NOT implemented: `QueueConsumerPort` (adapters/ports.py, owned
by chunk domain-events-scan) exposes only `claim`/`ack`/`nack` -- there is no
renew-lease primitive to call, and this chunk may not add one to a Protocol
it does not own; each `run_once` call is expected to complete well inside one
lease (`QueueConfig.lease_seconds`), which Phase 0's batch sizes make true in
practice. Metrics are `prometheus_client` counters (the project already
depends on it -- see `stores/pg/queue.py`'s Gauges).
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from prometheus_client import Counter

from tracebed.stores.pg.queue import TOPIC_OUTCOME_EVENT, TOPIC_TRACE_EVENT

if TYPE_CHECKING:
    from tracebed.domain.clock import Clock
    from tracebed.ingest.outcome_intake import OutcomeIntake
    from tracebed.ingest.trace_writer import TraceWriter

__all__ = ["ConsumerRunner", "RunnerConfig"]

logger = logging.getLogger(__name__)

INGEST_EVENTS_PROCESSED: Counter = Counter(
    "tracebed_ingest_events_processed_total",
    "Trace/outcome events successfully processed by the ingest runner.",
    ["topic"],
)
INGEST_RUN_ERRORS: Counter = Counter(
    "tracebed_ingest_run_errors_total",
    "Exceptions raised out of one dispatch cycle ('sweep' for the completeness sweeper).",
    ["topic"],
)


@dataclass(frozen=True, slots=True)
class RunnerConfig:
    """Poll and sweep cadence for the loop. Not specified by the contract (see
    module docstring); kept as explicit, injected values rather than magic
    numbers inside `run_forever` (PLAN.md §6's "no magic numbers" rule)."""

    poll_interval_s: float = 1.0
    # Wall-clock, NOT "every N polls": a busy queue makes `poll_once` return
    # immediately, so a poll-counted cadence collapses to a full
    # `list_project_ids` x `find_runs_missing_sentinel` scan every few
    # milliseconds -- the sweeper would out-load the ingest it exists to
    # supervise, and it would do so exactly when the system is busiest.
    sweep_interval_s: float = 60.0
    trace_batch: int | None = None
    outcome_batch: int | None = None


class ConsumerRunner:
    """Dispatches `TraceWriter`/`OutcomeIntake` on a poll loop with graceful
    shutdown.

    `stop` is an externally-owned `threading.Event`: the caller (a `run()`
    console entry point, or a test) decides how shutdown is triggered --
    a SIGTERM handler, a bounded iteration count, or a test flipping the
    event directly. `run_forever` never installs a signal handler itself,
    so it stays safe to call from a non-main thread (Python only allows
    signal handlers on the main thread).
    """

    def __init__(
        self,
        writer: TraceWriter,
        outcomes: OutcomeIntake,
        clock: Clock,
        config: RunnerConfig | None = None,
    ) -> None:
        self._writer = writer
        self._outcomes = outcomes
        self._clock = clock
        self._config = config or RunnerConfig()
        # Monotonic, never wall time: a clock step (NTP, a container's first
        # sync) must not skip or stampede a sweep. Seeded at construction so
        # the first sweep happens one interval in, not at boot -- N workers
        # restarting together otherwise all scan every project at once.
        self._last_sweep_ms = self._clock.monotonic_ms()

    @property
    def config(self) -> RunnerConfig:
        """Read-only. `RunnerConfig` is frozen, so exposing it cannot let a caller retune
        this loop; it exists so a SIBLING queue consumer in the same process can poll at
        the cadence this loop was actually given rather than restating a literal that
        silently disagrees with it (`workers.runner.run`'s proposal loop)."""
        return self._config

    def poll_once(self) -> int:
        """One dispatch across both topics. Returns total events processed.

        Exceptions from either consumer are caught and counted
        (`INGEST_RUN_ERRORS`) rather than propagated -- one topic's outage
        must not stop the other's drain, and a crashed loop stops BOTH from
        making any progress at all.
        """
        total = self._dispatch_one(
            TOPIC_TRACE_EVENT, self._writer.run_once, self._config.trace_batch
        )
        total += self._dispatch_one(
            TOPIC_OUTCOME_EVENT, self._outcomes.run_once, self._config.outcome_batch
        )
        return total

    def _dispatch_one(
        self, topic: str, run_once: Callable[[int | None], int], batch: int | None
    ) -> int:
        """One consumer's `run_once(batch)`, isolated: an exception here is
        counted and swallowed, never propagated to `poll_once`'s caller."""
        try:
            n = run_once(batch)
        except Exception:
            logger.exception("ingest runner: %s dispatch failed", topic)
            INGEST_RUN_ERRORS.labels(topic=topic).inc()
            return 0
        if n:
            INGEST_EVENTS_PROCESSED.labels(topic=topic).inc(n)
        return n

    def sweep_once(self) -> int:
        """Runs the completeness sweep (`TraceWriter.sweep_incomplete`).
        Isolated from `poll_once` the same way each topic is isolated from
        the other: a sweep failure must not stop event dispatch."""
        self._last_sweep_ms = self._clock.monotonic_ms()
        try:
            return self._writer.sweep_incomplete()
        except Exception:
            logger.exception("ingest runner: completeness sweep failed")
            INGEST_RUN_ERRORS.labels(topic="sweep").inc()
            return 0

    def sweep_if_due(self) -> int:
        """Sweeps only once `sweep_interval_s` of monotonic time has passed."""
        elapsed_ms = self._clock.monotonic_ms() - self._last_sweep_ms
        if elapsed_ms < self._config.sweep_interval_s * 1000.0:
            return 0
        return self.sweep_once()

    def run_forever(self, stop: threading.Event, *, max_iterations: int | None = None) -> None:
        """Polls until `stop` is set (graceful shutdown) or `max_iterations`
        is reached (bounded, so this method is finite and assertable in a
        test -- an unbounded loop cannot be driven to completion by one).

        Sleeps `poll_interval_s` only when a poll cycle did no work, via
        `stop.wait()` rather than `time.sleep()`, so a shutdown request
        during an idle wait is honoured immediately instead of after the
        full interval; a busy queue drains back-to-back with no delay at
        all.
        """
        iterations = 0
        while not stop.is_set():
            processed = self.poll_once()
            self.sweep_if_due()

            iterations += 1
            if max_iterations is not None and iterations >= max_iterations:
                return
            if processed == 0:
                stop.wait(self._config.poll_interval_s)
