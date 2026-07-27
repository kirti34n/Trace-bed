"""Worker process: per-topic `WorkQueue` dispatch (PLAN.md §7 Phase 2, chunk
`worker-runner`). `run()` is pyproject's `tracebed-worker` console entry
point.

Delivery is at-least-once (`stores/pg/queue.py`'s own module docstring):
every handler registered here MUST be idempotent on its own natural key.
This module does not relax that contract, it only dispatches to it: on a
raising handler, the claimed batch is nacked with exponential backoff
(`stores.pg.queue.compute_backoff`) and the loop continues -- one broken
handler must never take the whole process down. On a graceful-shutdown
request, work already claimed for the CURRENT dispatch round is always
driven all the way to ack/nack before the loop exits, so a batch is never
abandoned mid-flight: `run_forever` only re-checks the stop signal BETWEEN
`run_once()` calls, and `run_once()` itself always finishes claiming,
dispatching, and acking/nacking every batch it claims before returning.

Lease renewal: deliberately NOT implemented, mirroring `ingest.runner`'s own
documented choice for the identical reason -- `adapters.ports.QueueConsumerPort`
(owned by chunk `domain-events-scan`, outside this chunk's file list per hard
rule 6) exposes only `claim`/`ack`/`nack`, no renew-lease primitive, and this
chunk may not add one to a Protocol it does not own. Handlers registered here
are expected to complete well inside one lease (`QueueConfig.lease_seconds`);
a handler that cannot is a contract_gap against whichever chunk owns
`adapters/ports.py`/`stores/pg/queue.py`, not something this module can paper
over silently.

What this module CAN do about an overrun, and does: measure it against the
injected clock and refuse the one action that turns an overrun into data
loss. Once a batch's lease has expired, the rows it came from are already
claimable by another consumer (`_CLAIM_SQL`'s `lease_expires_at < now()`),
so a second worker may be holding and processing them right now.
`ack()` after an overrun is still safe -- it deletes a row whose work has
been done, and the other consumer's later `ack()` is a documented no-op. But
`nack()` after an overrun is NOT: `_NACK_SQL` sets `lease_expires_at = NULL`
unconditionally, which CLEARS THE OTHER CONSUMER'S LIVE LEASE and hands the
row to a third worker while the second is still mid-flight -- unbounded
concurrent duplicates from what looks like an ordinary retry. So a batch
whose handler raised AFTER its lease expired is left to expire naturally
(already redeliverable, no lease to clear) and counted on
`WORKER_LEASE_OVERRUNS`, rather than nacked. The cost is one lost backoff
interval on an item that had already overrun; `max_attempts` still bounds it
into `dead_letter`.

PROJECT-HOMOGENEOUS BATCHES (PLAN.md §10 -- no cross-project aggregation of
any kind, ever): `work_queue` is unpartitioned (contract §5.3), so a single
`claim()` call for one topic can return rows for several projects at once.
This module never hands a handler a batch mixing projects: `claim()`'s
result is split by `group_by_project()` into `WorkBatch` values, each
carrying exactly one `ProjectId`, and `WorkBatch.__post_init__` raises
`TypeError` -- not a soft check a caller could catch, log, and ignore -- the
instant a batch would otherwise be constructed spanning two projects, so
"one project per batch" is enforced at the type's own boundary rather than
by convention at each call site.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Protocol

from prometheus_client import Counter

from tracebed.stores.pg.queue import QueueItem, compute_backoff

if TYPE_CHECKING:
    from tracebed.adapters.ports import QueueConsumerPort
    from tracebed.domain.clock import Clock
    from tracebed.domain.ids import ProjectId

__all__ = [
    "BatchHandler",
    "WorkBatch",
    "WorkerRunner",
    "group_by_project",
    "run",
]

logger = logging.getLogger(__name__)

WORKER_BATCHES_PROCESSED: Counter = Counter(
    "tracebed_worker_batches_processed_total",
    "Project-homogeneous batches successfully handled by a worker handler.",
    ["topic"],
)
WORKER_BATCH_ERRORS: Counter = Counter(
    "tracebed_worker_batch_errors_total",
    "Project-homogeneous batches whose handler raised.",
    ["topic"],
)
WORKER_ITEMS_NACKED: Counter = Counter(
    "tracebed_worker_items_nacked_total",
    "Queue items nacked because their batch's handler raised.",
    ["topic"],
)
WORKER_LEASE_OVERRUNS: Counter = Counter(
    "tracebed_worker_lease_overruns_total",
    "Batches whose handler was still running when the claim's lease expired -- "
    "the rows were redeliverable to another consumer while this one held them.",
    ["topic"],
)

_DEFAULT_POLL_INTERVAL: timedelta = timedelta(seconds=1.0)
"""Idle-poll cadence when a round claimed no work. Mirrors
`ingest.runner.RunnerConfig.poll_interval_s`'s own documented reasoning: this
is an operational polling cadence, not one of PLAN.md §6's business
thresholds, so a named, explicit default here is not hard rule 4's "magic
number" -- it is the same choice that sibling module already made, kept
consistent rather than reinvented."""


@dataclass(frozen=True, slots=True)
class WorkBatch:
    """A `claim()` result restricted to ONE project and ONE topic (PLAN.md
    §10). Constructing one whose `items` disagree with `project_id`/`topic`
    is a `TypeError` raised at construction, not a value a caller could
    inspect and decide to use anyway.
    """

    project_id: ProjectId
    topic: str
    items: tuple[QueueItem, ...]

    def __post_init__(self) -> None:
        # Coerced, not merely annotated, for the same reason `QueueItem.payload`
        # is a `MappingProxyType`: a frozen dataclass whose only interesting
        # field is a mutable sequence is not frozen in any sense the
        # one-project-per-batch check can rely on. Validating a caller-supplied
        # list here and then handing that same list to a handler leaves the
        # window open for anything holding a reference to append a foreign
        # project's item AFTER the check has passed.
        object.__setattr__(self, "items", tuple(self.items))
        for item in self.items:
            if item.project_id != self.project_id:
                raise TypeError(
                    f"WorkBatch(project_id={self.project_id}) received an item for "
                    f"project {item.project_id}: a worker batch must never mix "
                    "projects (PLAN.md §10)"
                )
            if item.topic != self.topic:
                raise TypeError(
                    f"WorkBatch(topic={self.topic!r}) received an item for topic "
                    f"{item.topic!r}"
                )


def group_by_project(topic: str, items: Sequence[QueueItem]) -> list[WorkBatch]:
    """Splits a possibly-multi-project `claim()` result into
    project-homogeneous `WorkBatch`es, ordered by each project's first
    appearance in `items` -- deterministic given a deterministic claim order,
    with no re-sorting by any other field.
    """
    order: list[ProjectId] = []
    buckets: dict[ProjectId, list[QueueItem]] = {}
    for item in items:
        if item.project_id not in buckets:
            buckets[item.project_id] = []
            order.append(item.project_id)
        buckets[item.project_id].append(item)
    return [
        WorkBatch(project_id=pid, topic=topic, items=tuple(buckets[pid])) for pid in order
    ]


class BatchHandler(Protocol):
    """One topic's worker. Must be idempotent under at-least-once redelivery
    (module docstring) and must never mix projects -- `WorkBatch` makes the
    second half structural."""

    def handle(self, batch: WorkBatch) -> None: ...


class WorkerRunner:
    """Claims from `WorkQueue` by topic, dispatches each project-homogeneous
    batch to its registered handler, and acks/nacks accordingly. See the
    module docstring for the at-least-once/lease/graceful-shutdown contract.
    """

    def __init__(
        self,
        queue: QueueConsumerPort,
        clock: Clock,
        handlers: Mapping[str, BatchHandler],
        *,
        batch_size: int,
        lease_seconds: int,
    ) -> None:
        if batch_size <= 0:
            raise ValueError("batch_size must be positive")
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        self._queue = queue
        self._clock = clock
        self._handlers = dict(handlers)
        self._batch_size = batch_size
        # Required, never defaulted: `QueueConfig.lease_seconds` already exists
        # (PLAN.md §6's `queue.lease_seconds`), so the lease length this runner
        # reasons about must be the same number the queue actually leases with.
        # A default here would be an invented literal silently disagreeing with
        # the store (hard rule 4).
        self._lease_ms = lease_seconds * 1000.0
        # Every worker takes a Clock (hard rule 3); used here for a
        # wall-clock-free "last time any batch was processed" signal a
        # future health check can read, never for gating dispatch itself.
        self.last_activity_ms: float | None = None

    def run_once(self) -> int:
        """One claim+dispatch round across every registered topic. Returns
        the total number of queue items acked or nacked this round (0 means
        idle -- nothing claimed anywhere).
        """
        processed = 0
        for topic, handler in self._handlers.items():
            # Read BEFORE the claim, and once per claim rather than per batch:
            # the lease actually starts at the database's `now()` inside
            # `claim()`, so anchoring here can only over-estimate elapsed lease
            # time, never under-estimate it. Erring early is the safe
            # direction -- a nack skipped one round-trip too eagerly costs a
            # backoff interval; a nack issued one round-trip too late clears
            # another consumer's live lease.
            claimed_at_ms = self._clock.monotonic_ms()
            items = self._queue.claim(topic, self._batch_size)
            if not items:
                continue
            for batch in group_by_project(topic, items):
                processed += self._run_batch(topic, handler, batch, claimed_at_ms)
        if processed:
            self.last_activity_ms = self._clock.monotonic_ms()
        return processed

    def _lease_expired(self, claimed_at_ms: float) -> bool:
        return self._clock.monotonic_ms() - claimed_at_ms >= self._lease_ms

    def _run_batch(
        self, topic: str, handler: BatchHandler, batch: WorkBatch, claimed_at_ms: float
    ) -> int:
        """Dispatches one project-homogeneous batch. Any exception from
        `handler.handle` is caught here: the batch's items are nacked with
        backoff computed from each item's OWN `attempts` count (already
        incremented once by this round's `claim()`), and the runner moves on
        -- a worker raising never kills the runner (module docstring).

        The nack is skipped when the claim's lease has already expired, for
        the reason the module docstring spells out: `nack()` clears
        `lease_expires_at` unconditionally, so nacking a row this process no
        longer holds would steal it from whichever consumer picked it up on
        redelivery.
        """
        try:
            handler.handle(batch)
        except Exception:
            logger.exception(
                "worker runner: handler for topic %r failed on project %s",
                topic,
                batch.project_id,
            )
            WORKER_BATCH_ERRORS.labels(topic=topic).inc()
            if self._lease_expired(claimed_at_ms):
                WORKER_LEASE_OVERRUNS.labels(topic=topic).inc()
                logger.warning(
                    "worker runner: topic %r batch for project %s outran its %.0fms "
                    "lease before failing; leaving the rows to expire rather than "
                    "nacking a lease this process no longer holds",
                    topic,
                    batch.project_id,
                    self._lease_ms,
                )
                return len(batch.items)
            for item in batch.items:
                self._queue.nack(item.id, compute_backoff(item.attempts))
                WORKER_ITEMS_NACKED.labels(topic=topic).inc()
            return len(batch.items)
        if self._lease_expired(claimed_at_ms):
            # The ack below is still correct (the work IS done; a redelivered
            # duplicate's later ack is a documented no-op), but the duplicate
            # processing itself must not stay invisible.
            WORKER_LEASE_OVERRUNS.labels(topic=topic).inc()
            logger.warning(
                "worker runner: topic %r batch for project %s outran its %.0fms lease; "
                "its rows were redeliverable to another consumer while it ran",
                topic,
                batch.project_id,
                self._lease_ms,
            )
        for item in batch.items:
            self._queue.ack(item.id)
        WORKER_BATCHES_PROCESSED.labels(topic=topic).inc()
        return len(batch.items)

    def run_forever(
        self,
        stop: threading.Event,
        *,
        poll_interval: timedelta = _DEFAULT_POLL_INTERVAL,
        max_iterations: int | None = None,
    ) -> None:
        """Polls until `stop` is set (graceful shutdown) or `max_iterations`
        is reached (bounded, so a test can drive this to completion without
        a background thread). `stop` is checked only BETWEEN `run_once()`
        calls -- a batch claimed inside a `run_once()` call is always driven
        to ack/nack before this method can exit, even if `stop` is set by a
        handler as a side effect while that call is in progress. Sleeps via
        `stop.wait()`, never `time.sleep()`, so a shutdown request during an
        idle wait is honoured immediately.
        """
        iterations = 0
        while not stop.is_set():
            processed = self.run_once()
            iterations += 1
            if max_iterations is not None and iterations >= max_iterations:
                return
            if processed == 0:
                stop.wait(poll_interval.total_seconds())


def run() -> None:
    """Console entry point (`tracebed-worker`, pyproject.toml). Builds real
    adapters from `TracebedSettings` read off the process environment and
    runs two loops on one shared shutdown signal:

      * the ingest consumer loop (`ingest.runner.ConsumerRunner` over real
        `TraceWriter`/`OutcomeIntake`) -- the two Phase 0 topics this
        process is actually responsible for draining. `ingest.runner`
        deliberately has no `run()` of its own (its module docstring:
        "a thin scheduler over the two run_once/sweep_incomplete methods");
        this is that loop's one wiring point.
      * the Phase 4 `workflow.agent_control.ProposalIntake` loop, which drains
        `TOPIC_MEMORY_PROPOSAL` -- the third and last topic `stores.pg.queue`
        defines. Without this loop `POST /v1/propose_memory` enqueues rows
        that nothing ever consumes: the API answers 202, the agent believes
        its proposal was accepted, and the row sits in `work_queue` until it
        is swept. It gets its own loop rather than a `WorkerRunner` handler
        entry because its ack/nack policy is per item, not per batch -- see
        `ProposalIntake.run_forever`'s docstring.
      * this chunk's `WorkerRunner`, registered with `handlers={}` today.
        All three of `stores.pg.queue`'s topics are drained by the two loops
        above, and its own DO-NOT list forbids adding more. Every Phase 2
        sibling that HAS landed in `workers/` (`sweeps`, `revalidation`,
        `consolidator`, `invalidator`, `prefix_builder`, `derived_state`) is
        a periodic pass over the memory store, not a queue-topic consumer --
        none of them defines a `TOPIC_*` constant to register here. So an
        empty handler map is an honestly-idle, ready-to-extend engine, not a
        stub standing in for missing logic.

    No loop is allowed to die quietly. Every thread target is wrapped so that
    returning OR raising sets the shared `stop`: a process that has lost one
    loop but still holds the others looks alive to a supervisor while silently
    draining nothing, which is strictly worse than exiting and being restarted.

    CONTRACT GAP -- `workers.scheduler.Scheduler` / `workers.gc`'s periodic
    jobs are deliberately NOT constructed here, and neither are the Phase 2
    siblings listed above. All are complete and fully tested offline; what is
    missing is a real cadence to give them, and `domain/config.py` (outside
    this chunk's file list) has no field for "how often does the TTL sweep /
    GC pass run" (see `workers.scheduler`'s module docstring). Picking an
    arbitrary number here would put an invented literal directly on a live
    process rather than in a test fixture the soak explicitly drives --
    reported as a contract_gap against `domain/config.py` instead.
    """
    import signal

    from tracebed.domain.clock import SystemClock
    from tracebed.domain.config import ConfigResolver, TracebedSettings
    from tracebed.domain.errors import ConfigError
    from tracebed.ingest.outcome_intake import OutcomeIntake
    from tracebed.ingest.runner import ConsumerRunner
    from tracebed.ingest.trace_writer import TraceWriter
    from tracebed.stores.pg.pool import create_pool
    from tracebed.stores.pg.queue import WorkQueue
    from tracebed.stores.pg.repo import Repo
    from tracebed.stores.tracestore import TraceStorePort
    from tracebed.stores.tracestore.fs import FsTraceStore
    from tracebed.stores.tracestore.s3 import S3TraceStore
    from tracebed.workflow.agent_control import AgentControl, ProposalIntake

    def _build_tracestore(cfg: TracebedSettings, clock: SystemClock) -> TraceStorePort:
        tc = cfg.storage.tracestore
        if tc.driver == "fs":
            return FsTraceStore(tc.root)
        if tc.driver == "s3":
            return S3TraceStore(tc, clock=clock)
        raise ConfigError(f"unknown storage.tracestore.driver: {tc.driver!r}")

    settings = TracebedSettings()
    clock = SystemClock()
    pool = create_pool(settings.storage.pg_dsn)
    repo = Repo(pool, clock)
    queue = WorkQueue(pool, clock, settings.queue)
    tracestore = _build_tracestore(settings, clock)

    from tracebed.crypto.shred import EnvMasterKeyProvider, SubjectKeyManager

    keys = SubjectKeyManager(store=repo, master=EnvMasterKeyProvider(), clock=clock)
    writer = TraceWriter(queue, repo, tracestore, keys, clock, settings)
    outcomes = OutcomeIntake(queue, repo, clock, settings)
    ingest_runner = ConsumerRunner(writer, outcomes, clock)

    # `Repo` satisfies both AgentControlRepoPort and DurableProposalCapPort, so the
    # proposal caps this process enforces are exact across processes, not merely across
    # this process's threads -- asserted below rather than assumed, because the difference
    # is invisible until a second consumer is running.
    agent_control = AgentControl(repo, clock)
    if not agent_control.durable_caps:  # pragma: no cover - wiring assertion
        raise ConfigError(
            "the proposal consumer was wired with a store that cannot enforce "
            "proposals.per_run_cap / per_project_daily_cap across processes"
        )
    proposal_intake = ProposalIntake(
        queue,
        agent_control,
        repo,
        ConfigResolver(settings, repo),
        batch_size=settings.queue.batch_size,
    )

    worker_runner = WorkerRunner(
        queue=queue,
        clock=clock,
        handlers={},
        batch_size=settings.queue.batch_size,
        lease_seconds=settings.queue.lease_seconds,
    )

    from types import FrameType

    stop = threading.Event()

    def _shutdown(signum: int, frame: FrameType | None) -> None:
        del signum, frame
        stop.set()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    def _supervised(name: str, loop: Callable[[threading.Event], None]) -> Callable[[], None]:
        def _target() -> None:
            try:
                loop(stop)
            except BaseException:
                logger.exception("worker process: %s loop died", name)
                raise
            finally:
                # Whichever loop ends first ends the process. See the
                # docstring: a half-dead process is worse than a restarted one.
                stop.set()

        return _target

    def _proposal_loop(stop_event: threading.Event) -> None:
        # The SAME cadence the ingest loop polls its own two topics with, read off that
        # loop's config rather than restated: three consumers of one `work_queue` polling
        # at three different invented intervals is a load profile nobody chose.
        proposal_intake.run_forever(
            stop_event, poll_interval_s=ingest_runner.config.poll_interval_s
        )

    ingest_thread = threading.Thread(
        target=_supervised("ingest", ingest_runner.run_forever),
        name="tracebed-ingest",
        daemon=True,
    )
    proposal_thread = threading.Thread(
        target=_supervised("proposal", _proposal_loop),
        name="tracebed-proposals",
        daemon=True,
    )
    worker_thread = threading.Thread(
        target=_supervised("worker", worker_runner.run_forever),
        name="tracebed-worker",
        daemon=True,
    )
    for thread in (ingest_thread, proposal_thread, worker_thread):
        thread.start()
    for thread in (ingest_thread, proposal_thread, worker_thread):
        thread.join()
