"""Worker process: per-topic `WorkerQueue` dispatch (PLAN.md §7 Phase 2, chunk
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
Every acknowledgement outcome is generation-fenced by the claimed attempt
and lease expiry. A worker which has been superseded by a renewed lease cannot
clear, delete, or dead-letter the current claimant's work; its mutation is a
safe no-op. The runner still records an overrun so operations can tune lease
duration rather than silently treating the condition as ordinary throughput.

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
import os
import threading
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Protocol, cast

from prometheus_client import Counter

from tracebed.domain.errors import ActivityBusy
from tracebed.stores.pg.activity import ActivityGate
from tracebed.stores.pg.queue import QueueItem, compute_backoff

if TYPE_CHECKING:
    from psycopg_pool import ConnectionPool

    from tracebed.adapters.ports import EmbeddingPort, QueueConsumerPort, WorkerQueueConsumerPort
    from tracebed.domain.clock import Clock
    from tracebed.domain.config import TracebedSettings
    from tracebed.domain.ids import ProjectId
    from tracebed.stores.pg.authority_dsn import RuntimeDsn
    from tracebed.stores.tracestore import TraceStorePort

__all__ = [
    "BatchHandler",
    "WorkBatch",
    "WorkerOwnedResources",
    "WorkerResourceFactories",
    "WorkerRunner",
    "group_by_project",
    "register_worker_cleanup",
    "run",
    "supervise_worker_loops",
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


WorkerLoop = Callable[[threading.Event], None]


@dataclass(frozen=True, slots=True)
class WorkerOwnedResources:
    """Concrete process resources owned together by one private ``ExitStack``.

    The stack is intentionally not exposed to a worker body.  A body can use
    the resources, but cannot pop or discard their callbacks; normal return,
    a body exception, and a later construction failure all leave through the
    same reverse-order cleanup path.
    """

    pool: object
    tracestore: object
    embedding: object
    valkey: object


@dataclass(frozen=True, slots=True)
class WorkerResourceFactories:
    """Concrete process-resource constructors, including a narrow test seam.

    Production supplies real constructors below.  Tests may supply closable
    concrete fakes, but cannot pass cleanup callbacks separately: ownership
    is always derived from each actual object's ``.close`` method.
    """

    build_pool: Callable[[], object]
    build_tracestore: Callable[[], object]
    build_embedding: Callable[[], object]
    build_valkey: Callable[[], object]


def register_worker_cleanup(resources: ExitStack, close: Callable[[], None]) -> None:
    """Register one concrete owned resource without widening an adapter port.

    Composition decides ownership from the concrete constructor it called;
    data ports deliberately do not grow a ``close`` method merely because one
    process happens to hold a socket.  Registering each concrete closer as it
    is built gives ``ExitStack`` the same reverse-order guarantee for normal
    shutdown and partial construction failure.
    """

    resources.callback(close)


def _required_closer(resource: object, *, name: str) -> Callable[[], None]:
    """Return the real closer for a mandatory concrete process resource."""

    close = getattr(resource, "close", None)
    if not callable(close):
        raise TypeError(f"worker {name} resource must expose a callable close()")
    return cast(Callable[[], None], close)


def _optional_closer(resource: object) -> Callable[[], None] | None:
    """Find an optional concrete closer without widening any data port."""

    close = getattr(resource, "close", None)
    return cast(Callable[[], None], close) if callable(close) else None


@contextmanager
def _owned_worker_resources(
    factories: WorkerResourceFactories,
) -> Iterator[WorkerOwnedResources]:
    """Acquire pool → trace → embedding → Valkey under one private stack.

    Registration occurs immediately after each construction.  Consequently a
    trace, embedding, or Valkey construction failure closes exactly the
    already-owned resources, and every yielded body exits through the same
    stack in reverse acquisition order.
    """

    with ExitStack() as resources:
        pool = factories.build_pool()
        register_worker_cleanup(resources, _required_closer(pool, name="pool"))

        tracestore = factories.build_tracestore()
        if close := _optional_closer(tracestore):
            register_worker_cleanup(resources, close)

        embedding = factories.build_embedding()
        if close := _optional_closer(embedding):
            register_worker_cleanup(resources, close)

        valkey = factories.build_valkey()
        register_worker_cleanup(resources, _required_closer(valkey, name="Valkey"))
        yield WorkerOwnedResources(
            pool=pool,
            tracestore=tracestore,
            embedding=embedding,
            valkey=valkey,
        )


def supervise_worker_loops(
    loops: Sequence[tuple[str, WorkerLoop]],
    stop: threading.Event,
) -> None:
    """Run every process loop under one fail-fast, join-before-reraise policy.

    A loop that returns while no external shutdown was requested is just as
    unhealthy as one that raises: leaving the other loops alive would make a
    half-working worker look healthy.  Thread failures are collected under a
    lock, trigger the shared stop once, and are re-raised on the main thread
    only after every started thread joined.  An externally-set stop is the
    normal exit path and records no synthetic failure.
    """

    failures: list[BaseException] = []
    failure_lock = threading.Lock()

    def _record(error: BaseException) -> None:
        with failure_lock:
            failures.append(error)
        stop.set()

    def _target(name: str, loop: WorkerLoop) -> None:
        try:
            loop(stop)
        except BaseException as exc:
            logger.exception("worker process: %s loop died", name)
            _record(exc)
            return
        if not stop.is_set():
            _record(RuntimeError(f"worker process: {name} loop returned unexpectedly"))

    threads = [
        threading.Thread(
            target=_target,
            args=(name, loop),
            name=f"tracebed-{name}",
            daemon=False,
        )
        for name, loop in loops
    ]
    started: list[threading.Thread] = []
    try:
        for thread in threads:
            thread.start()
            started.append(thread)
    except BaseException as exc:
        _record(exc)
    finally:
        for thread in started:
            thread.join()

    if failures:
        raise failures[0]


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
    """Claims from `WorkerQueue` by topic, dispatches each project-homogeneous
    batch to its registered handler, and acks/nacks accordingly. See the
    module docstring for the at-least-once/lease/graceful-shutdown contract.
    """

    def __init__(
        self,
        queue: WorkerQueueConsumerPort,
        clock: Clock,
        handlers: Mapping[str, BatchHandler],
        *,
        batch_size: int,
        lease_seconds: int,
        activity: ActivityGate | None = None,
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
        self._activity = activity
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
            if self._activity is None:
                return self._run_batch_while_fenced(topic, handler, batch, claimed_at_ms)
            # The shared activity lock deliberately includes ACK/NACK. A
            # request cannot acquire its exclusive drain between a handler's
            # final durable write and the queue settlement that makes stale
            # work observable for another consumer.
            with self._activity.shared(batch.project_id):
                return self._run_batch_while_fenced(topic, handler, batch, claimed_at_ms)
        except ActivityBusy:
            # No handler has run. NACK the claimed attempt so its durable
            # snapshot is reloaded after the request's exclusive drain ends.
            if self._lease_expired(claimed_at_ms):
                WORKER_LEASE_OVERRUNS.labels(topic=topic).inc()
                return len(batch.items)
            for item in batch.items:
                self._nack(item)
                WORKER_ITEMS_NACKED.labels(topic=topic).inc()
            return len(batch.items)

    def _run_batch_while_fenced(
        self, topic: str, handler: BatchHandler, batch: WorkBatch, claimed_at_ms: float
    ) -> int:
        """Dispatch and settle while the caller holds the project shared gate."""

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
                self._nack(item)
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
            self._ack(item)
        WORKER_BATCHES_PROCESSED.labels(topic=topic).inc()
        return len(batch.items)

    def _ack(self, item: QueueItem) -> None:
        if item.authority_version == 1:
            self._queue.ack(item)
        else:
            cast("QueueConsumerPort", self._queue).ack(item.id)

    def _nack(self, item: QueueItem) -> None:
        if item.authority_version == 1:
            self._queue.nack(item, compute_backoff(item.attempts))
        else:
            cast("QueueConsumerPort", self._queue).nack(item.id, compute_backoff(item.attempts))

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
    runs FIVE loops -- one thread each -- on one shared shutdown signal:

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
      * this chunk's `WorkerRunner`, registered with
        `workers.registry.build_default_registry(WorkerDeps())`. That call --
        not a bare `{}` literal -- is what makes the handler map auditable:
        it refuses to return at all unless every topic `stores.pg.queue`
        defines is either handled here or named in
        `registry.UNREGISTERED_TOPICS` with the reason it is not, and unless
        no handler is registered for a topic that does not exist. So a future
        worker dropped because its dependencies were absent fails THIS
        process's construction instead of shrinking the map silently.
        It resolves to an empty map today, and that emptiness is checked on
        the same terms as any populated one: all three of `stores.pg.queue`'s
        topics are drained by the two loops above (each claims its own rows,
        so a second `BatchHandler` layer over them would double-claim), and
        its own DO-NOT list forbids adding more. Every Phase 2 sibling that
        HAS landed in `workers/` (`sweeps`, `revalidation`, `consolidator`,
        `invalidator`, `prefix_builder`, `derived_state`) is a periodic pass
        over the memory store, not a queue-topic consumer -- none of them
        defines a `TOPIC_*` constant to register here. See
        `workers/registry.py`'s module docstring for the full reasoning.

      * the PERIODIC plane: a `workers.scheduler.Scheduler` over the
        `ScheduledJob`s `workers.composition.build_scheduled_jobs` returns.
        This is the loop the fidelity audit's M2 was about ("a deployed
        Tracebed today ingests traces and outcome events faithfully and
        learns nothing from either") and it now exists. The jobs it drives
        today are the embedding sweep, the shadow-confirmation writer (only
        when a `CorroborationCandidateSource` is supplied -- see below), the
        per-project TTL / idle-decay sweeps (`workers.sweeps.run_all_sweeps`,
        driven by the per-project `EffectiveConfig` the shared `ConfigResolver`
        resolves), the per-(project, agent_type) static-prefix rebuild
        (`workers.prefix_builder.PrefixBuilder`, publishing into the Valkey
        static-prefix cache), and the queue GC pass; every other periodic
        worker is recorded in `composition.UNSCHEDULED_WORKERS` with the exact
        dependency it is blocked on, and `build_scheduled_jobs` REFUSES TO
        RETURN if any module under `workers/` is neither scheduled nor
        accounted for.

      * the trace-learning pull loop, which claims at most one Tier-A/v1 job
        per project, decrypts its strict archive, plans under freshly resolved
        config, and makes one fenced finalizer call.  It is intentionally not
        a periodic Scheduler job: work immediately triggers the next sweep;
        idle periods wait on the ingest polling cadence.

    Cadences come from `domain.config.WorkersConfig`, which exists precisely
    because the previous version of this docstring recorded the contract gap
    that made this loop unbuildable: "`domain/config.py` has no field for how
    often the TTL sweep / GC pass runs ... picking an arbitrary number here
    would put an invented literal directly on a live process". Every interval
    is now a declared, overridable, deployment-visible field (D-128).

    STILL A CONTRACT GAP, narrowed rather than closed: no
    `CorroborationCandidateSource` implementation exists anywhere in this
    repository, so the corroboration job is constructed and NOT scheduled
    unless a host supplies one. Deciding which runs corroborate which
    quarantined memory is a declared host seam (D-121), and inventing a
    matching heuristic here would make this process the second author of
    "these two runs are about the same thing".

    No loop is allowed to die quietly. Every thread target is wrapped so that
    returning OR raising sets the shared `stop`: a process that has lost one
    loop but still holds the others looks alive to a supervisor while silently
    draining nothing, which is strictly worse than exiting and being restarted.
    """
    _run_worker_process()


def _load_worker_runtime_configuration() -> tuple[RuntimeDsn, TracebedSettings]:
    """Read the exclusive worker DB credential before non-DB settings.

    Runtime processes intentionally inherit no general PostgreSQL/libpq
    environment controls: the split worker URL is the sole DB connection
    input.  The normal settings model still carries Valkey, trace-store,
    embedding and pool-timeout configuration, while its legacy library
    ``storage.pg_dsn`` must stay absent in production.
    """

    from tracebed.domain.config import TracebedSettings
    from tracebed.domain.errors import ConfigError
    from tracebed.stores.pg.authority_dsn import runtime_dsn_from_environment

    runtime_dsn = runtime_dsn_from_environment("tracebed_worker", os.environ)
    settings = TracebedSettings()
    if settings.storage.pg_dsn is not None:
        raise ConfigError("runtime database credential configuration is invalid")
    return runtime_dsn, settings


def _run_worker_process(
    *,
    resource_factories: WorkerResourceFactories | None = None,
    process_body: Callable[[WorkerOwnedResources], None] | None = None,
) -> None:
    """Construct, supervise, and close the five worker loops.

    Tests can inject only concrete resource constructors and a body.  They
    still enter the same private ownership context as production; neither the
    body nor any resource factory receives the ``ExitStack`` itself.
    """

    if resource_factories is not None:
        if process_body is None:
            raise ValueError("injected worker resources require a process body")
        with _owned_worker_resources(resource_factories) as owned:
            process_body(owned)
        return
    if process_body is not None:
        raise ValueError("an injected process body requires resource factories")

    import signal
    from types import FrameType

    from psycopg_pool import ConnectionPool

    from tracebed.adapters.embedding.factory import build_embedding_driver, model_pin_from_settings
    from tracebed.crypto.shred import EnvMasterKeyProvider, SubjectKeyManager
    from tracebed.domain.clock import SystemClock
    from tracebed.domain.config import ConfigResolver
    from tracebed.domain.errors import ConfigError
    from tracebed.ingest.outcome_intake import OutcomeIntake
    from tracebed.ingest.runner import ConsumerRunner
    from tracebed.ingest.trace_writer import TraceWriter
    from tracebed.stores.pg.activity import ActivityGate, create_activity_pool
    from tracebed.stores.pg.erasure import WorkerErasureGuard
    from tracebed.stores.pg.pool import create_pool
    from tracebed.stores.pg.queue import (
        TOPIC_MEMORY_PROPOSAL,
        TOPIC_OUTCOME_EVENT,
        TOPIC_TRACE_EVENT,
        WorkerQueue,
    )
    from tracebed.stores.pg.repo import Repo
    from tracebed.stores.pg.runtime_identity import (
        probe_runtime_prepublication_readiness,
        runtime_pool_configure,
    )
    from tracebed.stores.tracestore.fs import FsTraceStore
    from tracebed.stores.tracestore.s3 import S3TraceStore
    from tracebed.stores.valkey.client import ValkeyClient
    from tracebed.workers.composition import (
        build_learning_plane,
        build_scheduled_jobs,
        build_trace_learning_runner,
    )
    from tracebed.workers.registry import WorkerDeps, build_default_registry
    from tracebed.workers.scheduler import Scheduler
    from tracebed.workers.spend import SpendMeter
    from tracebed.workflow.agent_control import AgentControl, ProposalIntake

    def _build_tracestore(settings: TracebedSettings, clock: SystemClock) -> TraceStorePort:
        config = settings.storage.tracestore
        if config.driver == "fs":
            return FsTraceStore(config.root)
        if config.driver == "s3":
            return S3TraceStore(config, clock=clock)
        raise ConfigError(f"unknown storage.tracestore.driver: {config.driver!r}")

    runtime_dsn, settings = _load_worker_runtime_configuration()
    clock = SystemClock()

    def _build_worker_pool() -> ConnectionPool:
        pool = create_pool(
            runtime_dsn.value,
            connect_timeout_s=settings.storage.pg_connect_timeout_s,
            checkout_timeout_s=settings.storage.pg_checkout_timeout_s,
            configure=runtime_pool_configure("tracebed_worker"),
            checkout_check=ConnectionPool.check_connection,
        )
        try:
            probe_runtime_prepublication_readiness(pool, expected_role="tracebed_worker")
        except Exception:
            pool.close()
            raise
        return pool

    factories = WorkerResourceFactories(
        build_pool=_build_worker_pool,
        build_tracestore=lambda: _build_tracestore(settings, clock),
        build_embedding=lambda: build_embedding_driver(settings, clock),
        build_valkey=lambda: ValkeyClient.from_url(settings.storage.valkey_url),
    )

    def _production_body(owned: WorkerOwnedResources) -> None:
        pool = cast("ConnectionPool", owned.pool)
        tracestore = cast("TraceStorePort", owned.tracestore)
        embedding_port = cast("EmbeddingPort", owned.embedding)
        valkey = cast(ValkeyClient, owned.valkey)
        repo = Repo(pool, clock)
        queue = WorkerQueue(pool, clock, settings.queue)
        activity_pool = create_activity_pool(
            runtime_dsn.value,
            connect_timeout_s=settings.storage.pg_connect_timeout_s,
            checkout_timeout_s=settings.storage.pg_checkout_timeout_s,
            connection_check=runtime_pool_configure("tracebed_worker"),
            checkout_check=ConnectionPool.check_connection,
        )
        activity = ActivityGate(activity_pool)
        erasure_guard = WorkerErasureGuard(pool)
        keys = SubjectKeyManager(store=repo, master=EnvMasterKeyProvider(), clock=clock)
        writer = TraceWriter(
            queue,
            repo,
            tracestore,
            keys,
            clock,
            settings,
            activity=activity,
            erasure_guard=erasure_guard,
        )
        outcomes = OutcomeIntake(
            queue,
            repo,
            clock,
            settings,
            activity=activity,
            erasure_guard=erasure_guard,
        )
        ingest_runner = ConsumerRunner(writer, outcomes, clock)

        agent_control = AgentControl(repo, clock)
        if not agent_control.durable_caps:  # pragma: no cover - wiring assertion
            raise ConfigError(
                "the proposal consumer was wired with a store that cannot enforce "
                "proposals.per_run_cap / per_project_daily_cap across processes"
            )
        resolver = ConfigResolver(settings, repo)
        proposal_intake = ProposalIntake(
            queue,
            agent_control,
            repo,
            resolver,
            batch_size=settings.queue.batch_size,
            activity=activity,
            erasure_guard=erasure_guard,
        )
        worker_runner = WorkerRunner(
            queue=queue,
            clock=clock,
            handlers=build_default_registry(WorkerDeps()),
            batch_size=settings.queue.batch_size,
            lease_seconds=settings.queue.lease_seconds,
            activity=activity,
        )
        plane = build_learning_plane(
            pool=pool,
            repo=repo,
            clock=clock,
            cfg=settings.workers,
            pin=model_pin_from_settings(settings),
            embedding_port=embedding_port,
            spend=SpendMeter(repo, clock, settings.spend),
            candidate_source=None,
        )
        scheduler = Scheduler(
            clock,
            build_scheduled_jobs(
                plane,
                cfg=settings.workers,
                list_project_ids=repo.list_project_ids,
                queue_observability=queue,
                topics=(TOPIC_TRACE_EVENT, TOPIC_OUTCOME_EVENT, TOPIC_MEMORY_PROPOSAL),
                lease_seconds=settings.queue.lease_seconds,
                clock=clock,
                config_resolver=resolver,
                memory_store=repo,
                prefix_cache=valkey,
                list_agent_type_ids=repo.list_agent_type_ids,
                candidate_source=None,
                activity=activity,
            ),
        )
        trace_learning_runner = build_trace_learning_runner(
            pool=pool,
            repo=repo,
            tracestore=tracestore,
            keys=keys,
            config_resolver=resolver,
            clock=clock,
            lease_seconds=settings.queue.lease_seconds,
            poll_interval=timedelta(seconds=ingest_runner.config.poll_interval_s),
            activity=activity,
            erasure_guard=erasure_guard,
        )

        stop = threading.Event()

        def _shutdown(signum: int, frame: FrameType | None) -> None:
            del signum, frame
            stop.set()

        signal.signal(signal.SIGTERM, _shutdown)
        signal.signal(signal.SIGINT, _shutdown)

        def _proposal_loop(stop_event: threading.Event) -> None:
            proposal_intake.run_forever(
                stop_event, poll_interval_s=ingest_runner.config.poll_interval_s
            )

        def _scheduler_loop(stop_event: threading.Event) -> None:
            while not stop_event.is_set():
                scheduler.tick()
                stop_event.wait(settings.workers.scheduler_tick_seconds)

        try:
            supervise_worker_loops(
                (
                    ("ingest", ingest_runner.run_forever),
                    ("proposals", _proposal_loop),
                    ("worker", worker_runner.run_forever),
                    ("scheduler", _scheduler_loop),
                    ("trace-learning", trace_learning_runner.run_forever),
                ),
                stop,
            )
        finally:
            activity_pool.close()

    with _owned_worker_resources(factories) as owned:
        _production_body(owned)
