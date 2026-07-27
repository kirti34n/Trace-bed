"""Queue/trace-store maintenance: GC (PLAN.md §7 Phase 2, chunk `worker-runner`).

Two tiers, deliberately kept apart because they differ in whether a real,
production adapter exists for them today.

TIER 1 -- observability, real today. `queue_health()` is wired against
primitives `stores.pg.queue.WorkQueue` already implements
(`dead_letter_count`, `depth`, `oldest_age_s`, `xmin_horizon_alarm`), and
`find_orphaned_trace_payloads()` against `Repo.list_runs` +
`TraceStorePort.exists` -- both already real. Neither invents a threshold:
"stuck" is defined against `QueueConfig.lease_seconds`, an EXISTING config
field (a row older than one full lease period has outlived at least one
worker cycle), never a new magic number. See `QueueHealthReport.stuck_topics`
for exactly how coarse that signal is and why it cannot be sharpened from
this module.

TIER 2 -- active maintenance, NOT wireable to a real store today.
`reap_dead_letter()`/`expired_lease_counts()` are built against
`DeadLetterReaperPort`/`ExpiredLeasePort` seams because `stores/pg/queue.py`
(owned by chunk `queue`, outside this chunk's file list per hard rule 6) has
no delete/purge primitive for `dead_letter` rows and no "count rows whose
lease has expired" primitive for `work_queue` -- only `dead_letter_count()`
and `oldest_age_s()`, which count/age but cannot act or enumerate. This is
the same seam shape as `hotpath.pipeline.CandidateAssemblyPort` (D-054): the
LOGIC (when to reap, by what age cutoff, on what cadence via
`workers.scheduler.Scheduler`) is built and fully tested offline against a
Protocol; no concrete adapter satisfying either Protocol exists anywhere in
this codebase yet. Reported as a contract_gap against `stores/pg/queue.py`.
`workers.runner.run()` does not yet call any function in this module at all
-- not because Tier 1 is unreal, but because there is no `EffectiveConfig`
field for the cadence a `workers.scheduler.ScheduledJob` around it would
need (see that module's docstring); wiring `queue_health()` /
`find_orphaned_trace_payloads()` into the live process is a contract_gap
against `domain/config.py`, not against this module.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from tracebed.stores.tracestore import PayloadRef

if TYPE_CHECKING:
    from datetime import datetime, timedelta

    from tracebed.domain.clock import Clock
    from tracebed.domain.ids import ProjectId, RunId
    from tracebed.stores.pg.rows import TraceIndexRow
    from tracebed.stores.tracestore import TraceStorePort

__all__ = [
    "DeadLetterReaperPort",
    "ExpiredLeasePort",
    "GcReport",
    "OrphanedPayload",
    "QueueHealthReport",
    "QueueObservabilityPort",
    "TopicQueueStats",
    "TraceIndexLister",
    "expired_lease_counts",
    "find_orphaned_trace_payloads",
    "queue_health",
    "reap_dead_letter",
    "run_gc_cycle",
]


# --------------------------------------------------------------------------- #
# Tier 1 -- observability (real against `WorkQueue` today).
# --------------------------------------------------------------------------- #


class QueueObservabilityPort(Protocol):
    """The subset of `stores.pg.queue.WorkQueue`'s public surface this module
    reads. `WorkQueue` satisfies this structurally with zero changes."""

    def depth(self, topic: str) -> int: ...
    def dead_letter_count(self, topic: str) -> int: ...
    def oldest_age_s(self, topic: str) -> float | None: ...
    def xmin_horizon_alarm(self) -> bool: ...


@dataclass(frozen=True, slots=True)
class TopicQueueStats:
    topic: str
    depth: int
    dead_letter_count: int
    oldest_age_s: float | None


@dataclass(frozen=True, slots=True)
class QueueHealthReport:
    stats: tuple[TopicQueueStats, ...]
    stuck_topics: tuple[str, ...]
    """Topics whose oldest row has sat longer than one full lease period
    (`QueueConfig.lease_seconds`) -- a sign consumers for that topic have
    stopped keeping up, not a business alarm.

    Deliberately stated as "oldest row", not "oldest UNCLAIMED row": the only
    primitive `QueueObservabilityPort` offers is `oldest_age_s`, and
    `WorkQueue.oldest_age_s` is `MIN(available_at)` across every row on the
    topic regardless of lease state (`stores/pg/queue.py`). A topic with a
    genuine backlog being actively drained therefore also reports stuck. A
    precise signal needs a lease-aware age primitive on the queue, which
    `stores/pg/queue.py` does not expose and this chunk may not add
    (contract_gap); overstating what this predicate measures would be worse
    than the coarse signal itself."""
    xmin_horizon_alarm: bool
    """PLAN.md §3: `work_queue` shares Postgres's buffer cache with the
    vector index, so bloat here is a hot-path latency risk. Read straight
    through `WorkQueue.xmin_horizon_alarm()`, which already implements the
    threshold check (`stores/pg/queue.py::XMIN_HORIZON_ALARM_THRESHOLD_S`) --
    this module does not duplicate that constant, only surfaces it."""


def queue_health(
    port: QueueObservabilityPort, topics: Sequence[str], *, lease_seconds: int
) -> QueueHealthReport:
    """One maintenance snapshot across every named topic plus the
    queue-wide xmin-horizon alarm. Pure orchestration -- every number comes
    from `port`; this function invents nothing.
    """
    if lease_seconds <= 0:
        raise ValueError("lease_seconds must be positive")
    stats: list[TopicQueueStats] = []
    stuck: list[str] = []
    for topic in topics:
        age = port.oldest_age_s(topic)
        stats.append(
            TopicQueueStats(
                topic=topic,
                depth=port.depth(topic),
                dead_letter_count=port.dead_letter_count(topic),
                oldest_age_s=age,
            )
        )
        if age is not None and age > lease_seconds:
            stuck.append(topic)
    return QueueHealthReport(
        stats=tuple(stats),
        stuck_topics=tuple(stuck),
        xmin_horizon_alarm=port.xmin_horizon_alarm(),
    )


class TraceIndexLister(Protocol):
    """The one `Repo` method this needs (`Repo` satisfies structurally)."""

    def list_runs(self, project_id: ProjectId, *, limit: int = 100) -> list[TraceIndexRow]: ...


@dataclass(frozen=True, slots=True)
class OrphanedPayload:
    run_id: RunId
    payload_ref: str


def find_orphaned_trace_payloads(
    repo: TraceIndexLister,
    tracestore: TraceStorePort,
    project_id: ProjectId,
    *,
    limit: int = 500,
) -> tuple[OrphanedPayload, ...]:
    """`trace_index` rows whose `payload_ref` does not resolve in the
    configured trace store -- a corrupted or missing archive object. This is
    the one direction detectable with `TraceStorePort`'s actual surface
    (`put`/`get`/`exists`/`delete_project` -- no listing primitive): index ->
    store. The reverse direction (an object in the store with no
    `trace_index` row pointing to it) is NOT computable here -- neither the
    fs nor s3 driver exposes an enumeration primitive on `TraceStorePort`,
    and adding one is outside this chunk's file list (`stores/tracestore/`,
    owned by chunk `crypto-tracestore`); reported as a contract_gap.

    A row whose `project_id` is not the one asked for is a `TypeError`, not a
    finding. `TraceStorePort.exists` answers `False` for any ref outside the
    project's own prefix (invariant 4, enforced in `fs.py`/`s3.py` before any
    I/O), so without this check a foreign row would be silently downgraded
    into a routine "missing object" line in a maintenance report -- the one
    place an isolation failure must NOT be allowed to look benign. Raising
    mirrors `workers.runner.WorkBatch`'s identical refusal to let a
    cross-project mix be a value a caller can inspect and use anyway.
    """
    if limit <= 0:
        raise ValueError("limit must be positive")
    orphans: list[OrphanedPayload] = []
    for row in repo.list_runs(project_id, limit=limit):
        if row.project_id != project_id:
            raise TypeError(
                f"find_orphaned_trace_payloads(project_id={project_id}) received a "
                f"trace_index row for project {row.project_id} (run {row.run_id}): "
                "a cross-project row is an isolation failure, not a GC finding "
                "(PLAN.md §2 invariant 4)"
            )
        if not row.payload_ref:
            continue
        ref = PayloadRef.parse(row.payload_ref)
        if not tracestore.exists(project_id, ref):
            orphans.append(OrphanedPayload(run_id=row.run_id, payload_ref=row.payload_ref))
    return tuple(orphans)


# --------------------------------------------------------------------------- #
# Tier 2 -- active maintenance (no real adapter exists yet; see module
# docstring). Logic is complete and fully tested against these seams.
# --------------------------------------------------------------------------- #


class DeadLetterReaperPort(Protocol):
    """CONTRACT GAP: `stores.pg.queue.WorkQueue` does not implement this --
    see module docstring. Declared so the reaping LOGIC (cutoff computation,
    cadence via `workers.scheduler.Scheduler`) is complete and fully tested;
    no concrete adapter satisfies it yet anywhere in this codebase."""

    def purge_dead_letter(self, topic: str, *, older_than: datetime) -> int: ...


class ExpiredLeasePort(Protocol):
    """CONTRACT GAP: ditto. `WorkQueue` has no primitive to COUNT `work_queue`
    rows whose lease has expired -- only the automatic reclaim-on-claim
    behaviour (`claim()`'s own `WHERE lease_expires_at IS NULL OR
    lease_expires_at < now()`), which needs no action to correct itself but
    also gives no visibility into how many rows are currently sitting
    expired -- e.g. because every consumer for that topic has crashed."""

    def count_expired_leases(self, topic: str) -> int: ...


def reap_dead_letter(
    port: DeadLetterReaperPort,
    topics: Sequence[str],
    clock: Clock,
    *,
    retention: timedelta,
) -> Mapping[str, int]:
    """Purges `dead_letter` rows older than `retention`, per topic. `retention`
    is a required, caller-supplied duration -- there is no
    `EffectiveConfig` field for dead-letter retention (hard rule 4: no
    invented default)."""
    if retention.total_seconds() <= 0:
        raise ValueError("retention must be positive")
    cutoff = clock.now() - retention
    return {topic: port.purge_dead_letter(topic, older_than=cutoff) for topic in topics}


def expired_lease_counts(port: ExpiredLeasePort, topics: Sequence[str]) -> Mapping[str, int]:
    """Rows per topic whose lease has expired but have not yet been
    reclaimed by a `claim()` call -- a stuck-worker signal, reported, never
    acted on directly (reclaiming happens structurally inside `claim()`)."""
    return {topic: port.count_expired_leases(topic) for topic in topics}


@dataclass(frozen=True, slots=True)
class GcReport:
    purged_dead_letter: Mapping[str, int]
    expired_leases: Mapping[str, int]


def run_gc_cycle(
    *,
    observability: QueueObservabilityPort,
    topics: Sequence[str],
    lease_seconds: int,
    reaper: DeadLetterReaperPort | None = None,
    lease_counter: ExpiredLeasePort | None = None,
    clock: Clock | None = None,
    dead_letter_retention: timedelta | None = None,
) -> tuple[QueueHealthReport, GcReport]:
    """One GC pass: always computes Tier 1's `QueueHealthReport`; runs Tier
    2's reaping/lease-counting only when the caller supplies an adapter for
    it (`reaper`/`lease_counter`), so a deployment with no such adapter
    (every deployment, today -- see module docstring) still gets the real
    observability half without a fake standing in for a missing store
    method. `workers.scheduler.ScheduledJob.run` is this function bound to
    its arguments via `functools.partial`/a closure -- this module owns the
    "what a GC pass does" logic, `Scheduler` only owns "when".
    """
    health = queue_health(observability, topics, lease_seconds=lease_seconds)
    purged: dict[str, int] = {}
    if reaper is not None:
        if clock is None or dead_letter_retention is None:
            raise ValueError(
                "run_gc_cycle: reaper requires both clock and dead_letter_retention"
            )
        purged = dict(reap_dead_letter(reaper, topics, clock, retention=dead_letter_retention))
    expired: dict[str, int] = (
        dict(expired_lease_counts(lease_counter, topics)) if lease_counter is not None else {}
    )
    return health, GcReport(purged_dead_letter=purged, expired_leases=expired)
