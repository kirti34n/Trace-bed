"""The composition root for the periodic learning plane (FIDELITY-AUDIT.md M1/M2/M3;
PLAN.md §11.1).

THE GAP THIS CLOSES, in the audit's own words: "the learning half of the system is a library,
not a service ... `workers/runner.py` starts the worker process with `handlers={}`". Two
separate absences produced that: nothing constructed the periodic workers, and nothing could,
because `workers.scheduler.ScheduledJob` needs a cadence and `domain/config.py` had no field
for one. `domain.config.WorkersConfig` supplies the cadences; this module supplies the
construction.

WHY A SEPARATE MODULE AND NOT `runner.run()`'s BODY. `run()` is a console entry point that
opens a real connection pool, installs signal handlers, and blocks on three threads — nothing
about it is callable from a test or a drill. Every decision that matters here (which worker is
schedulable, which is not and why, what cadence each gets) is a pure function of injected
dependencies, so it lives where `harness/closed_loop.py` and `tests/phase2/test_composition.py`
can call it with fakes. `run()` keeps exactly one job: turn `TracebedSettings` into real
adapters and hand them to `build_scheduled_jobs`.

SCHEDULING IS AUDITED, NOT MERELY PARTIAL — the same discipline `workers.registry` applies to
queue topics, for the same reason. A worker that is not scheduled because its store port has no
implementation must be RECORDED WITH A REASON, never silently dropped: a process that starts
healthy and sweeps nothing looks identical to one that is working, and the only symptom is a
vault that never changes. `validate_worker_coverage` therefore refuses to return unless every
module under `tracebed.workers` is either

  * scheduled by `build_scheduled_jobs`, or
  * named in `UNSCHEDULED_WORKERS` with the specific missing dependency, or
  * named in `NON_PERIODIC_WORKERS` — infrastructure and pure-computation modules that have no
    cadence to have (a statistics function is not a worker that failed to be scheduled).

The module set is DISCOVERED by walking the package, not hand-listed, so a new worker module
added later fails this check until somebody decides which of the three it is. That is the whole
point: the failure mode being guarded is not "we scheduled the wrong thing", it is "we quietly
scheduled nothing".

WHAT IS SCHEDULABLE TODAY, and it is a minority: `workers.embedder` (its `EmbeddingRepoPort`
now has `stores.pg.learning.EmbeddingRepo`), `workers.corroboration` (its
`CorroborationRepoPort` now has `stores.pg.learning.CorroborationRepo`, and only when the host
supplies the `CorroborationCandidateSource` that decides which runs corroborate which memory —
a declared seam, D-121), and `workers.gc` (`stores.pg.queue.WorkQueue` already satisfies
`QueueObservabilityPort` structurally). The other ten periodic workers are complete, tested,
and unschedulable because the Postgres implementation of the port each one takes does not
exist — audit finding M3, still open, now enumerated one worker at a time instead of as a
paragraph.
"""

from __future__ import annotations

import logging
import pkgutil
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import timedelta
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from tracebed.domain.errors import ConfigError
from tracebed.workers.scheduler import ScheduledJob

if TYPE_CHECKING:  # pragma: no cover - typing only
    from psycopg_pool import ConnectionPool

    from tracebed.adapters.embedding.pinning import ModelPin
    from tracebed.adapters.ports import EmbeddingPort
    from tracebed.domain.clock import Clock
    from tracebed.domain.config import WorkersConfig
    from tracebed.domain.ids import ProjectId
    from tracebed.stores.pg.lifecycle import LifecycleWriter
    from tracebed.stores.pg.repo import Repo
    from tracebed.workers.corroboration import (
        CorroborationCandidateSource,
        CorroborationWriter,
    )
    from tracebed.workers.edit_ops import EditOps
    from tracebed.workers.embedder import Embedder, SpendRecorderPort
    from tracebed.workers.forensics import Forensics
    from tracebed.workers.gc import QueueObservabilityPort
    from tracebed.workers.preferences import PreferenceManager

__all__ = [
    "NON_PERIODIC_WORKERS",
    "UNSCHEDULED_WORKERS",
    "LearningPlane",
    "build_learning_plane",
    "build_scheduled_jobs",
    "discover_worker_modules",
    "validate_worker_coverage",
]

logger = logging.getLogger(__name__)


def discover_worker_modules() -> frozenset[str]:
    """Every top-level module name under `tracebed.workers`.

    Walked rather than listed for the same reason `workers.registry.ALL_TOPICS` introspects
    `stores.pg.queue`: a hand-copied list keeps passing the day a new worker lands with no
    scheduling decision made about it. Sub-packages (`extractors`) are included by their
    package name only — the individual extractors are driven by the trace path, not by a
    cadence, and the package is classified once.
    """
    import tracebed.workers as package

    return frozenset(
        info.name for info in pkgutil.iter_modules(package.__path__) if not info.name.startswith("_")
    )


# Modules that have no cadence to have. Each entry is a claim that the module is a library,
# an on-demand operator surface, or the scheduling machinery itself -- NOT a claim that it works.
NON_PERIODIC_WORKERS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "composition": "this module -- the composition root itself. It decides what is "
        "scheduled; being scheduled by its own output would be a cycle, not a pass.",
        "runner": "the worker process entry point; it OWNS the scheduler thread rather than "
        "being scheduled by it",
        "scheduler": "the generic cadence harness every ScheduledJob below is handed to; it "
        "owns WHEN a job runs and knows nothing at all about what any job does",
        "registry": "the queue-topic -> BatchHandler map for the push plane; the pull plane "
        "is this module",
        "statistics": "pure functions (Benjamini-Hochberg in exact arithmetic); no state, no "
        "cadence, called by killswitch and by api.reports",
        "lift": "pure lift/confidence-interval arithmetic consumed by killswitch and reports",
        "safety_lift": "pure stratified safety-lift arithmetic, same shape and same reason "
        "as lift; consumed by the kill switch on the grid it is already evaluating",
        "independence": "pure predicate over confirmation graphs, called by shadow_validator",
        "novelty": "pure near-duplicate scoring, called by the distiller and consolidator",
        "deltas": "pure diff computation over two derived-state versions; called by "
        "derived_state on the pair it has just read, with no state of its own",
        "baselines": "pure baseline arithmetic (movement clamp, divergence alarm) consumed "
        "by derived_state within its own pass; it holds no store and no cadence",
        "epochs": "scoring-epoch value types and comparison rules; a store surface, not a pass",
        "contribution_judge": "an LLM judge invoked BY the scorer on the batch it is already "
        "processing; scheduling it separately would judge nothing",
        "spend": "the spend meter every costing worker writes through, per call, not per tick",
        "spend_enforce": "the cap guard that WRAPS another worker's unit of work "
        "(`run_guarded`); it has no unit of its own",
        "review_queue": "the human-review store surface; a queue an operator drains, not a "
        "pass a scheduler drives",
        "tier_a_lane": "runs synchronously on the trace path (`ingest`), once per trace, not "
        "on a cadence",
        "extractors": "structural Tier A extractors, driven per trace by tier_a_lane",
        "edit_ops": "operator-invoked (pin/merge/correct/delete-by-subject); every call has a "
        "human actor and a request behind it, so a cadence would be an actor-less edit",
        "forensics": "operator-invoked Recall & Rollback; a blast radius is computed for a "
        "memory somebody asked about",
        "preferences": "operator-invoked pin/unpin of preference memories; a pinned "
        "preference enters every run's static prefix, so the actor behind it is the point",
    }
)

# Periodic workers this process CANNOT schedule, and the exact missing dependency. Each reason
# names a port and the audit finding it belongs to, so the list reads as a work queue rather
# than as an apology.
UNSCHEDULED_WORKERS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "sweeps": "run_all_sweeps takes a MemoryLifecycleRepoPort-shaped store "
        "(select_by_status / persist); no Postgres implementation exists -- FIDELITY-AUDIT.md "
        "M3. Its TTL, decay and archive-floor arithmetic is complete and tested offline.",
        "revalidation": "Invalidator-shaped MemoryLifecycleRepoPort plus a host-supplied "
        "RevalidationCheckPort ('what counts as re-verified' is deliberately not this "
        "repository's decision, D-113); neither exists -- FIDELITY-AUDIT.md M3.",
        "invalidator": "MemoryLifecycleRepoPort (select_by_provenance / select_by_status / "
        "persist) has no Postgres implementation -- FIDELITY-AUDIT.md M3.",
        "consolidator": "needs a store that can read near-duplicate candidates and write "
        "memory_link rows; memory_link has no writer at all -- FIDELITY-AUDIT.md M4.",
        "prefix_builder": "needs MemoryStorePort plus a StaticPrefixCachePort; no class "
        "implements StaticPrefixPort anywhere -- FIDELITY-AUDIT.md M5.",
        "derived_state": "DerivedStateStorePort has no Postgres implementation and the "
        "derived_state table has no writer -- FIDELITY-AUDIT.md M3/M4.",
        "scorer": "ScorerRepoPort has no Postgres implementation, and the outcome -> "
        "trace_index -> injection_log -> memory_item join that would feed it is written "
        "nowhere -- FIDELITY-AUDIT.md M3/M7.",
        "shadow_validator": "ShadowValidatorRepoPort has no Postgres implementation. The "
        "EVIDENCE half is now live (workers.corroboration is scheduled below and writes "
        "shadow_confirm_runs); what is missing is the store that reads a quarantined row "
        "and persists the promotion -- FIDELITY-AUDIT.md M3.",
        "promotion": "PromotionRepoPort has no Postgres implementation -- FIDELITY-AUDIT.md M3.",
        "killswitch": "KillswitchStorePort has no Postgres implementation and killswitch_state "
        "has no writer; the grid evaluation and its Benjamini-Hochberg correction are complete "
        "-- FIDELITY-AUDIT.md M3/M4.",
        "distiller": "needs a TraceIndexPort + KnownDistillationPort pair and an "
        "LLMProviderPort; the first two have no Postgres implementation -- FIDELITY-AUDIT.md M3.",
    }
)

_MIN_REASON_CHARS: Final = 60
"""Same floor, and the same reason, as `workers.registry._MIN_REASON_CHARS`: a reason short
enough to be a placeholder leaves the worker exactly as unexamined as an omission while
discharging the coverage check."""


@dataclass(frozen=True, slots=True)
class LearningPlane:
    """Every learning-plane object this deployment could actually construct.

    Fields are `None` only where the dependency genuinely does not exist -- never as a
    placeholder. `corroboration` is `None` when the host supplied no
    `CorroborationCandidateSource`, which is a real deployment state (the run-to-memory match
    is a declared seam, D-121), not a build failure.
    """

    lifecycle: LifecycleWriter
    edit_ops: EditOps
    forensics: Forensics
    preferences: PreferenceManager
    embedder: Embedder
    corroboration: CorroborationWriter | None


def build_learning_plane(
    *,
    pool: ConnectionPool,
    repo: Repo,
    clock: Clock,
    cfg: WorkersConfig,
    pin: ModelPin,
    embedding_port: EmbeddingPort,
    spend: SpendRecorderPort,
    key_manager: object,
    candidate_source: CorroborationCandidateSource | None = None,
) -> LearningPlane:
    """Construct the learning plane against real stores.

    `key_manager` is typed `object` and passed straight through to `EditOps` because
    `crypto.shred.SubjectKeyManager` is a concrete class with a `Repo`-shaped store dependency;
    naming it here would make this module import the crypto package for a type it never calls.
    `EditOps` does the real typing.

    Note what is NOT optional: `lifecycle`, `edit_ops`, `forensics` and `preferences` are always
    constructed. That is the point of M1's closure -- `persist_status`, whose only
    implementations were three test fakes, now has a real one on every path that calls it.
    """
    from tracebed.stores.pg.learning import CorroborationRepo, EmbeddingRepo
    from tracebed.stores.pg.lifecycle import ForensicsRepo, LifecycleWriter, MemoryEditRepo
    from tracebed.workers.corroboration import CorroborationWriter
    from tracebed.workers.edit_ops import EditOps
    from tracebed.workers.embedder import Embedder
    from tracebed.workers.forensics import Forensics
    from tracebed.workers.preferences import PreferenceManager

    lifecycle = LifecycleWriter(pool, clock)
    edit_repo = MemoryEditRepo(pool, repo, lifecycle)
    forensics_repo = ForensicsRepo(pool, repo, lifecycle)

    embedder = Embedder(
        clock=clock,
        embedding_port=embedding_port,
        repo=EmbeddingRepo(pool),
        spend=spend,
        pin=pin,
        usd_per_1k_tokens=cfg.embedding_usd_per_1k_tokens,
        timeout_ms=cfg.embedding_timeout_ms,
        max_batch=cfg.embedding_max_batch,
    )

    corroboration = (
        CorroborationWriter(CorroborationRepo(pool)) if candidate_source is not None else None
    )

    return LearningPlane(
        lifecycle=lifecycle,
        edit_ops=EditOps(edit_repo, key_manager, clock),  # type: ignore[arg-type]
        forensics=Forensics(forensics_repo, clock),
        preferences=PreferenceManager(edit_repo, clock),
        embedder=embedder,
        corroboration=corroboration,
    )


def build_scheduled_jobs(
    plane: LearningPlane,
    *,
    cfg: WorkersConfig,
    list_project_ids: Callable[[], Sequence[ProjectId]],
    queue_observability: QueueObservabilityPort,
    topics: Sequence[str],
    lease_seconds: int,
    candidate_source: CorroborationCandidateSource | None = None,
) -> tuple[ScheduledJob, ...]:
    """The `ScheduledJob`s a `workers.scheduler.Scheduler` should be constructed with.

    `list_project_ids` is a callable, not a list, and it is re-called on EVERY tick. A project
    provisioned after this process started must be swept without a restart, and a snapshot
    taken at construction would silently exclude it forever -- which is the same class of
    defect as the empty registry, one layer down.

    Every job iterates projects itself and calls its worker once per project (PLAN.md §10: a
    worker batch never mixes projects). A project whose sweep raises is logged and the loop
    continues to the next project, for the reason `Scheduler.tick` gives for a raising job: one
    broken project must not stop the other nine hundred.

    Validates coverage before returning, so a worker dropped for a missing dependency fails
    process construction rather than shrinking the schedule.
    """
    from tracebed.workers.gc import run_gc_cycle

    jobs: list[ScheduledJob] = []

    def _per_project(name: str, body: Callable[[ProjectId], None]) -> Callable[[], None]:
        def _run() -> None:
            for project_id in list_project_ids():
                try:
                    body(project_id)
                except Exception:
                    logger.exception("scheduled job %r failed for project %s", name, project_id)

        return _run

    embedder = plane.embedder
    jobs.append(
        ScheduledJob(
            name="embedder",
            interval=timedelta(minutes=cfg.embedding_interval_minutes),
            run=_per_project(
                "embedder",
                lambda project_id: _drop(
                    embedder.run(project_id, limit=cfg.embedding_batch_limit)
                ),
            ),
        )
    )

    corroboration = plane.corroboration
    if corroboration is not None and candidate_source is not None:
        source = candidate_source
        jobs.append(
            ScheduledJob(
                name="corroboration",
                interval=timedelta(minutes=cfg.corroboration_interval_minutes),
                run=_per_project(
                    "corroboration",
                    lambda project_id: _drop(corroboration.run_once(project_id, source=source)),
                ),
            )
        )

    jobs.append(
        ScheduledJob(
            name="gc",
            interval=timedelta(minutes=cfg.gc_interval_minutes),
            # Not per-project: `work_queue` and `dead_letter` are unpartitioned (contract
            # §5.3), so queue health is a process-wide reading and iterating projects here
            # would report the same numbers N times.
            run=lambda: _drop(
                run_gc_cycle(
                    observability=queue_observability,
                    topics=list(topics),
                    lease_seconds=lease_seconds,
                )
            ),
        )
    )

    scheduled = {job.name for job in jobs}
    unscheduled = dict(UNSCHEDULED_WORKERS)
    if corroboration is None or candidate_source is None:
        unscheduled["corroboration"] = (
            "constructed, but not scheduled: no CorroborationCandidateSource was supplied. "
            "Deciding WHICH runs corroborate WHICH quarantined memory is a declared "
            "host-supplied seam (D-121), not this repository's invention -- without one there "
            "is nothing for the writer to record."
        )
    validate_worker_coverage(scheduled, unscheduled=unscheduled)
    for name, reason in sorted(unscheduled.items()):
        logger.info("worker composition: %r deliberately unscheduled: %s", name, reason)
    return tuple(jobs)


def validate_worker_coverage(
    scheduled: Sequence[str] | set[str],
    *,
    unscheduled: Mapping[str, str] = UNSCHEDULED_WORKERS,
    non_periodic: Mapping[str, str] = NON_PERIODIC_WORKERS,
    all_workers: frozenset[str] | None = None,
) -> None:
    """Raises `ConfigError` unless the three sets PARTITION every module under
    `tracebed.workers`.

    Parameterised for the same reason `workers.registry.validate_topic_coverage` is: a check
    whose only exercisable input is the one arrangement that happens to be correct today is a
    check nobody has ever seen fail.
    """
    known = discover_worker_modules() if all_workers is None else all_workers
    if not known:
        raise ConfigError(
            "worker composition: no modules discovered under tracebed.workers -- the package "
            "walk behind discover_worker_modules() has stopped finding anything, so every "
            "coverage relation below would be vacuously satisfied by scheduling nothing"
        )
    scheduled_set = set(scheduled)
    unscheduled_set = set(unscheduled)
    non_periodic_set = set(non_periodic)

    phantom = sorted((scheduled_set | unscheduled_set | non_periodic_set) - known)
    if phantom:
        raise ConfigError(
            f"worker composition: {phantom} are classified but are not modules under "
            f"tracebed.workers (known: {sorted(known)}). A schedule entry for a module that "
            "does not exist runs nothing, forever, without ever raising"
        )
    overlaps = sorted(
        (scheduled_set & unscheduled_set)
        | (scheduled_set & non_periodic_set)
        | (unscheduled_set & non_periodic_set)
    )
    if overlaps:
        raise ConfigError(
            f"worker composition: {overlaps} appear in more than one classification -- a "
            "worker is scheduled, or blocked on a named dependency, or has no cadence to "
            "have; the three are exclusive and the combination hides which one is true"
        )
    uncovered = sorted(known - scheduled_set - unscheduled_set - non_periodic_set)
    if uncovered:
        raise ConfigError(
            f"worker composition: module(s) {uncovered} under tracebed.workers are neither "
            "scheduled, nor recorded in UNSCHEDULED_WORKERS with the dependency they are "
            "blocked on, nor recorded in NON_PERIODIC_WORKERS as having no cadence. A worker "
            "dropped without a recorded reason is indistinguishable from one that is running"
        )
    thin = sorted(
        name
        for table in (unscheduled, non_periodic)
        for name, reason in table.items()
        if len(reason.strip()) < _MIN_REASON_CHARS
    )
    if thin:
        raise ConfigError(
            f"worker composition: entries for {thin} do not carry a real reason (fewer than "
            f"{_MIN_REASON_CHARS} characters). A placeholder discharges this check while "
            "leaving the worker exactly as unexamined as an omission"
        )


def _drop(value: object) -> None:
    """Discard a worker's return value. `ScheduledJob.run` is `Callable[[], None]`, and the
    per-project bodies above call methods that return result objects; a lambda that returned
    them would not type-check. Named rather than inlined as `del` so the intent is visible: the
    result is DISCARDED here, and every worker that produces one already records what matters
    on its own metrics/ledger rather than relying on a caller to read it."""
    del value
