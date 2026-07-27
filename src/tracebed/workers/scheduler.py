"""Periodic schedule: TTL sweeps, revalidation, consolidation, prefix
rebuild, derived-state refresh, GC (PLAN.md §7 Phase 2, chunk `worker-runner`).

`Scheduler` is a generic "run this job every interval, driven by an
injectable `Clock`" harness -- deliberately ignorant of what any individual
job DOES. The concrete Phase 2 jobs it will eventually drive (TTL sweeps,
consolidation, invalidator revalidation, prefix rebuild, derived-state
refresh) are owned by other Phase 2 chunks (`extractors`, `consolidator`,
`invalidator`, `prefix_builder` -- none of which exist in this workspace yet;
`src/tracebed/workers/` currently holds only `spend.py` besides this chunk's
own files) plus this chunk's own `workers.gc`. Hard-coding imports to modules
that do not exist yet would make this file unimportable until every sibling
chunk lands; instead, jobs are supplied by the CALLER as
`ScheduledJob(name, interval, run)` values, so `Scheduler` itself never
imports a job's implementation and stays usable the moment any one job is
ready, independent of the others.

CONTRACT GAP -- cadence is intentionally NOT read from `EffectiveConfig`:
PLAN.md §6's config table has no field for "how often does the TTL sweep
run" (only the TTL *durations* themselves -- `lifecycle.quarantine_ttl_days`
etc. -- which are `domain.state_machine` guard thresholds, not sweep
periods). Inventing one here would be exactly hard rule 4's "a number that
is not there is a contract_gap, not a licence to invent a literal" --
`ScheduledJob.interval` is therefore a required, caller-supplied value with
no default anywhere in this module, and the missing config field is reported
as a contract_gap against `domain/config.py` (outside this chunk's file
list) for whichever future chunk wires real cadences into
`workers.runner.run()`.

This is what lets the Phase 2 gate's 30-simulated-day soak (PLAN.md §7)
drive 30 days of scheduled work in milliseconds: `Scheduler.tick()` reads
only `clock.monotonic_ms()`, so advancing a `FakeClock` by
`timedelta(days=30)` in one step and calling `tick()` once catches every job
up to its true simulated-cadence count in a single call -- no wall-clock
sleep anywhere in this module, and no dependence on how finely the caller
chooses to advance the clock between `tick()` calls.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Final

from prometheus_client import Counter

if TYPE_CHECKING:
    from tracebed.domain.clock import Clock

__all__ = ["ScheduledJob", "Scheduler"]

logger = logging.getLogger(__name__)

SCHEDULER_JOB_RUNS: Counter = Counter(
    "tracebed_scheduler_job_runs_total",
    "Number of times a scheduled job's `run` callable was invoked (including "
    "invocations that raised).",
    ["job"],
)
SCHEDULER_JOB_ERRORS: Counter = Counter(
    "tracebed_scheduler_job_errors_total",
    "Number of times a scheduled job's `run` callable raised.",
    ["job"],
)

# A job's cadence is caller-supplied and therefore attacker/operator-influenced
# in the same sense `domain.state_machine.MAX_CONFIRMATIONS_CONSIDERED` bounds
# an attacker-influenced graph size (PLAN.md §5's independence search): an
# absurdly short interval combined with a large clock jump (the 30-simulated
# -day soak advances the clock in large steps) must not turn `tick()` into an
# unbounded loop. This bound can only ever make the reported catch-up count
# SMALLER than the true elapsed-interval count for one `tick()` call -- it
# never fires a job MORE often than its own interval -- so it is a safety
# ceiling, never a scheduling behaviour.
_MAX_CATCH_UP_RUNS_PER_TICK: Final = 100_000


@dataclass(frozen=True, slots=True)
class ScheduledJob:
    """One periodic job. `run` is a zero-argument callable -- how it does its
    own per-project iteration and homogeneity (PLAN.md §10: a worker batch
    must never mix projects) is the job's own concern; this module only
    decides WHEN to call it, never what it does once called.
    """

    name: str
    interval: timedelta
    run: Callable[[], None]

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("ScheduledJob.name must be a non-empty string")
        if self.interval <= timedelta(0):
            raise ValueError(f"ScheduledJob({self.name!r}).interval must be positive")


class Scheduler:
    """Drives a set of `ScheduledJob`s off an injectable `Clock`'s monotonic
    reading. See the module docstring for why cadence is caller-supplied
    rather than read from `EffectiveConfig`.
    """

    def __init__(self, clock: Clock, jobs: Sequence[ScheduledJob]) -> None:
        names = [job.name for job in jobs]
        if len(names) != len(set(names)):
            raise ValueError(f"duplicate ScheduledJob names: {sorted(names)}")
        self._clock = clock
        self._jobs = tuple(jobs)
        # First fire one interval AFTER construction, never at t=0: several
        # `Scheduler` instances starting together (a process restart, a
        # multi-worker deployment) must not all sweep every project in the
        # same instant. Mirrors `ingest.runner.ConsumerRunner`'s identical,
        # already-documented choice for `sweep_incomplete`.
        start_ms = clock.monotonic_ms()
        self._due_at_ms: dict[str, float] = {
            job.name: start_ms + job.interval.total_seconds() * 1000.0 for job in self._jobs
        }

    def tick(self) -> Mapping[str, int]:
        """Runs every job whose interval has elapsed one or more times since
        the last `tick()` (or construction), once per elapsed interval, so a
        single large clock jump still fires the correct total count rather
        than collapsing to one run. Returns, for each job that fired at
        least once this call, the number of times it ran; a job that did not
        become due is omitted (not reported as zero).

        A job that raises is caught, logged, and counted
        (`SCHEDULER_JOB_ERRORS`) rather than propagated -- one broken job
        must not stop the rest of the schedule, or that same job's own next
        occurrence, from running. This mirrors
        `workers.runner.WorkerRunner`'s identical reasoning for a raising
        handler.
        """
        now_ms = self._clock.monotonic_ms()
        fired: dict[str, int] = {}
        for job in self._jobs:
            interval_ms = job.interval.total_seconds() * 1000.0
            due = self._due_at_ms[job.name]
            count = 0
            while due <= now_ms:
                if count >= _MAX_CATCH_UP_RUNS_PER_TICK:
                    logger.warning(
                        "scheduler: job %r exceeded %d catch-up runs in one tick; "
                        "skipping the remaining backlog instead of looping unbounded",
                        job.name,
                        _MAX_CATCH_UP_RUNS_PER_TICK,
                    )
                    due = now_ms + interval_ms
                    break
                try:
                    job.run()
                except Exception:
                    logger.exception("scheduler: job %r raised", job.name)
                    SCHEDULER_JOB_ERRORS.labels(job=job.name).inc()
                SCHEDULER_JOB_RUNS.labels(job=job.name).inc()
                count += 1
                due += interval_ms
            self._due_at_ms[job.name] = due
            if count:
                fired[job.name] = count
        return fired

    def due_in_ms(self, name: str) -> float:
        """Milliseconds until `name` next fires (negative if a `tick()` is
        overdue). Offline-testable visibility with no side effect -- used by
        tests and by the soak harness to assert cadence without waiting for
        a `tick()`.
        """
        for job in self._jobs:
            if job.name == name:
                return self._due_at_ms[name] - self._clock.monotonic_ms()
        raise KeyError(name)
