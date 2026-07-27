"""Queue-topic -> `BatchHandler` registry (PLAN.md §7 Phase 2, chunk `worker-handlers`).

`build_default_registry` is the one call site `workers.runner.run()` asks "what does this
process's `WorkerRunner` actually consume." It replaces the `handlers={}` literal
(`workers/runner.py:422`) that `docs/FIDELITY-AUDIT.md` §11 flags (gap M2: "a deployed Tracebed
today ingests traces and outcome events faithfully and learns nothing from either").

CONTRACT_GAP -- the task brief for this chunk names an eight-topic mapping table
(`trace_event`/`outcome_event`/`memory_proposal`/`distill`/`score`/`consolidate`/`invalidate`/
`prefix_build`), each pointed at a "real worker" module, and separately instructs "read
`stores/pg/queue.py` for the authoritative topic constants -- do NOT invent topic strings."
Reading `stores/pg/queue.py` (as instructed) settles the conflict against the eight-topic table:

  * `stores/pg/queue.py` defines exactly THREE `TOPIC_*` constants -- `TOPIC_TRACE_EVENT`,
    `TOPIC_OUTCOME_EVENT`, `TOPIC_MEMORY_PROPOSAL` -- and its own module comment records that a
    prior chunk already asked for the wider vocabulary this brief repeats (distill, consolidate,
    invalidate, prefix_build, score) and was refused: PHASE0-CONTRACT.md §5.3 defines only the
    three, and §14's queue DO-NOT list is explicit, "do NOT add topics beyond the three
    constants." `stores/pg/queue.py` is not in this chunk's file list, so that refusal cannot be
    revisited here either. Registering `"distill"`/`"score"`/`"consolidate"`/`"invalidate"`/
    `"prefix_build"` as dict keys below would be exactly the invented topic string this chunk's
    own instructions forbid -- a `WorkerRunner` that polls `queue.claim("distill", n)` forever
    against a topic no producer ever enqueues onto is a silent no-op, not a fix.

    Independently of the topic-string question: none of `workers.distiller.Distiller.distill`,
    `workers.scorer.run_scorer_batch`, `workers.consolidator.Consolidator.consolidate`,
    `workers.invalidator.Invalidator`, or `workers.prefix_builder.PrefixBuilder.run` are shaped
    like `workers.runner.BatchHandler.handle(batch: WorkBatch)` -- each takes an explicit
    `ProjectId`/`ProjectScope` and does its own per-project iteration, which is exactly the shape
    `workers.scheduler.Scheduler`'s `ScheduledJob(name, interval, run: Callable[[], None])`
    expects (`workers/scheduler.py`'s own docstring: "how it does its own per-project iteration
    ... is the job's own concern"), not this registry's `Mapping[str, BatchHandler]`. Wiring
    those five into `runner.run()` needs a `Scheduler` instance and five `ScheduledJob`s
    constructed in that function's body -- a `runner.run()`-body change this chunk's file list
    (`registry.py`, plus the single `handlers=` line in `runner.py`) does not reach. It is the
    other half of gap M2, reported here rather than built here.

  * The three real topics are, today, each already consumed end-to-end by their own dedicated,
    self-claiming consumer -- constructed directly in `runner.run()`, not through `WorkerRunner`
    at all:

      - `TOPIC_TRACE_EVENT`  -> `ingest.trace_writer.TraceWriter.run_once` (the `tracebed-ingest`
        thread, via `ingest.runner.ConsumerRunner`)
      - `TOPIC_OUTCOME_EVENT` -> `ingest.outcome_intake.OutcomeIntake.run_once` (same thread)
      - `TOPIC_MEMORY_PROPOSAL` -> `workflow.agent_control.ProposalIntake.run_forever` (the
        `tracebed-proposals` thread)

    Each of those three's own `run_once`/`run_forever` calls `self._queue.claim(TOPIC, n)`
    ITSELF -- `ingest/runner.py`'s module docstring says so outright ("a second layer of
    claim/ack/nack here would double-claim the same queue rows against the same
    `QueueConsumerPort`"), and `workflow/agent_control.py`'s `ProposalIntake` docstring gives the
    independent, sharper reason `TOPIC_MEMORY_PROPOSAL` specifically must never become a
    `BatchHandler`: its ack/nack policy is PER ITEM (a scan rejection or a cap refusal is acked,
    a store error is nacked), while `WorkerRunner` acks or nacks an entire claimed batch on one
    handler outcome -- "folding it into a batch handler would collapse those into one verdict for
    every item claimed in the same round, which turns one poisoned proposal into a retry storm
    for the innocent items beside it." Registering any of the three here a second time would not
    merely be redundant polling; a `BatchHandler` adapter over one of these `run_once` methods
    would ack/nack THIS registry's own claimed `WorkBatch` based on a side effect performed on a
    COMPLETELY DIFFERENT batch claimed underneath by the wrapped call -- rows this process
    reports as durably processed that were never touched. That is a correctness regression, not
    wiring progress, so none of the three is registered below.

Given both halves of the gap, `build_default_registry` returns an EMPTY `Mapping[str,
BatchHandler]` today. That is not a repeat of the `handlers={}` defect this chunk exists to fix:
the defect was an UNAUDITED empty literal with no record of why nothing was reachable. This one is
audited -- `UNREGISTERED_TOPICS` names every topic `stores.pg.queue` defines (discovered by
introspecting that module at import time, not hand-copied, so a topic added there without a
matching entry here is caught by `validate_topic_coverage` rather than silently falling through)
and the reason it is not this registry's to consume. A hard-coded non-empty return with a
fabricated handler would be the "no plausible-constant returns" hard rule forbids; this is the
honest alternative.

COVERAGE IS ENFORCED, NOT MERELY ASSERTED IN A TEST. `validate_topic_coverage` runs inside
`build_default_registry`, so `workers.runner.run()` cannot construct a `WorkerRunner` over a
handler map that disagrees with `stores.pg.queue` in EITHER direction. A test alone would not be
enough, for a reason this chunk's own "a worker whose dependencies are absent must be OMITTED"
rule makes concrete: the moment a handler is built conditionally, the registry a test observes
(with test-shaped `WorkerDeps`) and the registry a deployed process builds (with production
`WorkerDeps`) are DIFFERENT MAPPINGS, and only the second one matters. The three failures the
validator refuses to return from are each silent in production and invisible to a test of the
other configuration:

  * a topic in `ALL_TOPICS` covered by NEITHER half -- a queue topic nothing in this process
    consumes and nothing disclaims: rows accumulate on `work_queue` forever, and the only symptom
    is a depth gauge nobody is watching. This is the omitted-worker case: a handler dropped
    because its dependency was absent shrinks the registry, and without this check the process
    starts healthy and drains nothing.
  * a handler key NOT in `ALL_TOPICS` -- `WorkerRunner.run_once` would poll `claim("distil", n)`
    (note the typo) every second forever against a topic no producer writes to. Never an error,
    never any work: exactly as bad as an unconsumed topic, and harder to spot because the
    process looks busy.
  * a topic in BOTH halves -- a registry claiming to consume what it simultaneously documents as
    another loop's, which is how the double-claim hazard the reasons below describe gets
    reintroduced by an edit that only reads one of the two tables.

`ALL_TOPICS` being empty is itself refused, because every check above degenerates to a tautology
if the introspection that feeds it silently stops finding anything.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

import tracebed.stores.pg.queue as _queue_module
from tracebed.domain.errors import ConfigError

if TYPE_CHECKING:
    from tracebed.workers.runner import BatchHandler

__all__ = [
    "ALL_TOPICS",
    "UNREGISTERED_TOPICS",
    "WorkerDeps",
    "build_default_registry",
    "validate_topic_coverage",
]

logger = logging.getLogger(__name__)

# Discovered, not hand-copied: walking `stores.pg.queue`'s own module namespace for its
# `TOPIC_*` constants (rather than re-listing their string values here) is what makes
# `tests/phase2/test_worker_registry.py`'s coverage assertion a real regression guard. A
# hand-copied literal set would keep passing the day a new `TOPIC_*` constant landed in
# `queue.py` without a corresponding entry in this module -- exactly the silent-backlog failure
# mode this chunk's tests exist to catch.
ALL_TOPICS: Final[frozenset[str]] = frozenset(
    value
    for name, value in vars(_queue_module).items()
    if name.startswith("TOPIC_") and isinstance(value, str)
)

_TRACE_EVENT_REASON: Final = (
    "already consumed end-to-end by ingest.trace_writer.TraceWriter.run_once, wired directly "
    "in workers.runner.run() as the `tracebed-ingest` thread (ingest.runner.ConsumerRunner). "
    "TraceWriter.run_once claims TOPIC_TRACE_EVENT itself (ingest/runner.py's own docstring: "
    "'a second layer of claim/ack/nack here would double-claim the same queue rows'); "
    "registering it here too would race that thread for the same rows, and a BatchHandler "
    "adapter over run_once would ack THIS registry's claimed batch based on a side effect "
    "performed on a different batch claimed underneath by the wrapped call."
)
_OUTCOME_EVENT_REASON: Final = (
    "already consumed end-to-end by ingest.outcome_intake.OutcomeIntake.run_once, wired "
    "directly in workers.runner.run() as the `tracebed-ingest` thread (same "
    "ingest.runner.ConsumerRunner as TOPIC_TRACE_EVENT). Same double-claim hazard as "
    "TOPIC_TRACE_EVENT (see that reason) -- OutcomeIntake.run_once claims TOPIC_OUTCOME_EVENT "
    "itself."
)
_MEMORY_PROPOSAL_REASON: Final = (
    "already consumed end-to-end by workflow.agent_control.ProposalIntake.run_forever, wired "
    "directly in workers.runner.run() as the `tracebed-proposals` thread. ProposalIntake's own "
    "docstring gives the specific reason this topic must never become a workers.runner."
    "BatchHandler: its ack/nack policy is PER ITEM (a scan rejection or cap refusal is acked, "
    "a store error is nacked), while WorkerRunner acks or nacks a whole claimed batch on one "
    "handler outcome -- folding it in would turn one poisoned proposal into a retry storm for "
    "every innocent item claimed in the same round."
)

# Every topic `stores.pg.queue` defines that this registry deliberately does not hand to
# `WorkerRunner`, and why. `validate_topic_coverage` enforces
# `ALL_TOPICS == set(build_default_registry(...)) | set(UNREGISTERED_TOPICS)` with the two
# halves disjoint -- a topic can be registered, or justified, never neither and never both.
#
# `MappingProxyType`, not a bare dict, for the reason `stores.pg.queue.QueueItem.payload` is one:
# this table is the evidence half of an invariant checked at process construction, and a plain
# module-level dict can be mutated by any importer AFTER that check has run -- a test or a
# sibling module that "temporarily" inserts a key here would be silently rewriting the audit
# trail a deployed process reports, not just its own fixture.
UNREGISTERED_TOPICS: Final[Mapping[str, str]] = MappingProxyType(
    {
        _queue_module.TOPIC_TRACE_EVENT: _TRACE_EVENT_REASON,
        _queue_module.TOPIC_OUTCOME_EVENT: _OUTCOME_EVENT_REASON,
        _queue_module.TOPIC_MEMORY_PROPOSAL: _MEMORY_PROPOSAL_REASON,
    }
)

# A reason shorter than this is not a reason. The three above each name the owning consumer AND
# the specific hazard of consuming the topic twice; the floor exists so a future entry cannot
# discharge the coverage check with "TODO" / "n/a" / "not needed" and leave the topic just as
# unexamined as if it had been omitted entirely (hard rule 9).
_MIN_REASON_CHARS: Final = 60


@dataclass(frozen=True, slots=True)
class WorkerDeps:
    """Constructor inputs for the topic handlers this registry builds.

    Empty today, deliberately: every topic `stores.pg.queue` currently defines is accounted for
    in `UNREGISTERED_TOPICS` (see the module docstring for why each is not this registry's to
    consume), so no handler built here needs a dependency yet. This type is the stable call site
    `workers.runner.run()` already passes through (`build_default_registry(WorkerDeps())`) for
    the day a genuinely `BatchHandler`-shaped, topic-driven worker lands -- e.g. a future worker
    gated on `LLMProviderPort` availability, per this chunk's own "a worker whose dependencies
    are absent must be OMITTED, not registered-and-broken" rule. Adding invented fields ahead of
    a real consumer would be exactly hard rule 9's "plausible-constant" placeholder; the fields
    arrive with the first handler that reads them.
    """


def validate_topic_coverage(
    registered: Mapping[str, object],
    *,
    all_topics: frozenset[str] = ALL_TOPICS,
    unregistered: Mapping[str, str] = UNREGISTERED_TOPICS,
) -> None:
    """Raises `ConfigError` unless `registered` and `unregistered` PARTITION `all_topics`.

    The module docstring spells out why each refusal below is a production-silent failure
    rather than something a test of one configuration would catch. Called by
    `build_default_registry`, so the failure lands at process construction -- before
    `workers.runner.run()` starts a `WorkerRunner` thread and a supervisor concludes from its
    continued liveness that the queue is being drained.

    `ConfigError` (not `ValueError`) because this is the same class of fault as
    `runner.run()`'s existing "the proposal consumer was wired with a store that cannot enforce
    the caps" assertion: a wiring/composition mistake, raised where it is made.

    Parameterised rather than reading the module globals directly so the enforcement can be
    driven with synthetic inputs -- a check whose only exercisable input is the one arrangement
    that happens to be correct today is a check nobody has ever seen fail.
    """
    if not all_topics:
        # Guards the discovery step itself: `ALL_TOPICS` is introspected, so a refactor in
        # `stores.pg.queue` that moves the topic names anywhere other than module-level
        # `TOPIC_*` strings would leave it empty -- and every set relation below would then be
        # vacuously satisfied by any registry at all, including one consuming nothing.
        raise ConfigError(
            "worker registry: no queue topics discovered on tracebed.stores.pg.queue -- "
            "the TOPIC_* introspection behind ALL_TOPICS has stopped finding anything, so "
            "topic coverage cannot be verified in either direction"
        )
    registered_topics = set(registered)
    unregistered_topics = set(unregistered)

    phantom = sorted(registered_topics - all_topics)
    if phantom:
        raise ConfigError(
            f"worker registry: handler(s) registered for topic(s) {phantom} that "
            f"tracebed.stores.pg.queue does not define (known topics: {sorted(all_topics)}). "
            "WorkerRunner would poll a topic no producer ever enqueues onto -- a permanent "
            "no-op that never raises and never processes anything"
        )
    disclaimed_phantom = sorted(unregistered_topics - all_topics)
    if disclaimed_phantom:
        raise ConfigError(
            f"worker registry: UNREGISTERED_TOPICS justifies topic(s) {disclaimed_phantom} "
            f"that tracebed.stores.pg.queue does not define (known topics: "
            f"{sorted(all_topics)}) -- a stale disclaimer can silently discharge the coverage "
            "check for a topic that no longer exists"
        )
    both = sorted(registered_topics & unregistered_topics)
    if both:
        raise ConfigError(
            f"worker registry: topic(s) {both} are simultaneously registered as a "
            "BatchHandler and documented as another loop's to consume -- one of the two is "
            "wrong, and the combination reintroduces the double-claim hazard the "
            "UNREGISTERED_TOPICS reasons describe"
        )
    uncovered = sorted(all_topics - registered_topics - unregistered_topics)
    if uncovered:
        raise ConfigError(
            f"worker registry: queue topic(s) {uncovered} have no handler and no entry in "
            "UNREGISTERED_TOPICS. Rows enqueued onto them would accumulate on work_queue "
            "forever with no error anywhere; a worker omitted because its dependencies were "
            "absent must be recorded as unregistered WITH A REASON, never merely dropped"
        )
    thin = sorted(
        topic
        for topic, reason in unregistered.items()
        if len(reason.strip()) < _MIN_REASON_CHARS
    )
    if thin:
        raise ConfigError(
            f"worker registry: UNREGISTERED_TOPICS entries for {thin} do not carry a real "
            f"reason (fewer than {_MIN_REASON_CHARS} characters). A placeholder leaves the "
            "topic exactly as unexamined as an omission while passing the coverage check"
        )


def build_default_registry(deps: WorkerDeps) -> Mapping[str, BatchHandler]:
    """The real handler map for `workers.runner.WorkerRunner` -- replaces `handlers={}`.

    Returns an empty mapping today: see the module docstring for the two independent reasons
    (no queue topic beyond the three `stores.pg.queue` defines exists to register, and each of
    those three is already owned end-to-end by a dedicated, self-claiming consumer thread that
    a `BatchHandler` adapter cannot safely wrap). `deps` is accepted, not read, for the same
    reason -- it is wired through so a future handler's construction has a real, single call
    site to extend rather than a second one invented at the point it is first needed.

    Every return passes `validate_topic_coverage` first, so this function cannot hand back a
    map that disagrees with `stores.pg.queue` in either direction -- including the empty one it
    returns today, which is checked on exactly the same terms as any future populated one.

    `logger.info` at construction, not merely a comment, so the audit trail this docstring
    describes for `UNREGISTERED_TOPICS` is also visible in the running process, not just in
    source -- "a worker whose dependencies are absent must be OMITTED ... with a logged reason
    at construction" applies just as much to a worker omitted for architectural reasons as to
    one omitted for a missing dependency.

    The result is a read-only view: `WorkerRunner` copies what it is given, but a caller holding
    a mutable registry could otherwise add a topic AFTER validation and get exactly the phantom
    -topic poll the validator exists to refuse.
    """
    del deps  # see docstring: accepted for the stable call site, not yet read
    handlers: dict[str, BatchHandler] = {}
    for topic, reason in UNREGISTERED_TOPICS.items():
        logger.info("worker registry: topic %r deliberately unregistered: %s", topic, reason)
    validate_topic_coverage(handlers)
    return MappingProxyType(handlers)
