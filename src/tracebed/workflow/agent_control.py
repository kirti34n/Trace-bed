"""`propose_memory`, LIVE end-to-end (PLAN.md §3 `POST /v1/propose_memory`; §7 Phase 4
"agent_control mode (`propose_memory` live end-to-end with caps)"; D-023).

`api.routes_v1.propose_memory` already enqueues every submitted proposal onto
`TOPIC_MEMORY_PROPOSAL` (`stores.pg.queue`: "enqueued Phase 0, consumed Phase 4"). This
module is the consumer that turns a queued envelope into a governed `memory_item` row, and
the two properties D-023 exists to guarantee are both enforced here, not merely inherited:

1. A PROPOSAL ALWAYS LANDS QUARANTINED WITH PROVENANCE CLASS `PROPOSAL`, AND CAN NEVER SKIP
   CORROBORATION. `submit_proposal` calls `domain.state_machine.apply(None, QUARANTINED,
   evidence, limits)` for the ONE creation edge `ProvenanceClass.PROPOSAL` has
   (`_guard_none_to_quarantined`); nothing here computes a status any other way. That the
   resulting row can never exit quarantine through a skip is `_guard_quarantined_to_candidate`
   hard-coding "for `provenance_class == PROPOSAL`, both routes return not-ok
   unconditionally" -- a rule this module does not implement and cannot weaken, because
   `domain/state_machine.py` is outside this chunk's file list (hard rule 7). What THIS
   module is responsible for is never lying about the class: `Provenance(cls=
   ProvenanceClass.PROPOSAL, run_id=run_id)` is the only provenance shape `submit_proposal`
   ever builds.

2. THE CAPS ARE ENFORCED SERVER-SIDE, PER RUN AND PER PROJECT PER UTC DAY, FROM THE INJECTED
   CLOCK -- NEVER FROM CALLER INPUT. `proposals.per_run_cap` (2) and
   `proposals.per_project_daily_cap` (50) are read from `EffectiveConfig` (hard rule 4: no
   magic numbers), and "today" is `clock.now().date()` -- the same clock every other
   transition's `now` comes from (hard rule 3), so a day boundary in a test is exactly where
   a `FakeClock.advance()` puts it, never wall time. `now` is read ONCE per submission and
   both `today` and `evidence.now` derive from that one instant, so a submission that
   straddles UTC midnight cannot be counted against one day and stamped with the other.
   Both counts are durable, queried counts (`AgentControlRepoPort.count_proposals_in_run` /
   `.count_proposals_in_project_day`), not an in-process counter -- an in-memory count would
   reset on restart and would not be shared across worker instances, which is precisely the
   flooding an agent-authored proposal stream can otherwise produce (PLAN.md §6's own note:
   "the control that stops an agent flooding its own vault with self-authored beliefs").

3. THE CAP IS CHECKED AND SPENT ATOMICALLY, NOT MERELY CHECKED. "Count, then insert" is a
   read-modify-write over durable state, and two proposals racing between the count and the
   insert both observe `count == cap - 1` and both land -- the caps hold for every
   sequential test and leak under exactly the concurrency `ProposalIntake` creates. The whole
   count->scan->apply->insert sequence therefore runs inside `_cap_lock` (see
   `AgentControl.submit_proposal`), which makes the caps exact for every submission this
   PROCESS handles, including a `ProposalIntake` batch fanned across threads.
   THE DURABLE HALF: a process-local lock is not enough on its own -- two API/worker
   processes sharing one Postgres would each count `cap - 1` and each land a row. So when
   the injected store offers `insert_proposal_within_caps` (`stores.pg.repo.Repo` does),
   the dedup check, both counts and the INSERT are re-done inside ONE database transaction
   holding a project-scoped `pg_advisory_xact_lock`, and THAT result is authoritative. The
   in-process counts before it are a cheap pre-check whose only job is to refuse an
   over-cap proposal before it pays for the scan suite; they never decide the outcome on
   their own. A store that does not implement the method (`AgentControlRepoPort`'s minimum
   surface) still gets exact caps per process, and `AgentControl.durable_caps` reports
   which of the two is in force rather than leaving a caller to guess.

4. AT-LEAST-ONCE DELIVERY IS A WRITE-PATH HAZARD HERE, NOT A NOTE. `adapters.ports
   .QueueConsumerPort` states it outright: "Delivery is at-least-once: every consumer behind
   this port must be idempotent (trace writer on `(run_id, seq)`, outcome intake on
   `event_id`)." A proposal envelope carries no such key -- `api.routes_v1
   ._proposal_envelope` mints none -- so a lease expiry, or a crash between a successful
   insert and its `ack`, redelivers the item and lands a SECOND vault row for one submitted
   belief. `submit_proposal` therefore dedups on the only durable identity a proposal has:
   `(project_id, run_id, content_hash(content))`, via
   `AgentControlRepoPort.find_proposal_in_run`, and returns `ProposalDuplicate` naming the
   row that already exists rather than writing a second one. The check is inside `_cap_lock`
   with everything else, so a redelivery racing the original cannot slip between them.

CONTRACT GAP (narrowed, and what remains is real): `stores.pg.repo.Repo` now implements all
three `AgentControlRepoPort` queries plus `insert_proposal_within_caps`, so the port is
satisfied by the shipped store rather than by fixtures only. What is still missing is the
INDEXES those queries want -- `(project_id, (provenance->>'run_id'))` and
`(project_id, created_at)` filtered to `provenance->>'class' = 'proposal'`, plus
`(project_id, content_hash)`. Without them each count is a partition scan. That is correct
but not fast, and it is on a path an agent runtime does not await, so it is recorded here
rather than fixed with an index nobody has measured a need for.

CONTRACT GAP (reported): `api.routes_v1._proposal_envelope` (owned by a different chunk, not
in this chunk's file list) carries `project_id`/`principal_id`/`run_id`/`proposal` but no
`agent_type_id` -- unlike `_trace_envelope`, which does. This module does not need it added:
`AgentControlRepoPort.resolve_project(principal_id)` (== `Repo.resolve_project`, PLAN.md §5's
`agent_registration` isolation root) already derives `agent_type_id` server-side from the
authenticated principal for a `claimed_scope="agent_type"` proposal, so no wire-shape change
was needed to keep scope derivation server-side (invariant 4).
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from datetime import date
from enum import StrEnum
from typing import TYPE_CHECKING, Final, Protocol, runtime_checkable
from uuid import UUID

from pydantic import BaseModel, ConfigDict, ValidationError

from tracebed.core.scans import ScanContext, scan
from tracebed.domain.canonical import content_hash
from tracebed.domain.enums import Lane, MemType, ProvenanceClass, ScopeType, TrustTier
from tracebed.domain.errors import ScanRejected, TracebedError
from tracebed.domain.events import MemoryProposal
from tracebed.domain.ids import AgentTypeId, MemoryId, PrincipalId, ProjectId, RunId
from tracebed.domain.memory import NewMemoryItem, Provenance, validate_provenance
from tracebed.domain.state_machine import Status, TransitionEvidence, TransitionLimits, apply
from tracebed.stores.pg.queue import TOPIC_MEMORY_PROPOSAL, compute_backoff
from tracebed.stores.pg.repo import ProposalCapOutcome, ProposalInsertResult

if TYPE_CHECKING:
    from tracebed.adapters.ports import QueueConsumerPort
    from tracebed.domain.clock import Clock
    from tracebed.domain.config import EffectiveConfig
    from tracebed.domain.scan import ScanVerdict
    from tracebed.domain.scope import ProjectScope
    from tracebed.stores.pg.queue import QueueItem

logger = logging.getLogger(__name__)

__all__ = [
    "PROPOSABLE_MEM_TYPES",
    "PROPOSABLE_SCOPE_TYPES",
    "AgentControl",
    "AgentControlRepoPort",
    "ConfigProvider",
    "DurableProposalCapPort",
    "NotProposable",
    "ProposalAccepted",
    "ProposalDuplicate",
    "ProposalIntake",
    "ProposalOutcome",
    "ProposalQueueEnvelope",
    "ProposalRefused",
]

# PLAN.md §3's `POST /v1/propose_memory` body states both vocabularies exhaustively:
# `mem_type: "lesson"|"semantic"`, `claimed_scope: "agent_type"|"project_shared"`.
# `domain.events.MemoryProposal` pins them as pydantic `Literal`s, which is the control at
# the HTTP edge -- but this module is a governance boundary reached by three callers that
# are not that edge (`ProposalIntake` off a durable queue whose jsonb was written by an
# older build, a future admin/dashboard route, and any in-process caller), and pydantic
# validation is skippable in-process (`model_construct`). A proposal is Tier B content whose
# `mem_type` decides which scan schema check runs and which retrieval slot it can ever
# occupy; re-asserting the closed vocabulary here costs one comparison.
PROPOSABLE_MEM_TYPES: Final = frozenset({MemType.LESSON, MemType.SEMANTIC})
PROPOSABLE_SCOPE_TYPES: Final = frozenset({ScopeType.AGENT_TYPE, ScopeType.PROJECT_SHARED})


class NotProposable(ValueError):
    """A proposal naming a `mem_type`/`claimed_scope` outside PLAN.md §3's wire vocabulary.

    A `ValueError` subclass so `ProposalIntake` can tell it apart from a store failure: it is
    deterministic on the item's own bytes, so the item is acked, never retried."""


def _admitted[EnumT: StrEnum](
    enum_cls: type[EnumT], raw: str, admitted: frozenset[EnumT], *, field: str
) -> EnumT:
    """Parse `raw` into `enum_cls` and refuse anything outside `admitted`, as ONE refusal.

    An unrecognised value and a recognised-but-inadmissible one (`mem_type="preference"`)
    are the same kind of defect -- a proposal whose shape this service never promised to
    accept -- and both are deterministic on the item's own bytes. Letting the first escape as
    a bare `ValueError` would send it down `ProposalIntake`'s retry path to `dead_letter`
    while the second is acked immediately, which is an arbitrary difference in how two
    equally hopeless items are handled.
    """
    try:
        value = enum_cls(raw)
    except ValueError as exc:
        raise NotProposable(
            f"propose_memory refuses {field}={raw!r}: not a {enum_cls.__name__} value"
        ) from exc
    if value not in admitted:
        raise NotProposable(
            f"propose_memory refuses {field}={value.value!r}: PLAN.md §3 admits exactly "
            f"{sorted(member.value for member in admitted)}"
        )
    return value


def _estimate_token_count(content: str) -> int:
    """Mirrors `workers.distiller._estimate_tokens` / `workers.edit_ops
    ._estimate_token_count` exactly -- the same CONTRACT GAP applies (no canonical
    tokenizer exists anywhere in this codebase for `memory_item.token_count`)."""
    return max(1, len(content) // 4)


@dataclass(frozen=True, slots=True)
class ProposalAccepted:
    memory_id: MemoryId
    status: Status
    """Always `Status.QUARANTINED` (D-023) -- carried as a field, like every other
    transition-result dataclass in this codebase, rather than hard-coded at the call site."""


@dataclass(frozen=True, slots=True)
class ProposalDuplicate:
    """An identical proposal (same project, same run, same `content_hash`) already landed.

    Point 4 of the module docstring: the queue is at-least-once and a proposal envelope has
    no dedup key of its own, so this is the redelivery outcome. It is deliberately NOT a
    `ProposalAccepted`: no `Status` is reported, because this module did not compute one --
    the pre-existing row's status is whatever the state machine has since made it (a
    quarantine TTL may already have archived it), and inventing `QUARANTINED` here would be
    exactly the "plausible constant" a status must never be.
    """

    memory_id: MemoryId


@dataclass(frozen=True, slots=True)
class ProposalRefused:
    reason: str


ProposalOutcome = ProposalAccepted | ProposalDuplicate | ProposalRefused


@runtime_checkable
class AgentControlRepoPort(Protocol):
    """What `AgentControl` needs from a memory/registry store.

    `resolve_project` and `insert_memory_item` are `stores.pg.repo.Repo`'s real method
    signatures verbatim (zero adapter needed for those two); the two `count_*` methods are a
    CONTRACT GAP the module docstring records.
    """

    def resolve_project(self, principal_id: PrincipalId) -> ProjectScope:
        """Raises `ScopeResolutionFailed` for an unregistered principal -- identical to
        `adapters.ports.ProjectResolverPort`, which `Repo` already satisfies."""
        ...

    def insert_memory_item(
        self, project_id: ProjectId, item: NewMemoryItem, scan_verdict: ScanVerdict
    ) -> MemoryId: ...

    def count_proposals_in_run(self, project_id: ProjectId, run_id: RunId) -> int:
        """Count of already-landed `provenance.class='proposal'` rows whose
        `provenance.run_id` equals this run -- an indexed `(project_id, run_id)` count, never
        a trace scan (CONTRACT GAP: no such `Repo` query exists today)."""
        ...

    def count_proposals_in_project_day(self, project_id: ProjectId, day: date) -> int:
        """Count of already-landed `provenance.class='proposal'` rows created on this UTC
        calendar day -- an indexed `(project_id, DATE(created_at))` count (CONTRACT GAP: no
        such `Repo` query exists today). `day` is always `clock.now().date()` at the call
        site; this port never reads a clock itself."""
        ...

    def find_proposal_in_run(
        self, project_id: ProjectId, run_id: RunId, content_hash_hex: str
    ) -> MemoryId | None:
        """The already-landed `provenance.class='proposal'` row for this exact
        `(run, content_hash)`, or `None` -- the redelivery check (point 4 of the module
        docstring). `content_hash_hex` is `domain.canonical.content_hash`, byte-identical to
        what `Repo.insert_memory_item` stores in `memory_item.content_hash`, so the lookup
        is an equality match on a stored column and not a recomputation."""
        ...


@runtime_checkable
class DurableProposalCapPort(Protocol):
    """The OPTIONAL half of the store contract: check-and-insert as one database
    transaction, serialised across processes.

    Deliberately a separate Protocol from `AgentControlRepoPort` rather than a fourth method
    on it. `AgentControlRepoPort` is the minimum an in-memory fixture must implement to
    exercise every governance decision offline; this one can only be implemented by
    something with a real transaction. Splitting them means `AgentControl` can state which
    guarantee it is actually giving (`durable_caps`) instead of every caller assuming the
    stronger one. `stores.pg.repo.Repo` satisfies both.
    """

    def insert_proposal_within_caps(
        self,
        project_id: ProjectId,
        run_id: RunId,
        item: NewMemoryItem,
        scan_verdict: ScanVerdict,
        *,
        per_run_cap: int,
        per_project_daily_cap: int,
        day: date,
    ) -> ProposalInsertResult: ...


@runtime_checkable
class ConfigProvider(Protocol):
    """What `ProposalIntake` needs to resolve per-(project, agent_type) settings. Declared
    locally, the same shape `workers.prefix_builder.ConfigProvider` already declares for the
    identical reason: no import-time dependency on whatever `domain.config.ConfigResolver`
    itself depends on, which `ConfigResolver` satisfies structurally regardless."""

    def effective(
        self, project_id: ProjectId, agent_type_id: AgentTypeId | None = None
    ) -> EffectiveConfig: ...


def _from_insert_result(
    result: ProposalInsertResult, *, status: Status, run_id: RunId, day: date, cfg: EffectiveConfig
) -> ProposalOutcome:
    """Translate the store's transaction-authoritative verdict into this module's outcome
    vocabulary. Exhaustive over `ProposalCapOutcome` with no `else`: a member added to that
    enum without a branch here fails mypy's exhaustiveness check rather than silently
    falling through to "accepted"."""
    match result.outcome:
        case ProposalCapOutcome.INSERTED:
            if result.memory_id is None:  # pragma: no cover - store contract violation
                raise TracebedError("insert_proposal_within_caps reported INSERTED with no id")
            return ProposalAccepted(memory_id=result.memory_id, status=status)
        case ProposalCapOutcome.DUPLICATE:
            if result.memory_id is None:  # pragma: no cover - store contract violation
                raise TracebedError("insert_proposal_within_caps reported DUPLICATE with no id")
            return ProposalDuplicate(memory_id=result.memory_id)
        case ProposalCapOutcome.PER_RUN_CAP:
            return ProposalRefused(
                reason=(
                    f"proposals.per_run_cap ({cfg.proposals.per_run_cap}) reached for run "
                    f"{run_id}: {result.observed_count} already landed"
                )
            )
        case ProposalCapOutcome.PER_PROJECT_DAILY_CAP:
            return ProposalRefused(
                reason=(
                    f"proposals.per_project_daily_cap ({cfg.proposals.per_project_daily_cap}) "
                    f"reached for {day.isoformat()}: {result.observed_count} already landed"
                )
            )


class AgentControl:
    """`submit_proposal` is the pure, fully-offline-testable governance decision: given an
    already-authenticated `(project_id, run_id, principal_id, proposal)` and a resolved
    `EffectiveConfig`, land it quarantined or refuse it. `cfg` is a caller-supplied
    parameter, not something this class resolves itself -- the same convention every other
    worker in this codebase follows (`workers.edit_ops.EditOps`, `workers.sweeps`,
    `workers.promotion.PromotionWorker` all take `cfg: EffectiveConfig` per call), which is
    what makes a fixed `EffectiveConfig` enough to test every cap/state-machine interaction
    with no config store at all. `ProposalIntake` (below) is the thin queue-consuming layer
    that resolves `cfg` per envelope and calls this.
    """

    def __init__(self, repo: AgentControlRepoPort, clock: Clock) -> None:
        self._repo = repo
        self._clock = clock
        # Point 3 of the module docstring: the caps are a read-modify-write over durable
        # state, so checking them outside a critical section enforces nothing under the
        # concurrency `ProposalIntake` itself creates. One lock per instance rather than one
        # per project: proposals are capped at 50/project/day by construction, so the
        # serialisation this costs is bounded by the very control it protects.
        self._cap_lock = threading.Lock()

    @property
    def durable_caps(self) -> bool:
        """True iff the injected store can enforce the caps across PROCESSES, not merely
        across this process's threads (module docstring point 3). Exposed so an operator or
        a gate can read the guarantee off the wiring instead of inferring it from the store
        class -- the difference between the two is invisible in every sequential test and
        only appears under a second running consumer."""
        return isinstance(self._repo, DurableProposalCapPort)

    def submit_proposal(
        self,
        project_id: ProjectId,
        run_id: RunId,
        principal_id: PrincipalId,
        proposal: MemoryProposal,
        *,
        cfg: EffectiveConfig,
    ) -> ProposalOutcome:
        """PLAN.md §3 `POST /v1/propose_memory` / §5 row 2 (`None -> quarantined`), the
        `ProvenanceClass.PROPOSAL` half.

        Order, deliberately: (1) re-derive scope from the authenticated principal and refuse
        a mismatch (invariant 4 -- the same defensive re-check every other worker in this
        codebase performs on its own store reads); (2) re-assert PLAN.md §3's closed
        `mem_type`/`claimed_scope` vocabulary; (3) build and `validate_provenance` the
        provenance, so `evidence.provenance_complete` is a fact this method established
        rather than a literal it asserted (invariant 6); then, under `_cap_lock`:
        (4) the redelivery check; (5) the per-run cap; (6) the per-project-per-UTC-day cap --
        all three BEFORE the scan suite runs, so a proposal that is going to be refused for
        flooding never pays for the scan work either; (7) scan + `apply()` + insert,
        identically to `workers.distiller`'s own Tier B quarantined-insert shape.

        Steps 4-7 are one critical section because 4, 5 and 6 all read state that step 7
        writes (points 3 and 4 of the module docstring).
        """
        scope = self._repo.resolve_project(principal_id)
        if scope.project_id != project_id:
            raise TracebedError(
                f"resolve_project({principal_id}) resolved to project {scope.project_id}, "
                f"not the requested {project_id} (invariant 4)"
            )

        mem_type = _admitted(MemType, proposal.mem_type, PROPOSABLE_MEM_TYPES, field="mem_type")
        scope_type = _admitted(
            ScopeType, proposal.claimed_scope, PROPOSABLE_SCOPE_TYPES, field="claimed_scope"
        )
        # Server-derived, never caller-named: `MemoryProposal` has no agent_type field, and
        # this is the registry's own answer for the authenticated principal (invariant 4).
        scope_id: UUID | None = (
            scope.agent_type_id.value if scope_type is ScopeType.AGENT_TYPE else None
        )

        provenance = Provenance(cls=ProvenanceClass.PROPOSAL, run_id=run_id)
        validate_provenance(provenance)  # raises ProvenanceIncomplete -- invariant 6

        # One clock read for the whole submission: `today` and `evidence.now` must not be
        # able to land on opposite sides of UTC midnight.
        now = self._clock.now()
        today = now.date()
        digest = content_hash(proposal.content)

        with self._cap_lock:
            already = self._repo.find_proposal_in_run(project_id, run_id, digest)
            if already is not None:
                return ProposalDuplicate(memory_id=already)

            run_count = self._repo.count_proposals_in_run(project_id, run_id)
            if run_count >= cfg.proposals.per_run_cap:
                return ProposalRefused(
                    reason=(
                        f"proposals.per_run_cap ({cfg.proposals.per_run_cap}) reached for run "
                        f"{run_id}: {run_count} already landed"
                    )
                )

            day_count = self._repo.count_proposals_in_project_day(project_id, today)
            if day_count >= cfg.proposals.per_project_daily_cap:
                return ProposalRefused(
                    reason=(
                        f"proposals.per_project_daily_cap ({cfg.proposals.per_project_daily_cap}) "
                        f"reached for {today.isoformat()}: {day_count} already landed"
                    )
                )

            scan_ctx = ScanContext(
                project_id=project_id,
                mem_type=mem_type,
                trust_tier=TrustTier.B,
                provenance_class=ProvenanceClass.PROPOSAL,
                lane=Lane.QUALITY,
            )
            result = scan(proposal.content, context=scan_ctx)
            verdict = result.verdict(clock=self._clock)  # raises ScanRejected if not passed

            limits = TransitionLimits.from_config(cfg)
            evidence = TransitionEvidence(
                now=now,
                provenance_class=ProvenanceClass.PROPOSAL,
                trust_tier=TrustTier.B,
                mem_type=mem_type,
                scan_passed=result.passed,
                provenance_complete=True,  # established by validate_provenance() above
            )
            new_status = apply(None, Status.QUARANTINED, evidence, limits)

            item = NewMemoryItem(
                scope_type=scope_type,
                scope_id=scope_id,
                mem_type=mem_type,
                kind="proposal",
                lane=Lane.QUALITY,
                trust_tier=TrustTier.B,
                status=new_status,
                content=proposal.content,
                token_count=_estimate_token_count(proposal.content),
                provenance=provenance,
                subject_tag=proposal.subject_tag,
            )

            if isinstance(self._repo, DurableProposalCapPort):
                # The authoritative decision. Everything above this line -- including the
                # two counts -- was a pre-check that avoided paying for the scan suite on a
                # proposal that was already over cap. This re-does all three checks inside
                # one transaction under a project-scoped advisory lock, so a second process
                # counting concurrently cannot also land a row.
                return _from_insert_result(
                    self._repo.insert_proposal_within_caps(
                        project_id,
                        run_id,
                        item,
                        verdict,
                        per_run_cap=cfg.proposals.per_run_cap,
                        per_project_daily_cap=cfg.proposals.per_project_daily_cap,
                        day=today,
                    ),
                    status=new_status,
                    run_id=run_id,
                    day=today,
                    cfg=cfg,
                )

            memory_id = self._repo.insert_memory_item(project_id, item, verdict)

        return ProposalAccepted(memory_id=memory_id, status=new_status)


# --------------------------------------------------------------------------- #
# Queue consumer -- TOPIC_MEMORY_PROPOSAL, mirrors ingest.outcome_intake.OutcomeIntake's
# shape (claim/validate/act/ack-or-nack), folded into this chunk's own file list rather than
# a separate `ingest/proposal_intake.py` (outside this chunk's file list).
# --------------------------------------------------------------------------- #


class ProposalQueueEnvelope(BaseModel):
    """One `TOPIC_MEMORY_PROPOSAL` row's payload -- the exact shape
    `api.routes_v1._proposal_envelope` builds. `proposal` is the real `MemoryProposal` model,
    so a malformed proposal fails this same validation offline, with no HTTP layer involved
    (mirrors `ingest.outcome_intake._OutcomeQueueEnvelope`)."""

    model_config = ConfigDict(extra="forbid")

    project_id: UUID
    principal_id: UUID
    run_id: UUID
    proposal: MemoryProposal


class ProposalIntake:
    """Consumes `TOPIC_MEMORY_PROPOSAL` (stores.pg.queue: "enqueued Phase 0, consumed Phase
    4"). Claim, validate, resolve per-(project, agent_type) config, hand off to
    `AgentControl.submit_proposal`, ack.

    A refused item -- fails envelope validation, disagrees with the queue row about which
    tenant it belongs to, or makes `AgentControl.submit_proposal` raise (a store error) -- is
    `nack`'d with `compute_backoff(item.attempts)`, mirroring
    `ingest.outcome_intake.OutcomeIntake.run_once` exactly. `ScanRejected`, `NotProposable`,
    and a proposal `submit_proposal` REFUSES on its own authority (a cap reached) are all
    `ack`'d instead: none is a transient failure a retry could fix -- the scan verdict, the
    wire vocabulary, and the durable caps are each deterministic on the same input, so
    retrying the identical item only wastes a claim slot on a decision that will not change
    until the content changes or the next run/day.

    THE QUEUE ROW'S `project_id` IS THE SCOPING AUTHORITY (invariant 4), exactly as in
    `ingest.outcome_intake`: it was written server-side from `ProjectScope` by
    `api.routes_v1.propose_memory` and is the column the partition/RLS decision was already
    made against. The envelope must agree with it, the principal's registration must resolve
    to it, and it -- not the re-resolved scope -- is what is handed to `submit_proposal`.
    Passing `scope.project_id` there instead would make `submit_proposal`'s own invariant-4
    comparison compare a value with itself, which is a check that can never fail.
    """

    def __init__(
        self,
        queue: QueueConsumerPort,
        control: AgentControl,
        repo: AgentControlRepoPort,
        config_provider: ConfigProvider,
        *,
        batch_size: int = 100,
    ) -> None:
        self._queue = queue
        self._control = control
        self._repo = repo
        self._config_provider = config_provider
        self._batch_size = batch_size

    def run_once(self, max_batch: int | None = None) -> int:
        n = max_batch if max_batch is not None else self._batch_size
        items = self._queue.claim(TOPIC_MEMORY_PROPOSAL, n)
        return sum(1 for item in items if self._process_one(item))

    def run_forever(
        self,
        stop: threading.Event,
        *,
        poll_interval_s: float,
        max_iterations: int | None = None,
    ) -> None:
        """Polls `TOPIC_MEMORY_PROPOSAL` until `stop` is set. Mirrors
        `ingest.runner.ConsumerRunner.run_forever` deliberately, including `max_iterations`
        (so this method is finite and a test can drive it to completion) and `stop.wait()`
        rather than `time.sleep()` (so a shutdown request during an idle wait is honoured
        immediately, not after the full interval).

        `ProposalIntake` gets its own loop rather than being registered as a
        `workers.runner.BatchHandler` because `WorkerRunner` acks or nacks a whole batch on
        one handler outcome, while this consumer's whole ack/nack policy is PER ITEM: a
        scan rejection and a cap refusal are acked (deterministic on the item's own bytes --
        retrying wastes a claim slot on a decision that cannot change), a store error is
        nacked with backoff. Folding it into a batch handler would collapse those into one
        verdict for every item claimed in the same round, which turns one poisoned proposal
        into a retry storm for the innocent items beside it.
        """
        iterations = 0
        while not stop.is_set():
            processed = self.run_once()
            iterations += 1
            if max_iterations is not None and iterations >= max_iterations:
                return
            if processed == 0:
                stop.wait(poll_interval_s)

    def _process_one(self, item: QueueItem) -> bool:
        """Returns True iff the item was acked (successful terminal handling, including a
        deterministic refusal); False iff it was nacked for a retry."""
        try:
            envelope = ProposalQueueEnvelope.model_validate(dict(item.payload))
        except ValidationError:
            logger.warning("agent_control: refusing malformed proposal item %s", item.id)
            self._queue.nack(item.id, compute_backoff(item.attempts))
            return False

        if ProjectId(envelope.project_id) != item.project_id:
            # A payload-derived project_id must never decide which tenant's partition a row
            # lands in (invariant 4) -- mirrors outcome_intake's identical check.
            logger.warning(
                "agent_control: item %s envelope project_id disagrees with the queue row",
                item.id,
            )
            self._queue.nack(item.id, compute_backoff(item.attempts))
            return False

        principal_id = PrincipalId(envelope.principal_id)
        try:
            scope = self._repo.resolve_project(principal_id)
        except Exception:
            logger.exception("agent_control: cannot resolve scope for proposal item %s", item.id)
            self._queue.nack(item.id, compute_backoff(item.attempts))
            return False

        if scope.project_id != item.project_id:
            # The principal's registration no longer agrees with the tenant this row was
            # enqueued under. Landing the row in either project would be a scope decision
            # made by a disagreement (invariant 4) -- refuse, do not choose.
            logger.warning(
                "agent_control: item %s principal resolves to project %s, not the queue "
                "row's %s",
                item.id,
                scope.project_id,
                item.project_id,
            )
            self._queue.nack(item.id, compute_backoff(item.attempts))
            return False

        try:
            cfg = self._config_provider.effective(item.project_id, scope.agent_type_id)
            outcome = self._control.submit_proposal(
                item.project_id,
                RunId(envelope.run_id),
                principal_id,
                envelope.proposal,
                cfg=cfg,
            )
        except ScanRejected:
            logger.info("agent_control: proposal in item %s failed the scan suite", item.id)
            self._queue.ack(item.id)  # deterministic on this content -- not retryable
            return True
        except NotProposable:
            logger.warning(
                "agent_control: proposal in item %s is outside the wire vocabulary", item.id
            )
            self._queue.ack(item.id)  # deterministic on this content -- not retryable
            return True
        except Exception:
            logger.exception("agent_control: failed processing proposal item %s", item.id)
            self._queue.nack(item.id, compute_backoff(item.attempts))
            return False

        if isinstance(outcome, ProposalRefused):
            logger.info(
                "agent_control: proposal in item %s refused: %s", item.id, outcome.reason
            )
        elif isinstance(outcome, ProposalDuplicate):
            logger.info(
                "agent_control: item %s is a redelivery of memory %s; no second row written",
                item.id,
                outcome.memory_id,
            )
        self._queue.ack(item.id)
        return True
