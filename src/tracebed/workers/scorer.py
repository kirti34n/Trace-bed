"""The scorer (PLAN.md Â§2 invariant 8 â€” "the most-corrected piece in the plan").

THE rule, exactly:

    Q <- clamp01(Q + alpha * w * c * (r - Q))

`r` is outcome polarity in [0, 1] (positive=1.0, negative=0.0; a graded `r` is
reserved for correction diffs and is out of this chunk's scope). `w` is the
adapter trust weight from `scoring.adapter_weights`, SERVER-DERIVED from the
authenticated adapter class â€” it scales the *learning rate*, it is never the
reward. Feeding `w` in as the reward is the original spec bug the whole
formula exists to correct (DECISIONS D-011): starting from Q=0.5, a
*successful* downstream event (w=0.3) fed in as `r` gives `r - Q = -0.2` and
LOWERS the score â€” the update would punish success. `c` is the contribution
factor in {0, 0.5, 1.0} from `workers.contribution_judge`. `alpha` is
`scoring.alpha`. `w == 0` (and, in this implementation, `c == 0` â€” see
`compute_new_q`'s docstring) SHORT-CIRCUITS: nothing is computed beyond the
short-circuit check, nothing is written, nothing is mutated.

WHERE EACH INPUT IS ENFORCED, and why they are not all enforced in one place.
`r` and `c` are *semantic quantities read from the world* â€” an adapter's
polarity and a judge's rubric answer. An out-of-range value there is not a
fast update, it is a WRONG one, and `clamp01` would hide it perfectly: r=100
turns a single event into `Q + alpha*w*c*99.5`, which saturates at 1.0 and
pins any memory to a perfect score in one call. So `compute_new_q` refuses
them outright (`ScoringInputInvalid`) rather than clamping the damage.
`w` and `alpha` are *server configuration* (`scoring` is an
`OVERRIDABLE_SECTIONS` member, so a `project_config` row reaches both), and
they are refused rather than clamped for the same reason: each is a factor of
`alpha*w*c*(r-Q)`, so a NEGATIVE one inverts the update â€” a failing outcome
raises Q and a succeeding one lowers it â€” which is a silent memory-poisoning
primitive available from one config row, not a loud failure. `w` is refused at
`resolve_weight`, the only sanctioned producer of a `w`: outside `(0, 1]` it
resolves to 0.0 and the update short-circuits. `alpha` is refused inside
`compute_new_q` (`ScoringConfig.alpha` is already `gt=0, le=1` at the
pydantic layer, but the pure function is exported and a `model_construct`-ed
or non-pydantic config reaches it unvalidated â€” the same defence-in-depth
`DerivedStateWriter` keeps under D-075). `clamp01` stays as the last-ditch
bound for any value that reached the arithmetic another way.

This module also owns the one-update-per-memory-per-day cap
(`scoring.updates_per_memory_per_day`) and its tie-break (highest-w adapter
first, then earliest arrival, then the server-minted run_id, then event_id so
the order is TOTAL and a replay of the same batch picks the same winner), and
replay-idempotency via `event_id` â€” a replayed outcome event must never move Q
twice.

CONTRACT GAP (reported, not worked around): this chunk's file list is exactly
`workers/scorer.py`, `workers/contribution_judge.py`, `workers/epochs.py` â€”
not `stores/pg/repo.py`. Persisting current Q, the set of event_ids already
applied to a memory, how many updates a memory has received today, and the
actual write of a new Q value all require repository methods that do not
exist yet (`Repo` has no `get_memory_score_state`, no per-memory scored-event
ledger, no `update_memory_item` for a Q write â€” the same gap
`workers/novelty.py`'s docstring already names for a merge write). `ScorerRepoPort`
below is declared beside its consumer for exactly the reason `adapters/ports.py`
gives for `ConfigStorePort` (C-18): a future `Repo` satisfies it structurally.

CONTRACT GAP, second: the daily cap is read-then-write across two port calls,
so two `run_scorer_batch` invocations racing on one memory can each see an
unspent slot. `ScorerRepoPort.apply_q_update` therefore carries an atomicity
requirement in its own docstring; a repo that cannot honour it re-opens the
cap bypass, and no arrangement of calls in this module can close it from
outside a transaction.

CONTRACT GAP, third: `QUpdate.principal_id` exists so the state machine's
`validated -> retired` guard can count DISTINCT PRINCIPALS OVER SCORED UPDATES.
PLAN.md Â§5's transition table says "Q < 0.25 after >=4 scored uses **from >=K
distinct principals**" â€” the qualifier attaches to *scored uses*, while
`migrations/0002_partitioned.sql`'s own comment points the count at
`outcome_event`. Those differ: `outcome_event` also holds the `implicit`
(w=0) and cap-skipped events that never moved Q, so counting there lets two
principals who never influenced Q at all satisfy a floor that exists to stop
one attacker-controlled feedback source from retiring a memory alone (D-021).
Computing the count is whichever chunk owns retirement orchestration; this
module's job is to make the correct count *possible*, which is what stamping
the principal on the applied update does.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Protocol, runtime_checkable
from uuid import UUID

from tracebed.domain.clock import Clock
from tracebed.domain.config import ScoringConfig
from tracebed.domain.enums import AdapterClass
from tracebed.domain.errors import TracebedError
from tracebed.domain.ids import MemoryId, PrincipalId, ProjectId, RunId
from tracebed.workers.contribution_judge import ContributionVerdict
from tracebed.workers.epochs import ScoringEpoch, assert_same_epoch

__all__ = [
    "ContributionJudgePort",
    "QUpdate",
    "ScoreBatchResult",
    "ScorerRepoPort",
    "ScoringEvent",
    "ScoringInputInvalid",
    "clamp01",
    "compute_new_q",
    "resolve_weight",
    "run_scorer_batch",
    "select_daily_winner",
]


class ScoringInputInvalid(TracebedError):
    """An input to the Q update was outside the range invariant 8 defines for it.

    Raised, never clamped and never skipped, for the reason the module
    docstring gives: a clamp turns "this adapter is broken" into "this memory
    is now perfect", and a silent skip turns it into "this memory is never
    scored again" â€” both are indistinguishable from correct operation from
    the outside. The same choice `contribution_judge.JudgeResponseInvalid`
    makes for a malformed rubric answer.
    """


def clamp01(value: float) -> float:
    """Bounds `value` into `[0, 1]`.

    Refuses non-finite input rather than clamping it: a NaN or infinite Q is
    the scorer failing, not a value the [0, 1] interval can meaningfully
    absorb (the same reasoning `hotpath.abstention` already applies to a
    non-finite similarity signal â€” a clamp that silently accepted NaN would
    just move the corruption one hop downstream instead of surfacing it).
    Mathematically, a legally-configured update (`alpha`, `w`, `c` all in
    [0, 1]) can never leave [0, 1] in the first place â€” `Q_new` is a convex
    combination of `Q` and `r` whenever `alpha*w*c <= 1`. The clamp exists for
    the adversarial case: a value that reached the arithmetic without passing
    `resolve_weight`, or a `current_q` read back from a corrupted row.
    """
    if not math.isfinite(value):
        raise ValueError(f"Q update produced a non-finite value: {value!r}")
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return value


@dataclass(frozen=True, slots=True)
class ScoringEvent:
    """One outcome_event's worth of scoring input for ONE memory it touched
    (an event that reached several injected memories produces several of
    these â€” one per memory, since each has its own current Q and its own
    daily cap state).

    There is deliberately no `w` field, and no keyword this dataclass accepts
    could carry one through: `resolve_weight` below is the ONLY way to obtain
    a weight, and it always derives one from `adapter` plus the server's own
    `scoring.adapter_weights` config â€” never from anything a caller supplies
    on this object (invariant 8: "callers never supply weights").
    """

    event_id: UUID
    run_id: RunId
    memory_id: MemoryId
    adapter: AdapterClass
    r: float
    principal_id: PrincipalId
    arrived_at: datetime
    outcome_summary: str

    def __post_init__(self) -> None:
        # `arrived_at` orders the tie-break, so a naive value is not a cosmetic
        # problem: comparing a naive against an aware datetime raises TypeError
        # mid-sort, and Postgres would have reinterpreted it in the session
        # TimeZone on the way in besides (the exact hazard D-043 moved to the
        # wire for `occurred_at`). `outcome_event.arrived_at` is timestamptz,
        # so every honest producer already has an aware value.
        if self.arrived_at.tzinfo is None or self.arrived_at.utcoffset() is None:
            raise ScoringInputInvalid("ScoringEvent.arrived_at must be timezone-aware")
        # Refused at construction as well as in the formula: an event carrying
        # an impossible polarity should not survive long enough to be selected
        # as a daily-cap winner and thereby consume the day's only slot.
        _require_unit_interval("r", self.r)


def _require_unit_interval(name: str, value: float) -> None:
    """Every quantity invariant 8 defines as living in [0, 1], checked the same way.

    `not (0.0 <= value <= 1.0)` rather than two comparisons because that form
    also rejects NaN, for which every ordered comparison is False.
    """
    if not isinstance(value, int | float) or isinstance(value, bool):
        raise ScoringInputInvalid(f"{name} must be a real number, got {value!r}")
    if not (0.0 <= float(value) <= 1.0):
        raise ScoringInputInvalid(f"{name} must be in [0, 1], got {value!r}")


def _require_positive_rate(name: str, value: float) -> None:
    """A learning-rate factor: finite and strictly positive, no upper bound.

    Separate from `_require_unit_interval` because the two failure modes are
    not the same shape â€” see `compute_new_q` on why `alpha` is bounded below
    but not above.
    """
    if not isinstance(value, int | float) or isinstance(value, bool):
        raise ScoringInputInvalid(f"{name} must be a real number, got {value!r}")
    if not math.isfinite(value) or float(value) <= 0.0:
        raise ScoringInputInvalid(f"{name} must be finite and > 0, got {value!r}")


def resolve_weight(adapter: AdapterClass, adapter_weights: Mapping[str, float]) -> float:
    """`w`, derived from the AUTHENTICATED adapter class alone (invariant 8).

    Fail-closed. `adapters.feedback.base.resolve_weight` applies the IDENTICAL
    `(0, 1]` test and the two are pinned equal in both directions by
    `tests/phase3/test_feedback_adapters.py::test_this_packages_weight_resolver_agrees_with_the_real_scorers`,
    so neither can be loosened alone. (An earlier revision of this docstring
    claimed the two diverged and that the divergence was safe because the
    sibling "only records an `outcome_event`" â€” that was wrong on the second
    half: `base.resolve_weight`'s return value is passed as the `w=` keyword
    to `ScorerPort.record_outcome`, i.e. straight into a learning rate. It has
    since been tightened to match.)

    `ingest.outcome_intake` genuinely does still test `w > 0.0` only, and that
    one is not a divergence: it derives the `w_zero` BOOLEAN for the
    `outcome_event` row and never produces a numeric weight at all, so an
    out-of-range value cannot reach any arithmetic through it.

    Anything outside `(0, 1]` â€” absent from
    the map, zero, negative, NaN, or above 1 â€” resolves to `0.0`, i.e. the
    short-circuit, never a real weight:

    - absent / 0.0: the adapter class is not configured for scoring.
    - negative: `scoring` is an `OVERRIDABLE_SECTIONS` member, so a
      `project_config` row can set one. `alpha*w*c*(r-Q)` with `w < 0`
      INVERTS the update â€” a negative outcome raises Q and a positive one
      lowers it â€” which is a silent memory-poisoning primitive available from
      a config row, not a loud failure.
    - NaN: every comparison against it is False, so it fails the range test
      by the same expression rather than needing its own branch.
    - above 1.0: "more than fully trusted" has no meaning, and `alpha*w*c > 1`
      makes one event overshoot past `r` into the clamp â€” a single outcome
      that sets Q to 0 or 1 outright instead of moving it. Refusing to score
      under a misconfigured weight is recoverable; a saturated Q is not.
    """
    w = adapter_weights.get(adapter.value)
    if w is None or not (0.0 < w <= 1.0):
        return 0.0
    return w


def compute_new_q(
    *, current_q: float, r: float, w: float, c: float, alpha: float
) -> float | None:
    """THE rule (invariant 8, D-011): `Q <- clamp01(Q + alpha*w*c*(r-Q))`.

    RETURNS THE NEW Q, NOT A DELTA. It was called `compute_q_delta` until an
    audit pass noticed the name invites `q += compute_q_delta(...)`, which
    double-applies the update. Nothing was wrong at the single call site, but
    this is the one function in the codebase whose arithmetic the whole audit
    existed to correct, so it is the last place worth leaving an ambiguous name.

    Returns `None` â€” meaning "no update, caller must write nothing" â€” for
    both of the two conditions that make the update meaningless rather than
    merely small:

    - `w == 0.0`: the adapter class is untrusted for scoring (`implicit`, by
      default, and anything `resolve_weight` refused). This is the
      short-circuit invariant 8 names explicitly.
    - `c == 0.0`: the contribution judge found this memory had no bearing on
      the outcome. The formula's own arithmetic already makes this a
      mathematical no-op (`alpha*w*0*(r-Q) == 0`), but a "no-op update" that
      still bumps `scored_use_count`/`last_scored_at` would count an
      irrelevant memory as a scored use for retirement purposes â€” exactly
      the "every memory injected into a successful run is credited equally
      including the irrelevant ones" failure the contribution judge exists
      to prevent. Treating it as a full short-circuit (no row touched at
      all) is what makes that prevention actually land.

    `r`, `c` and `current_q` are range-checked, and `alpha` is required to be
    finite and strictly positive (see the module docstring for why here and
    not only at their producers). `w` is not range-checked here, because
    `resolve_weight` is its only sanctioned producer and refuses out-of-range
    values there â€” `clamp01` remains the backstop for a `w` that arrived some
    other way.

    `alpha` deliberately has no UPPER bound here even though
    `ScoringConfig.alpha` caps it at 1.0: an overshooting learning rate is
    what the clamp exists for and what the overshoot tests exercise, whereas a
    non-positive one is not a fast update but a broken or inverted one â€”
    `alpha <= 0` either freezes Q while still spending the memory's one daily
    slot, or flips the sign of every outcome the deployment ever records.
    """
    _require_unit_interval("r", r)
    _require_unit_interval("c", c)
    _require_unit_interval("current_q", current_q)
    _require_positive_rate("alpha", alpha)
    if w == 0.0 or c == 0.0:
        return None
    return clamp01(current_q + alpha * w * c * (r - current_q))


def select_daily_winner(
    candidates: Sequence[ScoringEvent], *, adapter_weights: Mapping[str, float]
) -> ScoringEvent | None:
    """Tie-break for the one-update-per-day cap (`scoring.updates_per_memory_per_day`):
    highest-w adapter first, then earliest arrival (DECISIONS D-011), then
    `run_id`, then `event_id`.

    The keys past the second are not decoration. D-011 names only two, and two
    are not a total order: two events from the same adapter class arriving in
    the same `arrived_at` (a `timestamptz DEFAULT now()` is identical for
    every row written in one transaction) would otherwise be separated only by
    the order the caller's query happened to return them in â€” so the SAME
    pending batch, replayed after a restart, could pick a different winner and
    write a different Q.

    THE ORDER OF THE LAST TWO KEYS IS THE POINT. `event_id` is the dedup key
    the SOURCE asserts (`adapters.feedback.base.require_event_id` refuses to
    mint one on the signal's behalf, precisely so replay dedup means
    something), which makes it caller-chosen: breaking ties on it alone hands
    an attacker a deterministic win over every honest event it ties with â€”
    submit `00000000-0000-...` and own that memory's daily slot whenever the
    weights and arrival instants collide, which is exactly the situation
    D-021's four-day memory-destruction walk needs. `run_id` is minted by the
    service at `/v1/retrieve` (PLAN.md Â§3: "minted by the service â€” credit
    assignment with zero host support") and is a time-ordered UUIDv7, so it
    cannot be chosen downward: an attacker would have to own an OLDER real
    run, which is the same thing "earliest arrival" already prefers. Ordering
    on it first demotes the one caller-controlled field to the last resort it
    should always have been, and `event_id` still closes the order for the
    genuinely indistinguishable case (two events from one run, one
    transaction).

    `None` for an empty input â€” there is nothing to pick a winner from.
    """
    if not candidates:
        return None

    def _key(event: ScoringEvent) -> tuple[float, datetime, bytes, bytes]:
        return (
            -resolve_weight(event.adapter, adapter_weights),
            event.arrived_at,
            event.run_id.value.bytes,
            event.event_id.bytes,
        )

    return min(candidates, key=_key)


@dataclass(frozen=True, slots=True)
class QUpdate:
    """One applied Q movement â€” what `ScorerRepoPort.apply_q_update` persists.

    `epoch_id` is carried on every update (invariant 7: "every Q update ...
    records scoring_epoch") even though no `memory_item` column exists yet to
    durably hold it (module docstring's contract_gap) â€” the value is correct
    the moment a repo owner adds the column.

    `principal_id` is the authenticated principal of the outcome event that
    moved Q, carried for the reason the module docstring's third contract gap
    gives: the retirement floor counts distinct principals over SCORED uses,
    and an update row is the only place that count can be taken without
    re-including events that never scored.
    """

    memory_id: MemoryId
    event_id: UUID
    principal_id: PrincipalId
    previous_q: float
    new_q: float
    contribution: float
    epoch_id: int
    scored_at: datetime


@dataclass(frozen=True, slots=True)
class ScoreBatchResult:
    """What happened to every candidate `ScoringEvent` handed to
    `run_scorer_batch` for one memory. Every DISTINCT event_id in `candidates`
    appears in exactly one of these four tuples (`run_scorer_batch` collapses
    a repeated event_id to its first occurrence before deciding anything, so a
    duplicated candidate cannot be both applied and skipped).

    THE TWO SKIP KINDS MEAN OPPOSITE THINGS TO THE ORCHESTRATOR, and confusing
    them starves the memory:

    - `skipped_cap` is RETRYABLE. The event lost today's tie-break or arrived
      after the slot was spent; a later day can still score it.
    - `skipped_short_circuit` is TERMINAL. Nothing about waiting changes an
      untrusted adapter class or a judged non-contribution. Re-submitting such
      an event is not merely wasteful: it is never recorded in the replay
      ledger (nothing was applied), so it stays "fresh" forever and wins the
      tie-break against every genuinely scoreable event for that memory on
      every subsequent tick â€” one irrelevant high-weight event silently
      blocking that memory from ever being scored again.
    """

    applied: tuple[QUpdate, ...] = field(default_factory=tuple)
    skipped_replay: tuple[UUID, ...] = field(default_factory=tuple)
    skipped_short_circuit: tuple[UUID, ...] = field(default_factory=tuple)
    skipped_cap: tuple[UUID, ...] = field(default_factory=tuple)


@runtime_checkable
class ScorerRepoPort(Protocol):
    """What the scorer needs from storage (module docstring's contract_gap).

    Every method is scoped by `project_id` (invariant 4) and by `memory_id`
    â€” there is no batch/multi-memory method here because `run_scorer_batch`
    itself operates on one memory's candidates at a time; a caller processing
    many memories calls it once per memory.
    """

    def current_q(self, project_id: ProjectId, memory_id: MemoryId) -> float:
        """The memory's current `q_value`, read fresh â€” never cached across
        calls, since a concurrent update elsewhere must be seen."""
        ...

    def applied_event_ids(
        self, project_id: ProjectId, memory_id: MemoryId
    ) -> AbstractSet[UUID]:
        """Every `event_id` that has EVER produced a Q update for this
        memory â€” the replay-idempotency ledger. Not day-scoped: an event
        replayed on a different calendar day than it was first applied must
        still not move Q twice."""
        ...

    def scored_updates_today(
        self, project_id: ProjectId, memory_id: MemoryId, day: date
    ) -> int:
        """How many Q updates this memory has already received on `day` â€”
        the daily-cap counter `run_scorer_batch` compares against
        `scoring.updates_per_memory_per_day`. `day` is a UTC calendar date
        (`Clock.now()` is documented UTC), so an implementation must bucket
        `scored_at` in UTC too or the cap is a different length than the
        scorer thinks."""
        ...

    def apply_q_update(self, project_id: ProjectId, update: QUpdate) -> None:
        """Persists `update` â€” the ONLY mutating call this port exposes.
        `run_scorer_batch` calls this at most once per invocation, and never
        at all on any short-circuited path.

        ATOMICITY REQUIREMENT (module docstring's second contract gap): the
        implementation must make this write conditional on the daily cap and
        the replay ledger it was checked against â€” an unconditional UPDATE
        lets two concurrent scorer ticks on one memory each observe an unspent
        slot and each apply, which is the one-update-per-day cap bypassed by
        concurrency rather than by any input. A conditional write (or the
        write and both reads inside one transaction with the row locked) is
        what closes it; nothing in this module can."""
        ...


@runtime_checkable
class ContributionJudgePort(Protocol):
    """What the scorer needs from `workers.contribution_judge` â€” judged at
    most once per `run_scorer_batch` call, for the daily cap's winner only
    (an LLM call for every losing candidate would be pure spend for a verdict
    that can never be applied)."""

    def judge(self, *, memory_content: str, outcome_summary: str) -> ContributionVerdict: ...


def run_scorer_batch(
    *,
    project_id: ProjectId,
    memory_id: MemoryId,
    memory_content: str,
    candidates: Sequence[ScoringEvent],
    repo: ScorerRepoPort,
    judge: ContributionJudgePort,
    config: ScoringConfig,
    epoch: ScoringEpoch,
    clock: Clock,
) -> ScoreBatchResult:
    """Applies invariant 8 to every pending `ScoringEvent` one memory received,
    honouring replay-idempotency, the daily cap, and its tie-break â€” in that
    order, so a replayed event never re-consumes a cap slot it already spent,
    and a memory already at its daily cap never gets a fresh contribution
    judgement (an LLM call) for events that cannot be applied regardless.

    Exactly one candidate â€” the tie-break winner among the events not already
    applied â€” is ever judged or scored per call. Every other fresh candidate
    lands in `skipped_cap`: it lost the tie-break, or the cap was already
    spent for today, either way it does not get its own attempt this tick (a
    future tick, on a future day, may still score it if it is re-submitted as
    a candidate and nothing else has claimed that day's slot). The one
    exception is the zero-weight path, where every fresh candidate is reported
    as short-circuited instead â€” see `ScoreBatchResult` for why the two skip
    kinds must not be conflated.

    Every candidate must belong to `memory_id`. A batch mixing memories is
    refused rather than scored, because the Q, the cap counter and the replay
    ledger are all read for `memory_id` while `r` and the judged contribution
    would come from an event about a different memory â€” a mis-grouped caller
    would silently write one memory's outcome onto another's score.
    """
    for event in candidates:
        if event.memory_id != memory_id:
            raise ScoringInputInvalid(
                f"candidate {event.event_id} belongs to memory {event.memory_id}, "
                f"not the batch's memory {memory_id}"
            )

    # ONE clock read for the whole tick. Two reads would let a batch that
    # straddles midnight check the cap against day D and stamp `scored_at`
    # into day D+1, so the store would bucket the update on a day the cap was
    # never checked for â€” a second update on D+1 would then be allowed.
    instant = clock.now()
    if instant.tzinfo is None or instant.utcoffset() is None:
        # `.astimezone()` on a naive value silently assumes the HOST's local
        # zone, so a naive clock would not fail â€” it would give this process a
        # different midnight than the next one, and the daily cap would have a
        # different length on every deployment host.
        raise ScoringInputInvalid("Clock.now() must return a timezone-aware instant")
    # `Clock.now()` is documented UTC, but `ScorerRepoPort.scored_updates_today`
    # buckets on a UTC calendar date and NOTHING here can check a host clock's
    # zone. Normalising both the cap key and the `scored_at` stamp through UTC
    # makes `update.scored_at.date() == today` an identity rather than a
    # coincidence: an aware +05:30 clock would otherwise check the cap against
    # its local date while the store buckets the stamp in UTC, giving the
    # memory two scoreable slots on every day boundary the offset straddles.
    now = instant.astimezone(UTC)
    today = now.date()

    applied_ids = repo.applied_event_ids(project_id, memory_id)
    seen: set[UUID] = set()
    replayed: list[UUID] = []
    fresh: list[ScoringEvent] = []
    for event in candidates:
        if event.event_id in seen:
            continue
        seen.add(event.event_id)
        if event.event_id in applied_ids:
            replayed.append(event.event_id)
        else:
            fresh.append(event)

    if repo.scored_updates_today(project_id, memory_id, today) >= config.updates_per_memory_per_day:
        return ScoreBatchResult(
            skipped_replay=tuple(replayed),
            skipped_cap=tuple(event.event_id for event in fresh),
        )

    winner = select_daily_winner(fresh, adapter_weights=config.adapter_weights)
    if winner is None:
        return ScoreBatchResult(skipped_replay=tuple(replayed))

    losers = tuple(event.event_id for event in fresh if event.event_id != winner.event_id)
    w = resolve_weight(winner.adapter, config.adapter_weights)

    if w == 0.0:
        # Short-circuit before the judge is even called: an untrusted adapter
        # class can never produce a Q movement, so spending an LLM call on
        # its contribution would answer a question nothing downstream needs.
        # EVERY fresh candidate is reported as short-circuited, not just the
        # winner: the winner holds the maximum weight by construction, so a
        # zero there means every candidate resolved to zero. Reporting the
        # losers as `skipped_cap` instead would tell a caller to retry them
        # tomorrow, forever, for a weight that can never become non-zero.
        return ScoreBatchResult(
            skipped_replay=tuple(replayed),
            skipped_short_circuit=tuple(event.event_id for event in fresh),
        )

    verdict = judge.judge(memory_content=memory_content, outcome_summary=winner.outcome_summary)
    assert_same_epoch(epoch, verdict)

    current_q = repo.current_q(project_id, memory_id)
    new_q = compute_new_q(
        current_q=current_q, r=winner.r, w=w, c=verdict.factor, alpha=config.alpha
    )

    if new_q is None:
        return ScoreBatchResult(
            skipped_replay=tuple(replayed),
            skipped_short_circuit=(winner.event_id,),
            skipped_cap=losers,
        )

    update = QUpdate(
        memory_id=memory_id,
        event_id=winner.event_id,
        principal_id=winner.principal_id,
        previous_q=current_q,
        new_q=new_q,
        contribution=verdict.factor,
        epoch_id=epoch.epoch_id,
        scored_at=now,
    )
    repo.apply_q_update(project_id, update)
    return ScoreBatchResult(
        applied=(update,), skipped_replay=tuple(replayed), skipped_cap=losers
    )
