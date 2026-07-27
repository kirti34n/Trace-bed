"""The one memory state machine (PHASE-0 Task 4; PLAN.md §5; invariant 7).

Nothing content-derived is retrievable until it exits `quarantined` through this
module's transition table. There is no other way for a `memory_item.status`
to change anywhere in the codebase -- `apply()` is the sole entry point, and it
is a pure function of (current status, target status, evidence, limits). Guards
never read a clock, never read config, and never talk to a store: everything
they need arrives frozen in `TransitionEvidence` / `TransitionLimits`, which is
what makes every legal and illegal edge table-driven and exhaustively testable
(PHASE-0.md Task 4's own test list).

Contract: docs/PHASE0-CONTRACT.md §3.9 (binding; this file implements it, with
three deliberate tightenings that are documented at their definition sites and
reported as contract addenda: the transition table is exposed read-only,
`TransitionLimits` refuses invariant-violating thresholds, and
`independent_confirmations` is bounded rather than unbounded-exponential).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from tracebed.domain.enums import MemType, ProvenanceClass, TrustTier
from tracebed.domain.errors import ConfigError, GuardNotSatisfied, IllegalTransition
from tracebed.domain.ids import PrincipalId, RunId
from tracebed.domain.signatures import SIG_HASH_LEN, same_cluster

if TYPE_CHECKING:
    # Only needed for the `TransitionLimits.from_config` annotation; guards
    # themselves never import config (they read the frozen TransitionLimits
    # snapshot instead -- see the module docstring).
    from tracebed.domain.config import EffectiveConfig


__all__ = [
    "LEGAL_CREATION_STATUSES",
    "MAX_CONFIRMATIONS_CONSIDERED",
    "RETRIEVABLE_STATUSES",
    "SHADOW_CONFIRM_MIN_INDEPENDENT",
    "STALE_RETIRE_STRIKE_THRESHOLD",
    "TRANSITIONS",
    "Guard",
    "GuardOutcome",
    "ShadowConfirmation",
    "Status",
    "TransitionEvidence",
    "TransitionLimits",
    "apply",
    "assert_legal_creation_status",
    "independent_confirmations",
]


class Status(StrEnum):
    """Every legal `memory_item.status` value (PLAN.md §5's one enum, D-013).

    `Trace`/`Extracted` are not memory states (transient/trace rows); Tier A/B
    live in the separate, immutable `trust_tier` column, never in `Status`.
    """

    QUARANTINED = "quarantined"
    CANDIDATE = "candidate"
    VALIDATED = "validated"
    SUPERSEDED = "superseded"
    STALE = "stale"
    RETIRED = "retired"
    ARCHIVED = "archived"
    PINNED = "pinned"
    TOMBSTONED = "tombstoned"


RETRIEVABLE_STATUSES: Final = frozenset({Status.VALIDATED, Status.CANDIDATE, Status.PINNED})
# candidate: Tier A only, capped 1/run, labeled lower-trust (enforced in hotpath/, Phase 1).
# pinned: static-prefix placement only (enforced in the prefix builder, Phase 2).
# Nothing else is ever retrievable -- this is invariant 7's retrieval-side half.

# D-020's "shadow confirmation" number: >=2 distinct runs from distinct principals
# AND distinct input-signature clusters. Not a config field -- PLAN.md §5 states it
# as a fixed count next to (not instead of) the configurable failure-lesson count.
SHADOW_CONFIRM_MIN_INDEPENDENT: Final = 2

# PLAN.md §5: "stale -> retired | second strike". Fixed, like the shadow-confirm
# count above -- there is no `retirement.stale_strike_count` config field.
STALE_RETIRE_STRIKE_THRESHOLD: Final = 2

# Independence is a maximum-clique problem (below), which is NP-hard. The two
# constants below make it bounded rather than unbounded, because the size of a
# confirmation set is attacker-influenced: any principal that can submit runs
# adds nodes to the graph. Both bounds can only ever make the computed
# independence SMALLER, never larger, so exhausting them refuses a promotion --
# it can never grant one (see `independent_confirmations`).
MAX_CONFIRMATIONS_CONSIDERED: Final = 256
_MAX_CLIQUE_SEARCH_STEPS: Final = 50_000


@dataclass(frozen=True, slots=True)
class ShadowConfirmation:
    """One candidate corroborating observation for `quarantined -> candidate`.

    D-020: independence is computable only because all three fields below
    exist -- `run_id` alone (the spec's original shape) makes "two calls" and
    "two independent confirmations" indistinguishable, which is exactly the
    Sybil bypass invariant 7's test exists to close.
    """

    run_id: RunId
    principal_id: PrincipalId
    input_signature_hash: bytes  # exactly SIG_HASH_LEN bytes (domain/signatures.py)

    def __post_init__(self) -> None:
        """Reject a malformed signature at construction, not mid-guard.

        `signatures.same_cluster` raises `ValueError` on a wrong-length
        signature. Without this check that `ValueError` escapes `apply()` as a
        non-`TracebedError`, so a caller's uniform "guard refused" handling
        would not catch it and a malformed row would crash the shadow
        validator instead of merely failing to corroborate (invariant 7:
        deficient evidence refuses, it does not explode).
        """
        if len(self.input_signature_hash) != SIG_HASH_LEN:
            raise ValueError(
                f"input_signature_hash must be {SIG_HASH_LEN} bytes, "
                f"got {len(self.input_signature_hash)}"
            )


@dataclass(frozen=True, slots=True)
class TransitionLimits:
    """Threshold snapshot so the machine never reads config or DB (contract §3.9).

    Built once per evaluation via `from_config`; guards only ever see this
    frozen value, which is what keeps `apply()` reproducible from its four
    arguments alone -- no hidden config lookup can make the same call disagree
    with itself between two invocations.
    """

    quarantine_ttl_days: int
    candidate_ttl_days: int
    promote_min_outcomes: int
    failure_lesson_outcomes: int
    promotion_min_distinct_principals: int
    retire_q_threshold: float
    retire_min_scored_uses: int
    retire_min_distinct_principals: int
    archive_floor: float

    def __post_init__(self) -> None:
        """Refuse thresholds that would make the machine a bypass of itself.

        Invariant 7 ends "No admin bypass in code" and PLAN.md §10 forbids
        changing a status outside the machine. Every threshold below arrives
        from `EffectiveConfig`, and §3.4/C-03 makes the `promotion`,
        `retirement`, and `lifecycle` sections overridable per project through
        `project_config` dotted keys -- none of which carry a lower bound in
        `domain/config.py`. Without these floors, `UPDATE project_config SET
        value='0' WHERE key='promotion.failure_lesson_outcomes'` promotes
        quarantined content with ZERO corroboration: an admin bypass reached
        through configuration rather than through code, which is the same
        hole wearing a different hat. A threshold below its floor is a hard
        `ConfigError`, never a silent clamp -- operating with the invariant
        disabled is worse than refusing to operate.

        Each floor is a value PLAN.md states literally, not a value this
        module invents:
        - `>=2 distinct principals` for promotion (PLAN.md §5 row 6);
        - `1 run for failure lessons` (PLAN.md §5 row 4, invariant 7);
        - K >= 2 for retirement -- D-021's whole finding is that ONE
          attacker-controlled feedback source must not be able to retire a
          memory, so K=1 restores the memory-destruction primitive verbatim;
        - a TTL of 0 days makes `now - status_changed_at >= 0` true for every
          row, mass-archiving a project's entire quarantine in one sweep.
        """
        floors: tuple[tuple[str, int, int], ...] = (
            ("quarantine_ttl_days", self.quarantine_ttl_days, 1),
            ("candidate_ttl_days", self.candidate_ttl_days, 1),
            ("promote_min_outcomes", self.promote_min_outcomes, 1),
            ("failure_lesson_outcomes", self.failure_lesson_outcomes, 1),
            (
                "promotion_min_distinct_principals",
                self.promotion_min_distinct_principals,
                SHADOW_CONFIRM_MIN_INDEPENDENT,
            ),
            ("retire_min_scored_uses", self.retire_min_scored_uses, 1),
            ("retire_min_distinct_principals", self.retire_min_distinct_principals, 2),
        )
        for name, value, floor in floors:
            if value < floor:
                raise ConfigError(
                    f"TransitionLimits.{name}={value} is below the invariant-7 floor of "
                    f"{floor}; a config override cannot weaken the state machine below "
                    f"what PLAN.md §5 states"
                )
        for name, fvalue in (
            ("retire_q_threshold", self.retire_q_threshold),
            ("archive_floor", self.archive_floor),
        ):
            if not 0.0 <= fvalue <= 1.0:
                raise ConfigError(
                    f"TransitionLimits.{name}={fvalue} is outside [0.0, 1.0]; "
                    f"q_value and the decay floor are both clamped probabilities"
                )

    @classmethod
    def from_config(cls, cfg: EffectiveConfig) -> TransitionLimits:
        """Project the overridable config sections the guards below actually read.

        (invariant 7 / PLAN.md §6: every threshold a guard uses is a config
        field, never a literal buried in guard logic -- the two counts that
        *are* literals, `SHADOW_CONFIRM_MIN_INDEPENDENT` and
        `STALE_RETIRE_STRIKE_THRESHOLD`, are the ones PLAN.md §5 states as
        fixed numbers rather than as entries in the §6 config table.)

        Raises `ConfigError` (via `__post_init__`) if any projected threshold
        is below its invariant floor.
        """
        return cls(
            quarantine_ttl_days=cfg.lifecycle.quarantine_ttl_days,
            candidate_ttl_days=cfg.lifecycle.candidate_ttl_days,
            promote_min_outcomes=cfg.promotion.min_outcomes,
            failure_lesson_outcomes=cfg.promotion.failure_lesson_outcomes,
            promotion_min_distinct_principals=cfg.promotion.min_distinct_principals,
            retire_q_threshold=cfg.retirement.q_threshold,
            retire_min_scored_uses=cfg.retirement.min_scored_uses,
            retire_min_distinct_principals=cfg.retirement.min_distinct_principals,
            archive_floor=cfg.lifecycle.archive_floor,
        )


@dataclass(frozen=True, slots=True)
class TransitionEvidence:
    """Every field a guard in the PLAN.md §5 table may inspect (contract §3.9).

    Guards read only their own fields and reject on absence -- a field a
    caller forgot to populate must never read as a silent pass. `now` comes
    from a `Clock` at the call site; no guard here ever calls one, which is
    what makes TTL guards testable with a `FakeClock` instead of real time.
    """

    now: datetime
    provenance_class: ProvenanceClass
    trust_tier: TrustTier
    mem_type: MemType
    is_failure_lesson: bool = False
    scan_passed: bool = False
    scan_repass: bool = False
    provenance_complete: bool = False
    status_changed_at: datetime | None = None
    # quarantined -> candidate
    confirmations: tuple[ShadowConfirmation, ...] = ()
    has_verified_human_verdict: bool = False
    """UNCONSULTED by any guard as of D-133, and it must STAY that way until an audited
    operator route exists: `workers.shadow_validator.evaluate_one` derives this flag from a
    row's STORED `provenance.cls`/`verdict_id`, and the insert door accepts that provenance on
    a `quarantined` row without running any creation guard (D-137, and
    `_guard_quarantined_to_candidate`'s docstring). Any guard that starts reading this field
    therefore re-opens a zero-corroboration exit from quarantine.
    `tests/phase3/test_human_verdict_route.py::
    test_no_guard_in_the_table_consults_the_human_verdict_flag` sweeps every edge in
    `TRANSITIONS` to keep that true.
    Kept as a field, not deleted, solely because `workers.shadow_validator.evaluate_one` still
    constructs a `TransitionEvidence` with this keyword on every call; deleting the field would
    require editing that module, which is outside this chunk's file list."""
    # candidate -> validated
    promotion_outcomes: int = 0
    promotion_distinct_principals: int = 0
    outcome_consistent: bool = False
    open_contradiction: bool = False
    # contradiction / supersession
    contradiction_equal_or_stronger: bool = False  # validated -> superseded
    contradiction_weaker_provenance: bool = False  # candidate -> quarantined
    scan_reflag: bool = False
    # staleness / retirement / decay
    invalidation_event: bool = False
    ttl_class_expired: bool = False
    revalidation_failed: bool = False
    reverified: bool = False
    strike_count: int = 0
    q_value: float = 0.0
    scored_use_count: int = 0
    distinct_scoring_principals: int = 0
    decay_floor_reached: bool = False
    # operator / erasure
    operator_restore: bool = False
    operator_created: bool = False  # empty -> pinned
    erasure_or_approved_delete: bool = False

    def __post_init__(self) -> None:
        """Reject timezone-naive datetimes: the TTL guards cannot survive them.

        Two distinct failures the contract's bare `datetime` annotation lets
        through. (a) One naive and one aware value makes `now -
        status_changed_at` raise `TypeError` out of `apply()` -- an untyped
        crash where a `GuardNotSatisfied` was the contract. (b) BOTH naive is
        worse, because it silently succeeds: a `status_changed_at` read back
        as a local-time-naive value and compared against a UTC `Clock` shifts
        every TTL by the deployment's UTC offset (+05:30 here), so quarantine
        expiry drifts by hours with nothing to indicate it. Every timestamp in
        this system is tz-aware by construction (`Clock.now()`, `timestamptz`
        columns, §3.5's event validator); anything else is a caller bug that
        must surface at construction, not as skewed governance decisions.
        """
        for name, value in (("now", self.now), ("status_changed_at", self.status_changed_at)):
            if value is None:
                continue
            if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
                raise ValueError(
                    f"TransitionEvidence.{name} must be timezone-aware; got a naive datetime"
                )


@dataclass(frozen=True, slots=True)
class GuardOutcome:
    """A guard's verdict. `reason` becomes `GuardNotSatisfied.reason` on failure.

    CONTRACT GAP (reported, not deviated from): the chunk task description
    that spawned this file asked for `GuardOutcome(ok, reason, route_to_review)`
    and a `GuardNotSatisfied` that "carries route_to_review". Contract §3.9
    defines `GuardOutcome` as exactly `(ok, reason)` and §3.1's
    `GuardNotSatisfied.__init__` takes exactly `(current, target, reason)` --
    no `route_to_review` field exists on either. The contract wins (per this
    task's own instructions): implemented with no `route_to_review` field.
    PLAN.md §5 itself resolves the `validated -> retired` "otherwise ->
    review_queue" branch the same way: "The caller's job (Phase 3 workers) --
    the machine only refuses." A caller that wants to distinguish "route to
    review" from "just illegal/deficient" has only `GuardNotSatisfied.reason`
    (a string) to key off of in Phase 0/3; see contract_gaps in this chunk's
    report.
    """

    ok: bool
    reason: str


Guard = Callable[[TransitionEvidence, TransitionLimits], GuardOutcome]


def _compatibility_graph(confirmations: Sequence[ShadowConfirmation]) -> list[int]:
    """Adjacency bitmasks over "these two corroborate each other independently".

    Two confirmations are compatible iff they share NO run, NO principal, and
    NO input-signature cluster. All three matter (PLAN.md §5 row 4 / D-020):
    ">=2 distinct runs, distinct principals AND distinct input-signature
    clusters". Dropping the run check would let one run that somehow appears
    twice in a confirmation set count as its own corroboration, which is
    precisely the "two calls == two confirmations" degradation D-020 exists to
    kill; the cluster check is what stops the same wording resubmitted under a
    second identity.
    """
    n = len(confirmations)
    adjacency = [0] * n
    for i in range(n):
        a = confirmations[i]
        for j in range(i + 1, n):
            b = confirmations[j]
            if a.run_id == b.run_id:
                continue
            if a.principal_id == b.principal_id:
                continue
            if same_cluster(a.input_signature_hash, b.input_signature_hash):
                continue
            adjacency[i] |= 1 << j
            adjacency[j] |= 1 << i
    return adjacency


def independent_confirmations(
    confirmations: Sequence[ShadowConfirmation], *, at_least: int | None = None
) -> int:
    """Size of the largest mutually-independent subset of `confirmations`.

    Independence is D-020's computable definition -- pairwise-distinct runs,
    principals, and input-signature clusters -- so the answer is a maximum
    clique of `_compatibility_graph`, not a count of distinct principals or
    distinct clusters (GovMem measured naive counting at a 0.597 false
    promotion rate; a naive count over {p1/clusterA, p2/clusterB, p3/clusterA}
    says 3 when the truthful answer is 2).

    Maximum clique is NP-hard and the input is attacker-influenced -- every
    principal that can submit a run adds a node -- so this search is bounded
    three ways rather than left to run to completion:

    1. Only the first `MAX_CONFIRMATIONS_CONSIDERED` confirmations are read,
       bounding the O(n^2) graph build against an unbounded input.
    2. `at_least` stops the search the moment the answer is known to clear a
       threshold. Callers comparing with `>=` (every guard here does) get the
       same decision for a fraction of the work.
    3. A hard step budget stops a pathological graph. On exhaustion the best
       clique found so far is returned.

    All three bounds can only make the result SMALLER than the true maximum,
    which is the only safe direction: under-reporting independence refuses a
    promotion, it can never grant one. The result is exact whenever the search
    completes without hitting the step budget and without an `at_least`
    early exit.

    Contract note: §3.9 specifies `independent_confirmations(confirmations)`.
    `at_least` is keyword-only with a default, so every contract-shaped call
    still type-checks and still returns the exact maximum.
    """
    considered = confirmations[:MAX_CONFIRMATIONS_CONSIDERED]
    n = len(considered)
    if n == 0:
        return 0

    adjacency = _compatibility_graph(considered)
    # `n` as the target means "no early exit": the search runs to completion
    # unless it finds a clique containing every node.
    target = n if at_least is None else min(at_least, n)

    best = 0
    steps = 0

    def expand(size: int, candidates: int, excluded: int) -> bool:
        """Bron-Kerbosch with pivoting. Returns True to abort the whole search.

        Pivoting is load-bearing, not a micro-optimisation: the unpivoted
        recursion is O(2^n) even on a graph of entirely independent
        confirmations, so a memory that accumulated ~30 genuine corroborations
        would wedge the shadow validator for minutes and ~50 for years.
        """
        nonlocal best, steps
        if candidates == 0 and excluded == 0:
            best = max(best, size)
            return best >= target
        steps += 1
        if steps > _MAX_CLIQUE_SEARCH_STEPS:
            return True
        if size + candidates.bit_count() <= best:
            return False  # cannot beat the incumbent even taking every candidate

        pivot = -1
        pivot_degree = -1
        remaining = candidates | excluded
        while remaining:
            low = remaining & -remaining
            vertex = low.bit_length() - 1
            remaining ^= low
            degree = (candidates & adjacency[vertex]).bit_count()
            if degree > pivot_degree:
                pivot_degree = degree
                pivot = vertex

        branch = candidates & ~adjacency[pivot] if pivot >= 0 else candidates
        while branch:
            low = branch & -branch
            vertex = low.bit_length() - 1
            branch ^= low
            if expand(size + 1, candidates & adjacency[vertex], excluded & adjacency[vertex]):
                return True
            candidates ^= low
            excluded |= low
        return False

    expand(0, (1 << n) - 1, 0)
    return best


# --------------------------------------------------------------------------- #
# Guards -- one per legal (from, to) edge in PLAN.md §5's table. Each is a pure
# function of (evidence, limits); none of them raise -- `apply()` is the only
# place a table miss or a failed guard becomes an exception, per contract §3.9.
# --------------------------------------------------------------------------- #


def _guard_none_to_candidate(
    evidence: TransitionEvidence, limits: TransitionLimits
) -> GuardOutcome:
    """PLAN §5 row 1: Tier A parser output, scan pass, provenance complete."""
    if evidence.trust_tier is not TrustTier.A:
        return GuardOutcome(False, "trust_tier must be A for a direct-to-candidate insert")
    if evidence.provenance_class is not ProvenanceClass.PARSER:
        return GuardOutcome(
            False, "provenance_class must be parser for a direct-to-candidate insert"
        )
    if not evidence.scan_passed:
        return GuardOutcome(False, "scan did not pass")
    if not evidence.provenance_complete:
        return GuardOutcome(False, "provenance incomplete")
    return GuardOutcome(True, "")


def _guard_none_to_quarantined(
    evidence: TransitionEvidence, limits: TransitionLimits
) -> GuardOutcome:
    """PLAN §5 row 2: Tier B (distiller or proposal), scan pass, provenance complete."""
    if evidence.trust_tier is not TrustTier.B:
        return GuardOutcome(False, "trust_tier must be B for a quarantined insert")
    if evidence.provenance_class not in (ProvenanceClass.DISTILLER, ProvenanceClass.PROPOSAL):
        return GuardOutcome(
            False, "provenance_class must be distiller or proposal for a quarantined insert"
        )
    if not evidence.scan_passed:
        return GuardOutcome(False, "scan did not pass")
    if not evidence.provenance_complete:
        return GuardOutcome(False, "provenance incomplete")
    return GuardOutcome(True, "")


def _guard_none_to_pinned(evidence: TransitionEvidence, limits: TransitionLimits) -> GuardOutcome:
    """PLAN §5 row 3: operator-created preference (D-014's ungoverned status)."""
    if evidence.provenance_class is not ProvenanceClass.OPERATOR:
        return GuardOutcome(False, "provenance_class must be operator to create a pinned row")
    if not evidence.operator_created:
        return GuardOutcome(False, "operator_created not set")
    if evidence.mem_type is not MemType.PREFERENCE:
        return GuardOutcome(False, "pinned rows are preferences only")
    return GuardOutcome(True, "")


def _guard_quarantined_to_candidate(
    evidence: TransitionEvidence, limits: TransitionLimits
) -> GuardOutcome:
    """PLAN §5 row 4 / D-020 / D-023 / D-133 -- invariant 7's load-bearing guard.

    D-023 is checked first and unconditionally: `propose_memory` proposals are
    a provenance class that can never satisfy the corroboration skip, full
    stop -- not a config flag, not overridable by any amount of corroborating
    evidence.

    D-133/D-137: PLAN.md §5 row 4 names a SECOND skip, "OR verified-human-
    verdict provenance", and this guard used to grant it -- an UNCONDITIONAL
    `candidate`, zero corroboration -- whenever `evidence
    .has_verified_human_verdict` was set together with `provenance_class is
    ProvenanceClass.HUMAN_VERDICT`. The clause is removed.

    D-137 corrects D-133's stated reason, which was wrong in the direction
    that matters. D-133 (following BMAD finding B28 and fidelity-audit S26)
    justified the removal as dead-code cleanup: no `∅ -> quarantined` edge in
    the table below admits `HUMAN_VERDICT` provenance, and no transition
    rewrites a row's stored class, so "no row this system can produce" could
    satisfy it. The first two facts are true and the conclusion does not
    follow, because `apply()` is not the only door into `memory_item`.
    `Repo.insert_memory_item` runs `assert_legal_creation_status(status)`
    (membership in `LEGAL_CREATION_STATUSES` -- `quarantined` is a member) and
    `validate_provenance` (`HUMAN_VERDICT` requires a `verdict_id` and nothing
    else); it does NOT call `apply(None, status, evidence, limits)`, so
    `_guard_none_to_quarantined`'s class restriction is enforced only on
    callers that voluntarily route through this module first. A `quarantined`
    row carrying `HUMAN_VERDICT` provenance and a `verdict_id` is therefore
    insertable, `workers.shadow_validator.evaluate_one` derives
    `has_verified_human_verdict` straight off that stored provenance, and this
    guard used to return `candidate` for it with no corroboration at all.
    The removed clause was a REACHABLE invariant-7 bypass whose only remaining
    barrier was that no shipped writer happens to construct that provenance --
    convention, not mechanism. `tests/phase3/test_human_verdict_route.py`
    section 2b pins the asymmetry (this guard refuses the combination; the
    insert door accepts it), so the reasoning cannot silently rot back.

    Restoring the route for real needs a genuinely new capability this module
    cannot provide alone: a repository write path that can promote an EXISTING
    row's stored provenance to `HUMAN_VERDICT` (`stores/pg/lifecycle.py`'s
    `LifecycleWriter` writes `status` only, by design --
    `tests/phase1/test_learning_repos.py::
    test_exactly_one_status_writing_statement_exists_in_the_lifecycle_module`
    pins that to exactly one statement in `stores/pg/`), plus an explicit,
    audited operator action (an `api/admin.py` route backed by a
    `workers/edit_ops.py`-shaped write) that performs that promotion as its
    own logged event -- and, per PLAN.md §10, that route must itself be a
    state-machine transition carrying provenance, never an admin bypass around
    one. Building it is out of this chunk's file list (`repo.py`
    /`state_machine.py` only); until it exists, quarantined content leaves
    quarantine through shadow corroboration ONLY, and `PLAN.md` §5 row 4's
    "OR verified-human-verdict provenance" clause documents a route this build
    does not implement (contract_gap, not a code deviation -- `PLAN.md` is
    outside this chunk's file list).

    The failure-lesson relaxation is gated on `mem_type` as well as on the
    flag. PLAN.md §5 and invariant 7 both say "1 run for failure lessons", and
    a lesson is `mem_type == LESSON`; without the type check, setting
    `is_failure_lesson` on a semantic memory halves the corroboration
    requirement for content that is not a lesson at all -- a one-boolean
    downgrade of the quarantine threshold on the exact class of content
    quarantine exists to hold.
    """
    if evidence.provenance_class is ProvenanceClass.PROPOSAL:
        return GuardOutcome(
            False, "proposal provenance class can never exit quarantine via any skip (D-023)"
        )

    if evidence.is_failure_lesson and evidence.mem_type is MemType.LESSON:
        required = limits.failure_lesson_outcomes
    else:
        required = SHADOW_CONFIRM_MIN_INDEPENDENT
    independent = independent_confirmations(evidence.confirmations, at_least=required)
    if independent >= required:
        return GuardOutcome(True, "")
    return GuardOutcome(
        False,
        f"only {independent} independent confirmation(s) (distinct run, distinct principal AND "
        f"distinct input-signature cluster); need >= {required} -- there is no verified-human-"
        f"verdict skip in this build (D-133); quarantined content exits only via shadow "
        f"corroboration",
    )


def _guard_quarantined_to_archived(
    evidence: TransitionEvidence, limits: TransitionLimits
) -> GuardOutcome:
    """PLAN §5 row 5: quarantine TTL (default 30d) expired."""
    return _guard_ttl_expired(evidence, limits.quarantine_ttl_days, "quarantine")


def _guard_candidate_to_validated(
    evidence: TransitionEvidence, limits: TransitionLimits
) -> GuardOutcome:
    """PLAN §5 row 6: promotion predicate."""
    if evidence.promotion_outcomes < limits.promote_min_outcomes:
        return GuardOutcome(
            False,
            f"promotion_outcomes {evidence.promotion_outcomes} < required "
            f"{limits.promote_min_outcomes}",
        )
    if evidence.promotion_distinct_principals < limits.promotion_min_distinct_principals:
        return GuardOutcome(
            False,
            f"promotion_distinct_principals {evidence.promotion_distinct_principals} < required "
            f"{limits.promotion_min_distinct_principals}",
        )
    if not evidence.outcome_consistent:
        return GuardOutcome(False, "outcomes are not consistent")
    if not evidence.scan_repass:
        return GuardOutcome(False, "scan re-pass missing")
    if evidence.open_contradiction:
        return GuardOutcome(False, "an open contradiction blocks promotion")
    return GuardOutcome(True, "")


def _guard_candidate_to_quarantined(
    evidence: TransitionEvidence, limits: TransitionLimits
) -> GuardOutcome:
    """PLAN §5 row 7: contradiction with weaker provenance, or scan re-flag."""
    if evidence.contradiction_weaker_provenance or evidence.scan_reflag:
        return GuardOutcome(True, "")
    return GuardOutcome(False, "no weaker-provenance contradiction and no scan re-flag")


def _guard_candidate_to_archived(
    evidence: TransitionEvidence, limits: TransitionLimits
) -> GuardOutcome:
    """PLAN §5 row 8: candidate TTL (default 45d) unpromoted."""
    return _guard_ttl_expired(evidence, limits.candidate_ttl_days, "candidate")


def _guard_validated_to_superseded(
    evidence: TransitionEvidence, limits: TransitionLimits
) -> GuardOutcome:
    """PLAN §5 row 9: contradicted by equal/stronger provenance (link kept by the caller)."""
    if evidence.contradiction_equal_or_stronger:
        return GuardOutcome(True, "")
    return GuardOutcome(False, "no equal-or-stronger-provenance contradiction")


def _guard_validated_to_stale(
    evidence: TransitionEvidence, limits: TransitionLimits
) -> GuardOutcome:
    """PLAN §5 row 10: invalidation event, TTL-class expiry, or revalidation fail (strike 1)."""
    if evidence.invalidation_event or evidence.ttl_class_expired or evidence.revalidation_failed:
        return GuardOutcome(True, "")
    return GuardOutcome(False, "no invalidation event, TTL-class expiry, or revalidation failure")


def _guard_validated_to_archived(
    evidence: TransitionEvidence, limits: TransitionLimits
) -> GuardOutcome:
    """PLAN §5 row 11: decay floor (default 0.15) reached (D-022)."""
    if evidence.decay_floor_reached:
        return GuardOutcome(True, "")
    return GuardOutcome(False, "decay floor not reached")


def _guard_validated_to_retired(
    evidence: TransitionEvidence, limits: TransitionLimits
) -> GuardOutcome:
    """PLAN §5 row 12 / D-021.

    Below K distinct scoring principals this simply refuses -- routing the
    memory to `review_queue` instead of auto-retiring it is the *caller's*
    responsibility (PLAN.md §5: "otherwise -> review_queue"; contract §3.9:
    "the machine only refuses"). See the CONTRACT GAP note on `GuardOutcome`.
    """
    if evidence.q_value >= limits.retire_q_threshold:
        return GuardOutcome(
            False, f"q_value {evidence.q_value} >= retire threshold {limits.retire_q_threshold}"
        )
    if evidence.scored_use_count < limits.retire_min_scored_uses:
        return GuardOutcome(
            False,
            f"scored_use_count {evidence.scored_use_count} < required "
            f"{limits.retire_min_scored_uses}",
        )
    if evidence.distinct_scoring_principals < limits.retire_min_distinct_principals:
        return GuardOutcome(
            False,
            f"distinct_scoring_principals {evidence.distinct_scoring_principals} < required K="
            f"{limits.retire_min_distinct_principals} (D-021: route to review_queue instead of "
            f"auto-retiring)",
        )
    return GuardOutcome(True, "")


def _guard_stale_to_validated(
    evidence: TransitionEvidence, limits: TransitionLimits
) -> GuardOutcome:
    """PLAN §5 row 13: re-verification pass."""
    if evidence.reverified:
        return GuardOutcome(True, "")
    return GuardOutcome(False, "not re-verified")


def _guard_stale_to_retired(
    evidence: TransitionEvidence, limits: TransitionLimits
) -> GuardOutcome:
    """PLAN §5 row 14: second strike."""
    if evidence.strike_count >= STALE_RETIRE_STRIKE_THRESHOLD:
        return GuardOutcome(True, "")
    return GuardOutcome(
        False,
        f"strike_count {evidence.strike_count} < {STALE_RETIRE_STRIKE_THRESHOLD} "
        f"(second strike required)",
    )


def _guard_archived_to_validated(
    evidence: TransitionEvidence, limits: TransitionLimits
) -> GuardOutcome:
    """PLAN §5 row 15: operator restore (recoverable, logged by the caller).

    D-023 IS RE-CHECKED HERE, and this is not belt-and-braces -- it closes a
    live route to `validated` that skipped every corroboration control in the
    system. `_guard_quarantined_to_candidate` refuses PROPOSAL, so D-023 was
    read as settled; but `archived` is reachable from `quarantined` on plain
    TTL expiry, and this edge previously checked `operator_restore` and
    nothing else. The whole path is three legal edges:

        None -> quarantined   (propose_memory, Tier B, scan passes)
        quarantined -> archived   (30-day quarantine TTL, no corroboration)
        archived -> validated     (operator restore)

    and it lands proposal-class content in `RETRIEVABLE_STATUSES` having never
    invoked `independent_confirmations` and never faced the promotion
    predicate. D-023's wording is "no skip EVER applies", and a restore that
    reaches `validated` without passing through `candidate` is the largest
    skip in the table. Found by exhaustive reachability search at Phase 3
    integration (`tests/phase3/test_learning_loop_seams.py`); every Phase 3
    red-team probe terminated in `archived` and was recorded as "never
    validated", one guard away from exactly this.

    THE BROADER GAP IS RECORDED, NOT CLOSED (DECISIONS D-085): evidence
    carries no "was ever validated" field, so this guard still cannot
    distinguish an operator restoring a memory that WAS validated and decayed
    to `archived` (the intended use) from one restoring a Tier B row that was
    quarantined, TTL-expired without ever being corroborated, and never earned
    `validated` in the first place. Narrowing that needs a field this frozen
    dataclass does not have, and forbidding operator restore outright would
    contradict PLAN.md §5 row 15.
    """
    if evidence.provenance_class is ProvenanceClass.PROPOSAL:
        return GuardOutcome(
            False,
            "proposal provenance class can never reach validated via any skip (D-023); "
            "an archived proposal must re-enter through quarantine and be corroborated",
        )
    if evidence.operator_restore:
        return GuardOutcome(True, "")
    return GuardOutcome(False, "no operator restore")


def _guard_to_tombstoned(evidence: TransitionEvidence, limits: TransitionLimits) -> GuardOutcome:
    """PLAN §5's wildcard row, materialised per C-08: subject erasure (crypto-shred)
    or review-queue-approved delete. Tombstoned is the only terminal status, so this
    guard is attached to every non-terminal status (erasure must reach everything
    that is not already a tombstone -- retired/superseded/archived rows included)."""
    if evidence.erasure_or_approved_delete:
        return GuardOutcome(True, "")
    return GuardOutcome(False, "no erasure reason or review-approved delete")


def _guard_ttl_expired(evidence: TransitionEvidence, ttl_days: int, label: str) -> GuardOutcome:
    """Shared TTL check for the quarantine/candidate archive rows.

    Reads `evidence.now` (from a `Clock` at the call site) against
    `status_changed_at` -- never `datetime.now()` (hard rule 5); a missing
    `status_changed_at` is a deficiency, never a default pass. Both values are
    guaranteed tz-aware by `TransitionEvidence.__post_init__`, so the
    subtraction below cannot raise and cannot silently compare across zones.
    """
    if evidence.status_changed_at is None:
        return GuardOutcome(False, f"status_changed_at missing; cannot evaluate {label} TTL")
    age = evidence.now - evidence.status_changed_at
    limit = timedelta(days=ttl_days)
    if age >= limit:
        return GuardOutcome(True, "")
    return GuardOutcome(False, f"{label} TTL not reached ({age} < {limit})")


# --------------------------------------------------------------------------- #
# The table. Exactly PLAN.md §5's rows, plus C-08's explicit *->tombstoned
# expansion (every status except TOMBSTONED itself, derived from `Status` so a
# future status member cannot silently miss its erasure edge). `None` is the
# empty pre-insert state (memory creation).
# --------------------------------------------------------------------------- #

_NON_TERMINAL_STATUSES: Final = tuple(s for s in Status if s is not Status.TOMBSTONED)

_TRANSITIONS: Final[dict[tuple[Status | None, Status], Guard]] = {
    (None, Status.CANDIDATE): _guard_none_to_candidate,
    (None, Status.QUARANTINED): _guard_none_to_quarantined,
    (None, Status.PINNED): _guard_none_to_pinned,
    (Status.QUARANTINED, Status.CANDIDATE): _guard_quarantined_to_candidate,
    (Status.QUARANTINED, Status.ARCHIVED): _guard_quarantined_to_archived,
    (Status.CANDIDATE, Status.VALIDATED): _guard_candidate_to_validated,
    (Status.CANDIDATE, Status.QUARANTINED): _guard_candidate_to_quarantined,
    (Status.CANDIDATE, Status.ARCHIVED): _guard_candidate_to_archived,
    (Status.VALIDATED, Status.SUPERSEDED): _guard_validated_to_superseded,
    (Status.VALIDATED, Status.STALE): _guard_validated_to_stale,
    (Status.VALIDATED, Status.ARCHIVED): _guard_validated_to_archived,
    (Status.VALIDATED, Status.RETIRED): _guard_validated_to_retired,
    (Status.STALE, Status.VALIDATED): _guard_stale_to_validated,
    (Status.STALE, Status.RETIRED): _guard_stale_to_retired,
    (Status.ARCHIVED, Status.VALIDATED): _guard_archived_to_validated,
    **{(status, Status.TOMBSTONED): _guard_to_tombstoned for status in _NON_TERMINAL_STATUSES},
}

TRANSITIONS: Final[Mapping[tuple[Status | None, Status], Guard]] = MappingProxyType(_TRANSITIONS)

# Invariant 7's CREATION half. Derived from the table rather than written out, so a future
# `(None, X)` edge is legal at insert automatically and — more importantly — a status that is
# NOT a creation target can never become insertable by anything short of adding its edge here.
#
# This exists because the transition table alone did not cover the door it names: the guards
# above police `apply()`, but `Repo.insert_memory_item` used to bind `item.status.value`
# straight through, and `migrations/0002_partitioned.sql`'s CHECK admits all nine statuses. A
# caller could therefore insert a directly-retrievable `validated` row having never called
# `apply()` at all, while `domain.memory.NewMemoryItem` asserted in two docstrings that "the
# repository re-checks that the status is a legal creation status". It does now, and so does
# `NewMemoryItem.__post_init__` — the type-level half, which no repository implementation
# (Postgres, a fake, a future driver) can bypass.
LEGAL_CREATION_STATUSES: Final[frozenset[Status]] = frozenset(
    target for (current, target) in _TRANSITIONS if current is None
)


def assert_legal_creation_status(status: Status) -> None:
    """Raise `IllegalTransition(None, status)` unless `status` is a `(None, X)` target.

    The status-independent half of the check: the guards on each creation edge decide whether
    THIS item may enter at that status (scan passed, provenance complete, Tier A, ...), and
    they are `apply()`'s job. This decides whether the status is a creation status at all,
    and it is the check a caller cannot skip by not calling `apply()`.
    """
    if status not in LEGAL_CREATION_STATUSES:
        raise IllegalTransition(None, status)
# CONTRACT ADDENDUM (reported): §3.9 types this `Final[dict[...]]`. `Final` stops
# rebinding but not mutation, and a plain dict here is an admin bypass with extra
# steps -- `TRANSITIONS[(QUARANTINED, VALIDATED)] = lambda e, l: GuardOutcome(True, "")`
# is one line in any module and legalises the exact edge invariant 7 names. PLAN.md
# §10 ("no admin bypass exists in code") makes read-only the only defensible shape.
# Every documented use of this table is a read (`in`, `.get`, `.keys()`), so a
# `Mapping` satisfies the contract's consumers exactly. `apply()` reads the private
# `_TRANSITIONS` so that rebinding this module attribute cannot change its behaviour
# either.


def apply(
    current: Status | None,
    target: Status,
    evidence: TransitionEvidence,
    limits: TransitionLimits,
) -> Status:
    """Returns `target` iff (current, target) is a legal edge AND its guard passes.

    The sole entry point for a status change (invariant 7): there is no other
    function anywhere in the codebase that computes a new `Status`. Raises
    `IllegalTransition` for any pair absent from the table (including
    `quarantined -> validated` directly, which does not appear in PLAN.md §5's
    table), and `GuardNotSatisfied(current, target, reason)` when the edge
    exists but `evidence` does not clear its guard.

    Table membership is checked BEFORE any guard runs, so no strength of
    evidence can ever conjure an edge that PLAN.md §5 does not contain.
    """
    guard = _TRANSITIONS.get((current, target))
    if guard is None:
        raise IllegalTransition(current, target)
    outcome = guard(evidence, limits)
    if not outcome.ok:
        raise GuardNotSatisfied(current, target, outcome.reason)
    return target
