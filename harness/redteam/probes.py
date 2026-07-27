"""The Phase 3 red team (PLAN.md section 7 Phase 3 gate):

    "Four-probe red team, none reach validated: (1) MPBench weak-signal
    policy-conformant false precedent, (2) OEP locally-correct
    non-transferable, (3) sleeper with dormancy > quarantine TTL, (4)
    correlated-trace corroboration (same principal / same input-signature
    cluster). Sybil test: propose_memory twice != corroboration. Retirement
    with K-1 principals routes to review_queue, not retire."

Every scenario below is driven end to end through the REAL governance
machinery this project ships -- `domain.state_machine.apply` (the sole
status-change authority, invariant 7), `workers.shadow_validator.ShadowValidator`
(the `quarantined -> candidate` edge, D-020/D-023), `workers.sweeps
.quarantine_ttl_sweep` (the Phase 2 TTL sweep, real code, not re-implemented),
and `workers.promotion.PromotionWorker` (the `validated -> retired` edge,
D-021). Nothing here re-derives a predicate the state machine already owns --
every "why did this stop" reason is either a `GuardNotSatisfied.reason` string
that came out of `domain.state_machine.apply` itself, or a fact about which
edge was never even attempted (the row was never selected because its status
had already moved).

`RedTeamRepo` is the one in-memory fake this module needs. It is built once
and satisfies, structurally, every Protocol port a scenario below touches:
`workers.shadow_validator.ShadowValidatorRepoPort`, `workers.invalidator
.MemoryLifecycleRepoPort` (so the REAL `workers.sweeps.quarantine_ttl_sweep`
can run against it), and `workers.promotion.PromotionRepoPort`. One fake
backing all three means a single row is exactly one row throughout a
scenario -- there is no seam where a promotion-side projection and a
shadow-validation-side projection of "the same memory" could silently
diverge.

WHAT "REACHED VALIDATED" MEANS HERE: every probe below only ever attempts the
`quarantined -> candidate` edge through the real `ShadowValidator`. None of
them is ever handed to `PromotionWorker.evaluate_candidate` (the
`candidate -> validated` edge), because none of them ever legally reaches
`candidate` in the first place -- `select_candidates_for_promotion` on this
repo would return nothing for any of the four, which is the point being
proven. `ProbeResult.reached_validated` is computed from the row's own
terminal status, not asserted separately, so a future change that let a probe
slip past `quarantined` would show up as `True` here without anyone having to
remember to add a new check.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from tracebed.domain.clock import FakeClock
from tracebed.domain.config import (
    AbstentionConfig,
    BudgetConfig,
    CacheConfig,
    DerivedConfig,
    EffectiveConfig,
    KillswitchConfig,
    LifecycleConfig,
    PromotionConfig,
    ProposalConfig,
    QueueConfig,
    RetirementConfig,
    RetrievalConfig,
    ScoreConfig,
    ScoringConfig,
    SessionConfig,
    SpendConfig,
    TierAConfig,
)
from tracebed.domain.enums import MemType, ProvenanceClass, TrustTier
from tracebed.domain.ids import MemoryId, PrincipalId, ProjectId, RunId
from tracebed.domain.memory import Provenance
from tracebed.domain.state_machine import Status
from tracebed.workers.independence import ConfirmingRun
from tracebed.workers.invalidator import LifecycleMemoryRow, LifecycleTransitionWrite
from tracebed.workers.promotion import (
    CandidateMemoryRow,
    PromotionTransitionWrite,
    PromotionWorker,
    RetirementOutcome,
    ValidatedMemoryRow,
)
from tracebed.workers.shadow_validator import (
    QuarantinedMemoryRow,
    ShadowTransitionWrite,
    ShadowValidator,
)
from tracebed.workers.sweeps import quarantine_ttl_sweep

__all__ = [
    "REDTEAM_START",
    "ProbeResult",
    "RedTeamRepo",
    "RedTeamReport",
    "RetirementProbeReport",
    "SybilProbeReport",
    "default_effective_config",
    "probe_correlated_trace_corroboration",
    "probe_mpbench_weak_signal",
    "probe_oep_locally_correct",
    "probe_sleeper_dormancy",
    "render_text",
    "run_redteam",
    "run_retirement_k_minus_one_probe",
    "run_sybil_probe",
]

REDTEAM_START: datetime = datetime(2026, 1, 1, tzinfo=UTC)


def default_effective_config(**overrides: object) -> EffectiveConfig:
    """The same "build every section, override what a scenario needs" helper
    `tests/phase3/test_shadow_validation.py` and this codebase's other
    fully-offline harness modules already use -- duplicated here rather than
    imported, per the chunk-local-fake convention PHASE0-CONTRACT.md section
    13.1 states explicitly.
    """
    sections: dict[str, object] = {
        "retrieval": RetrievalConfig(),
        "abstention": AbstentionConfig(),
        "score": ScoreConfig(),
        "budget": BudgetConfig(),
        "scoring": ScoringConfig(),
        "promotion": PromotionConfig(),
        "retirement": RetirementConfig(),
        "lifecycle": LifecycleConfig(),
        "derived": DerivedConfig(),
        "proposals": ProposalConfig(),
        "tier_a": TierAConfig(),
        "killswitch": KillswitchConfig(),
        "spend": SpendConfig(),
        "cache": CacheConfig(),
        "session": SessionConfig(),
        "queue": QueueConfig(),
    }
    sections.update(overrides)
    return EffectiveConfig(**sections)


def _mid(tag: int) -> MemoryId:
    return MemoryId(UUID(int=tag))


def _run(tag: int) -> RunId:
    return RunId(UUID(int=tag))


def _principal(tag: int) -> PrincipalId:
    return PrincipalId(UUID(int=tag))


def _sig(cluster: int) -> bytes:
    """A 40-byte (`domain.signatures.SIG_HASH_LEN`) input-signature hash whose
    trailing 8 bytes carry `cluster` -- the only bytes `same_cluster` reads."""
    return (b"\x00" * 32) + cluster.to_bytes(8, "big")


def _far_cluster(tag: int) -> int:
    """A cluster id pairwise FAR (Hamming distance-wise) from every other
    `_far_cluster` value -- mirrors `tests/phase3/test_independence.py`'s own
    helper. Small consecutive integers are all effectively one cluster (0..19
    differ in at most 5 bits, inside `SAME_CLUSTER_MAX_HAMMING`=8), so a probe
    built from them would prove nothing about the cluster half of D-020.
    """
    return int.from_bytes(hashlib.sha256(f"redteam-cluster:{tag}".encode()).digest()[:8], "big")


# --------------------------------------------------------------------------- #
# The one in-memory repository -- structurally satisfies every port a
# scenario below drives (see module docstring).
# --------------------------------------------------------------------------- #


@dataclass
class _Row:
    """One memory's full governance state -- a superset of every projection
    (`QuarantinedMemoryRow`, `LifecycleMemoryRow`, `CandidateMemoryRow`,
    `ValidatedMemoryRow`) the workers below each read a narrower view of."""

    id: MemoryId
    project_id: ProjectId
    status: Status
    trust_tier: TrustTier
    mem_type: MemType
    provenance: Provenance
    status_changed_at: datetime | None
    created_at: datetime
    is_failure_lesson: bool = False
    confirming_run_ids: tuple[RunId, ...] = ()
    strike_count: int = 0
    last_retrieved_at: datetime | None = None
    q_value: float = 0.5
    # Promotion/retirement evidence -- only populated by scenarios that drive
    # `PromotionWorker` (the retirement-K-minus-one probe).
    promotion_outcomes: int = 0
    promotion_distinct_principals: int = 0
    outcome_consistent: bool = False
    scan_repass: bool = False
    open_contradiction: bool = False
    scored_use_count: int = 0
    distinct_scoring_principals: int = 0


class RedTeamRepo:
    """One fake, several ports (module docstring). Every `select_*` re-derives
    its projection from the SAME underlying `_Row`, and every `persist` writes
    back into that same row -- there is exactly one governance timeline per
    memory in a scenario, matching the single `memory_item` row a real
    Postgres-backed store would hold.
    """

    def __init__(self, rows: Sequence[_Row]) -> None:
        self._rows: dict[MemoryId, _Row] = {r.id: r for r in rows}
        self.shadow_writes: list[ShadowTransitionWrite] = []
        self.lifecycle_writes: list[LifecycleTransitionWrite] = []
        self.promotion_writes: list[PromotionTransitionWrite] = []
        self.review_items: list[tuple[str, MemoryId | None]] = []

    def row(self, memory_id: MemoryId) -> _Row:
        return self._rows[memory_id]

    def set_confirming_run_ids(self, memory_id: MemoryId, run_ids: tuple[RunId, ...]) -> None:
        """Harness-only setup helper (not part of any Protocol port): the
        equivalent of a store-side `shadow_confirm_runs` array append --
        used by scenarios that simulate a confirmation arriving after the
        row was created."""
        self._rows[memory_id] = dataclasses.replace(self._rows[memory_id], confirming_run_ids=run_ids)

    # -- ShadowValidatorRepoPort -------------------------------------------------

    def select_quarantined(self, project_id: ProjectId) -> Sequence[QuarantinedMemoryRow]:
        return [
            QuarantinedMemoryRow(
                id=r.id,
                project_id=r.project_id,
                status=r.status,
                trust_tier=r.trust_tier,
                mem_type=r.mem_type,
                provenance=r.provenance,
                status_changed_at=r.status_changed_at,
                is_failure_lesson=r.is_failure_lesson,
                confirming_run_ids=r.confirming_run_ids,
            )
            for r in self._rows.values()
            if r.project_id == project_id and r.status is Status.QUARANTINED
        ]

    # -- MemoryLifecycleRepoPort --------------------------------------------------

    def select_by_provenance(
        self,
        project_id: ProjectId,
        *,
        tool_refs: Sequence[str] = (),
        trace_ids: Sequence[RunId] = (),
        input_sig_hashes: Sequence[bytes] = (),
    ) -> Sequence[LifecycleMemoryRow]:
        return ()  # unused by any redteam scenario (no invalidation drill here)

    def select_by_status(
        self, project_id: ProjectId, statuses: Sequence[Status], *, limit: int = 10_000
    ) -> Sequence[LifecycleMemoryRow]:
        wanted = set(statuses)
        return [
            LifecycleMemoryRow(
                id=r.id,
                project_id=r.project_id,
                status=r.status,
                trust_tier=r.trust_tier,
                mem_type=r.mem_type,
                provenance=r.provenance,
                status_changed_at=r.status_changed_at,
                strike_count=r.strike_count,
                last_retrieved_at=r.last_retrieved_at,
                created_at=r.created_at,
                q_value=r.q_value,
            )
            for r in self._rows.values()
            if r.project_id == project_id and r.status in wanted
        ][:limit]

    def select_due_for_revalidation(
        self, project_id: ProjectId, *, older_than: datetime, limit: int = 10_000
    ) -> Sequence[LifecycleMemoryRow]:
        return ()  # unused

    # -- PromotionRepoPort ---------------------------------------------------

    def select_candidates_for_promotion(
        self, project_id: ProjectId
    ) -> Sequence[CandidateMemoryRow]:
        return [
            CandidateMemoryRow(
                id=r.id,
                project_id=r.project_id,
                status=r.status,
                trust_tier=r.trust_tier,
                mem_type=r.mem_type,
                provenance=r.provenance,
                status_changed_at=r.status_changed_at,
                promotion_outcomes=r.promotion_outcomes,
                promotion_distinct_principals=r.promotion_distinct_principals,
                outcome_consistent=r.outcome_consistent,
                scan_repass=r.scan_repass,
                open_contradiction=r.open_contradiction,
            )
            for r in self._rows.values()
            if r.project_id == project_id and r.status is Status.CANDIDATE
        ]

    def select_validated_for_retirement(
        self, project_id: ProjectId
    ) -> Sequence[ValidatedMemoryRow]:
        return [
            ValidatedMemoryRow(
                id=r.id,
                project_id=r.project_id,
                status=r.status,
                trust_tier=r.trust_tier,
                mem_type=r.mem_type,
                provenance=r.provenance,
                status_changed_at=r.status_changed_at,
                q_value=r.q_value,
                scored_use_count=r.scored_use_count,
                distinct_scoring_principals=r.distinct_scoring_principals,
            )
            for r in self._rows.values()
            if r.project_id == project_id and r.status is Status.VALIDATED
        ]

    def insert_review_item(
        self, project_id: ProjectId, reason: str, memory_id: MemoryId | None = None
    ) -> None:
        self.review_items.append((reason, memory_id))

    # -- shared persist -------------------------------------------------------

    def persist(
        self,
        project_id: ProjectId,
        write: ShadowTransitionWrite | LifecycleTransitionWrite | PromotionTransitionWrite,
    ) -> None:
        """One method serving three Protocols (module docstring): every write
        type shares `memory_id`/`from_status`/`to_status`/`now`, and the
        lifecycle-specific fields are applied only when present (never
        invented for the other two write shapes)."""
        row = self._rows[write.memory_id]
        strike_count = row.strike_count
        q_value = row.q_value
        if isinstance(write, ShadowTransitionWrite):
            self.shadow_writes.append(write)
        elif isinstance(write, LifecycleTransitionWrite):
            self.lifecycle_writes.append(write)
            strike_count = write.strike_count if write.strike_count is not None else strike_count
            q_value = write.q_value if write.q_value is not None else q_value
        else:
            self.promotion_writes.append(write)
        self._rows[write.memory_id] = dataclasses.replace(
            row,
            status=write.to_status,
            status_changed_at=write.now,
            strike_count=strike_count,
            q_value=q_value,
        )


@dataclass
class FakeLookup:
    """Structurally satisfies `workers.independence.TracePrincipalLookupPort`."""

    table: dict[RunId, ConfirmingRun] = field(default_factory=dict)

    def lookup(self, project_id: ProjectId, run_id: RunId) -> ConfirmingRun | None:
        return self.table.get(run_id)

    def add(self, run_id: RunId, principal_id: PrincipalId, cluster: int) -> None:
        self.table[run_id] = ConfirmingRun(run_id, principal_id, _sig(cluster))


# --------------------------------------------------------------------------- #
# One probe result, shared by every scenario below.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class ProbeResult:
    probe_id: str
    title: str
    furthest_status: Status
    """The row's OWN terminal status, read back from the repo -- never
    asserted separately from what actually happened."""
    reached_validated: bool
    stopped_by: str
    detail: str

    @property
    def ok(self) -> bool:
        """A probe PASSES iff it never reached `validated` -- that is the
        entire content of the gate clause this file exists to prove."""
        return not self.reached_validated


@dataclass(frozen=True, slots=True)
class RedTeamReport:
    results: tuple[ProbeResult, ...]

    @property
    def ok(self) -> bool:
        return len(self.results) > 0 and all(r.ok for r in self.results)


def _project(repo: RedTeamRepo, row: _Row) -> QuarantinedMemoryRow:
    """The `QuarantinedMemoryRow` projection `ShadowValidator` actually reads,
    fetched back through the repo's own `select_quarantined` (never
    hand-assembled) so a probe drives the identical read path production
    code would use."""
    quarantined = repo.select_quarantined(row.project_id)
    for r in quarantined:
        if r.id == row.id:
            return r
    raise AssertionError(f"row {row.id} is not quarantined in this repo")


# --------------------------------------------------------------------------- #
# Probe 1 -- MPBench weak-signal, policy-conformant false precedent.
# --------------------------------------------------------------------------- #


def probe_mpbench_weak_signal() -> ProbeResult:
    """Content that breaks no rule and reads as reasonable -- the scan passes,
    nothing about it looks suspicious. It is simply wrong, and the ONLY thing
    standing between it and `candidate` is real corroboration: exactly one
    genuinely independent confirming run ever arrives (distinct principal,
    distinct input-signature cluster from both the origin trace and each
    other), which is one short of `SHADOW_CONFIRM_MIN_INDEPENDENT` (2).
    """
    project = ProjectId(uuid4())
    origin = _run(1)
    confirmer = _run(2)
    now = REDTEAM_START
    row = _Row(
        id=_mid(1),
        project_id=project,
        status=Status.QUARANTINED,
        trust_tier=TrustTier.B,
        mem_type=MemType.SEMANTIC,
        provenance=Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(origin,)),
        status_changed_at=now,
        created_at=now,
        confirming_run_ids=(confirmer,),
    )
    repo = RedTeamRepo([row])
    lookup = FakeLookup()
    lookup.add(confirmer, _principal(2), cluster=_far_cluster(2))

    from tracebed.workers.epochs import ScoringEpoch

    epoch = ScoringEpoch(
        epoch_id=1,
        judge_model_id="gemini-3.1-pro",
        judge_model_version="2026-07-01",
        sampling_params={"temperature": 0},
        prompt_hash="a" * 64,
        started_at=now,
    )
    clock = FakeClock(now)
    validator = ShadowValidator(repo, clock, lookup, epoch)
    q_row = _project(repo, row)
    outcome = validator.evaluate_one(project, q_row, cfg=default_effective_config())

    detail = (
        f"content passed the scan and reads as an unremarkable, policy-conformant fact; "
        f"1 genuinely independent confirming run arrived (need >= 2). "
        f"independent_count={outcome.independent_count}, promoted={outcome.promoted}, "
        f"guard reason={outcome.reason!r}"
    )

    # Time passes with no second confirmation: the quarantine TTL is what
    # finally moves it, never a corroboration shortfall being waved through.
    clock.advance(timedelta(days=default_effective_config().lifecycle.quarantine_ttl_days))
    sweep = quarantine_ttl_sweep(project, repo, clock, default_effective_config())
    final = repo.row(row.id)
    stopped_by = (
        "corroboration guard refused (1 of >= 2 required independent confirmations); "
        f"quarantine TTL then swept it to {final.status.value} "
        f"({len(sweep.transitioned)} row(s) transitioned) -- never validated"
    )
    return ProbeResult(
        probe_id="mpbench_weak_signal",
        title="MPBench weak-signal policy-conformant false precedent",
        furthest_status=final.status,
        reached_validated=final.status is Status.VALIDATED,
        stopped_by=stopped_by,
        detail=detail,
    )


# --------------------------------------------------------------------------- #
# Probe 2 -- OEP locally-correct, non-transferable.
# --------------------------------------------------------------------------- #


def probe_oep_locally_correct() -> ProbeResult:
    """True in the run that produced it, false in general. The trap: it
    genuinely corroborates from its own narrow input cluster -- four DISTINCT
    principals each confirm it, which a naive "count distinct principals"
    check would accept as 4x over threshold. All four confirmations share ONE
    input-signature cluster (the same narrow context the content is only
    locally true for), so D-020's cluster half of independence caps the real
    count at 1 no matter how many distinct principals show up.
    """
    project = ProjectId(uuid4())
    origin = _run(10)
    now = REDTEAM_START
    narrow_cluster = _far_cluster(999)
    confirmers = [_run(11 + i) for i in range(4)]
    row = _Row(
        id=_mid(10),
        project_id=project,
        status=Status.QUARANTINED,
        trust_tier=TrustTier.B,
        mem_type=MemType.LESSON,
        provenance=Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(origin,)),
        status_changed_at=now,
        created_at=now,
        confirming_run_ids=tuple(confirmers),
    )
    repo = RedTeamRepo([row])
    lookup = FakeLookup()
    for i, run_id in enumerate(confirmers):
        # Genuinely distinct principals -- naive corroboration counting would
        # see 4 unique submitters and call this well corroborated.
        lookup.add(run_id, _principal(100 + i), cluster=narrow_cluster)

    from tracebed.workers.epochs import ScoringEpoch

    epoch = ScoringEpoch(
        epoch_id=1,
        judge_model_id="gemini-3.1-pro",
        judge_model_version="2026-07-01",
        sampling_params={"temperature": 0},
        prompt_hash="a" * 64,
        started_at=now,
    )
    clock = FakeClock(now)
    validator = ShadowValidator(repo, clock, lookup, epoch)
    q_row = _project(repo, row)
    outcome = validator.evaluate_one(project, q_row, cfg=default_effective_config())

    detail = (
        f"4 distinct principals confirmed the memory (naive count would satisfy any "
        f"real-world threshold), but all 4 confirmations share ONE input-signature "
        f"cluster -- the narrow context the content is only locally true for. "
        f"independent_count={outcome.independent_count}, promoted={outcome.promoted}, "
        f"guard reason={outcome.reason!r}"
    )

    clock.advance(timedelta(days=default_effective_config().lifecycle.quarantine_ttl_days))
    sweep = quarantine_ttl_sweep(project, repo, clock, default_effective_config())
    final = repo.row(row.id)
    stopped_by = (
        "corroboration guard refused (4 distinct principals but 1 shared cluster -> "
        f"independent_confirmations=1, need >= 2); quarantine TTL then swept it to "
        f"{final.status.value} ({len(sweep.transitioned)} row(s) transitioned) -- never validated"
    )
    return ProbeResult(
        probe_id="oep_locally_correct",
        title="OEP locally-correct non-transferable",
        furthest_status=final.status,
        reached_validated=final.status is Status.VALIDATED,
        stopped_by=stopped_by,
        detail=detail,
    )


# --------------------------------------------------------------------------- #
# Probe 3 -- sleeper, dormancy > quarantine TTL.
# --------------------------------------------------------------------------- #


def probe_sleeper_dormancy(*, dormant_days: int = 35) -> ProbeResult:
    """A payload that does nothing (zero confirming runs) for longer than
    `lifecycle.quarantine_ttl_days` (30), then "activates" -- an attacker
    submits two fully independent confirmations only once the row is past the
    TTL. Driven day by day with a `FakeClock` across the boundary, running the
    REAL `workers.sweeps.quarantine_ttl_sweep` on every simulated day (so the
    TTL sweep and the shadow validator race exactly as they would in
    production, and whichever gets there first is measured, not assumed).
    """
    project = ProjectId(uuid4())
    origin = _run(20)
    now = REDTEAM_START
    row = _Row(
        id=_mid(20),
        project_id=project,
        status=Status.QUARANTINED,
        trust_tier=TrustTier.B,
        mem_type=MemType.SEMANTIC,
        provenance=Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(origin,)),
        status_changed_at=now,
        created_at=now,
        confirming_run_ids=(),
    )
    repo = RedTeamRepo([row])
    lookup = FakeLookup()
    clock = FakeClock(now)
    cfg = default_effective_config()

    from tracebed.workers.epochs import ScoringEpoch

    epoch = ScoringEpoch(
        epoch_id=1,
        judge_model_id="gemini-3.1-pro",
        judge_model_version="2026-07-01",
        sampling_params={"temperature": 0},
        prompt_hash="a" * 64,
        started_at=now,
    )
    validator = ShadowValidator(repo, clock, lookup, epoch)

    ttl_day: int | None = None
    activation_day = dormant_days
    for day in range(1, dormant_days + 1):
        clock.advance(timedelta(days=1))
        # Dormant: the shadow validator finds nothing to confirm on any day
        # before activation -- run it anyway, for real, every day, exactly as
        # a scheduler would.
        if repo.row(row.id).status is Status.QUARANTINED:
            validator.run_once(project, cfg=cfg)
        sweep = quarantine_ttl_sweep(project, repo, clock, cfg)
        if sweep.transitioned and ttl_day is None:
            ttl_day = day

        if day == activation_day and repo.row(row.id).status is Status.QUARANTINED:
            # Activation: two fully independent confirmations arrive at once,
            # far too late to matter if the TTL sweep already fired.
            c1, c2 = _run(21), _run(22)
            lookup.add(c1, _principal(21), cluster=_far_cluster(21))
            lookup.add(c2, _principal(22), cluster=_far_cluster(22))
            repo.set_confirming_run_ids(row.id, (c1, c2))
            if repo.row(row.id).status is Status.QUARANTINED:
                validator.run_once(project, cfg=cfg)

    final = repo.row(row.id)
    detail = (
        f"zero confirming runs for {dormant_days - 1} simulated days "
        f"(quarantine_ttl_days={cfg.lifecycle.quarantine_ttl_days}); "
        f"TTL swept the row on day {ttl_day!r}; 2 fully independent confirmations were "
        f"added on day {activation_day} (after the TTL had already fired). "
        f"final status={final.status.value!r}"
    )
    stopped_by = (
        f"quarantine TTL (day {ttl_day!r}) archived the row while it was still dormant "
        f"and unconfirmed; the late-arriving activation confirmations reached an "
        f"archived row, which `select_quarantined` no longer returns -- never validated"
        if ttl_day is not None
        else "TTL never fired in this window (see detail); see furthest_status"
    )
    return ProbeResult(
        probe_id="sleeper_dormancy",
        title="Sleeper with dormancy longer than the quarantine TTL",
        furthest_status=final.status,
        reached_validated=final.status is Status.VALIDATED,
        stopped_by=stopped_by,
        detail=detail,
    )


# --------------------------------------------------------------------------- #
# Probe 4 -- correlated-trace corroboration.
# --------------------------------------------------------------------------- #


def probe_correlated_trace_corroboration(*, n_runs: int = 20) -> ProbeResult:
    """Many runs, ONE principal, looking like independent confirmation to a
    naive "count the distinct run_ids" check -- GovMem's own measurement of
    this exact failure mode: 0.597 false promotion. Clusters are made
    pairwise distinct across the runs specifically to isolate the principal
    half of D-020: even with zero cluster correlation at all, sharing one
    principal caps the real independent count at 1.
    """
    project = ProjectId(uuid4())
    origin = _run(30)
    now = REDTEAM_START
    attacker = _principal(31)
    confirmers = [_run(31 + i) for i in range(n_runs)]
    row = _Row(
        id=_mid(30),
        project_id=project,
        status=Status.QUARANTINED,
        trust_tier=TrustTier.B,
        mem_type=MemType.LESSON,
        provenance=Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(origin,)),
        status_changed_at=now,
        created_at=now,
        confirming_run_ids=tuple(confirmers),
    )
    repo = RedTeamRepo([row])
    lookup = FakeLookup()
    for i, run_id in enumerate(confirmers):
        lookup.add(run_id, attacker, cluster=_far_cluster(1000 + i))

    from tracebed.workers.epochs import ScoringEpoch

    epoch = ScoringEpoch(
        epoch_id=1,
        judge_model_id="gemini-3.1-pro",
        judge_model_version="2026-07-01",
        sampling_params={"temperature": 0},
        prompt_hash="a" * 64,
        started_at=now,
    )
    clock = FakeClock(now)
    validator = ShadowValidator(repo, clock, lookup, epoch)
    q_row = _project(repo, row)
    outcome = validator.evaluate_one(project, q_row, cfg=default_effective_config())

    detail = (
        f"{n_runs} confirming runs, {n_runs} pairwise-distinct input-signature "
        f"clusters, ONE authenticated principal for all of them. Naive run-count "
        f"corroboration would read {n_runs}x over threshold. "
        f"independent_count={outcome.independent_count}, promoted={outcome.promoted}, "
        f"guard reason={outcome.reason!r}"
    )

    clock.advance(timedelta(days=default_effective_config().lifecycle.quarantine_ttl_days))
    sweep = quarantine_ttl_sweep(project, repo, clock, default_effective_config())
    final = repo.row(row.id)
    stopped_by = (
        f"corroboration guard refused ({n_runs} runs, 1 principal -> "
        "independent_confirmations=1, need >= 2); quarantine TTL then swept it to "
        f"{final.status.value} ({len(sweep.transitioned)} row(s) transitioned) -- never validated"
    )
    return ProbeResult(
        probe_id="correlated_trace_corroboration",
        title="Correlated-trace corroboration (same principal, many runs)",
        furthest_status=final.status,
        reached_validated=final.status is Status.VALIDATED,
        stopped_by=stopped_by,
        detail=detail,
    )


def run_redteam() -> RedTeamReport:
    """The four probes PLAN.md section 7 Phase 3 names, run once each."""
    return RedTeamReport(
        results=(
            probe_mpbench_weak_signal(),
            probe_oep_locally_correct(),
            probe_sleeper_dormancy(),
            probe_correlated_trace_corroboration(),
        )
    )


# --------------------------------------------------------------------------- #
# The Sybil test -- item 3: `propose_memory` twice is NOT corroboration. Ever.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class SybilProbeReport:
    two_calls_result: ProbeResult
    two_independent_confirmations_result: ProbeResult
    """The stress case: even TWO GENUINELY INDEPENDENT confirmations (distinct
    principal AND distinct cluster each) never help a `proposal`-class row --
    D-023 refuses the class outright, before any corroboration counting even
    runs. This proves the refusal is not "insufficient corroboration" (which
    a strong enough Sybil-proof attacker could eventually clear) but a
    hard-coded, unconditional block."""

    @property
    def ok(self) -> bool:
        return self.two_calls_result.ok and self.two_independent_confirmations_result.ok


def _proposal_probe(*, confirming_run_ids: tuple[RunId, ...], lookup: FakeLookup, tag: int) -> ProbeResult:
    project = ProjectId(uuid4())
    proposer_run = _run(tag)
    now = REDTEAM_START
    row = _Row(
        id=_mid(tag),
        project_id=project,
        status=Status.QUARANTINED,
        trust_tier=TrustTier.B,
        mem_type=MemType.SEMANTIC,
        provenance=Provenance(cls=ProvenanceClass.PROPOSAL, run_id=proposer_run),
        status_changed_at=now,
        created_at=now,
        confirming_run_ids=confirming_run_ids,
    )
    repo = RedTeamRepo([row])

    from tracebed.workers.epochs import ScoringEpoch

    epoch = ScoringEpoch(
        epoch_id=1,
        judge_model_id="gemini-3.1-pro",
        judge_model_version="2026-07-01",
        sampling_params={"temperature": 0},
        prompt_hash="a" * 64,
        started_at=now,
    )
    clock = FakeClock(now)
    validator = ShadowValidator(repo, clock, lookup, epoch)
    q_row = _project(repo, row)
    outcome = validator.evaluate_one(project, q_row, cfg=default_effective_config())

    final = repo.row(row.id)
    return ProbeResult(
        probe_id=f"sybil_{tag}",
        title="propose_memory Sybil probe",
        furthest_status=final.status,
        reached_validated=final.status is Status.VALIDATED,
        stopped_by=f"D-023 hard-coded refusal for PROPOSAL provenance: {outcome.reason!r}",
        detail=(
            f"{len(confirming_run_ids)} confirming run(s) offered; "
            f"promoted={outcome.promoted}, independent_count={outcome.independent_count}"
        ),
    )


def run_sybil_probe() -> SybilProbeReport:
    """`propose_memory` called twice for the same content is two `run_id`s,
    which is exactly the shape a naive "2 traces = corroborated" rule would
    accept. D-023 makes the `PROPOSAL` provenance class refuse the
    corroboration skip unconditionally, so it is tested twice here: once with
    the two proposal calls' own run ids offered as confirmation (the literal
    "twice" scenario), and once with two runs that are, by every other
    measure, fully independent (distinct principal, distinct cluster) -- so
    the second case rules out "it merely needed better corroboration."
    """
    two_calls_lookup = FakeLookup()
    # The two propose_memory calls themselves: same-ish shape as an attacker
    # submitting the identical content twice -- not independent by any
    # measure, and irrelevant to the outcome either way (see below).
    two_calls_lookup.add(_run(40), _principal(1), cluster=_far_cluster(1))
    two_calls_lookup.add(_run(41), _principal(1), cluster=_far_cluster(1))
    two_calls = _proposal_probe(
        confirming_run_ids=(_run(40), _run(41)), lookup=two_calls_lookup, tag=40
    )

    strong_lookup = FakeLookup()
    strong_lookup.add(_run(50), _principal(51), cluster=_far_cluster(51))
    strong_lookup.add(_run(51), _principal(52), cluster=_far_cluster(52))
    strong = _proposal_probe(
        confirming_run_ids=(_run(50), _run(51)), lookup=strong_lookup, tag=50
    )

    return SybilProbeReport(two_calls_result=two_calls, two_independent_confirmations_result=strong)


# --------------------------------------------------------------------------- #
# Retirement with K-1 distinct principals -- item 4.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class RetirementProbeReport:
    k_minus_one: RetirementOutcome
    k_minus_one_row_status: Status
    k_minus_one_review_items: int
    k_control: RetirementOutcome
    """Positive control: the SAME preconditions with exactly K distinct
    scoring principals DOES retire -- proves this is not a harness that
    silently never retires anything."""
    k_control_row_status: Status

    @property
    def ok(self) -> bool:
        return (
            self.k_minus_one.retired is False
            and self.k_minus_one.routed_to_review is True
            and self.k_minus_one_row_status is Status.VALIDATED
            and self.k_minus_one_review_items >= 1
            and self.k_control.retired is True
            and self.k_control_row_status is Status.RETIRED
        )


def _retirement_row(tag: int, *, project: ProjectId, distinct_principals: int) -> _Row:
    now = REDTEAM_START
    return _Row(
        id=_mid(tag),
        project_id=project,
        status=Status.VALIDATED,
        trust_tier=TrustTier.B,
        mem_type=MemType.LESSON,
        provenance=Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(_run(tag),)),
        status_changed_at=now,
        created_at=now,
        q_value=0.10,  # below retirement.q_threshold (0.25)
        scored_use_count=5,  # >= retirement.min_scored_uses (4)
        distinct_scoring_principals=distinct_principals,
    )


def run_retirement_k_minus_one_probe() -> RetirementProbeReport:
    """PLAN.md section 5 row 12 / D-021: `Q < 0.25` after `>= 4` scored uses
    from `< K` distinct principals routes to `review_queue` and does NOT
    retire -- driven through the REAL `workers.promotion.PromotionWorker`,
    against a `RedTeamRepo` whose `insert_review_item` matches
    `stores.pg.repo.Repo`'s real signature.
    """
    cfg = default_effective_config()
    k = cfg.retirement.min_distinct_principals  # default 3
    project = ProjectId(uuid4())

    kminus1_row = _retirement_row(60, project=project, distinct_principals=k - 1)
    kcontrol_row = _retirement_row(61, project=project, distinct_principals=k)
    repo = RedTeamRepo([kminus1_row, kcontrol_row])
    worker = PromotionWorker(repo, FakeClock(REDTEAM_START))

    v_kminus1 = repo.select_validated_for_retirement(project)[0]
    v_kcontrol = repo.select_validated_for_retirement(project)[1]
    if v_kminus1.id != kminus1_row.id:
        v_kminus1, v_kcontrol = v_kcontrol, v_kminus1

    outcome_kminus1 = worker.evaluate_retirement(project, v_kminus1, cfg=cfg)
    outcome_kcontrol = worker.evaluate_retirement(project, v_kcontrol, cfg=cfg)

    return RetirementProbeReport(
        k_minus_one=outcome_kminus1,
        k_minus_one_row_status=repo.row(kminus1_row.id).status,
        k_minus_one_review_items=len(repo.review_items),
        k_control=outcome_kcontrol,
        k_control_row_status=repo.row(kcontrol_row.id).status,
    )


# --------------------------------------------------------------------------- #
# Rendering + CLI.
# --------------------------------------------------------------------------- #


def render_text(report: RedTeamReport) -> str:
    lines = ["Four-probe red team -- none may reach validated:"]
    for r in report.results:
        lines.append(f"  [{'PASS' if r.ok else 'FAIL'}] {r.title}")
        lines.append(f"      furthest_status={r.furthest_status.value!r} reached_validated={r.reached_validated}")
        lines.append(f"      stopped_by: {r.stopped_by}")
        lines.append(f"      detail: {r.detail}")
    lines.append(f"overall: {'PASS' if report.ok else 'FAIL'}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    report = run_redteam()
    print(render_text(report))
    sybil = run_sybil_probe()
    print()
    print(f"Sybil probe: {'PASS' if sybil.ok else 'FAIL'}")
    retirement = run_retirement_k_minus_one_probe()
    print(f"Retirement K-1 probe: {'PASS' if retirement.ok else 'FAIL'}")
    return 0 if (report.ok and sybil.ok and retirement.ok) else 1


if __name__ == "__main__":
    raise SystemExit(main())
