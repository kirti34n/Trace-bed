"""`workers.shadow_validator` — `quarantined -> candidate`, the anti-poisoning core
(PLAN.md §2 invariant 7; §5 row 4; D-020; D-023).

Fully offline: `_FakeRepo` and `_FakeLookup` are in-file fakes (this codebase's convention,
contract §13.1). Every promoting assertion is cross-checked against a direct
`domain.state_machine.apply()` call built from the identical evidence, proving the worker
never performs a status change the state machine did not itself authorise.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

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
from tracebed.domain.errors import GuardNotSatisfied, TracebedError
from tracebed.domain.ids import MemoryId, PrincipalId, ProjectId, RunId
from tracebed.domain.memory import Provenance
from tracebed.domain.state_machine import (
    ShadowConfirmation,
    Status,
    TransitionEvidence,
    TransitionLimits,
    apply,
)
from tracebed.workers.epochs import ScoringEpoch
from tracebed.workers.independence import ConfirmingRun
from tracebed.workers.shadow_validator import (
    QuarantinedMemoryRow,
    ShadowTransitionWrite,
    ShadowValidator,
    origin_runs,
)

pytestmark = pytest.mark.phase3

EPOCH = datetime(2026, 1, 1, tzinfo=UTC)
PROJECT = ProjectId(UUID(int=1))
OTHER_PROJECT = ProjectId(UUID(int=2))

# NOT 0 -- see `tests/phase3/test_independence.py::_CLUSTER_A`. A zero cluster makes the whole
# 40-byte signature `ABSENT_SIGNATURE`, which `build_confirmations` excludes as missing evidence
# (D-131) rather than resolving as a real cluster.
_CLUSTER_A = 0x0000000000000001
_CLUSTER_B = 0xFFFFFFFFFFFFFFFF


def _far_cluster(tag: int) -> int:
    """A cluster id pairwise FAR from every other `_far_cluster` value -- see
    `tests/phase3/test_independence.py::_far_cluster`. Small integers are all ONE cluster
    (0..19 differ in at most 5 bits, inside `SAME_CLUSTER_MAX_HAMMING`), so a "twenty
    distinct clusters" fixture built from them proves nothing about the principal half of
    D-020."""
    return int.from_bytes(hashlib.sha256(f"cluster:{tag}".encode()).digest()[:8], "big")


# The run a memory was DISTILLED FROM, deliberately never reused as a confirming run in
# the tests that are about corroboration arithmetic -- `origin_runs` subtracts it, so a
# fixture that conflated the two would be testing the subtraction, not the arithmetic.
_ORIGIN = 900


def _effective_config(**overrides: object) -> EffectiveConfig:
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
    return (b"\x00" * 32) + cluster.to_bytes(8, "big")


def _row(
    tag: int,
    *,
    provenance: Provenance,
    mem_type: MemType = MemType.LESSON,
    is_failure_lesson: bool = False,
    confirming_run_ids: tuple[RunId, ...] = (),
    status: Status = Status.QUARANTINED,
    status_changed_at: datetime | None = EPOCH,
    project_id: ProjectId = PROJECT,
) -> QuarantinedMemoryRow:
    return QuarantinedMemoryRow(
        id=_mid(tag),
        project_id=project_id,
        status=status,
        trust_tier=TrustTier.B,
        mem_type=mem_type,
        provenance=provenance,
        status_changed_at=status_changed_at,
        is_failure_lesson=is_failure_lesson,
        confirming_run_ids=confirming_run_ids,
    )


@dataclass
class _FakeLookup:
    table: dict[RunId, ConfirmingRun] = field(default_factory=dict)
    calls: list[RunId] = field(default_factory=list)

    def lookup(self, project_id: ProjectId, run_id: RunId) -> ConfirmingRun | None:
        self.calls.append(run_id)
        return self.table.get(run_id)

    def add(self, run_id: RunId, principal_id: PrincipalId, cluster: int) -> None:
        self.table[run_id] = ConfirmingRun(run_id, principal_id, _sig(cluster))


_EPOCH_ROW = ScoringEpoch(
    epoch_id=7,
    judge_model_id="gemini-3.1-pro",
    judge_model_version="2026-07-01",
    sampling_params={"temperature": 0},
    prompt_hash="deadbeef",
    started_at=EPOCH,
)


class _FakeRepo:
    def __init__(self, rows: Sequence[QuarantinedMemoryRow]) -> None:
        self._rows: dict[MemoryId, QuarantinedMemoryRow] = {r.id: r for r in rows}
        self.persisted: list[ShadowTransitionWrite] = []

    def select_quarantined(self, project_id: ProjectId) -> Sequence[QuarantinedMemoryRow]:
        return [r for r in self._rows.values() if r.status is Status.QUARANTINED]

    def persist(self, project_id: ProjectId, write: ShadowTransitionWrite) -> None:
        self.persisted.append(write)
        old = self._rows[write.memory_id]
        self._rows[write.memory_id] = QuarantinedMemoryRow(
            id=old.id,
            project_id=old.project_id,
            status=write.to_status,
            trust_tier=old.trust_tier,
            mem_type=old.mem_type,
            provenance=old.provenance,
            status_changed_at=write.now,
            is_failure_lesson=old.is_failure_lesson,
            confirming_run_ids=old.confirming_run_ids,
        )


def _worker(lookup: _FakeLookup, repo: _FakeRepo, clock: FakeClock) -> ShadowValidator:
    return ShadowValidator(repo, clock, lookup, _EPOCH_ROW)


# --------------------------------------------------------------------------- #
# The Sybil test: distinct principals AND distinct clusters, both required.
# --------------------------------------------------------------------------- #


def test_twenty_runs_one_principal_stays_quarantined() -> None:
    lookup = _FakeLookup()
    run_ids = []
    for i in range(20):
        run_ids.append(_run(i))
        # Genuinely distinct clusters, ONE principal -- so the principal half of D-020 is
        # the only thing that can cap this at 1.
        lookup.add(_run(i), _principal(1), cluster=_far_cluster(i))
    row = _row(
        1,
        provenance=Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(_run(_ORIGIN),)),
        confirming_run_ids=tuple(run_ids),
    )
    repo = _FakeRepo([row])
    worker = _worker(lookup, repo, FakeClock(EPOCH))

    outcome = worker.evaluate_one(PROJECT, row, cfg=_effective_config())

    assert outcome.promoted is False
    assert outcome.independent_count == 1
    assert repo.persisted == []


def test_twenty_principals_one_cluster_stays_quarantined() -> None:
    lookup = _FakeLookup()
    run_ids = []
    for i in range(20):
        run_ids.append(_run(i))
        lookup.add(_run(i), _principal(i), cluster=_CLUSTER_A)  # distinct principals, ONE cluster
    row = _row(
        1,
        provenance=Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(_run(_ORIGIN),)),
        confirming_run_ids=tuple(run_ids),
    )
    repo = _FakeRepo([row])
    worker = _worker(lookup, repo, FakeClock(EPOCH))

    outcome = worker.evaluate_one(PROJECT, row, cfg=_effective_config())

    assert outcome.promoted is False
    assert outcome.independent_count == 1
    assert repo.persisted == []


def test_two_principals_two_clusters_promotes() -> None:
    lookup = _FakeLookup()
    lookup.add(_run(1), _principal(1), cluster=_CLUSTER_A)
    lookup.add(_run(2), _principal(2), cluster=_CLUSTER_B)
    row = _row(
        1,
        provenance=Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(_run(_ORIGIN),)),
        confirming_run_ids=(_run(1), _run(2)),
    )
    repo = _FakeRepo([row])
    worker = _worker(lookup, repo, FakeClock(EPOCH))

    outcome = worker.evaluate_one(PROJECT, row, cfg=_effective_config())

    assert outcome.promoted is True
    assert outcome.to_status is Status.CANDIDATE
    assert outcome.independent_count == 2
    assert len(repo.persisted) == 1
    assert repo.persisted[0].to_status is Status.CANDIDATE

    # Cross-check against a direct apply() call built from identical evidence -- the worker
    # must never authorise a transition the state machine itself would refuse.
    limits = TransitionLimits.from_config(_effective_config())
    evidence = TransitionEvidence(
        now=EPOCH,
        provenance_class=row.provenance.cls,
        trust_tier=row.trust_tier,
        mem_type=row.mem_type,
        status_changed_at=row.status_changed_at,
        confirmations=(
            _confirmation(_run(1), _principal(1), _CLUSTER_A),
            _confirmation(_run(2), _principal(2), _CLUSTER_B),
        ),
    )
    assert apply(Status.QUARANTINED, Status.CANDIDATE, evidence, limits) is Status.CANDIDATE


def _confirmation(run_id: RunId, principal_id: PrincipalId, cluster: int) -> ShadowConfirmation:
    return ShadowConfirmation(run_id, principal_id, _sig(cluster))


# --------------------------------------------------------------------------- #
# D-023: propose_memory proposals can never use either skip.
# --------------------------------------------------------------------------- #


def test_proposal_class_never_uses_corroboration_skip() -> None:
    lookup = _FakeLookup()
    lookup.add(_run(1), _principal(1), cluster=_CLUSTER_A)
    lookup.add(_run(2), _principal(2), cluster=_CLUSTER_B)
    row = _row(
        1,
        provenance=Provenance(cls=ProvenanceClass.PROPOSAL, run_id=_run(1)),
        confirming_run_ids=(_run(1), _run(2)),  # would satisfy corroboration for any other class
    )
    repo = _FakeRepo([row])
    worker = _worker(lookup, repo, FakeClock(EPOCH))

    outcome = worker.evaluate_one(PROJECT, row, cfg=_effective_config())

    assert outcome.promoted is False
    assert "proposal" in outcome.reason.lower()
    assert repo.persisted == []


def test_proposal_class_never_uses_human_verdict_skip() -> None:
    """Even fabricating `has_verified_human_verdict=True` directly against the state
    machine (bypassing this worker's own class-derived flag entirely), PROPOSAL provenance
    is refused -- D-023's short-circuit reads the class first, unconditionally, before it
    ever looks at the verdict flag."""
    limits = TransitionLimits.from_config(_effective_config())
    evidence = TransitionEvidence(
        now=EPOCH,
        provenance_class=ProvenanceClass.PROPOSAL,
        trust_tier=TrustTier.B,
        mem_type=MemType.SEMANTIC,
        status_changed_at=EPOCH,
        has_verified_human_verdict=True,
    )
    with pytest.raises(GuardNotSatisfied) as exc_info:
        apply(Status.QUARANTINED, Status.CANDIDATE, evidence, limits)
    assert "proposal" in exc_info.value.reason.lower()


# --------------------------------------------------------------------------- #
# The verified-human-verdict skip.
# --------------------------------------------------------------------------- #


def test_human_verdict_class_does_not_promote_with_zero_confirmations() -> None:
    """The end-to-end half of D-134/D-137, inverted from what it asserted before.

    This row shape is constructible through the real insert door -- `insert_memory_item`
    checks status MEMBERSHIP and per-class provenance FIELDS, never the creation guard --
    so the removed skip was a reachable zero-evidence exit from quarantine, not dead code.
    With the skip gone the worker still computes `has_verified_human_verdict` from the
    stored provenance and no guard reads it, so the row stays quarantined on the ordinary
    corroboration arithmetic: zero confirmations against a threshold of two.
    """
    lookup = _FakeLookup()
    row = _row(
        1,
        provenance=Provenance(cls=ProvenanceClass.HUMAN_VERDICT, verdict_id=uuid4()),
        confirming_run_ids=(),
    )
    repo = _FakeRepo([row])
    worker = _worker(lookup, repo, FakeClock(EPOCH))

    outcome = worker.evaluate_one(PROJECT, row, cfg=_effective_config())

    assert outcome.promoted is False
    assert outcome.to_status is None
    assert outcome.independent_count == 0


# --------------------------------------------------------------------------- #
# Failure lessons: 1 confirmation, but only when mem_type is actually LESSON.
# --------------------------------------------------------------------------- #


def test_failure_lesson_needs_only_one_confirmation() -> None:
    lookup = _FakeLookup()
    lookup.add(_run(1), _principal(1), cluster=_CLUSTER_A)
    row = _row(
        1,
        provenance=Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(_run(_ORIGIN),)),
        mem_type=MemType.LESSON,
        is_failure_lesson=True,
        confirming_run_ids=(_run(1),),
    )
    repo = _FakeRepo([row])
    worker = _worker(lookup, repo, FakeClock(EPOCH))

    outcome = worker.evaluate_one(PROJECT, row, cfg=_effective_config())

    assert outcome.promoted is True
    assert outcome.to_status is Status.CANDIDATE


def test_failure_lesson_flag_ignored_when_mem_type_is_not_lesson() -> None:
    """`is_failure_lesson=True` on a SEMANTIC memory must not halve the corroboration
    requirement -- the guard checks `mem_type is LESSON` as well as the flag."""
    lookup = _FakeLookup()
    lookup.add(_run(1), _principal(1), cluster=_CLUSTER_A)
    row = _row(
        1,
        provenance=Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(_run(_ORIGIN),)),
        mem_type=MemType.SEMANTIC,
        is_failure_lesson=True,
        confirming_run_ids=(_run(1),),
    )
    repo = _FakeRepo([row])
    worker = _worker(lookup, repo, FakeClock(EPOCH))

    outcome = worker.evaluate_one(PROJECT, row, cfg=_effective_config())

    assert outcome.promoted is False
    assert repo.persisted == []


# --------------------------------------------------------------------------- #
# Defensive re-assertion and batch behaviour.
# --------------------------------------------------------------------------- #


def test_wrong_project_row_raises() -> None:
    lookup = _FakeLookup()
    row = _row(
        1,
        provenance=Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(_run(_ORIGIN),)),
        project_id=OTHER_PROJECT,
    )
    repo = _FakeRepo([row])
    worker = _worker(lookup, repo, FakeClock(EPOCH))
    with pytest.raises(TracebedError):
        worker.evaluate_one(PROJECT, row, cfg=_effective_config())


@pytest.mark.parametrize("status", [Status.CANDIDATE, Status.VALIDATED, Status.STALE])
def test_non_quarantined_row_raises(status: Status) -> None:
    """Matched on the worker's OWN message, not merely on `TracebedError`.

    `apply(<anything but quarantined>, candidate)` is an illegal edge, and
    `IllegalTransition` is itself a `TracebedError` -- so a bare `pytest.raises(
    TracebedError)` stays green with the defensive re-assertion deleted outright, and says
    nothing about whether an over-returning select is caught BEFORE the state machine is
    asked to judge an edge the row is not on. Verified by mutation: `if row.status is not
    Status.QUARANTINED` -> `if False` left the untightened version passing."""
    lookup = _FakeLookup()
    row = _row(
        1,
        provenance=Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(_run(_ORIGIN),)),
        status=status,
    )
    repo = _FakeRepo([row])
    worker = _worker(lookup, repo, FakeClock(EPOCH))
    with pytest.raises(TracebedError, match="not 'quarantined'"):
        worker.evaluate_one(PROJECT, row, cfg=_effective_config())


def test_run_once_processes_every_quarantined_row() -> None:
    lookup = _FakeLookup()
    lookup.add(_run(1), _principal(1), cluster=_CLUSTER_A)
    lookup.add(_run(2), _principal(2), cluster=_CLUSTER_B)
    promotable = _row(
        1,
        provenance=Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(_run(_ORIGIN),)),
        confirming_run_ids=(_run(1), _run(2)),
    )
    stuck = _row(
        2,
        provenance=Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(_run(_ORIGIN),)),
        confirming_run_ids=(_run(1),),
    )
    repo = _FakeRepo([promotable, stuck])
    worker = _worker(lookup, repo, FakeClock(EPOCH))

    result = worker.run_once(PROJECT, cfg=_effective_config())

    assert result.rows_examined == 2
    promoted_ids = {o.memory_id for o in result.outcomes if o.promoted}
    assert promoted_ids == {promotable.id}
    assert len(repo.persisted) == 1


# --------------------------------------------------------------------------- #
# A memory cannot corroborate itself (`origin_runs`). Without this, quarantine is
# a formality for exactly the two classes it exists to hold.
# --------------------------------------------------------------------------- #


def test_failure_lesson_is_not_confirmed_by_its_own_origin_trace() -> None:
    """The sharpest version: `promotion.failure_lesson_outcomes` is 1, and a distiller
    memory's provenance ALWAYS names at least one trace (invariant 6). If that trace counts
    as its own confirmation, every quarantined failure lesson exits quarantine on the first
    sweep after it is written, having been confirmed by nothing at all."""
    lookup = _FakeLookup()
    lookup.add(_run(_ORIGIN), _principal(1), cluster=_CLUSTER_A)
    row = _row(
        1,
        provenance=Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(_run(_ORIGIN),)),
        mem_type=MemType.LESSON,
        is_failure_lesson=True,
        confirming_run_ids=(_run(_ORIGIN),),  # a store that folded provenance.trace_ids in
    )
    repo = _FakeRepo([row])
    worker = _worker(lookup, repo, FakeClock(EPOCH))

    outcome = worker.evaluate_one(PROJECT, row, cfg=_effective_config())

    assert outcome.promoted is False
    assert outcome.independent_count == 0
    assert repo.persisted == []


def test_multi_trace_distillation_is_not_its_own_shadow_confirmation() -> None:
    """A distiller batch over two traces that genuinely differ in principal AND in
    input-signature cluster would clear the corroboration arithmetic at the instant the
    memory was created -- zero evidence that arrived after the content existed. The
    distillation inputs are provenance, not confirmation."""
    lookup = _FakeLookup()
    lookup.add(_run(_ORIGIN), _principal(1), cluster=_CLUSTER_A)
    lookup.add(_run(_ORIGIN + 1), _principal(2), cluster=_CLUSTER_B)
    row = _row(
        1,
        provenance=Provenance(
            cls=ProvenanceClass.DISTILLER,
            trace_ids=(_run(_ORIGIN), _run(_ORIGIN + 1)),
        ),
        mem_type=MemType.SEMANTIC,
        confirming_run_ids=(_run(_ORIGIN), _run(_ORIGIN + 1)),
    )
    repo = _FakeRepo([row])
    worker = _worker(lookup, repo, FakeClock(EPOCH))

    outcome = worker.evaluate_one(PROJECT, row, cfg=_effective_config())

    assert outcome.promoted is False
    assert outcome.independent_count == 0
    assert repo.persisted == []


def test_one_genuine_external_run_still_promotes_a_failure_lesson() -> None:
    """The exclusion must not make the relaxation unusable: one run that is NOT an origin
    run is exactly the "1 run for failure lessons" PLAN.md §5 row 4 allows."""
    lookup = _FakeLookup()
    lookup.add(_run(_ORIGIN), _principal(1), cluster=_CLUSTER_A)
    lookup.add(_run(5), _principal(2), cluster=_CLUSTER_B)
    row = _row(
        1,
        provenance=Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(_run(_ORIGIN),)),
        mem_type=MemType.LESSON,
        is_failure_lesson=True,
        confirming_run_ids=(_run(_ORIGIN), _run(5)),
    )
    repo = _FakeRepo([row])
    worker = _worker(lookup, repo, FakeClock(EPOCH))

    outcome = worker.evaluate_one(PROJECT, row, cfg=_effective_config())

    assert outcome.promoted is True
    assert outcome.independent_count == 1


@pytest.mark.parametrize(
    "replay_principal,replay_cluster",
    [
        (1, _CLUSTER_A),  # same principal, same wording -- a verbatim replay
        (1, _CLUSTER_B),  # same principal, different wording
        (2, _CLUSTER_A),  # different principal, same wording
    ],
)
def test_failure_lesson_is_not_confirmed_by_a_replay_of_its_own_origin(
    replay_principal: int, replay_cluster: int
) -> None:
    """Red-team probe 4 (correlated-trace corroboration) in its n=1 form.

    `promotion.failure_lesson_outcomes` is 1, and pairwise independence over a set of ONE
    confirmation is vacuous -- the guard's clique search returns 1 for any single
    confirmation whatsoever. So excluding the origin `run_id` alone leaves the entire
    failure-lesson class exitable by re-running the same input under the same identity: a
    different run id, so id-exclusion passes it, and quarantine is cleared by a verbatim
    replay of the run the memory was distilled out of.

    All three parametrisations must refuse, because D-020's predicate is a conjunction:
    distinct principal AND distinct input-signature cluster. Sharing either one with the
    origin makes the "confirmation" the same observation again.
    """
    lookup = _FakeLookup()
    lookup.add(_run(_ORIGIN), _principal(1), cluster=_CLUSTER_A)
    lookup.add(_run(5), _principal(replay_principal), cluster=replay_cluster)
    row = _row(
        1,
        provenance=Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(_run(_ORIGIN),)),
        mem_type=MemType.LESSON,
        is_failure_lesson=True,
        confirming_run_ids=(_run(5),),
    )
    repo = _FakeRepo([row])
    worker = _worker(lookup, repo, FakeClock(EPOCH))

    outcome = worker.evaluate_one(PROJECT, row, cfg=_effective_config())

    assert outcome.promoted is False
    assert outcome.independent_count == 0
    assert repo.persisted == []


def test_correlation_with_any_single_origin_is_enough_to_discard_a_confirmation() -> None:
    """A distiller batch has SEVERAL origin runs, and a confirmation only has to repeat one
    of them to be a repeat. Run 5 here is independent of origin A and a verbatim replay of
    origin B; treating "independent of at least one origin" as sufficient would let the
    replay through -- and every other fixture in this file has exactly one origin, so the
    all/any distinction is invisible without two."""
    lookup = _FakeLookup()
    lookup.add(_run(_ORIGIN), _principal(1), cluster=_CLUSTER_A)
    lookup.add(_run(_ORIGIN + 1), _principal(2), cluster=_CLUSTER_B)
    lookup.add(_run(5), _principal(2), cluster=_CLUSTER_B)  # a replay of the SECOND origin
    row = _row(
        1,
        provenance=Provenance(
            cls=ProvenanceClass.DISTILLER,
            trace_ids=(_run(_ORIGIN), _run(_ORIGIN + 1)),
        ),
        mem_type=MemType.LESSON,
        is_failure_lesson=True,
        confirming_run_ids=(_run(5),),
    )
    repo = _FakeRepo([row])
    worker = _worker(lookup, repo, FakeClock(EPOCH))

    outcome = worker.evaluate_one(PROJECT, row, cfg=_effective_config())

    assert outcome.promoted is False
    assert outcome.independent_count == 0
    assert repo.persisted == []


def test_a_confirmation_correlated_with_the_origin_does_not_count_toward_two() -> None:
    """The same hole at the default threshold. {replay-of-origin, genuinely-new} scores 2 on
    pairwise independence among the confirmations alone, while containing exactly ONE
    observation that arrived after the content existed."""
    lookup = _FakeLookup()
    lookup.add(_run(_ORIGIN), _principal(1), cluster=_CLUSTER_A)
    lookup.add(_run(5), _principal(1), cluster=_CLUSTER_A)  # replay of the origin run
    lookup.add(_run(6), _principal(2), cluster=_far_cluster(3))  # a genuine second observation
    row = _row(
        1,
        provenance=Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(_run(_ORIGIN),)),
        mem_type=MemType.SEMANTIC,
        confirming_run_ids=(_run(5), _run(6)),
    )
    repo = _FakeRepo([row])
    worker = _worker(lookup, repo, FakeClock(EPOCH))

    outcome = worker.evaluate_one(PROJECT, row, cfg=_effective_config())

    assert outcome.promoted is False
    assert outcome.independent_count == 1
    assert repo.persisted == []


def test_two_genuinely_independent_confirmations_still_promote_past_the_origin_filter() -> None:
    """The origin-correlation filter must not swallow real corroboration: two runs that are
    independent of each other AND of the origin still clear the threshold."""
    lookup = _FakeLookup()
    lookup.add(_run(_ORIGIN), _principal(1), cluster=_CLUSTER_A)
    lookup.add(_run(5), _principal(2), cluster=_CLUSTER_B)
    lookup.add(_run(6), _principal(3), cluster=_far_cluster(3))
    row = _row(
        1,
        provenance=Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(_run(_ORIGIN),)),
        mem_type=MemType.SEMANTIC,
        confirming_run_ids=(_run(5), _run(6)),
    )
    repo = _FakeRepo([row])
    worker = _worker(lookup, repo, FakeClock(EPOCH))

    outcome = worker.evaluate_one(PROJECT, row, cfg=_effective_config())

    assert outcome.promoted is True
    assert outcome.independent_count == 2


def test_an_unresolvable_origin_does_not_freeze_promotion() -> None:
    """An origin run with no `trace_index` row says nothing about its principal or its
    wording, so it cannot mark anything as correlated. Refusing every confirmation on an
    unresolvable origin would turn an incomplete trace index into a project-wide promotion
    freeze -- the id-exclusion (which needs no lookup) still applies."""
    lookup = _FakeLookup()  # deliberately no row for _ORIGIN
    lookup.add(_run(5), _principal(2), cluster=_CLUSTER_B)
    row = _row(
        1,
        provenance=Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(_run(_ORIGIN),)),
        mem_type=MemType.LESSON,
        is_failure_lesson=True,
        confirming_run_ids=(_run(5),),
    )
    repo = _FakeRepo([row])
    worker = _worker(lookup, repo, FakeClock(EPOCH))

    assert worker.evaluate_one(PROJECT, row, cfg=_effective_config()).promoted is True


def test_no_offered_runs_means_no_lookups_at_all() -> None:
    """A quarantined row whose only listed confirming runs ARE its origins must not schedule
    a `trace_index` read per origin on every sweep for its whole 30-day quarantine TTL."""
    lookup = _FakeLookup()
    lookup.add(_run(_ORIGIN), _principal(1), cluster=_CLUSTER_A)
    row = _row(
        1,
        provenance=Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(_run(_ORIGIN),)),
        confirming_run_ids=(_run(_ORIGIN),),
    )
    repo = _FakeRepo([row])
    worker = _worker(lookup, repo, FakeClock(EPOCH))

    assert worker.evaluate_one(PROJECT, row, cfg=_effective_config()).promoted is False
    assert lookup.calls == []


def test_origin_runs_covers_trace_ids_and_the_proposal_run_id() -> None:
    assert origin_runs(
        Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(_run(1), _run(2)))
    ) == frozenset({_run(1), _run(2)})
    assert origin_runs(Provenance(cls=ProvenanceClass.PROPOSAL, run_id=_run(3))) == frozenset(
        {_run(3)}
    )
    assert origin_runs(Provenance(cls=ProvenanceClass.HUMAN_VERDICT, verdict_id=uuid4())) == (
        frozenset()
    )


def test_proposal_resolves_no_confirmations_at_all() -> None:
    """D-023 makes the class dispositive, so a proposal must not be able to schedule a
    `trace_index` read per offered run on every sweep for its whole quarantine TTL."""
    lookup = _FakeLookup()
    for i in range(20):
        lookup.add(_run(i), _principal(i), cluster=_far_cluster(i))
    row = _row(
        1,
        provenance=Provenance(cls=ProvenanceClass.PROPOSAL, run_id=_run(1)),
        confirming_run_ids=tuple(_run(i) for i in range(20)),
    )
    repo = _FakeRepo([row])
    worker = _worker(lookup, repo, FakeClock(EPOCH))

    outcome = worker.evaluate_one(PROJECT, row, cfg=_effective_config())

    assert outcome.promoted is False
    assert lookup.calls == []


# --------------------------------------------------------------------------- #
# Epoch stamping and the verdict record behind the human-verdict skip.
# --------------------------------------------------------------------------- #


def test_shadow_confirmation_records_the_scoring_epoch() -> None:
    """PLAN.md §5, `scoring_epoch`: "every Q update and shadow confirmation records
    epoch_id"."""
    lookup = _FakeLookup()
    lookup.add(_run(1), _principal(1), cluster=_CLUSTER_A)
    lookup.add(_run(2), _principal(2), cluster=_CLUSTER_B)
    row = _row(
        1,
        provenance=Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(_run(_ORIGIN),)),
        confirming_run_ids=(_run(1), _run(2)),
    )
    repo = _FakeRepo([row])
    worker = _worker(lookup, repo, FakeClock(EPOCH))

    worker.evaluate_one(PROJECT, row, cfg=_effective_config())

    assert repo.persisted[0].epoch_id == _EPOCH_ROW.epoch_id


def test_human_verdict_class_without_a_verdict_id_is_not_a_skip() -> None:
    """`Provenance.from_json` rehydrates whatever is on disk; `validate_provenance` only
    ran at insert. A class label with no verdict behind it is not a verified human
    verdict, and must not buy a zero-evidence exit from quarantine."""
    lookup = _FakeLookup()
    row = _row(
        1,
        provenance=Provenance(cls=ProvenanceClass.HUMAN_VERDICT, verdict_id=None),
        confirming_run_ids=(),
    )
    repo = _FakeRepo([row])
    worker = _worker(lookup, repo, FakeClock(EPOCH))

    outcome = worker.evaluate_one(PROJECT, row, cfg=_effective_config())

    assert outcome.promoted is False
    assert repo.persisted == []
