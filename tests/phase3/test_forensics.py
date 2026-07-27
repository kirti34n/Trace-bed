"""`workers.forensics` — Recall & Rollback (PLAN.md §8 improvement 1; CUTTABLE).

Fully offline. `_FakeForensicsRepo` holds an in-memory `memory_link` graph
(`parent -> {direct children}`) and an `injection_log`/`outcome_event` projection, so the
gate scenario — a poisoned memory injected into 12 runs with 3 generations of derived
descendants — is built directly rather than through any store.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from uuid import uuid4

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
from tracebed.domain.errors import TracebedError
from tracebed.domain.ids import MemoryId, ProjectId, RunId, mint_run_id
from tracebed.domain.memory import Provenance
from tracebed.domain.state_machine import Status, TransitionLimits
from tracebed.workers import forensics as forensics_module
from tracebed.workers.edit_ops import EditableMemory, MemoryStatusWrite
from tracebed.workers.forensics import Forensics, OutcomeEventRef
from tracebed.workers.review_queue import ReviewQueue, reversible_containment_targets

pytestmark = pytest.mark.phase3

PROJECT = ProjectId(uuid4())
EPOCH = datetime(2026, 1, 1, tzinfo=UTC)


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


def _mid() -> MemoryId:
    return MemoryId(uuid4())


def _row(memory_id: MemoryId, *, status: Status) -> EditableMemory:
    return EditableMemory(
        id=memory_id,
        project_id=PROJECT,
        status=status,
        trust_tier=TrustTier.B,
        mem_type=MemType.LESSON,
        provenance=Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(mint_run_id(),)),
        status_changed_at=EPOCH,
        subject_tag=None,
    )


class _FakeForensicsRepo:
    def __init__(self, rows: list[EditableMemory]) -> None:
        self._rows: dict[MemoryId, EditableMemory] = {r.id: r for r in rows}
        self.persisted: list[MemoryStatusWrite] = []
        self.injections: dict[MemoryId, tuple[RunId, ...]] = {}
        self.links: dict[MemoryId, tuple[MemoryId, ...]] = {}
        """parent memory_id -> direct children (memory_link relation='derived_from',
        dst_id=parent, src_id=child)."""
        self.outcomes: dict[RunId, tuple[OutcomeEventRef, ...]] = {}

    def get_memory_by_id(self, project_id: ProjectId, memory_id: MemoryId) -> EditableMemory:
        return self._rows[memory_id]

    def persist_status(self, project_id: ProjectId, write: MemoryStatusWrite) -> None:
        self.persisted.append(write)
        old = self._rows[write.memory_id]
        self._rows[write.memory_id] = EditableMemory(
            id=old.id,
            project_id=old.project_id,
            status=write.to_status,
            trust_tier=old.trust_tier,
            mem_type=old.mem_type,
            provenance=old.provenance,
            status_changed_at=write.now,
            subject_tag=old.subject_tag,
        )

    def list_runs_injected_with(self, project_id: ProjectId, memory_id: MemoryId) -> Sequence[RunId]:
        return self.injections.get(memory_id, ())

    def list_direct_derived_descendants(
        self, project_id: ProjectId, memory_id: MemoryId
    ) -> Sequence[MemoryId]:
        return self.links.get(memory_id, ())

    def list_outcome_events_for_runs(
        self, project_id: ProjectId, run_ids: Sequence[RunId]
    ) -> Sequence[OutcomeEventRef]:
        out: list[OutcomeEventRef] = []
        for run_id in run_ids:
            out.extend(self.outcomes.get(run_id, ()))
        return out


class _FakeReviewRepo:
    def __init__(self) -> None:
        self.calls: list[tuple[ProjectId, str, MemoryId | None]] = []

    def insert_review_item(self, project_id: ProjectId, reason: str, memory_id: MemoryId | None = None) -> None:
        self.calls.append((project_id, reason, memory_id))


def _three_generations(
    repo: _FakeForensicsRepo, poisoned: MemoryId
) -> tuple[list[MemoryId], list[MemoryId], list[MemoryId]]:
    """Wires a 3-generation `derived_from` chain under `poisoned`: 2 first-generation
    children, each with 2 second-generation children, each with 1 third-generation child
    (2 + 4 + 4 = 10 descendants total)."""
    gen1 = [_mid(), _mid()]
    for m in gen1:
        repo._rows[m] = _row(m, status=Status.VALIDATED)
    repo.links[poisoned] = tuple(gen1)

    gen2: list[MemoryId] = []
    for parent in gen1:
        children = [_mid(), _mid()]
        for m in children:
            repo._rows[m] = _row(m, status=Status.VALIDATED)
        repo.links[parent] = tuple(children)
        gen2.extend(children)

    gen3: list[MemoryId] = []
    for parent in gen2:
        child = _mid()
        repo._rows[child] = _row(child, status=Status.VALIDATED)
        repo.links[parent] = (child,)
        gen3.append(child)

    return gen1, gen2, gen3


def test_recall_and_rollback_finds_every_run_and_every_transitive_descendant() -> None:
    poisoned = _mid()
    repo = _FakeForensicsRepo([_row(poisoned, status=Status.VALIDATED)])
    gen1, gen2, gen3 = _three_generations(repo, poisoned)

    runs = [mint_run_id() for _ in range(12)]
    repo.injections[poisoned] = tuple(runs)
    repo.outcomes = {
        run_id: (OutcomeEventRef(event_id=uuid4(), run_id=run_id),) for run_id in runs
    }

    review_repo = _FakeReviewRepo()
    review_queue = ReviewQueue(review_repo, FakeClock(EPOCH))
    forensics = Forensics(repo, FakeClock(EPOCH), review_queue=review_queue)
    cfg = _effective_config()

    report = forensics.recall_and_rollback(PROJECT, poisoned, cfg=cfg)

    assert report.from_status is Status.VALIDATED
    assert report.already_contained is False
    assert report.contained_status is Status.STALE  # nearest legal edge for a validated row
    # The containment does NOT hold on its own, and the report says so as data.
    assert report.containment_reversible_by == (Status.VALIDATED,)
    assert set(report.affected_run_ids) == set(runs)
    assert len(report.affected_run_ids) == 12

    all_descendants = set(gen1) | set(gen2) | set(gen3)
    assert set(report.descendant_memory_ids) == all_descendants
    assert len(all_descendants) == 10
    # The transitive third generation specifically — a one-hop implementation would miss
    # every id in gen2 and gen3.
    for third_gen_id in gen3:
        assert third_gen_id in report.descendant_memory_ids

    assert len(report.reopened_outcomes) == 12
    assert {ref.run_id for ref in report.reopened_outcomes} == set(runs)

    # The containment write actually went through apply(): recorded exactly once, from
    # VALIDATED to STALE.
    assert len(repo.persisted) == 1
    assert repo.persisted[0].from_status is Status.VALIDATED
    assert repo.persisted[0].to_status is Status.STALE
    assert repo.get_memory_by_id(PROJECT, poisoned).status is Status.STALE

    assert report.descendants_truncated is False

    # Every descendant and every reopened outcome was also flagged for a human, plus one
    # row for the contained memory itself.
    reasons = [reason for _pid, reason, _mid_ in review_repo.calls]
    assert sum(str(d) in " ".join(reasons) for d in all_descendants) == len(all_descendants)
    assert len(review_repo.calls) == 1 + len(runs) + len(all_descendants)
    contained_rows = [r for r in reasons if r.startswith("contained memory")]
    assert len(contained_rows) == 1
    assert str(poisoned) in contained_rows[0]
    assert "10 derived descendant(s) across 12 affected run(s)" in contained_rows[0]


def test_the_contained_memory_itself_gets_a_review_row_warning_that_stale_is_reversible() -> None:
    """`domain.state_machine` has no `validated -> quarantined` edge, so containment lands
    on `stale` — and `stale -> validated` is a real edge `workers.revalidation.check_stale`
    takes unattended. A human has to be told the containment can be undone, and the
    warning is derived from the live TRANSITIONS table, not hardcoded."""
    poisoned = _mid()
    repo = _FakeForensicsRepo([_row(poisoned, status=Status.VALIDATED)])
    review_repo = _FakeReviewRepo()
    forensics = Forensics(
        repo, FakeClock(EPOCH), review_queue=ReviewQueue(review_repo, FakeClock(EPOCH))
    )

    forensics.recall_and_rollback(PROJECT, poisoned, cfg=_effective_config())

    assert len(review_repo.calls) == 1
    _pid, reason, mid = review_repo.calls[0]
    assert mid == poisoned
    assert "'validated' -> 'stale'" in reason
    assert "reversible" in reason
    assert "validated" in reason.split("retrievable status(es)")[1]

    limits = TransitionLimits.from_config(_effective_config())
    assert reversible_containment_targets(Status.STALE, limits=limits, now=EPOCH) == (
        Status.VALIDATED,
    )


def test_a_superseded_containment_would_carry_no_reversibility_warning() -> None:
    """The other half of the warning's meaning: it is probed through `apply()`, so a
    status with no legal route back into retrievability produces no warning at all.
    `superseded` is that status today — if the transition table ever grows an edge out of
    it into a retrievable status, this test fails and the warning starts firing for it
    automatically."""
    cfg = _effective_config()
    limits = TransitionLimits.from_config(cfg)
    assert reversible_containment_targets(Status.SUPERSEDED, limits=limits, now=EPOCH) == ()
    assert reversible_containment_targets(Status.TOMBSTONED, limits=limits, now=EPOCH) == ()
    # …and quarantine itself is reversible (that is what quarantine is for), so the probe
    # is not merely returning () for everything that is not `stale`.
    assert reversible_containment_targets(Status.QUARANTINED, limits=limits, now=EPOCH) == (
        Status.CANDIDATE,
    )

    repo = _FakeReviewRepo()
    ReviewQueue(repo, FakeClock(EPOCH)).flag_contained_memory(
        PROJECT,
        memory_id=_mid(),
        from_status=Status.VALIDATED,
        contained_status=Status.SUPERSEDED,
        already_contained=False,
        affected_run_count=0,
        descendant_count=0,
        descendants_truncated=False,
        cfg=cfg,
    )
    assert "reversible" not in repo.calls[0][1]


def test_an_already_contained_memory_still_gets_a_review_row() -> None:
    """Containment that was a no-op is exactly the case a human most needs told: the
    memory is poisoned and nothing changed."""
    memory_id = _mid()
    repo = _FakeForensicsRepo([_row(memory_id, status=Status.STALE)])
    review_repo = _FakeReviewRepo()
    forensics = Forensics(
        repo, FakeClock(EPOCH), review_queue=ReviewQueue(review_repo, FakeClock(EPOCH))
    )

    report = forensics.recall_and_rollback(PROJECT, memory_id, cfg=_effective_config())

    assert report.already_contained is True
    assert len(review_repo.calls) == 1
    assert "was already outside the retrievable statuses" in review_repo.calls[0][1]


def test_a_truncated_descendant_walk_says_so_in_the_report_and_in_the_review_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The finding this test exists for: an under-reported blast radius that reads as a
    complete one is worse than none, because every id in it is real and nothing about it
    looks wrong."""
    poisoned = _mid()
    repo = _FakeForensicsRepo([_row(poisoned, status=Status.VALIDATED)])
    _gen1, _gen2, _gen3 = _three_generations(repo, poisoned)

    monkeypatch.setattr(forensics_module, "MAX_DESCENDANTS_CONSIDERED", 3)
    review_repo = _FakeReviewRepo()
    forensics = Forensics(
        repo, FakeClock(EPOCH), review_queue=ReviewQueue(review_repo, FakeClock(EPOCH))
    )

    report = forensics.recall_and_rollback(PROJECT, poisoned, cfg=_effective_config())

    assert len(report.descendant_memory_ids) == 3  # of 10 that really exist
    assert report.descendants_truncated is True
    contained = next(r for _p, r, _m in review_repo.calls if r.startswith("contained memory"))
    assert "at least 3 derived descendant(s)" in contained
    assert "INCOMPLETE" in contained


def test_a_generation_bounded_walk_is_also_reported_as_truncated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    poisoned = _mid()
    repo = _FakeForensicsRepo([_row(poisoned, status=Status.VALIDATED)])
    gen1, _gen2, _gen3 = _three_generations(repo, poisoned)

    monkeypatch.setattr(forensics_module, "MAX_GENERATIONS_CONSIDERED", 1)
    forensics = Forensics(repo, FakeClock(EPOCH))
    report = forensics.recall_and_rollback(PROJECT, poisoned, cfg=_effective_config())

    assert set(report.descendant_memory_ids) == set(gen1)
    assert report.descendants_truncated is True


def test_a_walk_that_exhausts_the_graph_exactly_on_the_bound_is_not_truncated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The case a `len(descendants) >= BOUND` heuristic would get wrong in the direction
    that matters: complete, but reported incomplete."""
    poisoned = _mid()
    repo = _FakeForensicsRepo([_row(poisoned, status=Status.VALIDATED)])
    children = [_mid(), _mid()]
    for child in children:
        repo._rows[child] = _row(child, status=Status.VALIDATED)
    repo.links[poisoned] = tuple(children)

    monkeypatch.setattr(forensics_module, "MAX_DESCENDANTS_CONSIDERED", 2)
    forensics = Forensics(repo, FakeClock(EPOCH))
    report = forensics.recall_and_rollback(PROJECT, poisoned, cfg=_effective_config())

    assert set(report.descendant_memory_ids) == set(children)
    assert report.descendants_truncated is False


def test_forensics_refuses_a_foreign_project_row() -> None:
    """Invariant 4: the defensive re-check on a row the store handed back."""
    foreign_id = _mid()
    foreign = EditableMemory(
        id=foreign_id,
        project_id=ProjectId(uuid4()),
        status=Status.VALIDATED,
        trust_tier=TrustTier.B,
        mem_type=MemType.LESSON,
        provenance=Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(mint_run_id(),)),
        status_changed_at=EPOCH,
        subject_tag=None,
    )
    repo = _FakeForensicsRepo([foreign])
    forensics = Forensics(repo, FakeClock(EPOCH))

    with pytest.raises(TracebedError, match="invariant 4"):
        forensics.recall_and_rollback(PROJECT, foreign_id, cfg=_effective_config())

    assert repo.persisted == []


def test_duplicate_injection_rows_do_not_inflate_the_blast_radius() -> None:
    """Inflating a blast radius is the same class of lie as truncating one: a duplicated
    `injection_log` row would double every re-opened outcome and every review entry."""
    poisoned = _mid()
    repo = _FakeForensicsRepo([_row(poisoned, status=Status.VALIDATED)])
    run_id = mint_run_id()
    repo.injections[poisoned] = (run_id, run_id, run_id)
    repo.outcomes = {run_id: (OutcomeEventRef(event_id=uuid4(), run_id=run_id),)}

    review_repo = _FakeReviewRepo()
    forensics = Forensics(
        repo, FakeClock(EPOCH), review_queue=ReviewQueue(review_repo, FakeClock(EPOCH))
    )
    report = forensics.recall_and_rollback(PROJECT, poisoned, cfg=_effective_config())

    assert report.affected_run_ids == (run_id,)
    assert len(report.reopened_outcomes) == 1
    assert len(review_repo.calls) == 2  # the contained memory + one reopened outcome


def test_recall_and_rollback_reports_an_empty_radius_for_an_uninjected_memory() -> None:
    """"Assert a memory with no injections reports an empty radius rather than failing."""
    clean = _mid()
    repo = _FakeForensicsRepo([_row(clean, status=Status.VALIDATED)])
    forensics = Forensics(repo, FakeClock(EPOCH))  # no review_queue at all
    cfg = _effective_config()

    report = forensics.recall_and_rollback(PROJECT, clean, cfg=cfg)

    assert report.affected_run_ids == ()
    assert report.descendant_memory_ids == ()
    assert report.reopened_outcomes == ()
    # Containment still ran (validated -> stale) — the empty radius is about the blast
    # radius, not about whether the memory itself was touched.
    assert report.contained_status is Status.STALE


@pytest.mark.parametrize(
    ("start_status", "expected_target"),
    [
        (Status.CANDIDATE, Status.QUARANTINED),
        (Status.VALIDATED, Status.STALE),
        (Status.PINNED, Status.TOMBSTONED),
    ],
)
def test_contain_uses_the_nearest_legal_edge_per_status(
    start_status: Status, expected_target: Status
) -> None:
    memory_id = _mid()
    repo = _FakeForensicsRepo([_row(memory_id, status=start_status)])
    forensics = Forensics(repo, FakeClock(EPOCH))
    cfg = _effective_config()

    report = forensics.recall_and_rollback(PROJECT, memory_id, cfg=cfg)

    assert report.already_contained is False
    assert report.contained_status is expected_target
    assert repo.get_memory_by_id(PROJECT, memory_id).status is expected_target


@pytest.mark.parametrize(
    "already_status",
    [Status.QUARANTINED, Status.STALE, Status.SUPERSEDED, Status.RETIRED, Status.ARCHIVED, Status.TOMBSTONED],
)
def test_already_non_retrievable_memory_is_reported_contained_without_a_write(
    already_status: Status,
) -> None:
    memory_id = _mid()
    repo = _FakeForensicsRepo([_row(memory_id, status=already_status)])
    forensics = Forensics(repo, FakeClock(EPOCH))
    cfg = _effective_config()

    report = forensics.recall_and_rollback(PROJECT, memory_id, cfg=cfg)

    assert report.already_contained is True
    assert report.contained_status is already_status
    assert repo.persisted == []


def test_the_report_carries_the_incomplete_containment_as_data_not_only_as_prose() -> None:
    """A caller that must not act on an incomplete containment has to be able to TEST for
    it. `containment_reversible_by` is that test; the `review_queue` reason text says the
    same thing to a human but nothing can branch on prose, and `review_queue` has no
    read-back path at all today.

    Asserted as a PROPERTY against `apply()` rather than against a hardcoded status, so
    the day `domain.state_machine` grows a `validated -> quarantined` edge (or drops
    `stale -> validated`) this test tracks the machine instead of pinning a stale answer.
    """
    poisoned = _mid()
    repo = _FakeForensicsRepo([_row(poisoned, status=Status.VALIDATED)])
    forensics = Forensics(repo, FakeClock(EPOCH))
    cfg = _effective_config()

    report = forensics.recall_and_rollback(PROJECT, poisoned, cfg=cfg)

    limits = TransitionLimits.from_config(cfg)
    assert report.containment_reversible_by == reversible_containment_targets(
        report.contained_status, limits=limits, now=EPOCH
    )
    # And the substantive claim the field exists to make: containment at `stale` is
    # undone by `workers.revalidation.check_stale` with no human in the loop, so this is
    # NOT empty. If it ever becomes empty, the containment finally holds.
    assert report.containment_reversible_by != ()


def test_a_pinned_memorys_containment_is_reported_as_holding() -> None:
    """The other side of the same field: `pinned -> tombstoned` is terminal, so nothing
    can walk it back and the field is empty. Without this, a caller could not tell whether
    an empty tuple ever happens at all."""
    memory_id = _mid()
    repo = _FakeForensicsRepo([_row(memory_id, status=Status.PINNED)])
    forensics = Forensics(repo, FakeClock(EPOCH))

    report = forensics.recall_and_rollback(PROJECT, memory_id, cfg=_effective_config())

    assert report.contained_status is Status.TOMBSTONED
    assert report.containment_reversible_by == ()


def test_duplicate_outcome_rows_do_not_double_the_reopened_outcomes() -> None:
    """`list_runs_injected_with` is de-duplicated on the way in, but the outcome query is
    a second, independent store call: a join that fans out (one `outcome_event` reachable
    through two index paths) hands back the same `(event_id, run_id)` twice. Un-deduped,
    that opened two review rows for one outcome and reported a blast radius twice its real
    size -- the inflation half of the same lie truncation is the deflation half of."""
    poisoned = _mid()
    repo = _FakeForensicsRepo([_row(poisoned, status=Status.VALIDATED)])
    run_id = mint_run_id()
    repo.injections[poisoned] = (run_id,)
    ref = OutcomeEventRef(event_id=uuid4(), run_id=run_id)
    repo.outcomes = {run_id: (ref, ref, ref)}

    review_repo = _FakeReviewRepo()
    forensics = Forensics(
        repo, FakeClock(EPOCH), review_queue=ReviewQueue(review_repo, FakeClock(EPOCH))
    )
    report = forensics.recall_and_rollback(PROJECT, poisoned, cfg=_effective_config())

    assert report.reopened_outcomes == (ref,)
    assert len(review_repo.calls) == 2  # the contained memory + exactly one reopened outcome


def test_an_outcome_for_a_run_outside_the_radius_is_refused() -> None:
    """The same store-output discipline `_require_project` applies to memory rows and
    `edit_ops` applies to subject tags. An outcome attached to a run this memory was never
    injected into is not part of this blast radius; admitting it puts a review row naming
    an unrelated run in front of a human, and every id in that row is real, so nothing
    about it looks wrong."""
    poisoned = _mid()
    repo = _FakeForensicsRepo([_row(poisoned, status=Status.VALIDATED)])
    injected_run = mint_run_id()
    unrelated_run = mint_run_id()
    repo.injections[poisoned] = (injected_run,)
    repo.outcomes = {
        injected_run: (
            OutcomeEventRef(event_id=uuid4(), run_id=injected_run),
            OutcomeEventRef(event_id=uuid4(), run_id=unrelated_run),
        )
    }

    forensics = Forensics(repo, FakeClock(EPOCH))
    with pytest.raises(TracebedError, match="never injected into"):
        forensics.recall_and_rollback(PROJECT, poisoned, cfg=_effective_config())


def test_transitive_descendants_are_bounded_against_a_cycle() -> None:
    """A malformed `memory_link` cycle must degrade to a bounded, terminating result --
    never an infinite loop."""
    a, b = _mid(), _mid()
    repo = _FakeForensicsRepo([_row(a, status=Status.VALIDATED), _row(b, status=Status.VALIDATED)])
    repo.links[a] = (b,)
    repo.links[b] = (a,)  # cycle back to the root

    forensics = Forensics(repo, FakeClock(EPOCH))
    report = forensics.recall_and_rollback(PROJECT, a, cfg=_effective_config())

    assert report.descendant_memory_ids == (b,)
