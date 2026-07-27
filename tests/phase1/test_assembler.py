"""Budget packing, dedup, and placement (PLAN.md §6 `budget.*`; §7 Phase 1).

Every test here is pure and offline: `EffectiveConfig` is built directly from
the real Phase 0 section models (no fake with matching attribute names, so a
field rename in `domain/config.py` breaks this test rather than staying
silently green), and `Candidate` is constructed by hand -- no retriever, no
Postgres, no clock.
"""

from __future__ import annotations

from itertools import permutations
from uuid import uuid4

import pytest

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
from tracebed.domain.enums import MemType, Slot
from tracebed.domain.ids import MemoryId
from tracebed.hotpath.assembler import Candidate, assemble

pytestmark = pytest.mark.phase1


def _effective_config(**overrides: object) -> EffectiveConfig:
    """A real `EffectiveConfig` from the real section models (see
    `tests/phase0/test_state_machine.py::_effective_config` for the same
    pattern) -- binds these tests to the actual §3.4 field names/defaults."""
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


def _cand(
    *,
    slot: Slot,
    tokens: int,
    score: float,
    mem_type: MemType = MemType.LESSON,
    text: str | None = None,
    dedup_key: str | None = None,
    memory_id: MemoryId | None = None,
) -> Candidate:
    mid = memory_id if memory_id is not None else MemoryId(uuid4())
    return Candidate(
        slot=slot,
        memory_id=mid,
        mem_type=mem_type,
        text=text if text is not None else f"content for {mid}",
        tokens=tokens,
        score=score,
        dedup_key=dedup_key if dedup_key is not None else str(mid),
    )


# --------------------------------------------------------------------------- #
# Per-slot and shared-pool budget packing.
# --------------------------------------------------------------------------- #


def test_single_fact_within_cap_is_kept_whole() -> None:
    cfg = _effective_config()
    c = _cand(slot=Slot.FACT, tokens=100, score=1.0)
    result = assemble([c], cfg=cfg)

    assert len(result.slots) == 1
    assert result.slots[0].memory_id == c.memory_id.value
    assert result.slots[0].tokens == 100
    assert result.total_tokens == 100
    assert result.dropped_memory_ids == ()


def test_fact_slot_cap_binds_before_shared_dynamic_pool() -> None:
    """fact's own cap is 250 (well under the 500 shared dynamic pool), so
    with only fact candidates present, the per-slot cap is what binds."""
    cfg = _effective_config()
    candidates = [_cand(slot=Slot.FACT, tokens=100, score=float(10 - i)) for i in range(4)]
    result = assemble(candidates, cfg=cfg)

    fact_tokens = sum(s.tokens for s in result.slots if s.slot is Slot.FACT)
    assert fact_tokens <= cfg.budget.slot_caps["fact"]
    assert fact_tokens == 200  # two of the four 100-token candidates fit under 250


def test_shared_dynamic_pool_binds_across_slots() -> None:
    """Per-slot caps (250+150+100+100+150=750) sum to more than the shared
    `budget.dynamic` pool (500) -- PLAN.md §6 states the pool is what
    actually binds in the mixed case."""
    cfg = _effective_config()
    candidates = []
    for slot, per_slot_cap in cfg.budget.slot_caps.items():
        # One candidate per dynamic slot, sized to exactly fill that slot's
        # own cap -- if every slot cap were independently honoured, total
        # would be 750; the shared pool must cut this down to <= 500.
        candidates.append(_cand(slot=Slot(slot), tokens=per_slot_cap, score=1.0))

    result = assemble(candidates, cfg=cfg)
    dynamic_tokens = sum(s.tokens for s in result.slots if s.slot is not Slot.STATIC_PREFIX)
    assert dynamic_tokens <= cfg.budget.dynamic


def test_static_prefix_splits_into_prefs_and_lessons_sub_budgets() -> None:
    """Both sub-caps bind INDEPENDENTLY while the 700-token static pool still
    has room -- 300 tokens of prefs and 600 of lessons are offered against a
    pool that could hold 900 of the 900, so a single undivided 700-token pool
    would take 700 of them. Only the split produces exactly 200 + 500."""
    cfg = _effective_config()
    prefs = [
        _cand(slot=Slot.STATIC_PREFIX, tokens=100, score=float(3 - i), mem_type=MemType.PREFERENCE)
        for i in range(3)
    ]
    lessons = [
        _cand(slot=Slot.STATIC_PREFIX, tokens=100, score=float(6 - i), mem_type=MemType.LESSON)
        for i in range(6)
    ]
    result = assemble(prefs + lessons, cfg=cfg)

    pref_ids = {c.memory_id.value for c in prefs}
    selected_pref_tokens = sum(s.tokens for s in result.slots if s.memory_id in pref_ids)
    selected_lesson_tokens = sum(
        s.tokens
        for s in result.slots
        if s.slot is Slot.STATIC_PREFIX and s.memory_id not in pref_ids
    )
    assert selected_pref_tokens == cfg.budget.static_prefix_prefs == 200
    assert selected_lesson_tokens == cfg.budget.static_prefix_lessons == 500
    assert result.total_tokens == cfg.budget.static_prefix == 700


def test_prefs_over_their_sub_cap_are_truncated_at_the_cap_not_arbitrarily() -> None:
    cfg = _effective_config()
    # 3 x 100 = 300 tokens of prefs offered; static_prefix_prefs cap is 200.
    prefs = [_cand(slot=Slot.STATIC_PREFIX, tokens=100, score=float(3 - i), mem_type=MemType.PREFERENCE) for i in range(3)]
    result = assemble(prefs, cfg=cfg)

    prefs_tokens = sum(s.tokens for s in result.slots if s.slot is Slot.STATIC_PREFIX)
    assert prefs_tokens == cfg.budget.static_prefix_prefs  # exactly the configured cap, not less
    assert len(result.dropped_memory_ids) == 1  # the third, lowest-scoring pref


def test_lessons_get_remaining_static_budget_after_prefs() -> None:
    """lessons cap is min(static_prefix_lessons, static_prefix - prefs_used).

    prefs fill their full 200-token sub-cap, leaving 500 of the 700-token
    static_prefix pool for lessons -- exactly `static_prefix_lessons`'s own
    cap, so both limits agree here (a stronger test than either alone: it
    proves the two numbers PLAN.md §6 states, 700 and 500, are both actually
    read, not just one of them with the other inferred).
    """
    cfg = _effective_config()
    prefs = [_cand(slot=Slot.STATIC_PREFIX, tokens=200, score=1.0, mem_type=MemType.PREFERENCE)]
    # 6 x 100 = 600 tokens of lessons offered against a 500-token remaining
    # cap -- greedy fill takes 5 whole candidates (500) and drops the 6th.
    lessons = [
        _cand(slot=Slot.STATIC_PREFIX, tokens=100, score=float(6 - i), mem_type=MemType.LESSON)
        for i in range(6)
    ]
    result = assemble(prefs + lessons, cfg=cfg)

    lesson_slots = [
        s for s in result.slots if s.slot is Slot.STATIC_PREFIX and s.tokens != 200
    ]
    assert sum(s.tokens for s in lesson_slots) == cfg.budget.static_prefix_lessons == 500
    assert len(lesson_slots) == 5
    assert len(result.dropped_memory_ids) == 1  # the 6th, lowest-scoring lesson


def test_lessons_cap_is_reduced_by_what_prefs_already_spent() -> None:
    """`lessons_cap = min(static_prefix_lessons, static_prefix - prefs_used)`.

    Under the SHIPPED defaults this `min` is dead code: prefs can never spend
    more than 200 of the 700-token pool, so the remainder is always >= 500 ==
    `static_prefix_lessons` and the second term never binds. `budget.*` is
    overridable per project and per agent type, though, so the branch is
    live in production -- exercised here with a 300-token static pool, where
    200 spent on prefs leaves lessons 100 rather than their nominal 500.
    """
    cfg = _effective_config(
        budget=BudgetConfig(
            total_tokens=800,
            static_prefix=300,
            static_prefix_prefs=200,
            static_prefix_lessons=500,
            dynamic=500,
        )
    )
    prefs = [_cand(slot=Slot.STATIC_PREFIX, tokens=200, score=9.0, mem_type=MemType.PREFERENCE)]
    lessons = [
        _cand(slot=Slot.STATIC_PREFIX, tokens=50, score=float(4 - i), mem_type=MemType.LESSON)
        for i in range(4)
    ]
    result = assemble(prefs + lessons, cfg=cfg)

    pref_ids = {c.memory_id.value for c in prefs}
    lesson_tokens = sum(s.tokens for s in result.slots if s.memory_id not in pref_ids)
    assert lesson_tokens == 100  # 300-token pool minus the 200 prefs spent, not 500
    assert result.total_tokens == cfg.budget.static_prefix == 300
    assert len(result.dropped_memory_ids) == 2


def test_total_tokens_is_the_outer_bound_when_section_sums_disagree() -> None:
    """`total_tokens` is the budget the operator actually set; `static_prefix`
    and `dynamic` are its parts. Nothing in `BudgetConfig` validates that the
    parts sum to the whole, and both are independently overridable, so an
    operator lowering only `total_tokens` must still get a block within it --
    not an over-budget block, and not a crash on the hot path.
    """
    # total_tokens (150) is below even `static_prefix_prefs` (200), so the
    # outer bound has to bind on the prefs sub-budget itself -- not merely on
    # the dynamic pool, which a later clamp would catch anyway.
    cfg = _effective_config(
        budget=BudgetConfig(
            total_tokens=150,
            static_prefix=700,
            static_prefix_prefs=200,
            static_prefix_lessons=500,
            dynamic=500,
        )
    )
    candidates = [
        _cand(slot=Slot.STATIC_PREFIX, tokens=50, score=float(30 - i), mem_type=MemType.PREFERENCE)
        for i in range(10)
    ] + [_cand(slot=Slot.FACT, tokens=50, score=float(10 - i)) for i in range(10)]
    result = assemble(candidates, cfg=cfg)

    assert result.total_tokens == cfg.budget.total_tokens == 150
    assert sum(s.tokens for s in result.slots) == result.total_tokens


def test_slot_with_no_configured_cap_is_dropped_and_reported_never_a_crash() -> None:
    """`slot_caps` is a plain dict; a project override may replace it wholesale
    and omit a slot. Invariant 2 says a memory-layer problem degrades to less
    context, never to a failed retrieve -- so the unconfigured slot's
    candidates must be absent from `slots` AND present in
    `dropped_memory_ids`, where an operator can see the misconfiguration."""
    cfg = _effective_config(budget=BudgetConfig(slot_caps={"fact": 250}))
    fact = _cand(slot=Slot.FACT, tokens=10, score=1.0)
    orphan = _cand(slot=Slot.PITFALL, tokens=10, score=2.0)
    result = assemble([fact, orphan], cfg=cfg)

    assert [s.memory_id for s in result.slots] == [fact.memory_id.value]
    assert orphan.memory_id in result.dropped_memory_ids


def test_every_unselected_candidate_is_reported_as_dropped() -> None:
    """`dropped_memory_ids` is derived by subtraction, so no exclusion reason
    -- dedup, count cap, token cap, unconfigured slot -- can go unreported."""
    cfg = _effective_config()
    dupe = "shared-content-hash"
    candidates = [
        _cand(slot=Slot.FACT, tokens=10, score=0.1, dedup_key=dupe),
        _cand(slot=Slot.EXEMPLAR, tokens=10, score=0.9, dedup_key=dupe),
        _cand(slot=Slot.CANDIDATE_NOTE, tokens=10, score=0.8),
        _cand(slot=Slot.CANDIDATE_NOTE, tokens=10, score=0.7),
        *[_cand(slot=Slot.PITFALL, tokens=60, score=float(5 - i)) for i in range(5)],
    ]
    result = assemble(candidates, cfg=cfg)

    selected = {s.memory_id for s in result.slots}
    expected_dropped = {c.memory_id for c in candidates if c.memory_id.value not in selected}
    assert set(result.dropped_memory_ids) == expected_dropped
    assert len(selected) + len(result.dropped_memory_ids) == len(candidates)


def test_total_never_exceeds_total_tokens() -> None:
    cfg = _effective_config()
    candidates = []
    for slot in Slot:
        mem_type = MemType.PREFERENCE if slot is Slot.STATIC_PREFIX else MemType.LESSON
        for i in range(20):
            candidates.append(
                _cand(slot=slot, tokens=200, score=float(20 - i), mem_type=mem_type)
            )
    result = assemble(candidates, cfg=cfg)

    assert result.total_tokens <= cfg.budget.total_tokens
    assert sum(s.tokens for s in result.slots) == result.total_tokens


# --------------------------------------------------------------------------- #
# Tier A / candidate_note count cap.
# --------------------------------------------------------------------------- #


def test_candidate_note_count_is_capped_regardless_of_remaining_tokens() -> None:
    cfg = _effective_config()
    # Two small candidate_note candidates, easily both fitting the 100-token
    # slot cap -- the COUNT cap (tier_a.candidate_cap_per_run == 1) must still
    # bind, independent of token budget.
    candidates = [
        _cand(slot=Slot.CANDIDATE_NOTE, tokens=10, score=2.0),
        _cand(slot=Slot.CANDIDATE_NOTE, tokens=10, score=1.0),
    ]
    result = assemble(candidates, cfg=cfg)

    candidate_note_slots = [s for s in result.slots if s.slot is Slot.CANDIDATE_NOTE]
    assert len(candidate_note_slots) == cfg.tier_a.candidate_cap_per_run == 1
    # the higher-scoring one is the one kept
    assert candidate_note_slots[0].memory_id == candidates[0].memory_id.value
    assert candidates[1].memory_id in result.dropped_memory_ids


def test_candidate_note_label_is_distinct_from_fact() -> None:
    """Sanity check that CANDIDATE_NOTE is its own slot, not a flag on FACT --
    the lower-trust labeling in `templates.SECTION_LABELS` depends on this."""
    cfg = _effective_config()
    candidates = [
        _cand(slot=Slot.CANDIDATE_NOTE, tokens=10, score=1.0),
        _cand(slot=Slot.FACT, tokens=10, score=1.0),
    ]
    result = assemble(candidates, cfg=cfg)
    slots_present = {s.slot for s in result.slots}
    assert slots_present == {Slot.CANDIDATE_NOTE, Slot.FACT}


# --------------------------------------------------------------------------- #
# Dedup across slots.
# --------------------------------------------------------------------------- #


def test_dedup_keeps_the_highest_scoring_copy() -> None:
    cfg = _effective_config()
    dupe_key = "duplicate-content-hash"
    low = _cand(slot=Slot.FACT, tokens=50, score=0.2, dedup_key=dupe_key)
    high = _cand(slot=Slot.EXEMPLAR, tokens=50, score=0.9, dedup_key=dupe_key)
    result = assemble([low, high], cfg=cfg)

    assert len(result.slots) == 1
    assert result.slots[0].slot is Slot.EXEMPLAR
    assert result.slots[0].memory_id == high.memory_id.value
    assert low.memory_id in result.dropped_memory_ids


def test_dedup_is_score_deterministic_on_exact_tie() -> None:
    cfg = _effective_config()
    dupe_key = "tied-content-hash"
    a = _cand(slot=Slot.FACT, tokens=10, score=0.5, dedup_key=dupe_key)
    b = _cand(slot=Slot.FACT, tokens=10, score=0.5, dedup_key=dupe_key)
    expected_winner = min(a, b, key=lambda c: str(c.memory_id))

    result_ab = assemble([a, b], cfg=cfg)
    result_ba = assemble([b, a], cfg=cfg)
    assert result_ab.slots[0].memory_id == expected_winner.memory_id.value
    assert result_ba.slots[0].memory_id == expected_winner.memory_id.value


def test_dedup_runs_before_per_slot_packing_not_after() -> None:
    """A duplicate must not consume budget twice -- if dedup ran per-slot
    instead of globally, this fact-slot candidate and this exemplar-slot
    candidate (same dedup_key) would each separately fit their own slot cap
    and the assembler would emit two entries instead of one."""
    cfg = _effective_config()
    dupe_key = "cross-slot-dupe"
    fact = _cand(slot=Slot.FACT, tokens=240, score=0.5, dedup_key=dupe_key)
    exemplar = _cand(slot=Slot.EXEMPLAR, tokens=140, score=0.9, dedup_key=dupe_key)
    result = assemble([fact, exemplar], cfg=cfg)

    assert len(result.slots) == 1
    assert result.slots[0].slot is Slot.EXEMPLAR


# --------------------------------------------------------------------------- #
# Placement: static prefix first, dynamic slots last (D-016).
# --------------------------------------------------------------------------- #


def test_placement_is_always_static_first_dynamic_last() -> None:
    cfg = _effective_config()
    candidates = [
        _cand(slot=Slot.JIT_LESSON, tokens=10, score=1.0),
        _cand(slot=Slot.STATIC_PREFIX, tokens=10, score=1.0, mem_type=MemType.PREFERENCE),
        _cand(slot=Slot.FACT, tokens=10, score=1.0),
        _cand(slot=Slot.PITFALL, tokens=10, score=1.0),
    ]
    result = assemble(candidates, cfg=cfg)

    slot_sequence = [s.slot for s in result.slots]
    first_dynamic_index = next(
        i for i, s in enumerate(slot_sequence) if s is not Slot.STATIC_PREFIX
    )
    # every STATIC_PREFIX entry occurs before every dynamic entry
    assert all(s is Slot.STATIC_PREFIX for s in slot_sequence[:first_dynamic_index])
    assert all(s is not Slot.STATIC_PREFIX for s in slot_sequence[first_dynamic_index:])


def test_placement_holds_even_when_no_static_prefix_candidates_exist() -> None:
    cfg = _effective_config()
    candidates = [_cand(slot=Slot.FACT, tokens=10, score=1.0)]
    result = assemble(candidates, cfg=cfg)
    assert all(s.slot is not Slot.STATIC_PREFIX for s in result.slots)


# --------------------------------------------------------------------------- #
# Empty input.
# --------------------------------------------------------------------------- #


def test_empty_candidates_produce_empty_assembly() -> None:
    cfg = _effective_config()
    result = assemble([], cfg=cfg)
    assert result.slots == ()
    assert result.total_tokens == 0
    assert result.dropped_memory_ids == ()


# --------------------------------------------------------------------------- #
# Candidate construction guards.
# --------------------------------------------------------------------------- #


def test_candidate_rejects_negative_tokens() -> None:
    with pytest.raises(ValueError):
        _cand(slot=Slot.FACT, tokens=-1, score=1.0)


def test_candidate_rejects_empty_text() -> None:
    with pytest.raises(ValueError):
        _cand(slot=Slot.FACT, tokens=1, score=1.0, text="   ")


def test_candidate_rejects_empty_dedup_key() -> None:
    with pytest.raises(ValueError):
        _cand(slot=Slot.FACT, tokens=1, score=1.0, dedup_key="")


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_candidate_rejects_non_finite_score(bad: float) -> None:
    """A NaN score is not a ranking edge case, it is a determinism break: NaN
    compares False against everything, so `sorted(key=(-score, memory_id))`
    stops being a total order and the SAME candidate set packs differently
    depending on the retriever's iteration order (measured: four distinct
    orderings from three candidates). The rendered block would then not be
    reproducible from the stored `retrieval_event`."""
    with pytest.raises(ValueError):
        _cand(slot=Slot.FACT, tokens=1, score=bad)


def test_packing_is_independent_of_input_order() -> None:
    """The determinism `_pack`'s tie-break promises, asserted end to end over
    every permutation of a candidate set with an exact score tie."""
    cfg = _effective_config()
    candidates = [
        _cand(slot=Slot.FACT, tokens=100, score=0.5),
        _cand(slot=Slot.FACT, tokens=100, score=0.5),
        _cand(slot=Slot.FACT, tokens=100, score=0.5),
        _cand(slot=Slot.STATIC_PREFIX, tokens=100, score=0.5, mem_type=MemType.PREFERENCE),
    ]
    renderings = {
        tuple((s.slot, s.memory_id, s.tokens) for s in assemble(list(perm), cfg=cfg).slots)
        for perm in permutations(candidates)
    }
    assert len(renderings) == 1, f"packing depended on input order: {len(renderings)} orderings"
