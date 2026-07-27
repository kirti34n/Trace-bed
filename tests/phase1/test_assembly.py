"""The connective tissue (`hotpath.assembly`): fused candidates -> decided outcome + slots.

Fully offline. `CandidateStorePort` is satisfied by a recording fake, so the real
`abstention.decide`, `calibration.calibrated_score` and `assembler.assemble` all execute for
real -- only the three Postgres reads are replaced. `EffectiveConfig` is built from the real
Phase 0 section models, so a field rename in `domain/config.py` breaks these tests rather than
leaving them silently green.
"""

from __future__ import annotations

import dataclasses
import inspect
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

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
from tracebed.domain.enums import MemType, OutcomeCode, ScopeType, Slot, TrustTier
from tracebed.domain.ids import AgentTypeId, MemoryId, PrincipalId, ProjectId
from tracebed.domain.scope import ProjectScope
from tracebed.domain.state_machine import Status
from tracebed.hotpath import assembly as assembly_module
from tracebed.hotpath import pipeline as pipeline_module
from tracebed.hotpath.assembly import CandidateAssembly, CandidateStorePort, query_terms, slot_for
from tracebed.hotpath.fusion import ArmSignal, FusedCandidate
from tracebed.stores.pg.search import CandidateRow, SearchStore

pytestmark = pytest.mark.phase1

SCOPE = ProjectScope(
    project_id=ProjectId("11111111-1111-1111-1111-111111111111"),
    agent_type_id=AgentTypeId("22222222-2222-2222-2222-222222222222"),
    principal_id=PrincipalId("33333333-3333-3333-3333-333333333333"),
)
NOW = datetime(2026, 7, 26, 12, 0, 0, tzinfo=UTC)

# Two rare terms shared between query and content, so the rarity gate (>= 2) passes by default.
QUERY = "retry idempotent tool invocation"


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


def _mid(tag: str) -> MemoryId:
    return MemoryId(f"{tag * 8}-{tag * 4}-{tag * 4}-{tag * 4}-{tag * 12}")


def _row(
    memory_id: MemoryId,
    *,
    mem_type: MemType = MemType.SEMANTIC,
    status: Status = Status.VALIDATED,
    trust_tier: TrustTier = TrustTier.B,
    content: str = "retry idempotent invocation guidance",
    tokens: int = 10,
    q_value: float = 0.8,
    confidence: float = 0.9,
    created_at: datetime | None = None,
    scope_type: ScopeType = ScopeType.PROJECT_SHARED,
    scope_id: uuid.UUID | None = None,
) -> CandidateRow:
    return CandidateRow(
        memory_id=memory_id,
        mem_type=mem_type,
        trust_tier=trust_tier,
        status=status,
        content=content,
        token_count=tokens,
        q_value=q_value,
        confidence=confidence,
        created_at=created_at if created_at is not None else NOW - timedelta(days=1),
        scope_type=scope_type,
        scope_id=scope_id,
    )


def _fused(
    memory_id: MemoryId,
    *,
    rank: int = 1,
    cos: float | None = 0.9,
    bm25: float | None = 50.0,
    status: Status = Status.VALIDATED,
    trust_tier: TrustTier = TrustTier.B,
) -> FusedCandidate:
    return FusedCandidate(
        memory_id=memory_id,
        trust_tier=trust_tier,
        status=status,
        fused_rank=rank,
        lexical=None if bm25 is None else ArmSignal(raw_score=bm25, rank=rank),
        vector=None if cos is None else ArmSignal(raw_score=cos, rank=rank),
    )


class FakeStore:
    """Records every call, so a test can assert a query was NOT issued."""

    def __init__(
        self,
        rows: Sequence[CandidateRow] = (),
        *,
        corpus: int = 1_000,
        frequencies: dict[str, int] | None = None,
    ) -> None:
        self._rows = list(rows)
        self._corpus = corpus
        self._frequencies = frequencies if frequencies is not None else {}
        self.fetch_calls: list[tuple[ProjectId, list[MemoryId]]] = []
        self.df_calls: list[tuple[ProjectId, list[str]]] = []
        self.corpus_calls: list[ProjectId] = []

    def fetch_candidates(
        self, project_id: ProjectId, memory_ids: Sequence[MemoryId]
    ) -> list[CandidateRow]:
        self.fetch_calls.append((project_id, list(memory_ids)))
        wanted = set(memory_ids)
        return [row for row in self._rows if row.memory_id in wanted]

    def document_frequency(self, project_id: ProjectId, terms: Sequence[str]) -> dict[str, int]:
        self.df_calls.append((project_id, list(terms)))
        # Default: every term is rare (df 1), so the rarity gate passes unless a test says
        # otherwise. Stated explicitly rather than left implicit -- a fake that made every gate
        # pass by accident would make the abstention tests below prove nothing.
        return {term: self._frequencies.get(term, 1) for term in terms}

    def corpus_size(self, project_id: ProjectId) -> int:
        self.corpus_calls.append(project_id)
        return self._corpus


def _run(store: FakeStore, candidates: Sequence[FusedCandidate], **cfg_overrides: object) -> object:
    assembly = CandidateAssembly(store, FakeClock(NOW))
    return assembly.run(
        SCOPE, query_text=QUERY, candidates=candidates, cfg=_effective_config(**cfg_overrides)
    )


# --------------------------------------------------------------------------- #
# Seam drift: two independently-declared shapes that must stay one contract.
# --------------------------------------------------------------------------- #


def test_result_shape_matches_the_pipelines_own_declaration() -> None:
    """`assembly.CandidateSetResult` and `pipeline.CandidateSetResult` are declared in two
    modules on purpose (so `assembly` never imports `pipeline`). Nothing but this test stops
    them drifting into two different contracts, at which point `Pipeline` would silently read a
    field that no longer means what it did."""
    ours = {f.name for f in dataclasses.fields(assembly_module.CandidateSetResult)}
    theirs = {f.name for f in dataclasses.fields(pipeline_module.CandidateSetResult)}
    assert ours == theirs == {"outcome_code", "slots", "top_score", "injections"}


def test_the_real_assembly_satisfies_the_pipelines_port() -> None:
    """Structural typing is only a contract if something checks it: `Pipeline` accepts this
    object by Protocol, so a renamed keyword here would fail at request time, in production."""
    assert isinstance(CandidateAssembly(FakeStore(), FakeClock(NOW)), pipeline_module.CandidateAssemblyPort)
    ours = inspect.signature(CandidateAssembly.run)
    theirs = inspect.signature(pipeline_module.CandidateAssemblyPort.run)
    assert list(ours.parameters) == list(theirs.parameters)


def test_the_local_store_port_matches_the_real_searchstore() -> None:
    """`CandidateStorePort` narrows `SearchStore` to three methods. If `SearchStore`'s
    signatures move, the fake in these tests keeps passing while production breaks."""
    for name in ("fetch_candidates", "document_frequency", "corpus_size"):
        assert inspect.signature(getattr(SearchStore, name)) == inspect.signature(
            getattr(CandidateStorePort, name)
        ), name


# --------------------------------------------------------------------------- #
# The four outcomes of a retrieval that worked.
# --------------------------------------------------------------------------- #


def test_no_candidates_is_empty_and_issues_no_query_at_all() -> None:
    store = FakeStore()
    result = _run(store, [])
    assert result.outcome_code is OutcomeCode.EMPTY_RESULT
    assert result.slots == ()
    assert result.injections == ()
    assert store.fetch_calls == [] and store.corpus_calls == [] and store.df_calls == []


def test_a_candidate_whose_row_is_gone_is_empty_not_an_abstention() -> None:
    """The content fetch re-applies the retrievability predicate, so a memory quarantined
    between the arm query and this one simply does not come back. Nothing abstained -- claiming
    an abstention would invent a decision nobody made."""
    store = FakeStore(rows=[])
    result = _run(store, [_fused(_mid("a"))])
    assert result.outcome_code is OutcomeCode.EMPTY_RESULT
    assert result.slots == ()


def test_a_clean_candidate_injects_into_the_slot_its_mem_type_names() -> None:
    mid = _mid("a")
    result = _run(FakeStore(rows=[_row(mid, mem_type=MemType.LESSON)]), [_fused(mid)])
    assert result.outcome_code is OutcomeCode.INJECTED
    assert [s.slot for s in result.slots] == [Slot.PITFALL]
    assert [s.memory_id for s in result.slots] == [mid.value]


def test_cold_start_abstains_on_rarity_and_never_pays_for_the_df_query() -> None:
    """Below `rarity_min_corpus_docs` the gate fails unconditionally, so the per-term document
    frequency cannot change the answer -- issuing it would be a Postgres round trip on a 300ms
    budget whose result is discarded."""
    store = FakeStore(rows=[_row(_mid("a"))], corpus=0)
    result = _run(store, [_fused(_mid("a"))])
    assert result.outcome_code is OutcomeCode.ABSTAINED_RARITY
    assert store.df_calls == []


def test_a_corpus_below_the_configured_floor_abstains_on_rarity() -> None:
    store = FakeStore(rows=[_row(_mid("a"))], corpus=199)
    result = _run(store, [_fused(_mid("a"))], abstention=AbstentionConfig(rarity_min_corpus_docs=200))
    assert result.outcome_code is OutcomeCode.ABSTAINED_RARITY
    # And the mirror: one more document and the same candidate clears the same gate.
    store = FakeStore(rows=[_row(_mid("a"))], corpus=200)
    assert (
        _run(store, [_fused(_mid("a"))], abstention=AbstentionConfig(rarity_min_corpus_docs=200)).outcome_code
        is OutcomeCode.INJECTED
    )


def test_common_shared_terms_do_not_count_as_rare() -> None:
    """Every shared term is present, but each matches 10% of a 1000-document corpus, well above
    `rarity_max_df_pct` (2.0) -- this is the gate that stops a generic query matching generic
    memory."""
    store = FakeStore(rows=[_row(_mid("a"))], corpus=1_000, frequencies=dict.fromkeys(query_terms(QUERY), 100))
    assert _run(store, [_fused(_mid("a"))]).outcome_code is OutcomeCode.ABSTAINED_RARITY


def test_terms_the_candidate_does_not_share_are_not_counted() -> None:
    """The rarity gate counts SHARED terms. A candidate whose content shares only one of the
    query's rare terms has one, not four, regardless of how rare the other three are."""
    store = FakeStore(rows=[_row(_mid("a"), content="retry only")], corpus=1_000)
    assert _run(store, [_fused(_mid("a"))]).outcome_code is OutcomeCode.ABSTAINED_RARITY


def test_a_low_cosine_abstains_on_the_threshold_gate() -> None:
    store = FakeStore(rows=[_row(_mid("a"))])
    result = _run(store, [_fused(_mid("a"), cos=0.1)])
    assert result.outcome_code is OutcomeCode.ABSTAINED_THRESHOLD


def test_a_low_bm25_abstains_on_the_threshold_gate() -> None:
    store = FakeStore(rows=[_row(_mid("a"))])
    # bm25_saturate(1.0, k=10) == 0.09, below the 0.50 default threshold.
    assert _run(store, [_fused(_mid("a"), bm25=1.0)]).outcome_code is OutcomeCode.ABSTAINED_THRESHOLD


def test_everything_clears_but_nothing_fits_is_empty_not_injected() -> None:
    """A `budget.*` override can leave a slot no room. Reporting `injected` for a block
    containing nothing would be a lie; reporting an abstention would invent one."""
    store = FakeStore(rows=[_row(_mid("a"), tokens=10)])
    result = _run(store, [_fused(_mid("a"))], budget=BudgetConfig(slot_caps={"fact": 0}))
    assert result.outcome_code is OutcomeCode.EMPTY_RESULT
    assert result.slots == ()
    assert result.injections == ()


def test_the_reported_abstention_is_the_best_ranked_candidates() -> None:
    """`candidates` arrives in RRF-fused order, so the code an operator sees is the one for the
    candidate they would ask about first -- and it is deterministic."""
    first, second = _mid("a"), _mid("b")
    store = FakeStore(rows=[_row(first), _row(second, content="retry only")], corpus=1_000)
    result = _run(store, [_fused(first, rank=1, cos=0.1), _fused(second, rank=2)])
    assert result.outcome_code is OutcomeCode.ABSTAINED_THRESHOLD  # first's reason, not second's


# --------------------------------------------------------------------------- #
# The degraded rung: a candidate no vector arm ever evaluated (D-065).
# --------------------------------------------------------------------------- #


def test_a_lexical_only_candidate_still_injects_on_the_degraded_rung() -> None:
    """PLAN.md §2 defines `degraded_lexical` as a WORKING rung. With no vector arm, no candidate
    has a cosine; treating that absence as a failed gate would make the rung return nothing on
    every call, forever, while looking healthy."""
    mid = _mid("a")
    result = _run(FakeStore(rows=[_row(mid)]), [_fused(mid, cos=None)])
    assert result.outcome_code is OutcomeCode.INJECTED
    assert len(result.slots) == 1


def test_the_rarity_gate_still_applies_with_no_vector_arm() -> None:
    """Skipping the cosine gate must not skip the others: the rarity gate reads neither arm's
    score, so it applies in full on every rung."""
    store = FakeStore(rows=[_row(_mid("a"))], corpus=10)
    assert _run(store, [_fused(_mid("a"), cos=None)]).outcome_code is OutcomeCode.ABSTAINED_RARITY


def test_a_vector_only_candidate_skips_the_bm25_gate_not_the_cosine_one() -> None:
    mid = _mid("a")
    assert _run(FakeStore(rows=[_row(mid)]), [_fused(mid, bm25=None)]).outcome_code is (
        OutcomeCode.INJECTED
    )
    assert _run(FakeStore(rows=[_row(mid)]), [_fused(mid, bm25=None, cos=0.1)]).outcome_code is (
        OutcomeCode.ABSTAINED_THRESHOLD
    )


# --------------------------------------------------------------------------- #
# injection_log: the only record of what actually entered a prompt.
# --------------------------------------------------------------------------- #


def test_injections_are_produced_only_for_memories_that_reached_a_slot() -> None:
    """Two candidates clear every gate; the slot cap fits one. The dropped one must not appear
    in `injection_log` -- a row there means "this memory was in that prompt"."""
    big, small = _mid("a"), _mid("b")
    store = FakeStore(
        rows=[
            _row(big, tokens=200),
            # Distinct content: identical text would collapse in dedup before packing, which is
            # a different (also correct) behaviour, tested separately below.
            _row(small, tokens=5, content="retry idempotent invocation notes"),
        ]
    )
    result = _run(
        store,
        [_fused(big, rank=1), _fused(small, rank=2)],
        budget=BudgetConfig(slot_caps={"fact": 10}),
    )
    assert [i.memory_id for i in result.injections] == [small]
    assert {s.memory_id for s in result.slots} == {small.value}


def test_an_injection_row_carries_the_score_that_won_the_slot() -> None:
    """`score` exists nowhere in the rendered block, so if this were reconstructed downstream it
    could only ever be fabricated."""
    mid = _mid("a")
    result = _run(FakeStore(rows=[_row(mid, tokens=7)]), [_fused(mid)])
    (row,) = result.injections
    assert row.memory_id == mid and row.slot is Slot.FACT and row.tokens == 7
    assert 0.0 < row.score <= 1.0


# --------------------------------------------------------------------------- #
# Scoring inputs.
# --------------------------------------------------------------------------- #


def test_top_score_reports_the_best_candidate_even_when_everything_abstained() -> None:
    """On an abstaining call this number is the whole diagnostic: how close did the best
    candidate get. Reporting `None` would erase it."""
    store = FakeStore(rows=[_row(_mid("a"), q_value=1.0, confidence=1.0)], corpus=10)
    result = _run(store, [_fused(_mid("a"))])
    assert result.outcome_code is OutcomeCode.ABSTAINED_RARITY
    assert result.top_score is not None and result.top_score > 0


def test_a_stale_memory_scores_below_an_identical_fresh_one() -> None:
    """`score.recency_half_life_days` is read, and `created_at` is what it is read against."""
    fresh, stale = _mid("a"), _mid("b")
    store = FakeStore(
        rows=[
            _row(fresh, created_at=NOW),
            _row(stale, created_at=NOW - timedelta(days=365), content="retry idempotent invocation notes"),
        ]
    )
    result = _run(store, [_fused(fresh, rank=1), _fused(stale, rank=2)])
    by_id = {i.memory_id: i.score for i in result.injections}
    assert by_id[fresh] > by_id[stale]


def test_a_created_at_in_the_future_costs_recency_precision_not_the_retrieval() -> None:
    """Clock skew between a server timestamp and the injected `Clock` is possible in either
    direction, and `CalibratedSignals` refuses a negative age."""
    mid = _mid("a")
    result = _run(FakeStore(rows=[_row(mid, created_at=NOW + timedelta(days=30))]), [_fused(mid)])
    assert result.outcome_code is OutcomeCode.INJECTED


def test_a_document_frequency_above_the_corpus_count_does_not_raise() -> None:
    """`df` and the corpus count come from two separate statements; a write landing between them
    can make the ratio exceed 1. `RarityEvidence` refuses a percentage outside [0, 100], and a
    benign race must not become the ladder's store-error rung."""
    store = FakeStore(rows=[_row(_mid("a"))], corpus=10, frequencies=dict.fromkeys(query_terms(QUERY), 999))
    assert _run(store, [_fused(_mid("a"))]).outcome_code is OutcomeCode.ABSTAINED_RARITY


# --------------------------------------------------------------------------- #
# Slot mapping and tokenisation.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("mem_type", "expected"),
    [
        (MemType.SEMANTIC, Slot.FACT),
        (MemType.EPISODIC, Slot.EXEMPLAR),
        (MemType.LESSON, Slot.PITFALL),
        (MemType.PREFERENCE, Slot.STATIC_PREFIX),
    ],
)
def test_every_mem_type_maps_to_a_slot(mem_type: MemType, expected: Slot) -> None:
    assert slot_for(_row(_mid("a"), mem_type=mem_type)) is expected


@pytest.mark.parametrize("mem_type", list(MemType))
def test_a_tier_a_candidate_row_is_a_candidate_note_whatever_its_mem_type(mem_type: MemType) -> None:
    """PLAN.md §5: a `candidate` row is retrievable only as Tier A, labelled lower-trust, capped
    at 1/run. The label IS the slot -- routing it by mem_type instead would render an
    unpromoted memory as an ordinary validated fact."""
    row = _row(_mid("a"), mem_type=mem_type, status=Status.CANDIDATE, trust_tier=TrustTier.A)
    assert slot_for(row) is Slot.CANDIDATE_NOTE


def test_a_candidate_note_lands_in_the_candidate_note_slot_end_to_end() -> None:
    mid = _mid("a")
    row = _row(mid, status=Status.CANDIDATE, trust_tier=TrustTier.A)
    result = _run(
        FakeStore(rows=[row]),
        [_fused(mid, status=Status.CANDIDATE, trust_tier=TrustTier.A)],
    )
    assert [s.slot for s in result.slots] == [Slot.CANDIDATE_NOTE]


def test_query_terms_are_lowercased_deduped_and_order_preserving() -> None:
    assert query_terms("Retry the RETRY, tool_id=42!") == ("retry", "the", "tool", "id", "42")


def test_query_terms_of_punctuation_only_text_is_empty() -> None:
    assert query_terms("!!! ---") == ()


def test_two_memories_with_identical_content_collapse_to_one_slot() -> None:
    """Dedup is on CONTENT, not identity: a Tier A candidate note duplicating an
    already-validated fact must not spend the budget twice, and must not produce two
    `injection_log` rows for one prompt."""
    first, second = _mid("a"), _mid("b")
    store = FakeStore(rows=[_row(first), _row(second)])  # byte-identical content
    result = _run(store, [_fused(first, rank=1), _fused(second, rank=2)])
    assert len(result.slots) == 1
    assert len(result.injections) == 1


# --------------------------------------------------------------------------- #
# Kill switch (PLAN.md §2: auto-disable a memory type on sustained negative lift)
# --------------------------------------------------------------------------- #


def test_a_killswitched_mem_type_is_never_injected() -> None:
    """Until this landed, `killswitch_overlay` was read by exactly ONE module in
    the tree -- `hotpath.jit` -- so a killswitched mem_type was still retrieved
    and injected by every ordinary /v1/retrieve call and disabled only on the
    side channel. That is worse than no kill switch: it moves injection volume
    onto the unmeasured path instead of stopping it."""
    mid = _mid("a")
    store = FakeStore(rows=[_row(mid, mem_type=MemType.LESSON)])

    result = _run(store, [_fused(mid)], killswitch_overlay={MemType.LESSON.value: True})

    assert result.slots == ()
    assert result.injections == ()
    assert result.outcome_code is OutcomeCode.EMPTY_RESULT


def test_the_same_candidate_injects_with_the_switch_off() -> None:
    """Guard the guard: the assertion above must fail because the switch is ON,
    not because the fixture could never inject."""
    mid = _mid("a")
    store = FakeStore(rows=[_row(mid, mem_type=MemType.LESSON)])

    result = _run(store, [_fused(mid)], killswitch_overlay={MemType.LESSON.value: False})

    assert [s.slot for s in result.slots] == [Slot.PITFALL]
    assert result.outcome_code is OutcomeCode.INJECTED


def test_an_empty_overlay_disables_nothing() -> None:
    """`killswitch_state` is empty for a project nobody has ever tripped. If an
    absent key read as "disabled", an empty overlay would silently switch the
    whole product off."""
    mid = _mid("a")
    result = _run(FakeStore(rows=[_row(mid, mem_type=MemType.LESSON)]), [_fused(mid)])

    assert result.outcome_code is OutcomeCode.INJECTED


def test_killswitching_one_mem_type_leaves_its_siblings_injecting() -> None:
    """The switch is per memory type. Disabling lessons must not disable facts
    -- otherwise one negative-lift finding takes the whole vault offline."""
    lesson, fact = _mid("a"), _mid("b")
    store = FakeStore(
        rows=[
            _row(lesson, mem_type=MemType.LESSON, content="retry idempotent invocation lesson"),
            _row(fact, mem_type=MemType.SEMANTIC, content="retry idempotent invocation fact"),
        ]
    )

    result = _run(
        store,
        [_fused(lesson, rank=1), _fused(fact, rank=2)],
        killswitch_overlay={MemType.LESSON.value: True},
    )

    assert [s.slot for s in result.slots] == [Slot.FACT]
    assert [i.memory_id for i in result.injections] == [fact]


def test_a_killswitched_row_is_not_reported_as_an_abstention() -> None:
    """`abstained_threshold`/`abstained_rarity` are statements about THIS
    query's evidence. Reporting a disabled memory type as an abstention would
    send an operator reading the Abstention dashboard to tune thresholds
    against a row that was never eligible."""
    mid = _mid("a")
    store = FakeStore(rows=[_row(mid, mem_type=MemType.LESSON)])

    result = _run(store, [_fused(mid)], killswitch_overlay={MemType.LESSON.value: True})

    assert result.outcome_code not in (
        OutcomeCode.ABSTAINED_THRESHOLD,
        OutcomeCode.ABSTAINED_RARITY,
    )


def test_both_injection_paths_share_one_definition_of_disabled() -> None:
    """`hotpath.jit` and `hotpath.assembly` are the only two paths that can put
    a memory in a prompt. Two independent readings of `killswitch_overlay`
    would eventually disagree about a mem_type, and the disagreement would be
    invisible: one path keeps injecting while the dashboard says disabled."""
    import tracebed.hotpath.jit as jit_module

    assert jit_module.killswitched is assembly_module.killswitched
    assert assembly_module.killswitched(MemType.LESSON, _effective_config()) is False
    assert (
        assembly_module.killswitched(
            MemType.LESSON, _effective_config(killswitch_overlay={MemType.LESSON.value: True})
        )
        is True
    )
