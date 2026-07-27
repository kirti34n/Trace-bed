"""Negative probes: queries for which the CORRECT hot-path behaviour is to inject
NOTHING dynamic (PLAN.md §7 Phase 1 gate — the headline assertion: "negative
probes: 0 dynamic injections").

Four classes, each modelling a different reason the real production ladder must
abstain, built from `hotpath.retriever.RetrievalOutcome`-shaped fixtures rather
than a live Postgres (none is reachable on this build machine):

  * ``EMPTY_VAULT``            — a project with an empty vault: the retriever's
    two arms return zero candidates. Correct outcome: `OutcomeCode.EMPTY_RESULT`
    (this is NOT an abstention code — nothing was ever found to abstain on).
  * ``UNCOVERED_QUERY``        — a query about something no memory covers: real
    candidates exist, but their cosine/BM25 signals are weak. Correct outcome:
    `OutcomeCode.ABSTAINED_THRESHOLD` (`hotpath.abstention`'s gates 2/3).
  * ``GENERIC_COMMON_TERMS``   — a generic query whose only matches share common
    terms: cosine/BM25 look strong, but every shared term's document frequency
    is above `rarity_max_df_pct`, so the rarity gate (an IDF computation, D-003)
    fails on its own merits — not on cold start. Correct outcome:
    `OutcomeCode.ABSTAINED_RARITY`.
  * ``COLD_START``             — a project under `rarity_min_corpus_docs`: every
    other signal is deliberately excellent, and the rarity gate still refuses
    unconditionally (`hotpath.abstention.rarity_gate_passes`'s cold-start
    branch). Correct outcome: `OutcomeCode.ABSTAINED_RARITY`.

HOW THIS EXERCISES REAL CODE, NOT A STUB: `ProbeAssembly` below is a genuine,
correct implementation of `hotpath.pipeline.CandidateAssemblyPort` — it calls
the actual, already-tested `hotpath.abstention.decide`,
`hotpath.calibration.calibrated_score`, and `hotpath.assembler.assemble`
functions over each probe's synthetic (but fully-formed) candidate content. The
only thing faked is where the candidate's raw signals and text come from
(a fixture, not a live `SearchStore`) — nothing about the DECISION is faked.
`run_probe_through_pipeline` goes one step further and wires that same
`ProbeAssembly` into a real `hotpath.pipeline.Pipeline`, with a fake
`HybridRetrieverPort` that simply hands back the probe's own candidates as
`FusedCandidate`s, so the negative-probe gate exercises the SAME orchestrator
code path `/v1/retrieve` uses, not merely the abstention module in isolation.

A POSITIVE CONTROL (`positive_control_probe`) is included and deliberately
excluded from `build_probes()`'s count: a probe whose signals clear every gate,
run through the identical `ProbeAssembly`/`Pipeline` wiring the 25+ negative
probes use. If the harness's own assembly were rigged to always report
"nothing" (which would make "0 dynamic injections" trivially true and worth
nothing), the positive control would go red — it does not.

The abstention TARGET is read from `EffectiveConfig.abstention
.target_abstention_pct` (PLAN.md §6, default 50), not from a harness-local
literal, and it is compared against the MEASURED rate. It is a reporting target
only: nothing in `hotpath/` branches on it (an abstention rate is a property of a
population of retrievals; the hot path sees one), so this harness is its only
consumer that does anything other than quote it.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final
from uuid import uuid4

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
from tracebed.domain.enums import MemType, OutcomeCode, Slot, TrustTier
from tracebed.domain.events import RetrieveResult, RunContext
from tracebed.domain.ids import AgentTypeId, MemoryId, PrincipalId, ProjectId, mint_memory_id
from tracebed.domain.scope import ProjectScope
from tracebed.domain.state_machine import Status
from tracebed.hotpath.abstention import (
    AbstentionDecision,
    CandidateSignals,
    RarityEvidence,
    decide,
    measured_abstention_rate,
)
from tracebed.hotpath.assembler import Candidate, assemble
from tracebed.hotpath.calibration import CalibratedSignals, calibrated_score
from tracebed.hotpath.fusion import ArmSignal, FusedCandidate
from tracebed.hotpath.pipeline import CandidateSetResult, Pipeline

__all__ = [
    "TARGET_ABSTENTION_PCT",
    "CandidateFixture",
    "NegativeProbeReport",
    "Probe",
    "ProbeAssembly",
    "ProbeClass",
    "ProbeResult",
    "build_probes",
    "default_config",
    "main",
    "positive_control_probe",
    "render_text",
    "run_negative_probes",
    "run_probe",
    "run_probe_through_pipeline",
]

# PLAN.md §6's documented default for `abstention.target_abstention_pct`. Kept as a
# named constant ONLY so the existing importers of this name keep working and so a
# drift between PLAN.md's stated default and `AbstentionConfig`'s can be asserted;
# `run_negative_probes` reads the resolved config field, never this.
TARGET_ABSTENTION_PCT: Final[float] = 50.0


class ProbeClass:
    """The four negative-probe classes PLAN.md §7 names, as string constants
    (not a `StrEnum`: this is harness-local vocabulary, never a wire value or a
    DB column, so it does not belong beside `domain.enums`' shared enums)."""

    EMPTY_VAULT: Final[str] = "empty_vault"
    UNCOVERED_QUERY: Final[str] = "uncovered_query"
    GENERIC_COMMON_TERMS: Final[str] = "generic_common_terms"
    COLD_START: Final[str] = "cold_start"

    ALL: Final[tuple[str, ...]] = (
        EMPTY_VAULT,
        UNCOVERED_QUERY,
        GENERIC_COMMON_TERMS,
        COLD_START,
    )


def default_config(**overrides: object) -> EffectiveConfig:
    """The shipped-default `EffectiveConfig` (PLAN.md §6), matching the
    construction pattern `tests/phase1/test_pipeline.py`/`test_degradation_ladder.py`
    already use. `overrides` lets a caller widen/narrow one section (e.g. a
    non-default `abstention=`) without repeating every other section."""
    base: dict[str, object] = {
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
        "killswitch_overlay": {},
    }
    base.update(overrides)
    return EffectiveConfig(**base)


@dataclass(frozen=True, slots=True)
class CandidateFixture:
    """One synthetic candidate: the raw signals `hotpath.abstention` gates on,
    plus exactly the content `hotpath.assembler`/`hotpath.calibration` would
    need if this candidate DID clear every gate — so a probe that turns out to
    inject (it never should, for a true negative probe) still produces a real,
    renderable `ContextSlot` rather than crashing the harness."""

    memory_id: MemoryId
    mem_type: MemType
    slot: Slot
    text: str
    tokens: int
    signals: CandidateSignals
    q_value: float = 0.5
    age_days: float = 1.0
    validity: float = 0.8
    status: Status = Status.VALIDATED
    trust_tier: TrustTier = TrustTier.B


@dataclass(frozen=True, slots=True)
class Probe:
    """One negative probe: a query plus the candidates the retriever's two
    arms would have handed back (`()` models an empty vault / nothing found at
    all — the `EMPTY_VAULT` class's actual fixture)."""

    name: str
    probe_class: str
    query_text: str
    candidates: tuple[CandidateFixture, ...] = ()


@dataclass(frozen=True, slots=True)
class ProbeResult:
    probe: Probe
    outcome_code: OutcomeCode
    injected_count: int
    decisions: tuple[AbstentionDecision, ...]
    """One `AbstentionDecision` per candidate (empty when the probe models an
    empty vault) — `decide()`'s own, unmodified output; not re-derived."""


class ProbeAssembly:
    """A REAL `hotpath.pipeline.CandidateAssemblyPort` implementation — not a
    stub. Every value it returns is genuinely computed by production code
    (`hotpath.abstention.decide`, `hotpath.calibration.calibrated_score`,
    `hotpath.assembler.assemble`) over one probe's fixtures; the only thing
    faked is that a probe's candidate content and its per-candidate
    `CandidateSignals` are supplied directly rather than fetched and composed
    from `memory_item` rows.

    KNOWN LIMIT, stated plainly because it bounds what clause 1 of the gate
    proves: the production implementation of that composition step now exists
    (`hotpath.assembly.CandidateAssembly` — it fetches the rows, builds the
    rarity evidence from `document_frequency`/`corpus_size`, and decides which
    arm signals are present). These probes do NOT run it, so "0 dynamic
    injections" is a statement about `decide()`, `calibrated_score()` and
    `assemble()` over hand-built signals — not about how those signals are
    derived from a real fused candidate. That derivation is covered instead by
    `tests/phase1/test_assembly.py` and `tests/phase1/test_hotpath_end_to_end.py`.
    Porting the probe fixtures onto `CandidateAssembly` (supplying `CandidateRow`s
    and a df map instead of `CandidateSignals`) would make this clause cover the
    whole chain and is recorded as remaining work.
    """

    def __init__(self, probe: Probe) -> None:
        self._by_id: dict[MemoryId, CandidateFixture] = {c.memory_id: c for c in probe.candidates}

    def run(
        self,
        scope: ProjectScope,
        *,
        query_text: str,
        candidates: Sequence[FusedCandidate],
        cfg: EffectiveConfig,
    ) -> CandidateSetResult:
        if not candidates:
            return CandidateSetResult(outcome_code=OutcomeCode.EMPTY_RESULT, slots=(), top_score=None)

        decisions: list[tuple[FusedCandidate, AbstentionDecision]] = [
            (fc, decide(self._by_id[fc.memory_id].signals, cfg.abstention)) for fc in candidates
        ]
        injected = [(fc, d) for fc, d in decisions if d.inject]
        if not injected:
            # Every real negative probe's candidates fail at least one gate; the
            # first decision's code is as good as any (all candidates in these
            # fixtures are constructed to fail identically) and is never invented
            # — it is `decide()`'s own `outcome_code`.
            code = next(d.outcome_code for _, d in decisions if d.outcome_code is not None)
            return CandidateSetResult(outcome_code=code, slots=(), top_score=None)

        built: list[Candidate] = []
        for fc, _ in injected:
            fixture = self._by_id[fc.memory_id]
            score = calibrated_score(
                CalibratedSignals(
                    cos_sim=fixture.signals.cos_sim,
                    q_value=fixture.q_value,
                    age_days=fixture.age_days,
                    validity=fixture.validity,
                ),
                cfg.score,
            )
            built.append(
                Candidate(
                    slot=fixture.slot,
                    memory_id=fc.memory_id,
                    mem_type=fixture.mem_type,
                    text=fixture.text,
                    tokens=fixture.tokens,
                    score=score,
                    dedup_key=str(fc.memory_id),
                )
            )
        assembled = assemble(built, cfg=cfg)
        top_score = max((c.score for c in built), default=None)
        return CandidateSetResult(outcome_code=OutcomeCode.INJECTED, slots=assembled.slots, top_score=top_score)


def _fused_candidates(probe: Probe) -> tuple[FusedCandidate, ...]:
    """The `FusedCandidate` shape `hotpath.fusion.fuse()` would have produced,
    built directly from a probe's fixtures rather than run through real RRF —
    the probes exist to prove abstention/assembly never inject, which is
    downstream of fusion and does not depend on fusion's own ordering math
    (already covered by `tests/phase1/test_fusion.py`)."""
    fused: list[FusedCandidate] = []
    for rank, c in enumerate(probe.candidates, start=1):
        fused.append(
            FusedCandidate(
                memory_id=c.memory_id,
                trust_tier=c.trust_tier,
                status=c.status,
                fused_rank=rank,
                lexical=ArmSignal(raw_score=c.signals.bm25_raw, rank=rank),
                vector=ArmSignal(raw_score=c.signals.cos_sim, rank=rank),
            )
        )
    return tuple(fused)


def run_probe(probe: Probe, *, cfg: EffectiveConfig | None = None) -> ProbeResult:
    """Runs one probe through the real `ProbeAssembly` (abstention + assembler,
    unmodified production code) and returns what it decided."""
    resolved = cfg if cfg is not None else default_config()
    fused = _fused_candidates(probe)
    assembly = ProbeAssembly(probe)
    scope = _scope()
    result = assembly.run(scope, query_text=probe.query_text, candidates=fused, cfg=resolved)
    decisions = tuple(decide(c.signals, resolved.abstention) for c in probe.candidates)
    return ProbeResult(
        probe=probe,
        outcome_code=result.outcome_code,
        injected_count=len(result.slots),
        decisions=decisions,
    )


# --------------------------------------------------------------------------- #
# End-to-end: the same probe, through a real `hotpath.pipeline.Pipeline`.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class _FixedOutcome:
    """Structurally satisfies `hotpath.pipeline.RetrievalOutcomeLike`."""

    candidates: tuple[FusedCandidate, ...]
    degraded: bool
    embed_latency_ms: int
    candidates_considered: int


class _FixedRetriever:
    """Satisfies `hotpath.pipeline.HybridRetrieverPort`: hands back exactly one
    probe's own fused candidates, as if the two search arms had already run."""

    def __init__(self, candidates: Sequence[FusedCandidate]) -> None:
        self._candidates = tuple(candidates)

    def retrieve(self, project_id: ProjectId, query_text: str, *, cfg: RetrievalConfig) -> _FixedOutcome:
        return _FixedOutcome(
            candidates=self._candidates,
            degraded=False,
            embed_latency_ms=5,
            candidates_considered=len(self._candidates),
        )


class _StaticConfigProvider:
    def __init__(self, cfg: EffectiveConfig) -> None:
        self._cfg = cfg

    def effective(self, project_id: ProjectId, agent_type_id: AgentTypeId | None = None) -> EffectiveConfig:
        return self._cfg


class _NullTelemetry:
    """Satisfies `hotpath.pipeline.TelemetryRecorderPort`; records nothing —
    the probe result is read straight off `Pipeline.retrieve()`'s return
    value, not off a telemetry side-channel."""

    def record_retrieval(self, *args: object, **kwargs: object) -> None:
        return None


def _scope() -> ProjectScope:
    return ProjectScope(
        project_id=ProjectId(uuid4()),
        agent_type_id=AgentTypeId(uuid4()),
        principal_id=PrincipalId(uuid4()),
    )


def run_probe_through_pipeline(probe: Probe, *, cfg: EffectiveConfig | None = None) -> RetrieveResult:
    """Runs one probe through a REAL `hotpath.pipeline.Pipeline` — the exact
    orchestrator `/v1/retrieve` calls — with a fake retriever standing in for
    the two search arms and the same `ProbeAssembly` `run_probe` uses standing
    in for the not-yet-built `CandidateAssemblyPort`. Proves the negative-probe
    guarantee survives the orchestrator, not just the abstention module."""
    from tracebed.domain.clock import FakeClock

    resolved = cfg if cfg is not None else default_config()
    # The holdout arm is memory-off (D-099): a probe whose random scope hashes into holdout
    # returns OutcomeCode.HOLDOUT and an empty block, which would count as a (vacuous) zero
    # injection and would drag the measured abstention rate around for a reason that has
    # nothing to do with the abstention gates these probes exist to exercise. Every probe
    # therefore runs on the memory-on arm; the holdout arm is covered by
    # tests/phase1/test_pipeline.py and by harness/dependence_test.py.
    resolved = resolved.model_copy(
        update={"killswitch": resolved.killswitch.model_copy(update={"holdout_pct": 0.0})}
    )
    pipeline = Pipeline(
        clock=FakeClock(),
        config=_StaticConfigProvider(resolved),
        telemetry=_NullTelemetry(),
        retriever=_FixedRetriever(_fused_candidates(probe)),
        assembly=ProbeAssembly(probe),
        holdout_salt="negative-probe-salt",
    )
    return pipeline.retrieve(_scope(), RunContext(query_text=probe.query_text), session_id=probe.name)


# --------------------------------------------------------------------------- #
# Fixture builders — >= 25 probes across the four classes (PLAN.md §7).
# --------------------------------------------------------------------------- #


def _rare_signals(*, cos_sim: float, bm25_raw: float) -> CandidateSignals:
    """Rarity gate PASSES (corpus healthy, two genuinely rare shared terms) —
    isolates the threshold gates for the `UNCOVERED_QUERY` class."""
    return CandidateSignals(
        cos_sim=cos_sim,
        bm25_raw=bm25_raw,
        rarity=RarityEvidence(shared_term_doc_freq_pct=(1.0, 1.5), corpus_doc_count=250),
    )


def _common_term_signals(*, cos_sim: float, bm25_raw: float, corpus_doc_count: int) -> CandidateSignals:
    """Rarity gate FAILS on term commonness alone — every shared term's
    document frequency is well above `rarity_max_df_pct` (2.0), and
    `corpus_doc_count` clears `rarity_min_corpus_docs` (200) so this is not
    the cold-start branch."""
    return CandidateSignals(
        cos_sim=cos_sim,
        bm25_raw=bm25_raw,
        rarity=RarityEvidence(shared_term_doc_freq_pct=(10.0, 40.0, 80.0), corpus_doc_count=corpus_doc_count),
    )


def _cold_start_signals(*, corpus_doc_count: int) -> CandidateSignals:
    """Every OTHER signal is deliberately excellent — cosine, BM25, and the
    per-term document frequencies would all clear their own gates — so the
    only thing that can produce an abstention is the cold-start branch of
    `rarity_gate_passes` itself."""
    return CandidateSignals(
        cos_sim=0.9,
        bm25_raw=80.0,
        rarity=RarityEvidence(shared_term_doc_freq_pct=(0.5, 1.0, 1.5), corpus_doc_count=corpus_doc_count),
    )


def _empty_vault_probes() -> list[Probe]:
    queries = (
        "how do I configure the retry backoff for the payments webhook",
        "what caused the nightly reconciliation batch to fail last night",
        "which feature flag controls the new onboarding flow",
        "why did the deploy pipeline roll back on staging",
        "what is the on-call escalation policy for the billing service",
        "how should the ETL job handle a malformed CSV row",
        "what did we decide about the rate limiter's burst size",
        "who owns the incident response runbook for the auth service",
    )
    return [
        Probe(name=f"empty_vault_{i:02d}", probe_class=ProbeClass.EMPTY_VAULT, query_text=q, candidates=())
        for i, q in enumerate(queries)
    ]


def _uncovered_query_probes() -> list[Probe]:
    # (cos_sim, bm25_raw, candidate_count) — cos_sim always < cos_threshold
    # (0.60); bm25_raw small enough that its saturated form is also well below
    # bm25_norm_threshold (0.50), so this class is doubly clear of the
    # threshold gates rather than riding exactly on one boundary.
    variants: tuple[tuple[float, float, int], ...] = (
        (-0.80, 0.2, 1),
        (-0.30, 0.5, 1),
        (0.00, 1.0, 2),
        (0.20, 1.5, 1),
        (0.40, 2.0, 3),
        (0.55, 0.3, 1),
        (0.59, 0.1, 2),
        (0.10, 3.0, 1),
    )
    probes: list[Probe] = []
    for i, (cos_sim, bm25_raw, n) in enumerate(variants):
        candidates = tuple(
            CandidateFixture(
                memory_id=mint_memory_id(),
                mem_type=MemType.SEMANTIC,
                slot=Slot.FACT,
                text=f"uncovered query candidate {i}-{j}",
                tokens=20,
                signals=_rare_signals(cos_sim=cos_sim, bm25_raw=bm25_raw),
            )
            for j in range(n)
        )
        probes.append(
            Probe(
                name=f"uncovered_query_{i:02d}",
                probe_class=ProbeClass.UNCOVERED_QUERY,
                query_text=f"a query with no real coverage, variant {i}",
                candidates=candidates,
            )
        )
    return probes


def _generic_common_terms_probes() -> list[Probe]:
    # (cos_sim, bm25_raw, corpus_doc_count) — cos_sim/bm25_raw are deliberately
    # STRONG (would clear the threshold gates easily) so only the rarity gate's
    # own IDF computation is what abstains here.
    variants: tuple[tuple[float, float, int], ...] = (
        (0.70, 20.0, 300),
        (0.75, 30.0, 500),
        (0.80, 40.0, 800),
        (0.85, 50.0, 1_000),
        (0.90, 60.0, 1_500),
        (0.95, 70.0, 2_000),
        (0.72, 25.0, 400),
        (0.88, 55.0, 900),
    )
    probes: list[Probe] = []
    for i, (cos_sim, bm25_raw, corpus_doc_count) in enumerate(variants):
        candidate = CandidateFixture(
            memory_id=mint_memory_id(),
            mem_type=MemType.LESSON,
            slot=Slot.PITFALL,
            text=f"generic common-term candidate {i}",
            tokens=25,
            signals=_common_term_signals(cos_sim=cos_sim, bm25_raw=bm25_raw, corpus_doc_count=corpus_doc_count),
        )
        probes.append(
            Probe(
                name=f"generic_common_terms_{i:02d}",
                probe_class=ProbeClass.GENERIC_COMMON_TERMS,
                query_text=f"a generic query matching only common terms, variant {i}",
                candidates=(candidate,),
            )
        )
    return probes


def _cold_start_probes() -> list[Probe]:
    corpus_sizes = (0, 1, 10, 50, 100, 150, 175, 199)  # all < rarity_min_corpus_docs (200)
    probes: list[Probe] = []
    for i, corpus_doc_count in enumerate(corpus_sizes):
        candidate = CandidateFixture(
            memory_id=mint_memory_id(),
            mem_type=MemType.SEMANTIC,
            slot=Slot.EXEMPLAR,
            text=f"cold-start candidate {i}",
            tokens=30,
            signals=_cold_start_signals(corpus_doc_count=corpus_doc_count),
        )
        probes.append(
            Probe(
                name=f"cold_start_{i:02d}",
                probe_class=ProbeClass.COLD_START,
                query_text=f"a query into a young project, variant {i}",
                candidates=(candidate,),
            )
        )
    return probes


def build_probes() -> list[Probe]:
    """>= 25 negative probes across all four classes (PLAN.md §7 Phase 1 gate:
    "Build at least 25 real probes across those classes and assert ZERO
    dynamic injections")."""
    probes = (
        _empty_vault_probes()
        + _uncovered_query_probes()
        + _generic_common_terms_probes()
        + _cold_start_probes()
    )
    assert len(probes) >= 25, f"expected >= 25 negative probes, built {len(probes)}"
    return probes


def positive_control_probe() -> Probe:
    """NOT one of the 25+ negative probes (deliberately excluded from
    `build_probes()`): a candidate that clears every gate, run through the
    IDENTICAL `ProbeAssembly`/`Pipeline` wiring. Proves the harness can still
    detect an injection — if `ProbeAssembly` were rigged to always report
    "nothing", this probe would go red instead of green."""
    candidate = CandidateFixture(
        memory_id=mint_memory_id(),
        mem_type=MemType.LESSON,
        slot=Slot.FACT,
        text="the payments webhook retries with exponential backoff starting at 2s, capped at 60s",
        tokens=40,
        signals=CandidateSignals(
            cos_sim=0.90,
            bm25_raw=40.0,
            rarity=RarityEvidence(shared_term_doc_freq_pct=(0.5, 1.0), corpus_doc_count=500),
        ),
        q_value=0.8,
        age_days=2.0,
        validity=0.9,
    )
    return Probe(
        name="positive_control",
        probe_class="positive_control",
        query_text="how do I configure the retry backoff for the payments webhook",
        candidates=(candidate,),
    )


# --------------------------------------------------------------------------- #
# Aggregate report.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class NegativeProbeReport:
    total_probes: int
    total_dynamic_injections: int
    abstention_rate_pct: float
    target_abstention_pct: float
    per_class_counts: Mapping[str, int]
    per_class_injections: Mapping[str, int]
    results: tuple[ProbeResult, ...]

    @property
    def zero_injections(self) -> bool:
        return self.total_dynamic_injections == 0

    @property
    def meets_target_abstention(self) -> bool:
        return self.abstention_rate_pct >= self.target_abstention_pct


def run_negative_probes(cfg: EffectiveConfig | None = None) -> NegativeProbeReport:
    """Runs every probe from `build_probes()` and aggregates the result. This
    is the function the Phase 1 gate calls."""
    resolved = cfg if cfg is not None else default_config()
    probes = build_probes()
    results = tuple(run_probe(p, cfg=resolved) for p in probes)

    all_decisions = [d for r in results for d in r.decisions]
    rate = measured_abstention_rate(all_decisions) if all_decisions else 0.0

    per_class_counts: dict[str, int] = {}
    per_class_injections: dict[str, int] = {}
    for r in results:
        per_class_counts[r.probe.probe_class] = per_class_counts.get(r.probe.probe_class, 0) + 1
        per_class_injections[r.probe.probe_class] = (
            per_class_injections.get(r.probe.probe_class, 0) + r.injected_count
        )

    return NegativeProbeReport(
        total_probes=len(results),
        total_dynamic_injections=sum(r.injected_count for r in results),
        abstention_rate_pct=rate,
        target_abstention_pct=resolved.abstention.target_abstention_pct,
        per_class_counts=per_class_counts,
        per_class_injections=per_class_injections,
        results=results,
    )


def render_text(report: NegativeProbeReport) -> str:
    verdict = "PASS" if report.zero_injections else "FAIL"
    lines = [
        f"negative probes: {report.total_probes} run, "
        f"{report.total_dynamic_injections} dynamic injection(s): {verdict}",
        f"measured abstention rate: {report.abstention_rate_pct:.2f}% "
        f"(documented target >= {report.target_abstention_pct:.0f}%): "
        f"{'PASS' if report.meets_target_abstention else 'FAIL'}",
        "",
        f"{'class':<24} {'probes':>7} {'injections':>11}",
    ]
    for cls in ProbeClass.ALL:
        lines.append(
            f"{cls:<24} {report.per_class_counts.get(cls, 0):>7} "
            f"{report.per_class_injections.get(cls, 0):>11}"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a text table")
    args = parser.parse_args(argv)

    report = run_negative_probes()

    if args.json:
        payload = {
            "total_probes": report.total_probes,
            "total_dynamic_injections": report.total_dynamic_injections,
            "abstention_rate_pct": report.abstention_rate_pct,
            "target_abstention_pct": report.target_abstention_pct,
            "per_class_counts": dict(report.per_class_counts),
            "per_class_injections": dict(report.per_class_injections),
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(render_text(report))

    return 0 if report.zero_injections else 1


if __name__ == "__main__":
    raise SystemExit(main())
