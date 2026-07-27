"""Abstention from calibrated raw signals (PLAN.md §6 `abstention.*`, §7 Phase 1; D-015).

Abstention must NEVER be computed from RRF output. RRF (`retrieval.rrf_k`)
fuses two arms into one ordering; a rank cannot be thresholded because rank 1
of a bad candidate set looks identical to rank 1 of a good one. What
abstention consumes instead is the raw signal the retriever attached to a
candidate before fusion: cosine similarity, a saturation-normalised BM25
score (`calibration.bm25_saturate`), and the rarity gate's per-term IDF
evidence.

Three independent gates, each able to abstain on its own:

  1. The rarity gate: at least `rarity_min_shared_terms` query terms shared
     with the candidate, each with a document frequency no higher than
     `rarity_max_df_pct` percent of the corpus — an IDF computation, and the
     one gate that stops a generic query matching generic memory.
  2. `cos_threshold` on the raw vector signal.
  3. `bm25_norm_threshold` on BM25 after saturation (raw BM25 is unbounded
     and not comparable across queries).

Cold start folds into gate 1: below `rarity_min_corpus_docs` documents in
the project there is no statistical basis for an IDF judgement at all, so
the gate fails unconditionally regardless of how good every other signal
looks (a young project has no rarity basis to poison with its own early
feedback loop).

`domain.enums.OutcomeCode` has exactly two abstention codes,
`ABSTAINED_THRESHOLD` and `ABSTAINED_RARITY` (that enum is frozen Phase-0
surface — see PHASE0-CONTRACT.md §3.2). Gates 2 and 3 are both literally
threshold gates on a calibrated signal and share `ABSTAINED_THRESHOLD`; gate
1 (including the cold-start case, which is a rarity-basis failure, not a
threshold miss) reports `ABSTAINED_RARITY`. This module produces at most one
code per decision, chosen by evaluating the gates in the fixed order above
and reporting the first one that fails.

Every signal must be a finite real number. A non-finite one (a NaN cosine, a
NaN or infinite BM25 out of a store that hit an overflow or a null) is
refused at construction rather than fed to a comparison: NaN compares
`False` against everything, so `bm25_norm < bm25_norm_threshold` is `False`
for a NaN and the candidate would sail through every threshold gate and
inject. A malformed signal is the system failing, not the system deciding —
it must surface as the store-error rung of the ladder, never as a silent
injection.

Pure and I/O-free: no repo, no clock, no network — everything the gates need
is passed in as already-computed raw signals.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass

from tracebed.domain.config import AbstentionConfig
from tracebed.domain.enums import OutcomeCode
from tracebed.hotpath.calibration import bm25_saturate

__all__ = [
    "AbstentionDecision",
    "CandidateSignals",
    "RarityEvidence",
    "decide",
    "measured_abstention_rate",
    "rare_shared_term_count",
    "rarity_gate_passes",
]


@dataclass(frozen=True, slots=True)
class RarityEvidence:
    """Per-shared-term document-frequency evidence feeding the rarity gate.

    `shared_term_doc_freq_pct` holds exactly one entry per query term that
    ALSO appears in the candidate's content — genuinely shared terms only;
    tokenising both sides and computing per-term document frequency from
    the `lexemes` tsvector (the corpus-wide IDF source, D-003/D-140) is the
    retriever's job, not this module's. A shared term counts as "rare" when
    its document-frequency percentage is `<= rarity_max_df_pct`.
    """

    shared_term_doc_freq_pct: tuple[float, ...]
    corpus_doc_count: int

    def __post_init__(self) -> None:
        if self.corpus_doc_count < 0:
            raise ValueError(f"corpus_doc_count must be non-negative, got {self.corpus_doc_count!r}")
        for pct in self.shared_term_doc_freq_pct:
            # `not (0 <= pct <= 100)` also refuses NaN, which compares False
            # against every bound and would otherwise silently count as "not
            # rare" rather than as the malformed evidence it is.
            if not 0.0 <= pct <= 100.0:
                raise ValueError(f"document-frequency percentage out of [0, 100]: {pct!r}")


@dataclass(frozen=True, slots=True)
class CandidateSignals:
    """The raw retriever-attached signals abstention consumes for one candidate.

    Never an RRF rank or RRF-fused score (D-015) — `cos_sim` and `bm25_raw`
    are the arms' own pre-fusion signals (`stores.pg.search.ArmHit.raw_score`
    from the vector and lexical arm respectively).
    """

    cos_sim: float | None
    """Cosine similarity, in `[-1, 1]`, or `None` when the vector arm never
    evaluated this candidate.

    The vector arm computes `1 - (embedding <=> query)` over pgvector cosine
    ops, whose range is `[-1, 1]` — a candidate genuinely pointing away from
    the query has a negative cosine, and that is an ordinary "abstain on the
    cosine gate" input, not malformed evidence. Refusing it here would turn a
    working abstention into the store-error rung of the ladder, which is the
    one confusion `retrieval_event.outcome_code` exists to prevent (PLAN.md §5).

    `None` means something different from any number: the arm produced no
    opinion at all. `hotpath.fusion.FusedCandidate` carries `ArmSignal | None`
    per arm for exactly this reason ("a candidate absent from an arm carries
    None rather than a zero score — zero is a real score"), and the whole
    vector arm is absent on the ladder's `degraded_lexical` rung. Substituting
    a number for absent evidence picks a side by accident: 0.0 silently
    abstains every candidate, 1.0 silently injects every candidate, and
    neither is a measurement."""

    bm25_raw: float | None
    """Unbounded, non-negative raw BM25 relevance from the lexical arm,
    pre-saturation, or `None` when the lexical arm never evaluated this
    candidate (see `cos_sim`)."""

    rarity: RarityEvidence

    def __post_init__(self) -> None:
        # `not (lo <= x <= hi)` rather than `x < lo or x > hi`: the former
        # also refuses NaN. See the module docstring — a NaN signal passes
        # every `<` threshold gate and would inject.
        if self.cos_sim is not None and not -1.0 <= self.cos_sim <= 1.0:
            raise ValueError(f"cos_sim must be a finite value in [-1, 1], got {self.cos_sim!r}")
        if self.bm25_raw is not None and (
            not math.isfinite(self.bm25_raw) or self.bm25_raw < 0
        ):
            raise ValueError(f"bm25_raw must be finite and non-negative, got {self.bm25_raw!r}")
        if self.cos_sim is None and self.bm25_raw is None:
            # Not a defensive nicety: a candidate with no signal from EITHER arm
            # is a candidate no arm retrieved. `fuse()` cannot produce one
            # (`FusedCandidate.__post_init__` refuses it), so reaching this
            # means the caller invented a candidate, and every remaining gate
            # would be skipped for want of evidence — i.e. it would inject on
            # nothing at all.
            raise ValueError("a candidate must carry at least one arm's signal")


@dataclass(frozen=True, slots=True)
class AbstentionDecision:
    """The result of running one candidate's signals through all three gates.

    `outcome_code` is `None` iff `inject` is `True` — there is no code for
    "injected", because injection is the absence of an abstention reason
    (`OutcomeCode.INJECTED` is stamped by the assembler once assembly
    actually places the candidate in a slot, which this module has no
    visibility into).
    """

    inject: bool
    outcome_code: OutcomeCode | None
    bm25_norm: float | None
    """`None` iff the lexical arm produced no score for this candidate — the
    saturation of a signal that does not exist is not 0.0, it is nothing."""
    rare_shared_term_count: int


def rare_shared_term_count(rarity: RarityEvidence, cfg: AbstentionConfig) -> int:
    """How many shared query/candidate terms clear the rarity bar.

    A term counts iff its document frequency is `<= rarity_max_df_pct`
    percent of the corpus — this *is* the IDF computation (D-003/D-140: the
    exact per-term document frequency comes from the `lexemes` tsvector, which
    exposes a real DF; `ts_rank` has none, and this gate could not exist
    against it).
    """
    return sum(1 for pct in rarity.shared_term_doc_freq_pct if pct <= cfg.rarity_max_df_pct)


def rarity_gate_passes(rarity: RarityEvidence, cfg: AbstentionConfig) -> bool:
    """Gate 3: enough rare shared terms, AND enough corpus to trust the judgement.

    Cold start is conservative by construction: below
    `rarity_min_corpus_docs` documents the gate fails unconditionally, no
    matter how many rare-looking shared terms a candidate has — a young
    project's IDF percentages are themselves noise, and injecting on top of
    noisy IDF is how memory poisons its own early feedback loop.
    """
    if rarity.corpus_doc_count < cfg.rarity_min_corpus_docs:
        return False
    return rare_shared_term_count(rarity, cfg) >= cfg.rarity_min_shared_terms


def decide(signals: CandidateSignals, cfg: AbstentionConfig) -> AbstentionDecision:
    """Run all three gates and return the first failure, or an inject decision.

    Gate order (cold start folded into gate 1, evaluated first because it is
    the cheapest and most conservative check): rarity/cold-start, then
    `cos_threshold`, then `bm25_norm_threshold`. The order only decides which
    `OutcomeCode` is reported when more than one gate would have failed —
    each gate is independently sufficient to abstain (a candidate must clear
    all three to be injected), which is what makes the "fails exactly one
    gate" test cases below meaningful regardless of the order chosen here.

    A gate whose signal is `None` is SKIPPED, not failed (D-065). A gate is a
    test applied to evidence; with no evidence there is nothing to test, and
    the two alternatives are both wrong in a way that hides: treating absence
    as failure makes the ladder's `degraded_lexical` rung — where no candidate
    has a cosine, because the vector arm never ran — abstain on every single
    candidate, i.e. a rung PLAN.md §2 defines as a WORKING degradation would
    silently return nothing forever; treating absence as a pass by
    substituting a number injects on a measurement nobody took. The rarity
    gate is unaffected either way: it reads neither arm's score, so it still
    applies in full to every candidate, on every rung.
    """
    bm25_norm = (
        None if signals.bm25_raw is None else bm25_saturate(signals.bm25_raw, k=cfg.bm25_sat_k)
    )
    shared_rare = rare_shared_term_count(signals.rarity, cfg)
    cold_start = signals.rarity.corpus_doc_count < cfg.rarity_min_corpus_docs

    if cold_start or shared_rare < cfg.rarity_min_shared_terms:
        return AbstentionDecision(
            inject=False,
            outcome_code=OutcomeCode.ABSTAINED_RARITY,
            bm25_norm=bm25_norm,
            rare_shared_term_count=shared_rare,
        )

    if signals.cos_sim is not None and signals.cos_sim < cfg.cos_threshold:
        return AbstentionDecision(
            inject=False,
            outcome_code=OutcomeCode.ABSTAINED_THRESHOLD,
            bm25_norm=bm25_norm,
            rare_shared_term_count=shared_rare,
        )

    if bm25_norm is not None and bm25_norm < cfg.bm25_norm_threshold:
        return AbstentionDecision(
            inject=False,
            outcome_code=OutcomeCode.ABSTAINED_THRESHOLD,
            bm25_norm=bm25_norm,
            rare_shared_term_count=shared_rare,
        )

    return AbstentionDecision(
        inject=True,
        outcome_code=None,
        bm25_norm=bm25_norm,
        rare_shared_term_count=shared_rare,
    )


def measured_abstention_rate(decisions: Sequence[AbstentionDecision]) -> float:
    """Percentage of `decisions` that abstained — what the negative-probe harness
    asserts against PLAN.md §6's `abstention.target_abstention_pct >= 50`.

    `AbstentionConfig.target_abstention_pct` is that field. It is deliberately
    NOT read here: an abstention rate is a property of a *population* of
    retrievals, and the hot path only ever sees one — a per-call comparison
    against a fleet-level target would be meaningless, and worse, would put a
    reporting number on a decision path. This function exposes the measured rate
    over a caller-supplied population; the harness resolves the target from
    `EffectiveConfig` and does the comparison.
    """
    if not decisions:
        raise ValueError("measured_abstention_rate requires at least one decision")
    abstained = sum(1 for d in decisions if not d.inject)
    return 100.0 * abstained / len(decisions)
