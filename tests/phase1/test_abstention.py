"""Abstention from calibrated raw signals (PLAN.md §6 `abstention.*`; D-015).

Every test here is pure and offline: `AbstentionConfig`/`ScoreConfig` are
constructed directly from their Phase-0 defaults, no Postgres/Valkey/S3
fixture is touched, and nothing imports a clock — `hotpath.abstention` and
`hotpath.calibration` take no I/O.
"""

from __future__ import annotations

import random
from itertools import pairwise

import pytest

from tracebed.domain.config import AbstentionConfig, ScoreConfig
from tracebed.domain.enums import OutcomeCode
from tracebed.hotpath.abstention import (
    AbstentionDecision,
    CandidateSignals,
    RarityEvidence,
    decide,
    measured_abstention_rate,
)
from tracebed.hotpath.calibration import (
    CalibratedSignals,
    bm25_saturate,
    calibrated_score,
    recency_weight,
)

pytestmark = pytest.mark.phase1


def _rarity(pcts: tuple[float, ...], corpus: int = 1_000) -> RarityEvidence:
    return RarityEvidence(shared_term_doc_freq_pct=pcts, corpus_doc_count=corpus)


def _signals(
    *, cos: float = 0.9, bm25: float = 50.0, pcts: tuple[float, ...] = (0.5, 0.5), corpus: int = 1_000
) -> CandidateSignals:
    return CandidateSignals(cos_sim=cos, bm25_raw=bm25, rarity=_rarity(pcts, corpus))


# --------------------------------------------------------------------------- #
# Each gate fires independently, with the correct OutcomeCode.
# --------------------------------------------------------------------------- #


def test_cos_gate_fires_alone() -> None:
    cfg = AbstentionConfig()
    # bm25 and rarity both comfortably clear their gates; only cos_sim fails.
    signals = _signals(cos=0.10, bm25=500.0, pcts=(0.1, 0.2), corpus=1_000)
    decision = decide(signals, cfg)

    assert decision.inject is False
    assert decision.outcome_code is OutcomeCode.ABSTAINED_THRESHOLD


def test_bm25_gate_fires_alone() -> None:
    cfg = AbstentionConfig()
    # cos and rarity both comfortably clear; bm25_raw is small enough that
    # saturation puts it well under the 0.50 norm threshold.
    signals = _signals(cos=0.95, bm25=0.01, pcts=(0.1, 0.2), corpus=1_000)
    decision = decide(signals, cfg)

    assert decision.bm25_norm < cfg.bm25_norm_threshold
    assert decision.inject is False
    assert decision.outcome_code is OutcomeCode.ABSTAINED_THRESHOLD


def test_rarity_gate_fires_alone() -> None:
    cfg = AbstentionConfig()
    # cos and bm25 both comfortably clear; only one shared term is rare
    # (rarity_min_shared_terms defaults to 2), and corpus is well above the
    # cold-start floor so this is a genuine rarity failure, not cold start.
    signals = _signals(cos=0.95, bm25=500.0, pcts=(0.1,), corpus=1_000)
    decision = decide(signals, cfg)

    assert decision.inject is False
    assert decision.outcome_code is OutcomeCode.ABSTAINED_RARITY


@pytest.mark.parametrize(
    "signals",
    [
        _signals(cos=0.10, bm25=500.0, pcts=(0.1, 0.2), corpus=1_000),  # fails cos only
        _signals(cos=0.95, bm25=0.01, pcts=(0.1, 0.2), corpus=1_000),  # fails bm25 only
        _signals(cos=0.95, bm25=500.0, pcts=(0.1,), corpus=1_000),  # fails rarity only
    ],
)
def test_failing_exactly_one_gate_abstains(signals: CandidateSignals) -> None:
    """A candidate passing two of the three gates still abstains overall."""
    cfg = AbstentionConfig()
    decision = decide(signals, cfg)
    assert decision.inject is False
    assert decision.outcome_code is not None


def test_all_three_gates_passing_injects() -> None:
    cfg = AbstentionConfig()
    signals = _signals(cos=0.95, bm25=500.0, pcts=(0.1, 0.2), corpus=1_000)
    decision = decide(signals, cfg)
    assert decision.inject is True
    assert decision.outcome_code is None


# --------------------------------------------------------------------------- #
# Every threshold is READ FROM CONFIG, not a literal matching Phase 0's default
# (hard rule 4). Each test below moves one knob off its default and asserts the
# decision follows it — an implementation that hardcoded 0.60 / 0.50 / 10.0 /
# 2.0 / 200 would pass every default-config test above and fail these.
# --------------------------------------------------------------------------- #


def test_cos_gate_follows_a_non_default_cos_threshold() -> None:
    lenient = AbstentionConfig(cos_threshold=0.20)
    strict = AbstentionConfig(cos_threshold=0.99)
    signals = _signals(cos=0.50, bm25=500.0, pcts=(0.1, 0.2), corpus=1_000)

    assert decide(signals, lenient).inject is True
    strict_decision = decide(signals, strict)
    assert strict_decision.inject is False
    assert strict_decision.outcome_code is OutcomeCode.ABSTAINED_THRESHOLD


def test_cos_exactly_at_the_threshold_injects() -> None:
    """The comparison is `cos_sim < cos_threshold`, so equality passes."""
    cfg = AbstentionConfig()
    at_threshold = _signals(cos=cfg.cos_threshold, bm25=500.0, pcts=(0.1, 0.2), corpus=1_000)

    assert decide(at_threshold, cfg).inject is True


def test_bm25_gate_follows_a_non_default_norm_threshold() -> None:
    cfg_default = AbstentionConfig()
    # bm25_raw == bm25_sat_k saturates to exactly 0.5 (x / (x + k) at x == k).
    signals = _signals(cos=0.95, bm25=cfg_default.bm25_sat_k, pcts=(0.1, 0.2), corpus=1_000)

    # Exactly at the default 0.50 threshold: `<` means equality injects.
    assert decide(signals, cfg_default).bm25_norm == pytest.approx(0.5)
    assert decide(signals, cfg_default).inject is True

    stricter = AbstentionConfig(bm25_norm_threshold=0.90)
    strict_decision = decide(signals, stricter)
    assert strict_decision.inject is False
    assert strict_decision.outcome_code is OutcomeCode.ABSTAINED_THRESHOLD


def test_bm25_gate_follows_a_non_default_saturation_k() -> None:
    """`bm25_sat_k` sets the raw score that normalises to 0.5; moving it moves
    where a fixed raw score lands relative to `bm25_norm_threshold`."""
    raw = 20.0
    lenient = AbstentionConfig(bm25_sat_k=5.0)  # 20/25 = 0.80 -> clears 0.50
    strict = AbstentionConfig(bm25_sat_k=500.0)  # 20/520 = 0.038 -> misses 0.50
    signals = _signals(cos=0.95, bm25=raw, pcts=(0.1, 0.2), corpus=1_000)

    assert decide(signals, lenient).bm25_norm == pytest.approx(0.8)
    assert decide(signals, lenient).inject is True
    assert decide(signals, strict).inject is False
    assert decide(signals, strict).outcome_code is OutcomeCode.ABSTAINED_THRESHOLD


def test_rarity_gate_follows_a_non_default_max_df_pct() -> None:
    lenient = AbstentionConfig(rarity_max_df_pct=30.0)
    strict = AbstentionConfig(rarity_max_df_pct=0.05)
    signals = _signals(cos=0.95, bm25=500.0, pcts=(10.0, 20.0), corpus=1_000)

    assert decide(signals, lenient).inject is True
    assert decide(signals, strict).inject is False
    assert decide(signals, strict).outcome_code is OutcomeCode.ABSTAINED_RARITY


def test_cold_start_floor_follows_a_non_default_min_corpus_docs() -> None:
    corpus = 500
    permissive = AbstentionConfig(rarity_min_corpus_docs=100)
    conservative = AbstentionConfig(rarity_min_corpus_docs=10_000)
    signals = _signals(cos=0.95, bm25=500.0, pcts=(0.1, 0.2), corpus=corpus)

    assert decide(signals, permissive).inject is True
    assert decide(signals, conservative).inject is False
    assert decide(signals, conservative).outcome_code is OutcomeCode.ABSTAINED_RARITY


# --------------------------------------------------------------------------- #
# Malformed signals fail LOUD, never fail open. A NaN or infinite raw score
# compares False against every `<` threshold, so an unguarded gate would let
# exactly the most broken candidate through all three gates and inject it.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("bad_bm25", [float("nan"), float("inf")])
def test_non_finite_bm25_is_refused_not_injected(bad_bm25: float) -> None:
    with pytest.raises(ValueError, match="finite"):
        CandidateSignals(cos_sim=0.95, bm25_raw=bad_bm25, rarity=_rarity((0.1, 0.2)))


def test_nan_cos_sim_is_refused() -> None:
    with pytest.raises(ValueError, match="finite"):
        CandidateSignals(cos_sim=float("nan"), bm25_raw=50.0, rarity=_rarity((0.1, 0.2)))


@pytest.mark.parametrize("bad_cos", [-1.01, 1.01, float("inf")])
def test_out_of_range_cos_sim_is_refused(bad_cos: float) -> None:
    with pytest.raises(ValueError, match=r"\[-1, 1\]"):
        CandidateSignals(cos_sim=bad_cos, bm25_raw=50.0, rarity=_rarity((0.1, 0.2)))


def test_negative_cosine_abstains_rather_than_raising() -> None:
    """`1 - (embedding <=> query)` over pgvector cosine ops is genuinely
    negative for a candidate pointing away from the query. That is an ordinary
    abstention input; refusing it would report a working abstention as the
    store-error rung of the degradation ladder."""
    cfg = AbstentionConfig()
    opposed = CandidateSignals(cos_sim=-0.8, bm25_raw=500.0, rarity=_rarity((0.1, 0.2)))

    decision = decide(opposed, cfg)
    assert decision.inject is False
    assert decision.outcome_code is OutcomeCode.ABSTAINED_THRESHOLD


def test_negative_bm25_is_refused() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        CandidateSignals(cos_sim=0.95, bm25_raw=-1.0, rarity=_rarity((0.1, 0.2)))


# --------------------------------------------------------------------------- #
# Cold start: conservative regardless of how good every other signal looks.
# --------------------------------------------------------------------------- #


def test_cold_start_abstains_even_for_a_perfect_candidate() -> None:
    """The one case that matters most: nothing about signal quality can buy
    an exit from cold start (`rarity_min_corpus_docs`, default 200)."""
    cfg = AbstentionConfig()
    perfect = CandidateSignals(
        cos_sim=1.0,
        bm25_raw=1_000_000.0,
        rarity=RarityEvidence(
            shared_term_doc_freq_pct=(0.01, 0.01, 0.01),  # maximally rare
            corpus_doc_count=cfg.rarity_min_corpus_docs - 1,  # just short of the floor
        ),
    )
    decision = decide(perfect, cfg)

    assert decision.inject is False
    assert decision.outcome_code is OutcomeCode.ABSTAINED_RARITY


def test_corpus_at_exactly_the_floor_is_not_cold_start() -> None:
    """`rarity_min_corpus_docs` documents is enough; the floor is a `<`, not `<=`."""
    cfg = AbstentionConfig()
    signals = CandidateSignals(
        cos_sim=0.95,
        bm25_raw=500.0,
        rarity=RarityEvidence(
            shared_term_doc_freq_pct=(0.1, 0.2),
            corpus_doc_count=cfg.rarity_min_corpus_docs,
        ),
    )
    decision = decide(signals, cfg)
    assert decision.inject is True


# --------------------------------------------------------------------------- #
# BM25 saturation: monotonic, bounded in [0, 1).
# --------------------------------------------------------------------------- #


def test_bm25_saturate_boundary_values() -> None:
    assert bm25_saturate(0.0, k=10.0) == 0.0
    # x / (x + k) at x == k is exactly 0.5 by construction.
    assert bm25_saturate(10.0, k=10.0) == pytest.approx(0.5)


def test_bm25_saturate_is_monotonic_and_bounded() -> None:
    raws = [0.0, 0.5, 1.0, 5.0, 10.0, 50.0, 1_000.0, 1_000_000.0]
    normed = [bm25_saturate(x, k=10.0) for x in raws]

    for prior, nxt in pairwise(normed):
        assert nxt > prior  # strictly increasing over strictly increasing raws

    for value in normed:
        assert 0.0 <= value < 1.0  # never reaches 1, however large raw_bm25 gets


def test_bm25_saturate_never_exceeds_one_for_absurd_magnitudes() -> None:
    """The gate is `bm25_norm < threshold`; a normalised score above 1.0 would
    make `bm25_norm_threshold` meaningless for large raw scores. Float rounding
    can reach exactly 1.0 (`raw + k == raw` past ~`k * 2**53`) — it must never
    go past it, and must stay non-decreasing on the way."""
    extremes = [1e6, 1e15, 1e17, 1e100, 1.0e308]
    normed = [bm25_saturate(x, k=10.0) for x in extremes]

    for value in normed:
        assert 0.0 <= value <= 1.0
    for prior, nxt in pairwise(normed):
        assert nxt >= prior


def test_bm25_saturate_rejects_invalid_input() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        bm25_saturate(-1.0, k=10.0)
    with pytest.raises(ValueError, match="positive"):
        bm25_saturate(5.0, k=0.0)


@pytest.mark.parametrize("bad_raw", [float("nan"), float("inf")])
def test_bm25_saturate_rejects_non_finite_raw(bad_raw: float) -> None:
    """`inf / (inf + k)` and any NaN both evaluate to NaN, and NaN compares
    False against every threshold — the one input that would sail past a `<`
    gate must not be silently normalised."""
    with pytest.raises(ValueError, match="finite"):
        bm25_saturate(bad_raw, k=10.0)


# --------------------------------------------------------------------------- #
# Recency decay: halves at exactly the half-life.
# --------------------------------------------------------------------------- #


def test_recency_weight_halves_at_exactly_the_half_life() -> None:
    assert recency_weight(0.0, half_life_days=14.0) == pytest.approx(1.0)
    assert recency_weight(14.0, half_life_days=14.0) == pytest.approx(0.5)
    assert recency_weight(28.0, half_life_days=14.0) == pytest.approx(0.25)
    assert recency_weight(42.0, half_life_days=14.0) == pytest.approx(0.125)


def test_recency_weight_rejects_invalid_input() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        recency_weight(-1.0, half_life_days=14.0)
    with pytest.raises(ValueError, match="positive"):
        recency_weight(1.0, half_life_days=0.0)


def test_calibrated_score_is_the_documented_weighted_sum() -> None:
    """Four DISTINCT signal values, so swapping any two weights changes the
    result — with every signal at 1.0 a `w_sim <-> w_validity` swap is
    invisible."""
    cfg = ScoreConfig()  # w_sim .40 / w_q .30 / w_recency .15 / w_validity .15, half-life 14
    signals = CalibratedSignals(cos_sim=0.90, q_value=0.20, age_days=14.0, validity=0.40)

    score = calibrated_score(signals, cfg)

    expected = cfg.w_sim * 0.90 + cfg.w_q * 0.20 + cfg.w_recency * 0.5 + cfg.w_validity * 0.40
    assert score == pytest.approx(expected)


def test_calibrated_score_reads_every_weight_from_config() -> None:
    """Non-default, mutually distinct weights and a non-default half-life: an
    implementation with Phase 0's defaults baked in as literals fails here."""
    cfg = ScoreConfig(w_sim=0.10, w_q=0.20, w_recency=0.30, w_validity=0.40, recency_half_life_days=7)
    signals = CalibratedSignals(cos_sim=0.90, q_value=0.20, age_days=7.0, validity=0.40)

    score = calibrated_score(signals, cfg)

    expected = 0.10 * 0.90 + 0.20 * 0.20 + 0.30 * 0.5 + 0.40 * 0.40
    assert score == pytest.approx(expected)


def test_calibrated_score_recency_term_follows_the_configured_half_life() -> None:
    """One age, two half-lives: only the recency term may move, and it must
    move exactly as the half-life says."""
    signals = CalibratedSignals(cos_sim=0.90, q_value=0.20, age_days=14.0, validity=0.40)
    short = ScoreConfig(recency_half_life_days=14)  # age == half-life -> 0.5
    long = ScoreConfig(recency_half_life_days=28)  # age == half a half-life -> 2**-0.5

    delta = calibrated_score(signals, long) - calibrated_score(signals, short)
    assert delta == pytest.approx(short.w_recency * (recency_weight(14.0, half_life_days=28.0) - 0.5))
    assert delta > 0  # a longer half-life can only make an aged memory score higher


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("cos_sim", float("nan")),
        ("cos_sim", 1.5),
        ("q_value", float("nan")),
        ("q_value", 1.5),
        ("validity", -0.1),
        ("age_days", float("nan")),
        ("age_days", -1.0),
    ],
)
def test_calibrated_signals_refuse_malformed_input(field: str, bad: float) -> None:
    """A NaN anywhere makes the composite NaN, and a NaN score neither sorts
    nor compares — it silently scrambles which memories get the token budget."""
    kwargs: dict[str, float] = {"cos_sim": 0.9, "q_value": 0.5, "age_days": 1.0, "validity": 0.5}
    kwargs[field] = bad
    with pytest.raises(ValueError):
        CalibratedSignals(**kwargs)


# --------------------------------------------------------------------------- #
# Measured abstention rate — what the negative-probe harness checks against
# PLAN.md §6's target_abstention_pct >= 50 (see abstention.py's docstring for
# why that field is a contract_gap rather than a config read here).
# --------------------------------------------------------------------------- #


def test_measured_abstention_rate_computes_percentage() -> None:
    """Deliberately asymmetric (1 of 4, not 2 of 4): a 50/50 mix cannot tell
    "percentage abstained" from "percentage injected"."""
    injected = AbstentionDecision(inject=True, outcome_code=None, bm25_norm=0.9, rare_shared_term_count=3)
    abstained = AbstentionDecision(
        inject=False, outcome_code=OutcomeCode.ABSTAINED_THRESHOLD, bm25_norm=0.1, rare_shared_term_count=0
    )

    assert measured_abstention_rate([injected, abstained, injected, injected]) == pytest.approx(25.0)
    assert measured_abstention_rate([abstained, abstained, abstained, injected]) == pytest.approx(75.0)
    assert measured_abstention_rate([injected]) == pytest.approx(0.0)
    assert measured_abstention_rate([abstained]) == pytest.approx(100.0)


def test_measured_abstention_rate_rejects_empty_input() -> None:
    with pytest.raises(ValueError):
        measured_abstention_rate([])


def test_measured_abstention_rate_meets_target_on_a_representative_mix() -> None:
    """A stand-in for the negative-probe harness's real corpus: a mix of
    cold-start, borderline, and clearly-relevant candidates. Not a proof that
    production traffic clears 50% — that is the harness's job against real
    signals — but it demonstrates the gates are calibrated to abstain more
    often than not on an unremarkable mix, per PLAN.md §6's documented target.
    """
    cfg = AbstentionConfig()
    mix = [
        _signals(cos=0.20, bm25=1.0, pcts=(10.0, 20.0), corpus=1_000),  # fails everything
        _signals(cos=0.95, bm25=500.0, pcts=(50.0,), corpus=1_000),  # only common terms
        CandidateSignals(cos_sim=0.9, bm25_raw=200.0, rarity=_rarity((0.1, 0.2), corpus=50)),  # cold start
        _signals(cos=0.55, bm25=500.0, pcts=(0.1, 0.2), corpus=1_000),  # just under cos_threshold
        _signals(cos=0.95, bm25=500.0, pcts=(0.1, 0.2), corpus=1_000),  # clears everything
        _signals(cos=0.99, bm25=1_000.0, pcts=(0.1, 0.2, 0.3), corpus=5_000),  # clears everything
    ]
    decisions = [decide(s, cfg) for s in mix]

    assert measured_abstention_rate(decisions) >= 50.0


# --------------------------------------------------------------------------- #
# Property test: abstention is monotone in every signal.
#
# Strictly worsening any one signal (or several at once) can never turn an
# abstain into an inject — each gate is a non-decreasing function of its own
# signal and injection requires ALL of them to pass, so the boolean
# `inject(...)` is itself non-decreasing in "how good the signals are".
# No `hypothesis` dependency exists in this project (D-036's dependency list
# has none), so this drives many random trials with a fixed seed instead.
# --------------------------------------------------------------------------- #


def _worsen_toward(x: float, floor: float, rng: random.Random) -> float:
    """Move `x` some random part of the way toward `floor` — never away from it.

    Written as an interpolation toward a floor rather than a multiplication by
    a factor in `[0, 1)`: scaling *raises* a negative cosine toward zero, which
    is an improvement, so a scale-down helper would have made the negative half
    of the cosine domain silently untested.
    """
    return x - rng.random() * (x - floor)


def _worsen(signals: CandidateSignals, rng: random.Random) -> CandidateSignals:
    """Return signals that are componentwise no better than `signals` in every
    dimension the gates read, worsening exactly one randomly-chosen dimension."""
    dimension = rng.choice(("cos", "bm25", "rarity", "corpus"))
    cos, bm25 = signals.cos_sim, signals.bm25_raw
    pcts = list(signals.rarity.shared_term_doc_freq_pct)
    corpus = signals.rarity.corpus_doc_count

    if dimension == "cos":
        cos = _worsen_toward(cos, -1.0, rng)
    elif dimension == "bm25":
        bm25 = _worsen_toward(bm25, 0.0, rng)
    elif dimension == "rarity" and pcts:
        i = rng.randrange(len(pcts))
        if rng.random() < 0.5:
            pcts.pop(i)  # fewer shared terms can only reduce the rare-term count
        else:
            pcts[i] = 100.0  # push this term to "as common as possible" -> never rare
    elif dimension == "corpus":
        corpus = int(corpus * rng.random())  # only shrinks, pushing toward cold start

    return CandidateSignals(
        cos_sim=cos, bm25_raw=bm25, rarity=RarityEvidence(tuple(pcts), corpus)
    )


def test_abstention_is_monotone_worsening_never_flips_abstain_to_inject() -> None:
    cfg = AbstentionConfig()
    rng = random.Random(20260726)  # fixed seed: deterministic, reproducible failures

    for _ in range(500):
        cos = rng.uniform(-1.0, 1.0)  # the full pgvector cosine range, negatives included
        bm25 = rng.uniform(0.0, 200.0)
        pcts = tuple(rng.uniform(0.0, 100.0) for _ in range(rng.randint(0, 4)))
        corpus = rng.randint(0, 1_000)
        base = CandidateSignals(cos_sim=cos, bm25_raw=bm25, rarity=RarityEvidence(pcts, corpus))

        before = decide(base, cfg)
        worsened = _worsen(base, rng)
        after = decide(worsened, cfg)

        if not before.inject:
            assert not after.inject, (
                f"worsening turned an abstain into an inject: "
                f"before={base!r} -> {before!r}; after={worsened!r} -> {after!r}"
            )


# --------------------------------------------------------------------------- #
# A gate with no evidence is SKIPPED, not failed (D-065).
# --------------------------------------------------------------------------- #


def _rare_evidence(cfg: AbstentionConfig) -> RarityEvidence:
    """Evidence that clears the rarity gate, so the tests below isolate the other two."""
    return RarityEvidence(
        shared_term_doc_freq_pct=(0.1,) * cfg.rarity_min_shared_terms,
        corpus_doc_count=cfg.rarity_min_corpus_docs,
    )


def test_an_absent_cosine_skips_the_cosine_gate_rather_than_failing_it() -> None:
    """No vector arm ran (the ladder's `degraded_lexical` rung), so no candidate has a cosine.
    Failing the gate would make a rung PLAN.md §2 defines as WORKING return nothing on every
    call, forever, while every dashboard showed a healthy service."""
    cfg = AbstentionConfig()
    decision = decide(
        CandidateSignals(cos_sim=None, bm25_raw=100.0, rarity=_rare_evidence(cfg)), cfg
    )
    assert decision.inject is True
    assert decision.outcome_code is None


def test_an_absent_bm25_skips_only_its_own_gate() -> None:
    cfg = AbstentionConfig()
    assert decide(
        CandidateSignals(cos_sim=0.99, bm25_raw=None, rarity=_rare_evidence(cfg)), cfg
    ).inject is True
    # ... and the cosine gate still applies to the same candidate.
    assert decide(
        CandidateSignals(cos_sim=0.01, bm25_raw=None, rarity=_rare_evidence(cfg)), cfg
    ).outcome_code is OutcomeCode.ABSTAINED_THRESHOLD


def test_an_absent_bm25_reports_no_saturated_score() -> None:
    """The saturation of a signal that does not exist is not 0.0, it is nothing -- 0.0 would be
    indistinguishable from a real, genuinely terrible BM25 score on the Abstention dashboard."""
    cfg = AbstentionConfig()
    assert (
        decide(CandidateSignals(cos_sim=0.9, bm25_raw=None, rarity=_rare_evidence(cfg)), cfg).bm25_norm
        is None
    )


def test_the_rarity_gate_still_applies_when_both_arm_gates_are_skipped() -> None:
    """Skipping a gate for want of evidence must not skip the gate that reads no arm at all."""
    cfg = AbstentionConfig()
    decision = decide(
        CandidateSignals(
            cos_sim=None,
            bm25_raw=100.0,
            rarity=RarityEvidence(shared_term_doc_freq_pct=(), corpus_doc_count=0),
        ),
        cfg,
    )
    assert decision.inject is False
    assert decision.outcome_code is OutcomeCode.ABSTAINED_RARITY


def test_a_candidate_with_no_arm_signal_at_all_is_refused() -> None:
    """`fuse()` cannot produce one (`FusedCandidate` refuses it), so reaching this means a
    caller invented a candidate -- and every gate would be skipped for want of evidence, i.e.
    it would inject on nothing at all."""
    cfg = AbstentionConfig()
    with pytest.raises(ValueError, match="at least one arm"):
        CandidateSignals(cos_sim=None, bm25_raw=None, rarity=_rare_evidence(cfg))
