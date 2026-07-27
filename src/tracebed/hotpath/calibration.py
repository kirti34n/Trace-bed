"""Raw-signal -> calibrated-score mapping (PLAN.md §6 `score.*`; D-015).

RRF (`retrieval.rrf_k`) is used only to *order* the fused candidate list —
it discards score magnitude by construction, so its output encodes consensus
rank, not relevance, and rank 1 of a bad candidate set looks identical to
rank 1 of a good one. Everything below consumes the *raw* signals a
candidate carries (cosine similarity, a saturated BM25 score, the memory's
own Q, an age-based recency weight, and a validity term) and turns them into
one calibrated composite. Nothing here reads a rank.

Pure and I/O-free by construction: no repo, no clock, no network. Callers
(the retriever/assembler) own producing `age_days` from `clock.now()` minus
a stored timestamp — this module never touches a clock (PLAN.md hard rule 3).
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from tracebed.domain.config import ScoreConfig

__all__ = [
    "CalibratedSignals",
    "bm25_saturate",
    "calibrated_score",
    "recency_weight",
]


def bm25_saturate(raw_bm25: float, *, k: float) -> float:
    """Saturate an unbounded BM25 score into `[0, 1]` via `x / (x + k)`.

    Raw BM25 has no fixed upper bound and its scale shifts with query length,
    term rarity, and corpus size — comparing raw BM25 across two different
    queries (exactly what a threshold gate must do) is comparing numbers on
    two different rulers. The saturating transform is non-decreasing in
    `raw_bm25` (worsening the raw score can only lower the normalised one,
    never raise it) and its result can never EXCEED 1, so
    `bm25_norm_threshold` always has meaning regardless of how large a raw
    score gets.

    Bounded by `[0, 1]`, not `[0, 1)`: the real-valued function never reaches
    1, but in binary floating point `raw + k == raw` once `raw` exceeds
    roughly `k * 2**53`, so an astronomically large score returns exactly
    1.0. That is harmless — such a score should pass the gate — and it is the
    *only* value it can round to, so nothing can overshoot a threshold that a
    smaller score would not also have cleared.

    Non-finite inputs are refused rather than propagated: `inf / (inf + k)`
    and any NaN both evaluate to NaN, and NaN compares `False` against every
    threshold, so an overflowed or null store value would sail straight
    through `bm25_norm < bm25_norm_threshold` and inject.
    """
    if not math.isfinite(raw_bm25) or raw_bm25 < 0:
        raise ValueError(f"raw_bm25 must be finite and non-negative, got {raw_bm25!r}")
    if not math.isfinite(k) or k <= 0:
        raise ValueError(f"bm25_sat_k must be finite and positive, got {k!r}")
    return raw_bm25 / (raw_bm25 + k)


def recency_weight(age_days: float, *, half_life_days: float) -> float:
    """Exponential recency decay: exactly `0.5` at `age_days == half_life_days`.

    `2 ** (-age_days / half_life_days)`, i.e. one half-life of age halves the
    weight, two half-lives quarter it, and so on — the standard exponential
    decay parametrisation, chosen so `score.recency_half_life_days` (PLAN.md
    §6) has the literal meaning its name promises.
    """
    # Finiteness checked explicitly for the same reason as `bm25_saturate`: a
    # NaN age passes `age_days < 0` and yields a NaN weight, which then makes
    # the whole composite score NaN and sorts unpredictably.
    if not math.isfinite(age_days) or age_days < 0:
        raise ValueError(f"age_days must be finite and non-negative, got {age_days!r}")
    if not math.isfinite(half_life_days) or half_life_days <= 0:
        raise ValueError(f"half_life_days must be finite and positive, got {half_life_days!r}")
    # `math.pow`, not `0.5 ** x`: typeshed types `float.__pow__` as returning
    # `Any` (the base/exponent pair could in principle produce a complex
    # result), which would make this function's return type unchecked under
    # mypy --strict despite always being a real float in practice.
    return math.pow(0.5, age_days / half_life_days)


@dataclass(frozen=True, slots=True)
class CalibratedSignals:
    """The four calibrated inputs `calibrated_score` combines.

    Every field is a raw, already-calibrated signal — never an RRF rank or
    an RRF-fused score (D-015). Producing these values (looking up Q,
    computing age from a stored timestamp, deriving a validity term from
    `trust_tier`/status) is the retriever/assembler's job, not this module's.
    """

    cos_sim: float
    """Cosine similarity from the vector arm, in `[-1, 1]` — pgvector's
    `1 - (embedding <=> query)` is negative for a candidate pointing away
    from the query, and that is a real (badly-scoring) signal, not malformed
    input."""

    q_value: float
    """The candidate memory's current Q, in `[0, 1]`."""

    age_days: float
    """Age since the signal this recency weight represents (e.g. last
    revalidation or creation), in days, `>= 0`."""

    validity: float
    """A validity term in `[0, 1]` (e.g. lower for a Tier-A `candidate` row
    than for `validated`) — computed upstream, not by this module."""

    def __post_init__(self) -> None:
        """Refuse out-of-range and non-finite inputs at construction.

        Every check is `not (lo <= x <= hi)` so NaN is refused too: a NaN in
        any one term makes the whole composite NaN, and a NaN score neither
        sorts nor compares — it would silently scramble the ranking that
        decides which memories occupy the token budget.
        """
        if not -1.0 <= self.cos_sim <= 1.0:
            raise ValueError(f"cos_sim must be a finite value in [-1, 1], got {self.cos_sim!r}")
        if not 0.0 <= self.q_value <= 1.0:
            raise ValueError(f"q_value must be a finite value in [0, 1], got {self.q_value!r}")
        if not 0.0 <= self.validity <= 1.0:
            raise ValueError(f"validity must be a finite value in [0, 1], got {self.validity!r}")
        if not math.isfinite(self.age_days) or self.age_days < 0:
            raise ValueError(f"age_days must be finite and non-negative, got {self.age_days!r}")


def calibrated_score(signals: CalibratedSignals, cfg: ScoreConfig) -> float:
    """The composite ranking score: `w_sim*cos_sim + w_q*Q + w_recency*recency + w_validity*validity`.

    Every weight comes from `EffectiveConfig.score` (PLAN.md §6) — never a
    literal in this function (hard rule 4). Consumes only calibrated raw
    signals, never RRF output (D-015): RRF orders, it cannot be thresholded
    or weighted into a magnitude-sensitive score.
    """
    recency = recency_weight(signals.age_days, half_life_days=float(cfg.recency_half_life_days))
    return (
        cfg.w_sim * signals.cos_sim
        + cfg.w_q * signals.q_value
        + cfg.w_recency * recency
        + cfg.w_validity * signals.validity
    )
