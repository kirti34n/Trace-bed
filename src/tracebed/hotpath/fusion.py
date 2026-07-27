"""Reciprocal Rank Fusion over the two search arms (PLAN.md §6 `retrieval.rrf_k`; D-015).

RRF orders; it cannot be thresholded. `retrieval.rrf_k` (default 60) and the per-arm weights
(`retrieval.rrf_weight_vector` / `rrf_weight_lexical`) combine each arm's own within-arm RANK — not
its raw score — into one fused ordering:

    rrf(candidate) = sum over arms the candidate appears in of  weight_arm / (rrf_k + rank_arm)

Rank, not relevance magnitude: RRF's entire purpose is to fuse two rankings whose raw scores live
on incomparable scales (a BM25 relevance number and a cosine similarity are not the same kind of
quantity) without having to calibrate them against each other first. That is also exactly why its
OUTPUT cannot be thresholded for "good enough to inject" (D-015) — a fused rank-1 candidate from a
bad candidate set is indistinguishable, by rank alone, from a fused rank-1 candidate from a good
one. `FusedCandidate` is built so that fact cannot be un-learned three call frames downstream: it
carries `fused_rank` (an `int`, ordering only) and the untouched `ArmSignal.raw_score` from
whichever arm(s) produced this candidate (`hotpath.abstention.CandidateSignals`' `cos_sim` /
`bm25_raw` are meant to be filled from exactly these fields) — and it has NO field, property, or
method anywhere that reduces the two into one scalar. Abstention (a separate, already-landed
module, `hotpath.abstention`) is the only consumer of the raw signals; this module never imports
it, and never computes a composite itself.

Pure and I/O-free: no repo, no clock, no network. Ties (equal raw score within one arm, or equal
RRF sum across candidates) are broken by ascending `str(memory_id)` — arbitrary but deterministic,
so two runs over the same inputs always agree on order.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from tracebed.domain.enums import TrustTier
from tracebed.domain.ids import MemoryId
from tracebed.domain.state_machine import Status
from tracebed.stores.pg.search import ArmHit

__all__ = [
    "ArmSignal",
    "FusedCandidate",
    "fuse",
]


@dataclass(frozen=True, slots=True)
class ArmSignal:
    """One arm's untouched contribution to a fused candidate.

    `raw_score` is `ArmHit.raw_score`, carried through with no transformation — the calibrated
    signal D-015 says abstention must read, never an RRF rank or an RRF-fused score. `rank` is
    this candidate's 1-indexed position within THIS arm's own ranking (used to compute the RRF
    sum; exposed because a caller diagnosing "why did RRF order these this way" needs it, not
    because anything downstream thresholds it).
    """

    raw_score: float
    rank: int

    def __post_init__(self) -> None:
        if self.rank < 1:
            raise ValueError(f"rank must be >= 1, got {self.rank!r}")


@dataclass(frozen=True, slots=True)
class FusedCandidate:
    """One candidate in the RRF-fused order.

    Deliberately has no field, property, or method that reduces `lexical`/`vector` into one
    scalar: `fused_rank` is an ordering position (`int`), not a magnitude, and the only floats
    anywhere on this object live one level down, inside `ArmSignal`, one per arm that actually
    produced this candidate. A candidate absent from an arm carries `None` for that arm rather
    than a zero score — zero is a real (if minimal) score, and this candidate was simply never
    evaluated by that arm at all.
    """

    memory_id: MemoryId
    trust_tier: TrustTier
    status: Status
    fused_rank: int
    lexical: ArmSignal | None
    vector: ArmSignal | None

    def __post_init__(self) -> None:
        if self.fused_rank < 1:
            raise ValueError(f"fused_rank must be >= 1, got {self.fused_rank!r}")
        if self.lexical is None and self.vector is None:
            raise ValueError("a fused candidate must appear in at least one arm")


def _rank_within_arm(hits: Sequence[ArmHit]) -> dict[MemoryId, int]:
    """1-indexed rank by descending `raw_score`, ties broken by ascending `str(memory_id)` for a
    deterministic order two calls over the same input always agree on."""
    ordered = sorted(hits, key=lambda h: (-h.raw_score, str(h.memory_id)))
    return {hit.memory_id: position for position, hit in enumerate(ordered, start=1)}


def fuse(
    lexical_hits: Sequence[ArmHit],
    vector_hits: Sequence[ArmHit],
    *,
    rrf_k: int,
    weight_lexical: float,
    weight_vector: float,
) -> list[FusedCandidate]:
    """RRF-fuse the two arms' candidate lists into one ordering.

    Every constant this function needs is a caller-supplied parameter sourced from
    `EffectiveConfig.retrieval` (PLAN.md §6, hard rule 4) — nothing here is a literal. An empty
    arm contributes nothing to a candidate's sum (0, not a multiplicative zero across arms), so
    "the other arm returned nothing" never suppresses a candidate the surviving arm found
    (the documented "an empty arm does not zero the other" test).
    """
    if rrf_k <= 0:
        raise ValueError(f"rrf_k must be positive, got {rrf_k!r}")
    if weight_lexical < 0 or weight_vector < 0:
        raise ValueError("RRF arm weights must be non-negative")

    lexical_by_id = {hit.memory_id: hit for hit in lexical_hits}
    vector_by_id = {hit.memory_id: hit for hit in vector_hits}
    lexical_rank = _rank_within_arm(lexical_hits)
    vector_rank = _rank_within_arm(vector_hits)

    all_ids = set(lexical_by_id) | set(vector_by_id)

    def rrf_score(memory_id: MemoryId) -> float:
        score = 0.0
        if memory_id in lexical_rank:
            score += weight_lexical / (rrf_k + lexical_rank[memory_id])
        if memory_id in vector_rank:
            score += weight_vector / (rrf_k + vector_rank[memory_id])
        return score

    scores = {memory_id: rrf_score(memory_id) for memory_id in all_ids}
    ordered_ids = sorted(all_ids, key=lambda mid: (-scores[mid], str(mid)))

    fused: list[FusedCandidate] = []
    for position, memory_id in enumerate(ordered_ids, start=1):
        lexical_hit = lexical_by_id.get(memory_id)
        vector_hit = vector_by_id.get(memory_id)
        source = lexical_hit if lexical_hit is not None else vector_hit
        assert source is not None  # memory_id came from the union of the two id sets above
        fused.append(
            FusedCandidate(
                memory_id=memory_id,
                trust_tier=source.trust_tier,
                status=source.status,
                fused_rank=position,
                lexical=ArmSignal(raw_score=lexical_hit.raw_score, rank=lexical_rank[memory_id])
                if lexical_hit is not None
                else None,
                vector=ArmSignal(raw_score=vector_hit.raw_score, rank=vector_rank[memory_id])
                if vector_hit is not None
                else None,
            )
        )
    return fused
