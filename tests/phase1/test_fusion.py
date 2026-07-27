"""RRF fusion in isolation (PLAN.md §6 `retrieval.rrf_k`; D-015).

Pure and offline: every case here is hand-computed against the documented formula
`rrf(candidate) = sum over arms of weight_arm / (rrf_k + rank_arm)`, never against `fuse()`'s own
internals — a bug that changed the formula and its test in the same way would otherwise pass.
"""

from __future__ import annotations

import dataclasses
import uuid

import pytest

from tracebed.domain.enums import TrustTier
from tracebed.domain.ids import MemoryId
from tracebed.domain.state_machine import Status
from tracebed.hotpath.fusion import ArmSignal, FusedCandidate, fuse
from tracebed.stores.pg.search import ArmHit

pytestmark = pytest.mark.phase1

# Fixed ids so string tie-break order is legible in the tests below: A < B < C < D < E < F < G.
A = MemoryId(uuid.UUID(int=1))
B = MemoryId(uuid.UUID(int=2))
C = MemoryId(uuid.UUID(int=3))
D = MemoryId(uuid.UUID(int=4))
E = MemoryId(uuid.UUID(int=5))
F = MemoryId(uuid.UUID(int=6))
G = MemoryId(uuid.UUID(int=7))


def _hit(memory_id: MemoryId, raw_score: float, *, tier: TrustTier = TrustTier.A) -> ArmHit:
    return ArmHit(memory_id=memory_id, raw_score=raw_score, trust_tier=tier, status=Status.VALIDATED)


def _by_id(fused: list[FusedCandidate]) -> dict[MemoryId, FusedCandidate]:
    return {c.memory_id: c for c in fused}


# --------------------------------------------------------------------------- #
# Exact, hand-computed RRF output.
# --------------------------------------------------------------------------- #


def test_known_rank_lists_produce_the_exact_documented_rrf_output() -> None:
    # Lexical ranks (by descending raw_score): A=1, B=2, C=3.
    lexical = [_hit(A, 5.0), _hit(B, 3.0), _hit(C, 1.0)]
    # Vector ranks: B=1, C=2, A=3.
    vector = [_hit(B, 0.9), _hit(C, 0.5), _hit(A, 0.1)]

    fused = fuse(lexical, vector, rrf_k=60, weight_lexical=1.0, weight_vector=1.0)

    # rrf(A) = 1/61 + 1/63 ; rrf(B) = 1/62 + 1/61 ; rrf(C) = 1/63 + 1/62
    expected_score = {
        A: 1 / 61 + 1 / 63,
        B: 1 / 62 + 1 / 61,
        C: 1 / 63 + 1 / 62,
    }
    expected_order = sorted(expected_score, key=lambda mid: (-expected_score[mid], str(mid)))
    assert [c.memory_id for c in fused] == expected_order
    assert [c.fused_rank for c in fused] == [1, 2, 3]

    by_id = _by_id(fused)
    assert by_id[A].lexical == ArmSignal(raw_score=5.0, rank=1)
    assert by_id[A].vector == ArmSignal(raw_score=0.1, rank=3)
    assert by_id[B].lexical == ArmSignal(raw_score=3.0, rank=2)
    assert by_id[B].vector == ArmSignal(raw_score=0.9, rank=1)
    assert by_id[C].lexical == ArmSignal(raw_score=1.0, rank=3)
    assert by_id[C].vector == ArmSignal(raw_score=0.5, rank=2)


def test_rrf_k_changes_the_fused_ORDER_not_just_the_arithmetic() -> None:
    """`rrf_k` sets how much a strong position in ONE arm is worth against a mediocre position in
    BOTH: `1/(k+rank)` falls off fast in `rank` when `k` is small and flattens as `k` grows.

    The assertion is on `fuse()`'s own OUTPUT ORDER, never on a hand-recomputed margin -- a test
    that recomputes the formula itself and only checks that `fuse()` returned something stays
    green when `fuse()` ignores `rrf_k` entirely, which is exactly the mutation this test has to
    catch.

    A is lexical rank 1 and absent from the vector arm; B is rank 4 in BOTH arms. Solving
    `1/(k+1) = 2/(k+4)` puts the crossover at `k = 2`, so the two configured extremes fall on
    opposite sides of it and the fused order must actually flip:
      k=1  -> A: 1/2   = 0.5000 ; B: 2/5    = 0.4000  -> A first
      k=60 -> A: 1/61  = 0.0164 ; B: 2/64   = 0.0313  -> B first
    """
    # Lexical ranks by descending raw_score: A=1, E=2, F=3, B=4.
    lexical = [_hit(A, 5.0), _hit(E, 4.0), _hit(F, 3.0), _hit(B, 2.0)]
    # Vector ranks: G=1, C=2, D=3, B=4. A is absent from this arm entirely.
    vector = [_hit(G, 0.9), _hit(C, 0.8), _hit(D, 0.7), _hit(B, 0.6)]

    def _order(rrf_k: int) -> dict[MemoryId, int]:
        fused = fuse(lexical, vector, rrf_k=rrf_k, weight_lexical=1.0, weight_vector=1.0)
        return {c.memory_id: c.fused_rank for c in fused}

    small_k = _order(rrf_k=1)
    large_k = _order(rrf_k=60)

    assert small_k[A] < small_k[B], "at rrf_k=1 the single rank-1 hit must win"
    assert large_k[B] < large_k[A], "at rrf_k=60 the two rank-4 hits must win"


# --------------------------------------------------------------------------- #
# Per-arm weights change order predictably.
# --------------------------------------------------------------------------- #


def test_weights_change_order_predictably() -> None:
    # A wins the lexical arm outright; B wins the vector arm outright.
    lexical = [_hit(A, 10.0), _hit(B, 1.0)]
    vector = [_hit(B, 0.99), _hit(A, 0.01)]

    lexical_favoured = fuse(lexical, vector, rrf_k=60, weight_lexical=10.0, weight_vector=0.1)
    vector_favoured = fuse(lexical, vector, rrf_k=60, weight_lexical=0.1, weight_vector=10.0)

    assert lexical_favoured[0].memory_id == A
    assert vector_favoured[0].memory_id == B


def test_zero_weight_on_one_arm_makes_that_arm_irrelevant_to_order() -> None:
    lexical = [_hit(A, 10.0), _hit(B, 1.0)]
    vector = [_hit(B, 0.99), _hit(A, 0.01)]

    fused = fuse(lexical, vector, rrf_k=60, weight_lexical=1.0, weight_vector=0.0)

    # With weight_vector=0, order is decided by lexical rank alone: A (rank 1) beats B (rank 2).
    assert [c.memory_id for c in fused] == [A, B]
    # The vector arm's raw signal is still attached -- zero weight is not the same as absence.
    assert _by_id(fused)[A].vector == ArmSignal(raw_score=0.01, rank=2)


# --------------------------------------------------------------------------- #
# Ties broken deterministically.
# --------------------------------------------------------------------------- #


def test_within_arm_ties_break_by_ascending_memory_id() -> None:
    # A and B tie in the lexical arm; the winner must be A (lower string id), every time.
    lexical = [_hit(B, 5.0), _hit(A, 5.0)]
    fused = fuse(lexical, [], rrf_k=60, weight_lexical=1.0, weight_vector=1.0)
    assert [c.memory_id for c in fused] == [A, B]
    assert _by_id(fused)[A].lexical == ArmSignal(raw_score=5.0, rank=1)
    assert _by_id(fused)[B].lexical == ArmSignal(raw_score=5.0, rank=2)


def test_fused_score_ties_break_by_ascending_memory_id() -> None:
    # C and D each appear in exactly one arm, at the same rank, with equal weights -- their RRF
    # sums are numerically identical, so the tie-break is the only thing that can order them.
    lexical = [_hit(D, 1.0)]
    vector = [_hit(C, 1.0)]
    fused = fuse(lexical, vector, rrf_k=60, weight_lexical=1.0, weight_vector=1.0)
    assert [c.memory_id for c in fused] == [C, D]


def test_repeated_calls_over_the_same_input_agree_on_order() -> None:
    lexical = [_hit(A, 5.0), _hit(B, 5.0), _hit(C, 5.0)]
    first = fuse(lexical, [], rrf_k=60, weight_lexical=1.0, weight_vector=1.0)
    second = fuse(lexical, [], rrf_k=60, weight_lexical=1.0, weight_vector=1.0)
    assert [c.memory_id for c in first] == [c.memory_id for c in second]


# --------------------------------------------------------------------------- #
# An empty arm does not zero the other.
# --------------------------------------------------------------------------- #


def test_empty_vector_arm_does_not_zero_lexical_candidates() -> None:
    lexical = [_hit(A, 5.0), _hit(B, 3.0)]
    fused = fuse(lexical, [], rrf_k=60, weight_lexical=1.0, weight_vector=1.0)

    assert [c.memory_id for c in fused] == [A, B]
    by_id = _by_id(fused)
    assert by_id[A].vector is None
    assert by_id[B].vector is None
    assert by_id[A].lexical == ArmSignal(raw_score=5.0, rank=1)


def test_empty_lexical_arm_does_not_zero_vector_candidates() -> None:
    vector = [_hit(A, 0.9), _hit(B, 0.5)]
    fused = fuse([], vector, rrf_k=60, weight_lexical=1.0, weight_vector=1.0)

    assert [c.memory_id for c in fused] == [A, B]
    by_id = _by_id(fused)
    assert by_id[A].lexical is None
    assert by_id[B].lexical is None


def test_both_arms_empty_returns_empty_list_not_an_error() -> None:
    assert fuse([], [], rrf_k=60, weight_lexical=1.0, weight_vector=1.0) == []


# --------------------------------------------------------------------------- #
# Structural guarantee: no thresholdable scalar score anywhere on the fused object.
# --------------------------------------------------------------------------- #


def test_fused_candidate_exposes_no_top_level_float_score() -> None:
    """D-015: RRF orders, it cannot be thresholded. `FusedCandidate`'s own fields (excluding the
    per-arm `ArmSignal`s, which legitimately carry `raw_score` for abstention to read) must
    contain no float at all -- if one existed, it would be exactly the "fused RRF score" this
    module is designed never to expose."""
    field_types = {f.name: f.type for f in dataclasses.fields(FusedCandidate)}
    assert field_types == {
        "memory_id": "MemoryId",
        "trust_tier": "TrustTier",
        "status": "Status",
        "fused_rank": "int",
        "lexical": "ArmSignal | None",
        "vector": "ArmSignal | None",
    }
    assert "score" not in field_types
    assert "fused_score" not in field_types
    assert "rrf_score" not in field_types


def test_fused_candidate_has_no_score_attribute_or_method_at_all() -> None:
    lexical = [_hit(A, 5.0)]
    (candidate,) = fuse(lexical, [], rrf_k=60, weight_lexical=1.0, weight_vector=1.0)
    for name in ("score", "fused_score", "rrf_score", "raw_score", "threshold"):
        assert not hasattr(candidate, name), f"FusedCandidate must not expose {name!r}"


def test_fused_rank_is_a_total_order_with_no_gaps() -> None:
    lexical = [_hit(A, 5.0), _hit(B, 3.0), _hit(C, 1.0)]
    fused = fuse(lexical, [], rrf_k=60, weight_lexical=1.0, weight_vector=1.0)
    assert [c.fused_rank for c in fused] == [1, 2, 3]


# --------------------------------------------------------------------------- #
# Input validation.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("bad_k", [0, -1])
def test_fuse_rejects_a_non_positive_rrf_k(bad_k: int) -> None:
    with pytest.raises(ValueError, match="rrf_k"):
        fuse([_hit(A, 1.0)], [], rrf_k=bad_k, weight_lexical=1.0, weight_vector=1.0)


def test_fuse_rejects_negative_weights() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        fuse([_hit(A, 1.0)], [], rrf_k=60, weight_lexical=-1.0, weight_vector=1.0)


def test_arm_signal_rejects_a_rank_below_one() -> None:
    with pytest.raises(ValueError, match="rank"):
        ArmSignal(raw_score=1.0, rank=0)


def test_fused_candidate_rejects_absence_from_both_arms() -> None:
    with pytest.raises(ValueError, match="at least one arm"):
        FusedCandidate(
            memory_id=A,
            trust_tier=TrustTier.A,
            status=Status.VALIDATED,
            fused_rank=1,
            lexical=None,
            vector=None,
        )
