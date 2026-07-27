"""The rarity gate in isolation (PLAN.md §6 `abstention.rarity_*`; D-020's IDF cousin).

`rare_shared_term_count` / `rarity_gate_passes` are the IDF computation that
stops a generic query from matching generic memory — a bare cosine hit is
not enough; at least `rarity_min_shared_terms` of the terms the query and
the candidate actually share must each be rare in the project's corpus.
"""

from __future__ import annotations

import pytest

from tracebed.domain.config import AbstentionConfig
from tracebed.hotpath.abstention import RarityEvidence, rare_shared_term_count, rarity_gate_passes

pytestmark = pytest.mark.phase1


def _rarity(pcts: tuple[float, ...], corpus: int) -> RarityEvidence:
    return RarityEvidence(shared_term_doc_freq_pct=pcts, corpus_doc_count=corpus)


# --------------------------------------------------------------------------- #
# rare_shared_term_count
# --------------------------------------------------------------------------- #


def test_rare_shared_term_count_counts_terms_at_or_under_the_df_ceiling() -> None:
    cfg = AbstentionConfig()  # rarity_max_df_pct = 2.0
    rarity = _rarity((0.5, 1.9, 2.0, 2.1, 50.0), corpus=1_000)

    # 0.5, 1.9, 2.0 all qualify (<=); 2.1 and 50.0 do not.
    assert rare_shared_term_count(rarity, cfg) == 3


def test_rare_shared_term_count_boundary_is_inclusive() -> None:
    cfg = AbstentionConfig()
    exactly_at_ceiling = _rarity((cfg.rarity_max_df_pct,), corpus=1_000)
    just_over_ceiling = _rarity((cfg.rarity_max_df_pct + 0.0001,), corpus=1_000)

    assert rare_shared_term_count(exactly_at_ceiling, cfg) == 1
    assert rare_shared_term_count(just_over_ceiling, cfg) == 0


def test_rare_shared_term_count_of_no_shared_terms_is_zero() -> None:
    cfg = AbstentionConfig()
    assert rare_shared_term_count(_rarity((), corpus=1_000), cfg) == 0


def test_rare_shared_term_count_follows_a_non_default_df_ceiling() -> None:
    """The ceiling comes from `rarity_max_df_pct`, not from a literal 2.0 that
    happens to match Phase 0's default (hard rule 4)."""
    terms = (0.5, 1.9, 2.0, 2.1, 9.9, 50.0)
    strict = AbstentionConfig(rarity_max_df_pct=0.6)
    lenient = AbstentionConfig(rarity_max_df_pct=10.0)

    assert rare_shared_term_count(_rarity(terms, corpus=1_000), strict) == 1
    assert rare_shared_term_count(_rarity(terms, corpus=1_000), lenient) == 5


# --------------------------------------------------------------------------- #
# rarity_gate_passes: common-only terms rejected, rare terms accepted.
# --------------------------------------------------------------------------- #


def test_rarity_gate_rejects_a_query_sharing_only_common_terms() -> None:
    cfg = AbstentionConfig()
    # Two shared terms, both far above the 2.0% rarity ceiling: a generic
    # query matching generic memory, exactly what this gate exists to stop.
    common_only = _rarity((45.0, 60.0), corpus=1_000)

    assert rarity_gate_passes(common_only, cfg) is False


def test_rarity_gate_accepts_a_query_sharing_two_rare_terms() -> None:
    cfg = AbstentionConfig()
    two_rare = _rarity((0.3, 1.5), corpus=1_000)

    assert rarity_gate_passes(two_rare, cfg) is True


def test_rarity_gate_rejects_one_rare_term_short_of_the_minimum() -> None:
    cfg = AbstentionConfig()  # rarity_min_shared_terms defaults to 2
    one_rare = _rarity((0.3,), corpus=1_000)

    assert rarity_gate_passes(one_rare, cfg) is False


def test_rarity_gate_honours_a_configured_shared_term_minimum() -> None:
    """The gate reads `rarity_min_shared_terms` from config — not a literal 2."""
    cfg = AbstentionConfig(rarity_min_shared_terms=3)
    two_rare = _rarity((0.3, 0.5), corpus=1_000)
    three_rare = _rarity((0.3, 0.5, 1.0), corpus=1_000)

    assert rarity_gate_passes(two_rare, cfg) is False
    assert rarity_gate_passes(three_rare, cfg) is True


# --------------------------------------------------------------------------- #
# Cold start folds into the rarity gate.
# --------------------------------------------------------------------------- #


def test_rarity_gate_cold_start_below_the_floor_fails_unconditionally() -> None:
    cfg = AbstentionConfig()
    perfectly_rare_but_young_project = _rarity(
        (0.01, 0.01, 0.01), corpus=cfg.rarity_min_corpus_docs - 1
    )

    assert rarity_gate_passes(perfectly_rare_but_young_project, cfg) is False


def test_rarity_gate_corpus_exactly_at_the_floor_is_not_cold_start() -> None:
    cfg = AbstentionConfig()
    at_floor = _rarity((0.3, 0.5), corpus=cfg.rarity_min_corpus_docs)

    assert rarity_gate_passes(at_floor, cfg) is True


def test_rarity_gate_zero_corpus_docs_fails() -> None:
    cfg = AbstentionConfig()
    assert rarity_gate_passes(_rarity((0.01, 0.02), corpus=0), cfg) is False


def test_rarity_gate_cold_start_floor_follows_config() -> None:
    """One corpus size, two floors: the same evidence passes under a floor it
    clears and fails under one it does not — the floor is `rarity_min_corpus_docs`,
    not a literal 200."""
    evidence = _rarity((0.3, 0.5), corpus=500)

    assert rarity_gate_passes(evidence, AbstentionConfig(rarity_min_corpus_docs=100)) is True
    assert rarity_gate_passes(evidence, AbstentionConfig(rarity_min_corpus_docs=10_000)) is False


# --------------------------------------------------------------------------- #
# RarityEvidence input validation — malformed evidence must fail loudly, not
# silently compute a plausible-looking wrong gate result.
# --------------------------------------------------------------------------- #


def test_rarity_evidence_rejects_negative_corpus_doc_count() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        RarityEvidence(shared_term_doc_freq_pct=(1.0,), corpus_doc_count=-1)


@pytest.mark.parametrize("bad_pct", [-0.1, 100.1])
def test_rarity_evidence_rejects_out_of_range_doc_freq_pct(bad_pct: float) -> None:
    with pytest.raises(ValueError, match="0, 100"):
        RarityEvidence(shared_term_doc_freq_pct=(bad_pct,), corpus_doc_count=1_000)
