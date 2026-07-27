"""PLAN.md §7 Phase 1 gate — the headline assertion: "negative probes: 0 dynamic
injections". Report the measured abstention rate against the documented
`>= 50%` target (D-046 / `hotpath.abstention.measured_abstention_rate`'s own
docstring: the field does not exist in `domain.config.AbstentionConfig`, so the
comparison lives here, in the harness, against a literal copy of the documented
target).

Every probe here runs through REAL production code
(`hotpath.abstention.decide`, `hotpath.calibration.calibrated_score`,
`hotpath.assembler.assemble`, and — for a sample — the full
`hotpath.pipeline.Pipeline` orchestrator) over synthetic candidate content; see
`probes.py`'s module docstring for exactly what is faked (candidate content
and where the retriever's two arms found it) and what is not (the decision
itself). `test_positive_control_still_injects` is what proves this is not a
rigged "always abstain" harness.
"""

from __future__ import annotations

import pytest

from harness.negative_probes.probes import (
    TARGET_ABSTENTION_PCT,
    ProbeClass,
    build_probes,
    default_config,
    positive_control_probe,
    run_negative_probes,
    run_probe,
    run_probe_through_pipeline,
)
from tracebed.domain.enums import OutcomeCode

pytestmark = pytest.mark.phase1


# --------------------------------------------------------------------------- #
# The headline gate assertion.
# --------------------------------------------------------------------------- #


def test_at_least_25_probes_are_built() -> None:
    assert len(build_probes()) >= 25


def test_zero_dynamic_injections_across_every_negative_probe() -> None:
    report = run_negative_probes()
    assert report.total_dynamic_injections == 0
    assert report.zero_injections is True
    for result in report.results:
        assert result.injected_count == 0, (
            f"probe {result.probe.name!r} ({result.probe.probe_class}) injected "
            f"{result.injected_count} slot(s) — a negative probe must inject nothing"
        )


def test_measured_abstention_rate_meets_the_documented_target() -> None:
    report = run_negative_probes()
    # The report's target comes from the resolved `EffectiveConfig`, not from the
    # module constant. Asserting they agree is what catches PLAN.md §6's documented
    # default and `AbstentionConfig`'s shipped default drifting apart.
    assert report.target_abstention_pct == default_config().abstention.target_abstention_pct
    assert report.target_abstention_pct == TARGET_ABSTENTION_PCT
    assert report.abstention_rate_pct >= report.target_abstention_pct
    assert report.meets_target_abstention is True
    # Every probe here is a NEGATIVE probe by construction, so the honest
    # measurement over this specific corpus is 100%, not merely >= 50%. A
    # weaker number here would mean some probe's fixture accidentally cleared
    # every gate.
    assert report.abstention_rate_pct == 100.0


# --------------------------------------------------------------------------- #
# Every one of the four classes is represented, with the correct outcome code.
# --------------------------------------------------------------------------- #


def test_all_four_probe_classes_are_represented() -> None:
    report = run_negative_probes()
    for cls in ProbeClass.ALL:
        assert report.per_class_counts.get(cls, 0) >= 1, f"missing probe class {cls!r}"


def test_empty_vault_probes_report_empty_result_not_an_abstention_code() -> None:
    """An empty vault never even reached a candidate to abstain on — the
    correct code is `EMPTY_RESULT`, not one of the two abstention codes."""
    for probe in build_probes():
        if probe.probe_class != ProbeClass.EMPTY_VAULT:
            continue
        assert probe.candidates == ()
        result = run_probe(probe)
        assert result.outcome_code is OutcomeCode.EMPTY_RESULT
        assert result.decisions == ()


def test_uncovered_query_probes_abstain_on_threshold() -> None:
    """Weak cosine/BM25 signals over a healthy, non-cold-start corpus with
    genuinely rare shared terms — the rarity gate passes, so the threshold
    gates are what must fire."""
    for probe in build_probes():
        if probe.probe_class != ProbeClass.UNCOVERED_QUERY:
            continue
        result = run_probe(probe)
        assert result.outcome_code is OutcomeCode.ABSTAINED_THRESHOLD, probe.name
        assert all(not d.inject for d in result.decisions)


def test_generic_common_terms_probes_abstain_on_rarity_not_cold_start() -> None:
    """Strong cosine/BM25 (would otherwise clear the threshold gates easily)
    over a healthy corpus — only common shared terms. The rarity gate must be
    what refuses, and it must not be reachable via the cold-start branch
    (every fixture's corpus_doc_count clears rarity_min_corpus_docs)."""
    from tracebed.domain.config import AbstentionConfig

    cfg_abstention = AbstentionConfig()
    for probe in build_probes():
        if probe.probe_class != ProbeClass.GENERIC_COMMON_TERMS:
            continue
        for candidate in probe.candidates:
            assert candidate.signals.rarity.corpus_doc_count >= cfg_abstention.rarity_min_corpus_docs
        result = run_probe(probe)
        assert result.outcome_code is OutcomeCode.ABSTAINED_RARITY, probe.name


def test_cold_start_probes_abstain_regardless_of_otherwise_excellent_signals() -> None:
    """Every non-rarity signal is deliberately excellent; only corpus size is
    below the cold-start floor. The rarity gate must refuse unconditionally."""
    from tracebed.domain.config import AbstentionConfig

    cfg_abstention = AbstentionConfig()
    for probe in build_probes():
        if probe.probe_class != ProbeClass.COLD_START:
            continue
        for candidate in probe.candidates:
            assert candidate.signals.rarity.corpus_doc_count < cfg_abstention.rarity_min_corpus_docs
            # The signal is genuinely strong, so a naive "just check the
            # rarity code" test could pass even if cold-start stopped being
            # enforced and only the term-commonness path fired instead.
            assert candidate.signals.cos_sim >= cfg_abstention.cos_threshold
        result = run_probe(probe)
        assert result.outcome_code is OutcomeCode.ABSTAINED_RARITY, probe.name


# --------------------------------------------------------------------------- #
# End-to-end: the SAME probes through the real Pipeline orchestrator, not just
# the abstention module in isolation.
# --------------------------------------------------------------------------- #


def test_every_probe_never_injects_through_the_real_pipeline() -> None:
    for probe in build_probes():
        result = run_probe_through_pipeline(probe)
        assert result.outcome_code is not OutcomeCode.INJECTED, probe.name
        assert list(result.context_block.slots) == []
        assert result.context_block.rendered == ""


# --------------------------------------------------------------------------- #
# The positive control: proves the harness is not rigged to always abstain.
# --------------------------------------------------------------------------- #


def test_positive_control_still_injects() -> None:
    """Excluded from `build_probes()`'s 25+ — a candidate that clears every
    gate, run through the identical wiring every negative probe uses. If
    `ProbeAssembly` (or the fixtures) were rigged to always report "nothing",
    this would go red instead of green."""
    probe = positive_control_probe()
    assert probe.probe_class not in ProbeClass.ALL

    result = run_probe(probe)
    assert result.outcome_code is OutcomeCode.INJECTED
    assert result.injected_count == 1
    assert all(d.inject for d in result.decisions)

    pipeline_result = run_probe_through_pipeline(probe)
    assert pipeline_result.outcome_code is OutcomeCode.INJECTED
    assert list(pipeline_result.context_block.slots) != []
    assert pipeline_result.context_block.rendered != ""
    from tracebed.domain.events import MEMORY_HEADER

    assert MEMORY_HEADER in pipeline_result.context_block.rendered
