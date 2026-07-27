"""Invariant 8 ("no guessed rewards"), made collectable by pytest.

The drill itself lives in `harness/guessed_reward.py` and is thorough — row-level
before/after equality, the corrected-vs-original formula divergence, the w=0 short circuit,
the ambiguous-signal path, and cross-epoch rejection. But it contains no `def test_*`, it is
not named `test_*.py`, and its only caller is `harness/phase3_gate.py`, which no CI job runs.
The prompt makes invariant 8 CI-blocking from Phase 3 on; a drill nothing collects is not a
gate, it is a script.

This file is that collection point and nothing else: it runs the real drill and asserts each
clause separately, so a failure names the clause rather than reporting "the drill returned
False". `harness/phase3_gate.py` still calls the same function — the two are one implementation
with two entry points, not two implementations.
"""

from __future__ import annotations

import pytest
from harness.guessed_reward import GuessedRewardReport, run_guessed_reward_drill

pytestmark = pytest.mark.phase3


@pytest.fixture(scope="module")
def report() -> GuessedRewardReport:
    return run_guessed_reward_drill()


def test_the_corrected_q_formula_and_the_original_spec_bug_diverge(
    report: GuessedRewardReport,
) -> None:
    """D-011: on a successful downstream event the corrected formula moves Q up and the
    original spec's formula moves it DOWN — i.e. the spec punished success. A refactor that
    collapsed the two would make the correction invisible."""
    assert report.formula_shape_pinned_ok
    assert report.correct_q_after > 0.5 > report.broken_spec_q_after


def test_a_zero_weight_signal_produces_no_scorer_call_at_all(
    report: GuessedRewardReport,
) -> None:
    """Not a call with r/w = 0 — which would still spend the memory's one daily update slot."""
    assert report.w_zero_short_circuit_ok


def test_an_ambiguous_outcome_mutates_zero_rows(report: GuessedRewardReport) -> None:
    """The invariant's own wording: ambiguous signals are logged and never scored, asserted as
    row-level equality before and after."""
    assert report.ambiguous_zero_mutations_ok


def test_a_successful_downstream_outcome_moves_q_up(report: GuessedRewardReport) -> None:
    assert report.downstream_success_moves_q_up_ok
    assert report.q_after > report.q_before


def test_a_cross_epoch_verdict_is_rejected_rather_than_averaged(
    report: GuessedRewardReport,
) -> None:
    assert report.cross_epoch_rejected_ok


def test_the_drill_reports_overall_pass(report: GuessedRewardReport) -> None:
    """The aggregate `phase3_gate.py` reads, asserted here too so the two entry points cannot
    disagree about what "the drill passed" means."""
    assert report.ok
